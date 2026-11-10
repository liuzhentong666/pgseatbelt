"""Give each agent its own login on a database the guard protects, and keep the guard around those logins.

  install   run guard.sql as the owner, and protect the tables named with --protect
  uninstall take it all out again as the owner, saving the audit log first; --drop-roles also drops
            the three roles and the logins the broker issued
  run      issue a login, run a command with it in PGUSER, PGPASSWORD and the like, keep the keeper's
            rounds going meanwhile, and retire the login when the command ends. A login that goes past
            its limits --strikes times is stopped: it cannot write or connect again, and with
            --undo-on-stop what it changed since its first strike is put back
  status    frozen or not, what the self-check finds, each login's budget and strikes
  keep      the keeper's rounds alone: self-check (a problem freezes writes), end stuck sessions and
            the sessions of stopped logins
  undo      stop a login and undo its changes, newest first: all of them, or back to a point with
            --from or --since-strike
  report    what a login really changed, from the audit log, and its strikes; --timeline lists its
            transactions, for choosing the point undo --from goes back to
  freeze    stop every agent's writes now; unfreeze is the owner's
  backup    dump the database outside itself, and keep the dump only if it restores

A port of Forkpoint's agent_boundary.py (1273af5) to guard.sql. Every command needs --database. It runs
as guard_broker and guard_keeper, with install, uninstall, backup and unfreeze as the owner, and has to run where
agents cannot reach it or its connection config. The password is random, never leaves this process
except in the command's environment, and reaches the server only as a SCRAM verifier.
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading

from db import FLAGS, Connection, add_connection_arguments, database_name

HERE = Path(__file__).resolve().parent
WORKER, KEEPER, BROKER = "guard_worker", "guard_keeper", "guard_broker"
LOGIN = r"[a-z][a-z0-9_]{0,62}"
SIZE = r"[1-9][0-9]{0,8}(?:kB|MB|GB)"
# What a command needs to start at all, as in agent_boundary.py; --pass-env adds a name on purpose.
PASSED_ENVIRONMENT = ("PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR", "HOME",
                      "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "LANG", "LC_ALL", "TERM",
                      "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG")
THRESHOLDS = dict(idle=60, transaction=300)


def say(text):
    print(text, file=sys.stderr, flush=True)


def scram_verifier(password):
    """The form PostgreSQL stores (RFC 5802): with it the server never sees the password itself."""
    salt, iterations = secrets.token_bytes(16), 4096
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    stored = hashlib.sha256(hmac.digest(salted, b"Client Key", "sha256")).digest()
    server = hmac.digest(salted, b"Server Key", "sha256")
    encode = lambda value: base64.b64encode(value).decode("ascii")
    return f"SCRAM-SHA-256${iterations}:{encode(salt)}${encode(stored)}:{encode(server)}"


def install(owner, database, protect=()):
    """guard.sql as the owner (re-runnable), then guard.protect for each table named."""
    for table in protect:  # every name first, so a typo stops it before anything changes
        if not re.fullmatch(r"[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*", table):
            raise ValueError(f"Not a schema-qualified table name: {table}")
    owner.sql((HERE / "guard.sql").read_text(encoding="utf-8"), database)
    for table in protect:
        owner.sql(f"SELECT guard.protect('{table}');", database)
    return json.loads(owner.sql("SELECT guard.boundary_problems();", database))


# The audit log, undo records and budgets (with each login's strikes) as one JSON document, written
# row by row: psql fetches FETCH_COUNT rows at a time, so neither the server nor this process holds
# the whole log at once.
AUDIT_EXPORT = """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
\\set FETCH_COUNT 10000
SELECT '{"database": ' || to_json(current_database()) || ', "saved_at": ' || to_json(clock_timestamp()) || ', "audit": [';
SELECT CASE WHEN row_number() OVER (ORDER BY a.id) > 1 THEN ', ' ELSE '' END || row_to_json(a) FROM guard.audit a ORDER BY a.id;
SELECT '], "undone": [';
SELECT CASE WHEN row_number() OVER (ORDER BY u.audit_id) > 1 THEN ', ' ELSE '' END || row_to_json(u) FROM guard.undone u ORDER BY u.audit_id;
SELECT '], "budgets": [';
SELECT CASE WHEN row_number() OVER (ORDER BY b.login) > 1 THEN ', ' ELSE '' END || (to_jsonb(b) || to_jsonb(guard.strikes(b.login)))
FROM guard.budget b ORDER BY b.login;
SELECT ']}';
COMMIT;"""

GUARD_TRIGGERS = ("!guard_intent", "guard_intent_done", "guard_row", "guard_statement", "guard_truncate")
_trigger_list = ", ".join(f"'{name}'" for name in GUARD_TRIGGERS)

# Objects outside the guard's schema that depend on something in it (a view over guard.audit, say).
# DROP SCHEMA ... CASCADE would drop them too, so uninstall refuses while there are any. The guard's own
# triggers on the protected tables are left out; uninstall drops those first.
DEPENDENTS_SQL = f"""SELECT string_agg(DISTINCT pg_describe_object(d.classid, d.objid, d.objsubid), '; ')
FROM pg_depend d
WHERE ((d.refclassid = 'pg_class'::regclass AND d.refobjid IN (SELECT c.oid FROM pg_class c WHERE c.relnamespace = 'guard'::regnamespace))
    OR (d.refclassid = 'pg_proc'::regclass AND d.refobjid IN (SELECT p.oid FROM pg_proc p WHERE p.pronamespace = 'guard'::regnamespace))
    OR (d.refclassid = 'pg_type'::regclass AND d.refobjid IN (SELECT t.oid FROM pg_type t WHERE t.typnamespace = 'guard'::regnamespace)))
  AND d.deptype NOT IN ('i', 'e')
  AND CASE d.classid  -- the dependent's schema: its own, or its table's for a trigger, default, rule or policy
        WHEN 'pg_class'::regclass THEN (SELECT c.relnamespace FROM pg_class c WHERE c.oid = d.objid)
        WHEN 'pg_proc'::regclass THEN (SELECT p.pronamespace FROM pg_proc p WHERE p.oid = d.objid)
        WHEN 'pg_type'::regclass THEN (SELECT t.typnamespace FROM pg_type t WHERE t.oid = d.objid)
        WHEN 'pg_constraint'::regclass THEN (SELECT c.connamespace FROM pg_constraint c WHERE c.oid = d.objid)
        WHEN 'pg_attrdef'::regclass THEN (SELECT c.relnamespace FROM pg_attrdef a JOIN pg_class c ON c.oid = a.adrelid WHERE a.oid = d.objid)
        WHEN 'pg_trigger'::regclass THEN (SELECT c.relnamespace FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid WHERE t.oid = d.objid)
        WHEN 'pg_rewrite'::regclass THEN (SELECT c.relnamespace FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class WHERE r.oid = d.objid)
        WHEN 'pg_policy'::regclass THEN (SELECT c.relnamespace FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid WHERE p.oid = d.objid)
      END IS DISTINCT FROM 'guard'::regnamespace
  AND NOT (d.classid = 'pg_trigger'::regclass AND d.objid IN (
    SELECT t.oid FROM pg_trigger t JOIN guard.guarded g ON g.target = t.tgrelid WHERE t.tgname IN ({_trigger_list})))"""

# Inside one transaction: the guard's triggers off the protected tables that still exist, every grant
# to the three roles in this database taken back (pg_shdepend lists them all, columns, procedures,
# types and large objects included; CASCADE takes the CONNECT the broker gave each agent login with
# it), PUBLIC's rights put back as guard.installed_over recorded them, and the guard's schema dropped.
UNINSTALL_SQL = f"""DO $uninstall$
DECLARE was guard.installed_over; x record; o record; kind text; outside text;
  roles text := 'guard_worker, guard_keeper, guard_broker';
  role_oids oid[] := ARRAY['guard_worker'::regrole, 'guard_keeper'::regrole, 'guard_broker'::regrole]::oid[];
BEGIN
  SELECT * INTO was FROM guard.installed_over;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'guard.installed_over is empty, so what install changed is unknown; nothing was changed';
  END IF;
  outside := ({DEPENDENTS_SQL});
  IF outside IS NOT NULL THEN
    RAISE EXCEPTION 'Objects outside the guard depend on it: %; nothing was changed', outside;
  END IF;
  FOR x IN SELECT c.oid::regclass AS target FROM guard.guarded g JOIN pg_class c ON c.oid = g.target LOOP
    FOREACH kind IN ARRAY ARRAY[{_trigger_list}] LOOP
      EXECUTE format('DROP TRIGGER IF EXISTS %I ON %s', kind, x.target);
    END LOOP;
  END LOOP;
  FOR x IN SELECT DISTINCT s.classid, s.objid, CASE WHEN s.classid = 'pg_class'::regclass THEN 0 ELSE s.objsubid END AS objsubid
           FROM pg_shdepend s
           WHERE s.dbid = (SELECT d.oid FROM pg_database d WHERE d.datname = current_database())
             AND s.refclassid = 'pg_authid'::regclass AND s.refobjid = ANY(role_oids) AND s.deptype = 'a'
             AND s.classid <> 'pg_default_acl'::regclass LOOP
    o := pg_identify_object(x.classid, x.objid, x.objsubid);
    CONTINUE WHEN o.schema = 'guard' OR (o.type = 'schema' AND o.identity = 'guard');
    kind := CASE WHEN o.type IN ('table', 'view', 'materialized view', 'foreign table') THEN 'TABLE'
                 WHEN o.type = 'sequence' THEN 'SEQUENCE'
                 WHEN o.type IN ('function', 'procedure', 'aggregate') THEN 'ROUTINE'
                 WHEN o.type = 'schema' THEN 'SCHEMA'
                 WHEN o.type = 'type' THEN 'TYPE'
                 WHEN o.type = 'language' THEN 'LANGUAGE'
                 WHEN o.type = 'foreign-data wrapper' THEN 'FOREIGN DATA WRAPPER'
                 WHEN o.type = 'server' THEN 'FOREIGN SERVER'
                 WHEN o.type = 'large object' THEN 'LARGE OBJECT' END;
    IF kind IS NULL THEN
      RAISE EXCEPTION 'A guard role holds rights on % %, which uninstall cannot take back; nothing was changed', o.type, o.identity;
    END IF;
    EXECUTE format('REVOKE ALL ON %s %s FROM %s CASCADE', kind, o.identity, roles);
  END LOOP;
  FOR x IN SELECT DISTINCT d.defaclrole, d.defaclnamespace, d.defaclobjtype FROM pg_default_acl d, aclexplode(d.defaclacl) a
           WHERE a.grantee = ANY(role_oids) AND d.defaclnamespace <> 'guard'::regnamespace LOOP
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %s%s REVOKE ALL ON %s FROM %s CASCADE', x.defaclrole::regrole,
      CASE WHEN x.defaclnamespace = 0 THEN '' ELSE format(' IN SCHEMA %I', (SELECT n.nspname FROM pg_namespace n WHERE n.oid = x.defaclnamespace)) END,
      CASE x.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES' WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' ELSE 'SCHEMAS' END,
      roles);
  END LOOP;
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM %s CASCADE', current_database(), roles);
  IF was.public_connect THEN EXECUTE format('GRANT CONNECT ON DATABASE %I TO PUBLIC', current_database()); END IF;
  IF was.public_temporary THEN EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO PUBLIC', current_database()); END IF;
  IF was.public_large_objects THEN
    GRANT EXECUTE ON FUNCTION pg_catalog.lo_from_bytea(oid, bytea), pg_catalog.lo_create(oid), pg_catalog.lo_creat(integer) TO PUBLIC;
  END IF;
END $uninstall$;
DROP SCHEMA guard CASCADE;
"""


def literal(name):
    return "'" + name.replace("'", "''") + "'"


def identifier(name):
    return '"' + name.replace('"', '""') + '"'


def save_audit(owner, database, folder):
    """Stream the audit log, undo records and budgets to a new JSON file in folder; returns its path."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = owner.sql("SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYYMMDD-HH24MISS-US');", database)
    final = folder / f"{database}-guard-audit-{stamp}Z.json"
    partial = final.with_suffix(".partial")
    script = (f'SET ROLE "{owner.role}";\n' if owner.role else "") + AUDIT_EXPORT
    try:
        with partial.open("xb") as out:
            done = subprocess.run(owner.client_args(database), input=script.encode("utf-8"), stdout=out,
                                  stderr=subprocess.PIPE, env=owner.env, timeout=3600, creationflags=FLAGS)
        if done.returncode:
            raise RuntimeError("Saving the audit log failed: " + done.stderr.decode("utf-8", "replace")[-1000:])
        partial.rename(final)
    finally:
        partial.unlink(missing_ok=True)
    return final


def uninstall(owner, database, audit_to, drop_roles=False):
    """Take the guard out of a database, as its superuser owner, and put back what install changed.

    Agents are stopped first and the audit log is saved to a file in audit_to, because it is the only
    record of what they did. With drop_roles, the three roles and the logins the broker issued are
    dropped too, which is refused before anything changes while they are used in another database.
    All of it is one transaction: if any part fails, the guard stays (frozen) and nothing else changes.
    Data the agents changed stays as it is: undo first for anything that should go back.
    """
    database_name(database)
    if owner.sql("SELECT to_regnamespace('guard') IS NOT NULL;", database) != "t":
        raise ValueError(f"The guard is not installed in {database}")
    outside = owner.sql(f"SELECT coalesce(({DEPENDENTS_SQL}), '');", database)
    if outside:
        raise ValueError(f"Objects outside the guard depend on it, and dropping its schema would drop them too: {outside}. "
                         "Nothing was changed")
    # The logins the broker issued: direct members of guard_worker that can log in.
    issued = owner.sql("""SELECT coalesce(string_agg(r.rolname, ' ' ORDER BY r.rolname), '') FROM pg_auth_members m
      JOIN pg_roles r ON r.oid = m.member WHERE m.roleid = 'guard_worker'::regrole AND r.rolcanlogin;""", database).split()
    names = issued + ["guard_broker", "guard_keeper", "guard_worker"]
    listed = "ARRAY[" + ",".join(literal(name) for name in names) + "]::name[]"
    if drop_roles:
        # Roles belong to the whole server: whatever another database still grants them or lets them
        # own (the guard installed there, for one) would stop DROP ROLE, so it is refused up front.
        elsewhere = owner.sql(f"""SELECT coalesce(string_agg(DISTINCT d.datname::text, ', ' ORDER BY d.datname::text), '')
          FROM pg_shdepend s JOIN pg_database d ON d.oid = s.dbid
          WHERE s.refclassid = 'pg_authid'::regclass AND d.datname <> current_database()
            AND s.refobjid IN (SELECT r.oid FROM pg_roles r WHERE r.rolname = ANY({listed}));""", database)
        if elsewhere:
            raise ValueError(f"The guard's roles are still used in {elsewhere} (the guard is installed there, or something "
                             "there was granted to them), and roles are shared by every database; nothing was changed")
    end = ("SELECT count(pg_terminate_backend(a.pid)) FROM pg_stat_activity a WHERE a.datname = current_database() "
           "AND a.usesysid IN (SELECT guard.agent_logins());")
    owner.sql("SELECT guard.freeze('the guard is being uninstalled');", database)
    owner.sql(end, database)
    rows = int(owner.sql("SELECT count(*) FROM guard.audit;", database))
    path = save_audit(owner, database, audit_to)
    # A busy protected table fails fast rather than queue the application's statements behind DROP TRIGGER.
    script = "BEGIN;\nSET LOCAL lock_timeout = '2s';\n" + UNINSTALL_SQL
    if drop_roles:
        script += (f"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename = ANY({listed});\n"
                   "REVOKE SET ON PARAMETER temp_file_limit, log_statement FROM guard_broker;\n"
                   f"DROP OWNED BY {', '.join(identifier(name) for name in names)};\n"
                   + "".join(f"DROP ROLE {identifier(name)};\n" for name in names))
    owner.sql(script + "COMMIT;", database)
    if issued and not drop_roles:
        owner.sql("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = current_database() "
                  f"AND usename = ANY(ARRAY[{','.join(literal(name) for name in issued)}]::name[]);", database)
    return dict(database=database, audit_file=str(path), audit_rows=rows, logins_cut_off=issued,
                roles_dropped=names if drop_roles else [])


def issue_login(broker, database, rows, size, hours, connections=4, temp_file_limit="100MB", prefix="agent",
                max_table_share=0.1, strikes=3):
    """(login, password, valid_until) of a new login, on a connection running as guard_broker."""
    database_name(database)
    if not re.fullmatch(SIZE, temp_file_limit):
        raise ValueError("temp_file_limit must look like 100MB")
    for value, label, floor in ((rows, "rows", 0), (size, "bytes", 0), (hours, "hours", 1e-9), (connections, "connections", 1),
                                (strikes, "strikes", 1)):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < floor:
            raise ValueError(f"{label} must be at least {floor}")
    if isinstance(max_table_share, bool) or not isinstance(max_table_share, (int, float)) or not 0 < max_table_share <= 1:
        raise ValueError("max_table_share must be above 0 and at most 1")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,40}", prefix):
        raise ValueError("A login prefix is 1-41 lowercase letters, digits or underscores, starting with a letter")
    name, password = f"{prefix}_{secrets.token_hex(6)}", secrets.token_urlsafe(32)
    until = broker.sql(f"SELECT (clock_timestamp()+make_interval(secs=>{float(hours) * 3600}))::text;", database)
    broker.sql(f"""BEGIN;
CREATE ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT
  CONNECTION LIMIT {int(connections)} VALID UNTIL '{until}' PASSWORD '{scram_verifier(password)}';
GRANT {WORKER} TO {name} WITH INHERIT TRUE, SET FALSE;
GRANT CONNECT ON DATABASE "{database}" TO {name};
ALTER ROLE {name} SET temp_file_limit='{temp_file_limit}';
ALTER ROLE {name} SET idle_in_transaction_session_timeout='60s';
ALTER ROLE {name} SET log_statement='all';
SELECT guard.issue_budget('{name}',{int(rows)},{int(size)},{float(max_table_share)},{int(strikes)});
COMMIT;""", database)
    return name, password, until


def retire_login(broker, keeper, database, login):
    """End the login's sessions, spend its budget and drop it. The audit log keeps its name."""
    database_name(database)
    if not re.fullmatch(LOGIN, login):
        raise ValueError("Not a login name")
    broker.sql(f"ALTER ROLE {login} NOLOGIN;", database)
    keeper.sql(f"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename='{login}';", database)
    broker.sql(f"""BEGIN;
SELECT guard.stop_agent('{login}');
REVOKE CONNECT ON DATABASE "{database}" FROM {login};
REVOKE {WORKER} FROM {login};
DROP ROLE {login};
COMMIT;""", database)


def keeper_round(keeper, database=None, idle=THRESHOLDS["idle"], transaction=THRESHOLDS["transaction"]):
    """One round as guard_keeper: the self-check (a problem freezes writes), then the stuck sessions and
    every session of a stopped login."""
    status = json.loads(keeper.sql("SELECT guard.boundary_check();", database))
    ended = json.loads(keeper.sql(
        f"SELECT guard.end_stuck_sessions({int(idle)},{int(transaction)},{'true' if status['frozen'] else 'false'});", database))
    return dict(frozen=status["frozen"], problems=status["problems"], ended=ended, logins=len(status["logins"]),
                stopped=[login["login"] for login in status["logins"] if login["stopped"]])


def undo_login(keeper, login, database=None, start=None, since_strike=False):
    """Stop a login, then undo its changes newest first; stops at newer work and says why.

    Everything it changed, or back to a point, keeping what it did before: start is the audit id of the
    first change to undo (the "from" of a transaction in guard.timeline), and since_strike takes the
    login's own struck_from, which gives the state before it first went past a limit.
    """
    if not re.fullmatch(LOGIN, login):
        raise ValueError("Not a login name")
    if since_strike:
        start = json.loads(keeper.sql(f"SELECT guard.report('{login}');", database))["struck_from"]
        if start is None:
            raise ValueError(f"{login} has no strike to go back to")
    if start is not None and (isinstance(start, bool) or not isinstance(start, int) or start < 0):
        raise ValueError("The change to undo from is a whole number, as report --timeline shows it")
    # Sessions end first, since an open transaction could hold the budget row guard.stop_agent updates
    # or a row undo has to put back, and again after, for one that reconnected in between.
    end = f"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename='{login}';"
    keeper.sql(end, database)
    keeper.sql(f"SELECT guard.stop_agent('{login}');", database)
    keeper.sql(end, database)
    result = keeper.execute(f"SELECT guard.undo('{login}', {'NULL' if start is None else start});", database)
    if result.returncode:
        return dict(login=login, undone=0, remaining=None, refused=dict(error=result.stderr.strip()[:1000]))
    return json.loads(result.stdout)


def connect(args, role):
    return Connection(argparse.Namespace(**dict(vars(args), role=role)))


def run(args):
    if not args.command or args.command[0] != "--" or len(args.command) < 2:
        raise ValueError("Give the agent's command after --")
    broker, keeper = connect(args, BROKER), connect(args, KEEPER)
    database = broker.settings["database"]
    login, password, until = issue_login(broker, database, args.rows, args.bytes, args.hours, args.connections,
                                         args.temp_file_limit, args.prefix, args.max_table_share, args.strikes)
    host = args.agent_host or broker.settings["host"]
    environment = {name: os.environ[name] for name in (*PASSED_ENVIRONMENT, *args.pass_env) if name in os.environ}
    environment.update(PGUSER=login, PGPASSWORD=password, PGDATABASE=database,
                       PGHOST="127.0.0.1" if host.startswith("/") else host, PGPORT=str(broker.settings["port"]))
    say(json.dumps(dict(login=login, database=database, valid_until=until, rows=args.rows, bytes=args.bytes,
                        max_table_share=args.max_table_share, strikes=args.strikes)))
    stop, once, handled = threading.Event(), threading.Lock(), []

    def stopped(name):
        """This run's login is stopped: it may not connect again either, and with --undo-on-stop what it
        changed since its first strike is put back. Called by the keeper's rounds, and once more at the end."""
        with once:
            if name != login or handled:
                return
            broker.sql(f"ALTER ROLE {login} NOLOGIN;", database)
            report = dict(stopped=login)
            if args.undo_on_stop:
                try:
                    report["undo"] = undo_login(keeper, login, database, since_strike=True)
                except ValueError as error:  # no first strike on record: nothing is undone, and the report says so
                    report["undo"] = dict(undone=0, refused=dict(error=str(error)))
            handled.append(login)
            say(json.dumps(report))
    rounds = threading.Thread(target=keep, args=(args, stop, stopped), daemon=True)
    rounds.start()
    try:
        code = subprocess.run(args.command[1:], env=environment).returncode
    finally:
        stop.set()
        rounds.join(timeout=60)
        try:  # a command that ended before the keeper's next round
            if keeper.sql(f"SELECT guard.stopped('{login}');", database) == "t":
                stopped(login)
        finally:
            retire_login(broker, keeper, database, login)
    return code or (3 if handled else 0)  # a stopped run never looks like a clean one


def keep(args, stop=None, on_stopped=None):
    """The keeper's rounds every --interval seconds until stop is set, or one with --once (exit 1 if it failed).
    A login found stopped is reported once, and handed to on_stopped until that succeeds."""
    stop = stop or threading.Event()
    session, told = None, set()
    try:
        while True:
            failed = False
            try:
                session = session or connect(args, KEEPER).session()
                report = keeper_round(session, idle=args.idle_seconds or THRESHOLDS["idle"],
                                      transaction=args.transaction_seconds or THRESHOLDS["transaction"])
                new = [login for login in report["stopped"] if login not in told]
                if report["frozen"] or report["ended"] or report["problems"] or new:
                    say(json.dumps(report))
                for login in new:
                    if on_stopped:
                        on_stopped(login)
                    told.add(login)
            except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                say(f"keeper round failed: {' '.join(str(error).split())}")
                failed = True
            if args.once or stop.wait(args.interval):
                return 1 if failed else 0
    finally:
        if session:
            session.close()


def backup(args):
    """A copy outside the database, kept only after it restores into a scratch database whose guard is
    intact: the same fingerprint, and no problem once the scratch database has install's own revokes."""
    owner = connect(args, None)
    database, settings = owner.settings["database"], owner.settings

    def tool(program, *argv):
        return [*owner.prefix[:-1], re.sub(r"psql(\.exe)?$", program + r"\1", owner.prefix[-1]), "-h", settings["host"],
                "-p", str(settings["port"]), "-U", settings["user"], *argv]
    folder = Path(args.to)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = owner.sql("SELECT to_char(clock_timestamp(),'YYYYMMDD-HH24MISS');", database)
    partial, final = folder / f"{database}-{stamp}.partial", folder / f"{database}-{stamp}.dump"
    with partial.open("xb") as dump:
        done = subprocess.run(tool("pg_dump", "-Fc", "-d", database), stdout=dump, stderr=subprocess.PIPE, env=owner.env,
                              timeout=3600, creationflags=FLAGS)
    if done.returncode:
        raise RuntimeError("pg_dump failed: " + done.stderr.decode("utf-8", "replace")[-1000:])
    scratch = "agentdb_test_restore_" + secrets.token_hex(5)
    owner.create_database(scratch)
    try:
        # Closed before anything is restored into it: a dump holds no database-level privileges, and a new
        # database lets PUBLIC connect, so every login on the server could otherwise reach the copy.
        owner.sql(f'REVOKE CONNECT, TEMPORARY ON DATABASE "{scratch}" FROM PUBLIC;', settings["maintenance_database"])
        with partial.open("rb") as dump:
            done = subprocess.run(tool("pg_restore", "--exit-on-error", "-d", scratch), stdin=dump, stderr=subprocess.PIPE,
                                  stdout=subprocess.PIPE, env=owner.env, timeout=3600, creationflags=FLAGS)
        if done.returncode:
            raise RuntimeError("pg_restore failed: " + done.stderr.decode("utf-8", "replace")[-1000:])
        same = owner.sql("SELECT guard.fingerprint() = (SELECT fingerprint FROM guard.gate);", scratch)
        problems = json.loads(owner.sql("SELECT guard.boundary_problems();", scratch))
        if same != "t" or problems != []:
            raise RuntimeError(f"The restored guard is not intact: fingerprint matches {same}, problems {problems}")
        tables = {}
        for line in owner.sql("SELECT string_agg(c.oid::regclass::text, E'\\n') FROM guard.guarded g "
                              "JOIN pg_class c ON c.oid = g.target;", scratch).splitlines():
            tables[line] = int(owner.sql(f"SELECT count(*) FROM {line};", scratch))
        tables["guard.audit"] = int(owner.sql("SELECT count(*) FROM guard.audit;", scratch))
    finally:
        owner.sql(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE);', settings["maintenance_database"])
    partial.rename(final)
    removed = sorted(folder.glob(f"{database}-*.dump"))[:-args.keep]
    for old in removed:
        old.unlink()
    print(json.dumps(dict(file=str(final), bytes=final.stat().st_size, tables=tables, restored_and_checked=True,
                          removed=[old.name for old in removed]), indent=2))
    return 0


def seconds(text):
    value = int(text)
    if not 1 <= value <= 86400:
        raise argparse.ArgumentTypeError("1..86400")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    actions = parser.add_subparsers(dest="action", required=True)
    setup = actions.add_parser("install", help="run guard.sql as the owner and protect tables")
    setup.add_argument("--protect", action="append", default=[], help="a schema-qualified table agents may write; repeat")
    remove = actions.add_parser("uninstall", help="take the guard out as the owner, saving its audit log first")
    remove.add_argument("--audit-to", required=True, help="a folder for the audit log, the only record of what agents did")
    remove.add_argument("--drop-roles", action="store_true",
                        help="also drop the three guard roles and the logins the broker issued (refused while another database has the guard)")
    start = actions.add_parser("run", help="run a command under a new agent login")
    start.add_argument("--rows", type=int, default=1000, help="rows it may change, for its whole life")
    start.add_argument("--bytes", type=int, default=10_000_000, help="bytes of audit it may cause, for its whole life")
    start.add_argument("--hours", type=float, default=8, help="the login expires after this long")
    start.add_argument("--connections", type=int, default=4)
    start.add_argument("--temp-file-limit", default="100MB")
    start.add_argument("--prefix", default="agent", help="the start of the login's name")
    start.add_argument("--max-table-share", type=float, default=0.1,
                       help="beyond its first 20 rows, the share of a table it may change; 1 means no limit")
    start.add_argument("--strikes", type=int, default=3,
                       help="how many times it may be refused for going past a limit; at the last one it is stopped")
    start.add_argument("--undo-on-stop", action="store_true",
                       help="when it is stopped, undo what it changed since its first strike")
    start.add_argument("--pass-env", action="append", default=[], help="pass this variable on to the command; repeat as needed")
    start.add_argument("--agent-host", help="the server's address as the command sees it, e.g. host.docker.internal")
    start.add_argument("command", nargs=argparse.REMAINDER, help="-- the agent's command")
    start.set_defaults(once=False)
    actions.add_parser("status", help="report the guard; changes nothing")
    loop = actions.add_parser("keep", help="run the keeper's rounds alone")
    loop.add_argument("--once", action="store_true", help="one round, for a scheduler: exit 1 if it failed")
    for action in (start, loop):
        action.add_argument("--interval", type=float, default=5, help="seconds between the keeper's rounds")
        action.add_argument("--idle-seconds", type=seconds, help="end a session idle in a transaction this long; default 60")
        action.add_argument("--transaction-seconds", type=seconds, help="end a transaction open this long; default 300")
    back = actions.add_parser("undo", help="stop a login and undo its changes: all of them, or back to a point")
    back.add_argument("login")
    point = back.add_mutually_exclusive_group()
    point.add_argument("--from", dest="start", type=int, metavar="CHANGE",
                       help="undo only this change and the login's later ones; report --timeline lists them")
    point.add_argument("--since-strike", action="store_true", help="undo only what the login changed since its first strike")
    told = actions.add_parser("report", help="what a login changed, from the audit log, and its strikes")
    told.add_argument("login")
    told.add_argument("--timeline", action="store_true", help="also its transactions, each with the change undo --from takes")
    stop = actions.add_parser("freeze", help="stop every agent's writes now; reads go on")
    stop.add_argument("reason")
    actions.add_parser("unfreeze", help="open writes again; only the database owner can")
    copy = actions.add_parser("backup", help="dump the database, restore it into a scratch database and check it")
    copy.add_argument("--to", required=True, help="a folder agents cannot reach")
    copy.add_argument("--keep", type=int, default=7, help="how many checked dumps of this database to keep")
    for action in actions.choices.values():
        add_connection_arguments(action)
    args = parser.parse_args()
    if not args.database:  # never fall back to whatever database a shared config names
        parser.exit(2, "Name the database with --database.\n")
    if args.password:
        # Asked once, here: every connection reuses it. Otherwise each one would ask again, and under run the
        # keeper's thread would ask while the agent's command is already reading the same terminal.
        args.password_value, args.password = getpass.getpass("PostgreSQL password (not saved): "), False
    try:
        if args.action == "install":
            owner = connect(args, None)
            print(json.dumps(dict(problems=install(owner, owner.settings["database"], args.protect)), indent=2))
            return
        if args.action == "uninstall":
            owner = connect(args, None)
            print(json.dumps(uninstall(owner, owner.settings["database"], args.audit_to, args.drop_roles), indent=2))
            return
        if args.action == "status":
            print(json.dumps(json.loads(connect(args, KEEPER).sql("SELECT guard.boundary_status();")), indent=2))
            return
        if args.action == "report":
            if not re.fullmatch(LOGIN, args.login):
                raise ValueError("Not a login name")
            keeper = connect(args, KEEPER)
            report = json.loads(keeper.sql(f"SELECT guard.report('{args.login}');"))
            if args.timeline:
                report["transactions"] = json.loads(keeper.sql(f"SELECT guard.timeline('{args.login}');"))
            print(json.dumps(report, indent=2))
            return
        if args.action == "undo":
            result = undo_login(connect(args, KEEPER), args.login, start=args.start, since_strike=args.since_strike)
            print(json.dumps(result, indent=2))
            sys.exit(0 if not result["refused"] else 1)
        if args.action == "freeze":
            reason = args.reason.replace("'", "''")
            connect(args, KEEPER).sql(f"SELECT guard.freeze('{reason}');")
            print(json.dumps(dict(frozen=args.reason)))
            return
        if args.action == "unfreeze":
            connect(args, None).sql("SELECT guard.unfreeze();")  # refused unless this connection is the owner's
            print(json.dumps(dict(frozen=None)))
            return
        sys.exit(dict(run=run, keep=keep, backup=backup)[args.action](args))
    except KeyboardInterrupt:
        sys.exit(130)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
