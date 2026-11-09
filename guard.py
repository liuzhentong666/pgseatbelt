"""Give each agent its own login on a database the guard protects, and keep the guard around those logins.

  install   run guard.sql as the owner, and protect the tables named with --protect
  run       issue a login, run a command with it in PGUSER, PGPASSWORD and the like, keep the keeper's
            rounds going meanwhile, and retire the login when the command ends
  status    frozen or not, what the self-check finds, each login's budget
  keep      the keeper's rounds alone: self-check (a problem freezes writes), end stuck sessions
  undo      stop a login and undo its changes, newest first
  report    what a login really changed, from the audit log
  freeze    stop every agent's writes now; unfreeze is the owner's
  backup    dump the database outside itself, and keep the dump only if it restores

A port of Forkpoint's agent_boundary.py (1273af5) to guard.sql. Every command needs --database. It runs
as guard_broker and guard_keeper, with install, backup and unfreeze as the owner, and has to run where
agents cannot reach it or its connection config. The password is random, never leaves this process
except in the command's environment, and reaches the server only as a SCRAM verifier.
"""
import argparse
import base64
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
    owner.sql((HERE / "guard.sql").read_text(encoding="utf-8"), database)
    for table in protect:
        if not re.fullmatch(r"[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*", table):
            raise ValueError(f"Not a schema-qualified table name: {table}")
        owner.sql(f"SELECT guard.protect('{table}');", database)
    return json.loads(owner.sql("SELECT guard.boundary_problems();", database))


def issue_login(broker, database, rows, size, hours, connections=4, temp_file_limit="100MB", prefix="agent",
                max_table_share=0.1):
    """(login, password, valid_until) of a new login, on a connection running as guard_broker."""
    database_name(database)
    if not re.fullmatch(SIZE, temp_file_limit):
        raise ValueError("temp_file_limit must look like 100MB")
    for value, label, floor in ((rows, "rows", 0), (size, "bytes", 0), (hours, "hours", 1e-9), (connections, "connections", 1)):
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
SELECT guard.issue_budget('{name}',{int(rows)},{int(size)},{float(max_table_share)});
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
    """One round as guard_keeper: the self-check (a problem freezes writes), then the stuck sessions."""
    status = json.loads(keeper.sql("SELECT guard.boundary_check();", database))
    ended = json.loads(keeper.sql(
        f"SELECT guard.end_stuck_sessions({int(idle)},{int(transaction)},{'true' if status['frozen'] else 'false'});", database))
    return dict(frozen=status["frozen"], problems=status["problems"], ended=ended, logins=len(status["logins"]))


def undo_login(keeper, login, database=None):
    """Stop a login, then undo its changes newest first; stops at newer work and says why."""
    if not re.fullmatch(LOGIN, login):
        raise ValueError("Not a login name")
    # Sessions end first, since an open transaction could hold the budget row guard.stop_agent updates
    # or a row undo has to put back, and again after, for one that reconnected in between.
    end = f"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename='{login}';"
    keeper.sql(end, database)
    keeper.sql(f"SELECT guard.stop_agent('{login}');", database)
    keeper.sql(end, database)
    result = keeper.execute(f"SELECT guard.undo('{login}');", database)
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
                                         args.temp_file_limit, args.prefix, args.max_table_share)
    host = args.agent_host or broker.settings["host"]
    environment = {name: os.environ[name] for name in (*PASSED_ENVIRONMENT, *args.pass_env) if name in os.environ}
    environment.update(PGUSER=login, PGPASSWORD=password, PGDATABASE=database,
                       PGHOST="127.0.0.1" if host.startswith("/") else host, PGPORT=str(broker.settings["port"]))
    say(json.dumps(dict(login=login, database=database, valid_until=until, rows=args.rows, bytes=args.bytes,
                        max_table_share=args.max_table_share)))
    stop = threading.Event()
    rounds = threading.Thread(target=keep, args=(args, stop), daemon=True)
    rounds.start()
    try:
        return subprocess.run(args.command[1:], env=environment).returncode
    finally:
        stop.set()
        rounds.join(timeout=60)
        retire_login(broker, keeper, database, login)


def keep(args, stop=None):
    """The keeper's rounds every --interval seconds until stop is set, or one with --once (exit 1 if it failed)."""
    stop = stop or threading.Event()
    session = None
    try:
        while True:
            failed = False
            try:
                session = session or connect(args, KEEPER).session()
                report = keeper_round(session, idle=args.idle_seconds or THRESHOLDS["idle"],
                                      transaction=args.transaction_seconds or THRESHOLDS["transaction"])
                if report["frozen"] or report["ended"] or report["problems"]:
                    say(json.dumps(report))
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
        with partial.open("rb") as dump:
            done = subprocess.run(tool("pg_restore", "--exit-on-error", "-d", scratch), stdin=dump, stderr=subprocess.PIPE,
                                  stdout=subprocess.PIPE, env=owner.env, timeout=3600, creationflags=FLAGS)
        if done.returncode:
            raise RuntimeError("pg_restore failed: " + done.stderr.decode("utf-8", "replace")[-1000:])
        # A dump holds no database-level privileges, so the scratch database gets the ones install sets.
        owner.sql(f'REVOKE CONNECT, TEMPORARY ON DATABASE "{scratch}" FROM PUBLIC;', scratch)
        same = owner.sql("SELECT guard.fingerprint() = (SELECT fingerprint FROM guard.gate);", scratch)
        problems = json.loads(owner.sql("SELECT guard.boundary_problems();", scratch))
        if same != "t" or problems != []:
            raise RuntimeError(f"The restored guard is not intact: fingerprint matches {same}, problems {problems}")
        tables = {}
        for line in owner.sql("SELECT string_agg(target::text, E'\\n') FROM guard.guarded;", scratch).splitlines():
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
    start = actions.add_parser("run", help="run a command under a new agent login")
    start.add_argument("--rows", type=int, default=1000, help="rows it may change, for its whole life")
    start.add_argument("--bytes", type=int, default=10_000_000, help="bytes of audit it may cause, for its whole life")
    start.add_argument("--hours", type=float, default=8, help="the login expires after this long")
    start.add_argument("--connections", type=int, default=4)
    start.add_argument("--temp-file-limit", default="100MB")
    start.add_argument("--prefix", default="agent", help="the start of the login's name")
    start.add_argument("--max-table-share", type=float, default=0.1,
                       help="beyond its first 20 rows, the share of a table it may change; 1 means no limit")
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
    back = actions.add_parser("undo", help="stop a login and undo its changes")
    back.add_argument("login")
    told = actions.add_parser("report", help="what a login changed, from the audit log")
    told.add_argument("login")
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
    try:
        if args.action == "install":
            owner = connect(args, None)
            print(json.dumps(dict(problems=install(owner, owner.settings["database"], args.protect)), indent=2))
            return
        if args.action == "status":
            print(json.dumps(json.loads(connect(args, KEEPER).sql("SELECT guard.boundary_status();")), indent=2))
            return
        if args.action == "report":
            if not re.fullmatch(LOGIN, args.login):
                raise ValueError("Not a login name")
            print(json.dumps(json.loads(connect(args, KEEPER).sql(f"SELECT guard.report('{args.login}');")), indent=2))
            return
        if args.action == "undo":
            result = undo_login(connect(args, KEEPER), args.login)
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
