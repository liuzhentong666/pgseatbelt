"""Install the guard, use it, take it out again, and check that the database and the server are as they were.

Two temporary databases: one with PostgreSQL's default rights, and one whose owner had already taken CONNECT,
TEMPORARY and the creation of large objects from PUBLIC before the guard came, so uninstall must not hand them
back. In each, the broker issues an agent login and the agent changes one row; then uninstall runs, and every
right, schema and trigger is compared with what was there before, by what the rights mean (acldefault for a
default), not by the text of the ACL. The first database is installed and uninstalled a second time. The last
uninstall goes through the command line with --drop-roles, which has to be refused while the other database still
has the guard. Exit 1 on any difference. Drops every database and role it made.
"""
import argparse
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
import guard as gb  # noqa: E402
from check_guard import PROTECTED, SHOP_SQL  # noqa: E402
from db import FLAGS, Connection  # noqa: E402

WHO = "CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END || ' ' || a.privilege_type || CASE WHEN a.is_grantable THEN '+' ELSE '' END"
# Everything install or uninstall could touch in a database, as lines whose meaning, not spelling, is compared.
SNAPSHOT = f"""WITH named AS (SELECT n.oid, n.nspname FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema')
SELECT coalesce(json_agg(line ORDER BY line), '[]') FROM (
  SELECT 'database: ' || {WHO} AS line FROM pg_database d
  CROSS JOIN LATERAL aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a WHERE d.datname = current_database()
  UNION ALL
  SELECT 'schema ' || s.nspname || ': ' || {WHO} FROM pg_namespace s JOIN named n ON n.oid = s.oid
  CROSS JOIN LATERAL aclexplode(coalesce(s.nspacl, acldefault('n', s.nspowner))) a
  UNION ALL
  SELECT 'relation ' || c.oid::regclass::text || ': ' || {WHO} FROM pg_class c JOIN named n ON n.oid = c.relnamespace
  CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault((CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END)::"char", c.relowner))) a
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
  UNION ALL
  SELECT 'function ' || p.oid::regprocedure::text || ': ' || {WHO} FROM pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
  WHERE p.pronamespace IN (SELECT oid FROM named)
     OR p.oid IN ('pg_catalog.lo_create(oid)'::regprocedure, 'pg_catalog.lo_creat(integer)'::regprocedure,
                  'pg_catalog.lo_from_bytea(oid,bytea)'::regprocedure)
  UNION ALL
  SELECT 'column ' || c.oid::regclass::text || '.' || t.attname || ': ' || {WHO} FROM pg_attribute t JOIN pg_class c ON c.oid = t.attrelid
  JOIN named n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(t.attacl) a
  UNION ALL
  SELECT 'default ' || d.defaclrole::regrole::text || ' ' || coalesce(s.nspname, '-') || ' ' || d.defaclobjtype::text || ': ' || {WHO}
  FROM pg_default_acl d LEFT JOIN pg_namespace s ON s.oid = d.defaclnamespace CROSS JOIN LATERAL aclexplode(d.defaclacl) a
  UNION ALL
  SELECT 'trigger ' || t.tgrelid::regclass::text || ' ' || t.tgname || ' ' || t.tgenabled::text FROM pg_trigger t WHERE NOT t.tgisinternal
  UNION ALL
  SELECT 'schema exists: ' || nspname FROM named
) x;"""
GUARD_ROLES = ("SELECT coalesce(string_agg(rolname, ' ' ORDER BY rolname), '') FROM pg_roles "
               "WHERE rolname IN ('guard_worker', 'guard_keeper', 'guard_broker');")
# The application's own, before the guard: a table agents may read only some columns of, and a procedure only they may call.
NOTES_SQL = """CREATE TABLE shop.notes (id bigint PRIMARY KEY, body text, secret text);
CREATE PROCEDURE shop.touch_note(p_id bigint) LANGUAGE sql AS $$ UPDATE shop.notes SET body = body WHERE id = p_id $$;
REVOKE EXECUTE ON PROCEDURE shop.touch_note(bigint) FROM PUBLIC;"""
# Grants an owner may well make to the worker role, each kind of which uninstall has to take back.
WORKER_GRANTS = """REVOKE SELECT ON shop.notes FROM guard_worker; GRANT SELECT (id, body) ON shop.notes TO guard_worker;
GRANT EXECUTE ON PROCEDURE shop.touch_note(bigint) TO guard_worker;
ALTER DEFAULT PRIVILEGES IN SCHEMA shop GRANT SELECT ON TABLES TO guard_worker;"""


def connect(database, **login):
    return Connection(argparse.Namespace(config=None, database=database, role=login.pop("role", None), password=False, **login))


def main():
    admin = connect("postgres")
    if admin.sql(GUARD_ROLES):
        raise SystemExit("Guard roles already exist on this server, and this test drops them at the end; nothing was run")
    tag = uuid.uuid4().hex[:8]
    databases = dict(default=f"agentdb_test_unin_a_{tag}", locked=f"agentdb_test_unin_b_{tag}")
    results, before, logins = [], {}, []

    def record(name, ok, detail):
        results.append(dict(name=name, status="HOLDS" if ok else "GAP", detail=str(detail)[:600]))
        print(f"[{'HOLDS' if ok else '  GAP'}] {name}: {str(detail)[:220]}", flush=True)

    def snapshot(database):
        return json.loads(connect(database).sql(SNAPSHOT))

    def differences(database):
        now = snapshot(database)
        return sorted(set(before[database]) ^ set(now))

    def use(database):
        """Install, then one agent login, issued by the broker, changes product 2001's price."""
        owner = connect(database)
        gb.install(owner, database, PROTECTED)
        owner.sql("SELECT guard.allow('shop.restock(bigint,integer)', 'writes only shop.products');"
                  "GRANT SELECT ON ALL TABLES IN SCHEMA shop TO guard_worker;" + WORKER_GRANTS)
        login, password, _ = gb.issue_login(connect(database, role=gb.BROKER), database, 10, 100_000, 1, prefix="guard_atk")
        logins.append(login)
        agent = connect(database, user=login, host="127.0.0.1", password_value=password)
        agent.sql("UPDATE shop.products SET price = price + 1 WHERE id = 2001;")
        return agent, login

    folder = tempfile.mkdtemp(prefix="guard-uninstall-")
    try:
        for kind, database in databases.items():
            admin.create_database(database)
            owner = connect(database)
            owner.sql(SHOP_SQL + NOTES_SQL)
            if kind == "locked":
                owner.sql(f'REVOKE CONNECT, TEMPORARY ON DATABASE "{database}" FROM PUBLIC;'
                          "REVOKE EXECUTE ON FUNCTION lo_from_bytea(oid,bytea), lo_create(oid), lo_creat(integer) FROM PUBLIC;")
            before[database] = snapshot(database)
        a, b = databases["default"], databases["locked"]
        agent_a, login_a = use(a)
        use(b)
        problems = json.loads(connect(a).sql("SELECT guard.boundary_problems();"))
        record("installed_and_clean", problems == [] and snapshot(a) != before[a], f"problems {problems}")

        try:
            gb.uninstall(connect(a), a, folder, drop_roles=True)
            refused = None
        except ValueError as error:
            refused = str(error)
        still = connect(a).sql("SELECT to_regnamespace('guard') IS NOT NULL;")
        record("dropping_the_roles_is_refused_while_another_database_has_the_guard",
               refused is not None and b in refused and still == "t", refused or "NOT REFUSED")

        connect(a).sql("CREATE VIEW shop.agent_changes AS SELECT login, at FROM guard.audit;")
        try:
            gb.uninstall(connect(a), a, folder)
            refused = None
        except ValueError as error:
            refused = str(error)
        still = connect(a).sql("SELECT (SELECT frozen_reason IS NULL FROM guard.gate)::text || ' ' || "
                               "(SELECT count(*) FROM pg_trigger WHERE tgname = 'guard_row');")
        record("uninstall_refuses_while_something_outside_the_guard_depends_on_it",
               refused is not None and "agent_changes" in refused and still == f"true {len(PROTECTED)}",
               f"{refused or 'NOT REFUSED'}; open, triggers: {still}")
        connect(a).sql("DROP VIEW shop.agent_changes;")

        result = gb.uninstall(connect(a), a, folder)
        gone = differences(a)
        record("uninstall_puts_back_every_right_schema_and_trigger", gone == [], gone or "identical")
        saved = json.loads(Path(result["audit_file"]).read_text(encoding="utf-8"))
        audit = saved["audit"]
        record("the_audit_log_is_saved_first", len(audit) == 1 and audit[0]["login"] == login_a and audit[0]["op"] == "U"
               and audit[0]["target"] == "shop.products", f"{result['audit_rows']} rows in {Path(result['audit_file']).name}")
        price = connect(a).sql("SELECT price FROM shop.products WHERE id = 2001;")
        record("the_agents_change_stays", float(price) == 11, f"price {price}")
        # PUBLIC may connect here again, as before install, so the login may connect; it must not write.
        cut = agent_a.execute("UPDATE shop.products SET price = price + 1 WHERE id = 2002;", a)
        record("the_agent_login_can_no_longer_write", cut.returncode != 0 and "permission denied" in cut.stderr,
               (cut.stderr.strip().splitlines() or ["WRITTEN"])[0][:160])
        write = connect(a).execute("UPDATE shop.products SET stock = stock - 1 WHERE id = 1;", a)
        record("the_application_still_writes", write.returncode == 0, write.stderr.strip()[:160] or "written")
        roles = admin.sql(GUARD_ROLES)
        record("the_roles_stay_for_the_other_database", roles == "guard_broker guard_keeper guard_worker", roles)

        use(a)
        # A table protected and then dropped leaves only its number in guard.guarded.
        connect(a).sql("CREATE TABLE shop.scratch (id bigint PRIMARY KEY); SELECT guard.protect('shop.scratch'); DROP TABLE shop.scratch;")
        try:
            gb.uninstall(connect(a), a, folder)
            failed = None
        except (RuntimeError, ValueError) as error:
            failed = str(error)
        record("uninstall_works_after_a_protected_table_was_dropped", failed is None, (failed or "uninstalled")[:300])
        gone = differences(a)
        record("install_and_uninstall_again_put_back_the_same", gone == [], gone or "identical")

        # a has no guard now, but something there is granted to a guard role: dropping the roles must not start.
        connect(a).sql("GRANT SELECT ON shop.products TO guard_worker;")
        held = subprocess.run([sys.executable, str(ROOT / "guard.py"), "uninstall", "--database", b, "--audit-to", folder, "--drop-roles"],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, cwd=ROOT, creationflags=FLAGS)
        still = connect(b).sql("SELECT (to_regnamespace('guard') IS NOT NULL)::text;") + " " + admin.sql(GUARD_ROLES)
        record("dropping_the_roles_is_refused_while_another_database_grants_them_something",
               held.returncode == 1 and a in held.stderr and still == "true guard_broker guard_keeper guard_worker",
               f"exit {held.returncode}; {held.stderr.strip()[:200]}; then: {still}")
        connect(a).sql("REVOKE SELECT ON shop.products FROM guard_worker;")

        cli = subprocess.run([sys.executable, str(ROOT / "guard.py"), "uninstall", "--database", b, "--audit-to", folder, "--drop-roles"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, cwd=ROOT, creationflags=FLAGS)
        report = json.loads(cli.stdout) if cli.returncode == 0 else {}
        record("uninstall_from_the_command_line_with_drop_roles", cli.returncode == 0 and len(report.get("roles_dropped", [])) == len(logins) + 3,
               f"exit {cli.returncode}; dropped {report.get('roles_dropped')}; {cli.stderr.strip()[:200]}")
        gone = differences(b)
        record("a_database_locked_before_stays_locked", gone == [], gone or "identical")
        public = connect(b).sql("SELECT has_database_privilege('public', current_database(), 'CONNECT')::text || ' ' || "
                                "has_function_privilege('public', 'lo_create(oid)', 'EXECUTE')::text;")
        record("public_got_nothing_it_did_not_have", public == "false false", public)
        left = admin.sql(GUARD_ROLES) + " " + admin.sql("SELECT coalesce(string_agg(rolname, ' '), '') FROM pg_roles WHERE rolname = ANY(ARRAY["
                                                        + ",".join(f"'{name}'" for name in logins) + "]::name[]);")
        record("no_guard_role_or_agent_login_is_left", left.strip() == "", left.strip() or "none")
        again = subprocess.run([sys.executable, str(ROOT / "guard.py"), "uninstall", "--database", b, "--audit-to", folder],
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, cwd=ROOT, creationflags=FLAGS)
        record("uninstall_where_there_is_no_guard_is_refused", again.returncode == 1 and "not installed" in again.stderr, again.stderr.strip()[:160])
    finally:
        for database in databases.values():
            admin.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE);', "postgres")
        leftovers = [name for name in logins if admin.sql(f"SELECT count(*) FROM pg_roles WHERE rolname = '{name}';") == "1"]
        for name in leftovers:
            admin.execute(f'DROP ROLE "{name}";', "postgres")
        if admin.sql(GUARD_ROLES):
            admin.execute("REVOKE SET ON PARAMETER temp_file_limit, log_statement FROM guard_broker;"
                          "DROP ROLE IF EXISTS guard_broker; DROP ROLE IF EXISTS guard_keeper; DROP ROLE IF EXISTS guard_worker;", "postgres")
        output = dict(holds=sum(r["status"] == "HOLDS" for r in results), gaps=[r["name"] for r in results if r["status"] == "GAP"],
                      left_behind=admin.sql("SELECT count(*) FROM pg_database WHERE datname LIKE " + f"'agentdb_test_unin_%_{tag}'")
                      + " databases, " + str(len([1 for name in logins if admin.sql(f"SELECT count(*) FROM pg_roles WHERE rolname = '{name}';") == '1']))
                      + " logins, '" + admin.sql(GUARD_ROLES) + "' guard roles", results=results)
        (ROOT / "results" / "uninstall-results.json").write_bytes((json.dumps(output, indent=2) + "\n").encode("utf-8"))
        print(json.dumps({k: output[k] for k in ("holds", "gaps", "left_behind")}, indent=1), flush=True)
    sys.exit(1 if output["gaps"] else 0)


if __name__ == "__main__":
    main()
