-- guard: the agent boundary of Forkpoint's sql/011 (1273af5) on ordinary tables, with no branches,
-- merges or history. A prototype; tests/check_guard.py attacks it (README.md has the results).
--
-- Run as a superuser owner of the application's database (re-runnable). Then, as that owner, for
-- every table agents may write: SELECT guard.protect('<table>'); and grant guard_worker SELECT on
-- whatever agents may read. guard.unprotect('<schema.table>') takes one out again, and is how the
-- owner says that a protected table was dropped on purpose. Rerunning this file accepts the guard's
-- functions as they now are (the fingerprint), but never reopens writes: only the owner's
-- guard.unfreeze() does.
--
-- * Agents are logins the broker issues; each holds guard_worker. They write the live tables
--   directly. Triggers on each protected table charge the login's budget (rows and bytes, no
--   top-ups), refuse while frozen (AB000) or outside READ COMMITTED (AB006), and append every change
--   to guard.audit with the login from session_user.
-- * How much of one table: a small allowance (011's rule: a login's first 20 rows, then a tenth of
--   the table). Beyond it a login first declares how many rows of the table it means to change
--   (guard.declare; without that, AB009) and is held to its number (AB007), so that a statement
--   which touches far more than was meant is stopped. The number is the agent's own: it is no limit
--   against one that means harm. The operator's limits are the budget and, if given, a
--   max_table_share below 1, a ceiling no declaration lifts (AB007).
-- * A deferred trigger checks the gate again at commit, under a share lock on the gate's row that it
--   keeps until the transaction ends, so a write made before a freeze cannot commit after it. A
--   transaction that fires that check early (SET CONSTRAINTS ... IMMEDIATE) keeps the lock, and
--   guard.freeze() ends it.
-- * guard_keeper tightens and undoes, guard_broker issues logins, and nothing either holds loosens a
--   limit. guard.boundary_problems() checks all of it from the catalog; the keeper's round freezes on
--   a problem and ends stuck sessions, including any agent holding or waiting for a table lock
--   stronger than ROW EXCLUSIVE (an agent that may UPDATE a table may LOCK it).
-- * Going past a limit (AB002, AB003, AB007) is a strike against the login, and no rollback takes a
--   strike back. At max_strikes the login is stopped (AB001): none of its statements writes, none of
--   its transactions commits, and the keeper ends its sessions. guard.undo(login, from) then goes
--   back to a point: the login's first strike, or any transaction guard.timeline lists. A row that
--   something else has changed since is left as it is and named; guard.undo_logins undoes several
--   logins together, newest first across all of them, so none is in another's way.
-- * Codes: AB000 frozen; AB001 stopped; AB002 row budget; AB003 storage budget; AB005 changed since
--   (undo); AB006 not READ COMMITTED; AB007 more of a table than the login declared or than its
--   ceiling allows, or TRUNCATE; AB008 could not be put back (undo); AB009 declare first (no strike).
-- * guard.py uninstall takes all of this out again and puts back what guard.installed_over recorded.
BEGIN;
-- Before anything changes. Installed by a role that is not a superuser, the guard would look whole and
-- not work: the keeper could end no session and the broker could issue no login.
DO $preflight$
BEGIN
  IF current_setting('server_version_num')::integer < 160000 THEN
    RAISE EXCEPTION 'The guard needs PostgreSQL 16 or later, and this server is %; nothing was changed', current_setting('server_version');
  END IF;
  IF NOT (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = current_user) THEN
    RAISE EXCEPTION 'The guard has to be installed by a superuser, and % is not one; nothing was changed', current_user
      USING ERRCODE = '42501', HINT = 'Its keeper has to end sessions and its broker has to fix settings on the logins it issues, '
        'and only a superuser can grant either. A managed service that gives out no superuser cannot run it yet.';
  END IF;
END $preflight$;
CREATE SCHEMA IF NOT EXISTS guard;
REVOKE ALL ON SCHEMA guard FROM PUBLIC;
-- What install takes from PUBLIC outside the guard's own schema, as it was before the first install,
-- so that uninstall puts back exactly that and opens nothing that was closed before.
CREATE TABLE IF NOT EXISTS guard.installed_over(one boolean PRIMARY KEY DEFAULT true CHECK (one),
  public_connect boolean NOT NULL, public_temporary boolean NOT NULL, public_large_objects boolean NOT NULL,
  at timestamptz NOT NULL DEFAULT clock_timestamp());
INSERT INTO guard.installed_over(public_connect, public_temporary, public_large_objects)
SELECT has_database_privilege('public', current_database(), 'CONNECT'),
       has_database_privilege('public', current_database(), 'TEMPORARY'),
       has_function_privilege('public', 'pg_catalog.lo_create(oid)', 'EXECUTE')
ON CONFLICT DO NOTHING;
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'guard_worker') THEN
    CREATE ROLE guard_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'guard_keeper') THEN
    CREATE ROLE guard_keeper NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'guard_broker') THEN
    CREATE ROLE guard_broker NOLOGIN NOINHERIT CREATEROLE NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('guard_worker', 'guard_keeper', 'guard_broker')
      AND (rolsuper OR rolcreatedb OR rolreplication OR rolbypassrls OR rolcanlogin
           OR (rolcreaterole AND rolname <> 'guard_broker'))) THEN
    RAISE EXCEPTION 'An existing guard role has attributes it must not have; inspect it without changing it silently';
  END IF;
  GRANT pg_signal_backend, pg_read_all_stats TO guard_keeper;
  GRANT guard_worker TO guard_broker WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
  GRANT SET ON PARAMETER temp_file_limit, log_statement TO guard_broker;
  REVOKE EXECUTE ON FUNCTION pg_catalog.lo_from_bytea(oid, bytea), pg_catalog.lo_create(oid), pg_catalog.lo_creat(integer) FROM PUBLIC;
  EXECUTE format('REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO guard_keeper', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO guard_broker WITH GRANT OPTION', current_database());
END $roles$;

CREATE TABLE IF NOT EXISTS guard.gate(one boolean PRIMARY KEY DEFAULT true CHECK (one),
  frozen_reason text, frozen_by name, frozen_at timestamptz, fingerprint text, superuser_logins name[]);
INSERT INTO guard.gate DEFAULT VALUES ON CONFLICT DO NOTHING;
-- Insert only, through guard.issue_budget: no top-ups, and a retired login's row stays, so its
-- name is never issued again.
CREATE TABLE IF NOT EXISTS guard.budget(login name PRIMARY KEY,
  rows_left bigint NOT NULL CHECK (rows_left >= 0), bytes_left bigint NOT NULL CHECK (bytes_left >= 0),
  max_table_share numeric NOT NULL DEFAULT 1 CHECK (max_table_share > 0 AND max_table_share <= 1));
-- strikes and struck_from are a retired login's last numbers; a living login's are in its two
-- sequences (guard.strike). A login issued before strikes existed has no sequences: it is refused
-- as before and never counted, until it expires.
ALTER TABLE guard.budget ADD COLUMN IF NOT EXISTS max_strikes integer NOT NULL DEFAULT 3 CHECK (max_strikes >= 1);
-- max_table_share is the operator's ceiling on how much of one table a login may change; 1 is none.
ALTER TABLE guard.budget ALTER COLUMN max_table_share SET DEFAULT 1;
-- What a login has said it means to change in a table: rows, in all, with this login (guard.declare).
CREATE TABLE IF NOT EXISTS guard.declared(login name NOT NULL, target regclass NOT NULL, row_count bigint NOT NULL CHECK (row_count >= 0),
  at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (login, target));
ALTER TABLE guard.budget ADD COLUMN IF NOT EXISTS strikes bigint NOT NULL DEFAULT 0;
ALTER TABLE guard.budget ADD COLUMN IF NOT EXISTS struck_from bigint;
-- size_before: the table's row count when the login first wrote it; the share is measured against it.
CREATE TABLE IF NOT EXISTS guard.spend(login name NOT NULL, target regclass NOT NULL, size_before bigint NOT NULL,
  changed bigint NOT NULL DEFAULT 0, existing bigint NOT NULL DEFAULT 0, PRIMARY KEY (login, target));
-- pk_columns: the primary key the table's triggers were built with. name: the table as it was called
-- when last protected, which is all that names it once it has been dropped.
CREATE TABLE IF NOT EXISTS guard.guarded(target regclass PRIMARY KEY, pk_columns text[] NOT NULL);
ALTER TABLE guard.guarded ADD COLUMN IF NOT EXISTS name text;
-- The columns an agent's UPDATE itself changed, noted before the application's own BEFORE triggers.
-- guard.charge takes each row's out; guard.intent_done clears what a later BEFORE trigger skipped.
CREATE TABLE IF NOT EXISTS guard.intent(tx bigint NOT NULL, target regclass NOT NULL, pk jsonb NOT NULL,
  columns text[] NOT NULL, PRIMARY KEY (tx, target, pk));
CREATE TABLE IF NOT EXISTS guard.commit_check(tx bigint PRIMARY KEY);
CREATE TABLE IF NOT EXISTS guard.audit(id bigserial PRIMARY KEY, login name NOT NULL,
  tx bigint NOT NULL DEFAULT txid_current(), at timestamptz NOT NULL DEFAULT clock_timestamp(),
  target regclass NOT NULL, op text NOT NULL CHECK (op IN ('I', 'U', 'D')), pk jsonb NOT NULL,
  columns text[], before jsonb, after jsonb);
-- The table's name when the change was made: target is its oid, which names nothing once it is dropped.
ALTER TABLE guard.audit ADD COLUMN IF NOT EXISTS target_name text;
CREATE INDEX IF NOT EXISTS audit_target_pk ON guard.audit (target, pk);
CREATE TABLE IF NOT EXISTS guard.undone(audit_id bigint PRIMARY KEY REFERENCES guard.audit,
  at timestamptz NOT NULL DEFAULT clock_timestamp(), by name NOT NULL DEFAULT session_user);
-- SECURITY DEFINER functions agents may call, after the owner has read them (guard.allow): they run
-- as their owner, so the self-check reports every other one agents can execute, and an allowed one
-- whose definition has changed since.
CREATE TABLE IF NOT EXISTS guard.allowed_function(fn regprocedure PRIMARY KEY, definition_md5 text NOT NULL, reason text NOT NULL);

CREATE OR REPLACE FUNCTION guard.immutable() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, guard, pg_temp AS $$
BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000'; END $$;
CREATE OR REPLACE TRIGGER immutable BEFORE UPDATE OR DELETE ON guard.audit FOR EACH ROW EXECUTE FUNCTION guard.immutable();
CREATE OR REPLACE TRIGGER immutable_truncate BEFORE TRUNCATE ON guard.audit FOR EACH STATEMENT EXECUTE FUNCTION guard.immutable();
CREATE OR REPLACE TRIGGER immutable BEFORE UPDATE OR DELETE ON guard.undone FOR EACH ROW EXECUTE FUNCTION guard.immutable();
CREATE OR REPLACE TRIGGER immutable_truncate BEFORE TRUNCATE ON guard.undone FOR EACH STATEMENT EXECUTE FUNCTION guard.immutable();

-- A strike against a login. The refusal that follows rolls back everything its transaction wrote, but
-- not a sequence, so each login has two, made with its budget and named by the md5 of its name:
-- strikes_ counts them, and struck_from_ holds, from the first one on, the audit id from which every
-- change of the login is newer than that strike. After a server crash a count above 0 can come back
-- up to 32 higher, which stops the login: closed, not open.
CREATE OR REPLACE FUNCTION guard.strike(p_login name) RETURNS bigint LANGUAGE plpgsql
SET search_path = pg_catalog, guard, pg_temp AS $$
DECLARE tag text := md5(p_login::text); n bigint;
BEGIN
  IF to_regclass('guard.strikes_' || tag) IS NULL THEN RETURN NULL; END IF;  -- no budget, or retired
  n := nextval(('guard.strikes_' || tag)::regclass);
  IF n = 1 THEN
    PERFORM setval(('guard.struck_from_' || tag)::regclass, coalesce(pg_sequence_last_value('guard.audit_id_seq'::regclass), 0) + 1);
  END IF;
  RETURN n;
END $$;

-- A login's strikes, read where they are kept: its sequences, or its budget row once it is retired.
CREATE OR REPLACE FUNCTION guard.strikes(p_login name, OUT strikes bigint, OUT max_strikes integer, OUT struck_from bigint,
  OUT stopped boolean) LANGUAGE sql STABLE SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT n.strikes, b.max_strikes, n.struck_from, n.strikes >= b.max_strikes
  FROM guard.budget b CROSS JOIN LATERAL (SELECT
    coalesce(pg_sequence_last_value(to_regclass('guard.strikes_' || md5(b.login::text))), b.strikes) AS strikes,
    coalesce(pg_sequence_last_value(to_regclass('guard.struck_from_' || md5(b.login::text))), b.struck_from) AS struck_from) n
  WHERE b.login = p_login
$$;

CREATE OR REPLACE FUNCTION guard.stopped(p_login name) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT coalesce((guard.strikes(p_login)).stopped, false)
$$;

-- Going past a limit is a strike, and the agent is told how many it has left.
CREATE OR REPLACE FUNCTION guard.refuse(p_code text, p_message text, p_detail jsonb, p_hint text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, guard, pg_temp AS $$
DECLARE s record;
BEGIN
  IF p_code IN ('AB002', 'AB003', 'AB007') THEN
    IF guard.strike(session_user) IS NOT NULL THEN  -- NULL: a login with no budget has no count
      SELECT * INTO s FROM guard.strikes(session_user);
      p_detail := coalesce(p_detail, '{}') || jsonb_build_object('strikes', s.strikes, 'max_strikes', s.max_strikes);
      p_hint := p_hint || CASE WHEN s.stopped THEN ' That was this login''s last strike: it is now stopped.'
        ELSE format(' That was strike %s of %s; at %s this login is stopped.', s.strikes, s.max_strikes, s.max_strikes) END;
    END IF;
  END IF;
  RAISE EXCEPTION '%', p_message USING ERRCODE = p_code, DETAIL = coalesce(p_detail::text, ''), HINT = p_hint;
END $$;

-- At max_strikes a login is stopped: none of its statements writes and none of its transactions commits.
CREATE OR REPLACE FUNCTION guard.not_stopped() RETURNS void LANGUAGE plpgsql
SET search_path = pg_catalog, guard, pg_temp AS $$
BEGIN
  IF guard.stopped(session_user) THEN
    PERFORM guard.refuse('AB001', 'This login is stopped', jsonb_build_object('login', session_user) || to_jsonb(guard.strikes(session_user)),
      'It went past its limits too many times. Nothing in this transaction was kept and nothing more can be written '
      'with this login. Stop, and report this in your task status.');
  END IF;
END $$;

-- Whoever may use guard_worker's privileges, through INHERIT or SET, is an agent; a superuser is the
-- owner. With no guard_worker the cast fails, so every write to a protected table fails: closed.
CREATE OR REPLACE FUNCTION guard.is_agent() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT coalesce((SELECT NOT r.rolsuper AND (pg_has_role(r.oid, 'guard_worker'::regrole, 'USAGE')
                                              OR pg_has_role(r.oid, 'guard_worker'::regrole, 'SET'))
                   FROM pg_roles r WHERE r.rolname = session_user), true)
$$;

-- Every role that can use guard_worker, for the keeper and the self-check.
CREATE OR REPLACE FUNCTION guard.agent_logins() RETURNS SETOF oid LANGUAGE sql STABLE
SET search_path = pg_catalog, guard, pg_temp AS $$
  WITH RECURSIVE holder(role) AS (
    SELECT m.member FROM pg_auth_members m WHERE m.roleid = 'guard_worker'::regrole AND (m.inherit_option OR m.set_option)
    UNION
    SELECT m.member FROM pg_auth_members m JOIN holder h ON m.roleid = h.role WHERE m.inherit_option OR m.set_option
  ) SELECT role FROM holder
$$;

CREATE OR REPLACE FUNCTION guard.gate_open() RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
DECLARE reason text;
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    PERFORM guard.refuse('AB006', 'Agent writes need READ COMMITTED',
      jsonb_build_object('transaction_isolation', current_setting('transaction_isolation')),
      'An older snapshot could miss a freeze. Start a new transaction at READ COMMITTED.');
  END IF;
  SELECT g.frozen_reason INTO reason FROM guard.gate g;
  IF NOT FOUND OR reason IS NOT NULL THEN
    PERFORM guard.refuse('AB000', 'Writes are frozen', jsonb_build_object('reason', coalesce(reason, 'guard.gate is empty')),
      'Reads still work. Stop writing and report this reason in your task status.');
  END IF;
END $$;

-- Before any row is touched: frozen, isolation, stopped, TRUNCATE, a spent or missing budget (so a
-- stopped login never queues for a row lock), and the table's size the first time this login writes it.
CREATE OR REPLACE FUNCTION guard.before_statement() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
DECLARE b guard.budget; table_size bigint;
BEGIN
  IF NOT guard.is_agent() THEN RETURN NULL; END IF;
  PERFORM guard.gate_open();
  PERFORM guard.not_stopped();
  IF TG_OP = 'TRUNCATE' THEN
    PERFORM guard.refuse('AB007', 'Agents cannot truncate', jsonb_build_object('table', TG_RELID::regclass::text),
      'Delete the rows you mean to change instead.');
  END IF;
  SELECT x.* INTO b FROM guard.budget x WHERE x.login = session_user;
  IF NOT FOUND OR b.rows_left < 1 THEN
    PERFORM guard.refuse('AB002', CASE WHEN b.login IS NULL THEN 'No budget for this login' ELSE 'Row budget spent' END,
      jsonb_build_object('login', session_user, 'rows_left', b.rows_left, 'bytes_left', b.bytes_left),
      'Nothing was changed. A new budget comes only with a new login.');
  END IF;
  IF b.bytes_left < 1 THEN
    PERFORM guard.refuse('AB003', 'Storage budget spent', jsonb_build_object('login', session_user, 'bytes_left', b.bytes_left),
      'Nothing was changed. A new budget comes only with a new login.');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM guard.spend s WHERE s.login = session_user AND s.target = TG_RELID) THEN
    EXECUTE format('SELECT count(*) FROM %s', TG_RELID::regclass) INTO table_size;
    INSERT INTO guard.spend(login, target, size_before) VALUES (session_user, TG_RELID, table_size) ON CONFLICT DO NOTHING;
  END IF;
  RETURN NULL;
END $$;

-- A table's generated columns. PostgreSQL computes them from the other columns, so no statement
-- changes one itself and none can write one back: they are never among the columns a change is
-- recorded with, and undo never sets one. A BEFORE trigger sees them before they are computed, where
-- every one of them would look changed by every UPDATE.
CREATE OR REPLACE FUNCTION guard.generated_columns(p_table regclass) RETURNS text[] LANGUAGE sql STABLE
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT coalesce(array_agg(a.attname::text), '{}') FROM pg_attribute a
  WHERE a.attrelid = p_table AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated <> ''
$$;

-- intent, charge and undo fix every setting an agent could use to change the text to_jsonb writes
-- for a value, so that what is recorded and what undo compares it with are spelled alike.
CREATE OR REPLACE FUNCTION guard.intent() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp SET TimeZone = 'UTC' SET IntervalStyle = 'postgres'
SET extra_float_digits = 1 SET bytea_output = 'hex' SET lc_monetary = 'C' AS $$
DECLARE o jsonb; n jsonb; key jsonb; root regclass;
BEGIN
  IF NOT guard.is_agent() THEN RETURN NEW; END IF;
  root := coalesce(pg_partition_root(TG_RELID), TG_RELID);
  o := to_jsonb(OLD); n := to_jsonb(NEW);
  key := (SELECT jsonb_object_agg(k, o -> k) FROM unnest(TG_ARGV) k);
  INSERT INTO guard.intent VALUES (txid_current(), root, key,
    ARRAY(SELECT k FROM jsonb_object_keys(n) k WHERE n -> k IS DISTINCT FROM o -> k
            AND k <> ALL (guard.generated_columns(root)) ORDER BY k))
  ON CONFLICT (tx, target, pk) DO UPDATE SET columns = EXCLUDED.columns;
  RETURN NEW;
END $$;

-- After each UPDATE statement: a row a later BEFORE trigger skipped (suppress_redundant_updates_trigger,
-- say) never reaches guard.charge, so its intent would stay behind, uncharged. AFTER STATEMENT
-- triggers fire after the statement's row triggers, so guard.charge has taken the rest by now.
CREATE OR REPLACE FUNCTION guard.intent_done() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
BEGIN
  IF guard.is_agent() THEN
    DELETE FROM guard.intent i WHERE i.tx = txid_current_if_assigned() AND i.target = TG_RELID;
  END IF;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION guard.charge() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp SET TimeZone = 'UTC' SET IntervalStyle = 'postgres'
SET extra_float_digits = 1 SET bytea_output = 'hex' SET lc_monetary = 'C' AS $$
DECLARE b guard.budget; s guard.spend; o jsonb; n jsonb; key jsonb; cols text[]; row_bytes bigint; table_size bigint;
  root regclass; few boolean; over boolean; declared bigint;
BEGIN
  IF NOT guard.is_agent() THEN RETURN NULL; END IF;
  PERFORM guard.gate_open();
  -- On a partitioned table this trigger fires on the partition a row is in. Everything is counted,
  -- recorded and undone against the table itself: partitions come and go, and a row can move between them.
  root := coalesce(pg_partition_root(TG_RELID), TG_RELID);
  IF TG_OP <> 'INSERT' THEN o := to_jsonb(OLD); END IF;
  IF TG_OP <> 'DELETE' THEN n := to_jsonb(NEW); END IF;
  key := (SELECT jsonb_object_agg(k, coalesce(o, n) -> k) FROM unnest(TG_ARGV) k);
  IF TG_OP = 'UPDATE' THEN
    DELETE FROM guard.intent i WHERE i.tx = txid_current() AND i.target = root AND i.pk = key RETURNING i.columns INTO cols;
    cols := coalesce(cols, ARRAY(SELECT k FROM jsonb_object_keys(n) k WHERE n -> k IS DISTINCT FROM o -> k
                                   AND k <> ALL (guard.generated_columns(root)) ORDER BY k));
  END IF;
  -- The audit row's text, uncompressed: what is stored is what is paid for.
  row_bytes := 64 + coalesce(octet_length(o::text), 0) + coalesce(octet_length(n::text), 0);
  UPDATE guard.budget x SET rows_left = x.rows_left - 1, bytes_left = x.bytes_left - row_bytes
  WHERE x.login = session_user AND x.rows_left >= 1 AND x.bytes_left >= row_bytes RETURNING x.* INTO b;
  IF NOT FOUND THEN
    SELECT x.* INTO b FROM guard.budget x WHERE x.login = session_user;
    IF b.login IS NULL OR b.rows_left < 1 THEN
      PERFORM guard.refuse('AB002', 'Row budget spent', jsonb_build_object('login', session_user, 'rows_left', b.rows_left),
        'Nothing in this statement was kept. A new budget comes only with a new login.');
    END IF;
    PERFORM guard.refuse('AB003', 'Storage budget spent',
      jsonb_build_object('login', session_user, 'bytes_left', b.bytes_left, 'this_row_costs', row_bytes),
      'Nothing in this statement was kept. A new budget comes only with a new login.');
  END IF;
  UPDATE guard.spend x SET changed = x.changed + 1, existing = x.existing + CASE WHEN TG_OP = 'INSERT' THEN 0 ELSE 1 END
  WHERE x.login = session_user AND x.target = root RETURNING x.* INTO s;
  IF NOT FOUND THEN
    -- A write no statement trigger saw first (a foreign-key cascade): sized now, this row added back.
    EXECUTE format('SELECT count(*) FROM %s', root) INTO table_size;
    INSERT INTO guard.spend VALUES (session_user, root,
      table_size + CASE TG_OP WHEN 'DELETE' THEN 1 WHEN 'INSERT' THEN -1 ELSE 0 END, 1, CASE WHEN TG_OP = 'INSERT' THEN 0 ELSE 1 END)
    RETURNING * INTO s;
  END IF;
  -- How much of one table. Adding rows alone is free up to 20. Otherwise, within a login's first 20
  -- rows, at most half of the rows that were there (and always one); beyond 20, a share of the table.
  IF NOT (s.changed <= 20 AND s.existing = 0) THEN
    few := s.changed <= 20;
    -- The operator's ceiling, if one was set: no declaration lifts it.
    over := b.max_table_share < 1 AND CASE WHEN few THEN s.existing > greatest(1, s.size_before / 2)
                                           ELSE s.changed > b.max_table_share * s.size_before END;
    IF over THEN
      PERFORM guard.refuse('AB007', 'Too large a share of ' || root::text,
        jsonb_build_object('login', session_user, 'changed_by_this_login', s.changed, 'existing_changed_by_this_login', s.existing,
          'size_before', s.size_before, 'max_table_share', b.max_table_share,
          'rule', CASE WHEN few THEN 'within 20 rows, at most half of what was there'
                       ELSE 'beyond 20 rows, at most max_table_share of the table' END),
        'Nothing in this statement was kept. Change less. If the task really rewrites this much, a login issued with a '
        'larger max_table_share has to do it, which is decided before it starts; or the database owner can.');
    END IF;
    -- Past what a login may change without saying so (beyond 20 rows, a tenth of the table): it has
    -- to have declared how many rows of this table it means to change, and is held to that.
    over := CASE WHEN few THEN s.existing > greatest(1, s.size_before / 2) ELSE s.changed > 0.1 * s.size_before END;
    IF over THEN
      SELECT d.row_count INTO declared FROM guard.declared d WHERE d.login = session_user AND d.target = root;
      IF declared IS NULL THEN
        PERFORM guard.refuse('AB009', 'Declare this change to ' || root::text || ' first',
          jsonb_build_object('login', session_user, 'table', root::text, 'rows_in_table', s.size_before, 'changed_by_this_login', s.changed,
            'without_declaring', CASE WHEN few THEN 'within 20 rows, at most half of the rows that were there'
                                      ELSE 'beyond 20 rows, at most a tenth of the table' END),
          format('Nothing in this statement was kept, and this is not a strike. It changes more of %s than a login may without saying '
                 'so first. Count the rows you mean to change, run SELECT guard.declare(%L, <rows>); and then run the statement '
                 'again. <rows> is the total for this login in %s, with what it has changed there already (guard.status() shows '
                 'that). After that, a statement that changes more rows than you declared is refused, and that is a strike.',
                 root::text, root::text, root::text));
      ELSIF s.changed > declared THEN
        PERFORM guard.refuse('AB007', 'More rows of ' || root::text || ' than this login declared',
          jsonb_build_object('login', session_user, 'table', root::text, 'declared', declared, 'changed_by_this_login', s.changed,
            'rows_in_table', s.size_before),
          'Nothing in this statement was kept. It was about to change more rows than you said you would. If it does more than you '
          'meant, fix the statement. If you do mean to change this many, declare the real number first with guard.declare and '
          'run it again.');
      END IF;
    END IF;
  END IF;
  INSERT INTO guard.audit(login, target, target_name, op, pk, columns, before, after)
  VALUES (session_user, root, CASE WHEN root = TG_RELID THEN format('%I.%I', TG_TABLE_SCHEMA, TG_TABLE_NAME) ELSE root::text END,
          left(TG_OP, 1), key, cols, o, n);
  INSERT INTO guard.commit_check VALUES (txid_current()) ON CONFLICT DO NOTHING;
  RETURN NULL;
END $$;

-- At commit (deferred): a transaction in which an agent wrote does not commit while frozen, or once
-- its login is stopped. The share lock on the gate's row stays until this transaction ends, so a
-- freeze, which updates that row, waits for it: none can come between this check and the commit.
CREATE OR REPLACE FUNCTION guard.at_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
DECLARE reason text;
BEGIN
  SELECT g.frozen_reason INTO reason FROM guard.gate g FOR SHARE;
  IF NOT FOUND OR reason IS NOT NULL THEN
    PERFORM guard.refuse('AB000', 'Writes are frozen', jsonb_build_object('reason', coalesce(reason, 'guard.gate is empty')),
      'Nothing in this transaction was kept. Reads still work. Stop writing and report this reason in your task status.');
  END IF;
  PERFORM guard.not_stopped();
  DELETE FROM guard.commit_check c WHERE c.tx = NEW.tx;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS at_commit ON guard.commit_check;
CREATE CONSTRAINT TRIGGER at_commit AFTER INSERT ON guard.commit_check DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION guard.at_commit();

-- For an agent, before a change that goes past what it may do without saying so: how many rows of a
-- protected table it means to change with this login, in all. It can say so again, with a larger or
-- a smaller number. This changes nothing in the table and takes nothing from the budget.
CREATE OR REPLACE FUNCTION guard.declare(p_table regclass, p_rows bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
DECLARE root regclass := coalesce(pg_partition_root(p_table), p_table); b guard.budget;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM guard.guarded g WHERE g.target = root) THEN
    RAISE EXCEPTION '% is not a table agents may write', p_table USING ERRCODE = '42P01';
  END IF;
  IF p_rows IS NULL OR p_rows < 0 THEN
    RAISE EXCEPTION 'Declare a number of rows, 0 or more' USING ERRCODE = '22023';
  END IF;
  SELECT x.* INTO b FROM guard.budget x WHERE x.login = session_user;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'No budget for this login, so it has nothing to declare' USING ERRCODE = '42501';
  END IF;
  INSERT INTO guard.declared(login, target, row_count) VALUES (session_user, root, p_rows)
  ON CONFLICT (login, target) DO UPDATE SET row_count = EXCLUDED.row_count, at = clock_timestamp();
  RETURN jsonb_build_object('login', session_user, 'table', root::text, 'declared', p_rows,
    'changed_so_far', coalesce((SELECT s.changed FROM guard.spend s WHERE s.login = session_user AND s.target = root), 0),
    'rows_left', b.rows_left, 'max_table_share', b.max_table_share);
END $$;

-- A table's primary key columns in key order, or NULL without one.
CREATE OR REPLACE FUNCTION guard.primary_key(p_table regclass) RETURNS text[] LANGUAGE sql STABLE
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT array_agg(a.attname::text ORDER BY k.ord)
  FROM pg_index i CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
  WHERE i.indrelid = p_table AND i.indisprimary
$$;

-- Why the guard cannot protect a table, or NULL when it can (and for a table that does not exist).
-- An ordinary or a partitioned table with a primary key. A partition is covered through the table it
-- belongs to, whose row triggers PostgreSQL copies to every partition, now and later. A write through
-- a table that others inherit from the old way reaches their rows without firing its row triggers.
CREATE OR REPLACE FUNCTION guard.unsupported(p_table regclass) RETURNS text LANGUAGE sql STABLE
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT CASE
    WHEN c.relispartition THEN 'it is a partition: protect ' || pg_partition_root(c.oid)::text || ', which covers it'
    WHEN c.relkind NOT IN ('r', 'p') THEN 'it is not an ordinary or a partitioned table'
    WHEN c.relkind = 'r' AND EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent = c.oid) THEN 'other tables inherit from it'
    WHEN guard.primary_key(c.oid) IS NULL THEN 'it has no primary key'
  END FROM pg_class c WHERE c.oid = p_table
$$;

-- A table as a person knows it: its name now, or the name recorded for it once it has been dropped.
CREATE OR REPLACE FUNCTION guard.table_name(p_table regclass, p_recorded text) RETURNS text LANGUAGE sql STABLE
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = p_table) THEN p_table::text
              ELSE coalesce(p_recorded, p_table::text) || ' (dropped)' END
$$;

-- The sequences a table's rows take values from: those its columns own (serial, identity), and those
-- a column default names without owning, which is how a dumped or hand-written schema often has
-- them. An insert needs USAGE on each. Setting one needs UPDATE, which agents are never granted.
CREATE OR REPLACE FUNCTION guard.table_sequences(p_table regclass) RETURNS SETOF regclass LANGUAGE sql STABLE
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT d.objid::regclass FROM pg_depend d JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S'
  WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass AND d.refobjid = p_table AND d.deptype IN ('a', 'i')
  UNION
  SELECT d.refobjid::regclass FROM pg_attrdef a
  JOIN pg_depend d ON d.classid = 'pg_attrdef'::regclass AND d.objid = a.oid AND d.refclassid = 'pg_class'::regclass
  JOIN pg_class s ON s.oid = d.refobjid AND s.relkind = 'S'
  WHERE a.adrelid = p_table
$$;

-- The owner protects a table: triggers, and guard_worker's grants on it and its sequences. A trigger
-- needs a lock that stops the application's writes, and a wait for one queues them too, so a busy
-- table fails fast instead (rerun it). Protecting a table again brings its triggers, and the key they
-- use, up to the table as it now is.
CREATE OR REPLACE FUNCTION guard.protect(p_table regclass) RETURNS void LANGUAGE plpgsql
SET search_path = pg_catalog, guard, pg_temp SET lock_timeout = '2s' AS $$
DECLARE keys text[] := guard.primary_key(p_table); args text; seq record; reason text := guard.unsupported(p_table);
BEGIN
  IF reason IS NOT NULL THEN RAISE EXCEPTION '% cannot be protected: %', p_table, reason USING ERRCODE = '0A000'; END IF;
  INSERT INTO guard.guarded(target, pk_columns, name) VALUES (p_table, keys, p_table::text)
  ON CONFLICT (target) DO UPDATE SET pk_columns = EXCLUDED.pk_columns, name = EXCLUDED.name;
  args := (SELECT string_agg(quote_literal(k), ',') FROM unnest(keys) k);
  -- Triggers of one kind fire in name order; '!' sorts before letters and digits.
  EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION guard.intent(%s)', '!guard_intent', p_table, args);
  EXECUTE format('CREATE OR REPLACE TRIGGER guard_intent_done AFTER UPDATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION guard.intent_done()', p_table);
  EXECUTE format('CREATE OR REPLACE TRIGGER guard_statement BEFORE INSERT OR UPDATE OR DELETE ON %s FOR EACH STATEMENT EXECUTE FUNCTION guard.before_statement()', p_table);
  EXECUTE format('CREATE OR REPLACE TRIGGER guard_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION guard.before_statement()', p_table);
  EXECUTE format('CREATE OR REPLACE TRIGGER guard_row AFTER INSERT OR UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION guard.charge(%s)', p_table, args);
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO guard_worker',
                 (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = p_table));
  EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO guard_worker', p_table);
  -- A sequence a default names may live in another schema, which agents then have to be able to look in.
  FOR seq IN SELECT s.s, n.nspname FROM guard.table_sequences(p_table) s(s)
             JOIN pg_class c ON c.oid = s.s JOIN pg_namespace n ON n.oid = c.relnamespace LOOP
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO guard_worker', seq.nspname);
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO guard_worker', seq.s);
  END LOOP;
  UPDATE guard.gate SET fingerprint = guard.fingerprint();  -- the owner accepts the new triggers
END $$;

-- The owner takes a table out again: the guard's triggers go, and so does everything guard_worker was
-- granted on the table and on the sequences only it uses, reading included, so agents can no longer
-- write it (grant SELECT again for what they may still read). Its audit rows stay, and undo still puts them back. A
-- protected table that was dropped stays a problem until the owner says here that it was meant: give
-- the name the problem gives. Like guard.protect, this never reopens writes.
CREATE OR REPLACE FUNCTION guard.unprotect(p_table text) RETURNS void LANGUAGE plpgsql
SET search_path = pg_catalog, guard, pg_temp SET lock_timeout = '2s' AS $$
DECLARE g guard.guarded; trig text; seq record; taken integer := 0;
BEGIN
  FOR g IN SELECT x.* FROM guard.guarded x
           WHERE x.target = to_regclass(p_table)
              OR (x.name = p_table AND NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = x.target)) LOOP
    IF EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = g.target) THEN
      FOREACH trig IN ARRAY ARRAY['!guard_intent', 'guard_intent_done', 'guard_statement', 'guard_truncate', 'guard_row'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON %s', trig, g.target);
      END LOOP;
      EXECUTE format('REVOKE ALL ON %s FROM guard_worker', g.target);
      -- A sequence that another protected table also takes values from stays granted for that table.
      FOR seq IN SELECT s.s FROM guard.table_sequences(g.target) s(s)
                 WHERE NOT EXISTS (SELECT 1 FROM guard.guarded o JOIN pg_class c ON c.oid = o.target
                                   WHERE o.target <> g.target AND s.s IN (SELECT guard.table_sequences(o.target))) LOOP
        EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM guard_worker', seq.s);
      END LOOP;
    END IF;
    DELETE FROM guard.guarded x WHERE x.target = g.target;
    taken := taken + 1;
  END LOOP;
  IF taken = 0 THEN
    RAISE EXCEPTION 'Not a protected table: %', p_table USING ERRCODE = '42P01',
      HINT = 'Give its name with its schema, as SELECT name FROM guard.guarded lists it.';
  END IF;
  UPDATE guard.gate SET fingerprint = guard.fingerprint();  -- the owner accepts that its triggers are gone
END $$;

-- For the owner, after reading the function: agents may call it although it runs as its owner.
CREATE OR REPLACE FUNCTION guard.allow(p_function regprocedure, p_reason text) RETURNS void LANGUAGE sql
SET search_path = pg_catalog, guard, pg_temp AS $$
  INSERT INTO guard.allowed_function VALUES (p_function, md5(pg_get_functiondef(p_function)), p_reason)
  ON CONFLICT (fn) DO UPDATE SET definition_md5 = EXCLUDED.definition_md5, reason = EXCLUDED.reason
$$;

-- For the broker. Insert only: no top-ups, and a retired login's name cannot be issued again. The
-- login's two sequences for its strikes are made here (guard.strike).
DROP FUNCTION IF EXISTS guard.issue_budget(name, bigint, bigint, numeric);  -- as it was before strikes
CREATE OR REPLACE FUNCTION guard.issue_budget(p_login name, p_rows bigint, p_bytes bigint, p_share numeric DEFAULT 1,
  p_strikes integer DEFAULT 3) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, guard, pg_temp AS $$
BEGIN
  INSERT INTO guard.budget(login, rows_left, bytes_left, max_table_share, max_strikes) VALUES (p_login, p_rows, p_bytes, p_share, p_strikes);
  EXECUTE format('CREATE SEQUENCE guard.%I', 'strikes_' || md5(p_login::text));
  EXECUTE format('CREATE SEQUENCE guard.%I', 'struck_from_' || md5(p_login::text));
END $$;

-- Spends a login's whole budget: every write it tries is then refused before touching a row. Once
-- the login can no longer connect (retired), its strikes move into its budget row and its two
-- sequences go, so none is left behind for every login there ever was. The sequences come before the
-- budget row, the order in which a write of the login itself locks them.
CREATE OR REPLACE FUNCTION guard.stop_agent(p_login name) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
DECLARE tag text := md5(p_login::text); s record;
BEGIN
  IF to_regclass('guard.strikes_' || tag) IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = p_login AND r.rolcanlogin) THEN
    SELECT * INTO s FROM guard.strikes(p_login);
    EXECUTE format('DROP SEQUENCE guard.%I, guard.%I', 'strikes_' || tag, 'struck_from_' || tag);
    UPDATE guard.budget SET strikes = s.strikes, struck_from = s.struck_from WHERE login = p_login;
  END IF;
  UPDATE guard.budget SET rows_left = 0, bytes_left = 0 WHERE login = p_login;
END $$;

-- Tighten only. The first reason stays. Updating the gate's row waits for every agent transaction
-- that holds guard.at_commit's share lock on it. Most hold it only while they commit; one that fired
-- that check early (SET CONSTRAINTS ... IMMEDIATE) holds it until it ends, and could commit after
-- the freeze, so when the wait runs long, agent transactions that have written end here.
CREATE OR REPLACE FUNCTION guard.freeze(p_reason text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp SET lock_timeout = '1s' AS $$
BEGIN
  FOR attempt IN 1..30 LOOP
    BEGIN
      UPDATE guard.gate SET frozen_reason = coalesce(nullif(p_reason, ''), 'no reason given'),
        frozen_by = session_user, frozen_at = clock_timestamp()
      WHERE frozen_reason IS NULL;
      RETURN;
    EXCEPTION WHEN lock_not_available THEN
      PERFORM pg_stat_clear_snapshot();
      PERFORM pg_terminate_backend(a.pid, 1000) FROM pg_stat_activity a
      WHERE a.datname = current_database() AND a.backend_xid IS NOT NULL AND a.pid <> pg_backend_pid()
        AND a.usesysid IN (SELECT guard.agent_logins());
    END;
  END LOOP;
  RAISE EXCEPTION 'Writes could not be frozen: the gate stayed locked' USING ERRCODE = '55P03';
END $$;

-- Granted to no one: only the owner loosens. If the cause remains, the next check freezes again.
CREATE OR REPLACE FUNCTION guard.unfreeze() RETURNS void LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  UPDATE guard.gate SET frozen_reason = NULL, frozen_by = NULL, frozen_at = NULL WHERE frozen_reason IS NOT NULL
$$;

-- Every login the broker issued keeps its budget row, retired or not. Asking about a name that has
-- none is a mistake in the name, and an empty answer would read as "this login changed nothing".
CREATE OR REPLACE FUNCTION guard.known_login(p_login name) RETURNS void LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, guard, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM guard.budget b WHERE b.login = p_login) THEN
    RAISE EXCEPTION 'No login named % was ever issued in this database', p_login USING ERRCODE = '42704';
  END IF;
END $$;

-- Undo the changes of one or more logins, newest first across all of them, checking and putting
-- back only the columns each changed. A row that something outside this undo has changed since (another
-- login, the application, a person) is left as it is, and so are this undo's older changes to that row:
-- putting them back would overwrite newer work. The same goes for a change the database will not take
-- back (AB008, with its own error: a constraint added since, say) and for a row keyed by a primary key
-- the table no longer has (AB005), since the old key may now name several rows. Everything else is
-- undone, so a transaction can end up partly undone: the answer lists those, names each row it left
-- (conflicts, the first 20) and who has changed those rows since, from the audit log (blocked_by).
-- Undoing those logins too, in the same call or first, or settling the rows by hand, and then running
-- this again, takes back the rest. Changes to a table that has been dropped are passed over and counted
-- in dropped_tables: nothing is left there to put back.
-- With p_from, only the changes from that audit id on are undone, and older ones are kept: p_from is
-- the "from" of a transaction in guard.timeline, or a login's struck_from, the state before its first
-- strike. The key of each row is the one its audit row recorded, so a table taken out of the guard
-- since can still be undone.
CREATE OR REPLACE FUNCTION guard.undo_logins(p_logins name[], p_from bigint DEFAULT NULL) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp SET TimeZone = 'UTC' SET IntervalStyle = 'postgres'
SET extra_float_digits = 1 SET bytea_output = 'hex' SET lc_monetary = 'C' AS $$
DECLARE a guard.audit; keys text[]; doc jsonb; now_doc jsonb; key_where text; set_list text; n integer := 0; refused jsonb;
  dropped jsonb := '{}'; gone text; generated text[]; cols text[]; col_list text; value_list text;
  row_keys jsonb[]; row_tags text[]; blocked jsonb := '{}'; skipped integer := 0; problem jsonb; who text[]; w text;
  conflicts jsonb := '[]'; conflicts_total integer := 0; blocked_by jsonb := '{}';
BEGIN
  IF p_logins IS NULL OR cardinality(p_logins) = 0 THEN
    RAISE EXCEPTION 'Name at least one login' USING ERRCODE = '22023';
  END IF;
  PERFORM guard.known_login(l) FROM unnest(p_logins) l;
  FOR a IN SELECT x.* FROM guard.audit x WHERE x.login = ANY (p_logins) AND x.id >= coalesce(p_from, 0)
             AND NOT EXISTS (SELECT 1 FROM guard.undone u WHERE u.audit_id = x.id) ORDER BY x.id DESC LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = a.target) THEN
      gone := coalesce(a.target_name, a.target::text);
      dropped := dropped || jsonb_build_object(gone, coalesce((dropped ->> gone)::bigint, 0) + 1);
      CONTINUE;
    END IF;
    keys := ARRAY(SELECT k FROM jsonb_object_keys(a.pk) k ORDER BY k);
    -- The row this change was made to, by its key before and after: an UPDATE can change the key.
    row_keys := ARRAY(SELECT DISTINCT d FROM (SELECT a.pk AS d
                                              UNION ALL
                                              SELECT (SELECT jsonb_object_agg(k, a.after -> k) FROM unnest(keys) k) WHERE a.after IS NOT NULL) z
                      WHERE d IS NOT NULL);
    row_tags := ARRAY(SELECT a.target::oid::text || ':' || d::text FROM unnest(row_keys) d);
    -- A newer change to this row was left in place, so this older one is left too.
    IF blocked ?| row_tags THEN
      skipped := skipped + 1;
      blocked := blocked || coalesce((SELECT jsonb_object_agg(tag, true) FROM unnest(row_tags) tag), '{}');
      CONTINUE;
    END IF;
    problem := NULL;
    who := '{}';
    IF keys IS DISTINCT FROM ARRAY(SELECT k FROM unnest(guard.primary_key(a.target)) k ORDER BY k) THEN
      problem := jsonb_build_object('code', 'AB005', 'message', 'The table''s primary key has changed since this login changed it',
        'primary_key_now', to_jsonb(guard.primary_key(a.target)));
    ELSE
      doc := coalesce(a.after, a.before);
      generated := guard.generated_columns(a.target);
      -- The columns a statement can write. An audit row from before generated columns were left out
      -- may name one, and a column may have become generated since.
      cols := ARRAY(SELECT k FROM unnest(a.columns) k WHERE k <> ALL (generated));
      BEGIN
        key_where := (SELECT string_agg(format('t.%I = (jsonb_populate_record(NULL::%s, %L::jsonb)).%I', k, a.target, doc, k), ' AND ')
                      FROM unnest(keys) k);
        EXECUTE format('SELECT to_jsonb(t) FROM %s t WHERE %s FOR UPDATE', a.target, key_where) INTO now_doc;
        IF (a.op = 'I' AND (now_doc - generated) IS DISTINCT FROM (a.after - generated))
           OR (a.op = 'D' AND now_doc IS NOT NULL)
           OR (a.op = 'U' AND (now_doc IS NULL OR EXISTS (SELECT 1 FROM unnest(cols) k WHERE now_doc -> k IS DISTINCT FROM a.after -> k))) THEN
          problem := jsonb_build_object('code', 'AB005', 'message', 'A row changed after this login changed it',
            'columns', a.columns, 'now', now_doc, 'left_by_login', a.after);
          -- Who has changed it since, as far as the audit log knows: logins outside this undo whose change
          -- still stands. A writer that is not an agent (the application, a person) leaves no audit row.
          who := ARRAY(SELECT DISTINCT x.login::text FROM guard.audit x
                       WHERE x.target = a.target AND x.pk = ANY (row_keys) AND x.id > a.id AND x.login <> ALL (p_logins)
                         AND NOT EXISTS (SELECT 1 FROM guard.undone u WHERE u.audit_id = x.id) ORDER BY 1);
          IF cardinality(who) = 0 THEN who := ARRAY['(no agent change recorded)']; END IF;
        ELSE
          IF a.op = 'I' THEN
            EXECUTE format('DELETE FROM %s t WHERE %s', a.target, key_where);
          ELSIF a.op = 'D' THEN
            -- The row as it was, in the columns the table still has and a statement can write; a column
            -- added since takes its default. OVERRIDING SYSTEM VALUE gives a GENERATED ALWAYS identity
            -- column the number the row had, since other rows may still refer to it.
            SELECT string_agg(format('%I', c.attname), ', ' ORDER BY c.attnum), string_agg(format('r.%I', c.attname), ', ' ORDER BY c.attnum)
            INTO col_list, value_list FROM pg_attribute c
            WHERE c.attrelid = a.target AND c.attnum > 0 AND NOT c.attisdropped AND c.attgenerated = '' AND a.before ? c.attname::text;
            EXECUTE format('INSERT INTO %s (%s) OVERRIDING SYSTEM VALUE SELECT %s FROM jsonb_populate_record(NULL::%s, %L::jsonb) r',
                           a.target, col_list, value_list, a.target, a.before);
          ELSIF cardinality(cols) > 0 THEN
            set_list := (SELECT string_agg(format('%I = (jsonb_populate_record(NULL::%s, %L::jsonb)).%I', k, a.target, a.before, k), ', ')
                         FROM unnest(cols) k);
            EXECUTE format('UPDATE %s t SET %s WHERE %s', a.target, set_list, key_where);
          END IF;
          INSERT INTO guard.undone(audit_id) VALUES (a.id);
          n := n + 1;
        END IF;
      EXCEPTION WHEN OTHERS THEN
        -- Only this change is rolled back; the answer says what the database said.
        problem := jsonb_build_object('code', 'AB008', 'message', 'This change could not be put back', 'error', SQLERRM, 'sqlstate', SQLSTATE);
      END;
    END IF;
    IF problem IS NOT NULL THEN
      skipped := skipped + 1;
      conflicts_total := conflicts_total + 1;
      blocked := blocked || coalesce((SELECT jsonb_object_agg(tag, true) FROM unnest(row_tags) tag), '{}');
      problem := problem || jsonb_build_object('audit_id', a.id, 'login', a.login, 'table', a.target::text, 'key', a.pk,
                                               'changed_since_by', to_jsonb(who));
      FOREACH w IN ARRAY who LOOP
        blocked_by := blocked_by || jsonb_build_object(w, coalesce((blocked_by ->> w)::bigint, 0) + 1);
      END LOOP;
      IF refused IS NULL THEN refused := problem; END IF;
      IF conflicts_total <= 20 THEN conflicts := conflicts || jsonb_build_array(problem - 'now' - 'left_by_login'); END IF;
    END IF;
  END LOOP;
  RETURN jsonb_build_object('logins', to_jsonb(p_logins), 'from', p_from, 'undone', n, 'skipped', skipped,
    'refused', refused, 'conflicts', conflicts, 'conflicts_total', conflicts_total, 'blocked_by', blocked_by, 'dropped_tables', dropped,
    'remaining', (SELECT count(*) FROM guard.audit x WHERE x.login = ANY (p_logins) AND x.id >= coalesce(p_from, 0)
                  AND NOT EXISTS (SELECT 1 FROM guard.undone u WHERE u.audit_id = x.id)
                  AND EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = x.target)),
    'kept', (SELECT count(*) FROM guard.audit x WHERE x.login = ANY (p_logins) AND x.id < coalesce(p_from, 0)
             AND NOT EXISTS (SELECT 1 FROM guard.undone u WHERE u.audit_id = x.id)),
    -- Transactions of which some changes are undone and some are not: what they did together is now
    -- only partly there, which the owner may have to look at.
    'partly_undone_transactions', (SELECT coalesce(jsonb_agg(jsonb_build_object('from', y.from_id, 'login', y.login, 'undone', y.undone,
                                                                                'left', y.changes - y.undone) ORDER BY y.from_id), '[]')
      FROM (SELECT min(x.id) AS from_id, x.login, count(*) AS changes, count(u.audit_id) AS undone
            FROM guard.audit x LEFT JOIN guard.undone u ON u.audit_id = x.id
            WHERE x.login = ANY (p_logins) AND x.id >= coalesce(p_from, 0) AND EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = x.target)
            GROUP BY x.tx, x.login HAVING count(u.audit_id) > 0 AND count(u.audit_id) < count(*)) y));
END $$;

-- One login: guard.undo_logins for it alone.
DROP FUNCTION IF EXISTS guard.undo(name);  -- as it was before p_from
CREATE OR REPLACE FUNCTION guard.undo(p_login name, p_from bigint DEFAULT NULL) RETURNS jsonb LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT jsonb_build_object('login', p_login) || guard.undo_logins(ARRAY[p_login], p_from)
$$;

-- What a login really changed, from the audit log and not from anything it says, and its strikes.
-- Works after the login is retired.
CREATE OR REPLACE FUNCTION guard.report(p_login name) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT guard.known_login(p_login);
  SELECT to_jsonb(s) || jsonb_build_object('login', p_login,
    'changes', (SELECT count(*) FROM guard.audit a WHERE a.login = p_login),
    'changes_since_first_strike', (SELECT count(*) FROM guard.audit a WHERE a.login = p_login AND a.id >= s.struck_from),
    'undone', (SELECT count(*) FROM guard.audit a JOIN guard.undone u ON u.audit_id = a.id WHERE a.login = p_login),
    'first', (SELECT min(a.at) FROM guard.audit a WHERE a.login = p_login),
    'last', (SELECT max(a.at) FROM guard.audit a WHERE a.login = p_login),
    'tables', (SELECT coalesce(jsonb_object_agg(z.t, z.ops), '{}') FROM (
                 SELECT guard.table_name(y.target, y.target_name) AS t, jsonb_build_object('inserted', sum(y.inserted),
                   'updated', sum(y.updated), 'deleted', sum(y.deleted)) AS ops
                 FROM (SELECT a.target, a.target_name, count(*) FILTER (WHERE a.op = 'I') AS inserted,
                         count(*) FILTER (WHERE a.op = 'U') AS updated, count(*) FILTER (WHERE a.op = 'D') AS deleted
                       FROM guard.audit a WHERE a.login = p_login GROUP BY a.target, a.target_name) y
                 GROUP BY 1) z),
    'declared', (SELECT coalesce(jsonb_object_agg(d.target::text, d.row_count), '{}') FROM guard.declared d WHERE d.login = p_login),
    'budget', (SELECT jsonb_build_object('rows_left', b.rows_left, 'bytes_left', b.bytes_left, 'max_table_share', b.max_table_share)
               FROM guard.budget b WHERE b.login = p_login))
  FROM guard.strikes(p_login) s
$$;

-- A login's transactions, oldest first, for choosing how far back to undo: "from" is a transaction's
-- first change, and guard.undo(login, from) undoes that transaction and all the login did after it.
CREATE OR REPLACE FUNCTION guard.timeline(p_login name) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT guard.known_login(p_login);
  SELECT coalesce(jsonb_agg(jsonb_build_object('from', t.from_id, 'at', t.began, 'changes', t.changes, 'undone', t.undone,
      'after_first_strike', coalesce(t.from_id >= s.struck_from, false), 'tables', t.tables) ORDER BY t.from_id), '[]'::jsonb)
  FROM guard.strikes(p_login) s, (
    SELECT min(x.from_id) AS from_id, min(x.began) AS began, sum(x.changes) AS changes, sum(x.undone) AS undone,
           jsonb_object_agg(guard.table_name(x.target, x.target_name),
                            jsonb_build_object('inserted', x.inserted, 'updated', x.updated, 'deleted', x.deleted)) AS tables
    FROM (SELECT a.tx, a.target, max(a.target_name) AS target_name, min(a.id) AS from_id, min(a.at) AS began, count(*) AS changes,
                 count(u.audit_id) AS undone, count(*) FILTER (WHERE a.op = 'I') AS inserted,
                 count(*) FILTER (WHERE a.op = 'U') AS updated, count(*) FILTER (WHERE a.op = 'D') AS deleted
          FROM guard.audit a LEFT JOIN guard.undone u ON u.audit_id = a.id WHERE a.login = p_login GROUP BY a.tx, a.target) x
    GROUP BY x.tx) t
$$;

-- An agent's own view: its budget, its strikes, what it has changed, its expiry, and the freeze.
CREATE OR REPLACE FUNCTION guard.status() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT jsonb_build_object('login', session_user, 'rows_left', b.rows_left, 'bytes_left', b.bytes_left,
    'max_table_share', b.max_table_share,
    'changed', (SELECT coalesce(jsonb_object_agg(s.target::text, s.changed), '{}') FROM guard.spend s WHERE s.login = session_user),
    'declared', (SELECT coalesce(jsonb_object_agg(d.target::text, d.row_count), '{}') FROM guard.declared d WHERE d.login = session_user),
    'valid_until', (SELECT r.rolvaliduntil FROM pg_roles r WHERE r.rolname = session_user),
    'frozen', (SELECT g.frozen_reason FROM guard.gate g))
    || coalesce(to_jsonb(guard.strikes(session_user)) - 'struck_from', '{}')
  FROM (SELECT 1) one LEFT JOIN guard.budget b ON b.login = session_user
$$;

CREATE OR REPLACE FUNCTION guard.fingerprint() RETURNS text LANGUAGE sql STABLE
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT encode(sha256(convert_to(coalesce(string_agg(d, E'\n' ORDER BY d), ''), 'UTF8')), 'hex') FROM (
    SELECT pg_get_functiondef(p.oid) || pg_get_userbyid(p.proowner) AS d FROM pg_proc p
    WHERE p.pronamespace = 'guard'::regnamespace AND p.prokind IN ('f', 'p')
    UNION ALL
    -- Not the copies PostgreSQL makes on partitions (tgparentid): they follow from the table's own
    -- trigger, and a partition added or dropped, as applications do every month, is no change to the guard.
    SELECT pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
    WHERE p.pronamespace = 'guard'::regnamespace AND NOT t.tgisinternal AND t.tgparentid = 0
  ) x
$$;

-- Everything that must stay true, from the catalog alone. Empty means the guard stands. Agent-written
-- data never reaches it, so no agent can cause a freeze by writing something.
CREATE OR REPLACE FUNCTION guard.boundary_problems() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  WITH boundary(role, may_execute) AS (VALUES
    ('guard_worker'::regrole, ARRAY['guard.status()', 'guard.declare(regclass,bigint)']),
    ('guard_keeper'::regrole, ARRAY['guard.report(name)', 'guard.timeline(name)', 'guard.freeze(text)', 'guard.stop_agent(name)',
      'guard.stopped(name)', 'guard.undo(name,bigint)', 'guard.undo_logins(name[],bigint)', 'guard.boundary_check()', 'guard.boundary_status()',
      'guard.end_stuck_sessions(integer,integer,boolean)', 'guard.agent_logins()']),
    ('guard_broker'::regrole, ARRAY['guard.issue_budget(name,bigint,bigint,numeric,integer)', 'guard.stop_agent(name)'])
  ), agent_login AS (
    SELECT r.* FROM guard.agent_logins() a JOIN pg_roles r ON r.oid = a
  ), func AS (
    SELECT p.oid, n.nspname, p.prosecdef,
      n.nspname || '.' || p.proname || '(' || replace(oidvectortypes(p.proargtypes), ', ', ',') || ')' AS name
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype)
      AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
  ), user_table AS (
    -- Names are spelled out: inside these functions guard is on the search_path, so a regclass would drop it.
    SELECT c.oid, c.relkind, n.nspname || '.' || c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
  ), found(problem) AS (
    SELECT 'disabled trigger ' || n.nspname || '.' || c.relname || '.' || t.tgname
    FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE NOT t.tgisinternal AND t.tgenabled <> 'O'
      AND (c.relnamespace = 'guard'::regnamespace
           OR coalesce(pg_partition_root(c.oid), c.oid::regclass) IN (SELECT g.target FROM guard.guarded g))
    UNION ALL
    SELECT 'guarded table has been dropped: ' || coalesce(g.name, g.target::text) FROM guard.guarded g
    WHERE NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = g.target)
    UNION ALL
    -- What a table has become since it was protected: partitioned or inherited from, or without its key.
    SELECT 'guarded table ' || g.target::text || ' can no longer be protected: ' || guard.unsupported(g.target) FROM guard.guarded g
    WHERE guard.unsupported(g.target) IS NOT NULL
    UNION ALL
    -- Its triggers were built with the old key (their arguments), so audit rows would be keyed by it.
    SELECT 'guarded table ' || g.target::text || ' has a different primary key from the one its triggers use' FROM guard.guarded g
    WHERE EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = g.target) AND guard.unsupported(g.target) IS NULL
      AND guard.primary_key(g.target) IS DISTINCT FROM g.pk_columns
    UNION ALL
    SELECT 'guarded table without trigger ' || w.name || ': ' || g.target::text
    FROM guard.guarded g CROSS JOIN (VALUES ('!guard_intent'), ('guard_intent_done'), ('guard_row'), ('guard_statement'),
                                            ('guard_truncate')) w(name)
    WHERE EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = g.target)
      AND NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = g.target AND t.tgname = w.name)
    UNION ALL
    SELECT 'guard table without trigger ' || w.t || '.' || w.name
    FROM (VALUES ('guard.audit', 'immutable'), ('guard.audit', 'immutable_truncate'), ('guard.undone', 'immutable'),
                 ('guard.undone', 'immutable_truncate'), ('guard.commit_check', 'at_commit')) w(t, name)
    WHERE NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = w.t::regclass AND t.tgname = w.name)
    UNION ALL
    SELECT b.role::text || ' may execute ' || f.name FROM boundary b CROSS JOIN func f
    WHERE f.nspname = 'guard' AND has_function_privilege(b.role::oid, f.oid, 'EXECUTE') AND f.name <> ALL (b.may_execute)
    UNION ALL
    SELECT b.role::text || ' may execute ' || f.name || ', which runs as its owner' FROM boundary b CROSS JOIN func f
    WHERE f.nspname <> 'guard' AND f.prosecdef AND has_function_privilege(b.role::oid, f.oid, 'EXECUTE')
      AND f.oid NOT IN (SELECT a.fn FROM guard.allowed_function a)
    UNION ALL
    SELECT a.fn::text || ' was allowed, but has changed since' FROM guard.allowed_function a
    WHERE md5(pg_get_functiondef(a.fn)) IS DISTINCT FROM a.definition_md5
    UNION ALL
    -- A cascade runs as part of the agent's statement, but on a table with no guard nothing charges,
    -- records or can undo what it deletes or rewrites there.
    -- By table: a partitioned table has the constraint once more for each of its partitions.
    SELECT DISTINCT 'changing ' || k.parent::text || ' cascades into ' || k.child::text || ', which is not guarded'
    FROM (SELECT coalesce(pg_partition_root(c.confrelid), c.confrelid::regclass) AS parent,
                 coalesce(pg_partition_root(c.conrelid), c.conrelid::regclass) AS child
          FROM pg_constraint c
          WHERE c.contype = 'f' AND (c.confdeltype IN ('c', 'n', 'd') OR c.confupdtype IN ('c', 'n', 'd'))) k
    WHERE k.parent IN (SELECT g.target FROM guard.guarded g) AND k.child NOT IN (SELECT g.target FROM guard.guarded g)
    UNION ALL
    SELECT 'guard_worker may create large objects' WHERE has_function_privilege('guard_worker', 'pg_catalog.lo_create(oid)', 'EXECUTE')
      OR has_function_privilege('guard_worker', 'pg_catalog.lo_creat(integer)', 'EXECUTE')
      OR has_function_privilege('guard_worker', 'pg_catalog.lo_from_bytea(oid,bytea)', 'EXECUTE')
    UNION ALL
    -- has_table_privilege sees only grants on a whole table; a grant on some of its columns counts too.
    SELECT b.role::text || ' may change ' || u.name FROM boundary b CROSS JOIN user_table u
    WHERE CASE WHEN u.relkind IN ('r', 'p', 'v', 'm', 'f') THEN has_table_privilege(b.role::oid, u.oid, 'INSERT,UPDATE,DELETE')
                                                             OR has_any_column_privilege(b.role::oid, u.oid, 'INSERT,UPDATE') END
      AND NOT (b.role = 'guard_worker'::regrole AND u.oid IN (SELECT g.target FROM guard.guarded g))
    UNION ALL
    -- UPDATE on a sequence allows setval, which can make the application's next inserts collide.
    SELECT b.role::text || ' may set sequence ' || u.name FROM boundary b CROSS JOIN user_table u
    WHERE u.relkind = 'S' AND has_table_privilege(b.role::oid, u.oid, 'UPDATE')
    UNION ALL
    SELECT b.role::text || ' may truncate, reference or add triggers to ' || u.name FROM boundary b CROSS JOIN user_table u
    WHERE CASE WHEN u.relkind IN ('r', 'p') THEN has_table_privilege(b.role::oid, u.oid, 'TRUNCATE,REFERENCES,TRIGGER')
                                               OR has_any_column_privilege(b.role::oid, u.oid, 'REFERENCES') END
    UNION ALL
    SELECT b.role::text || ' may read guard.' || c.relname FROM boundary b CROSS JOIN pg_class c
    WHERE c.relnamespace = 'guard'::regnamespace
      AND CASE WHEN c.relkind IN ('r', 'p', 'v', 'm') THEN has_any_column_privilege(b.role::oid, c.oid, 'SELECT') END
    UNION ALL
    -- The strikes are kept in sequences: a role that could set one could take a strike back.
    SELECT b.role::text || ' may use the sequence guard.' || c.relname FROM boundary b CROSS JOIN pg_class c
    WHERE c.relnamespace = 'guard'::regnamespace AND c.relkind = 'S' AND has_sequence_privilege(b.role::oid, c.oid, 'USAGE,SELECT,UPDATE')
    UNION ALL
    SELECT b.role::text || ' may create in schema ' || n.nspname FROM boundary b CROSS JOIN pg_namespace n
    WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' AND has_schema_privilege(b.role::oid, n.oid, 'CREATE')
    UNION ALL
    SELECT b.role::text || ' may create schemas or temporary tables in this database' FROM boundary b
    WHERE has_database_privilege(b.role::oid, current_database(), 'CREATE,TEMPORARY')
    UNION ALL
    SELECT 'any role may connect to this database' FROM pg_database d
    WHERE d.datname = current_database() AND (d.datacl IS NULL OR EXISTS (
      SELECT 1 FROM aclexplode(d.datacl) a WHERE a.grantee = 0 AND a.privilege_type IN ('CONNECT', 'TEMPORARY')))
    UNION ALL
    SELECT r.rolname || ' has attributes it must not have' FROM pg_roles r
    WHERE r.rolname IN ('guard_worker', 'guard_keeper', 'guard_broker')
      AND (r.rolsuper OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls OR r.rolcanlogin
           OR (r.rolcreaterole AND r.rolname <> 'guard_broker'))
    UNION ALL
    SELECT m.member::regrole::text || ' holds ' || m.roleid::regrole::text FROM pg_auth_members m
    WHERE m.member IN (SELECT b.role::oid FROM boundary b)
      AND NOT (m.member = 'guard_keeper'::regrole AND NOT m.admin_option
               AND m.roleid IN ('pg_signal_backend'::regrole, 'pg_read_all_stats'::regrole))
      AND NOT (m.member = 'guard_broker'::regrole AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
               AND (m.roleid = 'guard_worker'::regrole OR m.roleid IN (SELECT a.oid FROM agent_login a)))
    UNION ALL
    SELECT 'agent login too strong: ' || a.rolname FROM agent_login a
    WHERE a.rolsuper OR a.rolcreaterole OR a.rolcreatedb OR a.rolreplication OR a.rolbypassrls
    UNION ALL
    SELECT 'agent login ' || a.rolname || ' holds ' || o.roleid::regrole::text FROM agent_login a
    JOIN pg_auth_members o ON o.member = a.oid AND o.roleid <> 'guard_worker'::regrole
    WHERE o.inherit_option OR o.set_option OR o.admin_option
    UNION ALL
    SELECT a.rolname || ' holds guard_worker through another role' FROM agent_login a
    WHERE NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = a.oid AND m.roleid = 'guard_worker'::regrole)
    UNION ALL
    SELECT 'agent login not built by the broker: ' || a.rolname FROM agent_login a
    WHERE a.rolcanlogin AND (a.rolvaliduntil IS NULL OR a.rolvaliduntil = 'infinity' OR a.rolconnlimit < 0 OR NOT EXISTS (
      SELECT 1 FROM pg_db_role_setting s WHERE s.setrole = a.oid AND s.setconfig::text LIKE '%temp_file_limit=%'
        AND s.setconfig::text LIKE '%log_statement=all%'))
    UNION ALL
    SELECT 'superuser logins changed' WHERE ARRAY(SELECT r.rolname FROM pg_roles r WHERE r.rolsuper AND r.rolcanlogin ORDER BY r.rolname)
      IS DISTINCT FROM (SELECT g.superuser_logins FROM guard.gate g)
    UNION ALL
    SELECT 'guard functions or triggers changed' WHERE guard.fingerprint() IS DISTINCT FROM (SELECT g.fingerprint FROM guard.gate g)
    UNION ALL
    -- A prepared transaction keeps its locks and its writes with no session left for the keeper to end.
    SELECT 'max_prepared_transactions is above 0' WHERE current_setting('max_prepared_transactions')::integer > 0
  ) SELECT coalesce(jsonb_agg(problem ORDER BY problem), '[]'::jsonb) FROM found
$$;

CREATE OR REPLACE FUNCTION guard.boundary_status() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  WITH open_database AS (
    SELECT d.datname FROM pg_database d
    WHERE d.datallowconn AND d.datname <> current_database() AND (d.datacl IS NULL OR EXISTS (
      SELECT 1 FROM aclexplode(d.datacl) a WHERE a.grantee = 0 AND a.privilege_type = 'CONNECT'))
  )
  SELECT jsonb_build_object('frozen', g.frozen_reason, 'frozen_by', g.frozen_by, 'frozen_at', g.frozen_at,
    'problems', guard.boundary_problems(),
    'logins', (SELECT coalesce(jsonb_agg(jsonb_build_object('login', r.rolname, 'rows_left', b.rows_left,
        'bytes_left', b.bytes_left, 'valid_until', r.rolvaliduntil,
        'sessions', (SELECT count(*) FROM pg_stat_activity a WHERE a.usesysid = r.oid),
        'strikes', (guard.strikes(r.rolname)).strikes, 'stopped', guard.stopped(r.rolname)) ORDER BY r.rolname), '[]'::jsonb)
      FROM guard.agent_logins() x JOIN pg_roles r ON r.oid = x LEFT JOIN guard.budget b ON b.login = r.rolname
      WHERE r.rolcanlogin OR guard.stopped(r.rolname)),
    'open_databases', (SELECT coalesce(jsonb_agg(o.datname ORDER BY o.datname), '[]'::jsonb) FROM open_database o))
  FROM guard.gate g
$$;

CREATE OR REPLACE FUNCTION guard.boundary_check() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
DECLARE found jsonb := guard.boundary_problems();
BEGIN
  IF jsonb_array_length(found) > 0 THEN
    PERFORM guard.freeze(left((SELECT string_agg(p, '; ' ORDER BY p) FROM jsonb_array_elements_text(found) p), 4000));
  END IF;
  RETURN guard.boundary_status();
END $$;

-- The keeper's rules, as the keeper (pg_signal_backend can end only non-superuser sessions). Beyond
-- 011's: an agent holding or waiting for a table lock stronger than ROW EXCLUSIVE ends at once, since
-- such a lock, or a request for one, stops the application's own statements on that table. And every
-- session of a stopped login ends, whatever it is doing.
CREATE OR REPLACE FUNCTION guard.end_stuck_sessions(p_idle_seconds integer, p_transaction_seconds integer, p_frozen boolean)
RETURNS jsonb LANGUAGE sql SET search_path = pg_catalog, guard, pg_temp AS $$
  WITH session AS (
    SELECT a.pid, r.rolname AS login, CASE
        WHEN NOT r.rolcanlogin OR r.rolvaliduntil <= clock_timestamp() THEN 'login expired'
        WHEN guard.stopped(r.rolname) THEN 'login stopped'
        WHEN p_frozen AND a.backend_xid IS NOT NULL THEN 'writing while frozen'
        WHEN EXISTS (SELECT 1 FROM pg_locks l WHERE l.pid = a.pid AND l.locktype = 'relation'
                       AND l.mode IN ('ShareUpdateExclusiveLock', 'ShareLock', 'ShareRowExclusiveLock', 'ExclusiveLock', 'AccessExclusiveLock'))
          THEN 'holding or waiting for a table lock'
        WHEN a.state LIKE 'idle in transaction%' AND clock_timestamp() - a.state_change > make_interval(secs => p_idle_seconds)
          THEN 'idle in transaction'
        WHEN clock_timestamp() - a.xact_start > make_interval(secs => p_transaction_seconds) THEN 'transaction too long'
        WHEN a.state = 'idle' AND clock_timestamp() - a.state_change > make_interval(secs => p_idle_seconds)
          AND EXISTS (SELECT 1 FROM pg_locks l WHERE l.pid = a.pid AND l.locktype = 'advisory') THEN 'idle holding an advisory lock'
      END AS reason
    FROM pg_stat_activity a JOIN pg_roles r ON r.oid = a.usesysid
    WHERE a.datname = current_database() AND a.backend_type = 'client backend' AND r.oid IN (SELECT guard.agent_logins())
  ), ended AS (
    SELECT s.pid, s.login, s.reason, pg_terminate_backend(s.pid) AS signalled FROM session s WHERE s.reason IS NOT NULL
  )
  SELECT coalesce(jsonb_agg(jsonb_build_object('pid', e.pid, 'login', e.login, 'reason', e.reason) ORDER BY e.pid), '[]'::jsonb)
  FROM ended e WHERE e.signalled
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA guard FROM PUBLIC;
GRANT USAGE ON SCHEMA guard TO guard_worker, guard_keeper, guard_broker;
GRANT EXECUTE ON FUNCTION guard.status(), guard.declare(regclass, bigint) TO guard_worker;
GRANT EXECUTE ON FUNCTION guard.report(name), guard.timeline(name), guard.freeze(text), guard.stop_agent(name), guard.stopped(name),
  guard.undo(name, bigint), guard.undo_logins(name[], bigint), guard.boundary_check(), guard.boundary_status(), guard.end_stuck_sessions(integer, integer, boolean),
  guard.agent_logins() TO guard_keeper;
GRANT EXECUTE ON FUNCTION guard.issue_budget(name, bigint, bigint, numeric, integer), guard.stop_agent(name) TO guard_broker;

-- A rerun brings the tables already protected up to this file's triggers and to their primary keys
-- as they now are, and clears intents an earlier version left behind (any of a transaction that is
-- over). A table that can no longer be protected is left as it is, for the self-check to report.
SELECT guard.protect(c.oid) FROM guard.guarded g JOIN pg_class c ON c.oid = g.target WHERE guard.unsupported(c.oid) IS NULL;
DELETE FROM guard.intent i WHERE txid_status(i.tx) IS DISTINCT FROM 'in progress';

UPDATE guard.gate SET fingerprint = guard.fingerprint(),
  superuser_logins = ARRAY(SELECT rolname FROM pg_roles WHERE rolsuper AND rolcanlogin ORDER BY rolname);
COMMIT;
