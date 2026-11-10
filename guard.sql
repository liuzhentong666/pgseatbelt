-- guard: the agent boundary of Forkpoint's sql/011 (1273af5) on ordinary tables, with no branches,
-- merges or history. A prototype; tests/check_guard.py attacks it (README.md has the results).
--
-- Run as a superuser owner of the application's database (re-runnable). Then, as that owner, for
-- every table agents may write: SELECT guard.protect('<table>'); and grant guard_worker SELECT on
-- whatever agents may read. Rerunning this file accepts the guard's functions as they now are (the
-- fingerprint), but never reopens writes: only the owner's guard.unfreeze() does.
--
-- * Agents are logins the broker issues; each holds guard_worker. They write the live tables
--   directly. Triggers on each protected table charge the login's budget (rows and bytes, no
--   top-ups), apply 011's table share (AB007), refuse while frozen (AB000) or outside READ COMMITTED
--   (AB006), and append every change to guard.audit with the login from session_user.
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
--   back to a point: the login's first strike, or any transaction guard.timeline lists.
-- * Codes: AB000 frozen; AB001 stopped; AB002 row budget; AB003 storage budget; AB005 changed since
--   (undo); AB006 not READ COMMITTED; AB007 too large a share of a table, or TRUNCATE.
-- * guard.py uninstall takes all of this out again and puts back what guard.installed_over recorded.
BEGIN;
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
  IF (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    GRANT pg_signal_backend, pg_read_all_stats TO guard_keeper;
    GRANT guard_worker TO guard_broker WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
    GRANT SET ON PARAMETER temp_file_limit, log_statement TO guard_broker;
    REVOKE EXECUTE ON FUNCTION pg_catalog.lo_from_bytea(oid, bytea), pg_catalog.lo_create(oid), pg_catalog.lo_creat(integer) FROM PUBLIC;
  END IF;
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
  max_table_share numeric NOT NULL DEFAULT 0.1 CHECK (max_table_share > 0 AND max_table_share <= 1));
-- strikes and struck_from are a retired login's last numbers; a living login's are in its two
-- sequences (guard.strike). A login issued before strikes existed has no sequences: it is refused
-- as before and never counted, until it expires.
ALTER TABLE guard.budget ADD COLUMN IF NOT EXISTS max_strikes integer NOT NULL DEFAULT 3 CHECK (max_strikes >= 1);
ALTER TABLE guard.budget ADD COLUMN IF NOT EXISTS strikes bigint NOT NULL DEFAULT 0;
ALTER TABLE guard.budget ADD COLUMN IF NOT EXISTS struck_from bigint;
-- size_before: the table's row count when the login first wrote it; the share is measured against it.
CREATE TABLE IF NOT EXISTS guard.spend(login name NOT NULL, target regclass NOT NULL, size_before bigint NOT NULL,
  changed bigint NOT NULL DEFAULT 0, existing bigint NOT NULL DEFAULT 0, PRIMARY KEY (login, target));
CREATE TABLE IF NOT EXISTS guard.guarded(target regclass PRIMARY KEY, pk_columns text[] NOT NULL);
-- The columns an agent's UPDATE itself changed, noted before the application's own BEFORE triggers.
-- guard.charge takes each row's out; guard.intent_done clears what a later BEFORE trigger skipped.
CREATE TABLE IF NOT EXISTS guard.intent(tx bigint NOT NULL, target regclass NOT NULL, pk jsonb NOT NULL,
  columns text[] NOT NULL, PRIMARY KEY (tx, target, pk));
CREATE TABLE IF NOT EXISTS guard.commit_check(tx bigint PRIMARY KEY);
CREATE TABLE IF NOT EXISTS guard.audit(id bigserial PRIMARY KEY, login name NOT NULL,
  tx bigint NOT NULL DEFAULT txid_current(), at timestamptz NOT NULL DEFAULT clock_timestamp(),
  target regclass NOT NULL, op text NOT NULL CHECK (op IN ('I', 'U', 'D')), pk jsonb NOT NULL,
  columns text[], before jsonb, after jsonb);
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

-- intent, charge and undo fix every setting an agent could use to change the text to_jsonb writes
-- for a value, so that what is recorded and what undo compares it with are spelled alike.
CREATE OR REPLACE FUNCTION guard.intent() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp SET TimeZone = 'UTC' SET IntervalStyle = 'postgres'
SET extra_float_digits = 1 SET bytea_output = 'hex' SET lc_monetary = 'C' AS $$
DECLARE o jsonb; n jsonb; key jsonb;
BEGIN
  IF NOT guard.is_agent() THEN RETURN NEW; END IF;
  o := to_jsonb(OLD); n := to_jsonb(NEW);
  key := (SELECT jsonb_object_agg(k, o -> k) FROM unnest(TG_ARGV) k);
  INSERT INTO guard.intent VALUES (txid_current(), TG_RELID, key,
    ARRAY(SELECT k FROM jsonb_object_keys(n) k WHERE n -> k IS DISTINCT FROM o -> k ORDER BY k))
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
DECLARE b guard.budget; s guard.spend; o jsonb; n jsonb; key jsonb; cols text[]; row_bytes bigint; table_size bigint; too_much boolean;
BEGIN
  IF NOT guard.is_agent() THEN RETURN NULL; END IF;
  PERFORM guard.gate_open();
  IF TG_OP <> 'INSERT' THEN o := to_jsonb(OLD); END IF;
  IF TG_OP <> 'DELETE' THEN n := to_jsonb(NEW); END IF;
  key := (SELECT jsonb_object_agg(k, coalesce(o, n) -> k) FROM unnest(TG_ARGV) k);
  IF TG_OP = 'UPDATE' THEN
    DELETE FROM guard.intent i WHERE i.tx = txid_current() AND i.target = TG_RELID AND i.pk = key RETURNING i.columns INTO cols;
    cols := coalesce(cols, ARRAY(SELECT k FROM jsonb_object_keys(n) k WHERE n -> k IS DISTINCT FROM o -> k ORDER BY k));
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
  WHERE x.login = session_user AND x.target = TG_RELID RETURNING x.* INTO s;
  IF NOT FOUND THEN
    -- A write no statement trigger saw first (a foreign-key cascade): sized now, this row added back.
    EXECUTE format('SELECT count(*) FROM %s', TG_RELID::regclass) INTO table_size;
    INSERT INTO guard.spend VALUES (session_user, TG_RELID,
      table_size + CASE TG_OP WHEN 'DELETE' THEN 1 WHEN 'INSERT' THEN -1 ELSE 0 END, 1, CASE WHEN TG_OP = 'INSERT' THEN 0 ELSE 1 END)
    RETURNING * INTO s;
  END IF;
  -- 011's rule: beyond a login's first 20 rows, at most max_table_share of the table; within them,
  -- at most half of the rows that were there (and always one); adding rows alone is free up to 20.
  IF b.max_table_share < 1 AND NOT (s.changed <= 20 AND s.existing = 0) THEN
    too_much := CASE WHEN s.changed > 20 THEN s.changed > b.max_table_share * s.size_before
                     ELSE s.existing > greatest(1, s.size_before / 2) END;
    IF too_much THEN
      PERFORM guard.refuse('AB007', 'Too large a share of ' || TG_RELID::regclass::text,
        jsonb_build_object('login', session_user, 'changed_by_this_login', s.changed, 'existing_changed_by_this_login', s.existing,
          'size_before', s.size_before, 'max_table_share', b.max_table_share,
          'rule', CASE WHEN s.changed > 20 THEN 'beyond 20 rows, at most max_table_share of the table'
                       ELSE 'within 20 rows, at most half of what was there' END),
        'Nothing in this statement was kept. Change less. If the task really rewrites this much, a login issued with a '
        'larger max_table_share has to do it, which is decided before it starts; or the database owner can.');
    END IF;
  END IF;
  INSERT INTO guard.audit(login, target, op, pk, columns, before, after)
  VALUES (session_user, TG_RELID, left(TG_OP, 1), key, cols, o, n);
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

-- The owner protects a table: triggers, and guard_worker's grants on it and its sequences. A trigger
-- needs a lock that stops the application's writes, and a wait for one queues them too, so a busy
-- table fails fast instead (rerun it).
CREATE OR REPLACE FUNCTION guard.protect(p_table regclass) RETURNS void LANGUAGE plpgsql
SET search_path = pg_catalog, guard, pg_temp SET lock_timeout = '2s' AS $$
DECLARE keys text[]; args text; seq record;
BEGIN
  SELECT array_agg(a.attname::text ORDER BY k.ord) INTO keys
  FROM pg_index i CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
  WHERE i.indrelid = p_table AND i.indisprimary;
  IF keys IS NULL THEN RAISE EXCEPTION 'A primary key is required: %', p_table; END IF;
  INSERT INTO guard.guarded VALUES (p_table, keys) ON CONFLICT (target) DO NOTHING;
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
  FOR seq IN SELECT d.objid::regclass AS s FROM pg_depend d JOIN pg_class c ON c.oid = d.objid AND c.relkind = 'S'
             WHERE d.refobjid = p_table AND d.deptype IN ('a', 'i') LOOP
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO guard_worker', seq.s);
  END LOOP;
  UPDATE guard.gate SET fingerprint = guard.fingerprint();  -- the owner accepts the new triggers
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
CREATE OR REPLACE FUNCTION guard.issue_budget(p_login name, p_rows bigint, p_bytes bigint, p_share numeric DEFAULT 0.1,
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

-- Undo a login's changes newest first, checking and putting back only the columns it changed. Stops
-- at the first change something newer has touched, and says which: undoing older ones around it
-- would leave a state nobody had. A rerun picks up where this stopped. With p_from, only that change
-- and the login's later ones are undone, and its older ones are kept: p_from is the "from" of a
-- transaction in guard.timeline, or the login's struck_from, the state before its first strike.
DROP FUNCTION IF EXISTS guard.undo(name);  -- as it was before p_from
CREATE OR REPLACE FUNCTION guard.undo(p_login name, p_from bigint DEFAULT NULL) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp SET TimeZone = 'UTC' SET IntervalStyle = 'postgres'
SET extra_float_digits = 1 SET bytea_output = 'hex' SET lc_monetary = 'C' AS $$
DECLARE a guard.audit; keys text[]; doc jsonb; now_doc jsonb; key_where text; set_list text; n integer := 0; refused jsonb;
BEGIN
  FOR a IN SELECT x.* FROM guard.audit x WHERE x.login = p_login AND x.id >= coalesce(p_from, 0)
             AND NOT EXISTS (SELECT 1 FROM guard.undone u WHERE u.audit_id = x.id) ORDER BY x.id DESC LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = a.target) THEN
      refused := jsonb_build_object('code', 'AB005', 'message', 'The table this login changed has been dropped since',
        'table', a.target::text, 'key', a.pk, 'audit_id', a.id);
      EXIT;
    END IF;
    SELECT g.pk_columns INTO keys FROM guard.guarded g WHERE g.target = a.target;
    doc := coalesce(a.after, a.before);
    key_where := (SELECT string_agg(format('t.%I = (jsonb_populate_record(NULL::%s, %L::jsonb)).%I', k, a.target, doc, k), ' AND ')
                  FROM unnest(keys) k);
    EXECUTE format('SELECT to_jsonb(t) FROM %s t WHERE %s FOR UPDATE', a.target, key_where) INTO now_doc;
    IF (a.op = 'I' AND now_doc IS DISTINCT FROM a.after)
       OR (a.op = 'D' AND now_doc IS NOT NULL)
       OR (a.op = 'U' AND (now_doc IS NULL OR EXISTS (SELECT 1 FROM unnest(a.columns) k WHERE now_doc -> k IS DISTINCT FROM a.after -> k))) THEN
      refused := jsonb_build_object('code', 'AB005', 'message', 'A row changed after this login changed it',
        'table', a.target::text, 'key', a.pk, 'audit_id', a.id, 'columns', a.columns, 'now', now_doc, 'left_by_login', a.after);
      EXIT;
    END IF;
    IF a.op = 'I' THEN
      EXECUTE format('DELETE FROM %s t WHERE %s', a.target, key_where);
    ELSIF a.op = 'D' THEN
      EXECUTE format('INSERT INTO %s SELECT (jsonb_populate_record(NULL::%s, %L::jsonb)).*', a.target, a.target, a.before);
    ELSIF cardinality(a.columns) > 0 THEN
      set_list := (SELECT string_agg(format('%I = (jsonb_populate_record(NULL::%s, %L::jsonb)).%I', k, a.target, a.before, k), ', ')
                   FROM unnest(a.columns) k);
      EXECUTE format('UPDATE %s t SET %s WHERE %s', a.target, set_list, key_where);
    END IF;
    INSERT INTO guard.undone(audit_id) VALUES (a.id);
    n := n + 1;
  END LOOP;
  RETURN jsonb_build_object('login', p_login, 'from', p_from, 'undone', n, 'refused', refused,
    'remaining', (SELECT count(*) FROM guard.audit x WHERE x.login = p_login AND x.id >= coalesce(p_from, 0)
                  AND NOT EXISTS (SELECT 1 FROM guard.undone u WHERE u.audit_id = x.id)),
    'kept', (SELECT count(*) FROM guard.audit x WHERE x.login = p_login AND x.id < coalesce(p_from, 0)
             AND NOT EXISTS (SELECT 1 FROM guard.undone u WHERE u.audit_id = x.id)));
END $$;

-- What a login really changed, from the audit log and not from anything it says, and its strikes.
-- Works after the login is retired.
CREATE OR REPLACE FUNCTION guard.report(p_login name) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT to_jsonb(s) || jsonb_build_object('login', p_login,
    'changes', (SELECT count(*) FROM guard.audit a WHERE a.login = p_login),
    'changes_since_first_strike', (SELECT count(*) FROM guard.audit a WHERE a.login = p_login AND a.id >= s.struck_from),
    'undone', (SELECT count(*) FROM guard.audit a JOIN guard.undone u ON u.audit_id = a.id WHERE a.login = p_login),
    'first', (SELECT min(a.at) FROM guard.audit a WHERE a.login = p_login),
    'last', (SELECT max(a.at) FROM guard.audit a WHERE a.login = p_login),
    'tables', (SELECT coalesce(jsonb_object_agg(z.t, z.ops), '{}') FROM (
                 SELECT a.target::text AS t, jsonb_build_object('inserted', count(*) FILTER (WHERE a.op = 'I'),
                   'updated', count(*) FILTER (WHERE a.op = 'U'), 'deleted', count(*) FILTER (WHERE a.op = 'D')) AS ops
                 FROM guard.audit a WHERE a.login = p_login GROUP BY a.target) z),
    'budget', (SELECT jsonb_build_object('rows_left', b.rows_left, 'bytes_left', b.bytes_left, 'max_table_share', b.max_table_share)
               FROM guard.budget b WHERE b.login = p_login))
  FROM guard.strikes(p_login) s
$$;

-- A login's transactions, oldest first, for choosing how far back to undo: "from" is a transaction's
-- first change, and guard.undo(login, from) undoes that transaction and all the login did after it.
CREATE OR REPLACE FUNCTION guard.timeline(p_login name) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  SELECT coalesce(jsonb_agg(jsonb_build_object('from', t.from_id, 'at', t.began, 'changes', t.changes, 'undone', t.undone,
      'after_first_strike', coalesce(t.from_id >= s.struck_from, false), 'tables', t.tables) ORDER BY t.from_id), '[]'::jsonb)
  FROM guard.strikes(p_login) s, (
    SELECT min(x.from_id) AS from_id, min(x.began) AS began, sum(x.changes) AS changes, sum(x.undone) AS undone,
           jsonb_object_agg(x.target, jsonb_build_object('inserted', x.inserted, 'updated', x.updated, 'deleted', x.deleted)) AS tables
    FROM (SELECT a.tx, a.target::text AS target, min(a.id) AS from_id, min(a.at) AS began, count(*) AS changes,
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
    SELECT pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
    WHERE p.pronamespace = 'guard'::regnamespace AND NOT t.tgisinternal
  ) x
$$;

-- Everything that must stay true, from the catalog alone. Empty means the guard stands. Agent-written
-- data never reaches it, so no agent can cause a freeze by writing something.
CREATE OR REPLACE FUNCTION guard.boundary_problems() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, guard, pg_temp AS $$
  WITH boundary(role, may_execute) AS (VALUES
    ('guard_worker'::regrole, ARRAY['guard.status()']),
    ('guard_keeper'::regrole, ARRAY['guard.report(name)', 'guard.timeline(name)', 'guard.freeze(text)', 'guard.stop_agent(name)',
      'guard.stopped(name)', 'guard.undo(name,bigint)', 'guard.boundary_check()', 'guard.boundary_status()',
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
      AND (c.relnamespace = 'guard'::regnamespace OR c.oid IN (SELECT g.target FROM guard.guarded g))
    UNION ALL
    SELECT 'guarded table has been dropped: ' || g.target::text FROM guard.guarded g
    WHERE NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = g.target)
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
    SELECT 'changing ' || c.confrelid::regclass::text || ' cascades into ' || c.conrelid::regclass::text || ', which is not guarded'
    FROM pg_constraint c
    WHERE c.contype = 'f' AND c.confrelid IN (SELECT g.target FROM guard.guarded g)
      AND c.conrelid NOT IN (SELECT g.target FROM guard.guarded g)
      AND (c.confdeltype IN ('c', 'n', 'd') OR c.confupdtype IN ('c', 'n', 'd'))
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
GRANT EXECUTE ON FUNCTION guard.status() TO guard_worker;
GRANT EXECUTE ON FUNCTION guard.report(name), guard.timeline(name), guard.freeze(text), guard.stop_agent(name), guard.stopped(name),
  guard.undo(name, bigint), guard.boundary_check(), guard.boundary_status(), guard.end_stuck_sessions(integer, integer, boolean),
  guard.agent_logins() TO guard_keeper;
GRANT EXECUTE ON FUNCTION guard.issue_budget(name, bigint, bigint, numeric, integer), guard.stop_agent(name) TO guard_broker;

-- A rerun brings the tables already protected up to this file's triggers, and clears intents an
-- earlier version left behind (any of a transaction that is over).
SELECT guard.protect(c.oid) FROM guard.guarded g JOIN pg_class c ON c.oid = g.target;
DELETE FROM guard.intent i WHERE txid_status(i.tx) IS DISTINCT FROM 'in progress';

UPDATE guard.gate SET fingerprint = guard.fingerprint(),
  superuser_logins = ARRAY(SELECT rolname FROM pg_roles WHERE rolsuper AND rolcanlogin ORDER BY rolname);
COMMIT;
