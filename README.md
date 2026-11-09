# agent-guard

Limits what an AI agent's own PostgreSQL login can do to an existing application's tables, even
when the agent writes raw SQL, without changing the application. "agent-guard" is a working name.

**Status:** a prototype (2026-11-09). Tested on one laptop with the attack suite below, reviewed
only by the assistant that wrote it, and not yet used on real data.

## Why

Agents on ordinary tasks have deleted or rewritten data nobody asked them to touch. A rule that
depends on someone watching, or on the agent behaving well, does not stop that. This guard puts the
limits on the agent's database login, decides with fixed code, records who changed what, and makes
changes undoable.

## What it does

- **Its own login per agent.** `guard.py run` issues a login that expires, holds `guard_worker`,
  logs every statement, and can raise neither its limits nor its privileges. The agent writes the
  application's tables directly.
- **Limits on every write.** Triggers on each protected table charge the login's budget of rows and
  bytes, fixed when it is issued with no top-ups (AB002, AB003). They also apply a share: beyond its
  first 20 rows, a login may change at most 10% of a table by default, and within those 20 at most
  half of the rows that were there (AB007). Writes are refused while frozen (AB000) or outside READ
  COMMITTED (AB006), TRUNCATE is refused, and every change goes into `guard.audit` under the login.
- **A check at commit.** A write made before a freeze cannot commit after it.
- **Undo and report.** `undo` puts a login's changes back newest first, checking only the columns it
  changed, and stops at newer work (AB005). `report` says what a login changed, from the audit log.
- **A keeper.** Its self-check reads the catalog and freezes agents' writes when anything is wrong.
  It ends stuck agent sessions: expired logins, writes while frozen, table locks, a transaction idle
  for 60 s or open for 300 s, and idle sessions holding advisory locks. Only the database owner can
  unfreeze.
- **The application stays as it is.** Its own logins are not limited or recorded. Each of its writes
  to a protected table still passes through the trigger code, about 40 us per row as measured.

## Use

As the database's superuser owner, protect the tables agents may write:

```
python guard.py install --database APP_DB --protect shop.products --protect shop.orders
```

Then grant `guard_worker` SELECT on whatever agents may read, and allow any SECURITY DEFINER function
agents may call, after reading it: `SELECT guard.allow('shop.restock(bigint,integer)', 'why');`.

```
python guard.py run --database APP_DB --rows 1000 --bytes 10000000 --hours 8 -- <the agent's command>
python guard.py keep --database APP_DB
python guard.py status --database APP_DB
python guard.py report --database APP_DB LOGIN
python guard.py undo --database APP_DB LOGIN
python guard.py freeze --database APP_DB "reason"
python guard.py unfreeze --database APP_DB
python guard.py backup --database APP_DB --to FOLDER
```

Connection settings come from `connection.local.json` (copy `connection.example.json`). Every command
needs `--database`.

Before installing on a real application:

- Installing revokes CONNECT and TEMPORARY on that database from PUBLIC, and the creation of large
  objects, so any login that relies on them needs its own grant first.
- Protected tables need a primary key. Prefer bigint keys, since agents can use up sequence values.
- An agent with a shell must run in a container or under a separate OS account: run
  `python check_sandbox.py` inside it.

## Evidence

`python tests/check_guard.py` builds a temporary database with an application's schema and rows,
installs the guard, and attacks it with real logins over real connections. The attacks are
Forkpoint's boundary suite (`scripts/agent_login_attacks.py` at 1273af5), ported group by group,
plus a review group: COPY, upsert, MERGE, writable CTEs, and a privileged function called in a loop.
A plain login with the same grants that does not hold `guard_worker` must get through the same data
attacks, which shows the attacks work.

Result on 2026-11-09 (`results/attack-results.json`): 258 held, 15 NOTEs, 0 gaps, with every test
database, role and login dropped afterwards. The groups not ported need Forkpoint's branches: the
read-set merges and the checks on files, commits and history. The mapping and the earlier runs are
in the local forkpoint-experiments repository (`experiments/guard_full_suite`,
`experiments/boundary_without_branches`).

## What it does not do

- **Reads are not protected.**
- **Availability.** An agent can slow the application: it can hold rows until the keeper's 60 or
  300 s rules end its session, lock a whole table until the keeper's next round (or queue the
  application's reads behind a lock it is waiting for), and do it again after reconnecting, until
  its login expires or is stopped.
- **No staging.** An agent's write is live when it commits. Stale reads are the agent's own job
  (`SELECT ... FOR UPDATE`).
- **Undo has gaps.** It does not handle GENERATED ALWAYS identity or generated columns, or a table
  whose columns changed since; an error during undo undoes nothing.
- **Trusted parts.** The broker, the keeper and the owner's credentials must be out of agents' reach.
- **Not yet tested:** partitioned tables, a real container, a second machine, an outside review.

## Origin

Rebuilt from Forkpoint's agent boundary (`sql/011_agent_boundary.sql` and `agent_boundary.py` at
1273af5), which works only on top of Forkpoint's own version engine. This one needs no engine.
`db.py` and `check_sandbox.py` are copied from Forkpoint. MIT licensed.
