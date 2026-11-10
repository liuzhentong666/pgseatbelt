# pgseatbelt

[中文](README.zh-CN.md)

**A seatbelt for Postgres.** It limits what an AI agent's own PostgreSQL login can do to an
existing application's tables, even when the agent writes raw SQL, without changing the
application. Like a seatbelt, it stays out of the way of normal work and limits the damage when
something goes wrong: an agent that keeps going past its limits is stopped, and what it changed can
be rolled back to the state before the trouble began.

Inside the database it goes by a short name, `guard`: the `guard` schema, `guard.sql`, `guard.py`,
and the roles `guard_worker`, `guard_keeper` and `guard_broker`.

**Status:** a prototype (2026-11-10). Tested on one laptop with the attack suite below, reviewed
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
- **Strikes, then a stop.** Each refused attempt to go past a limit (AB002, AB003, AB007) is a strike
  against the login, and the refusal tells the agent how many it has left. Catching the error or
  rolling back does not take a strike back. At the last one (3 by default) the login is stopped
  (AB001): it writes nothing more, the transaction of that last strike keeps nothing, the keeper ends
  its sessions, and `run` takes away its right to connect.
- **Undo and report.** `undo` puts a login's changes back newest first, checking only the columns it
  changed, and stops at newer work (AB005). It undoes everything the login did, or goes back to a
  point and keeps the work before it: the login's first strike, or any of its transactions. `report`
  says what a login changed, from the audit log, with its strikes and its transactions in order.
- **A keeper.** Its self-check reads the catalog and freezes agents' writes when anything is wrong.
  It ends stuck agent sessions: expired logins, stopped logins, writes while frozen, table locks, a
  transaction idle for 60 s or open for 300 s, and idle sessions holding advisory locks. Only the
  database owner can unfreeze.
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
python guard.py run --database APP_DB --rows 1000 --bytes 10000000 --hours 8 [--strikes 3] [--undo-on-stop] -- <the agent's command>
python guard.py keep --database APP_DB
python guard.py status --database APP_DB
python guard.py report --database APP_DB LOGIN [--timeline]
python guard.py undo --database APP_DB LOGIN [--since-strike | --from CHANGE]
python guard.py freeze --database APP_DB "reason"
python guard.py unfreeze --database APP_DB
python guard.py backup --database APP_DB --to FOLDER
python guard.py uninstall --database APP_DB --audit-to FOLDER [--drop-roles]
```

Connection settings come from `connection.local.json` (copy `connection.example.json`). Every command
needs `--database`.

Before installing on a real application:

- Installing revokes CONNECT and TEMPORARY on that database from PUBLIC, and the creation of large
  objects, so any login that relies on them needs its own grant first.
- Protected tables need a primary key. Prefer bigint keys, since agents can use up sequence values.
- An agent with a shell must run in a container or under a separate OS account: run
  `python check_sandbox.py` inside it.

## When an agent goes wrong

**The guard notices.** An attempt to go past a limit is refused, so it changes nothing, and it is a
strike. A login that reaches its last strike is stopped at once, inside the database. `run` then
takes away its right to connect, reports the stop on stderr, and exits with 3 if the agent's command
itself exited with 0. With `--undo-on-stop`, `run` also undoes what the login changed since its first
strike, which is the state before it first went past a limit. Changes it made before that strike
stay. Without the option nothing is undone until you say so:

```
python guard.py undo --database APP_DB LOGIN --since-strike
```

**You notice.** An agent can do the wrong thing inside its limits, and then there is no strike. List
its transactions, pick the first wrong one, and undo from there. Each transaction is listed with the
number of its first change, and `--from` takes that number:

```
python guard.py report --database APP_DB LOGIN --timeline
python guard.py undo --database APP_DB LOGIN --from CHANGE
```

`undo` without an option puts back everything the login did. Every form of `undo` stops the login
first, works after the login is retired, and stops at a row that someone else has changed since
(AB005) instead of overwriting it.

## Uninstall

`guard.py uninstall`, run as the superuser owner, takes the guard out of one database:

1. It freezes agents and ends their sessions.
2. It saves the audit log, undo records and budgets to a JSON file in `--audit-to`. That file is the
   only record of what agents did.
3. In one transaction, it drops the guard's triggers, revokes every grant made to the three guard
   roles, gives PUBLIC back exactly the access it had before the first install (recorded then in
   `guard.installed_over`), and drops the `guard` schema.

Rows the agents changed stay as they are, so run `undo` first for anything that should go back.

Without `--drop-roles`, the three roles and the agent logins stay on the server. The logins can no
longer write, but they can still connect wherever PUBLIC may. With `--drop-roles`, those roles and
logins are dropped too. That is refused, with nothing changed, while another database on the same
server still has the guard.

## Evidence

`python tests/check_guard.py` builds a temporary database with an application's schema and rows,
installs the guard, and attacks it with real logins over real connections. The attacks are
Forkpoint's boundary suite (`scripts/agent_login_attacks.py` at 1273af5), ported group by group,
plus a review group: COPY, upsert, MERGE, writable CTEs, and a privileged function called in a loop.
A plain login with the same grants that does not hold `guard_worker` must get through the same data
attacks, which shows the attacks work.

A strikes group checks the stop and the ways back: a login is stopped at its last strike, the
transaction of that strike keeps nothing, a strike survives a caught error, an agent cannot touch
its own count, the keeper ends a stopped login's sessions, and `undo` goes back to the first strike
or to a chosen transaction. The same is checked through `guard.py run`, `report` and `undo`.

Result on 2026-11-10 (`results/attack-results.json`): 301 held, 15 NOTEs, 0 gaps, with every test
database, role and login dropped afterwards. The groups not ported need Forkpoint's branches: the
read-set merges and the checks on files, commits and history. The mapping and the earlier runs are
in the local forkpoint-experiments repository (`experiments/guard_full_suite`,
`experiments/boundary_without_branches`).

`python tests/check_uninstall.py` installs the guard in two temporary databases, lets an agent login
change a row in each, and uninstalls it. One database has PostgreSQL's default access; the owner of
the other had already taken CONNECT, TEMPORARY and large objects from PUBLIC. Uninstalling must put
every right, schema and trigger back exactly, compared by what the rights mean. The first database
is then installed and uninstalled a second time, and the last uninstall runs from the command line
with `--drop-roles`. Result on 2026-11-10 (`results/uninstall-results.json`): 14 held, 0 gaps.

## Tested on

Only this setup, on 2026-11-10:

- One Windows 11 laptop (build 26200).
- PostgreSQL 16.15, the Ubuntu 24.04.2 package, running in WSL 2 (2.6.3, kernel 6.6.87.2).
- Python 3.10.11 on Windows, driving psql 16.15 inside WSL through `wsl.exe`.
- The owner connects over the Unix socket; agent logins connect to 127.0.0.1 with SCRAM passwords.

It needs PostgreSQL 16 or later, because it uses 16's role options. Only 16.15 has been tried.

## What it does not do

- **Reads are not protected.**
- **It does not judge what a change means.** The only behaviour it treats as abnormal is an attempt
  to go past a limit the login was issued with. An agent that does damage inside its limits gets no
  strike: a person has to notice, and `undo --from` puts it back.
- **Stopping has edges.** Holding locks earns no strike. With `keep` alone and no `run`, a stopped
  login can still connect and read until the keeper's next round ends its session. After a server
  crash a login that had a strike can come back with up to 32 more, which stops it.
- **Availability.** An agent can slow the application: it can hold rows until the keeper's 60 or
  300 s rules end its session, lock a whole table until the keeper's next round (or queue the
  application's reads behind a lock it is waiting for), and do it again after reconnecting, until
  its login expires or is stopped.
- **No staging.** An agent's write is live when it commits. Stale reads are the agent's own job
  (`SELECT ... FOR UPDATE`).
- **Undo has gaps.** It does not handle GENERATED ALWAYS identity or generated columns, or a table
  whose columns changed since; an error during undo undoes nothing. No command redoes what an undo
  put back, which is why `--undo-on-stop` is a choice and not the default. It goes back to the
  login's first strike, and no further.
- **Trusted parts.** The broker, the keeper and the owner's credentials must be out of agents' reach.
- **Not yet tested:** psql on native Linux or macOS, PostgreSQL 17 or later, a remote server over
  TLS, partitioned tables, a real container, a second machine, and an outside review.

## Origin

Rebuilt from Forkpoint's agent boundary (`sql/011_agent_boundary.sql` and `agent_boundary.py` at
1273af5), which works only on top of Forkpoint's own version engine. This one needs no engine.
`db.py` and `check_sandbox.py` are copied from Forkpoint. MIT licensed.
