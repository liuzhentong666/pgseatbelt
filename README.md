# pgseatbelt

[中文](README.zh-CN.md)

**A seatbelt for Postgres.** It limits what an AI agent's own PostgreSQL login can do to an
existing application's tables, even when the agent writes raw SQL, without changing the
application. Like a seatbelt, it stays out of the way of normal work and limits the damage when
something goes wrong: an agent that keeps going past its limits is stopped, and what it changed can
be rolled back to the state before the trouble began.

Inside the database it goes by a short name, `guard`: the `guard` schema, `guard.sql`, `guard.py`,
and the roles `guard_worker`, `guard_keeper` and `guard_broker`.

**Status:** a prototype (2026-11-14). Tested on one laptop with the attack suite below, reviewed
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
  bytes, fixed when it is issued with no top-ups (AB002, AB003). Writes are refused while frozen
  (AB000) or outside READ COMMITTED (AB006), TRUNCATE is refused, and every change goes into
  `guard.audit` under the login.
- **Declare, then do.** Without saying so first, a login may change a small part of a table: its
  first 20 rows, then a tenth of the table, and within those 20 rows at most half of the rows that
  were there. For more, the agent first declares how many rows of that table it means to change,
  `SELECT guard.declare('shop.orders', 500);`, and is held to its number. A larger change it did
  not declare is refused with the way to declare it, and is no strike (AB009). A statement that
  goes past what it declared is refused and is a strike (AB007): that is the statement which
  touches far more than was meant, such as an UPDATE that lost its WHERE. The number is the
  agent's own, so this is no limit against an agent that means harm. The budget is, and
  `--max-table-share` sets a ceiling on the share of a table that nothing an agent declares lifts.
- **A check at commit.** A write made before a freeze cannot commit after it. The check holds a lock
  that a freeze waits for, and a freeze ends any agent transaction that ran the check early
  (`SET CONSTRAINTS ... IMMEDIATE`), with or without a keeper running.
- **Strikes, then a stop.** Each refused attempt to go past a limit (AB002, AB003, AB007) is a strike
  against the login, and the refusal tells the agent how many it has left. Catching the error or
  rolling back does not take a strike back. At the last one (3 by default) the login is stopped
  (AB001): it writes nothing more, the transaction of that last strike keeps nothing, the keeper ends
  its sessions, and `run` takes away its right to connect.
- **Undo and report.** `undo` puts a login's changes back newest first, checking only the columns it
  changed. A row someone else has changed since is left as it is (AB005) and named, with who changed
  it; everything else goes back. It undoes everything the login did, or goes back to a point and
  keeps the work before it: the login's first strike, or any of its transactions. Several logins
  named together are undone newest first across all of them, so none is in another's way. `report`
  says what a login changed, from the audit log, with its strikes and its transactions in order.
  Both refuse a name no login was ever issued under, so a mistyped name is not read as "changed
  nothing".
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
python guard.py run --database APP_DB --rows 1000 --bytes 10000000 --hours 8 [--max-table-share 0.2] [--strikes 3] [--undo-on-stop] -- <the agent's command>
python guard.py keep --database APP_DB
python guard.py status --database APP_DB
python guard.py report --database APP_DB LOGIN [--timeline]
python guard.py undo --database APP_DB LOGIN [LOGIN ...] [--since-strike | --from CHANGE]
python guard.py freeze --database APP_DB "reason"
python guard.py unfreeze --database APP_DB
python guard.py backup --database APP_DB --to FOLDER
python guard.py unprotect --database APP_DB shop.orders
python guard.py uninstall --database APP_DB --audit-to FOLDER [--drop-roles]
```

Connection settings come from `connection.local.json` (copy `connection.example.json`). Every command
needs `--database`.

Before installing on a real application:

- Installing needs a superuser. For any other role it is refused with nothing changed, because the
  guard would look whole and not work: its keeper could end no session and its broker could issue
  no login. A managed service that gives out no superuser cannot run it yet.
- Installing revokes CONNECT and TEMPORARY on that database from PUBLIC, and the creation of large
  objects, so any login that relies on them needs its own grant first.
- A protected table has to have a primary key. A partitioned table is protected as one table:
  its limits, its audit rows and undo are of the whole table, whichever partition a row is in,
  and partitions added later are covered. Agents write through the table, never a partition
  directly. A partition by itself and a table that other tables inherit from are refused,
  because the guard's triggers would not cover them. Prefer bigint keys, since agents can use up
  sequence values.
- Protecting a table lets agents use the sequences its rows take values from: those its columns
  own (`serial`, identity) and those a column default names, as a dumped schema often has them.
  They can take the next value and never set one. A sequence reached only through a function in
  a default is not found, so grant `guard_worker` USAGE on that one yourself. After adding a
  default to a protected table, rerun `install`.
- Protecting a table waits at most 2 s for its lock, so a busy table fails with nothing changed
  instead of holding up the application; run it again. Rerunning install brings the tables already
  protected up to the current triggers.
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
first and works after the login is retired. It works on tables with generated columns, which
PostgreSQL computes again, and puts a deleted row back under the identity it had.

**When agents worked on the same rows.** `undo` never overwrites newer work. A row that something
else has changed since (another agent, the application, a person) is left as it is, and so are
the login's older changes to that row; everything else is undone. The answer lists each row it
left and who has changed it since (`conflicts`, `blocked_by`), and each transaction it left only
partly undone (`partly_undone_transactions`): check those, since what such a transaction did
together is now only partly there. To take back the rest, undo the agents in the way too, or
settle those rows by hand, and run `undo` again. Agents named together are undone newest first
across all of them, which is the order that leaves none in another's way:

```
python guard.py undo --database APP_DB LOGIN_A LOGIN_B
```

## When the application's schema changes

The self-check finds a protected table that has changed under the guard, and the keeper's next round
freezes agents' writes, as for any other problem. The owner settles it, then runs `unfreeze`.

- **A protected table was dropped.** The problem names it. `python guard.py unprotect --database
  APP_DB shop.orders` says the drop was meant. `report` still names the table, and `undo` passes
  over the changes made to it, which nothing can put back, and counts them in `dropped_tables`.
- **Its primary key changed.** Rerun `install`, which rebuilds the table's triggers with the new
  key. `undo` leaves, with AB005, a change recorded under a key that is no longer the primary key,
  since that key may now name several rows.
- **It became a partition of another table, is inherited from, or lost its primary key.** It can
  no longer be protected: put it back as it was, or take it out with `unprotect`.

`unprotect` is also how a table leaves the guard on purpose. The guard's triggers go, and so does
everything `guard_worker` was granted on the table and on the sequences only it uses, reading
included, so agents can no longer write it. Its audit rows stay, and `undo` still puts them back.

## Uninstall

`guard.py uninstall`, run as the superuser owner, takes the guard out of one database:

1. It freezes agents and ends their sessions.
2. It streams the audit log, undo records and budgets to a JSON file in `--audit-to`, row by row, so
   a large log fits. That file is the only record of what agents did.
3. In one transaction, it drops the guard's triggers, revokes every grant made to the three guard
   roles in that database (on tables and their columns, sequences, functions and procedures,
   schemas, types and large objects, and in default privileges), gives PUBLIC back exactly the access
   it had before the first install (recorded then in `guard.installed_over`), and drops the `guard`
   schema. It waits at most 2 s for each protected table's lock. If anything fails, nothing changes
   and the guard stays installed, frozen.

Rows the agents changed stay as they are, so run `undo` first for anything that should go back.
Uninstalling is refused, with nothing changed, while something outside the guard depends on it (a
view over `guard.audit`, say), because dropping the schema would drop that too.

Without `--drop-roles`, the three roles and the agent logins stay on the server. The logins can no
longer write, but they can still connect wherever PUBLIC may. With `--drop-roles`, those roles and
logins are dropped too, in the same transaction. That is refused, with nothing changed, while
another database on the same server still uses the roles: it still has the guard, or something
there was granted to them.

## Evidence

`python tests/check_guard.py` builds a temporary database with an application's schema and rows,
installs the guard, and attacks it with real logins over real connections. The attacks are
Forkpoint's boundary suite (`scripts/agent_login_attacks.py` at 1273af5), ported group by group,
plus a review group: COPY, upsert, MERGE, writable CTEs, a privileged function called in a loop,
and updates that an application trigger skips. A plain login with the same grants that does not
hold `guard_worker` must get through the same data attacks, which shows the attacks work.

A strikes group checks the stop and the ways back: a login is stopped at its last strike, the
transaction of that strike keeps nothing, a strike survives a caught error, an agent cannot touch
its own count, the keeper ends a stopped login's sessions, and `undo` goes back to the first strike
or to a chosen transaction. The same is checked through `guard.py run`, `report` and `undo`.

A lifecycle group changes the schema under the guard. Protecting a partition by itself, a table others
inherit from or a table with no primary key is refused; a child table added later, a
changed primary key and a dropped table are each found; `undo` leaves a change keyed by a primary
key that is gone, finishes it once the key is back, and passes over a dropped table; only the owner can
`unprotect`; a name no login was issued under is refused; and installing as a role that is not a
superuser is refused with nothing changed.

The undo group also covers a table with a generated column, a table whose identity the database
always generates, and a change the database refuses to take back (AB008): undo leaves that change,
does the rest, says what the database said, and finishes once the cause is gone. With other
agents and the owner changing some of the same rows afterwards, undo leaves just those rows and
the agent's older changes to them, undoes the rest, names each row with who changed it since,
lists the transaction left partly undone, and takes back the rest once the others are undone;
and two agents named together are undone completely, newest first across both.

A sequences group protects tables whose ids come from a sequence that a column default names and no
column owns, one of them in another schema: an agent's insert takes its id from the default, the
agent still cannot set the sequence, and unprotecting one table keeps a sequence another protected
table still uses.

A partitions group protects a partitioned table as one table. An agent writes through the table and
never a partition directly; the share is of the whole table; every change, a row moved between
partitions included, is recorded against the table, and undo puts it all back; a partition added
or dropped later is no problem and stays covered; and a guard trigger disabled on one partition is
found.

A declare group uses logins with no ceiling. A change within the allowance needs no declaration; a
larger one is refused without a strike and says how to declare; declared first, it goes through;
more rows than were declared, and an UPDATE with no WHERE, are refused as strikes; emptying a small
table needs a declaration and can be undone; and nothing an agent declares lifts the operator's
ceiling or stretches the budget.

Result on 2026-11-14 (`results/attack-results.json`): 377 held, 16 NOTEs, 0 gaps, with every test
database, role and login dropped afterwards. The groups not ported need Forkpoint's branches: the
read-set merges and the checks on files, commits and history. The mapping and the earlier runs are
in the local forkpoint-experiments repository (`experiments/guard_full_suite`,
`experiments/boundary_without_branches`).

`python tests/check_uninstall.py` installs the guard in two temporary databases, lets an agent login
change a row in each, and uninstalls it. One database has PostgreSQL's default access; the owner of
the other had already taken CONNECT, TEMPORARY and large objects from PUBLIC. The worker role also
gets a grant on only some columns of a table, a procedure, and default privileges, and one protected
table takes its ids from a sequence in another schema. Uninstalling must
put every right, schema and trigger back exactly, compared by what the rights mean, and must refuse
while a view depends on the guard. The first database is then installed and uninstalled a second
time, after a protected table was dropped, and the last uninstall runs from the command line with
`--drop-roles`, which has to be refused first while the other database still grants the roles
something. Result on 2026-11-14 (`results/uninstall-results.json`): 17 held, 0 gaps.

## Tested on

Only this setup, from 2026-11-09 to 2026-11-14:

- One Windows 11 laptop (build 26200).
- PostgreSQL 16.15, the Ubuntu 24.04.2 package, running in WSL 2 (2.6.3, kernel 6.6.87.2).
- Python 3.10.11 on Windows, driving psql 16.15 inside WSL through `wsl.exe`.
- The owner connects over the Unix socket; agent logins connect to 127.0.0.1 with SCRAM passwords.

It needs PostgreSQL 16 or later, because it uses 16's role options. Only 16.15 has been tried.

## What it does not do

- **Reads are not protected.**
- **It does not judge what a change means.** The only behaviour it treats as abnormal is an attempt
  to go past a limit the login was issued with, or past what it declared itself. An agent that does damage inside its limits gets no
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
- **Undo has gaps.** It leaves the changes it cannot put back, and the login's older changes to the
  same rows: a row someone else changed since, or a primary key the table no longer has (AB005), or
  a change the database itself refuses, such as a constraint added since (AB008, with the
  database's error). It knows rows, not what they mean together, so undoing the rest can leave a
  transaction partly undone, or a later change, by this agent or another, resting on one undone
  underneath it; the answer lists the partly undone transactions, and nothing else warns of this.
  A rerun takes back what was left once the cause is settled. A change to a table dropped since
  cannot be put back at all. A
  column added since takes its default in a row undo puts back. No command redoes what an undo put
  back, which is why `--undo-on-stop` is a choice and not the default. It goes back to the login's
  first strike, and no further.
- **Schema changes are found, not prevented.** Between a change to a protected table and the
  keeper's next round, the guard is as the change left it. A table the owner makes a child of a
  protected table, for one, can be written through its parent with nothing charged or recorded,
  until that round freezes writes.
- **Trusted parts.** The broker, the keeper and the owner's credentials must be out of agents' reach.
- **Not yet tested:** psql on native Linux or macOS, PostgreSQL 17 or later, a remote server over
  TLS, tables partitioned on more than one level, a real container, a second machine, and an
  outside review.

## Origin

Rebuilt from Forkpoint's agent boundary (`sql/011_agent_boundary.sql` and `agent_boundary.py` at
1273af5), which works only on top of Forkpoint's own version engine. This one needs no engine.
`db.py` and `check_sandbox.py` are copied from Forkpoint. MIT licensed.
