# pgseatbelt

[English](README.md)

**Postgres 的安全带。** 它限制 AI Agent 自己的 PostgreSQL 登录能对已有应用的表做什么，即使 Agent 自己写 SQL 也一样，而且不需要改动应用。就像安全带一样，它不妨碍正常工作，只在出问题时限制损害：一再越过限制的 Agent 会被停用，它改过的数据可以回滚到出问题之前的状态。

在数据库内部它用一个简称 `guard`：`guard` 模式、`guard.sql`、`guard.py`，以及角色 `guard_worker`、`guard_keeper` 和 `guard_broker`。

**状态：** 原型（2026-11-11）。只在一台笔记本上用下面的攻击套件测试过，只由编写它的助手审查过，尚未用于真实数据。

## 为什么需要它

Agent 在执行普通任务时，删除或改写过没有人让它碰的数据。依赖有人盯着、或依赖 Agent 表现良好的规则，挡不住这种事。这个防护把限制放在 Agent 的数据库登录本身上：由固定代码决定，记下谁改了什么，并让改动可以撤销。

## 它做什么

- **每个 Agent 有自己的登录。** `guard.py run` 发放一个登录：会过期，持有 `guard_worker`，记录每条语句，并且不能提高自己的限制或权限。Agent 直接写应用的表。
- **每次写入都受限制。** 每张受保护的表上都有触发器，扣除该登录的行预算和字节预算。预算在发放时固定，不能追加（AB002、AB003）。触发器还执行份额规则：在前 20 行之后，一个登录默认最多改动一张表的 10%；在前 20 行以内，最多改动原有行的一半（AB007）。冻结时（AB000）或不在 READ COMMITTED 隔离级别下（AB006）的写入会被拒绝，TRUNCATE 会被拒绝，每处改动都以该登录的名字记入 `guard.audit`。
- **提交时再检查一次。** 在冻结之前做的写入，不能在冻结之后提交。这次检查会持有一把锁，冻结要等这把锁；如果某个 Agent 事务提前触发了这次检查（`SET CONSTRAINTS ... IMMEDIATE`），冻结会直接结束它，不论看守程序是否在运行。
- **越界计次，到数即停。** 每次因试图越过限制而被拒绝（AB002、AB003、AB007），都给该登录记一次越界，拒绝信息会告诉 Agent 还剩几次。捕获这个错误或回滚事务，都抹不掉这次记录。记到最后一次时（默认 3 次），该登录被停用（AB001）：它不能再写入任何东西，最后一次越界所在的事务什么也留不下，看守程序会结束它的会话，`run` 会收回它的连接权限。
- **撤销与报告。** `undo` 从最新的开始把一个登录的改动放回去，只检查它改过的列，遇到之后更新过的改动就停下（AB005）。它可以撤销该登录做过的一切，也可以只回到某个点、保留这个点之前的工作：该登录的第一次越界，或它的任何一个事务。`report` 从审计日志得出一个登录改了什么，并给出它的越界次数和按顺序排列的事务。
- **看守程序。** 它的自检读取系统目录，发现任何问题就冻结 Agent 的写入。它会结束卡住的 Agent 会话：登录已过期、登录已停用、冻结时仍在写入、持有表锁、事务空闲 60 秒或开启 300 秒、空闲时持有咨询锁。只有数据库属主能解冻。
- **应用保持原样。** 应用自己的登录不受限制，也不被记录。不过它对受保护表的每次写入仍要经过触发器代码，实测每行多约 40 微秒。

## 使用

以数据库的超级用户属主身份，保护 Agent 可以写的表：

```
python guard.py install --database APP_DB --protect shop.products --protect shop.orders
```

然后授予 `guard_worker` 对 Agent 可读内容的 SELECT 权限。Agent 可以调用的 SECURITY DEFINER 函数，读过之后再允许：`SELECT guard.allow('shop.restock(bigint,integer)', '原因');`。

```
python guard.py run --database APP_DB --rows 1000 --bytes 10000000 --hours 8 [--strikes 3] [--undo-on-stop] -- <Agent 的命令>
python guard.py keep --database APP_DB
python guard.py status --database APP_DB
python guard.py report --database APP_DB LOGIN [--timeline]
python guard.py undo --database APP_DB LOGIN [--since-strike | --from CHANGE]
python guard.py freeze --database APP_DB "原因"
python guard.py unfreeze --database APP_DB
python guard.py backup --database APP_DB --to FOLDER
python guard.py uninstall --database APP_DB --audit-to FOLDER [--drop-roles]
```

连接设置来自 `connection.local.json`（复制 `connection.example.json` 得到）。每条命令都必须写 `--database`。

在真实应用上安装之前：

- 安装会撤销 PUBLIC 对该数据库的 CONNECT 和 TEMPORARY 权限，以及创建大对象的权限，所以依赖这些权限的登录需要先有自己的授权。
- 受保护的表需要主键。最好使用 bigint 键，因为 Agent 可以耗尽序列值。
- 保护一张表时，最多等它的锁 2 秒；表正忙时会失败且什么也不改，而不是挡住应用。再运行一次即可。重新运行安装，会把已受保护的表更新到当前的触发器。
- 能使用 shell 的 Agent 必须运行在容器里或单独的操作系统账户下：在其中运行 `python check_sandbox.py` 检查。

## 当 Agent 出问题时

**防护自己发现。** 试图越过限制的操作会被拒绝，所以它什么也没改，同时记一次越界。记满次数的登录会立刻在数据库内部被停用。`run` 随后收回它的连接权限，在 stderr 上报告这次停用；如果 Agent 的命令本身以 0 退出，`run` 以 3 退出。加上 `--undo-on-stop`，`run` 还会撤销该登录自第一次越界以来的改动，也就是回到它第一次越过限制之前的状态。第一次越界之前的改动保留。不加这个选项时，在你下令之前什么都不会撤销：

```
python guard.py undo --database APP_DB LOGIN --since-strike
```

**你自己发现。** Agent 可能在限制之内做错事，这时不会有越界记录。列出它的事务，找到第一个出错的事务，从那里开始撤销。每个事务都列有它第一处改动的编号，`--from` 用的就是这个编号：

```
python guard.py report --database APP_DB LOGIN --timeline
python guard.py undo --database APP_DB LOGIN --from CHANGE
```

不带选项的 `undo` 会放回该登录做过的一切。任何形式的 `undo` 都会先停止该登录，在登录退役后仍然可用，并且遇到别人之后改过的行就停下（AB005），不会覆盖它。

## 卸载

以超级用户属主身份运行 `guard.py uninstall`，从一个数据库中移除防护：

1. 冻结 Agent，并结束它们的会话。
2. 把审计日志、撤销记录和预算逐行写入 `--audit-to` 目录下的一个 JSON 文件，所以很大的日志也能保存。这个文件是 Agent 做过什么的唯一记录。
3. 在一个事务中：删除防护的触发器，撤销在该数据库中授予三个防护角色的所有权限（表及其列、序列、函数和过程、模式、类型、大对象，以及默认权限），把 PUBLIC 的权限恢复到第一次安装之前的样子（当时记录在 `guard.installed_over` 中），并删除 `guard` 模式。对每张受保护的表，最多等它的锁 2 秒。任何一步失败，都什么也不改，防护仍然装着，并保持冻结。

Agent 改过的数据保持原样，所以需要恢复的内容，请先运行 `undo`。如果防护之外有东西依赖它（例如建在 `guard.audit` 上的视图），卸载会被拒绝，并且什么也不改，因为删除模式会把它一起删掉。

不加 `--drop-roles` 时，三个角色和 Agent 登录仍留在服务器上。这些登录不能再写入，但在 PUBLIC 可以连接的地方仍能连接。加上 `--drop-roles`，这些角色和登录也会在同一个事务中被删除；如果同一服务器上还有别的数据库在用这些角色（还装着防护，或者那里给它们授予了什么），这一操作会被拒绝，并且什么也不改。

## 证据

`python tests/check_guard.py` 会新建一个带有应用表结构和数据的临时数据库，安装防护，并用真实的登录和真实的连接攻击它。攻击来自 Forkpoint 的边界攻击套件（1273af5 的 `scripts/agent_login_attacks.py`），逐组移植，另加一组复查攻击：COPY、upsert、MERGE、可写 CTE、在循环中调用特权函数，以及被应用触发器跳过的更新。一个有相同授权但不持有 `guard_worker` 的普通登录，必须能完成同样的数据攻击，以证明这些攻击本身有效。

另有一组越界检查，验证停用和回滚：登录在最后一次越界时被停用，那次越界所在的事务什么也留不下，捕获错误抹不掉越界记录，Agent 碰不到自己的计数，看守程序会结束已停用登录的会话，`undo` 能回到第一次越界之前或选定的事务之前。同样的内容也通过 `guard.py run`、`report` 和 `undo` 检查了一遍。

2026-11-11 的结果（`results/attack-results.json`）：308 项成立，15 项 NOTE，0 个缺口；之后所有测试数据库、角色和登录都已删除。没有移植的组需要 Forkpoint 的分支才有意义：读集合入，以及对文件、提交和历史的检查。对应关系和更早的运行记录在本地的 forkpoint-experiments 仓库中（`experiments/guard_full_suite`、`experiments/boundary_without_branches`）。

`python tests/check_uninstall.py` 在两个临时数据库中安装防护，让一个 Agent 登录在每个库里各改一行，然后卸载。一个库是 PostgreSQL 的默认权限；另一个库的属主事先已经收回了 PUBLIC 的 CONNECT、TEMPORARY 和创建大对象的权限。工作角色还会得到一张表部分列上的授权、一个过程，以及默认权限。卸载必须把每项权限、每个模式和每个触发器原样恢复，按权限的含义比较；有视图依赖防护时，卸载必须拒绝。之后第一个库在删掉一张受保护的表之后再安装、卸载一次；最后一次卸载通过命令行并带 `--drop-roles` 运行，而在另一个库还给这些角色授予着东西时，它必须先被拒绝。2026-11-11 的结果（`results/uninstall-results.json`）：17 项成立，0 个缺口。

## 测试环境

只在下面这个环境中测试过（2026-11-09、2026-11-10 和 2026-11-11）：

- 一台 Windows 11 笔记本（版本号 26200）。
- PostgreSQL 16.15，即 Ubuntu 24.04.2 的软件包，运行在 WSL 2 中（2.6.3，内核 6.6.87.2）。
- Windows 上的 Python 3.10.11 通过 `wsl.exe` 调用 WSL 内的 psql 16.15。
- 属主通过 Unix 套接字连接；Agent 登录用 SCRAM 口令连接 127.0.0.1。

需要 PostgreSQL 16 或更高版本，因为它用到了 16 的角色选项。目前只试过 16.15。

## 它不做什么

- **不保护读取。**
- **不判断改动的含义。** 它唯一视为异常的行为，是试图越过发放登录时定下的限制。在限制之内造成破坏的 Agent 不会被记越界：需要人来发现，再用 `undo --from` 放回去。
- **停用有边界情况。** 持有锁不记越界。只运行 `keep`、不通过 `run` 时，已停用的登录仍能连接和读取，直到看守程序的下一轮结束它的会话。服务器崩溃后，已有越界记录的登录，次数可能多出最多 32 次，从而被停用。
- **可用性。** Agent 能拖慢应用：它可以持有某些行，直到看守程序的 60 秒或 300 秒规则结束它的会话；可以锁住整张表直到看守程序的下一轮（或让应用的读取排在它等待的锁后面）；重新连接后还能再这样做，直到登录过期或被停止。
- **没有暂存。** Agent 的写入在提交时就生效。避免读到过期数据是 Agent 自己的事（`SELECT ... FOR UPDATE`）。
- **撤销有缺口。** 不处理 GENERATED ALWAYS 标识列或生成列，也不处理之后改过列的表（之后被删除的表会让撤销以 AB005 停下）；撤销中途出错时，什么也不会撤销。没有命令能重做被撤销的改动，所以 `--undo-on-stop` 是可选项而不是默认行为。它只回到该登录的第一次越界，不会更早。
- **需要信任的部分。** 发放程序、看守程序和属主的凭据必须放在 Agent 碰不到的地方。
- **尚未测试：** 原生 Linux 或 macOS 上的 psql、PostgreSQL 17 或更高版本、通过 TLS 连接的远程服务器、分区表、真实容器、第二台机器，以及外部审查。

## 来源

由 Forkpoint 的 Agent 边界（1273af5 的 `sql/011_agent_boundary.sql` 和 `agent_boundary.py`）改写而来。原版只能建立在 Forkpoint 自己的版本引擎之上，这个版本不需要引擎。`db.py` 和 `check_sandbox.py` 复制自 Forkpoint。采用 MIT 许可。
