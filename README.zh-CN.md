# agent-guard

[English](README.md)

限制 AI Agent 自己的 PostgreSQL 登录能对已有应用的表做什么，即使 Agent 自己写 SQL 也一样，而且不需要改动应用。"agent-guard" 是暂定名。

**状态：** 原型（2026-11-09）。只在一台笔记本上用下面的攻击套件测试过，只由编写它的助手审查过，尚未用于真实数据。

## 为什么需要它

Agent 在执行普通任务时，删除或改写过没有人让它碰的数据。依赖有人盯着、或依赖 Agent 表现良好的规则，挡不住这种事。这个防护把限制放在 Agent 的数据库登录本身上：由固定代码决定，记下谁改了什么，并让改动可以撤销。

## 它做什么

- **每个 Agent 有自己的登录。** `guard.py run` 发放一个登录：会过期，持有 `guard_worker`，记录每条语句，并且不能提高自己的限制或权限。Agent 直接写应用的表。
- **每次写入都受限制。** 每张受保护的表上都有触发器，扣除该登录的行预算和字节预算。预算在发放时固定，不能追加（AB002、AB003）。触发器还执行份额规则：在前 20 行之后，一个登录默认最多改动一张表的 10%；在前 20 行以内，最多改动原有行的一半（AB007）。冻结时（AB000）或不在 READ COMMITTED 隔离级别下（AB006）的写入会被拒绝，TRUNCATE 会被拒绝，每处改动都以该登录的名字记入 `guard.audit`。
- **提交时再检查一次。** 在冻结之前做的写入，不能在冻结之后提交。
- **撤销与报告。** `undo` 从最新的开始把一个登录的改动放回去，只检查它改过的列，遇到之后更新过的改动就停下（AB005）。`report` 从审计日志得出一个登录改了什么。
- **看守程序。** 它的自检读取系统目录，发现任何问题就冻结 Agent 的写入。它会结束卡住的 Agent 会话：登录已过期、冻结时仍在写入、持有表锁、事务空闲 60 秒或开启 300 秒、空闲时持有咨询锁。只有数据库属主能解冻。
- **应用保持原样。** 应用自己的登录不受限制，也不被记录。不过它对受保护表的每次写入仍要经过触发器代码，实测每行多约 40 微秒。

## 使用

以数据库的超级用户属主身份，保护 Agent 可以写的表：

```
python guard.py install --database APP_DB --protect shop.products --protect shop.orders
```

然后授予 `guard_worker` 对 Agent 可读内容的 SELECT 权限。Agent 可以调用的 SECURITY DEFINER 函数，读过之后再允许：`SELECT guard.allow('shop.restock(bigint,integer)', '原因');`。

```
python guard.py run --database APP_DB --rows 1000 --bytes 10000000 --hours 8 -- <Agent 的命令>
python guard.py keep --database APP_DB
python guard.py status --database APP_DB
python guard.py report --database APP_DB LOGIN
python guard.py undo --database APP_DB LOGIN
python guard.py freeze --database APP_DB "原因"
python guard.py unfreeze --database APP_DB
python guard.py backup --database APP_DB --to FOLDER
python guard.py uninstall --database APP_DB --audit-to FOLDER [--drop-roles]
```

连接设置来自 `connection.local.json`（复制 `connection.example.json` 得到）。每条命令都必须写 `--database`。

在真实应用上安装之前：

- 安装会撤销 PUBLIC 对该数据库的 CONNECT 和 TEMPORARY 权限，以及创建大对象的权限，所以依赖这些权限的登录需要先有自己的授权。
- 受保护的表需要主键。最好使用 bigint 键，因为 Agent 可以耗尽序列值。
- 能使用 shell 的 Agent 必须运行在容器里或单独的操作系统账户下：在其中运行 `python check_sandbox.py` 检查。

## 卸载

以超级用户属主身份运行 `guard.py uninstall`，从一个数据库中移除防护：

1. 冻结 Agent，并结束它们的会话。
2. 把审计日志、撤销记录和预算保存为 `--audit-to` 目录下的一个 JSON 文件。这个文件是 Agent 做过什么的唯一记录。
3. 在一个事务中：删除防护的触发器，撤销授予三个防护角色的所有权限，把 PUBLIC 的权限恢复到第一次安装之前的样子（当时记录在 `guard.installed_over` 中），并删除 `guard` 模式。

Agent 改过的数据保持原样，所以需要恢复的内容，请先运行 `undo`。

不加 `--drop-roles` 时，三个角色和 Agent 登录仍留在服务器上。这些登录不能再写入，但在 PUBLIC 可以连接的地方仍能连接。加上 `--drop-roles`，这些角色和登录也会被删除；如果同一服务器上还有别的数据库装着防护，这一操作会被拒绝，并且什么也不改。

## 证据

`python tests/check_guard.py` 会新建一个带有应用表结构和数据的临时数据库，安装防护，并用真实的登录和真实的连接攻击它。攻击来自 Forkpoint 的边界攻击套件（1273af5 的 `scripts/agent_login_attacks.py`），逐组移植，另加一组复查攻击：COPY、upsert、MERGE、可写 CTE，以及在循环中调用特权函数。一个有相同授权但不持有 `guard_worker` 的普通登录，必须能完成同样的数据攻击，以证明这些攻击本身有效。

2026-11-09 的结果（`results/attack-results.json`）：258 项成立，15 项 NOTE，0 个缺口；之后所有测试数据库、角色和登录都已删除。没有移植的组需要 Forkpoint 的分支才有意义：读集合入，以及对文件、提交和历史的检查。对应关系和更早的运行记录在本地的 forkpoint-experiments 仓库中（`experiments/guard_full_suite`、`experiments/boundary_without_branches`）。

`python tests/check_uninstall.py` 在两个临时数据库中安装防护，让一个 Agent 登录在每个库里各改一行，然后卸载。一个库是 PostgreSQL 的默认权限；另一个库的属主事先已经收回了 PUBLIC 的 CONNECT、TEMPORARY 和创建大对象的权限。卸载必须把每项权限、每个模式和每个触发器原样恢复，按权限的含义比较。之后第一个库再安装、卸载一次，最后一次卸载通过命令行并带 `--drop-roles` 运行。2026-11-09 的结果（`results/uninstall-results.json`）：14 项成立，0 个缺口。

## 测试环境

只在下面这个环境中测试过（2026-11-09）：

- 一台 Windows 11 笔记本（版本号 26200）。
- PostgreSQL 16.15，即 Ubuntu 24.04.2 的软件包，运行在 WSL 2 中（2.6.3，内核 6.6.87.2）。
- Windows 上的 Python 3.10.11 通过 `wsl.exe` 调用 WSL 内的 psql 16.15。
- 属主通过 Unix 套接字连接；Agent 登录用 SCRAM 口令连接 127.0.0.1。

需要 PostgreSQL 16 或更高版本，因为它用到了 16 的角色选项。目前只试过 16.15。

## 它不做什么

- **不保护读取。**
- **可用性。** Agent 能拖慢应用：它可以持有某些行，直到看守程序的 60 秒或 300 秒规则结束它的会话；可以锁住整张表直到看守程序的下一轮（或让应用的读取排在它等待的锁后面）；重新连接后还能再这样做，直到登录过期或被停止。
- **没有暂存。** Agent 的写入在提交时就生效。避免读到过期数据是 Agent 自己的事（`SELECT ... FOR UPDATE`）。
- **撤销有缺口。** 不处理 GENERATED ALWAYS 标识列或生成列，也不处理之后改过列的表；撤销中途出错时，什么也不会撤销。
- **需要信任的部分。** 发放程序、看守程序和属主的凭据必须放在 Agent 碰不到的地方。
- **尚未测试：** 原生 Linux 或 macOS 上的 psql、PostgreSQL 17 或更高版本、通过 TLS 连接的远程服务器、分区表、真实容器、第二台机器，以及外部审查。

## 来源

由 Forkpoint 的 Agent 边界（1273af5 的 `sql/011_agent_boundary.sql` 和 `agent_boundary.py`）改写而来。原版只能建立在 Forkpoint 自己的版本引擎之上，这个版本不需要引擎。`db.py` 和 `check_sandbox.py` 复制自 Forkpoint。采用 MIT 许可。
