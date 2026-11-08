# WG-Win-Check CLI 使用说明

## 功能概览

CLI 提供 Windows 本机用户、进程、网络、自启动项、服务、计划任务、活动痕迹和文件采集，以及风险汇总、文件信息/哈希/签名检查、IP 归属查询和进程内存文本检索，供程序与 Agent 调用。

本文对应产品版本 `2.0.0`，JSON 契约为 `schema_version: 1`。字段定义见 [JSON Schema](cli-schema.json)。

CLI 默认输出 UTF-8 JSON，可通过 `--output` 保存文件。命令沿用当前运行权限，无交互提示。

文件按修改时间倒序，活动痕迹按记录时间倒序。

## 命令

以下示例假设可执行文件在当前目录。

```powershell
# 采集单个模块
.\WG-Win-Check-CLI.exe user
.\WG-Win-Check-CLI.exe process
.\WG-Win-Check-CLI.exe network
.\WG-Win-Check-CLI.exe autorun
.\WG-Win-Check-CLI.exe service
.\WG-Win-Check-CLI.exe task
.\WG-Win-Check-CLI.exe traces
.\WG-Win-Check-CLI.exe files --path "C:\IR\samples"

# 采集八个模块并汇总风险
.\WG-Win-Check-CLI.exe all

# 采集用户、进程、自启动项、服务、计划任务并汇总风险
.\WG-Win-Check-CLI.exe risk

# 导出 JSON 或 CSV
.\WG-Win-Check-CLI.exe all --output "C:\IR\snapshot.json"
.\WG-Win-Check-CLI.exe process --format csv --output "C:\IR\processes.csv"
.\WG-Win-Check-CLI.exe risk --format csv --output "C:\IR\risks.csv"

# 查询网络连接的 IP 归属地
.\WG-Win-Check-CLI.exe network --ip-location

# 单项工具
.\WG-Win-Check-CLI.exe file info "C:\Windows\System32\cmd.exe"
.\WG-Win-Check-CLI.exe file hash "C:\Windows\System32\cmd.exe"
.\WG-Win-Check-CLI.exe file signature "C:\Windows\System32\cmd.exe"
.\WG-Win-Check-CLI.exe process modules 1234
.\WG-Win-Check-CLI.exe ip 8.8.8.8
.\WG-Win-Check-CLI.exe network external
.\WG-Win-Check-CLI.exe threat "keyword" --pid 1234 --context 100
.\WG-Win-Check-CLI.exe threat -- "--literal-keyword"
.\WG-Win-Check-CLI.exe version
.\WG-Win-Check-CLI.exe help
```

`help`、`--help` 或无参数启动显示帮助；`version`、`--version` 返回版本 JSON。帮助和版本入口须独立调用，不接受数据选项。

## 参数

| 参数 | 规则 |
|---|---|
| `--output <file>` | 显式导出目标；相对路径以工作目录为准；父目录必须已存在 |
| `--format json/csv` | 默认 JSON；CSV 仅支持单模块采集或 `risk`，须配合 `--output` |
| `--path <directory>` | 仅 `files` 或 `all`；只替换文件扫描目录，不影响其他模块，也不改变默认扩展名范围 |
| `--ip-location` | 仅 `network` 或 `all`；联网查询去重公网远端 IP 的归属地，默认关闭 |
| `--pid <pid>` | 仅 `threat`；整数 1–4294967295；省略时检索本机进程 |
| `--context <n>` | 仅 `threat`；默认 60，范围 0–1024；0 仅保留匹配文本，不附加上下文 |
| `--timeout <seconds>` | 默认 300，范围 1–86400；整个调用的协作式采集期限 |
| `--` | 终止选项解析；其后均作为输入文本，其他选项须放在它之前 |

每个选项只能出现一次。文件、IP 和威胁检索工具每次只接受一个输入，包含空格时作为一个参数传入。`process modules <pid>` 的 PID 范围同样为 1–4294967295。

威胁检索关键词最多 1024 个 Unicode 码点，不接受空文本、纯空白、无效代理对或受限控制字符。例如检索字面值 `--help`：`threat --pid 1234 -- --help`；其中 `--pid` 必须位于 `--` 之前。

文件扫描默认覆盖用户下载目录和 C 盘非系统目录，扫描可执行文件、脚本和压缩包；“其他”类型默认关闭。

`ip` 和 `--ip-location` 需联网，使用 ip-api.com 免费 HTTP 接口（仅限非商业用途）。

## JSON 输出

数据命令向 stdout 返回一个完整 JSON 文档，读取结束后再解析。主要字段如下：

| 字段 | 含义 |
|---|---|
| `schema_version` | 数据格式版本，当前为 1 |
| `kind` | `result` 为数据，`receipt` 为显式文件导出的保存回执 |
| `command` | 稳定命令名，例如 `process`、`file signature` |
| `data` | 按模块名分组的数据；错误响应可为空对象 |
| `summary` | 输出记录数、请求/执行模块数、未执行模块和风险汇总数量 |
| `issues` | 命令级错误；模块/文件诊断在各自的 `issues` 中 |
| `meta` | 产品版本、调用起止 UTC 时间、权限、调用者 SID、进程/系统位数和 Windows 时区标识 |
| `status` | 本次命令的执行状态 |
| `exit_code` | 对应进程退出码 |

模块数据的公共结构：

```json
{
  "records": [
    {
      "name": "sample.exe",
      "path": "C:\\IR\\samples\\sample.exe",
      "size_bytes": 4096,
      "created_at": "2026-09-26T01:00:00.000Z",
      "modified_at": "2026-09-26T02:00:00.000Z"
    }
  ],
  "module": "files",
  "count": 1,
  "collected_count": 1,
  "status": "ok",
  "coverage": {
    "enumeration": "complete",
    "evidence": "complete",
    "risk": "not_requested"
  },
  "truncated": false,
  "started_at": "2026-09-26T03:00:00.000Z",
  "finished_at": "2026-09-26T03:00:01.000Z",
  "sources": [],
  "issues": []
}
```

`count` 是实际输出的记录数，`collected_count` 是采集器取得的记录数。`risk` 的五个来源模块仅保留报告，没有 `records`，因此其 `count` 为 0；风险对象在 `data.risk.records`。

`summary.count` 为输出总记录数，包含风险汇总行；未请求风险汇总时，`summary.risk_count` 为 `null`。

### 各命令的结果位置

| 命令 | 记录位置 |
|---|---|
| `user` 等单模块 | `data.user.records`，名称与命令模块名一致 |
| `all` | `data.<module>.records`，模块为 `user`、`process`、`network`、`autorun`、`service`、`task`、`traces`、`files`、`risk` |
| `risk` | `data.risk.records`，五个核心来源报告仍保留 |
| `file info` | `data.file.records` |
| `file hash` | `data.hash.records` |
| `file signature` | `data.signature.records` |
| `process modules` | `data.modules.records` |
| `ip` | `data.ip.records` |
| `network external` | `data.external.records`，去重外联远端地址，不查询归属地 |
| `threat` | `data.threat.records`，同一对象还包含关键字、上下文配置和进程读取统计 |
| `version` | `data.version.records` |

## 结果字段

- 字段名使用英文；PID、端口、计数为数字，布尔值为 `true/false`。
- 未知或不适用的值为 `null`；`field_states` 区分 `available/unknown/not_requested/not_applicable`。
- 时间通常为 UTC ISO 8601；任务的 `next_run_local/last_run_local` 为本地时间，时区见 `meta.time_zone`，触发器边界保留原始值。
- 内存地址、模块基址为十六进制字符串；命令行、路径和描述保留原文。
- 无效 Unicode 字符替换为 `U+FFFD`，并记录 `INVALID_UNICODE_REPLACED` 提示。

主要记录结构：

| 模块 | 主要字段 |
|---|---|
| 用户 | 用户名、SID/RID、账户状态、管理员、三类隐藏标志、登录/密码计数、时间、`field_states`、`risk` |
| 进程 | PID/PPID、名称、路径、命令行、用户、线程数、创建时间、`file`、`risk` |
| 网络 | 协议/IP 版本、本地/远端地址和端口、TCP 状态、PID、进程信息、归属地及其状态；UDP 远端和 TCP 状态为 `null` |
| 自启动 | 类型、位置、原始命令、关联文件、注册表路径/视图、配置项状态、WMI 订阅字段、`file`、`risk` |
| 服务 | 状态、启动类型、PID、账户、启动命令、ServiceDll、关联文件、依赖、`field_states`、`file`、`risk` |
| 计划任务 | 状态、启用/隐藏、主体、执行结果、`actions[]`、`triggers[]`、`related_files[]`、`field_states`、`risk` |
| 活动痕迹 | UTC 时间、类型、描述、详情、来源 |
| 文件扫描 | 名称、路径、字节大小、创建/修改 UTC 时间 |
| 风险汇总 | `module/source_key/object_name/observed_at/risk/context`；一条对应一个风险对象，多个命中保留在 `risk.hits[]` |

任务 Action 和 Trigger 的 `index` 保留采集器的原生序号；`related_file_indexes` 则是当前任务 `related_files` 数组的零基索引，关联文件的 `action_index` 对应 Action 的 `index`。

### 签名和风险

签名对象包含状态、来源和发布者等信息。`state` 分为 `signed`（校验通过）、`unsigned`（未签名）、`mismatch`（签名异常）和 `unknown`（无法判断）。

`risk.level` 为最高等级，`risk.hits[]` 保留所有命中，`assessment` 和 `unevaluated_rules[]` 记录评估状态。风险汇总的 `context` 提供所属对象的定位信息。

## 执行状态

模块的 `coverage` 分别记录以下状态：

| 字段 | 含义 |
|---|---|
| `coverage.enumeration` | 请求的记录来源是否枚举完成 |
| `coverage.evidence` | 文件、签名等补充信息的获取情况 |
| `coverage.risk` | 风险规则是否完整评估 |

`all` 的退出码依据八个模块的枚举结果；`risk` 还检查风险评估是否完整，未完成时返回 1。

| 退出码 | `status` | 含义 |
|---|---|---|
| 0 | `ok` | 数据操作成功 |
| 1 | `partial` | 部分采集或评估未完成，已取得的结果仍可使用 |
| 2 | `invalid_arguments` | 参数、组合或输入/输出同文件冲突 |
| 3 | `failed` | 操作失败，未取得成功模块 |
| 4 | `cancelled` | 收到取消 |
| 5 | `timed_out` | 达到协作式期限 |
| 6 | `output_failed` | 无法打开、写入或发布输出 |

## 文件导出

- 使用 `--output <file>` 指定目标，父目录须已存在；成功保存后覆盖同名文件。
- 退出码 0 或 1 的结果可保存；失败、取消、超时或写入失败时保留旧文件。
- 导出回执为 `kind=receipt`，`data.artifact` 提供路径、格式和 `written`；`written=true` 表示本轮保存成功。
- 参数或输出准备失败时可能返回 `kind=result` 的错误 JSON，而非保存回执。
- 文件工具不允许输入和输出为同一文件。

CSV 使用英文表头和 UTF-8 无 BOM 编码，嵌套对象、数组写为 JSON 单元格，`null` 写为空单元格。

源码构建见 [README 构建说明](../README.md#源码构建)，版本变更见 [CHANGELOG.md](../CHANGELOG.md)。
