<p align="center">
  <img width="128" height="128" alt="WG-Win-Check logo" src="https://github.com/user-attachments/assets/662573b5-d4bb-4ea1-933f-e128e646c395" />
</p>

<h3 align="center">WG-Win-Check</h3>
<p align="center">轻量便携的 Windows 应急响应辅助工具</p>
<p align="center">
  <a href="https://github.com/SECWG/WG-Win-Check/stargazers">
    <img src="https://img.shields.io/github/stars/SECWG/WG-Win-Check?style=flat-square&amp;color=yellow" alt="Stars" />
  </a>
  <a href="https://github.com/SECWG/WG-Win-Check/network/members">
    <img src="https://img.shields.io/github/forks/SECWG/WG-Win-Check?style=flat-square&amp;color=orange" alt="Forks" />
  </a>
  <a href="https://github.com/SECWG/WG-Win-Check/releases">
    <img src="https://img.shields.io/github/v/release/SECWG/WG-Win-Check?style=flat-square&amp;color=blue" alt="Release" />
  </a>
  <a href="https://github.com/SECWG/WG-Win-Check/releases">
    <img src="https://img.shields.io/github/downloads/SECWG/WG-Win-Check/total?style=flat-square&amp;color=brightgreen" alt="Downloads" />
  </a>
  <a href="https://github.com/SECWG/WG-Win-Check#readme">
    <img src="https://img.shields.io/badge/platform-Windows-blue?style=flat-square&amp;logo=windows" alt="Platform" />
  </a>
</p>

<p align="center">
  <strong>简体中文</strong> | <a href="README.en.md">English</a>
</p>

## 简介

WG-Win-Check 是一款轻量便携的 Windows 应急响应辅助工具，提供图形界面和命令行两种使用方式，帮助安全人员快速查看本机账户、进程、网络连接、持久化配置及活动痕迹。

适用于主机安全排查、应急响应和批量数据采集。CLI 支持结构化结果输出，可供脚本、程序和 AI Agent 调用。

## 功能介绍

| 模块 | 主要功能 | CLI 入口 |
| --- | --- | --- |
| 风险概览 | 汇总用户、进程、自启动项、服务和计划任务的风险结果 | `risk` |
| 用户排查 | 查看本地账户、隐藏账户线索、RID 异常和密码策略信息 | `user` |
| 进程排查 | 查看路径、命令行、账户、签名及风险；GUI 提供进程树和 DLL 列表 | `process`、`process modules <pid>` |
| 网络排查 | 查看 TCP/UDP、IPv4/IPv6 连接及关联进程，提取外联地址、查询 IP 归属地 | `network`、`network external` |
| 自启动项 | 排查注册表启动项、启动文件夹、特殊启动配置及 WMI 订阅 | `autorun` |
| 服务排查 | 查看服务状态、启动配置、关联文件、签名及风险 | `service` |
| 计划任务 | 查看任务配置、触发器、执行动作、关联文件及风险 | `task` |
| 文件排查 | 按目录和类型查找可执行文件、脚本及压缩包，按时间辅助定位 | `files` |
| 事件日志 | 查询登录、进程创建、网络连接等常见系统事件 | GUI 页面 |
| 威胁检索 | 在进程内存中检索文本，展示命中位置与上下文 | `threat <keyword>` |
| 活动痕迹 | 查看 Prefetch、UserAssist、最近访问、登录和软件安装等记录 | `traces` |

CLI 另提供单文件信息、哈希、签名和单 IP 查询工具。`all` 可一次采集八个数据模块，并生成风险汇总。

## 下载与运行

- [下载发布包](https://github.com/SECWG/WG-Win-Check/releases)

运行环境：**Windows 10/11 x64**。下载并解压发布包，建议以管理员权限运行。

| 发布包 | 特点 |
| --- | --- |
| `ReleaseMT` | 推荐用于便携使用，无需额外安装 VC++ 运行库 |
| `Release` | EXE 较小，需要安装 Microsoft Visual C++ x64 运行库 |

**图形界面：** 运行 `WG-Win-Check.exe`，选择对应模块进行采集、筛选、查看和导出。

**命令行：** 在终端调用 `WG-Win-Check-CLI.exe`，按命令采集数据或使用单项工具。

## CLI 快速开始

在 EXE 所在目录执行。默认输出 JSON；`--output` 保存结果并覆盖同名文件，父目录须已存在。CSV 仅支持单个采集模块或 `risk`，须配合 `--output`。

```powershell
# 查看命令帮助
.\WG-Win-Check-CLI.exe help

# 采集单个模块或全部八个数据模块
.\WG-Win-Check-CLI.exe process
.\WG-Win-Check-CLI.exe all

# 采集并汇总五个核心模块的风险
.\WG-Win-Check-CLI.exe risk

# 导出 JSON 或单模块 CSV
.\WG-Win-Check-CLI.exe all --output ".\snapshot.json"
.\WG-Win-Check-CLI.exe process --format csv --output ".\processes.csv"

# 单文件签名、外联地址和指定进程内存文本检索
.\WG-Win-Check-CLI.exe file signature "C:\Windows\System32\cmd.exe"
.\WG-Win-Check-CLI.exe network external
.\WG-Win-Check-CLI.exe threat "keyword" --pid 1234 --context 100
```

## 详细文档

| 文档 | 内容 |
| --- | --- |
| [CLI 使用说明](docs/cli.md) | 完整命令、参数、结果字段和调用示例 |
| [JSON Schema](docs/cli-schema.json) | 机器接口的数据结构定义 |
| [Agent 调用技能](skills/wg-win-check-cli/SKILL.md) | CLI 命令、参数和结果格式（英文） |
| [更新历史](CHANGELOG.md) | 各版本功能与改进记录 |

## 源码构建

安装 **Visual Studio 2022 或 Build Tools 2022** 的 C++ 桌面开发工具（MSVC v143、Windows SDK），以及 **CMake 3.21+**。也可使用 VS 自带的 C++ CMake 工具组件。

在源码根目录执行：

```bat
rem 默认构建 ReleaseMT
build\Build.cmd

rem 构建 Release
build\Build.cmd Release
```

支持 `ReleaseMT`（默认）、`Release` 和 `Debug`，构建产物位于 `.build/cmake/bin/<配置>/`。

## 界面预览

<details>
<summary>查看进程、网络、自启动项与计划任务截图</summary>

![进程排查](https://github.com/user-attachments/assets/2c77d844-80bc-4b2c-9056-1b1262673636)

![网络排查](https://github.com/user-attachments/assets/cab25d08-fa68-4f68-91bc-5309ade843ef)

![自启动项](https://github.com/user-attachments/assets/6895fd92-6ebf-4eea-bb13-bf31a9d5297f)

![计划任务](https://github.com/user-attachments/assets/7c1ed08b-46fe-4662-9eb0-72839b2acd74)

</details>

## Pro 版本

**WG-Win-Check-Pro** 是功能更丰富的多功能增强版，目前作为内部工具使用。如果你希望赞赏支持项目，或对 Pro 版本感兴趣，可前往 [FreeBuf 页面](https://wiki.freebuf.com/good/goodDetail?id=341)了解更多。

## 许可证与反馈

本项目采用 [Apache License 2.0](LICENSE)。欢迎通过 [GitHub Issues](https://github.com/SECWG/WG-Win-Check/issues) 反馈问题和建议。
