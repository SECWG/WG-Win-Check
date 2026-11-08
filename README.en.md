<p align="center">
  <img width="128" height="128" alt="WG-Win-Check logo" src="https://github.com/user-attachments/assets/662573b5-d4bb-4ea1-933f-e128e646c395" />
</p>

<h3 align="center">WG-Win-Check</h3>
<p align="center">Lightweight, portable Windows incident response toolkit</p>
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
  <a href="README.md">简体中文</a> | <strong>English</strong>
</p>

## Overview

WG-Win-Check is a lightweight, portable Windows incident response toolkit with graphical and command-line interfaces. It helps security analysts inspect local accounts, processes, network connections, persistence settings, and activity traces.

Use it for host investigations, incident response, and batch data collection. The CLI provides structured output for scripts, applications, and AI agents.

## Features

| Module | Main capabilities | CLI command |
| --- | --- | --- |
| Risk Overview | Aggregate findings from users, processes, autoruns, services, and scheduled tasks | `risk` |
| Users | Inspect local accounts, hidden-account indicators, RID anomalies, and password settings | `user` |
| Processes | Inspect paths, command lines, accounts, signatures, and risks; the GUI also provides a process tree and DLL lists | `process`, `process modules <pid>` |
| Network | Inspect TCP/UDP and IPv4/IPv6 connections and their processes, extract external addresses, and query IP geolocation | `network`, `network external` |
| Autoruns | Inspect registry autoruns, startup folders, special startup settings, and WMI subscriptions | `autorun` |
| Services | Inspect service status, startup configuration, associated files, signatures, and risks | `service` |
| Scheduled Tasks | Inspect task configuration, triggers, actions, associated files, and risks | `task` |
| Files | Find executables, scripts, and archives by directory and type, using timestamps to aid investigation | `files` |
| Event Logs | Query common Windows events, including logons, process creation, and network connections | GUI |
| Threat Search | Search process memory for text and display matching locations and context | `threat <keyword>` |
| Activity Traces | Inspect Prefetch, UserAssist, recent access, logon, and software installation records | `traces` |

The CLI also provides tools for individual file information, hashes, signatures, and IP lookups. Use `all` to collect all eight data modules and generate a risk summary in one invocation.

## Download and Run

- [Download a release](https://github.com/SECWG/WG-Win-Check/releases)

Requirements: **Windows 10/11 x64**. Download and extract a release package. Running with administrator privileges is recommended.

| Package | Characteristics |
| --- | --- |
| `ReleaseMT` | Recommended for portable use; no separate VC++ runtime installation required |
| `Release` | Smaller executables; requires the Microsoft Visual C++ x64 Redistributable |

**GUI (Simplified Chinese):** Launch `WG-Win-Check.exe` and select a module to collect, filter, inspect, and export data.

**CLI:** Run `WG-Win-Check-CLI.exe` in a terminal to collect data or use an individual tool.

## CLI Quick Start

Run these commands from the executable directory. JSON is the default output. Use `--output` to save results and replace an existing file; the parent directory must exist. CSV requires `--output` and supports only a single collection module or `risk`.

```powershell
# Show command help
.\WG-Win-Check-CLI.exe help

# Collect one module or all eight data modules
.\WG-Win-Check-CLI.exe process
.\WG-Win-Check-CLI.exe all

# Collect and summarize risks from the five core modules
.\WG-Win-Check-CLI.exe risk

# Export JSON or single-module CSV
.\WG-Win-Check-CLI.exe all --output ".\snapshot.json"
.\WG-Win-Check-CLI.exe process --format csv --output ".\processes.csv"

# Check a file signature, list external IPs, and search a specific process
.\WG-Win-Check-CLI.exe file signature "C:\Windows\System32\cmd.exe"
.\WG-Win-Check-CLI.exe network external
.\WG-Win-Check-CLI.exe threat "keyword" --pid 1234 --context 100
```

## Documentation

| Document | Contents |
| --- | --- |
| [CLI Reference (Chinese)](docs/cli.md) | Commands, options, output fields, and invocation examples |
| [JSON Schema](docs/cli-schema.json) | Machine-readable output contract |
| [Agent Skill](skills/wg-win-check-cli/SKILL.md) | CLI commands, options, and output formats |
| [Changelog (Chinese)](CHANGELOG.md) | Features and improvements by release |

## Build from Source

Install **Visual Studio 2022 or Build Tools 2022** with the Desktop development with C++ workload (MSVC v143 and Windows SDK), plus **CMake 3.21+**. The C++ CMake tools bundled with Visual Studio can also be used.

From the repository root:

```bat
rem Build ReleaseMT by default
build\Build.cmd

rem Build Release
build\Build.cmd Release
```

Supported configurations are `ReleaseMT` (default), `Release`, and `Debug`. Build outputs are written to `.build/cmake/bin/<configuration>/`.

## Screenshots

<details>
<summary>View process, network, autorun, and scheduled task screenshots</summary>

![Processes](https://github.com/user-attachments/assets/2c77d844-80bc-4b2c-9056-1b1262673636)

![Network](https://github.com/user-attachments/assets/cab25d08-fa68-4f68-91bc-5309ade843ef)

![Autoruns](https://github.com/user-attachments/assets/6895fd92-6ebf-4eea-bb13-bf31a9d5297f)

![Scheduled Tasks](https://github.com/user-attachments/assets/7c1ed08b-46fe-4662-9eb0-72839b2acd74)

</details>

## License and Feedback

This project is licensed under the [Apache License 2.0](LICENSE). Report issues and share suggestions through [GitHub Issues](https://github.com/SECWG/WG-Win-Check/issues).
