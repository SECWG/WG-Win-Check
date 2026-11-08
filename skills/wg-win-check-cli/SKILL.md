---
name: wg-win-check-cli
description: Windows incident-response data collection with WG-Win-Check CLI, including host activity, risk summaries, file information, hashes, digital signatures, IP geolocation, and process memory text search.
---

# WG-Win-Check CLI

Use `WG-Win-Check-CLI.exe` on Windows 10/11 x64. The CLI uses the caller's current privileges and accepts commands as an argument array. This reference covers product version 2.0.0 and JSON schema version 1.

## Collection commands

Record groups are returned under `data.<group>.records`.

| Command | Collects | Record group |
| --- | --- | --- |
| `user` | Local accounts, account settings, hidden-account indicators, and risks | `user` |
| `process` | Running processes, command lines, accounts, file information, and risks | `process` |
| `network` | TCP/UDP connections, IPv4/IPv6 addresses, ports, and owning processes | `network` |
| `autorun` | Registry autoruns, startup folders, special startup settings, and WMI subscriptions | `autorun` |
| `service` | Services, startup settings, associated files, signatures, and risks | `service` |
| `task` | Scheduled tasks, triggers, actions, associated files, and risks | `task` |
| `traces` | Prefetch, UserAssist, recent access, logon, and installation records | `traces` |
| `files` | File paths, sizes, creation times, and modification times | `files` |
| `risk` | Risks from users, processes, autoruns, services, and tasks | `risk` |
| `all` | The eight collection modules above, plus their core risk summary | Separate module groups and `risk` |

`risk` actively collects its five source modules. Their groups contain collection reports without raw `records`; findings are in `data.risk.records`. `all` includes the eight collection modules and risk findings, not the individual tools below.

File collection defaults to user download folders and non-system directories on C:, scanning executables, scripts, and archives. Use `--path` to replace the scan directory; it does not change the file-type selection. Files are sorted by modification time and activity traces by record time, newest first.

## Individual tools

Each tool accepts one input per invocation.

| Command | Function | Record group |
| --- | --- | --- |
| `file info <file>` | File information | `file` |
| `file hash <file>` | MD5, SHA-1, and SHA-256 hashes | `hash` |
| `file signature <file>` | Signature verification and publisher information | `signature` |
| `process modules <pid>` | DLLs and modules of one process | `modules` |
| `network external` | Deduplicated external remote IP addresses | `external` |
| `ip <ip>` | Geolocation of one IP address | `ip` |
| `threat <keyword>` | Text matches in process memory, including location and context | `threat` |

`network` preserves individual connection records. `network external` only lists deduplicated remote addresses and does not query geolocation; its external-address filter is not a strict public-address classification.

`ip` and `--ip-location` perform online lookups through ip-api.com over HTTP. The current free endpoint is limited to non-commercial use. Network collection does not query geolocation unless `--ip-location` is supplied.

## Options

| Option | Scope and behavior |
| --- | --- |
| `--output <file>` | Collection and individual tools: save the result and replace an existing target. The parent directory must exist; relative paths use the working directory. |
| `--format <format>` | `json` by default. `csv` requires `--output` and supports only one collection module or `risk`, not `all` or individual tools. |
| `--timeout <seconds>` | Collection and individual tools: default 300, range 1-86400. Cancellation is cooperative, not a guaranteed hard deadline. |
| `--path <directory>` | `files` or `all`: replace only the file-scan directory. Other modules are unaffected. |
| `--ip-location` | `network` or `all`: query deduplicated public remote IPs and attach location data to connection records. |
| `--pid <pid>` | `threat` only: restrict the search to one process. Omit it to search local processes. |
| `--context <n>` | `threat` only: default 60, range 0-1024. Zero returns the matched text without surrounding context. |
| `--` | End option parsing. All subsequent arguments are input values; place other options before this separator. |

- Each option may appear only once. Collection commands do not accept extra positional inputs.
- PID values must be integers from 1 to 4294967295, including the positional PID for `process modules`.
- A keyword must be non-blank text of at most 1024 Unicode code points. Invalid surrogate pairs and restricted control characters are rejected.
- Pass paths or keywords containing spaces as one argument. For a literal keyword starting with `--`, use `threat --pid 1234 -- --help`.
- `help`, `--help`, or no arguments displays text help. `version` and `--version` return JSON in `data.version.records`. These commands run alone, without data options; `threat --help` is not a help command.

## Examples

These examples assume the executable is in the current directory.

```powershell
.\WG-Win-Check-CLI.exe process
.\WG-Win-Check-CLI.exe risk
.\WG-Win-Check-CLI.exe files --path "C:\IR\samples"
.\WG-Win-Check-CLI.exe all --output ".\snapshot.json"
.\WG-Win-Check-CLI.exe process --format csv --output ".\processes.csv"
.\WG-Win-Check-CLI.exe file signature "C:\Windows\System32\cmd.exe"
.\WG-Win-Check-CLI.exe network external
.\WG-Win-Check-CLI.exe threat "keyword" --pid 1234 --context 100
```

## JSON output

Data commands return one UTF-8 JSON document without a BOM on stdout. Read stdout to completion before parsing; this is not JSONL. No files are created unless `--output` is supplied.

| Top-level field | Meaning |
| --- | --- |
| `schema_version` | Output contract version, currently `1` |
| `kind` | `result` for data or an error response; `receipt` for an export receipt |
| `command` | Command name, such as `process`, `ip`, or `file signature` |
| `data` | Module groups; may be empty on failure |
| `summary` | Record and module counts, including risk summary counts when requested |
| `issues` | Command-level diagnostics; groups and individual records may have their own `issues` |
| `meta` | Product version, collection times, caller privileges, and system/time-zone information |
| `status` | Command execution status |
| `exit_code` | Process exit code |

A collection group includes `records`, `module`, `count`, `collected_count`, `status`, `coverage`, `truncated`, `started_at`, `finished_at`, `sources`, and `issues`. The five source reports in a standalone `risk` response omit `records`.

- `count` is the number of emitted records; `collected_count` is the number obtained by the collector. Risk source reports have `count=0` because they do not emit raw records.
- `summary.count` includes emitted risk rows. `summary.risk_count` is `null` when no risk summary was requested.
- `coverage.enumeration` describes record enumeration, `coverage.evidence` supplementary information, and `coverage.risk` risk assessment.
- Normal diagnostics are included in JSON. Stderr is used for output infrastructure failures.

### Record values

- Keys are English. Counts, PIDs, ports, and sizes are numbers; flags are booleans. Unknown or inapplicable values are `null`, distinct from zero, false, or an empty string.
- Where present, `field_states` uses `available`, `unknown`, `not_requested`, or `not_applicable`.
- Timestamps are generally UTC ISO 8601. Task `next_run_local` and `last_run_local` remain local times; `meta.time_zone` identifies the Windows time zone. Trigger boundaries retain their original values.
- Memory addresses and module base addresses are hexadecimal strings.
- Task `actions[]`, `triggers[]`, and `related_files[]` preserve multiple actions and their file associations. `related_file_indexes` contains zero-based indexes into `related_files`; `action_index` refers to the action's `index`.
- Signature objects include `state`, `source`, and `publisher`. States are `signed`, `unsigned`, `mismatch`, and `unknown`.
- Record `risk` objects include `assessment`, the highest `level`, all `hits[]`, and `unevaluated_rules[]`. Risk summary records include `module`, `source_key`, `object_name`, `observed_at`, `risk`, and locating information in `context`.

## File exports

- `--output` writes JSON by default. CSV uses English headers and UTF-8 without a BOM; nested objects and arrays are JSON inside cells, and `null` becomes an empty cell.
- Export results with exit code 0 or 1 can replace the destination. Failure, cancellation, timeout, or a write failure leaves the previous file unchanged.
- After execution, stdout returns a JSON receipt. `data.artifact` contains the absolute path, format, and `written`; only `written=true` confirms that this invocation saved the file.
- Argument errors or output preparation failures may instead return `kind=result` with error details and no receipt.
- File tools reject identical input and output files. Concurrent exports should use separate paths if both results need to be retained.

## Exit codes

| Code | Status | Meaning |
| --- | --- | --- |
| `0` | `ok` | Data operation succeeded |
| `1` | `partial` | Some collection or requested assessment was incomplete; available records remain usable |
| `2` | `invalid_arguments` | Invalid input, option combination, or input/output conflict |
| `3` | `failed` | Operation failed without a successful module |
| `4` | `cancelled` | Cancelled |
| `5` | `timed_out` | Cooperative deadline reached |
| `6` | `output_failed` | Output could not be opened, written, or published |

`all` derives its exit status from collection completeness. `risk` also requires complete assessment of its core sources. Read the JSON response even when the exit code is nonzero.
