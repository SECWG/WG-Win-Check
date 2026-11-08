#include "../core/system/Win32.h"
#include "CliApplication.h"
#include "output/MachineResult.h"
#include "../shared/Constants.h"
#include <algorithm>
#include <iterator>
#include <limits>
#include <map>
#include <set>

namespace wgwc::cli {
    namespace {
        using namespace core;
        using machine::Value;
        enum class Command {
            Help,
            Version,
            Collect,
            FileInfo,
            FileHash,
            Signature,
            Modules,
            Ip,
            External,
            Threat
        };

        struct Options {
            Command command = Command::Help;
            std::wstring module, target, path, output, label = L"help";
            bool csv = false, ipLocation = false;
            std::uint32_t pid = 0, timeoutSeconds = 300;
            std::size_t contextChars = threat::DefaultContextChars;
        };

        constexpr const wchar_t* AllModules[] = { L"user",    L"process", L"network", L"autorun",
                                                  L"service", L"task",    L"traces",  L"files" };
        constexpr const wchar_t* RiskModules[] = { L"user", L"process", L"autorun", L"service", L"task" };

        bool IsRiskModule(const std::wstring& name) {
            return std::find(std::begin(RiskModules), std::end(RiskModules), name) != std::end(RiskModules);
        }

        bool ParseUnsignedInteger(const std::wstring& text, std::uint64_t maximum, std::uint64_t& value) {
            if (text.empty())
                return false;
            value = 0;
            for (const wchar_t c : text) {
                if (c < L'0' || c > L'9')
                    return false;
                const auto digit = static_cast<unsigned>(c - L'0');
                if (value > maximum / 10 || (value == maximum / 10 && digit > maximum % 10))
                    return false;
                value = value * 10 + digit;
            }
            return true;
        }

        bool Parse(int argc, wchar_t* argv[], Options& o, CollectionIssue& problem) {
            std::vector<std::wstring> args;
            std::set<std::wstring> seen;
            bool ended = false;
            const auto reject = [&](const std::wstring& token, const std::wstring& message) {
                if (problem.code.empty())
                    problem = { L"cli", token, L"INVALID_ARGUMENTS", 0, message, true };
                return false;
            };
            for (int i = 1; i < argc; ++i) {
                const std::wstring arg = argv[i];
                if (!ended && arg == L"--") {
                    ended = true;
                    continue;
                }
                if (!ended && arg == L"--ip-location") {
                    if (!seen.insert(arg).second)
                        reject(arg, L"Option specified more than once: " + arg);
                    o.ipLocation = true;
                    continue;
                }
                if (!ended && (arg == L"--format" || arg == L"--output" || arg == L"--path" || arg == L"--pid" ||
                               arg == L"--context" || arg == L"--timeout")) {
                    if (!seen.insert(arg).second)
                        reject(arg, L"Option specified more than once: " + arg);
                    if (++i >= argc || !*argv[i]) {
                        reject(arg, L"Missing value for " + arg + L".");
                        continue;
                    }
                    const std::wstring value = argv[i];
                    if (arg == L"--format") {
                        if (value != L"json" && value != L"csv")
                            reject(arg, L"Unsupported format: " + value + L". Expected json or csv.");
                        else
                            o.csv = value == L"csv";
                    } else if (arg == L"--output")
                        o.output = value;
                    else if (arg == L"--path")
                        o.path = value;
                    else {
                        std::uint64_t number = 0;
                        const auto maximum = arg == L"--context"   ? threat::MaxContextChars
                                             : arg == L"--timeout" ? 86400ULL
                                                                   : MAXDWORD;
                        const auto minimum = arg == L"--context" ? 0ULL : 1ULL;
                        if (!ParseUnsignedInteger(value, maximum, number) || number < minimum) {
                            reject(arg, L"Invalid value for " + arg + L": " + value + L". Expected an integer in " +
                                            std::to_wstring(minimum) + L".." + std::to_wstring(maximum) + L".");
                            continue;
                        }
                        if (arg == L"--pid")
                            o.pid = static_cast<std::uint32_t>(number);
                        else if (arg == L"--timeout")
                            o.timeoutSeconds = static_cast<std::uint32_t>(number);
                        else
                            o.contextChars = static_cast<std::size_t>(number);
                    }
                } else if (!ended && arg.rfind(L"--", 0) == 0 &&
                           ((arg != L"--help" && arg != L"--version") ||
                            (!args.empty() && args[0] == L"threat")))
                    reject(arg, L"Unknown option: " + arg + L". Run help for supported options.");
                else
                    args.push_back(arg);
            }
            const bool modulesCommand = args.size() > 1 && args[0] == L"process" && args[1] == L"modules";
            const bool externalCommand = args.size() > 1 && args[0] == L"network" && args[1] == L"external";
            // 保留首个参数错误，但先整理命令名，避免错误响应误标为帮助命令。
            if (args.empty())
                o.label = seen.empty() && problem.code.empty() ? L"help" : L"unknown";
            else {
                o.label = args[0] == L"--help" ? L"help" : args[0] == L"--version" ? L"version" : args[0];
                if (args.size() > 1 && (args[0] == L"file" || modulesCommand || externalCommand))
                    o.label += L" " + args[1];
            }
            if (!problem.code.empty())
                return false;
            if (args.empty()) {
                if (!seen.empty())
                    return reject(L"command", L"Missing command. Run help for supported commands.");
                return true;
            }
            if (args.size() == 1 && (args[0] == L"help" || args[0] == L"--help")) {
                if (!seen.empty())
                    return reject(*seen.begin(), L"Options are not supported for help.");
                return true;
            }
            if (args.size() == 1 && (args[0] == L"version" || args[0] == L"--version")) {
                if (!seen.empty())
                    return reject(*seen.begin(), L"Options are not supported for version.");
                o.command = Command::Version;
                return true;
            }
            const bool collectionCommand =
                std::find(std::begin(AllModules), std::end(AllModules), args[0]) != std::end(AllModules) ||
                args[0] == L"all" || args[0] == L"risk";
            if (collectionCommand && !modulesCommand && !externalCommand) {
                if (args.size() != 1)
                    return reject(args[1],
                                  L"Collection commands take no positional arguments. Use a module name directly.");
                o.module = args[0];
                o.command = Command::Collect;
                if (seen.count(L"--pid"))
                    return reject(L"--pid", L"--pid is supported only by threat.");
                if (seen.count(L"--context"))
                    return reject(L"--context", L"--context is supported only by threat.");
                if (!o.path.empty() && o.module != L"files" && o.module != L"all")
                    return reject(L"--path", L"--path is supported only by files/all.");
                if (o.ipLocation && o.module != L"network" && o.module != L"all")
                    return reject(L"--ip-location", L"--ip-location is supported only by network/all.");
                if (o.csv && o.module == L"all")
                    return reject(L"--format",
                                  L"all does not support CSV; use JSON or export a single module.");
                if (o.csv && o.output.empty())
                    return reject(L"--output", L"CSV export requires --output <file>.");
                return true;
            }
            if (o.csv)
                return reject(L"--format",
                              L"CSV is supported only by a single collection module or risk with --output <file>.");
            if (!o.path.empty())
                return reject(L"--path", L"--path is supported only by files/all.");
            if (o.ipLocation)
                return reject(L"--ip-location", L"--ip-location is supported only by network/all.");
            if (args[0] == L"threat") {
                if (args.size() != 2)
                    return reject(L"keyword", L"threat requires exactly one keyword.");
                if (!threat::IsValidKeyword(args[1]))
                    return reject(L"keyword", L"Keyword must be valid non-empty text of at most " +
                                                  std::to_wstring(threat::MaxKeywordChars) + L" Unicode code points.");
                o.command = Command::Threat;
                o.target = args[1];
                return true;
            }
            if (seen.count(L"--pid"))
                return reject(L"--pid", L"--pid is supported only by threat.");
            if (seen.count(L"--context"))
                return reject(L"--context", L"--context is supported only by threat.");
            if (args[0] == L"ip") {
                if (args.size() != 2 || args[1].empty())
                    return reject(L"ip", L"ip requires exactly one non-empty IP address.");
                if (ip::ParseAddress(args[1]).type == ip::AddressType::Invalid)
                    return reject(L"ip",
                                  L"Invalid IP address: " + args[1] + L". Expected one IPv4 or IPv6 address.");
                o.command = Command::Ip;
                o.target = args[1];
                return true;
            }
            if (externalCommand) {
                if (args.size() != 2)
                    return reject(o.label, L"network external takes no positional arguments.");
                o.command = Command::External;
                return true;
            }
            if (args.size() < 2)
                return reject(o.label, L"Unknown or incomplete command. Run help for supported commands.");
            const bool fileCommand =
                args[0] == L"file" && (args[1] == L"info" || args[1] == L"hash" || args[1] == L"signature");
            if (!fileCommand && !modulesCommand)
                return reject(o.label, L"Unknown command or subcommand. Run help for supported commands.");
            const std::wstring targetName = fileCommand ? L"path" : L"pid";
            if (args.size() != 3 || args[2].empty())
                return reject(targetName, o.label + L" requires exactly one non-empty " + targetName + L" argument.");
            o.target = args[2];
            if (fileCommand) {
                o.command = args[1] == L"info"   ? Command::FileInfo
                            : args[1] == L"hash" ? Command::FileHash
                                                 : Command::Signature;
                return true;
            }
            std::uint64_t pid = 0;
            if (!ParseUnsignedInteger(o.target, MAXDWORD, pid) || !pid)
                return reject(L"pid", L"Invalid PID: " + o.target + L". Expected an integer in 1.." +
                                          std::to_wstring(MAXDWORD) + L".");
            o.command = Command::Modules;
            o.pid = static_cast<std::uint32_t>(pid);
            return true;
        }

        const wchar_t* Help() {
            return L"WG-Win-Check CLI: Windows incident-response data collection\n"
                   L"Usage: WG-Win-Check-CLI.exe <command> [options]\n"
                   L"Default: one UTF-8 JSON document on stdout; no automatic files or progress text.\n\n"
                   L"  user|process|network|autorun|service|task|traces|files|risk|all\n"
                   L"  files|all --path <directory>\n"
                   L"  network|all --ip-location\n"
                   L"  file info|hash|signature <file>\n"
                   L"  process modules <pid>\n"
                   L"  ip <ip>\n"
                   L"  network external\n"
                   L"  threat <keyword> [--pid <pid>] [--context 0..1024]\n"
                   L"  help | --help (also shown when no arguments are given)\n"
                   L"  version | --version\n\n"
                   L"Common data options: --output <file>, --format json|csv, --timeout <seconds>\n"
                   L"Help/version must be invoked alone, without data options.\n"
                   L"CSV: <single module or risk> --format csv --output <file>; not all or tools.\n"
                   L"After execution, JSON/CSV exports return a JSON receipt; early errors return a JSON result.\n"
                   L"Export parent directories must exist; completed exports atomically replace the target.\n"
                   L"--path changes only file-scan directories, including when used with all.\n"
                   L"Timeout: 300 seconds by default, range 1..86400; cooperative cancellation.\n"
                   L"PID: integer 1..4294967295. Threat keyword: non-blank, at most 1024 Unicode code points.\n"
                   L"Threat context: 60 characters by default, range 0..1024; 0 keeps only the matched text.\n"
                   L"Use -- before option-like input; all options must precede this separator.\n"
                   L"IP enrichment is opt-in and sends deduplicated public IPs to ip-api.com over HTTP.\n"
                   L"network external lists deduplicated remote addresses without querying IP locations.\n"
                   L"Exit: 0 ok, 1 partial enumeration/required assessment, 2 arguments, 3 failed,\n"
                   L"      4 cancelled, 5 timeout, 6 output failure.\n";
        }

        Value S(const std::wstring& text) {
            return Value::String(text);
        }

        Value N(std::uint64_t value) {
            return Value::Number(value);
        }

        std::wstring FullPath(const std::wstring& input) {
            const DWORD size = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
            if (!size)
                return {};
            std::vector<wchar_t> buffer(static_cast<std::size_t>(size) + 1);
            const DWORD length =
                GetFullPathNameW(input.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
            if (!length || length >= buffer.size())
                return {};
            return std::wstring(buffer.data(), length);
        }

        bool SameFile(const std::wstring& a, const std::wstring& b) {
            if (_wcsicmp(a.c_str(), b.c_str()) == 0)
                return true;
            const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
            HANDLE first = CreateFileW(a.c_str(), FILE_READ_ATTRIBUTES, share, nullptr, OPEN_EXISTING,
                                       FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            HANDLE second = CreateFileW(b.c_str(), FILE_READ_ATTRIBUTES, share, nullptr, OPEN_EXISTING,
                                        FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            BY_HANDLE_FILE_INFORMATION x{}, y{};
            const bool equal = first != INVALID_HANDLE_VALUE && second != INVALID_HANDLE_VALUE &&
                               GetFileInformationByHandle(first, &x) && GetFileInformationByHandle(second, &y) &&
                               x.dwVolumeSerialNumber == y.dwVolumeSerialNumber &&
                               x.nFileIndexHigh == y.nFileIndexHigh && x.nFileIndexLow == y.nFileIndexLow;
            if (first != INVALID_HANDLE_VALUE)
                CloseHandle(first);
            if (second != INVALID_HANDLE_VALUE)
                CloseHandle(second);
            return equal;
        }

        int OutputCode(DWORD error) {
            return error == ERROR_CANCELLED ? 4 : error == ERROR_TIMEOUT ? 5 : 6;
        }

        Value Metadata(const std::wstring& started) {
            const auto identity = GetExecutionIdentity();
            DYNAMIC_TIME_ZONE_INFORMATION zone{};
            const DWORD zoneState = GetDynamicTimeZoneInformation(&zone);
            return Value::Object()
                .Add(L"tool_version", S(PRODUCT_VERSION_WSTRING))
                .Add(L"started_at", S(started))
                .Add(L"finished_at", S(UtcNow()))
                .Add(L"elevated",
                     identity.elevationState == FieldState::Available ? Value::Boolean(identity.elevated) : Value{})
                .Add(L"user_sid", identity.state == FieldState::Available ? S(identity.userSid) : Value{})
                .Add(L"process_bits", N(identity.processBits))
                .Add(L"os_bits", N(identity.osBits))
                .Add(L"time_zone", zoneState != TIME_ZONE_ID_INVALID ? S(zone.TimeZoneKeyName) : Value{});
        }

        void StartDocument(JsonWriter& json, const Options& o, const wchar_t* kind) {
            json.Object();
            json.Key(L"schema_version");
            json.Number(1);
            json.Key(L"kind");
            json.String(kind);
            json.Key(L"command");
            json.String(o.label);
            json.Key(L"data");
            json.Object();
        }

        void FinishDocument(JsonWriter& json, const std::wstring& started, int code, const Value& summary,
                            const Value& issues, bool unicodeReplaced = false) {
            json.EndObject();
            json.Key(L"summary");
            machine::Write(json, summary);
            json.Key(L"issues");
            machine::WriteIssues(json, issues, unicodeReplaced);
            json.Key(L"meta");
            machine::Write(json, Metadata(started));
            json.Key(L"status");
            json.String(machine::ExecutionName(code));
            json.Key(L"exit_code");
            json.Number(code);
            json.EndObject();
        }

        CollectionIssue Error(const wchar_t* code, const wchar_t* message, DWORD native = 0) {
            return { L"cli", L"", code, native, message, true };
        }

        int Failure(const Options& o, int code, const CollectionIssue& issue,
                    const std::atomic<std::uint64_t>& generation) {
            OutputSink sink;
            JsonWriter json(sink);
            if (!sink.Open(L"", false) ||
                !sink.ArmCancellation(generation, generation.load(), generation.load() != 0, GetTickCount64() + 3000)) {
                WriteDiagnostic(L"Unable to write the JSON error response.");
                return OutputCode(sink.Error());
            }
            StartDocument(json, o, L"result");
            Value issues = Value::Array();
            issues.Push(machine::Issue(issue));
            FinishDocument(json, UtcNow(), code, Value::Object().Add(L"count", N(0)), issues);
            if (!json.Complete() || !sink.Write(L"\n") || !sink.Finish()) {
                WriteDiagnostic(L"Unable to finish the JSON error response.");
                return OutputCode(sink.Error());
            }
            return code;
        }

        struct ModuleReport {
            std::wstring name;
            CollectionOutcome outcome;
            CollectionStatus enumeration = CollectionStatus::Failed;
            std::size_t emitted = 0;
        };

        class Runner {
        public:
            Runner(const Options& options, CollectionContext& context, const std::atomic<std::uint64_t>& generation)
                : options_(options), context_(context), generation_(generation), json_(sink_), started_(UtcNow()) {}

            int Run() {
                if (!options_.output.empty()) {
                    path_ = FullPath(options_.output);
                    if (path_.empty())
                        return Failure(
                            options_, 6,
                            Error(L"OUTPUT_PATH_INVALID", L"Cannot resolve the output path.", GetLastError()),
                            generation_);
                    if (options_.command == Command::FileInfo || options_.command == Command::FileHash ||
                        options_.command == Command::Signature) {
                        const auto input = files::ResolvePath(options_.target);
                        if (!input.empty() && SameFile(input, path_))
                            return Failure(
                                options_, 2,
                                Error(L"OUTPUT_IS_INPUT", L"The output path must not replace the input file."),
                                generation_);
                    }
                }
                if (!sink_.Open(path_, true) ||
                    !sink_.ArmCancellation(generation_, 0, false, context_.deadlineTick + 30000))
                    return Failure(options_, OutputCode(sink_.Error()),
                                   Error(L"OUTPUT_OPEN_FAILED", L"Cannot open the output destination.", sink_.Error()),
                                   generation_);
                if (!options_.csv)
                    StartDocument(json_, options_, L"result");
                if (options_.command == Command::Collect)
                    Collect();
                else if (options_.command == Command::Threat)
                    Threat();
                else
                    Tool();
                int code = CompletionCode();
                PrepareOutput();
                if (!options_.csv)
                    FinishDocument(json_, started_, code, Summary(), issues_);
                if (sink_.Error())
                    code = OutputCode(sink_.Error());
                bool written = false;
                // 采集失败、取消或超时时，不覆盖先前已保存的结果。
                if (path_.empty() || code <= 1) {
                    if ((!options_.csv && (!json_.Complete() || !sink_.Write(L"\n"))) || !sink_.Finish())
                        code = OutputCode(sink_.Error());
                    else
                        written = !path_.empty();
                }
                if (!path_.empty())
                    return Receipt(code, written);
                if (sink_.Error())
                    WriteDiagnostic(L"JSON output interrupted; discard the incomplete document. Native error: " +
                                    std::to_wstring(sink_.Error()));
                return code;
            }

        private:
            bool PrepareOutput() {
                if (context_.IsCancelled() && !finalizing_) {
                    finalizing_ = true;
                    return sink_.BeginCancellationFinalization();
                }
                return !sink_.Error();
            }

            void Fields(const Value& object) {
                for (const auto& field : object.children) {
                    json_.Key(field.name);
                    machine::Write(json_, field);
                }
            }

            template <class T, class Converter>
            void Emit(const std::wstring& name, CollectionResult<T>& result, Converter convert,
                      bool includeRecords = true) {
                PrepareOutput();
                const auto enumeration = machine::EnumerationStatus(name, result);
                std::size_t emitted = 0;
                if (!options_.csv) {
                    json_.Key(name);
                    json_.Object();
                    if (includeRecords) {
                        json_.Key(L"records");
                        json_.Array();
                    }
                } else if (includeRecords)
                    machine::CsvHeader(sink_, convert(T{}));
                if (includeRecords) {
                    for (const auto& record : result.records) {
                        if (sink_.Error())
                            break;
                        const auto value = convert(record);
                        if (options_.csv)
                            machine::CsvRecord(sink_, value);
                        else
                            machine::Write(json_, value);
                        if (!sink_.Error())
                            ++emitted;
                    }
                    if (!options_.csv)
                        json_.EndArray();
                }
                if (!options_.csv) {
                    Fields(machine::Report(name, result, enumeration, emitted));
                    json_.EndObject();
                }
                count_ += emitted;
                if ((options_.module == L"all" || options_.module == L"risk") && IsRiskModule(name) &&
                    !result.findings.empty()) {
                    std::map<std::wstring, Value> locations;
                    for (const auto& record : result.records) {
                        auto location = machine::LocateRisk(record);
                        if (!location.sourceKey.empty())
                            locations.emplace(std::move(location.sourceKey), std::move(location.details));
                    }
                    for (auto& finding : result.findings) {
                        const auto found = locations.find(finding.sourceKey);
                        Value context = found == locations.end() ? Value{} : std::move(found->second);
                        risks_.push_back({ std::move(finding), std::move(context) });
                    }
                }
                std::vector<RiskFinding>().swap(result.findings);
                if (path_.empty())
                    machine::CompactReportForSummary(result);
                reports_.push_back({ name, std::move(static_cast<CollectionOutcome&>(result)), enumeration, emitted });
            }

            template <class T>
            void Emit(const std::wstring& name, CollectionResult<T>& result, bool includeRecords = true) {
                Emit(
                    name, result,
                    [](const T& record) {
                        return machine::Row(record);
                    },
                    includeRecords);
            }

            void Collect() {
                if (options_.module == L"all")
                    planned_.assign(std::begin(AllModules), std::end(AllModules));
                else if (options_.module == L"risk")
                    planned_.assign(std::begin(RiskModules), std::end(RiskModules));
                else
                    planned_.push_back(options_.module);
                const bool rows = options_.module != L"risk";
                context_.fileCache = std::make_shared<files::EvidenceCache>();
                for (const auto& name : planned_) {
                    if (context_.ShouldStop() || sink_.Error())
                        break;
                    if (name == L"user") {
                        auto r = users::CollectUsers(context_);
                        Emit(name, r, rows);
                    } else if (name == L"process") {
                        auto r = process::CollectProcesses({}, context_);
                        Emit(name, r, rows);
                    } else if (name == L"network") {
                        auto r = network::CollectConnections({}, context_);
                        ip::LocationMap locations;
                        if (options_.ipLocation && !context_.ShouldStop()) {
                            std::vector<std::wstring> addresses;
                            for (const auto& record : r.records)
                                addresses.push_back(record.remoteAddress);
                            CollectionContext lookup = context_;
                            lookup.deadlineTick = (std::min)(context_.deadlineTick, TickNow() + 10000);
                            ip::LocationQuerySummary summary;
                            locations = ip::QueryPublicLocations(addresses, lookup, {}, &summary);
                            machine::ApplyLocationQuerySummary(r, summary);
                        }
                        Emit(name, r, [&](const network::Connection& value) {
                            return machine::Row(value, locations, options_.ipLocation);
                        });
                    } else if (name == L"autorun") {
                        auto r = autorun::CollectAutoruns({}, context_);
                        Emit(name, r, rows);
                    } else if (name == L"service") {
                        auto r = services::CollectServices({}, context_);
                        Emit(name, r, rows);
                    } else if (name == L"task") {
                        auto r = tasks::CollectTasks({}, context_);
                        Emit(name, r, rows);
                    } else if (name == L"traces") {
                        auto r = traces::CollectActivities(context_);
                        std::stable_sort(r.records.begin(), r.records.end());
                        Emit(name, r);
                    } else if (name == L"files") {
                        filescan::ScanConfig config;
                        if (!options_.path.empty()) {
                            config.useUserDownloads = false;
                            config.useNonSystemCDirs = false;
                            config.customPaths = { options_.path };
                        }
                        auto r = filescan::ScanFiles(config, context_);
                        std::stable_sort(r.records.begin(), r.records.end());
                        Emit(name, r);
                    }
                }
                if ((options_.module == L"all" || options_.module == L"risk") && !sink_.Error())
                    RiskSummary();
            }

            void RiskSummary() {
                CollectionResult<machine::LocatedRisk> result;
                result.startedAt = started_;
                result.finishedAt = UtcNow();
                result.assessment = AssessmentState::Complete;
                bool any = false, missing = false;
                for (const auto name : RiskModules) {
                    const auto found = std::find_if(reports_.begin(), reports_.end(), [&](const auto& report) {
                        return report.name == name;
                    });
                    SourceCoverage source;
                    source.source = name;
                    if (found == reports_.end())
                        missing = true;
                    else {
                        source.status = StatusName(found->enumeration);
                        source.collected = found->outcome.collected;
                        any |= found->enumeration == CollectionStatus::Complete ||
                               found->enumeration == CollectionStatus::Partial;
                        missing |= found->enumeration != CollectionStatus::Complete ||
                                   found->outcome.assessment != AssessmentState::Complete;
                    }
                    result.sources.push_back(std::move(source));
                }
                result.records = std::move(risks_);
                result.collected = result.records.size();
                if (missing)
                    result.assessment = AssessmentState::Incomplete;
                result.status = context_.ShouldStop() ? context_.StopStatus()
                                : !any                ? CollectionStatus::Failed
                                : missing             ? CollectionStatus::Partial
                                                      : CollectionStatus::Complete;
                Emit(L"risk", result);
            }

            void Tool() {
                if (options_.command == Command::Modules) {
                    planned_ = { L"modules" };
                    auto r = process::CollectModules(options_.pid, true, context_);
                    Emit(L"modules", r);
                    return;
                }
                if (options_.command == Command::Ip) {
                    planned_ = { L"ip" };
                    auto r = ip::QueryBatch({ options_.target }, context_);
                    Emit(L"ip", r);
                    return;
                }
                if (options_.command == Command::External) {
                    planned_ = { L"external" };
                    network::NetworkOptions request;
                    request.resolveProcesses = false;
                    auto connections = network::CollectConnections(request, context_);
                    network::FilterOptions filter;
                    filter.scope = network::ScopeFilter::External;
                    std::vector<const network::Connection*> selected;
                    for (const auto& record : connections.records)
                        if (network::MatchesConnection(record, filter))
                            selected.push_back(&record);
                    CollectionResult<Value> result;
                    static_cast<CollectionOutcome&>(result) = std::move(static_cast<CollectionOutcome&>(connections));
                    for (const auto& endpoint :
                         network::ExtractRemoteEndpoints(selected, network::UniqueBy::Address, &context_))
                        result.records.push_back(Value::Object()
                                                     .Add(L"address", S(endpoint.address))
                                                     .Add(L"ip_version", N(endpoint.isIPv6 ? 6 : 4)));
                    result.collected = result.records.size();
                    if (context_.ShouldStop())
                        result.status = context_.StopStatus();
                    Emit(L"external", result, [](const Value& v) {
                        return v;
                    });
                    return;
                }
                CollectionResult<Value> result;
                result.status = CollectionStatus::Complete;
                result.startedAt = UtcNow();
                std::wstring name = L"file";
                if (options_.command == Command::Version) {
                    name = L"version";
                    result.records.push_back(
                        Value::Object().Add(L"version", S(PRODUCT_VERSION_WSTRING)).Add(L"schema_version", N(1)));
                } else if (options_.command == Command::FileHash) {
                    name = L"hash";
                    auto hashes = files::CalculateHashes(options_.target, files::HashAlgorithm::All,
                                                         (std::numeric_limits<std::uint64_t>::max)(), context_);
                    result.status = hashes.status;
                    result.issues = std::move(hashes.issues);
                    const bool complete = hashes.status == CollectionStatus::Complete;
                    result.records.push_back(Value::Object()
                                                 .Add(L"path", S(files::ResolvePath(options_.target)))
                                                 .Add(L"size_bytes", complete ? N(hashes.size) : Value{})
                                                 .Add(L"md5", complete ? S(hashes.md5) : Value{})
                                                 .Add(L"sha1", complete ? S(hashes.sha1) : Value{})
                                                 .Add(L"sha256", complete ? S(hashes.sha256) : Value{}));
                } else {
                    const auto file = files::QueryFile(options_.target, true, &context_);
                    const auto& e = file.evidence;
                    result.issues = e.issues;
                    if (e.existence != FieldState::Available || !e.exists || file.directory) {
                        result.status = CollectionStatus::Failed;
                        if (result.issues.empty())
                            result.issues.push_back(
                                Error(L"NOT_A_READABLE_FILE", L"The target is not a readable file."));
                    }
                    if (options_.command == Command::Signature) {
                        name = L"signature";
                        result.records.push_back(
                            Value::Object()
                                .Add(L"path", e.resolvedPath.empty() ? S(options_.target) : S(e.resolvedPath))
                                .Add(L"exists",
                                     e.existence == FieldState::Available ? Value::Boolean(e.exists) : Value{})
                                .Add(L"signature", machine::Signature(e)));
                        if (result.status == CollectionStatus::Complete && e.signatureState != FieldState::Available)
                            result.status = CollectionStatus::Partial;
                    } else
                        result.records.push_back(machine::File(file));
                }
                planned_ = { name };
                result.collected = result.records.size();
                result.finishedAt = UtcNow();
                if (context_.ShouldStop())
                    result.status = context_.StopStatus();
                Emit(name, result, [](const Value& v) {
                    return v;
                });
            }

            void Threat() {
                planned_ = { L"threat" };
                PrepareOutput();
                json_.Key(L"threat");
                json_.Object();
                json_.Key(L"keyword");
                json_.String(options_.target);
                json_.Key(L"pid");
                if (options_.pid)
                    json_.Number(options_.pid);
                else
                    json_.Null();
                json_.Key(L"context_chars");
                json_.Number(options_.contextChars);
                json_.Key(L"records");
                json_.Array();
                std::size_t emitted = 0;
                auto result = threat::Search({ options_.target, options_.pid, options_.contextChars }, context_,
                                             [&](const threat::Match& match) {
                                                 if (context_.ShouldStop() || sink_.Error())
                                                     return false;
                                                 machine::Write(json_, machine::Row(match));
                                                 if (sink_.Error())
                                                     return false;
                                                 ++emitted;
                                                 return true;
                                             });
                PrepareOutput();
                json_.EndArray();
                Fields(machine::Report(L"threat", result, result.status, emitted));
                json_.Key(L"search");
                machine::Write(json_, Value::Object()
                                          .Add(L"processes_attempted", N(result.processesAttempted))
                                          .Add(L"processes_read", N(result.processesRead))
                                          .Add(L"processes_failed", N(result.processesFailed))
                                          .Add(L"processes_partial", N(result.processesPartial))
                                          .Add(L"matched_processes", N(result.matchedProcesses))
                                          .Add(L"bytes_read", N(result.bytesRead))
                                          .Add(L"output_stopped", Value::Boolean(result.outputStopped)));
                json_.EndObject();
                count_ += emitted;
                const auto status = result.status;
                if (path_.empty())
                    machine::CompactReportForSummary(result);
                reports_.push_back({ L"threat", std::move(static_cast<CollectionOutcome&>(result)), status, emitted });
            }

            int CompletionCode() const {
                if (sink_.Error())
                    return OutputCode(sink_.Error());
                if (context_.ShouldStop())
                    return StatusExitCode(context_.StopStatus());
                bool any = false, partial = false, failed = false;
                for (const auto& report : reports_) {
                    if (report.name == L"risk" && options_.module == L"all")
                        continue;
                    if (report.enumeration == CollectionStatus::Cancelled)
                        return 4;
                    if (report.enumeration == CollectionStatus::TimedOut)
                        return 5;
                    any |= report.enumeration == CollectionStatus::Complete ||
                           report.enumeration == CollectionStatus::Partial;
                    partial |= report.enumeration == CollectionStatus::Partial;
                    failed |= report.enumeration == CollectionStatus::Failed;
                }
                if (!any)
                    return 3;
                return partial || failed ? 1 : 0;
            }

            Value Summary() const {
                Value skipped = Value::Array();
                std::size_t attempted = 0;
                Value findings;
                for (const auto& name : planned_) {
                    const auto found = std::find_if(reports_.begin(), reports_.end(), [&](const auto& r) {
                        return r.name == name;
                    });
                    if (found == reports_.end())
                        skipped.Push(S(name));
                    else
                        ++attempted;
                }
                for (const auto& report : reports_)
                    if (report.name == L"risk")
                        findings = N(report.emitted);
                return Value::Object()
                    .Add(L"count", N(count_))
                    .Add(L"modules_requested", N(planned_.size()))
                    .Add(L"modules_attempted", N(attempted))
                    .Add(L"not_started", std::move(skipped))
                    .Add(L"risk_count", std::move(findings));
            }

            int Receipt(int code, bool written) {
                OutputSink output;
                JsonWriter writer(output);
                const auto baseline = generation_.load();
                if (!output.Open(L"", false) ||
                    !output.ArmCancellation(generation_, baseline, baseline != 0, TickNow() + 3000))
                    return OutputCode(output.Error());
                StartDocument(writer, options_, L"receipt");
                writer.Key(L"artifact");
                machine::Write(writer, Value::Object()
                                           .Add(L"path", S(path_))
                                           .Add(L"format", S(options_.csv ? L"csv" : L"json"))
                                           .Add(L"written", Value::Boolean(written)));
                writer.Key(L"modules");
                writer.Array();
                for (const auto& report : reports_)
                    machine::Write(writer,
                                   machine::Report(report.name, report.outcome, report.enumeration, report.emitted));
                writer.EndArray();
                if (sink_.Error())
                    issues_.Push(machine::Issue(
                        Error(L"OUTPUT_WRITE_FAILED", L"The output file was not committed.", sink_.Error())));
                FinishDocument(writer, started_, code, Summary(), issues_, sink_.UnicodeReplaced());
                if (!writer.Complete() || !output.Write(L"\n") || !output.Finish())
                    return OutputCode(output.Error());
                return code;
            }

            const Options& options_;
            CollectionContext& context_;
            const std::atomic<std::uint64_t>& generation_;
            OutputSink sink_;
            JsonWriter json_;
            std::wstring path_, started_;
            std::vector<std::wstring> planned_;
            std::vector<ModuleReport> reports_;
            std::vector<machine::LocatedRisk> risks_;
            Value issues_ = Value::Array();
            std::size_t count_ = 0;
            bool finalizing_ = false;
        };
    }

    int RunCli(int argc, wchar_t* argv[], const std::atomic_bool& cancelled,
               const std::atomic<std::uint64_t>& generation) {
        Options options;
        CollectionIssue argumentIssue;
        if (!Parse(argc, argv, options, argumentIssue))
            return Failure(options, 2, argumentIssue, generation);
        if (options.command == Command::Help) {
            OutputSink output;
            if (!output.Open(L"", false) || !output.ArmCancellation(generation, 0, false, TickNow() + 3000) ||
                !output.Write(Help()) || !output.Finish())
                return OutputCode(output.Error());
            return 0;
        }
        CollectionContext context;
        context.externalCancel = &cancelled;
        context.maxRecords = (std::numeric_limits<std::size_t>::max)();
        context.deadlineTick = TickNow() + static_cast<std::uint64_t>(options.timeoutSeconds) * 1000;
        Runner runner(options, context, generation);
        return runner.Run();
    }
}
