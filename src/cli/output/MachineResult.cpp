#include "MachineResult.h"
#include <algorithm>
#include <cwchar>

namespace wgwc::cli::machine {
    using namespace core;

    Value Value::String(std::wstring value) {
        Value v;
        v.kind = Kind::String;
        v.text = std::move(value);
        return v;
    }

    Value Value::Number(std::uint64_t value) {
        Value v;
        v.kind = Kind::Number;
        v.number = value;
        return v;
    }

    Value Value::Boolean(bool value) {
        Value v;
        v.kind = Kind::Boolean;
        v.number = value ? 1 : 0;
        return v;
    }

    Value Value::Object() {
        Value v;
        v.kind = Kind::Object;
        return v;
    }

    Value Value::Array() {
        Value v;
        v.kind = Kind::Array;
        return v;
    }

    Value& Value::Add(const wchar_t* key, Value value) & {
        value.name = key;
        children.push_back(std::move(value));
        return *this;
    }

    Value& Value::Push(Value value) & {
        children.push_back(std::move(value));
        return *this;
    }

    Value&& Value::Add(const wchar_t* key, Value value) && {
        Add(key, std::move(value));
        return std::move(*this);
    }

    Value&& Value::Push(Value value) && {
        Push(std::move(value));
        return std::move(*this);
    }

    void Write(JsonWriter& w, const Value& v) {
        switch (v.kind) {
        case Value::Kind::String:
            w.String(v.text);
            break;
        case Value::Kind::Number:
            w.Number(v.number);
            break;
        case Value::Kind::Boolean:
            w.Bool(v.number != 0);
            break;
        case Value::Kind::Object:
            w.Object();
            for (const auto& item : v.children) {
                w.Key(item.name);
                Write(w, item);
            }
            w.EndObject();
            break;
        case Value::Kind::Array:
            w.Array();
            for (const auto& item : v.children)
                Write(w, item);
            w.EndArray();
            break;
        default:
            w.Null();
            break;
        }
    }

    std::wstring CompactJson(const Value& value, bool* unicodeReplaced) {
        std::wstring text;
        OutputSink sink;
        sink.OpenMemory(text);
        JsonWriter writer(sink);
        Write(writer, value);
        if (unicodeReplaced)
            *unicodeReplaced = writer.ReplacedUnicode();
        return text;
    }

    void CsvHeader(OutputSink& sink, const Value& record) {
        std::vector<std::wstring> columns;
        columns.reserve(record.children.size());
        for (const auto& field : record.children)
            columns.push_back(field.name);
        WriteCsvRow(sink, columns);
    }

    void CsvRecord(OutputSink& sink, const Value& record) {
        std::vector<std::wstring> cells;
        cells.reserve(record.children.size());
        for (const auto& field : record.children) {
            if (field.kind == Value::Kind::String)
                cells.push_back(field.text);
            else if (field.kind == Value::Kind::Null)
                cells.emplace_back();
            else {
                bool replaced = false;
                cells.push_back(CompactJson(field, &replaced));
                if (replaced)
                    sink.NoteUnicodeReplacement();
            }
        }
        WriteCsvRow(sink, cells);
    }

    namespace {
        Value S(const std::wstring& value, FieldState state = FieldState::Available) {
            return state == FieldState::Available ? Value::String(value) : Value{};
        }

        Value Optional(const std::wstring& value) {
            return value.empty() ? Value{} : Value::String(value);
        }

        Value N(std::uint64_t value, FieldState state = FieldState::Available) {
            return state == FieldState::Available ? Value::Number(value) : Value{};
        }

        Value B(bool value, FieldState state = FieldState::Available) {
            return state == FieldState::Available ? Value::Boolean(value) : Value{};
        }

        Value Time(std::uint64_t value, FieldState state = FieldState::Available) {
            return state == FieldState::Available && value ? S(FormatFileTime(value)) : Value{};
        }

        Value Time(const FILETIME& value) {
            return Time((static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime);
        }

        Value UnixTime(std::uint32_t value, FieldState state) {
            return value && value != MAXDWORD
                       ? Time(116444736000000000ULL + static_cast<std::uint64_t>(value) * 10000000, state)
                       : Value{};
        }

        Value Strings(const std::vector<std::wstring>& values) {
            Value array = Value::Array();
            for (const auto& value : values)
                array.Push(S(value));
            return array;
        }

        Value States(std::initializer_list<std::pair<const wchar_t*, FieldState>> fields) {
            Value result = Value::Object();
            for (const auto& field : fields)
                result.Add(field.first, S(FieldStateName(field.second)));
            return result;
        }

        std::wstring Hex(std::uint64_t value) {
            wchar_t text[24]{};
            swprintf_s(text, L"0x%llX", static_cast<unsigned long long>(value));
            return text;
        }

        Value Issues(const std::vector<CollectionIssue>& issues) {
            Value array = Value::Array();
            for (const auto& issue : issues)
                array.Push(Issue(issue));
            return array;
        }

        Value Action(const tasks::Action& a) {
            Value refs = Value::Array();
            for (const auto index : a.relatedFileIndexes)
                refs.Push(N(index));
            return Value::Object()
                .Add(L"index", N(a.index))
                .Add(L"type", S(tasks::ActionName(a.type), a.typeState))
                .Add(L"type_code", N(a.type, a.typeState))
                .Add(L"id", Optional(a.id))
                .Add(L"executable", S(a.execPath, a.execState))
                .Add(L"arguments", S(a.arguments, a.argumentsState))
                .Add(L"working_directory", S(a.workingDirectory, a.workingDirectoryState))
                .Add(L"class_id", S(a.classId, a.classIdState))
                .Add(L"data", S(a.data, a.dataState))
                .Add(L"related_file_indexes", std::move(refs))
                .Add(L"field_states", States({
                                          { L"detail",            a.detailState           },
                                          { L"executable",        a.execState             },
                                          { L"arguments",         a.argumentsState        },
                                          { L"working_directory", a.workingDirectoryState },
                                          { L"class_id",          a.classIdState          },
                                          { L"data",              a.dataState             },
                                          { L"association",       a.associationState      }
            }));
        }

        Value Trigger(const tasks::Trigger& t) {
            return Value::Object()
                .Add(L"index", N(t.index))
                .Add(L"type", S(tasks::TriggerName(t.type), t.typeState))
                .Add(L"type_code", N(t.type, t.typeState))
                .Add(L"id", Optional(t.id))
                .Add(L"enabled", B(t.enabled, t.enabledState))
                .Add(L"start_boundary", S(t.startBoundary, t.detailState))
                .Add(L"end_boundary", S(t.endBoundary, t.detailState))
                .Add(L"field_states",
                     States({
                         { L"type",    t.typeState    },
                         { L"enabled", t.enabledState },
                         { L"detail",  t.detailState  }
            }));
        }
    }

    const wchar_t* AssessmentName(AssessmentState state) {
        switch (state) {
        case AssessmentState::Complete:
            return L"complete";
        case AssessmentState::Incomplete:
            return L"incomplete";
        case AssessmentState::NotApplicable:
            return L"not_applicable";
        default:
            return L"not_requested";
        }
    }

    const wchar_t* LevelName(RiskLevel level) {
        switch (level) {
        case RiskLevel::Low:
            return L"low";
        case RiskLevel::Medium:
            return L"medium";
        case RiskLevel::High:
            return L"high";
        case RiskLevel::Critical:
            return L"critical";
        default:
            return L"none";
        }
    }

    const wchar_t* ExecutionName(int code) {
        switch (code) {
        case 0:
            return L"ok";
        case 1:
            return L"partial";
        case 2:
            return L"invalid_arguments";
        case 4:
            return L"cancelled";
        case 5:
            return L"timed_out";
        case 6:
            return L"output_failed";
        default:
            return L"failed";
        }
    }

    CollectionStatus EnumerationStatus(const std::wstring& module, const CollectionOutcome& outcome) {
        if (outcome.status == CollectionStatus::Cancelled || outcome.status == CollectionStatus::TimedOut ||
            outcome.status == CollectionStatus::Failed)
            return outcome.status;
        if (outcome.collectionTruncated)
            return CollectionStatus::Partial;
        // 可选补充信息获取失败，不改变基础枚举成功的状态。
        // 报告仍保留原始来源和诊断，用于说明证据覆盖范围。
        bool selected = false, complete = true, any = false;
        for (const auto& source : outcome.sources) {
            bool required = false;
            if (module == L"service")
                required = source.source == L"SCM:EnumServicesStatusExW:SERVICE_WIN32";
            else if (module == L"task")
                required = source.source == L"TaskScheduler:local-folders-and-tasks";
            else if (module == L"user")
                required = source.source == L"user.netapi.level3" || source.source == L"user.netapi.level0" ||
                           source.source == L"user.sam_names";
            else if (module == L"autorun")
                required = true;
            if (!required)
                continue;
            selected = true;
            complete &= source.status == L"complete";
            any |= source.status == L"complete" || source.status == L"partial" || source.collected != 0;
        }
        if (!selected)
            return outcome.status;
        if (complete)
            return CollectionStatus::Complete;
        return any || outcome.collected ? CollectionStatus::Partial : CollectionStatus::Failed;
    }

    Value Issue(const CollectionIssue& issue) {
        return Value::Object()
            .Add(L"source", S(issue.source))
            .Add(L"object_key", Optional(issue.objectKey))
            .Add(L"code", S(issue.code))
            .Add(L"native_code", N(issue.nativeCode))
            .Add(L"message", S(issue.message))
            .Add(L"affects_evidence", B(issue.affectsCompleteness));
    }

    void WriteIssues(JsonWriter& writer, const Value& issues, bool unicodeReplaced) {
        writer.Array();
        for (const auto& issue : issues.children)
            Write(writer, issue);
        if (unicodeReplaced || writer.ReplacedUnicode())
            Write(
                writer,
                Issue(
                    { L"cli.output", L"", L"INVALID_UNICODE_REPLACED", ERROR_NO_UNICODE_TRANSLATION,
                      L"Invalid UTF-16 code units were replaced by U+FFFD in output text; the affected text is not lossless.",
                      true }));
        writer.EndArray();
    }

    void ApplyLocationQuerySummary(CollectionOutcome& outcome, const ip::LocationQuerySummary& summary) {
        const bool complete = summary.state == ip::LookupState::Success || summary.state == ip::LookupState::NotFound ||
                              summary.state == ip::LookupState::LocalOnly;
        const wchar_t* status = complete ? L"complete" : summary.queried ? L"partial" : L"failed";
        if (summary.state == ip::LookupState::Cancelled)
            status = L"cancelled";
        else if (summary.state == ip::LookupState::TimedOut)
            status = L"timed_out";
        outcome.sources.push_back({ L"ip_location", status, summary.queried, summary.diagnostic.nativeCode });
        if (complete)
            return;
        CollectionIssue issue = summary.diagnostic;
        issue.source = L"ip_location";
        issue.affectsCompleteness = false;
        if (issue.code.empty()) {
            switch (summary.state) {
            case ip::LookupState::RateLimited:
                issue.code = L"IP_RATE_LIMITED";
                break;
            case ip::LookupState::Cancelled:
                issue.code = L"IP_LOCATION_CANCELLED";
                break;
            case ip::LookupState::TimedOut:
                issue.code = L"IP_LOCATION_TIMED_OUT";
                break;
            default:
                issue.code = L"IP_LOCATION_FAILED";
                break;
            }
            issue.message =
                L"Optional IP enrichment did not complete; connection records and prior successful lookups are retained.";
        }
        outcome.issues.push_back(std::move(issue));
    }

    void CompactReportForSummary(CollectionOutcome& outcome) {
        std::vector<CollectionIssue>().swap(outcome.issues);
        std::vector<SourceCoverage>().swap(outcome.sources);
        std::wstring().swap(outcome.startedAt);
        std::wstring().swap(outcome.finishedAt);
    }

    Value Report(const std::wstring& module, const CollectionOutcome& outcome, CollectionStatus enumeration,
                 std::size_t emitted) {
        Value sources = Value::Array();
        for (const auto& source : outcome.sources)
            sources.Push(Value::Object()
                             .Add(L"source", S(source.source))
                             .Add(L"status", S(source.status))
                             .Add(L"count", N(source.collected))
                             .Add(L"native_code", N(source.nativeCode)));
        return Value::Object()
            .Add(L"module", S(module))
            .Add(L"count", N(emitted))
            .Add(L"collected_count", N(outcome.collected))
            .Add(L"status", S(ExecutionName(StatusExitCode(enumeration))))
            .Add(L"coverage", Value::Object()
                                  .Add(L"enumeration", S(StatusName(enumeration)))
                                  .Add(L"evidence", S(StatusName(outcome.status)))
                                  .Add(L"risk", S(AssessmentName(outcome.assessment))))
            .Add(L"truncated", B(outcome.collectionTruncated))
            .Add(L"started_at", Optional(outcome.startedAt))
            .Add(L"finished_at", Optional(outcome.finishedAt))
            .Add(L"sources", std::move(sources))
            .Add(L"issues", Issues(outcome.issues));
    }

    Value Risk(const RiskAssessment& assessment) {
        Value hits = Value::Array();
        for (const auto& hit : assessment.hits)
            hits.Push(Value::Object()
                          .Add(L"rule_id", S(hit.ruleId))
                          .Add(L"level", S(LevelName(hit.level)))
                          .Add(L"reason", S(hit.reason))
                          .Add(L"evidence_ids", Strings(hit.evidenceIds)));
        return Value::Object()
            .Add(L"assessment", S(AssessmentName(assessment.state)))
            .Add(L"level", S(LevelName(assessment.level)))
            .Add(L"hits", std::move(hits))
            .Add(L"unevaluated_rules", Strings(assessment.unevaluatedRules));
    }

    Value Signature(const FileEvidence& e) {
        const wchar_t* source = e.signatureSource == SignatureSource::Embedded  ? L"embedded"
                                : e.signatureSource == SignatureSource::Catalog ? L"catalog"
                                                                                : L"none";
        return Value::Object()
            .Add(L"state", S(files::SignatureName(e.signature)))
            .Add(L"field_state", S(FieldStateName(e.signatureState)))
            .Add(L"source", S(source))
            .Add(L"publisher", Optional(e.publisher))
            .Add(L"native_code", N(e.signatureNativeCode))
            .Add(L"failure_reason", Optional(e.signatureFailureReason));
    }

    Value File(const files::FileInfo& file) {
        const auto& e = file.evidence;
        return Value::Object()
            .Add(L"path", Optional(e.resolvedPath))
            .Add(L"original_value", Optional(e.originalValue))
            .Add(L"evidence_id", Optional(e.evidenceId))
            .Add(L"identity", Optional(e.fileIdentity))
            .Add(L"exists", B(e.exists, e.existence))
            .Add(L"is_directory", B(file.directory, file.attributesState))
            .Add(L"attributes", N(file.attributes, file.attributesState))
            .Add(L"size_bytes", N(file.size, file.attributesState))
            .Add(L"created_at", Time(file.createdAt, file.attributesState))
            .Add(L"modified_at", Time(file.modifiedAt, file.attributesState))
            .Add(L"company", S(e.company, file.versionState))
            .Add(L"description", S(file.description, file.versionState))
            .Add(L"signature", Signature(e))
            .Add(L"field_states", States({
                                      { L"path",       e.resolution         },
                                      { L"exists",     e.existence          },
                                      { L"attributes", file.attributesState },
                                      { L"version",    file.versionState    }
        }))
            .Add(L"issues", Issues(e.issues));
    }

    Value Row(const users::UserRecord& r) {
        return Value::Object()
            .Add(L"source_key", S(users::SourceKey(r)))
            .Add(L"username", S(r.username))
            .Add(L"full_name", S(r.fullName, r.metadataState))
            .Add(L"description", S(r.description, r.metadataState))
            .Add(L"sid", S(r.sid, r.sidState))
            .Add(L"rid", N(r.rid, r.ridState))
            .Add(L"is_admin", B(r.isAdmin, r.adminState))
            .Add(L"disabled", B(r.isDisabled, r.metadataState))
            .Add(L"locked", B(r.isLocked, r.metadataState))
            .Add(L"password_not_required", B(r.passwordNotRequired, r.metadataState))
            .Add(L"password_never_expires", B(r.passwordNeverExpires, r.metadataState))
            .Add(L"password_age_seconds", N(r.passwordAge, r.metadataState))
            .Add(L"last_logon_at", UnixTime(r.lastLogon, r.metadataState))
            .Add(L"last_logoff_at", UnixTime(r.lastLogoff, r.metadataState))
            .Add(L"account_expires_at", UnixTime(r.accountExpires, r.metadataState))
            .Add(L"account_never_expires", B(r.accountExpires == MAXDWORD, r.metadataState))
            .Add(L"logon_count", N(r.numLogons, r.metadataState))
            .Add(L"bad_password_count", N(r.badPasswordCount, r.metadataState))
            .Add(L"hidden", B(r.isHidden, r.hiddenState))
            .Add(L"login_ui_hidden", B(r.loginUiHidden, r.loginUiHiddenState))
            .Add(L"dollar_hidden", B(r.dollarHidden, r.dollarHiddenState))
            .Add(L"sam_api_hidden", B(r.samApiHidden, r.samApiHiddenState))
            .Add(L"rid_hijacked", B(r.ridHijacked, r.ridHijackState))
            .Add(L"sam_rid", N(r.samRid, r.ridHijackState))
            .Add(L"observed_at", Optional(r.observedAt))
            .Add(L"source", S(r.source))
            .Add(L"field_states", States({
                                      { L"metadata",        r.metadataState      },
                                      { L"sid",             r.sidState           },
                                      { L"admin",           r.adminState         },
                                      { L"login_ui_hidden", r.loginUiHiddenState },
                                      { L"dollar_hidden",   r.dollarHiddenState  },
                                      { L"sam_api_hidden",  r.samApiHiddenState  },
                                      { L"hidden",          r.hiddenState        },
                                      { L"rid",             r.ridState           },
                                      { L"rid_hijack",      r.ridHijackState     }
        }))
            .Add(L"risk", Risk(r.assessment));
    }

    Value Row(const process::ProcessRecord& r) {
        const auto& p = r.process;
        return Value::Object()
            .Add(L"source_key", S(process::SourceKey(p)))
            .Add(L"pid", N(p.pid))
            .Add(L"ppid", N(p.ppid))
            .Add(L"name", S(p.name))
            .Add(L"path", S(p.path, p.pathState))
            .Add(L"command_line", S(p.commandLine, p.commandLineState))
            .Add(L"user", S(p.user, p.userState))
            .Add(L"thread_count", N(p.threadCount))
            .Add(L"created_at", Time(p.createdAt, p.createdAtState))
            .Add(L"observed_at", Optional(p.observedAt))
            .Add(L"field_states", States({
                                      { L"path",         p.pathState        },
                                      { L"command_line", p.commandLineState },
                                      { L"user",         p.userState        },
                                      { L"created_at",   p.createdAtState   }
        }))
            .Add(L"file", File(r.file))
            .Add(L"risk", Risk(r.assessment));
    }

    Value Row(const process::ModuleRecord& r) {
        return Value::Object()
            .Add(L"source_key", S(process::SourceKey(r)))
            .Add(L"pid", N(r.pid))
            .Add(L"process_created_at", Time(r.processCreatedAt))
            .Add(L"name", S(r.name))
            .Add(L"path", S(r.path))
            .Add(L"base_address", S(Hex(r.baseAddress)))
            .Add(L"image_size", N(r.imageSize, r.imageSizeState))
            .Add(L"image_size_state", S(FieldStateName(r.imageSizeState)))
            .Add(L"file", File(r.file));
    }

    Value Row(const network::Connection& r, const ip::LocationMap& locations, bool requested) {
        const bool tcp = r.transport == network::Transport::Tcp;
        const auto key = ip::PublicLookupKey(r.remoteAddress);
        const auto found = locations.find(key);
        const wchar_t* locationState = !requested                 ? L"not_requested"
                                       : key.empty()              ? L"not_applicable"
                                       : found == locations.end() ? L"unknown"
                                                                  : L"available";
        return Value::Object()
        .Add(L"protocol", S(tcp ? L"tcp" : L"udp"))
        .Add(L"ip_version", N(r.isIPv6 ? 6 : 4))
        .Add(L"local_address", S(r.localAddress))
        .Add(L"local_port", N(r.localPort))
        .Add(L"local_scope_id", N(r.localScopeId))
        .Add(L"remote_address", tcp ? S(r.remoteAddress) : Value{})
        .Add(L"remote_port", tcp ? N(r.remotePort) : Value{})
        .Add(L"remote_scope_id", tcp ? N(r.remoteScopeId) : Value{})
        .Add(L"state", tcp ? S(network::TcpStateName(r.tcpState)) : Value{})
        .Add(L"pid", N(r.pid))
        .Add(L"process_name", S(r.processName, r.processNameState))
        .Add(L"process_path", S(r.processPath, r.processPathState))
        .Add(L"process_created_at", Time(r.processCreatedAt, r.processTimeState))
        .Add(L"observed_at", Time(r.observedAt))
        .Add(L"remote_location", found == locations.end() ? Value{} : S(found->second))
        .Add(L"location_state", S(locationState))
        .Add(L"process_error", N(r.processError))
        .Add(L"field_states", States({ { L"process_name", r.processNameState },
                                       { L"process_path", r.processPathState },
                                       { L"process_created_at", r.processTimeState } }));
    }

    Value Row(const autorun::Record& r) {
        Value wmi = Value::Object()
                        .Add(L"filter_name", Optional(r.filterName))
                        .Add(L"consumer_name", Optional(r.consumerName))
                        .Add(L"consumer_type", Optional(r.consumerType))
                        .Add(L"filter_reference", Optional(r.filterReference))
                        .Add(L"consumer_reference", Optional(r.consumerReference))
                        .Add(L"script_filename", Optional(r.scriptFilename))
                        .Add(L"command", Optional(r.consumerCommand))
                        .Add(L"filter_state", S(FieldStateName(r.filterState)))
                        .Add(L"consumer_state", S(FieldStateName(r.consumerState)));
        return Value::Object()
            .Add(L"source_key", S(r.sourceKey))
            .Add(L"type", S(autorun::TypeName(r.type)))
            .Add(L"name", S(r.name))
            .Add(L"location", S(r.location))
            .Add(L"command", S(r.command))
            .Add(L"executable_path", Optional(r.filePath))
            .Add(L"associated_file", Optional(r.associatedFile))
            .Add(L"association_stable", B(r.associationStable))
            .Add(L"registry_path", Optional(r.registryPath))
            .Add(L"registry_value", Optional(r.registryValue))
            .Add(L"registry_view", Optional(r.registryView))
            .Add(L"origin_path", Optional(r.originPath))
            .Add(L"special_config", B(r.specialConfig))
            .Add(L"default_config", B(r.defaultConfig, r.configState))
            .Add(L"config_state", S(FieldStateName(r.configState)))
            .Add(L"wmi", r.type == autorun::Type::WmiSubscription ? std::move(wmi) : Value{})
            .Add(L"file", File(r.file))
            .Add(L"risk", Risk(r.assessment))
            .Add(L"observed_at", Optional(r.observedAt))
            .Add(L"source", S(r.source));
    }

    Value Row(const services::Record& r) {
        return Value::Object()
        .Add(L"source_key", S(r.sourceKey))
        .Add(L"name", S(r.serviceName))
        .Add(L"display_name", S(r.displayName))
        .Add(L"state", S(services::StateName(r.currentState), r.statusState))
        .Add(L"state_code", N(r.currentState, r.statusState))
        .Add(L"pid", N(r.processId, r.pidState))
        .Add(L"start_type", S(services::StartTypeName(r.startType), r.configState))
        .Add(L"start_type_code", N(r.startType, r.configState))
        .Add(L"service_type", N(r.serviceType, r.statusState))
        .Add(L"delayed_auto_start", B(r.delayedAutoStart, r.delayedAutoStartState))
        .Add(L"command", S(r.binaryPath, r.configState))
        .Add(L"account", S(r.account, r.configState))
        .Add(L"description", S(r.description, r.descriptionState))
        .Add(L"executable_path", Optional(r.executablePath))
        .Add(L"service_dll", S(r.serviceDll, r.serviceDllState))
        .Add(L"associated_file", Optional(r.associatedFile))
        .Add(L"association_source", S(r.associationSource))
        .Add(L"association_stable", B(r.associationStable))
        .Add(L"dependencies", r.configState == FieldState::Available ? Strings(r.dependencies) : Value{})
        .Add(L"registry_path", S(r.registryPath))
        .Add(L"observed_at", Optional(r.observedAt))
        .Add(L"field_states", States({ { L"status", r.statusState },
                                       { L"pid", r.pidState },
                                       { L"config", r.configState },
                                       { L"description", r.descriptionState },
                                       { L"service_dll", r.serviceDllState },
                                       { L"delayed_auto_start", r.delayedAutoStartState } }))
        .Add(L"file", File(r.file))
        .Add(L"risk", Risk(r.assessment));
    }

    Value Row(const tasks::Record& r) {
        Value actions = Value::Array(), triggers = Value::Array(), related = Value::Array();
        for (const auto& a : r.actions)
            actions.Push(Action(a));
        for (const auto& t : r.triggers)
            triggers.Push(Trigger(t));
        for (const auto& f : r.relatedFiles)
            related.Push(Value::Object()
                             .Add(L"action_index", N(f.actionIndex))
                             .Add(L"path", Optional(f.target.path.value))
                             .Add(L"stable", B(f.target.path.stable))
                             .Add(L"source", S(f.target.source))
                             .Add(L"registry_path", Optional(f.target.registryPath))
                             .Add(L"registry_view", Optional(f.target.registryView))
                             .Add(L"file", File(f.file)));
        return Value::Object()
            .Add(L"source_key", S(r.sourceKey))
            .Add(L"name", S(r.name))
            .Add(L"path", S(r.path, r.pathState))
            .Add(L"state", S(tasks::StateName(r.state), r.stateState))
            .Add(L"enabled", B(r.enabled, r.enabledState))
            .Add(L"hidden", B(r.hidden, r.hiddenState))
            .Add(L"author", S(r.author, r.authorState))
            .Add(L"description", S(r.description, r.descriptionState))
            .Add(L"principal_user", S(r.principalUser, r.principalState))
            .Add(L"principal_group", S(r.principalGroup, r.principalState))
            .Add(L"logon_type", N(r.logonType, r.principalState))
            .Add(L"run_level", N(r.runLevel, r.principalState))
            .Add(L"next_run_local", S(r.nextRunTimeLocal, r.nextRunState))
            .Add(L"last_run_local", S(r.lastRunTimeLocal, r.lastRunState))
            .Add(L"last_result", N(r.lastTaskResult, r.lastResultState))
            .Add(L"missed_runs", N(r.missedRuns, r.missedRunsState))
            .Add(L"actions", std::move(actions))
            .Add(L"triggers", std::move(triggers))
            .Add(L"related_files", std::move(related))
            .Add(L"field_states", States({
                                      { L"path",        r.pathState        },
                                      { L"state",       r.stateState       },
                                      { L"enabled",     r.enabledState     },
                                      { L"hidden",      r.hiddenState      },
                                      { L"definition",  r.definitionState  },
                                      { L"author",      r.authorState      },
                                      { L"description", r.descriptionState },
                                      { L"principal",   r.principalState   },
                                      { L"next_run",    r.nextRunState     },
                                      { L"last_run",    r.lastRunState     },
                                      { L"last_result", r.lastResultState  },
                                      { L"missed_runs", r.missedRunsState  },
                                      { L"actions",     r.actionsState     },
                                      { L"triggers",    r.triggersState    }
        }))
            .Add(L"risk", Risk(r.assessment))
            .Add(L"observed_at", Optional(r.observedAt))
            .Add(L"source", S(r.source));
    }

    Value Row(const traces::Record& r) {
        const wchar_t* name = L"unknown";
        switch (r.type) {
        case traces::ActivityType::SystemBoot:
            name = L"system_boot";
            break;
        case traces::ActivityType::SystemSleep:
            name = L"system_sleep";
            break;
        case traces::ActivityType::SystemWake:
            name = L"system_wake";
            break;
        case traces::ActivityType::UserLogin:
            name = L"user_login";
            break;
        case traces::ActivityType::ProgramExec:
            name = L"program_exec";
            break;
        case traces::ActivityType::DocumentAccess:
            name = L"document_access";
            break;
        case traces::ActivityType::SoftwareInstall:
            name = L"software_install";
            break;
        }
        return Value::Object()
            .Add(L"timestamp", Time(r.timestamp))
            .Add(L"type", S(name))
            .Add(L"description", S(r.description))
            .Add(L"details", S(r.details))
            .Add(L"source", S(r.source));
    }

    Value Row(const filescan::Record& r) {
        return Value::Object()
            .Add(L"name", S(r.fileName))
            .Add(L"path", S(r.filePath))
            .Add(L"size_bytes", N(r.fileSize))
            .Add(L"created_at", Time(r.creationTime))
            .Add(L"modified_at", Time(r.lastWriteTime));
    }

    RiskLocation LocateRisk(const users::UserRecord& r) {
        if (r.assessment.hits.empty())
            return {};
        return { users::SourceKey(r),
                 Value::Object().Add(L"sid", S(r.sid, r.sidState)).Add(L"rid", N(r.rid, r.ridState)) };
    }

    RiskLocation LocateRisk(const process::ProcessRecord& r) {
        if (r.assessment.hits.empty())
            return {};
        const auto& p = r.process;
        return { process::SourceKey(p), Value::Object()
                                            .Add(L"pid", N(p.pid))
                                            .Add(L"created_at", Time(p.createdAt, p.createdAtState))
                                            .Add(L"path", S(p.path, p.pathState))
                                            .Add(L"command_line", S(p.commandLine, p.commandLineState))
                                            .Add(L"file_evidence_id", Optional(r.file.evidence.evidenceId)) };
    }

    RiskLocation LocateRisk(const autorun::Record& r) {
        if (r.assessment.hits.empty())
            return {};
        auto details = Value::Object()
                           .Add(L"type", S(autorun::TypeName(r.type)))
                           .Add(L"location", S(r.location))
                           .Add(L"command", S(r.command))
                           .Add(L"associated_file", Optional(r.associatedFile))
                           .Add(L"association_stable", B(r.associationStable))
                           .Add(L"registry_path", Optional(r.registryPath))
                           .Add(L"file_evidence_id", Optional(r.file.evidence.evidenceId));
        if (r.type == autorun::Type::WmiSubscription)
            details.Add(L"wmi", Value::Object()
                                    .Add(L"filter_reference", Optional(r.filterReference))
                                    .Add(L"consumer_reference", Optional(r.consumerReference))
                                    .Add(L"consumer_type", Optional(r.consumerType))
                                    .Add(L"script_filename", Optional(r.scriptFilename)));
        return { r.sourceKey, std::move(details) };
    }

    RiskLocation LocateRisk(const services::Record& r) {
        if (r.assessment.hits.empty())
            return {};
        return { r.sourceKey, Value::Object()
                                  .Add(L"pid", N(r.processId, r.pidState))
                                  .Add(L"command", S(r.binaryPath, r.configState))
                                  .Add(L"associated_file", Optional(r.associatedFile))
                                  .Add(L"association_stable", B(r.associationStable))
                                  .Add(L"file_evidence_id", Optional(r.file.evidence.evidenceId)) };
    }

    RiskLocation LocateRisk(const tasks::Record& r) {
        if (r.assessment.hits.empty())
            return {};
        Value actions = Value::Array(), related = Value::Array();
        for (const auto& a : r.actions)
            actions.Push(Value::Object()
                             .Add(L"index", N(a.index))
                             .Add(L"type", S(tasks::ActionName(a.type), a.typeState))
                             .Add(L"executable", S(a.execPath, a.execState))
                             .Add(L"arguments", S(a.arguments, a.argumentsState))
                             .Add(L"working_directory", S(a.workingDirectory, a.workingDirectoryState))
                             .Add(L"class_id", S(a.classId, a.classIdState)));
        for (const auto& f : r.relatedFiles)
            related.Push(Value::Object()
                             .Add(L"action_index", N(f.actionIndex))
                             .Add(L"path", Optional(f.target.path.value))
                             .Add(L"stable", B(f.target.path.stable))
                             .Add(L"file_evidence_id", Optional(f.file.evidence.evidenceId)));
        return { r.sourceKey, Value::Object()
                                  .Add(L"path", S(r.path, r.pathState))
                                  .Add(L"actions_state", S(FieldStateName(r.actionsState)))
                                  .Add(L"actions", std::move(actions))
                                  .Add(L"related_files", std::move(related)) };
    }

    Value Row(const LocatedRisk& r) {
        return Row(r.finding).Add(L"context", r.context);
    }

    Value Row(const RiskFinding& r) {
        return Value::Object()
            .Add(L"module", S(r.moduleId))
            .Add(L"source_key", S(r.sourceKey))
            .Add(L"object_name", S(r.objectName))
            .Add(L"observed_at", Optional(r.updatedAt))
            .Add(L"risk", Risk(r.assessment));
    }

    Value Row(const ip::Record& r) {
        return Value::Object()
            .Add(L"input", S(r.input))
            .Add(L"address", Optional(r.address.normalized))
            .Add(L"address_type", S(ip::AddressTypeName(r.address.type)))
            .Add(L"ip_version", N(r.address.ipv6 ? 6 : 4))
            .Add(L"lookup_state", S(ip::LookupStateName(r.state)))
            .Add(L"country", Optional(r.country))
            .Add(L"region", Optional(r.region))
            .Add(L"city", Optional(r.city))
            .Add(L"isp", Optional(r.isp))
            .Add(L"location", Optional(r.location))
            .Add(L"observed_at", Optional(r.observedAt))
            .Add(L"network_attempted", B(r.networkAttempted))
            .Add(L"error_code", Optional(r.errorCode))
            .Add(L"native_code", N(r.nativeCode))
            .Add(L"http_status", N(r.httpStatus))
            .Add(L"retry_after_seconds", N(r.retryAfterSeconds));
    }

    Value Row(const threat::Match& r) {
        return Value::Object()
            .Add(L"pid", N(r.pid))
            .Add(L"process_name", S(r.processName))
            .Add(L"process_path", Optional(r.processPath))
            .Add(L"address", S(Hex(r.address)))
            .Add(L"encoding", S(r.matchType))
            .Add(L"context", S(r.context));
    }
}
