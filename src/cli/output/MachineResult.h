#pragma once
#include "Output.h"
#include "../../core/modules/user/UserModule.h"
#include "../../core/modules/process/ProcessModule.h"
#include "../../core/modules/network/NetworkModule.h"
#include "../../core/modules/autorun/AutorunModule.h"
#include "../../core/modules/service/ServiceModule.h"
#include "../../core/modules/task/TaskModule.h"
#include "../../core/modules/traces/TraceModule.h"
#include "../../core/modules/filescan/FileScanModule.h"
#include "../../core/modules/threat/ThreatSearch.h"
#include "../../core/system/IpLookupService.h"
#include <initializer_list>
#include <utility>

namespace wgwc::cli::machine {
    // 仅表示单条记录，不在内存中复制整个采集快照。
    struct Value {
        enum class Kind {
            Null,
            String,
            Number,
            Boolean,
            Object,
            Array
        };
        Kind kind = Kind::Null;
        std::wstring name, text;
        std::uint64_t number = 0;
        std::vector<Value> children;
        static Value String(std::wstring text);
        static Value Number(std::uint64_t number);
        static Value Boolean(bool value);
        static Value Object();
        static Value Array();
        Value& Add(const wchar_t* name, Value value) &;
        Value&& Add(const wchar_t* name, Value value) &&;
        Value& Push(Value value) &;
        Value&& Push(Value value) &&;
    };

    void Write(JsonWriter& writer, const Value& value);
    std::wstring CompactJson(const Value& value, bool* unicodeReplaced = nullptr);
    void CsvHeader(OutputSink& sink, const Value& record);
    void CsvRecord(OutputSink& sink, const Value& record);
    const wchar_t* AssessmentName(core::AssessmentState state);
    const wchar_t* LevelName(core::RiskLevel level);
    const wchar_t* ExecutionName(int exitCode);
    core::CollectionStatus EnumerationStatus(const std::wstring& module, const core::CollectionOutcome& outcome);
    Value Issue(const core::CollectionIssue& issue);
    void WriteIssues(JsonWriter& writer, const Value& issues, bool unicodeReplaced = false);
    void ApplyLocationQuerySummary(core::CollectionOutcome& outcome, const core::ip::LocationQuerySummary& summary);
    void CompactReportForSummary(core::CollectionOutcome& outcome);

    struct RiskLocation {
        std::wstring sourceKey;
        Value details;
    };

    struct LocatedRisk {
        core::RiskFinding finding;
        Value context;
    };

    template <class T> RiskLocation LocateRisk(const T&) {
        return {};
    }

    RiskLocation LocateRisk(const core::users::UserRecord& record);
    RiskLocation LocateRisk(const core::process::ProcessRecord& record);
    RiskLocation LocateRisk(const core::autorun::Record& record);
    RiskLocation LocateRisk(const core::services::Record& record);
    RiskLocation LocateRisk(const core::tasks::Record& record);
    Value Row(const LocatedRisk& record);
    Value Report(const std::wstring& module, const core::CollectionOutcome& outcome, core::CollectionStatus enumeration,
                 std::size_t emitted);
    Value Risk(const core::RiskAssessment& assessment);
    Value Signature(const core::FileEvidence& evidence);
    Value File(const core::files::FileInfo& file);
    Value Row(const core::users::UserRecord& record);
    Value Row(const core::process::ProcessRecord& record);
    Value Row(const core::process::ModuleRecord& record);
    Value Row(const core::network::Connection& record, const core::ip::LocationMap& locations = {},
              bool locationRequested = false);
    Value Row(const core::autorun::Record& record);
    Value Row(const core::services::Record& record);
    Value Row(const core::tasks::Record& record);
    Value Row(const core::traces::Record& record);
    Value Row(const core::filescan::Record& record);
    Value Row(const core::RiskFinding& record);
    Value Row(const core::ip::Record& record);
    Value Row(const core::threat::Match& record);
}
