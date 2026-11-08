#pragma once

#include "../../model/CollectionResult.h"
#include "../../runtime/CollectionContext.h"
#include "../../system/FileService.h"
#include "../../rules/RuleHelpers.h"
#include <functional>
#include <string>
#include <vector>

namespace wgwc::core::tasks {
    struct Path {
        std::wstring value;
        bool stable = false;
    };

    struct Target {
        Path path;
        std::wstring source, registryPath, registryView;
    };

    struct RelatedFile {
        std::size_t actionIndex = 0;
        Target target;
        files::FileInfo file;
        rules::DllSideLoadingRisk sideLoadingRisk = rules::DllSideLoadingRisk::None;
        FieldState sideLoadingState = FieldState::NotRequested;
    };

    struct Action {
        std::size_t index = 0;
        std::uint32_t type = 0;
        std::wstring id, execPath, arguments, workingDirectory, classId, data;
        FieldState typeState = FieldState::Unknown, detailState = FieldState::Unknown;
        FieldState execState = FieldState::Unknown, argumentsState = FieldState::Unknown;
        FieldState workingDirectoryState = FieldState::Unknown;
        FieldState classIdState = FieldState::Unknown, dataState = FieldState::Unknown;
        FieldState associationState = FieldState::Unknown;
        std::vector<std::size_t> relatedFileIndexes;
    };

    struct Trigger {
        std::size_t index = 0;
        std::uint32_t type = 0;
        std::wstring id, startBoundary, endBoundary;
        bool enabled = false;
        FieldState typeState = FieldState::Unknown, enabledState = FieldState::Unknown;
        FieldState detailState = FieldState::Unknown;
    };

    struct Record {
        std::wstring name, path, sourceKey, source, observedAt, author, description;
        std::wstring nextRunTimeLocal, lastRunTimeLocal;
        std::wstring principalUser, principalGroup;
        std::uint32_t state = 0, lastTaskResult = 0, missedRuns = 0;
        std::uint32_t logonType = 0, runLevel = 0;
        bool enabled = false, hidden = false;
        FieldState pathState = FieldState::Unknown, stateState = FieldState::Unknown;
        FieldState enabledState = FieldState::Unknown, hiddenState = FieldState::Unknown;
        FieldState definitionState = FieldState::Unknown, authorState = FieldState::Unknown;
        FieldState descriptionState = FieldState::Unknown, principalState = FieldState::Unknown;
        FieldState nextRunState = FieldState::Unknown, lastRunState = FieldState::Unknown;
        FieldState lastResultState = FieldState::Unknown, missedRunsState = FieldState::Unknown;
        FieldState actionsState = FieldState::Unknown, triggersState = FieldState::Unknown;
        std::vector<Action> actions;
        std::vector<Trigger> triggers;
        std::vector<RelatedFile> relatedFiles;
        RiskAssessment assessment;
    };

    struct Options {
        bool verifySignatures = true;
    };

    struct Filter {
        std::wstring name, path;
        std::wstring vendor = L"all", state = L"all", trigger = L"all";
    };

    using RegistryReader =
        std::function<std::uint32_t(const std::wstring&, const wchar_t*, std::uint32_t, std::wstring&)>;

    struct ComResolution {
        std::vector<Target> targets;
        std::vector<CollectionIssue> issues;
        FieldState state = FieldState::Unknown;
    };

    bool IsCommandWrapper(const std::wstring& path);
    Path ResolveFile(const std::wstring& value, const std::wstring& workingDirectory = L"");
    std::vector<Target> ResolveExec(const Action& action);
    bool NormalizeClassId(const std::wstring& value, std::wstring& normalized);
    ComResolution ResolveComHandler(const std::wstring& classId, const CollectionContext& context,
                                    const RegistryReader& reader = {});
    const wchar_t* StateName(std::uint32_t state);
    const wchar_t* ActionName(std::uint32_t type);
    const wchar_t* TriggerName(std::uint32_t type);
    const wchar_t* TriggerDisplay(std::uint32_t type);
    bool IsMicrosoftGroup(const Record& record);
    bool HasTrigger(const Record& record, const std::wstring& kind, bool enabledOnly = false);
    bool Matches(const Record& record, const Filter& filter);
    std::wstring ActionSummary(const Record& record);
    std::wstring TriggerSummary(const Record& record);
    RiskAssessment AssessRisk(const Record& record);
    std::wstring RiskReasons(const RiskAssessment& assessment);
    CollectionResult<Record> CollectTasks(const Options& options, const CollectionContext& context);
}
