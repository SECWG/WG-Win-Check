#pragma once

#include "../../model/CollectionResult.h"
#include "../../runtime/CollectionContext.h"
#include "../../system/FileService.h"
#include "../../rules/RuleHelpers.h"
#include <string>
#include <vector>

namespace wgwc::core::services {
    struct Record {
        std::wstring serviceName, displayName, binaryPath, executablePath;
        std::wstring serviceDll, associatedFile, associationSource;
        std::wstring description, account, loadOrderGroup;
        std::vector<std::wstring> dependencies;
        std::wstring sourceKey, source, observedAt, registryPath;
        std::uint32_t serviceType = 0, currentState = 0, startType = 0;
        std::uint32_t processId = 0, controlsAccepted = 0, win32ExitCode = 0, serviceExitCode = 0;
        FieldState statusState = FieldState::Unknown;
        FieldState pidState = FieldState::Unknown;
        FieldState configState = FieldState::Unknown;
        FieldState descriptionState = FieldState::NotRequested;
        FieldState serviceDllState = FieldState::Unknown;
        FieldState delayedAutoStartState = FieldState::Unknown;
        bool delayedAutoStart = false;
        bool associationStable = false;
        files::FileInfo file;
        rules::DllSideLoadingRisk sideLoadingRisk = rules::DllSideLoadingRisk::None;
        FieldState sideLoadingState = FieldState::NotRequested;
        RiskAssessment assessment;
    };

    struct Options {
        bool verifySignatures = true;
    };

    struct Filter {
        std::wstring name;
        std::wstring vendor = L"all";
        std::wstring state = L"all";
        std::wstring startType = L"all";
    };

    struct Path {
        std::wstring value;
        bool stable = false;
    };

    struct EnumerationPage {
        bool success = false;
        std::uint32_t error = 0, previousResume = 0, nextResume = 0;
        std::size_t returned = 0;
    };
    enum class PageAction {
        Complete,
        Continue,
        Failed
    };

    const wchar_t* StateName(std::uint32_t state);
    const wchar_t* StartTypeName(std::uint32_t startType);
    bool IsAutoStart(std::uint32_t startType);
    bool IsMicrosoftGroup(const std::wstring& company);
    bool Matches(const Record& record, const Filter& filter);
    PageAction NextPage(const EnumerationPage& page);
    Path ResolveFile(const std::wstring& value);
    Path ResolveExecutable(const std::wstring& command);
    bool IsSvchost(const std::wstring& executable);
    void SelectAssociatedFile(Record& record);
    RiskAssessment AssessRisk(const Record& record);
    std::wstring RiskReasons(const RiskAssessment& assessment);
    CollectionResult<Record> CollectServices(const Options& options, const CollectionContext& context);
}
