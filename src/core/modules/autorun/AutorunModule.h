#pragma once

#include "../../model/CollectionResult.h"
#include "../../runtime/CollectionContext.h"
#include "../../system/FileService.h"
#include "../../rules/RuleHelpers.h"
#include <string>
#include <vector>

namespace wgwc::core::autorun {

    enum class Type {
        Registry,
        StartupFolder,
        Winlogon,
        IFEO,
        AppInit,
        WindowsLoad,
        SafeBoot,
        RunOnceEx,
        WmiSubscription
    };

    struct Association {
        std::wstring executablePath;
        std::wstring associatedFile;
        bool stable = false;
    };

    struct Record {
        Type type = Type::Registry;
        std::wstring name, location, command, filePath, associatedFile;
        std::wstring sourceKey, source, observedAt;
        std::wstring registryPath, registryValue, registryView;
        std::wstring originPath, filterName, consumerName, consumerType;
        std::wstring filterReference, consumerReference, scriptFilename, consumerCommand;
        FieldState consumerState = FieldState::NotApplicable;
        FieldState filterState = FieldState::NotApplicable;
        bool specialConfig = false;
        bool defaultConfig = true;
        FieldState configState = FieldState::NotApplicable;
        bool originHidden = false;
        FieldState originState = FieldState::NotApplicable;
        bool associationStable = false;
        files::FileInfo file;
        rules::DllSideLoadingRisk sideLoadingRisk = rules::DllSideLoadingRisk::None;
        FieldState sideLoadingState = FieldState::NotRequested;
        RiskAssessment assessment;
    };

    struct Options {
        std::wstring type = L"all";
        bool verifySignatures = true;
    };

    const wchar_t* TypeName(Type type);
    const wchar_t* TypeDisplay(Type type);
    bool TypeMatches(const std::wstring& filter, Type type);
    std::wstring SourceKey(Type type, const std::wstring& location, const std::wstring& name,
                           const std::wstring& discriminator = L"");
    Association ResolveCommand(const std::wstring& command, const std::wstring& workingDirectory = L"");
    Association ResolveFile(const std::wstring& path, const std::wstring& workingDirectory = L"");
    bool IsDefaultConfig(Type type, const std::wstring& name, const std::wstring& value);
    bool DecodeRegistryString(std::uint32_t type, const unsigned char* bytes, std::size_t size, std::wstring& text);
    std::wstring WmiReferenceClass(const std::wstring& reference);
    std::wstring WmiReferenceName(const std::wstring& reference);
    RiskAssessment AssessRisk(const Record& record);
    std::wstring RiskReasons(const RiskAssessment& assessment);
    CollectionResult<Record> CollectAutoruns(const Options& options, const CollectionContext& context);

    // 内部采集入口；WMI 采集不会创建或修改订阅。
    void CollectWmiSubscriptions(CollectionResult<Record>& result, const CollectionContext& context);
}
