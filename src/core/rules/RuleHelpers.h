#pragma once
#include "../model/FileEvidence.h"
#include "../model/RiskFinding.h"

namespace wgwc::core::rules {
    enum class DllSideLoadingRisk {
        None = 0,
        Low,
        Medium,
        High
    };
    std::wstring ToLower(const std::wstring& value);
    std::wstring ExpandEnvStrings(const std::wstring& value);
    bool IsExistingFile(const std::wstring& path);
    void ClearDllSideLoadingRiskCache();
    DllSideLoadingRisk DetectDllSideLoadingRisk(const std::wstring& path, SignatureState signature);
    bool ContainsBidiOrZeroWidthChar(const std::wstring& text);
    bool HasHiddenNamePrefix(const std::wstring& name);
    bool HasDoubleExtensionSpoof(const std::wstring& text);

    struct CommandLineAssessment {
        RiskLevel level = RiskLevel::None;
        const wchar_t* reason = L"";
        bool scriptExecution = false;
    };

    CommandLineAssessment AssessCommandLine(const std::wstring& command);
    RiskLevel SignatureRiskLevel(const FileEvidence& evidence);
    const wchar_t* SignatureRiskReason(const FileEvidence& evidence);
    RiskLevel HiddenNameRiskLevel(const std::wstring& name);
    bool IsCommandWrapperLaunch(const std::wstring& command);
    bool IsScriptFilePath(const std::wstring& path);
    bool IsLikelyMicrosoftCompany(const std::wstring& company);
    bool IsSystemNameSpoof(const std::wstring& objectName, const std::wstring& filePath);
}
