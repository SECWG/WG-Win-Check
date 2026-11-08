#include "../../system/Win32.h"
#include "ServiceModule.h"
#include <algorithm>

namespace wgwc::core::services {
    RiskAssessment AssessRisk(const Record& record) {
        RiskAssessment result;
        result.state = AssessmentState::Complete;
        result.level = RiskLevel::None;
        auto hit = [&](const wchar_t* ruleId, RiskLevel level, const wchar_t* reason) {
            RiskHit value;
            value.ruleId = ruleId;
            value.level = level;
            value.reason = reason;
            if (!record.file.evidence.evidenceId.empty())
                value.evidenceIds.push_back(record.file.evidence.evidenceId);
            result.hits.push_back(std::move(value));
            if (level > result.level)
                result.level = level;
        };
        auto unknown = [&](const wchar_t* ruleId) {
            result.state = AssessmentState::Incomplete;
            if (std::find(result.unevaluatedRules.begin(), result.unevaluatedRules.end(), ruleId) ==
                result.unevaluatedRules.end())
                result.unevaluatedRules.push_back(ruleId);
        };
        const auto& file = record.file;
        const auto& evidence = file.evidence;
        const bool existenceKnown = evidence.existence == FieldState::Available;
        const bool exists = existenceKnown && evidence.exists && !file.directory;
        const bool signatureKnown =
            evidence.signatureState == FieldState::Available && evidence.signature != SignatureState::Unknown;
        const bool configKnown = record.configState == FieldState::Available;
        if (exists && signatureKnown && evidence.signature == SignatureState::Mismatch)
            hit(L"service.signature-mismatch", rules::SignatureRiskLevel(evidence),
                rules::SignatureRiskReason(evidence));
        if (exists && file.attributesState == FieldState::Available && (file.attributes & FILE_ATTRIBUTE_HIDDEN))
            hit(L"service.hidden-file", RiskLevel::Medium, L"隐藏文件");
        else if (!existenceKnown || (exists && file.attributesState != FieldState::Available))
            unknown(L"service.hidden-file");
        const auto command = configKnown ? rules::AssessCommandLine(record.binaryPath) : rules::CommandLineAssessment{};
        if (command.level != RiskLevel::None)
            hit(L"service.suspicious-command", command.level, command.reason);
        if (exists && record.sideLoadingState == FieldState::Available &&
            record.sideLoadingRisk != rules::DllSideLoadingRisk::None) {
            const auto level = record.sideLoadingRisk == rules::DllSideLoadingRisk::High
                                   ? RiskLevel::High
                                   : (record.sideLoadingRisk == rules::DllSideLoadingRisk::Medium ? RiskLevel::Medium
                                                                                                  : RiskLevel::Low);
            hit(L"service.dll-side-loading", level, L"疑似白加黑利用");
        }
        const auto nameLevel = rules::HiddenNameRiskLevel(record.serviceName);
        if (nameLevel != RiskLevel::None)
            hit(L"service.hidden-name", nameLevel, nameLevel == RiskLevel::Low ? L"名称前导空格" : L"隐藏服务名");
        if (configKnown && command.level < RiskLevel::Medium && rules::IsCommandWrapperLaunch(record.binaryPath))
            hit(L"service.command-wrapper", RiskLevel::Medium, L"命令包装器启动");
        if (configKnown && (rules::HasDoubleExtensionSpoof(record.associatedFile) ||
                            rules::HasDoubleExtensionSpoof(record.executablePath)))
            hit(L"service.double-extension", RiskLevel::Medium, L"双扩展名伪装");
        if (record.associationStable) {
            if (rules::IsSystemNameSpoof(record.serviceName, record.associatedFile) ||
                rules::IsSystemNameSpoof(record.displayName, record.associatedFile))
                hit(L"service.name-spoof", RiskLevel::Medium, L"名称伪装");
        } else
            unknown(L"service.name-spoof");
        if (exists && signatureKnown && evidence.signature == SignatureState::Unsigned &&
            !rules::IsLikelyMicrosoftCompany(evidence.company)) {
            if (configKnown && IsAutoStart(record.startType))
                hit(L"service.auto-third-party-unsigned", RiskLevel::Medium, L"自动启动第三方未签名");
            else {
                hit(L"service.third-party-unsigned", RiskLevel::Low, L"第三方程序未签名");
                if (!configKnown)
                    unknown(L"service.auto-third-party-unsigned");
            }
        }
        if (existenceKnown && !evidence.exists)
            hit(L"service.file-missing", RiskLevel::Low, L"文件不存在");
        else if (!existenceKnown || file.directory)
            unknown(L"service.file-missing");
        if (!configKnown) {
            unknown(L"service.suspicious-command");
            unknown(L"service.command-wrapper");
            unknown(L"service.double-extension");
        }
        if (!existenceKnown || (exists && !signatureKnown)) {
            unknown(L"service.signature-mismatch");
            unknown(L"service.third-party-unsigned");
            unknown(L"service.auto-third-party-unsigned");
            unknown(L"service.dll-side-loading");
        } else if (exists && evidence.signature == SignatureState::Signed &&
                   record.sideLoadingState != FieldState::Available)
            unknown(L"service.dll-side-loading");
        return result;
    }

    std::wstring RiskReasons(const RiskAssessment& assessment) {
        std::wstring result;
        for (const auto& hit : assessment.hits) {
            if (!result.empty())
                result += L"、";
            result += hit.reason;
        }
        return result;
    }
}
