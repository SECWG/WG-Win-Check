#include "../../system/Win32.h"
#include "AutorunModule.h"
#include <algorithm>

namespace wgwc::core::autorun {
    RiskAssessment AssessRisk(const Record& record) {
        RiskAssessment result;
        result.state = AssessmentState::Complete;
        result.level = RiskLevel::None;
        auto hit = [&](const wchar_t* id, RiskLevel level, const wchar_t* reason) {
            RiskHit value;
            value.ruleId = id;
            value.level = level;
            value.reason = reason;
            if (!record.file.evidence.evidenceId.empty())
                value.evidenceIds.push_back(record.file.evidence.evidenceId);
            result.hits.push_back(std::move(value));
            if (level > result.level)
                result.level = level;
        };
        auto unknown = [&](const wchar_t* id) {
            result.state = AssessmentState::Incomplete;
            result.unevaluatedRules.push_back(id);
        };
        if (record.type == Type::WmiSubscription) {
            hit(L"autorun.wmi-subscription", RiskLevel::Medium, L"WMI订阅");
            return result;
        }
        if (record.specialConfig) {
            if (record.configState != FieldState::Available)
                unknown(L"autorun.non-default-config");
            else if (!record.defaultConfig)
                hit(L"autorun.non-default-config", RiskLevel::Medium, L"非默认值");
            return result;
        }

        const auto& file = record.file;
        const auto& evidence = file.evidence;
        const bool existenceKnown = evidence.existence == FieldState::Available;
        const bool exists = existenceKnown && evidence.exists && !file.directory;
        const bool signatureKnown =
            evidence.signatureState == FieldState::Available && evidence.signature != SignatureState::Unknown;
        if (exists && signatureKnown && evidence.signature == SignatureState::Mismatch)
            hit(L"autorun.signature-mismatch", rules::SignatureRiskLevel(evidence),
                rules::SignatureRiskReason(evidence));

        if ((record.originState == FieldState::Available && record.originHidden) ||
            (file.attributesState == FieldState::Available && (file.attributes & FILE_ATTRIBUTE_HIDDEN)))
            hit(L"autorun.hidden-file", RiskLevel::Medium, L"隐藏文件");
        else if ((exists && file.attributesState != FieldState::Available) || record.originState == FieldState::Unknown)
            unknown(L"autorun.hidden-file");

        const auto command = rules::AssessCommandLine(record.command);
        if (command.level != RiskLevel::None)
            hit(L"autorun.suspicious-command", command.level, command.reason);
        if (record.sideLoadingState == FieldState::Available &&
            record.sideLoadingRisk == rules::DllSideLoadingRisk::High)
            hit(L"autorun.dll-side-loading", RiskLevel::High, L"疑似白加黑利用");
        if (command.level < RiskLevel::Medium && rules::IsCommandWrapperLaunch(record.command))
            hit(L"autorun.command-wrapper", RiskLevel::Medium, L"命令包装器启动");
        if (rules::HasDoubleExtensionSpoof(record.associatedFile) || rules::HasDoubleExtensionSpoof(record.filePath) ||
            rules::HasDoubleExtensionSpoof(record.name))
            hit(L"autorun.double-extension", RiskLevel::Medium, L"双扩展名伪装");
        if (rules::IsScriptFilePath(record.associatedFile))
            hit(L"autorun.script-persistence", RiskLevel::Medium, L"脚本持久化");
        if (record.sideLoadingState == FieldState::Available &&
            (record.sideLoadingRisk == rules::DllSideLoadingRisk::Medium ||
             record.sideLoadingRisk == rules::DllSideLoadingRisk::Low))
            hit(L"autorun.dll-side-loading",
                record.sideLoadingRisk == rules::DllSideLoadingRisk::Medium ? RiskLevel::Medium : RiskLevel::Low,
                L"疑似白加黑利用");
        if (existenceKnown && !evidence.exists)
            hit(L"autorun.file-missing", RiskLevel::Medium, L"文件不存在");
        else if (!existenceKnown || file.directory)
            unknown(L"autorun.file-missing");
        if (exists && signatureKnown && evidence.signature == SignatureState::Unsigned &&
            !rules::IsLikelyMicrosoftCompany(evidence.company))
            hit(L"autorun.third-party-unsigned", RiskLevel::Low, L"第三方程序未签名");

        if (exists && !signatureKnown) {
            unknown(L"autorun.signature-mismatch");
            unknown(L"autorun.third-party-unsigned");
            unknown(L"autorun.dll-side-loading");
        } else if (!existenceKnown) {
            unknown(L"autorun.signature-mismatch");
            unknown(L"autorun.third-party-unsigned");
            unknown(L"autorun.hidden-file");
            unknown(L"autorun.dll-side-loading");
        } else if (exists && evidence.signature == SignatureState::Signed &&
                   record.sideLoadingState != FieldState::Available)
            unknown(L"autorun.dll-side-loading");
        if (record.type == Type::RunOnceEx)
            hit(L"autorun.runonceex", RiskLevel::Medium, L"RunOnceEx 持久化");
        return result;
    }

    std::wstring RiskReasons(const RiskAssessment& assessment) {
        std::wstring reasons;
        for (const auto& hit : assessment.hits) {
            if (!reasons.empty())
                reasons += L"、";
            reasons += hit.reason;
        }
        return reasons;
    }
}
