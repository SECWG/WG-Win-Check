#include "../../system/Win32.h"
#include "TaskModule.h"
#include <taskschd.h>
#include <algorithm>

namespace wgwc::core::tasks {
    RiskAssessment AssessRisk(const Record& record) {
        RiskAssessment result;
        result.state = AssessmentState::Complete;
        result.level = RiskLevel::None;
        auto unknown = [&](const wchar_t* id) {
            result.state = AssessmentState::Incomplete;
            if (std::find(result.unevaluatedRules.begin(), result.unevaluatedRules.end(), id) ==
                result.unevaluatedRules.end())
                result.unevaluatedRules.push_back(id);
        };
        auto hit = [&](const wchar_t* id, RiskLevel level, const wchar_t* reason,
                       const std::wstring& evidenceId = L"") {
            auto it = std::find_if(result.hits.begin(), result.hits.end(), [&](const auto& item) {
                return item.ruleId == id;
            });
            if (it == result.hits.end()) {
                RiskHit item;
                item.ruleId = id;
                item.level = level;
                item.reason = reason;
                result.hits.push_back(std::move(item));
                it = result.hits.end() - 1;
            } else if (level > it->level) {
                it->level = level;
                it->reason = reason;
            }
            if (!evidenceId.empty() &&
                std::find(it->evidenceIds.begin(), it->evidenceIds.end(), evidenceId) == it->evidenceIds.end())
                it->evidenceIds.push_back(evidenceId);
            if (level > result.level)
                result.level = level;
        };
        const bool microsoft = IsMicrosoftGroup(record);
        const bool groupKnown =
            microsoft || (record.pathState == FieldState::Available && record.authorState == FieldState::Available);
        const auto nameLevel = rules::HiddenNameRiskLevel(record.name);
        if (nameLevel != RiskLevel::None)
            hit(L"task.hidden-name", nameLevel, nameLevel == RiskLevel::Low ? L"名称前导空格" : L"隐藏任务名");
        // 任务的 Hidden 设置明确不参与风险判定。
        bool script = false;
        if (rules::HasDoubleExtensionSpoof(record.name))
            hit(L"task.double-extension", RiskLevel::Medium, L"双扩展名伪装");
        for (const auto& action : record.actions) {
            if (action.typeState != FieldState::Available) {
                unknown(L"task.action-type");
                continue;
            }
            if (action.type == TASK_ACTION_EXEC) {
                if (action.execState == FieldState::Available && action.argumentsState == FieldState::Available) {
                    const bool quoted = action.execPath.size() >= 2 && action.execPath.front() == L'"' &&
                                        action.execPath.back() == L'"';
                    const auto command = (quoted ? action.execPath : std::wstring(1, L'"') + action.execPath + L'"') +
                                         L" " + action.arguments;
                    const auto commandRisk = rules::AssessCommandLine(command);
                    // 分类元数据不能豁免已命中的命令风险规则。
                    if (commandRisk.level != RiskLevel::None)
                        hit(L"task.suspicious-command", commandRisk.level, commandRisk.reason);
                    if (commandRisk.level < RiskLevel::Medium && rules::IsCommandWrapperLaunch(command)) {
                        const bool disabled = record.enabledState == FieldState::Available && !record.enabled;
                        hit(L"task.command-wrapper", disabled ? RiskLevel::Low : RiskLevel::Medium, L"命令包装器启动");
                    }
                    if (rules::HasDoubleExtensionSpoof(action.execPath))
                        hit(L"task.double-extension", RiskLevel::Medium, L"双扩展名伪装");
                    script |= commandRisk.scriptExecution;
                } else {
                    unknown(L"task.suspicious-command");
                    unknown(L"task.command-wrapper");
                    unknown(L"task.double-extension");
                    unknown(L"task.script-persistence");
                }
            } else if (action.type != TASK_ACTION_COM_HANDLER)
                unknown(L"task.unsupported-action");
            if (action.associationState != FieldState::Available)
                unknown(L"task.action-target");
        }
        if (record.actionsState != FieldState::Available) {
            unknown(L"task.suspicious-command");
            unknown(L"task.command-wrapper");
            unknown(L"task.action-target");
        }
        const bool activeLogonBoot = record.enabledState == FieldState::Available && record.enabled &&
                                     (HasTrigger(record, L"logon", true) || HasTrigger(record, L"boot", true));
        bool triggerKnowledge = record.triggersState == FieldState::Available;
        for (const auto& trigger : record.triggers)
            triggerKnowledge &=
                trigger.typeState == FieldState::Available && trigger.enabledState == FieldState::Available;
        for (const auto& related : record.relatedFiles) {
            const auto& file = related.file;
            const auto& evidence = file.evidence;
            const auto& id = evidence.evidenceId;
            const bool existenceKnown = related.target.path.stable && evidence.existence == FieldState::Available;
            const bool exists = existenceKnown && evidence.exists && !file.directory;
            const bool signatureKnown =
                evidence.signatureState == FieldState::Available && evidence.signature != SignatureState::Unknown;
            if (related.target.path.stable) {
                if (rules::HasDoubleExtensionSpoof(related.target.path.value))
                    hit(L"task.double-extension", RiskLevel::Medium, L"双扩展名伪装", id);
                if (rules::IsSystemNameSpoof(record.name, related.target.path.value))
                    hit(L"task.name-spoof", RiskLevel::Medium, L"名称伪装", id);
                script |= rules::IsScriptFilePath(related.target.path.value);
            } else {
                unknown(L"task.name-spoof");
                unknown(L"task.script-persistence");
            }
            if (exists && file.attributesState == FieldState::Available && (file.attributes & FILE_ATTRIBUTE_HIDDEN))
                hit(L"task.hidden-file", RiskLevel::Medium, L"隐藏文件", id);
            else if (!existenceKnown || (exists && file.attributesState != FieldState::Available))
                unknown(L"task.hidden-file");
            if (exists && signatureKnown && evidence.signature == SignatureState::Mismatch)
                hit(L"task.signature-mismatch", rules::SignatureRiskLevel(evidence),
                    rules::SignatureRiskReason(evidence), id);
            if (exists && signatureKnown && evidence.signature == SignatureState::Unsigned && !microsoft &&
                !rules::IsLikelyMicrosoftCompany(evidence.company)) {
                if (!groupKnown)
                    unknown(L"task.third-party-unsigned");
                else if (activeLogonBoot)
                    hit(L"task.logon-startup-third-party-unsigned", RiskLevel::Medium, L"登录/启动第三方未签名", id);
                else {
                    hit(L"task.third-party-unsigned", RiskLevel::Low, L"第三方程序未签名", id);
                    if (record.enabledState != FieldState::Available || (record.enabled && !triggerKnowledge))
                        unknown(L"task.logon-startup-third-party-unsigned");
                }
            }
            if (exists && evidence.signature == SignatureState::Signed && signatureKnown &&
                related.sideLoadingState == FieldState::Available &&
                related.sideLoadingRisk != rules::DllSideLoadingRisk::None) {
                const auto level =
                    related.sideLoadingRisk == rules::DllSideLoadingRisk::High
                        ? RiskLevel::High
                        : (related.sideLoadingRisk == rules::DllSideLoadingRisk::Medium ? RiskLevel::Medium
                                                                                        : RiskLevel::Low);
                hit(L"task.dll-side-loading", level, L"疑似白加黑利用", id);
            }
            if (existenceKnown && !evidence.exists)
                hit(L"task.file-missing", RiskLevel::Low, L"文件不存在", id);
            else if (!existenceKnown || file.directory)
                unknown(L"task.file-missing");
            if (!existenceKnown || (exists && !signatureKnown)) {
                unknown(L"task.signature-mismatch");
                unknown(L"task.third-party-unsigned");
                unknown(L"task.logon-startup-third-party-unsigned");
                unknown(L"task.dll-side-loading");
            } else if (exists && evidence.signature == SignatureState::Signed &&
                       related.sideLoadingState != FieldState::Available)
                unknown(L"task.dll-side-loading");
        }
        const bool persistent =
            HasTrigger(record, L"logon") || HasTrigger(record, L"boot") || HasTrigger(record, L"scheduled");
        if (!microsoft && groupKnown && persistent && script) {
            const bool activeTrigger = HasTrigger(record, L"logon", true) || HasTrigger(record, L"boot", true) ||
                                       HasTrigger(record, L"scheduled", true);
            const bool active = record.enabledState == FieldState::Available && record.enabled && activeTrigger;
            const bool disabled = record.enabledState == FieldState::Available && !record.enabled;
            const wchar_t* reason =
                active
                    ? L"脚本型持久化"
                    : (disabled ? L"脚本任务（已禁用）"
                                : (triggerKnowledge && !activeTrigger ? L"脚本任务（触发器已禁用）" : L"脚本任务配置"));
            hit(L"task.script-persistence", active ? RiskLevel::Medium : RiskLevel::Low, reason);
        }
        if (record.triggersState != FieldState::Available || (!microsoft && !groupKnown))
            unknown(L"task.script-persistence");
        if (record.definitionState != FieldState::Available)
            unknown(L"task.definition");
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
