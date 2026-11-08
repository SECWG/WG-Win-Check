#include "UserModule.h"
#include <algorithm>
#include <cstring>
#include <cwctype>

namespace wgwc::core::users {
    std::wstring NormalizeName(const std::wstring& name) {
        std::wstring value = name;
        for (auto& c : value)
            c = static_cast<wchar_t>(towlower(c));
        return value;
    }

    void ApplyHiddenEvidence(UserRecord& user, const HiddenEvidence& evidence) {
        const auto name = NormalizeName(user.username);
        user.loginUiHidden = evidence.loginUiHiddenNames.count(name) != 0;
        user.loginUiHiddenState =
            user.loginUiHidden || evidence.loginUiComplete ? FieldState::Available : FieldState::Unknown;
        user.dollarHidden = !name.empty() && name.back() == L'$';
        user.dollarHiddenState = name.empty() ? FieldState::Unknown : FieldState::Available;
        const bool inApi = evidence.apiNames.count(name) != 0, inSam = evidence.samNames.count(name) != 0;
        // API 枚举失败或未完成时，不能据此证明账户不存在。
        user.samApiHidden = inSam && evidence.apiComplete && !inApi;
        user.samApiHiddenState = user.samApiHidden || inApi || (evidence.samComplete && !inSam) ? FieldState::Available
                                                                                                : FieldState::Unknown;
        user.isHidden = user.loginUiHidden || user.dollarHidden || user.samApiHidden;
        user.hiddenState = user.isHidden || (user.loginUiHiddenState == FieldState::Available &&
                                             user.dollarHiddenState == FieldState::Available &&
                                             user.samApiHiddenState == FieldState::Available)
                               ? FieldState::Available
                               : FieldState::Unknown;
    }

    bool DecodeSamRid(const unsigned char* bytes, std::size_t length, std::uint32_t& rid) {
        rid = 0;
        if (!bytes || length < 0x34)
            return false;
        std::memcpy(&rid, bytes + 0x30, sizeof(rid));
        return rid != 0;
    }

    RiskAssessment AssessUser(const UserRecord& user) {
        RiskAssessment result;
        result.state = AssessmentState::Complete;
        auto hit = [&](const wchar_t* id, RiskLevel level, const wchar_t* reason) {
            result.hits.push_back({ id, level, reason, {} });
            result.level = (std::max)(result.level, level);
        };
        auto unknown = [&](const wchar_t* id) {
            result.state = AssessmentState::Incomplete;
            result.unevaluatedRules.push_back(id);
        };
        if (user.ridHijackState != FieldState::Available)
            unknown(L"user.rid_hijack");
        else if (user.ridHijacked)
            hit(L"user.rid_hijack", user.hijackedRid < 1000 ? RiskLevel::High : RiskLevel::Medium,
                user.hijackedRid == 500 ? L"RID劫持(管理员)" : L"RID劫持");
        if (user.loginUiHiddenState != FieldState::Available)
            unknown(L"user.login_ui_hidden");
        else if (user.loginUiHidden)
            hit(L"user.login_ui_hidden", RiskLevel::Medium, L"UserList 隐藏");
        if (user.dollarHiddenState != FieldState::Available)
            unknown(L"user.dollar_hidden");
        else if (user.dollarHidden)
            hit(L"user.dollar_hidden", RiskLevel::High, L"$隐藏用户");
        if (user.samApiHiddenState != FieldState::Available)
            unknown(L"user.sam_api_hidden");
        else if (user.samApiHidden)
            hit(L"user.sam_api_hidden", RiskLevel::High, L"隐藏用户(SAM/API不一致)");
        if (user.metadataState != FieldState::Available) {
            unknown(L"user.bad_password_count");
            unknown(L"user.password_not_required");
        } else {
            if (user.badPasswordCount > 20)
                hit(L"user.bad_password_count", RiskLevel::Medium, L"密码错误超过20次");
            if (user.passwordNotRequired && !user.isDisabled)
                hit(L"user.password_not_required", RiskLevel::Low, L"无需密码");
        }
        return result;
    }

    std::wstring HiddenTypeText(const UserRecord& user) {
        std::wstring value;
        auto append = [&](const wchar_t* text) {
            if (!value.empty())
                value += L"、";
            value += text;
        };
        if (user.loginUiHidden)
            append(L"UserList 隐藏");
        if (user.dollarHidden)
            append(L"$隐藏用户");
        if (user.samApiHidden)
            append(L"SAM/API不一致");
        return value;
    }

    std::wstring RiskReason(const UserRecord& user) {
        std::wstring value;
        for (const auto& hit : user.assessment.hits) {
            if (!value.empty())
                value += L"、";
            value += hit.reason;
        }
        return value;
    }
}
