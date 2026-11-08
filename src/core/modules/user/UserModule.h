#pragma once
#include "../../runtime/CollectionContext.h"
#include <map>
#include <set>

namespace wgwc::core::users {
    struct UserRecord {
        std::wstring username, fullName, description, sid, observedAt, source;
        std::uint32_t flags = 0, rid = 0;
        bool isAdmin = false, isHidden = false, loginUiHidden = false, dollarHidden = false, samApiHidden = false;
        bool isDisabled = false, isLocked = false, passwordNeverExpires = false, passwordNotRequired = false;
        std::uint32_t lastLogon = 0, lastLogoff = 0, passwordAge = 0, accountExpires = 0;
        std::uint32_t numLogons = 0, badPasswordCount = 0;
        bool ridHijacked = false;
        std::uint32_t originalRid = 0, hijackedRid = 0, samRid = 0;
        FieldState metadataState = FieldState::Unknown, sidState = FieldState::Unknown,
                   adminState = FieldState::Unknown;
        FieldState loginUiHiddenState = FieldState::Unknown, dollarHiddenState = FieldState::Unknown;
        FieldState samApiHiddenState = FieldState::Unknown, hiddenState = FieldState::Unknown;
        FieldState ridState = FieldState::Unknown, ridHijackState = FieldState::Unknown;
        RiskAssessment assessment;
    };

    struct HiddenEvidence {
        std::set<std::wstring> loginUiHiddenNames, apiNames, samNames;
        bool loginUiComplete = false, apiComplete = false, samComplete = false;
    };

    std::wstring NormalizeName(const std::wstring& name);

    // 保留以 SID 为优先依据、规范化用户名为回退值的现有键规则。
    inline std::wstring SourceKey(const UserRecord& user) {
        return user.sid.empty() ? NormalizeName(user.username) : user.sid;
    }

    void ApplyHiddenEvidence(UserRecord& user, const HiddenEvidence& evidence);
    bool DecodeSamRid(const unsigned char* bytes, std::size_t length, std::uint32_t& rid);
    RiskAssessment AssessUser(const UserRecord& user);
    std::wstring HiddenTypeText(const UserRecord& user);
    std::wstring RiskReason(const UserRecord& user);
    CollectionResult<UserRecord> CollectUsers(const CollectionContext& context);
}
