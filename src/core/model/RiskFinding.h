#pragma once
#include <string>
#include <vector>

namespace wgwc::core {
    enum class RiskLevel {
        None,
        Low,
        Medium,
        High,
        Critical
    };
    enum class AssessmentState {
        NotRequested,
        NotApplicable,
        Complete,
        Incomplete
    };

    struct RiskHit {
        std::wstring ruleId;
        RiskLevel level = RiskLevel::None;
        std::wstring reason;
        std::vector<std::wstring> evidenceIds;
    };

    struct RiskAssessment {
        AssessmentState state = AssessmentState::NotRequested;
        RiskLevel level = RiskLevel::None;
        std::vector<RiskHit> hits;
        std::vector<std::wstring> unevaluatedRules;
    };

    struct RiskFinding {
        std::wstring moduleId;
        std::wstring sourceKey;
        std::wstring objectName;
        std::wstring updatedAt;
        RiskAssessment assessment;
    };
}
