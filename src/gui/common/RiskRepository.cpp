// RiskRepository.cpp - 内存风险结果存储实现。

#include "RiskRepository.h"

#include <algorithm>

void RiskRepository::ReplaceModuleFindings(const std::wstring& moduleId,
                                           const std::vector<RiskOverviewItem>& findings) {
    std::vector<RiskOverviewItem> filtered;
    for (const auto& finding : findings) {
        if (finding.level == SuspicionLevel::None) {
            continue;
        }
        filtered.push_back(finding);
    }

    if (filtered.empty()) {
        m_findingsByModule.erase(moduleId);
        return;
    }

    m_findingsByModule[moduleId] = filtered;
}

std::vector<RiskOverviewItem> RiskRepository::GetAllFindings() const {
    std::vector<RiskOverviewItem> allFindings;

    for (const auto& entry : m_findingsByModule) {
        allFindings.insert(allFindings.end(), entry.second.begin(), entry.second.end());
    }

    std::sort(allFindings.begin(), allFindings.end(), [](const RiskOverviewItem& a, const RiskOverviewItem& b) {
        int rankA = RiskOverviewSeverityRank(a.level);
        int rankB = RiskOverviewSeverityRank(b.level);
        if (rankA != rankB) {
            return rankA > rankB;
        }
        if (a.moduleName != b.moduleName) {
            return a.moduleName < b.moduleName;
        }
        if (a.objectName != b.objectName) {
            return a.objectName < b.objectName;
        }
        return a.sourceKey < b.sourceKey;
    });

    return allFindings;
}

void RiskRepository::Clear() {
    m_findingsByModule.clear();
}
