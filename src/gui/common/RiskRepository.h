#pragma once

#include "RiskOverviewItem.h"

#include <map>
#include <string>
#include <vector>

class RiskRepository {
public:
    void ReplaceModuleFindings(const std::wstring& moduleId, const std::vector<RiskOverviewItem>& findings);
    std::vector<RiskOverviewItem> GetAllFindings() const;
    void Clear();

private:
    std::map<std::wstring, std::vector<RiskOverviewItem>> m_findingsByModule;
};
