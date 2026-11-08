#pragma once

#include "../../common/IInvestigator.h"
#include "../../common/RiskRepository.h"
#include <windows.h>
#include <vector>

class RiskOverviewInvestigator : public IInvestigator {
public:
    explicit RiskOverviewInvestigator(RiskRepository* repository);
    ~RiskOverviewInvestigator() override;

    InvestigationResult Investigate(bool resetFilter = true) override;
    InvestigationResult RefreshFromCache() override;

    bool HasCache() const override {
        return true;
    }

    InvestigationResult GetCachedResult() const override {
        return m_cachedResult;
    }

    std::wstring GetModuleName() const override {
        return L"RiskOverviewInvestigator";
    }

    const ColumnDef* GetColumns() const override {
        return s_Columns;
    }

    int GetColumnCount() const override {
        return s_ColumnCount;
    }

    bool GetCellHighlight(int row, int col, const InvestigationResult& result, COLORREF& outColor) const override;

    bool HasToolbar() const override {
        return false;
    }

    std::vector<RiskOverviewItem> GetRiskFindings() const override {
        return m_findings;
    }

private:
    void CollectFindings();
    InvestigationResult BuildResult();

    static const ColumnDef s_Columns[];
    static const int s_ColumnCount;

    static const int COL_MODULE = 0;
    static const int COL_LEVEL = 1;
    static const int COL_OBJECT = 2;
    static const int COL_INFO = 3;
    static const int COL_INFO2 = 4;
    static const int COL_REASON = 5;
    static const int COL_UPDATED_AT = 6;

    RiskRepository* m_repository;

    std::vector<RiskOverviewItem> m_findings;
    InvestigationResult m_cachedResult;
};
