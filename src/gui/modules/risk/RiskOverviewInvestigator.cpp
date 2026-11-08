#include "../../presentation/GuiColumns.h"
// RiskOverviewInvestigator.cpp - 风险概览展示模块。

#include "RiskOverviewInvestigator.h"

namespace {

    void ReplaceAll(std::wstring& text, const std::wstring& from, const std::wstring& to) {
        if (from.empty()) {
            return;
        }

        size_t pos = 0;
        while ((pos = text.find(from, pos)) != std::wstring::npos) {
            text.replace(pos, from.length(), to);
            pos += to.length();
        }
    }

    std::wstring NormalizeOverviewReason(std::wstring reason) {
        ReplaceAll(reason, L"命令行启动", L"命令包装器启动");
        ReplaceAll(reason, L"脚本文件", L"脚本持久化");
        ReplaceAll(reason, L"AppInit_DLLs 已启用", L"AppInit_DLLs 持久化");

        if (reason.find(L"IFEO Debugger 持久化") == std::wstring::npos) {
            ReplaceAll(reason, L"IFEO Debugger", L"IFEO Debugger 持久化");
        }

        if (reason.find(L"RunOnceEx 持久化") == std::wstring::npos) {
            ReplaceAll(reason, L"RunOnceEx", L"RunOnceEx 持久化");
        }

        return reason;
    }

    std::wstring CompactOverviewField(const std::wstring& value) {
        const size_t kMaxLength = 220;
        if (value.length() <= kMaxLength) {
            return value;
        }

        return value.substr(0, kMaxLength - 3) + L"...";
    }

}

const ColumnDef RiskOverviewInvestigator::s_Columns[] = { WG_COLUMNS_RISK };
const int RiskOverviewInvestigator::s_ColumnCount = sizeof(s_Columns) / sizeof(s_Columns[0]);

RiskOverviewInvestigator::RiskOverviewInvestigator(RiskRepository* repository) : m_repository(repository) {}

RiskOverviewInvestigator::~RiskOverviewInvestigator() {}

void RiskOverviewInvestigator::CollectFindings() {
    m_findings.clear();
    if (!m_repository) {
        return;
    }
    m_findings = m_repository->GetAllFindings();
}

InvestigationResult RiskOverviewInvestigator::BuildResult() {
    InvestigationResult result;
    result.moduleName = GetModuleName();
    result.success = true;
    result.errorCode = 0;
    result.totalCount = 0;
    result.suspiciousCount = 0;

    for (const auto& finding : m_findings) {
        const std::wstring reason = NormalizeOverviewReason(finding.reason);
        const std::wstring info2 = CompactOverviewField(finding.info2);

        InvestigationItem item;
        item.name = finding.objectName;
        item.description = reason;
        item.suspicion = finding.level;
        item.suspicionReason = reason;
        item.details.resize(s_ColumnCount);
        item.details[COL_MODULE] = finding.moduleName;
        item.details[COL_LEVEL] = SuspicionLevelToString(finding.level);
        item.details[COL_OBJECT] = finding.objectName;
        item.details[COL_INFO] = finding.info;
        item.details[COL_INFO2] = info2;
        item.details[COL_REASON] = reason;
        item.details[COL_UPDATED_AT] = finding.updatedAt;

        result.items.push_back(item);
        result.totalCount++;
        result.suspiciousCount++;
    }

    m_cachedResult = result;
    return result;
}

InvestigationResult RiskOverviewInvestigator::Investigate(bool resetFilter) {
    (void)resetFilter;
    CollectFindings();
    return BuildResult();
}

InvestigationResult RiskOverviewInvestigator::RefreshFromCache() {
    CollectFindings();
    return BuildResult();
}

bool RiskOverviewInvestigator::GetCellHighlight(int row, int col, const InvestigationResult& result,
                                                COLORREF& outColor) const {
    (void)col;

    if (row < 0 || row >= (int)result.items.size()) {
        return false;
    }

    switch (result.items[row].suspicion) {
    case SuspicionLevel::Critical:
    case SuspicionLevel::High:
        outColor = RGB(255, 0, 0);
        return true;
    case SuspicionLevel::Medium:
        outColor = RGB(255, 128, 0);
        return true;
    case SuspicionLevel::Low:
        outColor = RGB(128, 128, 0);
        return true;
    default:
        return false;
    }
}
