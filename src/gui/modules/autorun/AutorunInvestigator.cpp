#include "../../presentation/GuiColumns.h"
// AutorunInvestigator.cpp - 启动项排查模块实现

#include "../../../core/system/Win32.h"
#include "AutorunInvestigator.h"
#include "../../resources/resource.h"
#include "../../../core/modules/autorun/AutorunModule.h"
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

// 静态列定义
const ColumnDef AutorunInvestigator::s_Columns[] = { WG_COLUMNS_AUTORUN };
const int AutorunInvestigator::s_ColumnCount = sizeof(s_Columns) / sizeof(s_Columns[0]);

AutorunInvestigator::AutorunInvestigator() = default;
AutorunInvestigator::~AutorunInvestigator() = default;

namespace {
    AutorunType GuiAutorunType(wgwc::core::autorun::Type type) {
        using Type = wgwc::core::autorun::Type;
        switch (type) {
        case Type::StartupFolder:
            return AutorunType::StartupFolder;
        case Type::Winlogon:
            return AutorunType::Winlogon;
        case Type::IFEO:
            return AutorunType::IFEO;
        case Type::AppInit:
            return AutorunType::AppInit;
        case Type::WindowsLoad:
            return AutorunType::WindowsLoad;
        case Type::SafeBoot:
            return AutorunType::SafeBoot;
        case Type::WmiSubscription:
            return AutorunType::WmiSubscription;
        default:
            return AutorunType::Registry;
        }
    }

}

InvestigationResult AutorunInvestigator::Investigate(bool resetFilter) {
    auto context = MakeCollectionContext();
    const auto collectedAt = RiskOverviewNowString();
    return ApplyCollection(wgwc::core::autorun::CollectAutoruns({}, context), resetFilter, collectedAt);
}

InvestigationResult
AutorunInvestigator::ApplyCollection(const wgwc::core::CollectionResult<wgwc::core::autorun::Record>& collection,
                                     bool resetFilter, const std::wstring& collectedAt) {
    (void)resetFilter;
    wgwc::gui::ApplyCollectionOutcome(m_cachedResult, collection, m_hasCache, L"自启动项采集失败",
                                      L"部分来源或文件信息不可读取");
    m_cachedResult.moduleName = GetModuleName();
    if (!m_cachedResult.success)
        return m_cachedResult;
    InvestigationResult result;
    result.moduleName = GetModuleName();
    wgwc::gui::ApplyCollectionOutcome(result, collection, m_hasCache, L"自启动项采集失败",
                                      L"部分来源或文件信息不可读取");
    m_items.clear();
    m_riskMap.clear();
    m_collectedAt = collectedAt.empty() ? RiskOverviewNowString() : collectedAt;
    for (const auto& record : collection.records) {
        AutorunItem item{};
        item.name = record.name;
        item.type = GuiAutorunType(record.type);
        item.typeDisplay = wgwc::core::autorun::TypeDisplay(record.type);
        item.location = record.location;
        item.command = record.command;
        item.filePath = record.filePath;
        item.associatedFile = record.associatedFile;
        item.specialConfig = record.specialConfig;
        item.companyName = record.file.evidence.company;
        item.signatureState = record.file.evidence.signature;
        if (record.file.evidence.signatureState == wgwc::core::FieldState::Available)
            item.signatureInfo = CommonUtils::FormatSignatureText(item.signatureState, record.file.evidence.publisher);
        item.risk = ToModuleRiskLevel(record.assessment.level);
        item.riskReason = wgwc::core::autorun::RiskReasons(record.assessment);
        item.sourceKey = record.sourceKey;
        item.registryPath = record.registryPath;
        m_items.push_back(std::move(item));
    }

    for (size_t i = 0; i < m_items.size(); i++) {
        const AutorunItem& item = m_items[i];

        InvestigationItem resultItem;
        resultItem.name = item.name;
        resultItem.description = item.command;

        // 填充各列数据
        resultItem.details.push_back(item.name);
        resultItem.details.push_back(item.typeDisplay);
        resultItem.details.push_back(item.location);
        resultItem.details.push_back(item.command);
        resultItem.details.push_back(item.associatedFile);
        resultItem.details.push_back(item.companyName);
        resultItem.details.push_back(item.signatureInfo);

        // 风险描述：正常显示为空，有风险显示拼接的原因
        std::wstring riskText;
        if (item.risk != AutorunRiskLevel::None && !item.riskReason.empty()) {
            riskText = item.riskReason;
        }
        resultItem.details.push_back(riskText);

        switch (item.risk) {
        case AutorunRiskLevel::None:
            resultItem.suspicion = SuspicionLevel::None;
            break;
        case AutorunRiskLevel::Low:
            resultItem.suspicion = SuspicionLevel::Low;
            break;
        case AutorunRiskLevel::Medium:
            resultItem.suspicion = SuspicionLevel::Medium;
            break;
        case AutorunRiskLevel::High:
            resultItem.suspicion = SuspicionLevel::High;
            break;
        }
        resultItem.suspicionReason = item.riskReason;

        // 记录风险映射
        m_riskMap[(int)i] = item.risk;

        result.items.push_back(resultItem);
        result.totalCount++;

        if (item.risk != AutorunRiskLevel::None) {
            result.suspiciousCount++;
        }
    }

    // 缓存结果
    m_cachedResult = result;
    m_hasCache = true;

    return result;
}

std::vector<RiskOverviewItem> AutorunInvestigator::GetRiskFindings() const {
    std::vector<RiskOverviewItem> findings;
    if (!m_hasCache) {
        return findings;
    }

    const std::wstring& updatedAt = m_collectedAt;

    for (size_t i = 0; i < m_items.size(); i++) {
        const AutorunItem& item = m_items[i];
        SuspicionLevel level = ToModuleRiskLevel(item.risk);
        if (level == SuspicionLevel::None) {
            continue;
        }

        RiskOverviewItem finding;
        finding.moduleId = L"autorun";
        finding.moduleName = L"自启动排查";
        finding.tabIndex = TAB_AUTORUNS;
        finding.level = level;
        finding.objectName = item.name;
        finding.info = item.typeDisplay + L" / " + item.location;
        finding.info2 = item.associatedFile.empty() ? item.filePath : item.associatedFile;
        if (!item.command.empty()) {
            if (!finding.info2.empty()) {
                finding.info2 += L" | ";
            }
            finding.info2 += item.command;
        }
        finding.reason = item.riskReason;
        finding.updatedAt = updatedAt;
        finding.sourceKey = item.sourceKey;
        finding.sourceRow = (int)i;

        findings.push_back(finding);
    }

    return findings;
}

std::wstring AutorunInvestigator::GetRowIconPath(int row, const InvestigationItem& item) const {
    if (row >= 0 && row < (int)m_items.size()) {
        return m_items[row].associatedFile.empty() ? m_items[row].filePath : m_items[row].associatedFile;
    }
    if (item.details.size() > COL_ASSOCIATED_FILE && !item.details[COL_ASSOCIATED_FILE].empty()) {
        return item.details[COL_ASSOCIATED_FILE];
    }
    return L"";
}

std::wstring AutorunInvestigator::GetContextFilePath(int row) const {
    if (row < 0 || row >= (int)m_items.size())
        return L"";
    const AutorunItem& item = m_items[row];
    return item.associatedFile.empty() ? item.filePath : item.associatedFile;
}

bool AutorunInvestigator::GetCellHighlight(int row, int col, const InvestigationResult& result,
                                           COLORREF& outColor) const {
    (void)col;
    (void)result;

    auto it = m_riskMap.find(row);
    if (it == m_riskMap.end()) {
        return false;
    }

    switch (it->second) {
    case AutorunRiskLevel::High:
        outColor = RGB(255, 0, 0); // 红色
        return true;
    case AutorunRiskLevel::Medium:
        outColor = RGB(255, 128, 0); // 橙色
        return true;
    case AutorunRiskLevel::Low:
        outColor = RGB(128, 128, 0); // 暗黄色
        return true;
    default:
        return false;
    }
}

// 右键菜单支持

// 右键菜单ID
enum AutorunContextMenuId {
    IDM_AUTORUN_OPEN_REGISTRY = 4006
};

std::vector<ContextMenuItem> AutorunInvestigator::GetContextMenuItems(int row) const {
    std::vector<ContextMenuItem> items;

    if (row < 0 || row >= (int)m_items.size()) {
        return items;
    }

    const AutorunItem& item = m_items[row];

    // 注册表类型才显示打开注册表
    if (item.type == AutorunType::Registry || item.type == AutorunType::Winlogon || item.type == AutorunType::IFEO ||
        item.type == AutorunType::AppInit || item.type == AutorunType::WindowsLoad ||
        item.type == AutorunType::SafeBoot) {
        items.push_back({ IDM_AUTORUN_OPEN_REGISTRY, L"注册表位置", false, L"" });
    }

    return items;
}

// 处理右键菜单命令
bool AutorunInvestigator::HandleContextMenu(UINT menuId, int row) {
    if (row < 0 || row >= (int)m_items.size()) {
        return false;
    }

    const AutorunItem& item = m_items[row];

    switch (menuId) {
    case IDM_AUTORUN_OPEN_REGISTRY: {
        const std::wstring& regPath = item.registryPath;
        if (regPath.empty())
            return false;

        // 写入注册表让 regedit 打开到指定位置
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit", 0,
                            NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"LastKey", 0, REG_SZ, (LPBYTE)regPath.c_str(),
                           (DWORD)((regPath.length() + 1) * sizeof(wchar_t)));
            RegCloseKey(hKey);
        }

        // 启动 regedit
        ShellExecuteW(NULL, L"open", L"regedit.exe", NULL, NULL, SW_SHOWNORMAL);
    }
        return false; // 不需要刷新
    }

    return false;
}
