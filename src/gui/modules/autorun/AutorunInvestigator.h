#pragma once

#include "../../common/RiskOverviewItem.h"
#include "../../common/IInvestigator.h"
#include "../../../core/modules/autorun/AutorunModule.h"
#include "../../common/CommonUtils.h"
#include <windows.h>
#include <shlobj.h>
#include <map>

using AutorunRiskLevel = wgwc::core::RiskLevel;

enum class AutorunType {
    Registry,       // 注册表 Run 键
    StartupFolder,  // 启动文件夹
    Winlogon,       // Winlogon 外壳及用户初始化配置（Shell/Userinit）。
    IFEO,           // 映像文件执行选项（Image File Execution Options）。
    AppInit,        // 应用初始化 DLL 配置（AppInit_DLLs）。
    WindowsLoad,    // Windows 启动加载配置（Load）。
    SafeBoot,       // 安全模式备用外壳配置（SafeBoot AlternateShell）。
    WmiSubscription // WMI 永久事件订阅
};

struct AutorunItem {
    std::wstring name;           // 名称
    AutorunType type;            // 类型
    std::wstring typeDisplay;    // 类型显示文本
    std::wstring location;       // 位置（注册表路径或文件夹）
    std::wstring command;        // 命令/路径
    std::wstring filePath;       // 解析后的文件路径
    std::wstring associatedFile; // 关联文件（用于签名/风险判断）
    bool specialConfig = false;  // 配置型启动点，不套普通文件规则
    std::wstring companyName;    // 公司名
    CommonUtils::SignatureState signatureState = CommonUtils::SignatureState::Unknown;
    std::wstring signatureInfo; // 签名信息
    AutorunRiskLevel risk;      // 风险等级
    std::wstring riskReason;    // 风险原因
    std::wstring sourceKey;
    std::wstring registryPath;
};

class AutorunInvestigator : public IInvestigator {
public:
    AutorunInvestigator();
    ~AutorunInvestigator() override;

    InvestigationResult Investigate(bool resetFilter = true) override;
    // 仅在主线程应用已经采集的快照，工作线程不访问界面控件。
    InvestigationResult ApplyCollection(const wgwc::core::CollectionResult<wgwc::core::autorun::Record>& collection,
                                        bool resetFilter = false, const std::wstring& collectedAt = L"");

    std::wstring GetModuleName() const override {
        return L"AutorunInvestigator";
    }

    bool HasCache() const override {
        return m_hasCache;
    }

    InvestigationResult GetCachedResult() const override {
        return m_cachedResult;
    }

    void ClearCache() override {
        m_hasCache = false;
        m_cachedResult = InvestigationResult();
    }

    const ColumnDef* GetColumns() const override {
        return s_Columns;
    }

    int GetColumnCount() const override {
        return s_ColumnCount;
    }

    bool GetCellHighlight(int row, int col, const InvestigationResult& result, COLORREF& outColor) const override;

    std::vector<ContextMenuItem> GetContextMenuItems(int row) const override;
    bool HandleContextMenu(UINT menuId, int row) override;
    std::wstring GetContextFilePath(int row) const override;

    std::vector<RiskOverviewItem> GetRiskFindings() const override;

    bool HasRowIcons() const override {
        return true;
    }

    std::wstring GetRowIconPath(int row, const InvestigationItem& item) const override;

private:
    static const ColumnDef s_Columns[];
    static const int s_ColumnCount;

    // 列索引
    static const int COL_NAME = 0;
    static const int COL_TYPE = 1;
    static const int COL_LOCATION = 2;
    static const int COL_COMMAND = 3;
    static const int COL_ASSOCIATED_FILE = 4;
    static const int COL_COMPANY = 5;
    static const int COL_SIGNATURE = 6;
    static const int COL_RISK = 7;

    // 数据存储
    std::vector<AutorunItem> m_items;

    // 风险映射（用于高亮）
    mutable std::map<int, AutorunRiskLevel> m_riskMap;

    // 结果缓存
    bool m_hasCache = false;
    InvestigationResult m_cachedResult;
    std::wstring m_collectedAt;
};
