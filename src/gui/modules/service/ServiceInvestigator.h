#pragma once

#include "../../common/RiskOverviewItem.h"
#include "../../common/IInvestigator.h"
#include "../../../core/modules/service/ServiceModule.h"
#include "../../common/CommonUtils.h"
#include <windows.h>
#include <commctrl.h>

using ServiceRiskLevel = wgwc::core::RiskLevel;

struct ServiceInfo {
    std::wstring serviceName;            // 服务名
    std::wstring displayName;            // 显示名
    DWORD currentState = 0;              // 当前状态
    DWORD startType = SERVICE_NO_CHANGE; // 启动类型
    std::wstring binaryPath;             // 原始路径（含参数）
    std::wstring filePath;               // 解析后的文件路径
    std::wstring serviceDll;             // svchost 服务的 DLL 路径
    std::wstring associatedFile;         // 关联文件（优先 ServiceDll，否则服务 EXE）
    std::wstring description;            // 描述
    std::wstring companyName;            // 公司名
    std::wstring fileModifyTime;         // 文件修改时间
    CommonUtils::SignatureState signatureState = CommonUtils::SignatureState::Unknown;
    std::wstring signatureInfo; // 签名信息
    DWORD processId = 0;        // 进程ID
    DWORD controlsAccepted = 0;
    ServiceRiskLevel risk;   // 风险等级
    std::wstring riskReason; // 风险原因
    bool configKnown = false;
    bool statusKnown = false;
};

// 工具栏控件ID
#define IDC_SVC_COMBO_TYPE 6001
#define IDC_SVC_COMBO_SIGNATURE 6002
#define IDC_SVC_COMBO_START_TYPE 6003
#define IDC_SVC_COMBO_STATE 6004
#define IDC_SVC_EDIT_FILTER 6005
#define IDC_SVC_BTN_FILTER 6006
#define IDC_SVC_BTN_REFRESH 6007
#define IDC_SVC_BTN_MANAGER 6008
#define IDC_SVC_STATIC_KEYWORD 6009

// 右键菜单ID
#define IDM_SVC_OPEN_REG_LOC 7007
#define IDM_SVC_START 7008
#define IDM_SVC_STOP 7009
#define IDM_SVC_SET_AUTO 7010
#define IDM_SVC_SET_MANUAL 7011
#define IDM_SVC_DISABLE 7012
#define IDM_SVC_DELETE 7013

class ServiceInvestigator : public IInvestigator {
public:
    ServiceInvestigator();
    ~ServiceInvestigator() override;

    InvestigationResult Investigate(bool resetFilter = true) override;
    // 仅在主线程应用已经采集的快照，工作线程不访问界面控件。
    InvestigationResult ApplyCollection(const wgwc::core::CollectionResult<wgwc::core::services::Record>& collection,
                                        bool resetFilter = false, const std::wstring& collectedAt = L"");

    std::wstring GetModuleName() const override {
        return L"ServiceInvestigator";
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
        m_allServices.clear();
        m_filteredServices.clear();
        m_collectedAt.clear();
        m_collectionMessage.clear();
        m_collectionError = 0;
        m_collectionStale = false;
    }

    InvestigationResult RefreshFromCache() override;

    const ColumnDef* GetColumns() const override {
        return s_Columns;
    }

    int GetColumnCount() const override {
        return s_ColumnCount;
    }

    bool GetCellHighlight(int row, int col, const InvestigationResult& result, COLORREF& outColor) const override;

    bool HasToolbar() const override {
        return true;
    }

    int GetToolbarHeight() const override {
        return 38;
    }

    void CreateToolbar(HWND hParent, HINSTANCE hInst) override;
    void DestroyToolbar() override;
    void ShowToolbar(bool show) override;
    void ResizeToolbar(int x, int y, int width) override;
    bool HandleToolbarCommand(WORD id, WORD code) override;

    std::vector<ContextMenuItem> GetContextMenuItems(int row) const override;
    bool HandleContextMenu(UINT menuId, int row) override;
    std::wstring GetContextFilePath(int row) const override;

    void SetMainWindow(HWND hWnd) {
        m_hMainWnd = hWnd;
    }

    void SetListView(HWND hListView) {
        m_hListView = hListView;
    }

    std::vector<RiskOverviewItem> GetRiskFindings() const override;

    bool HasRowIcons() const override {
        return true;
    }

    std::wstring GetRowIconPath(int row, const InvestigationItem& item) const override;

private:
    bool IsMicrosoftService(const std::wstring& companyName);
    std::wstring StateToString(DWORD state);
    std::wstring StartTypeToString(DWORD startType);

    void ApplyFilter(bool updateUi = true);
    void UpdateListView();

    void OpenRegistryLocation(const std::wstring& serviceName);
    bool ExecuteServiceAction(UINT menuId, const ServiceInfo& info);
    void OpenServicesManager();

    static const ColumnDef s_Columns[];
    static const int s_ColumnCount;

    // 列索引
    static const int COL_NAME = 0;
    static const int COL_DISPLAY = 1;
    static const int COL_PID = 2;
    static const int COL_STATE = 3;
    static const int COL_START_TYPE = 4;
    static const int COL_PATH = 5;
    static const int COL_RELATED_FILE = 6;
    static const int COL_COMPANY = 7;
    static const int COL_DESC = 8;
    static const int COL_MODIFY_TIME = 9;
    static const int COL_SIGNATURE = 10;
    static const int COL_RISK = 11;

    // 数据存储
    std::vector<ServiceInfo> m_allServices;      // 所有服务
    std::vector<ServiceInfo> m_filteredServices; // 过滤后的服务

    // 工具栏控件
    HWND m_hComboType;
    HWND m_hComboSignature;
    HWND m_hComboStartType;
    HWND m_hComboState;
    HWND m_hStaticKeyword;
    HWND m_hEditFilter;
    HWND m_hBtnFilter;
    HWND m_hBtnRefresh;
    HWND m_hBtnManager = NULL;
    HWND m_hMainWnd;
    HWND m_hListView;
    HINSTANCE m_hInst;

    // 结果缓存
    bool m_hasCache = false;
    InvestigationResult m_cachedResult;
    std::wstring m_collectedAt, m_collectionMessage;
    DWORD m_collectionError = 0;
    bool m_collectionStale = false;
};
