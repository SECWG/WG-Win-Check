#pragma once

#include "../../common/RiskOverviewItem.h"
#include "../../common/IInvestigator.h"
#include "../../../core/modules/task/TaskModule.h"
#include "../../common/CommonUtils.h"
#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <vector>
#include <string>

using TaskRiskLevel = wgwc::core::RiskLevel;

struct TaskInfo {
    std::wstring name;                      // 任务名
    std::wstring path;                      // 任务路径
    TASK_STATE state = TASK_STATE_UNKNOWN;  // 状态
    std::wstring execPath;                  // 执行程序路径
    std::wstring arguments;                 // 参数
    std::wstring workingDirectory;          // 工作目录
    std::wstring relatedFile;               // 关联文件
    std::vector<std::wstring> relatedFiles; // 所有关联文件候选
    std::wstring actionSummary;             // 动作摘要
    std::wstring comClassId;                // COM 处理程序的类标识符（CLSID）。
    std::wstring triggerInfo;               // 触发器信息
    std::wstring nextRunTime;               // 下次运行时间
    std::wstring lastRunTime;               // 上次运行时间
    std::wstring author;                    // 作者
    std::wstring description;               // 描述
    bool identityKnown = false, stateKnown = false, definitionKnown = false, enabledKnown = false;
    bool enabled = false;
    std::vector<DWORD> triggerTypes;
    bool hidden = false;      // 是否隐藏
    std::wstring companyName; // 公司名
    CommonUtils::SignatureState signatureState = CommonUtils::SignatureState::Unknown;
    std::wstring signatureInfo;               // 签名信息
    TaskRiskLevel risk = TaskRiskLevel::None; // 风险等级
    std::wstring riskReason;                  // 风险原因
};

// 工具栏控件ID
#define IDC_TASK_COMBO_TYPE 8001
#define IDC_TASK_COMBO_STATE 8002
#define IDC_TASK_COMBO_TRIGGER 8003
#define IDC_TASK_STATIC_KEYWORD 8004
#define IDC_TASK_EDIT_FILTER 8005
#define IDC_TASK_BTN_FILTER 8006
#define IDC_TASK_BTN_REFRESH 8007
#define IDC_TASK_BTN_MANAGER 8008

// 右键菜单ID
#define IDM_TASK_RUN 8107
#define IDM_TASK_ENABLE 8108
#define IDM_TASK_DISABLE 8109
#define IDM_TASK_DELETE 8110

class TaskInvestigator : public IInvestigator {
public:
    TaskInvestigator();
    ~TaskInvestigator() override;

    InvestigationResult Investigate(bool resetFilter = true) override;
    // 仅在主线程应用已经采集的快照，工作线程不访问界面控件。
    InvestigationResult ApplyCollection(const wgwc::core::CollectionResult<wgwc::core::tasks::Record>& collection,
                                        bool resetFilter = false, const std::wstring& collectedAt = L"");

    std::wstring GetModuleName() const override {
        return L"TaskInvestigator";
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
        m_allTasks.clear();
        m_filteredTasks.clear();
        m_collectionStale = false;
        m_collectionError = 0;
        m_collectionMessage.clear();
        m_collectedAt.clear();
    }

    InvestigationResult RefreshFromCache() override;

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
    std::wstring StateToString(TASK_STATE state);
    bool IsMicrosoftTask(const TaskInfo& info);

    void ApplyFilter(bool updateView = true);
    void UpdateListView();

    bool ExecuteTaskAction(UINT menuId, const TaskInfo& info);

    static const ColumnDef s_Columns[];
    static const int s_ColumnCount;

    // 列索引
    static const int COL_NAME = 0;
    static const int COL_PATH = 1;
    static const int COL_STATE = 2;
    static const int COL_EXEC = 3;
    static const int COL_ARGS = 4;
    static const int COL_RELATED_FILE = 5;
    static const int COL_TRIGGER = 6;
    static const int COL_NEXT_RUN = 7;
    static const int COL_LAST_RUN = 8;
    static const int COL_AUTHOR = 9;
    static const int COL_SIGNATURE = 10;
    static const int COL_DESC = 11;

    // 数据存储
    std::vector<TaskInfo> m_allTasks;
    std::vector<TaskInfo> m_filteredTasks;

    // 工具栏控件
    HWND m_hComboType;
    HWND m_hComboState;
    HWND m_hComboTrigger;
    HWND m_hStaticKeyword;
    HWND m_hEditFilter;
    HWND m_hBtnFilter;
    HWND m_hBtnRefresh;
    HWND m_hBtnManager = NULL;
    HWND m_hMainWnd;
    HWND m_hListView;
    HINSTANCE m_hInst;

    // 结果缓存
    bool m_collectionStale = false;
    DWORD m_collectionError = 0;
    std::wstring m_collectionMessage, m_collectedAt;
    bool m_hasCache = false;
    InvestigationResult m_cachedResult;
};
