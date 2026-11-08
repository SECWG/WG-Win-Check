#pragma once

#include "../../common/RiskOverviewItem.h"
#include "../../common/IInvestigator.h"
#include "../../../core/modules/process/ProcessModule.h"
#include "../../common/CommonUtils.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <map>
#include <set>
#include <unordered_map>

#pragma comment(lib, "psapi.lib")

using RiskLevel = wgwc::core::RiskLevel;

struct ProcessInfo {
    DWORD pid = 0;
    DWORD ppid = 0;
    ULONGLONG createdAt = 0;
    std::wstring name;
    std::wstring path;
    std::wstring commandLine; // 命令行
    std::wstring user;
    std::wstring description; // 文件描述
    std::wstring companyName; // 公司名
    CommonUtils::SignatureState signatureState = CommonUtils::SignatureState::Unknown;
    std::wstring signatureInfo; // 签名信息
    std::wstring startTime;
    std::wstring fileModifyTime; // 文件修改时间
    std::wstring parentName;     // 父进程名（内部使用，用于风险检测）
    RiskLevel risk = RiskLevel::None;
    std::wstring riskReason;
    DWORD threadCount = 0;
};

struct SystemProcessDef {
    const wchar_t* name;
    const wchar_t* expectedPath;   // 期望路径（相对于System32）
    const wchar_t* expectedParent; // 期望父进程名
};

// 工具栏控件ID
#define IDC_PROC_EDIT_FILTER 5001
#define IDC_PROC_BTN_FILTER 5002
#define IDC_PROC_BTN_REFRESH 5004
#define IDC_PROC_STATIC_FILTER 5007
#define IDC_PROC_COMBO_TYPE 5009
#define IDC_PROC_COMBO_SIGN 5010

// 右键菜单ID
#define IDM_PROC_KILL 5101
#define IDM_PROC_KILL_TREE 5102
#define IDM_PROC_SUSPEND 5103
#define IDM_PROC_RESUME 5104
#define IDM_PROC_CALC_HASH 5111
#define IDM_PROC_VIRUSTOTAL 5112
#define IDM_PROC_THREATBOOK 5117
#define IDM_PROC_VIEW_MODULES 5113
#define IDM_PROC_VIEW_NETWORK 5114
#define IDM_PROC_VIEW_SERVICES 5115
#define IDM_PROC_DUMP_MEMORY 5116

class ProcessInvestigator : public IInvestigator {
public:
    ProcessInvestigator();
    ~ProcessInvestigator() override;

    InvestigationResult Investigate(bool resetFilter = true) override;
    // 仅在主线程应用已经采集的快照，工作线程不访问界面控件。
    InvestigationResult
    ApplyCollection(const wgwc::core::CollectionResult<wgwc::core::process::ProcessRecord>& collection,
                    bool resetFilter = false, const std::wstring& collectedAt = L"");

    std::wstring GetModuleName() const override {
        return L"ProcessInvestigator";
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
        m_allProcesses.clear();
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

    std::vector<ContextMenuItem> GetContextMenuItems(int row) const override;
    bool HandleContextMenu(UINT menuId, int row) override;
    std::wstring GetContextFilePath(int row) const override;

    std::vector<RiskOverviewItem> GetRiskFindings() const override;

    bool HasRowIcons() const override {
        return true;
    }

    std::wstring GetRowIconPath(int row, const InvestigationItem& item) const override;

private:
    // 右键菜单操作
    bool KillProcess(const ProcessInfo& proc);
    bool KillProcessTree(const ProcessInfo& proc);
    bool TerminateSelectedProcess(const ProcessInfo& proc, bool tree);
    bool SuspendProcess(DWORD pid);
    bool ResumeProcess(DWORD pid);
    void ShowFileHashes(const std::wstring& path);
    void ShowSvchostServices(DWORD pid);
    void ShowProcessModules(DWORD pid, const std::wstring& processName);
    void DumpProcessMemory(DWORD pid, const std::wstring& processName);
    bool CanOperateProcess(DWORD pid, const std::wstring& name) const;

    // 进程树
    void ShowProcessTree(DWORD pid);
    std::wstring BuildProcessTreeText(DWORD targetPid);
    void AppendChildren(std::wstring& result, DWORD parentPid,
                        const std::unordered_map<DWORD, const ProcessInfo*>& pidMap, int indent);

    static bool IsProtectedProcess(DWORD pid, const std::wstring& name);
    std::vector<ProcessInfo>
    ConvertProcesses(const wgwc::core::CollectionResult<wgwc::core::process::ProcessRecord>& collected);

    void AnalyzeRisk(ProcessInfo& proc);
    bool IsSystemProcess(const std::wstring& name);
    bool IsMicrosoftProcess(const std::wstring& companyName);
    bool IsValidSystemProcessPath(const std::wstring& name, const std::wstring& path);
    bool IsSuspiciousPath(const std::wstring& path);

    void ApplyFilter();
    bool MatchFilter(const ProcessInfo& proc, const std::wstring& filter);
    void UpdateListView();

    std::wstring GetSystem32Path();
    std::wstring GetWindowsPath();

    static const ColumnDef s_Columns[];
    static const int s_ColumnCount;

    // 列索引
    static const int COL_NAME = 0;
    static const int COL_PID = 1;
    static const int COL_PPID = 2;
    static const int COL_PATH = 3;
    static const int COL_CMDLINE = 4;
    static const int COL_USER = 5;
    static const int COL_DESC = 6;
    static const int COL_COMPANY = 7;
    static const int COL_SIGNATURE = 8;
    static const int COL_START_TIME = 9;
    static const int COL_FILE_MODIFY_TIME = 10;
    static const int COL_RISK = 11;

    // 系统进程定义表
    static const SystemProcessDef s_SystemProcesses[];

    // 缓存
    std::wstring m_system32Path;
    std::wstring m_sysWow64Path; // SysWOW64路径（64位系统上的32位程序目录）
    std::wstring m_windowsPath;
    bool m_processCollectionSucceeded = false;
    bool m_processCollectionPartial = false;
    DWORD m_processCollectionError = 0;
    std::wstring m_processCollectionMessage;

    // 数据存储
    std::vector<ProcessInfo> m_allProcesses;      // 所有进程（原始数据）
    std::vector<ProcessInfo> m_filteredProcesses; // 过滤后的进程

    // 风险进程索引（用于高亮）
    mutable std::map<int, RiskLevel> m_riskMap;

    // 工具栏控件
    HWND m_hToolbarPanel;
    HWND m_hComboType;
    HWND m_hComboSign;
    HWND m_hStaticFilter;
    HWND m_hEditFilter;
    HWND m_hBtnFilter;
    HWND m_hBtnRefresh;
    HWND m_hMainWnd;
    HWND m_hListView;
    HINSTANCE m_hInst;

    // 当前过滤条件
    std::wstring m_filterKeyword;
    int m_filterType; // 0=全部, 1=系统进程, 2=非系统进程, 3=微软进程, 4=非微软进程
    int m_filterSign; // 0=全部, 1=已签名, 2=未匹配, 3=未签名, 4=其他

    // 结果缓存
    bool m_hasCache = false;
    InvestigationResult m_cachedResult;
    std::wstring m_collectedAt;
};
