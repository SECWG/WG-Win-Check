#pragma once

#include "../../common/IInvestigator.h"
#include "../../common/CommonUtils.h"
#include <windows.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <vector>
#include <map>
#include <atomic>

struct ThreatSearchResult {
    DWORD pid;
    std::wstring processName;
    std::wstring processPath;
    std::wstring matchType;     // 文本编码：ASCII / UTF-8 / UTF-16LE / ANSI。
    std::wstring matchLocation; // 内存地址
    std::wstring context;       // 解码后的上下文
};

// 工具栏控件ID
#define IDC_THREAT_EDIT_IOC 9001
#define IDC_THREAT_BTN_SCAN 9002
#define IDC_THREAT_BTN_STOP 9003
#define IDC_THREAT_CHK_NONSYSTEM 9004
#define IDC_THREAT_CHK_FIRSTONLY 9005
#define IDC_THREAT_STATIC_IOC 9006
#define IDC_THREAT_STATIC_PID 9007
#define IDC_THREAT_EDIT_PID 9008
#define IDC_THREAT_EDIT_MEMLIMIT 9009

// 定时器ID
#define IDT_THREAT_PROGRESS 9201

class ThreatSearchInvestigator : public IInvestigator {
public:
    ThreatSearchInvestigator();
    ~ThreatSearchInvestigator() override;

    InvestigationResult Investigate(bool resetFilter = true) override;

    std::wstring GetModuleName() const override {
        return L"ThreatSearchInvestigator";
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

    UINT_PTR GetTimerId() const override {
        return IDT_THREAT_PROGRESS;
    }

    void OnTimer(UINT_PTR timerId) override;

    void SetMainWindow(HWND hWnd) {
        m_hMainWnd = hWnd;
    }

    void SetListView(HWND hListView) {
        m_hListView = hListView;
    }

    std::wstring GetStatusText() const;

    InvestigationResult GetCurrentResult() const;

    bool IsScanning() const {
        return m_scanning;
    }

    bool HasResults() const {
        return m_hasCache || m_scannedProcesses > 0;
    }

    std::wstring GetContextFilePath(int row) const override;

    bool HasRowIcons() const override {
        return true;
    }

    int GetRowIconColumn() const override {
        return COL_PROCESS;
    }

    std::wstring GetRowIconPath(int row, const InvestigationItem& item) const override;

private:
#ifdef WGWC_THREAT_TESTS
    friend struct ThreatGuiTestAccess;
#endif
    // 扫描控制：只有线程退出后，UI线程才能发布缓存或开始下一轮。
    void StartScan();
    void StopScan(bool waitForExit = false);
    void FinishScan(bool updateView = true);
    void SetScanControls(bool running);

    static DWORD WINAPI ScanThread(LPVOID lpParam);

    void DoMemoryScan();
    bool ScanProcessMemory(DWORD pid, const std::wstring& processName, const std::wstring& processPath);

    bool ShouldScanRegion(const MEMORY_BASIC_INFORMATION& mbi);

    struct ProcessEntry {
        DWORD pid;
        std::wstring name;
        std::wstring path;
    };

    std::vector<ProcessEntry> EnumerateProcesses();

    bool IsSystemProcess(const std::wstring& name, const std::wstring& path);

    void AddResult(const ThreatSearchResult& result);
    void UpdateListView();
    void UpdateProgress();

    std::wstring GetProcessPath(DWORD pid);
    std::wstring FormatAddress(ULONGLONG addr);

    static const ColumnDef s_Columns[];
    static const int s_ColumnCount;

    // 列索引
    static const int COL_PID = 0;
    static const int COL_PROCESS = 1;
    static const int COL_PATH = 2;
    static const int COL_MATCH_TYPE = 3;
    static const int COL_LOCATION = 4;
    static const int COL_CONTEXT = 5;

    // 工具栏控件（直接创建在主窗口上）
    HWND m_hStaticIOC;
    HWND m_hEditIOC;
    HWND m_hStaticPID;
    HWND m_hEditPID;
    HWND m_hBtnScan;
    HWND m_hBtnStop;
    HWND m_hChkNonSystem;   // 仅非系统进程
    HWND m_hChkFirstOnly;   // 仅首次匹配
    HWND m_hStaticMemLimit; // 内存限制标签
    HWND m_hEditMemLimit;   // 内存限制输入框
    HWND m_hMainWnd;
    HWND m_hListView;
    HINSTANCE m_hInst;

    // 扫描状态
    std::atomic<bool> m_scanning;
    std::atomic<int> m_scannedProcesses;
    std::atomic<int> m_totalProcesses;
    std::atomic<int> m_matchCount;
    HANDLE m_hScanThread;
    std::atomic_bool m_cancelRequested{ false };
    std::atomic<int> m_readProcesses{ 0 };
    std::atomic<int> m_failedProcesses{ 0 };
    std::atomic<int> m_partialProcesses{ 0 };
    std::atomic<DWORD> m_scanError{ ERROR_SUCCESS };
    bool m_stoppedByUser = false;
    bool m_toolbarVisible = false;

    // 本轮参数在线程启动前固定，工作线程不读取工具栏。
    std::wstring m_iocString;
    bool m_scanNonSystemOnly; // 仅扫描非系统进程
    bool m_firstMatchOnly;    // 仅首次匹配（每个进程只记录一个结果）
    DWORD m_targetPid;        // 指定扫描的PID，0表示扫描所有
    SIZE_T m_maxRegionSize;   // 最大内存区域扫描大小

    std::vector<ThreatSearchResult> m_results;
    CRITICAL_SECTION m_csResults;

    // 系统路径

    std::wstring m_windowsPath;

    // 自身进程ID (排除扫描)
    DWORD m_selfPid;

    // 扫描统计
    std::atomic<ULONGLONG> m_totalBytesScanned;
    std::atomic<int> m_regionsScanned;

    // 结果缓存
    bool m_hasCache = false;
    InvestigationResult m_cachedResult;
};
