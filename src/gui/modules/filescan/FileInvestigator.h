#pragma once

#include "../../common/IInvestigator.h"
#include "../../common/CommonUtils.h"
#include "../../../core/modules/filescan/FileScanModule.h"
#include <windows.h>
#include <vector>
#include <string>
#include <set>
#include <queue>
#include <mutex>
#include <atomic>

using FileInfo = wgwc::core::filescan::Record;

// 扫描配置（不持久化，每次启动恢复默认）
using ScanConfig = wgwc::core::filescan::ScanConfig;

// 工具栏控件ID
#define IDC_FILE_BTN_SCAN 7001
#define IDC_FILE_BTN_STOP 7002
#define IDC_FILE_BTN_LOAD 7003
#define IDC_FILE_BTN_SCAN_CONFIG 7012 // 扫描配置按钮
#define IDC_FILE_COMBO_LIMIT 7006
#define IDC_FILE_STATIC_KEYWORD 7009
#define IDC_FILE_EDIT_FILTER 7010
#define IDC_FILE_BTN_FILTER 7011
#define IDC_FILE_STATIC_EXCLUDE 7013 // 排除标签
#define IDC_FILE_EDIT_EXCLUDE 7014   // 排除输入框

// 右键菜单ID
#define IDM_FILE_CALC_HASH 7105
#define IDM_FILE_VIRUSTOTAL 7106
#define IDM_FILE_THREATBOOK 7107

enum ResultLimitOption {
    LIMIT_500 = 0,
    LIMIT_1000,
    LIMIT_3000,
    LIMIT_5000,
    LIMIT_10000,
    LIMIT_UNLIMITED
};

class FileInvestigator : public IInvestigator {
public:
    FileInvestigator();
    ~FileInvestigator() override;

    InvestigationResult Investigate(bool resetFilter = true) override;

    std::wstring GetModuleName() const override {
        return L"FileInvestigator";
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
        return m_timerId;
    }

    void OnTimer(UINT_PTR id) override;

    void SetMainWindow(HWND hWnd) {
        m_hMainWnd = hWnd;
    }

    void SetListView(HWND hListView) {
        m_hListView = hListView;
    }

    InvestigationResult GetScanResult() const;

    bool LoadFromCacheFile();
    void SaveToCacheFile();

private:
#ifdef WGWC_FILESCAN_TESTS
    friend struct FileInvestigatorTestAccess;
#endif
    void ShowScanConfigDialog();
    static INT_PTR CALLBACK ScanConfigDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);

    void StartScan();
    void StopScan(bool waitForExit = false);
    void UpdateScanControls();
    void ScanAllDirectories();

    static std::vector<std::wstring> ParseMultilineEdit(HWND hEdit);
    static void SetMultilineEdit(HWND hEdit, const std::vector<std::wstring>& lines);

    static DWORD WINAPI ScanThreadProc(LPVOID param);

    static std::wstring FormatFileSize(ULONGLONG size);
    static std::wstring FileTimeToString(const FILETIME& ft);

    // 线程安全添加文件
    bool AddMatchedFile(const FileInfo& info);

    int GetCurrentResultLimit();

    void ApplyFilter();
    bool MatchFilter(const FileInfo& info);
    void UpdateListView();
    void UpdateProgress();
    void UpdateStatusBar(const std::wstring& msg);

    void ShowFileHashes(const std::wstring& path);

    static const ColumnDef s_Columns[];
    static const int s_ColumnCount;

    // 列索引
    static const int COL_FILENAME = 0;
    static const int COL_PATH = 1;
    static const int COL_SIZE = 2;
    static const int COL_CREATION = 3;
    static const int COL_MODIFIED = 4;

    // 扫描结果
    std::vector<FileInfo> m_matchedFiles;  // 匹配的文件
    std::vector<FileInfo> m_filteredFiles; // 过滤后的文件
    CRITICAL_SECTION m_resultCS;           // 结果临界区

    // 扫描状态
    std::atomic<bool> m_scanning;     // 扫描中标志
    std::atomic<int> m_completedDirs; // 已完成目录数
    std::atomic<int> m_totalDirs;     // 总目录数
    std::atomic<int> m_scannedFiles;  // 已扫描文件数
    std::atomic<int> m_matchedCount;  // 匹配文件数
    std::atomic<bool> m_limitReached; // 是否达到结果上限

    HANDLE m_hScanThread;

    ScanConfig m_scanConfig;
    ScanConfig m_activeScanConfig;
    int m_activeResultLimit = 3000;
    bool m_stopRequested = false;

    // 工具栏控件
    HWND m_hBtnScan;
    HWND m_hBtnStop;
    HWND m_hBtnLoad;
    HWND m_hBtnScanConfig;
    HWND m_hComboLimit;
    HWND m_hStaticKeyword;
    HWND m_hEditFilter;
    HWND m_hStaticExclude;
    HWND m_hEditExclude;
    HWND m_hBtnFilter;
    HWND m_hMainWnd;
    HWND m_hListView;
    HINSTANCE m_hInst;

    UINT_PTR m_timerId;
};
