#pragma once

#include "../../common/IInvestigator.h"
#include "../../common/CommonUtils.h"
#include "../../../core/modules/traces/TraceModule.h"
#include <windows.h>
#include <vector>
#include <string>

using ActivityType = wgwc::core::traces::ActivityType;

// 工具栏控件 ID
#define IDC_ACT_BTN_SCAN 5001
#define IDC_ACT_BTN_LOAD 5002
#define IDC_ACT_COMBO_TYPE 5003
#define IDC_ACT_COMBO_SOURCE 5004
#define IDC_ACT_STATIC_FILTER 5005
#define IDC_ACT_EDIT_FILTER 5006
#define IDC_ACT_BTN_FILTER 5007

using ActivityRecord = wgwc::core::traces::Record;

class ActivityTraceInvestigator : public IInvestigator {
public:
    ActivityTraceInvestigator();
    ~ActivityTraceInvestigator() override;

    InvestigationResult Investigate(bool resetFilter = true) override;

    std::wstring GetModuleName() const override {
        return L"ActivityTraceInvestigator";
    }

    // 内存缓存用于切换页面；采集后自动保存，历史缓存由加载按钮读取。
    bool HasCache() const override {
        return !m_records.empty();
    } // 有数据时返回true

    InvestigationResult GetCachedResult() const override {
        return const_cast<ActivityTraceInvestigator*>(this)->BuildFilteredResult();
    }

    void ClearCache() override {
        m_records.clear();
        m_filteredRecords.clear();
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

    void SetMainWindow(HWND hWnd) override {
        m_hMainWnd = hWnd;
    }

    void SetListView(HWND hListView) override {
        m_hListView = hListView;
    }

    bool LoadFromCacheFile();
    void SaveToCacheFile();

    void StartScan();

private:
#ifdef WGWC_ACTIVITY_CACHE_TESTS
    friend struct ActivityCacheTestAccess;
#endif
    std::wstring FormatFileTime(const FILETIME& ft) const;
    std::wstring GetActivityTypeString(ActivityType type) const;

    void ApplyFilter();
    bool MatchesFilter(const ActivityRecord& record) const;
    InvestigationResult BuildFilteredResult();
    void UpdateListView();
    void UpdateStatusBar();

    static const ColumnDef s_Columns[];
    static const int s_ColumnCount;

    // 列索引
    static const int COL_TIME = 0;
    static const int COL_TYPE = 1;
    static const int COL_DESCRIPTION = 2;
    static const int COL_DETAILS = 3;
    static const int COL_SOURCE = 4;

    // 数据存储
    std::vector<ActivityRecord> m_records;
    std::vector<ActivityRecord> m_filteredRecords;

    // 工具栏控件
    HWND m_hToolbarPanel;
    HWND m_hBtnScan;
    HWND m_hBtnLoad;
    HWND m_hComboType;
    HWND m_hComboSource;
    HWND m_hStaticFilter;
    HWND m_hEditFilter;
    HWND m_hBtnFilter;

    HWND m_hMainWnd;
    HWND m_hListView;
    HINSTANCE m_hInst;

    // 过滤条件
    int m_filterType;   // 0=全部, 1-7=具体类型
    int m_filterSource; // 0=全部, 1-5=具体来源
    std::wstring m_filterText;
};
