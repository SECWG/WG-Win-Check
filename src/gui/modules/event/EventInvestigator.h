#pragma once

#include "../../common/IInvestigator.h"
#include "../../common/CommonUtils.h"
#include <windows.h>
#include <winevt.h>
#include <commctrl.h>
#include <vector>
#include <string>

#pragma comment(lib, "wevtapi.lib")

enum class FieldType {
    Normal,    // 普通文本
    LogonType, // 登录类型数字转中文
    HexToInt,  // 十六进制转十进制
    FilePath,  // 提取文件名部分
    EmptyDash, // "-"显示为空
    StartType, // 服务启动类型转中文
    EngineData // 从无名<Data>大字符串中提取 Key=Value
};

struct FieldMapping {
    const wchar_t* xmlName;     // XML中的字段名
    const wchar_t* displayName; // 列标题
    int width;                  // 列宽
    FieldType type;             // 转换类型
    const wchar_t* parentNode;  // 父节点名（可选，nullptr表示默认EventData）
};

struct EventConfig {
    const wchar_t* name;        // 显示名称（左侧列表）
    const wchar_t* channel;     // 日志通道
    DWORD eventId;              // 事件ID
    const FieldMapping* fields; // 字段映射数组
    int fieldCount;             // 字段数量
};

struct EventRecord {
    std::wstring timeCreated;
    DWORD eventId;
    std::vector<std::wstring> fieldValues; // 按字段顺序存储值
};

typedef void (*StatusCallback)(const wchar_t* text);

// 工具栏控件ID
#define IDC_EVT_CATEGORY_LIST 9001
#define IDC_EVT_COMBO_TIME 9002
#define IDC_EVT_DTP_START 9003
#define IDC_EVT_DTP_END 9004
#define IDC_EVT_COMBO_LIMIT 9005
#define IDC_EVT_BTN_QUERY 9006
#define IDC_EVT_BTN_PATH 9007
#define IDC_EVT_BTN_EVENTVWR 9008
#define IDC_EVT_EDIT_FILTER 9009
#define IDC_EVT_LISTVIEW 9010

// 右键菜单ID
#define IDM_EVT_COPY_CELL 9101
#define IDM_EVT_COPY_ROW 9102
#define IDM_EVT_COPY_ALL 9103

class EventInvestigator : public IInvestigator {
public:
    EventInvestigator();
    ~EventInvestigator() override;

    InvestigationResult Investigate(bool resetFilter = true) override;

    std::wstring GetModuleName() const override {
        return L"EventInvestigator";
    }

    const ColumnDef* GetColumns() const override {
        return nullptr;
    }

    int GetColumnCount() const override {
        return 0;
    }

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

    bool HasCustomLayout() const override {
        return true;
    }

    void SetMainWindow(HWND hWnd) override {
        m_hMainWnd = hWnd;
    }

    void SetListView(HWND hListView) override;

    void SetStatusCallback(StatusCallback cb) {
        m_statusCallback = cb;
    }

    std::vector<ContextMenuItem> GetContextMenuItems(int row) const override;
    bool HandleContextMenu(UINT menuId, int row) override;

private:
    void CreateCategoryList();
    void CreateFilterToolbar();
    void CreateEventListView();
    void UpdateLayout();

    void OnCategoryChanged();
    void UpdateColumns();

    void DoQuery();
    void QueryEvents();

    void UpdateStatus(const wchar_t* format, ...);

    void ParseEventXml(const wchar_t* xml);
    std::wstring ExtractDataValue(const std::wstring& xml, const std::wstring& name, const wchar_t* parentNode);
    std::wstring ExtractTimeCreated(const std::wstring& xml);
    std::wstring ConvertFieldValue(const std::wstring& value, FieldType type);

    void UpdateListView();
    void ApplyFilter();

    void UpdateTimeRange();
    std::wstring BuildXPathQuery();
    std::wstring FormatSystemTime(const std::wstring& utcTime);

    static const EventConfig s_EventConfigs[];
    static const int s_EventConfigCount;

    // 当前状态
    int m_currentIndex;                  // 当前选中的事件类型索引
    std::vector<EventRecord> m_records;  // 查询结果
    std::vector<EventRecord> m_filtered; // 过滤后结果
    DWORD m_lastError;                   // 最后一次查询错误码
    StatusCallback m_statusCallback;     // 状态栏回调

    // 控件句柄
    HWND m_hCategoryList;
    HWND m_hComboTime;
    HWND m_hDtpStart;
    HWND m_hDtpEnd;
    HWND m_hComboLimit;
    HWND m_hBtnQuery;
    HWND m_hBtnPath;
    HWND m_hBtnEventVwr;
    HWND m_hEditFilter;
    HWND m_hEventListView;
    HWND m_hMainListView;
    HWND m_hMainWnd;
    HINSTANCE m_hInst;

    // 布局参数
    int m_categoryWidth;
    int m_toolbarHeight;
    RECT m_clientRect;
    int m_contextColumn = -1;

    static LRESULT CALLBACK SubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass,
                                         DWORD_PTR dwRefData);
    void HandleListViewRightClick(LPNMITEMACTIVATE pnmia);
};
