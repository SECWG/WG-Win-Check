// WG-Win-Check.cpp : Windows应急响应工具 - 主程序
//

// winsock2.h 必须在 windows.h 之前包含
#ifndef _WINSOCK2API_
#include <winsock2.h>
#endif
#include <ws2tcpip.h>

#include "../common/framework.h"
#include "WG-Win-Check.h"
#include <commctrl.h>
#include <commdlg.h>
#include <vector>
#include <string>
#include <memory>
#include <fstream>
#include <map>
#include <shellapi.h>

// 引入通用接口和模块
#include "../common/IInvestigator.h"
#include "../modules/user/UserInvestigator.h"
#include "../modules/network/NetworkInvestigator.h"
#include "../modules/process/ProcessInvestigator.h"
#include "../modules/autorun/AutorunInvestigator.h"
#include "../modules/service/ServiceInvestigator.h"
#include "../modules/task/TaskInvestigator.h"
#include "../modules/filescan/FileInvestigator.h"
#include "../modules/event/EventInvestigator.h"
#include "../modules/threat/ThreatSearchInvestigator.h"
#include "../modules/traces/ActivityTraceInvestigator.h"
#include "../modules/risk/RiskOverviewInvestigator.h"
#include "../common/RiskRepository.h"
#include "../common/ListViewCsv.h"
#include "../common/ListViewSupport.h"
#include "../common/BackgroundTask.h"
#include <variant>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define MAX_LOADSTRING 100
constexpr UINT_PTR IDT_RISK_BACKGROUND = 0x57470001;
constexpr UINT_PTR IDT_UPDATE_BACKGROUND = 0x57470002;

// 全局变量
HINSTANCE hInst;
WCHAR szTitle[MAX_LOADSTRING];
WCHAR szWindowClass[MAX_LOADSTRING];

// 控件句柄
HWND g_hWndTab = NULL;
HWND g_hWndListView = NULL;
HWND g_hWndStatusBar = NULL;
HFONT g_hUIFont = NULL;   // 全局界面字体句柄
HFONT g_hListFont = NULL; // ListView字体句柄
UINT g_UiDpi = 96;

// 当前选中的标签页
int g_nCurrentTab = 0;

const int UI_FONT_POINT_SIZE = 10;
const int UI_TAB_HEIGHT = 34;
const int UI_STATUS_MIN_HEIGHT = 24;
const int UI_INITIAL_CLIENT_WIDTH = 1280;
const int UI_INITIAL_CLIENT_HEIGHT = 760;
const int UI_MIN_WINDOW_WIDTH = 1024;
const int UI_MIN_WINDOW_HEIGHT = 640;
const int UI_MAX_WORKAREA_PERCENT = 92;

// 标签页名称
const wchar_t* g_TabNames[] = { L"\u98CE\u9669\u6982\u89C8",
                                L"用户排查",
                                L"进程排查",
                                L"网络排查",
                                L"自启动项",
                                L"服务排查",
                                L"计划任务",
                                L"文件排查",
                                L"事件日志",
                                L"威胁检索",
                                L"活动痕迹" };
const int g_nTabCount = sizeof(g_TabNames) / sizeof(g_TabNames[0]);

// 模块实例数组（按标签页索引）
IInvestigator* g_Investigators[g_nTabCount] = { nullptr };

// 全局风险结果仓库
RiskRepository g_RiskRepository;

// 当前显示的结果（用于自定义绘制）
InvestigationResult g_CurrentResult;
wgwc::gui::RowIconCache g_RowIcons;
int g_ListRedrawSuspendCount = 0;
bool g_ContextMenuActive = false;
bool g_DeferredNetworkResults = false;
bool g_DeferredNetworkIpLocation = false;
WPARAM g_DeferredNetworkStatusKind = 0;

// 函数前向声明
ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE, int);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK About(HWND, UINT, WPARAM, LPARAM);

// 权限检测
#include "ElevationPrompt.h"
BOOL IsRunAsAdmin();

// GUI 辅助函数
void CreateMainControls(HWND hWnd);
void ResizeControls(HWND hWnd);
void InitTabControl(HWND hWnd);
void InitModules();
void CleanupModules();
void UpdateListViewColumns(int nTab);
void OnTabSelChange();
void UpdateStatusBar(const wchar_t* text);
void UpdateCollectionStatus(const InvestigationResult& result, int nTab, bool cached);
void CreateModuleToolbars(HWND hWnd);
void UpdateToolbarVisibility(int nTab);
HFONT CreateUIFont(int pointSize, int weight);
void ApplyFontToWindowTree(HWND hWnd, HFONT hFont);
void EnablePerMonitorDpiAwareness();
UINT GetWindowDpiSafe(HWND hWnd);
int ScaleUiValue(int value);
void PositionInitialWindow(HWND hWnd);
void RecreateUiFonts(HWND hWnd);
void ScaleCurrentListColumns(UINT oldDpi, UINT newDpi);
void AdjustListViewColumnWidths(int nTab);
void SuspendListViewRedraw();
void ResumeListViewRedraw();
void AlignActiveToolbarControls(HWND hWnd, int toolbarTop, int toolbarHeight);
void EnhanceToolbarCheckboxes(HWND hWnd);

HICON GetRowIconForItem(int row, const InvestigationItem& item);
bool DrawCellWithIcon(LPNMLVCUSTOMDRAW lpcd, int iItem, int iSubItem);

// 扫描函数
void ScanCurrentTab();
void PopulateListView(const InvestigationResult& result);
void AddListViewItem(int index, const InvestigationItem& item);

// 内存缓存函数

// 风险概览同步
bool IsRiskSourceTab(int nTab);
const wchar_t* GetRiskModuleIdByTab(int nTab);
void SyncRiskFindingsFromModule(int nTab);
void RefreshRiskOverviewIfVisible();
void BeginRiskSourceModuleScan(int tab = TAB_RISK_OVERVIEW, bool resetFilter = false);
void ContinueRiskSourceModuleScan();

// 导出功能
void ExportCurrentTabToCSV();

// 自定义绘制
void HandleCustomDraw(LPNMLVCUSTOMDRAW lpcd, LRESULT* pResult);

// 主窗口句柄（用于模块回调）
HWND g_hMainWnd = NULL;
bool g_RiskScanRunning = false;
// 请求参数仅由界面线程使用，工作线程通过独立入口确定采集范围。
int g_RiskScanTab = TAB_RISK_OVERVIEW;
bool g_RiskScanResetFilter = false;

// 每个快照只保存一个模块的 Core 结果，界面容器由主线程独占。
struct RiskScanSnapshot {
    int tab = TAB_USERS;
    std::wstring collectedAt;
    std::variant<wgwc::core::CollectionResult<wgwc::core::users::UserRecord>,
                 wgwc::core::CollectionResult<wgwc::core::process::ProcessRecord>,
                 wgwc::core::CollectionResult<wgwc::core::autorun::Record>,
                 wgwc::core::CollectionResult<wgwc::core::services::Record>,
                 wgwc::core::CollectionResult<wgwc::core::tasks::Record>>
        data;
};

using RiskScanJob = wgwc::gui::BackgroundTask<RiskScanSnapshot>;
RiskScanJob g_RiskScanJob;
int g_RiskScanSuccessCount = 0;
int g_RiskScanFailedCount = 0;

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine,
                      _In_ int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    EnablePerMonitorDpiAwareness();

    if (!IsRunAsAdmin()) {
        const ElevationPromptResult elevationResult = ShowElevationPrompt(hInstance);
        if (elevationResult == ElevationPromptResult::ExitApplication ||
            elevationResult == ElevationPromptResult::Relaunched) {
            return FALSE;
        }
    }

    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    InitModules();

    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_WGWINCHECK, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    if (!InitInstance(hInstance, nCmdShow)) {
        CleanupModules();
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_WGWINCHECK));
    MSG msg;

    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    CleanupModules();
    return (int)msg.wParam;
}

void InitModules() {
    g_Investigators[TAB_USERS] = new UserInvestigator();
    g_Investigators[TAB_PROCESSES] = new ProcessInvestigator();
    g_Investigators[TAB_NETWORK] = new NetworkInvestigator();
    g_Investigators[TAB_AUTORUNS] = new AutorunInvestigator();
    g_Investigators[TAB_SERVICES] = new ServiceInvestigator();
    g_Investigators[TAB_TASKS] = new TaskInvestigator();
    g_Investigators[TAB_FILES] = new FileInvestigator();
    g_Investigators[TAB_EVENTS] = new EventInvestigator();
    g_Investigators[TAB_THREAT_SEARCH] = new ThreatSearchInvestigator();
    g_Investigators[TAB_ACTIVITY_TRACE] = new ActivityTraceInvestigator();
    g_Investigators[TAB_RISK_OVERVIEW] = new RiskOverviewInvestigator(&g_RiskRepository);
}

void CleanupModules() {
    for (int i = 0; i < g_nTabCount; i++) {
        if (g_Investigators[i]) {
            delete g_Investigators[i];
            g_Investigators[i] = nullptr;
        }
    }
}

// 权限检测

BOOL IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0,
                                 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

// 窗口类注册

ATOM MyRegisterClass(HINSTANCE hInstance) {
    WNDCLASSEXW wcex;
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_WGWINCHECK));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_WGWINCHECK);
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));
    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    hInst = hInstance;

    HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1200, 700,
                              nullptr, nullptr, hInstance, nullptr);

    if (!hWnd) {
        return FALSE;
    }

    g_hMainWnd = hWnd;
    PositionInitialWindow(hWnd);

    // 检测管理员权限并更新窗口标题
    std::wstring newTitle = szTitle;
    if (IsRunAsAdmin()) {
        newTitle += L" [管理员]";
    } else {
        newTitle += L" [非管理员]";
    }
    SetWindowTextW(hWnd, newTitle.c_str());

    CreateMainControls(hWnd);

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    UpdateStatusBar(L"\u98CE\u9669\u6982\u89C8\u5C1A\u672A\u91C7\u96C6");

    return TRUE;
}

void EnablePerMonitorDpiAwareness() {
    typedef BOOL(WINAPI * SetProcessDpiAwarenessContextFn)(HANDLE);
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    SetProcessDpiAwarenessContextFn setDpiContext = hUser32
                                                        ? reinterpret_cast<SetProcessDpiAwarenessContextFn>(
                                                              GetProcAddress(hUser32, "SetProcessDpiAwarenessContext"))
                                                        : nullptr;

    if (setDpiContext) {
        // 每显示器感知模式 V2（DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2）。
        setDpiContext(reinterpret_cast<HANDLE>(-4));
        return;
    }

    SetProcessDPIAware();
}

UINT GetWindowDpiSafe(HWND hWnd) {
    typedef UINT(WINAPI * GetDpiForWindowFn)(HWND);
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    GetDpiForWindowFn getDpiForWindow =
        hUser32 ? reinterpret_cast<GetDpiForWindowFn>(GetProcAddress(hUser32, "GetDpiForWindow")) : nullptr;

    if (getDpiForWindow && hWnd) {
        UINT dpi = getDpiForWindow(hWnd);
        if (dpi != 0) {
            return dpi;
        }
    }

    HDC hdc = GetDC(hWnd);
    UINT dpi = hdc ? static_cast<UINT>(GetDeviceCaps(hdc, LOGPIXELSX)) : 96;
    if (hdc) {
        ReleaseDC(hWnd, hdc);
    }
    return dpi != 0 ? dpi : 96;
}

int ScaleUiValue(int value) {
    return MulDiv(value, static_cast<int>(g_UiDpi), 96);
}

void PositionInitialWindow(HWND hWnd) {
    if (!hWnd) {
        return;
    }

    g_UiDpi = GetWindowDpiSafe(hWnd);

    HMONITOR hMonitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo = { sizeof(monitorInfo) };
    if (!GetMonitorInfoW(hMonitor, &monitorInfo)) {
        return;
    }

    RECT windowRect = { 0, 0, ScaleUiValue(UI_INITIAL_CLIENT_WIDTH), ScaleUiValue(UI_INITIAL_CLIENT_HEIGHT) };

    DWORD style = static_cast<DWORD>(GetWindowLongPtrW(hWnd, GWL_STYLE));
    DWORD exStyle = static_cast<DWORD>(GetWindowLongPtrW(hWnd, GWL_EXSTYLE));
    BOOL hasMenu = GetMenu(hWnd) != NULL;

    typedef BOOL(WINAPI * AdjustWindowRectExForDpiFn)(LPRECT, DWORD, BOOL, DWORD, UINT);
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    AdjustWindowRectExForDpiFn adjustForDpi =
        hUser32 ? reinterpret_cast<AdjustWindowRectExForDpiFn>(GetProcAddress(hUser32, "AdjustWindowRectExForDpi"))
                : nullptr;

    if (adjustForDpi) {
        adjustForDpi(&windowRect, style, hasMenu, exStyle, g_UiDpi);
    } else {
        AdjustWindowRectEx(&windowRect, style, hasMenu, exStyle);
    }

    int windowWidth = windowRect.right - windowRect.left;
    int windowHeight = windowRect.bottom - windowRect.top;
    int workWidth = monitorInfo.rcWork.right - monitorInfo.rcWork.left;
    int workHeight = monitorInfo.rcWork.bottom - monitorInfo.rcWork.top;
    int maxWidth = workWidth * UI_MAX_WORKAREA_PERCENT / 100;
    int maxHeight = workHeight * UI_MAX_WORKAREA_PERCENT / 100;

    if (windowWidth > maxWidth) {
        windowWidth = maxWidth;
    }
    if (windowHeight > maxHeight) {
        windowHeight = maxHeight;
    }

    int x = monitorInfo.rcWork.left + (workWidth - windowWidth) / 2;
    int y = monitorInfo.rcWork.top + (workHeight - windowHeight) / 2;
    SetWindowPos(hWnd, NULL, x, y, windowWidth, windowHeight, SWP_NOZORDER | SWP_NOACTIVATE);
}

HFONT CreateUIFont(int pointSize, int weight) {
    int height = -MulDiv(pointSize, static_cast<int>(g_UiDpi), 72);
    return CreateFontW(height, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
}

static BOOL CALLBACK ApplyFontToChildProc(HWND hWnd, LPARAM lParam) {
    HFONT hFont = (HFONT)lParam;
    if (hFont) {
        SendMessage(hWnd, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    return TRUE;
}

void ApplyFontToWindowTree(HWND hWnd, HFONT hFont) {
    if (!hWnd || !hFont) {
        return;
    }

    SendMessage(hWnd, WM_SETFONT, (WPARAM)hFont, TRUE);
    EnumChildWindows(hWnd, ApplyFontToChildProc, (LPARAM)hFont);
}

void RecreateUiFonts(HWND hWnd) {
    if (g_hListFont) {
        DeleteObject(g_hListFont);
        g_hListFont = NULL;
    }
    if (g_hUIFont) {
        DeleteObject(g_hUIFont);
        g_hUIFont = NULL;
    }

    g_hUIFont = CreateUIFont(UI_FONT_POINT_SIZE, FW_NORMAL);
    g_hListFont = CreateUIFont(UI_FONT_POINT_SIZE, FW_NORMAL);

    HFONT hUIFont = g_hUIFont ? g_hUIFont : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    HFONT hListFont = g_hListFont ? g_hListFont : hUIFont;
    ApplyFontToWindowTree(hWnd, hUIFont);
    SendMessage(g_hWndListView, WM_SETFONT, (WPARAM)hListFont, TRUE);
    SendMessage(g_hWndStatusBar, SB_SETMINHEIGHT, ScaleUiValue(UI_STATUS_MIN_HEIGHT), 0);
    SendMessage(g_hWndTab, TCM_SETITEMSIZE, 0, MAKELPARAM(0, ScaleUiValue(UI_TAB_HEIGHT - 4)));
    SendMessage(g_hWndTab, TCM_SETPADDING, 0, MAKELPARAM(ScaleUiValue(10), ScaleUiValue(4)));
}

void ScaleCurrentListColumns(UINT oldDpi, UINT newDpi) {
    if (!g_hWndListView || oldDpi == 0 || oldDpi == newDpi) {
        return;
    }

    HWND hHeader = ListView_GetHeader(g_hWndListView);
    int columnCount = hHeader ? Header_GetItemCount(hHeader) : 0;
    for (int i = 0; i < columnCount; i++) {
        int width = ListView_GetColumnWidth(g_hWndListView, i);
        ListView_SetColumnWidth(g_hWndListView, i, MulDiv(width, static_cast<int>(newDpi), static_cast<int>(oldDpi)));
    }
}

void AdjustListViewColumnWidths(int nTab) {
    if (!g_hWndListView || nTab != TAB_RISK_OVERVIEW) {
        return;
    }

    HWND hHeader = ListView_GetHeader(g_hWndListView);
    if (!hHeader || Header_GetItemCount(hHeader) < 7) {
        return;
    }

    RECT rcList = {};
    GetClientRect(g_hWndListView, &rcList);
    int availableWidth = rcList.right - rcList.left - GetSystemMetrics(SM_CXVSCROLL) - 2;

    int moduleWidth = ScaleUiValue(95);
    int levelWidth = ScaleUiValue(60);
    int objectWidth = ScaleUiValue(180);
    int infoWidth = ScaleUiValue(210);
    int info2MinWidth = ScaleUiValue(280);
    int reasonMinWidth = ScaleUiValue(220);
    int updatedWidth = ScaleUiValue(165);

    int fixedWidth = moduleWidth + levelWidth + objectWidth + infoWidth + updatedWidth;
    int flexibleWidth = availableWidth - fixedWidth;
    int minimumFlexibleWidth = info2MinWidth + reasonMinWidth;
    if (flexibleWidth < minimumFlexibleWidth) {
        flexibleWidth = minimumFlexibleWidth;
    }

    int info2Width = flexibleWidth * 58 / 100;
    if (info2Width < info2MinWidth) {
        info2Width = info2MinWidth;
    }
    int reasonWidth = flexibleWidth - info2Width;
    if (reasonWidth < reasonMinWidth) {
        reasonWidth = reasonMinWidth;
    }

    ListView_SetColumnWidth(g_hWndListView, 0, moduleWidth);
    ListView_SetColumnWidth(g_hWndListView, 1, levelWidth);
    ListView_SetColumnWidth(g_hWndListView, 2, objectWidth);
    ListView_SetColumnWidth(g_hWndListView, 3, infoWidth);
    ListView_SetColumnWidth(g_hWndListView, 4, info2Width);
    ListView_SetColumnWidth(g_hWndListView, 5, reasonWidth);
    ListView_SetColumnWidth(g_hWndListView, 6, updatedWidth);
}

void SuspendListViewRedraw() {
    if (!g_hWndListView) {
        return;
    }

    if (g_ListRedrawSuspendCount++ == 0) {
        SendMessage(g_hWndListView, WM_SETREDRAW, FALSE, 0);
        HWND hHeader = ListView_GetHeader(g_hWndListView);
        if (hHeader) {
            SendMessage(hHeader, WM_SETREDRAW, FALSE, 0);
        }
    }
}

void ResumeListViewRedraw() {
    if (!g_hWndListView || g_ListRedrawSuspendCount <= 0) {
        return;
    }

    if (--g_ListRedrawSuspendCount == 0) {
        HWND hHeader = ListView_GetHeader(g_hWndListView);
        if (hHeader) {
            SendMessage(hHeader, WM_SETREDRAW, TRUE, 0);
            RedrawWindow(hHeader, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
        }
        SendMessage(g_hWndListView, WM_SETREDRAW, TRUE, 0);
        RedrawWindow(g_hWndListView, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
    }
}

struct ToolbarAlignContext {
    HWND parent;
    int toolbarTop;
    int toolbarHeight;
};

static BOOL CALLBACK AlignToolbarControlProc(HWND hControl, LPARAM lParam) {
    ToolbarAlignContext* context = reinterpret_cast<ToolbarAlignContext*>(lParam);
    if (!context || GetParent(hControl) != context->parent || !IsWindowVisible(hControl)) {
        return TRUE;
    }

    RECT rcControl = {};
    if (!GetWindowRect(hControl, &rcControl)) {
        return TRUE;
    }
    MapWindowPoints(HWND_DESKTOP, context->parent, reinterpret_cast<POINT*>(&rcControl), 2);

    int toolbarBottom = context->toolbarTop + context->toolbarHeight;
    if (rcControl.bottom <= context->toolbarTop || rcControl.top >= toolbarBottom) {
        return TRUE;
    }

    wchar_t className[32] = {};
    GetClassNameW(hControl, className, _countof(className));
    bool isCombo = _wcsicmp(className, L"ComboBox") == 0;
    bool isStandardControl = isCombo || _wcsicmp(className, L"Button") == 0 || _wcsicmp(className, L"Edit") == 0 ||
                             _wcsicmp(className, L"Static") == 0;
    if (!isStandardControl) {
        return TRUE;
    }

    int controlHeight = ScaleUiValue(26);
    int controlY = context->toolbarTop + (context->toolbarHeight - controlHeight) / 2;
    int controlX = ScaleUiValue(rcControl.left);
    int controlWidth = ScaleUiValue(rcControl.right - rcControl.left);
    int windowHeight = isCombo ? ScaleUiValue(200) : controlHeight;

    SetWindowPos(hControl, NULL, controlX, controlY, controlWidth, windowHeight, SWP_NOZORDER | SWP_NOACTIVATE);
    return TRUE;
}

void AlignActiveToolbarControls(HWND hWnd, int toolbarTop, int toolbarHeight) {
    if (!hWnd || toolbarHeight <= 0) {
        return;
    }

    ToolbarAlignContext context = { hWnd, toolbarTop, toolbarHeight };
    EnumChildWindows(hWnd, AlignToolbarControlProc, reinterpret_cast<LPARAM>(&context));
}

static int ScaleCheckboxValue(HWND hWnd, int value) {
    UINT dpi = GetWindowDpiSafe(hWnd);
    return MulDiv(value, static_cast<int>(dpi), 96);
}

static void DrawEnhancedCheckbox(HWND hWnd, HDC hdc) {
    RECT rc = {};
    GetClientRect(hWnd, &rc);
    FillRect(hdc, &rc, GetSysColorBrush(COLOR_WINDOW));

    int boxSize = ScaleCheckboxValue(hWnd, 17);
    int boxLeft = ScaleCheckboxValue(hWnd, 1);
    RECT rcBox = { boxLeft, (rc.bottom - boxSize) / 2, boxLeft + boxSize, (rc.bottom - boxSize) / 2 + boxSize };

    UINT drawState = DFCS_BUTTONCHECK;
    if (SendMessage(hWnd, BM_GETCHECK, 0, 0) == BST_CHECKED)
        drawState |= DFCS_CHECKED;
    if (!IsWindowEnabled(hWnd))
        drawState |= DFCS_INACTIVE;
    if ((SendMessage(hWnd, BM_GETSTATE, 0, 0) & BST_PUSHED) != 0)
        drawState |= DFCS_PUSHED;
    DrawFrameControl(hdc, &rcBox, DFC_BUTTON, drawState);

    wchar_t textBuffer[128] = {};
    GetWindowTextW(hWnd, textBuffer, _countof(textBuffer));
    RECT rcText = rc;
    rcText.left = rcBox.right + ScaleCheckboxValue(hWnd, 5);

    HFONT hFont = reinterpret_cast<HFONT>(SendMessage(hWnd, WM_GETFONT, 0, 0));
    HGDIOBJ hOldFont = hFont ? SelectObject(hdc, hFont) : NULL;
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, GetSysColor(IsWindowEnabled(hWnd) ? COLOR_WINDOWTEXT : COLOR_GRAYTEXT));
    DrawTextW(hdc, textBuffer, -1, &rcText, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);

    if (GetFocus() == hWnd) {
        RECT rcFocus = rcText;
        InflateRect(&rcFocus, -1, -ScaleCheckboxValue(hWnd, 3));
        DrawFocusRect(hdc, &rcFocus);
    }
    if (hOldFont)
        SelectObject(hdc, hOldFont);
}

static LRESULT CALLBACK EnhancedCheckboxSubclassProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam,
                                                     UINT_PTR subclassId, DWORD_PTR refData) {
    UNREFERENCED_PARAMETER(refData);

    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT ps = {};
        HDC hdc = BeginPaint(hWnd, &ps);
        DrawEnhancedCheckbox(hWnd, hdc);
        EndPaint(hWnd, &ps);
        return 0;
    }
    case WM_PRINTCLIENT:
        DrawEnhancedCheckbox(hWnd, reinterpret_cast<HDC>(wParam));
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case BM_SETCHECK:
    case BM_SETSTATE:
    case WM_ENABLE:
    case WM_SETTEXT:
    case WM_SETFONT:
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_KEYDOWN:
    case WM_KEYUP: {
        LRESULT result = DefSubclassProc(hWnd, message, wParam, lParam);
        InvalidateRect(hWnd, NULL, TRUE);
        return result;
    }
    case WM_NCDESTROY:
        RemoveWindowSubclass(hWnd, EnhancedCheckboxSubclassProc, subclassId);
        break;
    }
    return DefSubclassProc(hWnd, message, wParam, lParam);
}

static BOOL CALLBACK EnhanceCheckboxProc(HWND hControl, LPARAM lParam) {
    HWND hParent = reinterpret_cast<HWND>(lParam);
    if (GetParent(hControl) != hParent)
        return TRUE;

    wchar_t className[32] = {};
    GetClassNameW(hControl, className, _countof(className));
    if (_wcsicmp(className, L"Button") != 0)
        return TRUE;

    LONG_PTR style = GetWindowLongPtrW(hControl, GWL_STYLE);
    UINT buttonType = static_cast<UINT>(style) & BS_TYPEMASK;
    if (buttonType == BS_CHECKBOX || buttonType == BS_AUTOCHECKBOX || buttonType == BS_3STATE ||
        buttonType == BS_AUTO3STATE) {
        SetWindowSubclass(hControl, EnhancedCheckboxSubclassProc, 0x57474342, 0);
    }
    return TRUE;
}

void EnhanceToolbarCheckboxes(HWND hWnd) {
    if (hWnd)
        EnumChildWindows(hWnd, EnhanceCheckboxProc, reinterpret_cast<LPARAM>(hWnd));
}

void CreateMainControls(HWND hWnd) {
    RECT rcClient;
    GetClientRect(hWnd, &rcClient);

    if (!g_hUIFont) {
        g_hUIFont = CreateUIFont(UI_FONT_POINT_SIZE, FW_NORMAL);
    }
    if (!g_hListFont) {
        g_hListFont = CreateUIFont(UI_FONT_POINT_SIZE, FW_NORMAL);
    }
    HFONT hUIFont = g_hUIFont ? g_hUIFont : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    HFONT hListFont = g_hListFont ? g_hListFont : hUIFont;
    int tabHeight = ScaleUiValue(UI_TAB_HEIGHT);

    g_hWndStatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL, WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, hWnd,
                                     (HMENU)IDC_STATUSBAR, hInst, NULL);
    SendMessage(g_hWndStatusBar, WM_SETFONT, (WPARAM)hUIFont, TRUE);
    SendMessage(g_hWndStatusBar, SB_SETMINHEIGHT, ScaleUiValue(UI_STATUS_MIN_HEIGHT), 0);

    // 状态栏分区：第一个分区占大部分宽度用于显示状态信息
    int statusParts[] = { -1 }; // 单分区，占满整个宽度
    SendMessage(g_hWndStatusBar, SB_SETPARTS, 1, (LPARAM)statusParts);

    g_hWndTab = CreateWindowEx(0, WC_TABCONTROL, NULL, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_TABS, 0, 0,
                               rcClient.right, tabHeight, hWnd, (HMENU)IDC_TAB_MAIN, hInst, NULL);

    SendMessage(g_hWndTab, WM_SETFONT, (WPARAM)hUIFont, TRUE);
    SendMessage(g_hWndTab, TCM_SETITEMSIZE, 0, MAKELPARAM(0, ScaleUiValue(UI_TAB_HEIGHT - 4)));
    SendMessage(g_hWndTab, TCM_SETPADDING, 0, MAKELPARAM(ScaleUiValue(10), ScaleUiValue(4)));

    InitTabControl(hWnd);

    g_hWndListView = CreateWindowEx(
        0, WC_LISTVIEW, NULL, WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, 0, tabHeight,
        rcClient.right, rcClient.bottom - tabHeight, hWnd, (HMENU)IDC_LISTVIEW_MAIN, hInst, NULL);

    // 设置扩展样式：全行选择、双缓冲、标签提示（不使用网格线）
    ListView_SetExtendedListViewStyle(g_hWndListView, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

    SendMessage(g_hWndListView, WM_SETFONT, (WPARAM)hListFont, TRUE);

    CreateModuleToolbars(hWnd);
    ApplyFontToWindowTree(hWnd, hUIFont);
    SendMessage(g_hWndListView, WM_SETFONT, (WPARAM)hListFont, TRUE);
    EnhanceToolbarCheckboxes(hWnd);

    g_nCurrentTab = TAB_RISK_OVERVIEW;
    TabCtrl_SetCurSel(g_hWndTab, TAB_RISK_OVERVIEW);
    UpdateListViewColumns(TAB_RISK_OVERVIEW);
    UpdateToolbarVisibility(TAB_RISK_OVERVIEW);
    if (g_Investigators[TAB_RISK_OVERVIEW]) {
        PopulateListView(g_Investigators[TAB_RISK_OVERVIEW]->Investigate(false));
    }
}

void CreateModuleToolbars(HWND hWnd) {
    // 为每个有工具栏的模块创建工具栏
    for (int i = 0; i < g_nTabCount; i++) {
        IInvestigator* investigator = g_Investigators[i];
        if (investigator && investigator->HasToolbar()) {
            investigator->CreateToolbar(hWnd, hInst);
            investigator->ShowToolbar(false); // 初始隐藏
            investigator->SetMainWindow(hWnd);
            investigator->SetListView(g_hWndListView);

            // 窗口句柄已由共享接口设置，事件日志只需补充状态栏回调。
            EventInvestigator* evtInv = dynamic_cast<EventInvestigator*>(investigator);
            if (evtInv) {
                evtInv->SetStatusCallback(UpdateStatusBar);
            }
        }
    }

    // 设置主窗口句柄（用于用户模块，无工具栏但需要右键菜单）
    UserInvestigator* userInv = dynamic_cast<UserInvestigator*>(g_Investigators[TAB_USERS]);
    if (userInv) {
        userInv->SetMainWindow(hWnd);
    }
}

void UpdateToolbarVisibility(int nTab) {
    for (int i = 0; i < g_nTabCount; i++) {
        IInvestigator* investigator = g_Investigators[i];
        if (investigator && investigator->HasToolbar()) {
            investigator->ShowToolbar(i == nTab);
        }
    }

    // 调整布局
    ResizeControls(g_hMainWnd);
}

void InitTabControl(HWND hWnd) {
    TCITEM tie;
    tie.mask = TCIF_TEXT;

    for (int i = 0; i < g_nTabCount; i++) {
        tie.pszText = (LPWSTR)g_TabNames[i];
        TabCtrl_InsertItem(g_hWndTab, i, &tie);
    }
}

void UpdateListViewColumns(int nTab) {
    // 从模块获取列定义
    IInvestigator* investigator = g_Investigators[nTab];

    // 如果模块使用自定义布局，跳过主ListView的列更新
    if (investigator && investigator->HasCustomLayout()) {
        return;
    }

    // 清除现有列和数据
    while (ListView_DeleteColumn(g_hWndListView, 0))
        ;
    ListView_DeleteAllItems(g_hWndListView);
    g_CurrentResult.items.clear();

    if (investigator) {
        const ColumnDef* columns = investigator->GetColumns();
        int columnCount = investigator->GetColumnCount();

        LVCOLUMN lvc;
        lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
        lvc.fmt = LVCFMT_LEFT;

        for (int i = 0; i < columnCount; i++) {
            lvc.iSubItem = i;
            lvc.pszText = (LPWSTR)columns[i].name;
            lvc.cx = ScaleUiValue(columns[i].width);
            ListView_InsertColumn(g_hWndListView, i, &lvc);
        }

        AdjustListViewColumnWidths(nTab);
    }
}

void OnTabSelChange() {
    g_nCurrentTab = TabCtrl_GetCurSel(g_hWndTab);

    SuspendListViewRedraw();

    // 先替换列和旧数据，再切换工具栏，避免新标签页短暂显示旧模块表格
    UpdateListViewColumns(g_nCurrentTab);

    UpdateToolbarVisibility(g_nCurrentTab);

    IInvestigator* investigator = g_Investigators[g_nCurrentTab];

    // 网络页进入时只采集一次；工具栏显示和本地筛选不再触发采集。
    if (investigator && g_nCurrentTab == TAB_NETWORK) {
        InvestigationResult result = investigator->Investigate(false);
        PopulateListView(result);
        UpdateCollectionStatus(result, g_nCurrentTab, false);
    } else if (investigator && investigator->HasCache()) {
        // 从缓存刷新（重新应用当前过滤条件）
        InvestigationResult filtered = investigator->RefreshFromCache();
        PopulateListView(filtered);
        UpdateCollectionStatus(filtered, g_nCurrentTab, true);
    } else if (g_RiskScanRunning && IsRiskSourceTab(g_nCurrentTab)) {
        UpdateStatusBar(L"核心模块正在采集，请稍后");
    } else {
        // 文件排查、事件日志、威胁检索、活动痕迹不自动扫描
        if (g_nCurrentTab == TAB_FILES || g_nCurrentTab == TAB_EVENTS || g_nCurrentTab == TAB_THREAT_SEARCH ||
            g_nCurrentTab == TAB_ACTIVITY_TRACE) {
            wchar_t statusText[256];
            if (g_nCurrentTab == TAB_THREAT_SEARCH) {
                swprintf_s(statusText, L"当前: %s - 请输入IOC后点击扫描", g_TabNames[g_nCurrentTab]);
            } else {
                swprintf_s(statusText, L"当前: %s - 请点击扫描或加载缓存", g_TabNames[g_nCurrentTab]);
            }
            UpdateStatusBar(statusText);
        } else if (IsRiskSourceTab(g_nCurrentTab)) {
            BeginRiskSourceModuleScan(g_nCurrentTab, true);
        } else {
            // 非核心模块保留各自的扫描入口。
            PostMessage(g_hMainWnd, WM_COMMAND, MAKEWPARAM(IDM_REFRESH, 0), 0);
        }
    }

    ResumeListViewRedraw();
}

void ResizeControls(HWND hWnd) {
    if (!g_hWndStatusBar || !g_hWndTab || !g_hWndListView) {
        return;
    }

    RECT rcClient;
    GetClientRect(hWnd, &rcClient);

    SendMessage(g_hWndStatusBar, WM_SIZE, 0, 0);

    RECT rcStatus;
    GetWindowRect(g_hWndStatusBar, &rcStatus);
    int statusHeight = rcStatus.bottom - rcStatus.top;

    int tabHeight = ScaleUiValue(UI_TAB_HEIGHT);
    int toolbarHeight = 0;

    IInvestigator* investigator = g_Investigators[g_nCurrentTab];
    if (investigator && investigator->HasToolbar()) {
        toolbarHeight = ScaleUiValue(investigator->GetToolbarHeight());
        investigator->ResizeToolbar(0, tabHeight, rcClient.right);
        if (!investigator->HasCustomLayout()) {
            AlignActiveToolbarControls(hWnd, tabHeight, toolbarHeight);
        }
    }

    SetWindowPos(g_hWndTab, NULL, 0, 0, rcClient.right, tabHeight, SWP_NOZORDER);

    // 如果模块使用自定义布局，隐藏主ListView
    if (investigator && investigator->HasCustomLayout()) {
        ShowWindow(g_hWndListView, SW_HIDE);
    } else {
        ShowWindow(g_hWndListView, SW_SHOW);
        SetWindowPos(g_hWndListView, NULL, 0, tabHeight + toolbarHeight, rcClient.right,
                     rcClient.bottom - tabHeight - toolbarHeight - statusHeight, SWP_NOZORDER);
        AdjustListViewColumnWidths(g_nCurrentTab);
    }
}

void UpdateStatusBar(const wchar_t* text) {
    SendMessage(g_hWndStatusBar, SB_SETTEXT, 0, (LPARAM)text);
}

const wchar_t* GetCollectionStatusName(int nTab) {
    switch (nTab) {
    case TAB_USERS:
        return L"用户";
    case TAB_PROCESSES:
        return L"进程";
    case TAB_NETWORK:
        return L"网络连接";
    case TAB_AUTORUNS:
        return L"自启动项";
    case TAB_SERVICES:
        return L"服务";
    case TAB_TASKS:
        return L"计划任务";
    case TAB_FILES:
        return L"文件";
    case TAB_EVENTS:
        return L"事件日志";
    case TAB_THREAT_SEARCH:
        return L"威胁检索";
    case TAB_ACTIVITY_TRACE:
        return L"活动痕迹";
    case TAB_RISK_OVERVIEW:
        return L"风险概览";
    default:
        return L"当前模块";
    }
}

void UpdateCollectionStatus(const InvestigationResult& result, int nTab, bool cached) {
    std::wstring text = GetCollectionStatusName(nTab);
    if (!result.success) {
        text += L"采集失败";
        if (result.stale) {
            text += L"，保留上次结果";
        }
    } else if (result.partial) {
        text += cached ? L"（缓存，采集不完整）" : L"部分已采集";
    } else {
        text += cached ? L"（缓存）" : L"已采集";
    }
    text += L" - 共 " + std::to_wstring(result.totalCount) + L" 项";
    if (!result.errorMessage.empty()) {
        text += L"；" + result.errorMessage;
    } else if (result.errorCode != 0) {
        text += L"；错误码 " + std::to_wstring(result.errorCode);
    }
    UpdateStatusBar(text.c_str());
}

HICON GetRowIconForItem(int row, const InvestigationItem& item) {
    if (g_nCurrentTab < 0 || g_nCurrentTab >= g_nTabCount) {
        return NULL;
    }

    IInvestigator* investigator = g_Investigators[g_nCurrentTab];
    if (!investigator || !investigator->HasRowIcons()) {
        return NULL;
    }

    return g_RowIcons.Get(investigator->GetRowIconPath(row, item));
}

bool DrawCellWithIcon(LPNMLVCUSTOMDRAW lpcd, int iItem, int iSubItem) {
    if (!lpcd || iItem < 0 || g_nCurrentTab < 0 || g_nCurrentTab >= g_nTabCount) {
        return false;
    }

    IInvestigator* investigator = g_Investigators[g_nCurrentTab];
    if (!investigator || !investigator->HasRowIcons() || iSubItem != investigator->GetRowIconColumn() ||
        iItem >= ListView_GetItemCount(g_hWndListView)) {
        return false;
    }

    InvestigationItem emptyItem;
    const InvestigationItem& item =
        (size_t)iItem < g_CurrentResult.items.size() ? g_CurrentResult.items[iItem] : emptyItem;
    HICON hIcon = GetRowIconForItem(iItem, item);
    if (!hIcon) {
        return false;
    }

    RECT rcCell = { 0 };
    if (iSubItem == 0) {
        if (!ListView_GetItemRect(g_hWndListView, iItem, &rcCell, LVIR_BOUNDS)) {
            return false;
        }
        rcCell.right = rcCell.left + ListView_GetColumnWidth(g_hWndListView, 0);
    } else {
        if (!ListView_GetSubItemRect(g_hWndListView, iItem, iSubItem, LVIR_BOUNDS, &rcCell)) {
            return false;
        }
    }

    HDC hdc = lpcd->nmcd.hdc;
    UINT state = ListView_GetItemState(g_hWndListView, iItem, LVIS_SELECTED);
    COLORREF textColor = lpcd->clrText;
    COLORREF bkColor = lpcd->clrTextBk;

    if (state & LVIS_SELECTED) {
        textColor = GetSysColor(COLOR_HIGHLIGHTTEXT);
        bkColor = GetSysColor(COLOR_HIGHLIGHT);
    }

    HBRUSH hBrush = CreateSolidBrush(bkColor);
    if (hBrush) {
        FillRect(hdc, &rcCell, hBrush);
        DeleteObject(hBrush);
    }

    int iconSize = GetSystemMetrics(SM_CXSMICON);
    int iconOffsetY = ((rcCell.bottom - rcCell.top) - iconSize) / 2;
    if (iconOffsetY < 0) {
        iconOffsetY = 0;
    }
    int iconY = rcCell.top + iconOffsetY;
    int iconX = rcCell.left + 4;
    DrawIconEx(hdc, iconX, iconY, hIcon, iconSize, iconSize, 0, NULL, DI_NORMAL);

    wchar_t textBuffer[4096] = { 0 };
    ListView_GetItemText(g_hWndListView, iItem, iSubItem, textBuffer, _countof(textBuffer));
    std::wstring text = textBuffer;

    RECT rcText = rcCell;
    rcText.left = iconX + iconSize + 4;
    rcText.right -= 4;

    int oldBkMode = SetBkMode(hdc, TRANSPARENT);
    COLORREF oldTextColor = SetTextColor(hdc, textColor);
    HFONT hFont = (HFONT)SendMessage(g_hWndListView, WM_GETFONT, 0, 0);
    HGDIOBJ hOldFont = hFont ? SelectObject(hdc, hFont) : NULL;

    DrawTextW(hdc, text.c_str(), -1, &rcText, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

    if (hOldFont) {
        SelectObject(hdc, hOldFont);
    }
    SetTextColor(hdc, oldTextColor);
    SetBkMode(hdc, oldBkMode);

    return true;
}

void ScanCurrentTab() {
    IInvestigator* investigator = g_Investigators[g_nCurrentTab];

    if (!investigator) {
        MessageBox(NULL, L"该模块尚未实现", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (g_RiskScanRunning) {
        UpdateStatusBar(L"核心模块正在采集，请稍后");
        return;
    }

    if (g_nCurrentTab == TAB_RISK_OVERVIEW) {
        BeginRiskSourceModuleScan();
        return;
    }

    if (IsRiskSourceTab(g_nCurrentTab)) {
        BeginRiskSourceModuleScan(g_nCurrentTab, true);
        return;
    }

    // 如果模块使用自定义布局，由模块自己处理
    if (investigator->HasCustomLayout()) {
        return;
    }

    const wchar_t* collectionName = GetCollectionStatusName(g_nCurrentTab);
    wchar_t statusText[256];
    swprintf_s(statusText, L"正在采集%s...", collectionName);
    UpdateStatusBar(statusText);

    // 执行扫描（模块内部会保存缓存）
    InvestigationResult result = investigator->Investigate(g_nCurrentTab != TAB_NETWORK);

    if (result.success && IsRiskSourceTab(g_nCurrentTab)) {
        SyncRiskFindingsFromModule(g_nCurrentTab);
    }

    // 填充ListView
    PopulateListView(result);

    // 不用正常完成文本覆盖模块的失败或部分采集状态。
    UpdateCollectionStatus(result, g_nCurrentTab, false);

    RefreshRiskOverviewIfVisible();
}

bool IsRiskSourceTab(int nTab) {
    return nTab == TAB_USERS || nTab == TAB_PROCESSES || nTab == TAB_AUTORUNS || nTab == TAB_SERVICES ||
           nTab == TAB_TASKS;
}

const wchar_t* GetRiskModuleIdByTab(int nTab) {
    switch (nTab) {
    case TAB_USERS:
        return L"user";
    case TAB_PROCESSES:
        return L"process";
    case TAB_AUTORUNS:
        return L"autorun";
    case TAB_SERVICES:
        return L"service";
    case TAB_TASKS:
        return L"task";
    default:
        return L"";
    }
}

void SyncRiskFindingsFromModule(int nTab) {
    if (!IsRiskSourceTab(nTab) || nTab < 0 || nTab >= g_nTabCount) {
        return;
    }

    IInvestigator* investigator = g_Investigators[nTab];
    if (!investigator) {
        return;
    }

    g_RiskRepository.ReplaceModuleFindings(GetRiskModuleIdByTab(nTab), investigator->GetRiskFindings());
}

void RefreshRiskOverviewIfVisible() {
    if (g_nCurrentTab != TAB_RISK_OVERVIEW) {
        return;
    }

    IInvestigator* overview = g_Investigators[TAB_RISK_OVERVIEW];
    if (!overview) {
        return;
    }

    InvestigationResult result = overview->Investigate(false);
    PopulateListView(result);

    wchar_t statusText[256];
    swprintf_s(statusText, L"\u98CE\u9669\u6982\u89C8 - \u5171 %d \u9879\u98CE\u9669", result.totalCount);
    UpdateStatusBar(statusText);
}

template <int TargetTab> void CollectRiskSnapshots(RiskScanJob::State& state) {
    const int tabs[] = { TAB_USERS, TAB_PROCESSES, TAB_AUTORUNS, TAB_SERVICES, TAB_TASKS };
    wgwc::core::CollectionContext context;
    context.externalCancel = &state.cancelled;
    // 单个线程顺序使用同一轮文件缓存，不需要给缓存增加并行锁。
    context.fileCache = std::make_shared<wgwc::core::files::EvidenceCache>();
    for (int index = 0; index < 5 && !context.ShouldStop(); ++index) {
        if (TargetTab != TAB_RISK_OVERVIEW && tabs[index] != TargetTab)
            continue;
        state.progress.store(index + 1);
        RiskScanSnapshot snapshot;
        snapshot.tab = tabs[index];
        snapshot.collectedAt = RiskOverviewNowString();
        switch (snapshot.tab) {
        case TAB_USERS:
            snapshot.data = wgwc::core::users::CollectUsers(context);
            break;
        case TAB_PROCESSES:
            snapshot.data = wgwc::core::process::CollectProcesses({}, context);
            break;
        case TAB_AUTORUNS:
            snapshot.data = wgwc::core::autorun::CollectAutoruns({}, context);
            break;
        case TAB_SERVICES:
            snapshot.data = wgwc::core::services::CollectServices({}, context);
            break;
        case TAB_TASKS:
            snapshot.data = wgwc::core::tasks::CollectTasks({}, context);
            break;
        }
        if (context.ShouldStop())
            break;
        state.Publish(std::move(snapshot));
    }
}

InvestigationResult ApplyRiskSnapshot(const RiskScanSnapshot& snapshot, bool resetFilter) {
    using namespace wgwc::core;
    switch (snapshot.tab) {
    case TAB_USERS:
        return static_cast<UserInvestigator*>(g_Investigators[TAB_USERS])
            ->ApplyCollection(std::get<CollectionResult<users::UserRecord>>(snapshot.data), resetFilter,
                              snapshot.collectedAt);
    case TAB_PROCESSES:
        return static_cast<ProcessInvestigator*>(g_Investigators[TAB_PROCESSES])
            ->ApplyCollection(std::get<CollectionResult<process::ProcessRecord>>(snapshot.data), resetFilter,
                              snapshot.collectedAt);
    case TAB_AUTORUNS:
        return static_cast<AutorunInvestigator*>(g_Investigators[TAB_AUTORUNS])
            ->ApplyCollection(std::get<CollectionResult<autorun::Record>>(snapshot.data), resetFilter,
                              snapshot.collectedAt);
    case TAB_SERVICES:
        return static_cast<ServiceInvestigator*>(g_Investigators[TAB_SERVICES])
            ->ApplyCollection(std::get<CollectionResult<services::Record>>(snapshot.data), resetFilter,
                              snapshot.collectedAt);
    case TAB_TASKS:
        return static_cast<TaskInvestigator*>(g_Investigators[TAB_TASKS])
            ->ApplyCollection(std::get<CollectionResult<tasks::Record>>(snapshot.data), resetFilter,
                              snapshot.collectedAt);
    default:
        return {};
    }
}

void BeginRiskSourceModuleScan(int tab, bool resetFilter) {
    if (g_RiskScanRunning) {
        UpdateStatusBar(L"核心模块正在采集，请稍后");
        return;
    }
    RiskScanJob::Work work = nullptr;
    switch (tab) {
    case TAB_RISK_OVERVIEW:
        work = CollectRiskSnapshots<TAB_RISK_OVERVIEW>;
        break;
    case TAB_USERS:
        work = CollectRiskSnapshots<TAB_USERS>;
        break;
    case TAB_PROCESSES:
        work = CollectRiskSnapshots<TAB_PROCESSES>;
        break;
    case TAB_AUTORUNS:
        work = CollectRiskSnapshots<TAB_AUTORUNS>;
        break;
    case TAB_SERVICES:
        work = CollectRiskSnapshots<TAB_SERVICES>;
        break;
    case TAB_TASKS:
        work = CollectRiskSnapshots<TAB_TASKS>;
        break;
    default:
        return;
    }
    if (!SetTimer(g_hMainWnd, IDT_RISK_BACKGROUND, 100, nullptr)) {
        UpdateStatusBar(L"无法启动核心模块采集定时器");
        return;
    }
    if (!g_RiskScanJob.Start(work)) {
        KillTimer(g_hMainWnd, IDT_RISK_BACKGROUND);
        UpdateStatusBar(L"无法启动核心模块采集线程");
        return;
    }
    g_RiskScanRunning = true;
    g_RiskScanTab = tab;
    g_RiskScanResetFilter = tab != TAB_RISK_OVERVIEW && resetFilter;
    g_RiskScanSuccessCount = 0;
    g_RiskScanFailedCount = 0;
    if (tab == TAB_RISK_OVERVIEW) {
        UpdateStatusBar(L"开始采集核心模块...");
    } else {
        wchar_t text[256];
        swprintf_s(text, L"正在采集%s...", GetCollectionStatusName(tab));
        UpdateStatusBar(text);
    }
}

void ContinueRiskSourceModuleScan() {
    if (!g_RiskScanRunning || g_ContextMenuActive)
        return;
    // 定时器只接收快照，不运行采集；关闭窗口后也没有遗留消息指针需要释放。
    const bool done = g_RiskScanJob.Done();
    RiskScanSnapshot snapshot;
    bool changed = false;
    while (g_RiskScanJob.Take(snapshot)) {
        if (!g_Investigators[snapshot.tab]) {
            ++g_RiskScanFailedCount;
            continue;
        }
        InvestigationResult result =
            ApplyRiskSnapshot(snapshot, snapshot.tab == g_RiskScanTab && g_RiskScanResetFilter);
        if (result.success) {
            SyncRiskFindingsFromModule(snapshot.tab);
            ++g_RiskScanSuccessCount;
        } else {
            ++g_RiskScanFailedCount;
        }
        if (g_nCurrentTab == snapshot.tab) {
            PopulateListView(result);
            UpdateCollectionStatus(result, snapshot.tab, false);
        }
        changed = true;
    }
    if (changed)
        RefreshRiskOverviewIfVisible();
    if (done) {
        const int completedTab = g_RiskScanTab;
        g_RiskScanRunning = false;
        g_RiskScanTab = TAB_RISK_OVERVIEW;
        g_RiskScanResetFilter = false;
        KillTimer(g_hMainWnd, IDT_RISK_BACKGROUND);
        g_RiskScanJob.Cancel();
        if (g_nCurrentTab == TAB_RISK_OVERVIEW && completedTab == TAB_RISK_OVERVIEW) {
            wchar_t text[256];
            if (g_RiskScanFailedCount > 0) {
                swprintf_s(text, L"核心模块已采集 - 成功 %d, 失败 %d", g_RiskScanSuccessCount, g_RiskScanFailedCount);
            } else {
                swprintf_s(text, L"核心模块已采集 - 共 %zu 项风险", g_RiskRepository.GetAllFindings().size());
            }
            UpdateStatusBar(text);
        } else if (IsRiskSourceTab(g_nCurrentTab) && g_Investigators[g_nCurrentTab]) {
            // 单模块采集期间切到尚无缓存的核心页，结束后只采集当前页。
            if (completedTab != TAB_RISK_OVERVIEW && g_nCurrentTab != completedTab &&
                !g_Investigators[g_nCurrentTab]->HasCache()) {
                BeginRiskSourceModuleScan(g_nCurrentTab, true);
            } else {
                UpdateCollectionStatus(g_CurrentResult, g_nCurrentTab,
                                       completedTab != TAB_RISK_OVERVIEW && g_nCurrentTab != completedTab);
            }
        }
    } else if (g_nCurrentTab == TAB_RISK_OVERVIEW && g_RiskScanTab == TAB_RISK_OVERVIEW) {
        const int tabs[] = { TAB_USERS, TAB_PROCESSES, TAB_AUTORUNS, TAB_SERVICES, TAB_TASKS };
        const int progress = g_RiskScanJob.Progress();
        if (progress > 0 && progress <= 5) {
            wchar_t text[256];
            swprintf_s(text, L"正在采集核心模块 %d/5: %s", progress, g_TabNames[tabs[progress - 1]]);
            UpdateStatusBar(text);
        }
    } else if (g_nCurrentTab == g_RiskScanTab) {
        wchar_t text[256];
        swprintf_s(text, L"正在采集%s...", GetCollectionStatusName(g_RiskScanTab));
        UpdateStatusBar(text);
    }
}

void PopulateListView(const InvestigationResult& result) {
    // 保存结果用于自定义绘制
    g_CurrentResult = result;
    g_RowIcons.Clear();

    // 支持与标签页切换共用的嵌套暂停重绘
    SuspendListViewRedraw();

    ListView_DeleteAllItems(g_hWndListView);

    // 优先使用rows格式（网络模块等使用）
    if (!result.rows.empty()) {
        for (size_t i = 0; i < result.rows.size(); i++) {
            const auto& row = result.rows[i];
            if (row.empty())
                continue;

            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = (int)i;
            lvi.iSubItem = 0;
            lvi.pszText = (LPWSTR)row[0].c_str();
            ListView_InsertItem(g_hWndListView, &lvi);

            for (size_t col = 1; col < row.size(); col++) {
                ListView_SetItemText(g_hWndListView, (int)i, (int)col, (LPWSTR)row[col].c_str());
            }
        }
    } else {
        // 使用items格式（用户模块等使用）
        for (size_t i = 0; i < result.items.size(); i++) {
            AddListViewItem((int)i, result.items[i]);
        }
    }

    ResumeListViewRedraw();
}

void AddListViewItem(int index, const InvestigationItem& item) {
    LVITEM lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = index;
    lvi.iSubItem = 0;

    if (!item.details.empty()) {
        lvi.pszText = (LPWSTR)item.details[0].c_str();
    } else {
        lvi.pszText = (LPWSTR)item.name.c_str();
    }

    ListView_InsertItem(g_hWndListView, &lvi);

    for (size_t col = 1; col < item.details.size(); col++) {
        ListView_SetItemText(g_hWndListView, index, (int)col, (LPWSTR)item.details[col].c_str());
    }
}

// 自定义绘制 - 委托给各模块处理
void HandleCustomDraw(LPNMLVCUSTOMDRAW lpcd, LRESULT* pResult) {
    switch (lpcd->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        *pResult = CDRF_NOTIFYITEMDRAW;
        break;

    case CDDS_ITEMPREPAINT:
        *pResult = CDRF_NOTIFYSUBITEMDRAW;
        break;

    case CDDS_SUBITEM | CDDS_ITEMPREPAINT: {
        int iItem = (int)lpcd->nmcd.dwItemSpec;
        int iSubItem = lpcd->iSubItem;

        // 默认颜色
        lpcd->clrText = GetSysColor(COLOR_WINDOWTEXT);
        lpcd->clrTextBk = GetSysColor(COLOR_WINDOW);

        // 委托给当前模块处理高亮
        IInvestigator* investigator = g_Investigators[g_nCurrentTab];
        if (investigator) {
            COLORREF highlightColor;
            if (investigator->GetCellHighlight(iItem, iSubItem, g_CurrentResult, highlightColor)) {
                lpcd->clrText = highlightColor;
            }
        }

        if (DrawCellWithIcon(lpcd, iItem, iSubItem)) {
            *pResult = CDRF_SKIPDEFAULT;
            break;
        }

        *pResult = CDRF_NEWFONT;
        break;
    }

    default:
        *pResult = CDRF_DODEFAULT;
        break;
    }
}

class ContextMenuScope {
public:
    ContextMenuScope(IInvestigator& investigator, int row) : investigator_(investigator) {
        g_ContextMenuActive = true;
        investigator_.BeginContextMenu(row);
    }

    ~ContextMenuScope() {
        investigator_.EndContextMenu();
        g_ContextMenuActive = false;
        if (g_DeferredNetworkIpLocation) {
            g_DeferredNetworkIpLocation = false;
            PostMessageW(g_hMainWnd, WM_NET_IP_LOCATION_DONE, 0, 0);
        }
        if (g_DeferredNetworkResults) {
            g_DeferredNetworkResults = false;
            PostMessageW(g_hMainWnd, WM_NET_RESULTS_CHANGED, g_DeferredNetworkStatusKind, 0);
        }
    }

    ContextMenuScope(const ContextMenuScope&) = delete;
    ContextMenuScope& operator=(const ContextMenuScope&) = delete;

private:
    IInvestigator& investigator_;
};

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    // 静态画刷用于控件背景
    static HBRUSH hBrushBg = NULL;

    switch (message) {
    case WM_CREATE:
        hBrushBg = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
        break;

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        SetBkMode((HDC)wParam, TRANSPARENT);
        return (LRESULT)hBrushBg;

    case WM_NET_RESULTS_CHANGED: {
        if (g_ContextMenuActive) {
            g_DeferredNetworkResults = true;
            g_DeferredNetworkStatusKind = wParam;
            return 0;
        }
        if (g_nCurrentTab == TAB_NETWORK && g_Investigators[TAB_NETWORK]) {
            int topIndex = ListView_GetTopIndex(g_hWndListView);
            InvestigationResult result = g_Investigators[TAB_NETWORK]->GetCachedResult();
            PopulateListView(result);
            if (topIndex > 0 && topIndex < ListView_GetItemCount(g_hWndListView)) {
                ListView_EnsureVisible(g_hWndListView, topIndex, FALSE);
            }
            if (wParam != 0) {
                UpdateCollectionStatus(result, TAB_NETWORK, wParam == 2);
            }
        }
        return 0;
    }

    case WM_NET_IP_LOCATION_DONE: {
        if (g_ContextMenuActive) {
            g_DeferredNetworkIpLocation = true;
            return 0;
        }
        NetworkInvestigator* netInv = dynamic_cast<NetworkInvestigator*>(g_Investigators[TAB_NETWORK]);
        if (netInv) {
            netInv->OnIpLocationDone(g_nCurrentTab == TAB_NETWORK);
        }
        return 0;
    }

    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        int wmCode = HIWORD(wParam);

        // 先让当前模块处理工具栏命令
        IInvestigator* investigator = g_Investigators[g_nCurrentTab];
        if (investigator && investigator->HasToolbar()) {
            if (investigator->HandleToolbarCommand((WORD)wmId, (WORD)wmCode)) {
                if (IsRiskSourceTab(g_nCurrentTab)) {
                    SyncRiskFindingsFromModule(g_nCurrentTab);
                    RefreshRiskOverviewIfVisible();
                }
                return 0;
            }
        }

        switch (wmId) {
        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
        case IDM_SCAN_ALL:
        case IDM_REFRESH:
            ScanCurrentTab();
            break;
        case IDM_REFRESH_KEEP_FILTER: {
            if (IsRiskSourceTab(g_nCurrentTab)) {
                BeginRiskSourceModuleScan(g_nCurrentTab, false);
                break;
            }
            IInvestigator* inv = g_Investigators[g_nCurrentTab];
            if (inv) {
                InvestigationResult result = inv->Investigate(false);
                if (result.success && IsRiskSourceTab(g_nCurrentTab)) {
                    SyncRiskFindingsFromModule(g_nCurrentTab);
                }
                PopulateListView(result);
                UpdateCollectionStatus(result, g_nCurrentTab, false);
                RefreshRiskOverviewIfVisible();
            }
            break;
        }
        case IDM_EXPORT_CSV:
            ExportCurrentTabToCSV();
            break;
        case IDM_CMD_CMD:
            // 异步打开 CMD
            ShellExecuteW(NULL, L"open", L"cmd.exe", NULL, NULL, SW_SHOWNORMAL);
            break;
        case IDM_CMD_POWERSHELL:
            // 异步打开 PowerShell
            ShellExecuteW(NULL, L"open", L"powershell.exe", NULL, NULL, SW_SHOWNORMAL);
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
    } break;

    case WM_TIMER: {
        if (wParam == IDT_RISK_BACKGROUND) {
            ContinueRiskSourceModuleScan();
            return 0;
        }
        if (g_ContextMenuActive)
            return 0;
        // 让当前模块处理定时器
        IInvestigator* investigator = g_Investigators[g_nCurrentTab];
        if (investigator) {
            UINT_PTR timerId = investigator->GetTimerId();
            if (timerId != 0 && wParam == timerId) {
                investigator->OnTimer(wParam);

                if (g_nCurrentTab == TAB_THREAT_SEARCH) {
                    ThreatSearchInvestigator* threatInv = dynamic_cast<ThreatSearchInvestigator*>(investigator);
                    if (threatInv) {
                        std::wstring status = threatInv->GetStatusText();
                        UpdateStatusBar(status.c_str());
                    }
                }

                return 0;
            }
        }
    } break;

    case WM_NOTIFY: {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->hwndFrom == g_hWndTab && pnmh->code == TCN_SELCHANGE) {
            OnTabSelChange();
        } else if (pnmh->hwndFrom == g_hWndListView && pnmh->code == NM_CUSTOMDRAW) {
            LRESULT result = 0;
            HandleCustomDraw((LPNMLVCUSTOMDRAW)lParam, &result);
            return result;
        } else if (pnmh->hwndFrom == g_hWndListView && pnmh->code == NM_DBLCLK) {
            LPNMITEMACTIVATE pnmia = (LPNMITEMACTIVATE)lParam;
            int row = pnmia->iItem;
            int nTab = TabCtrl_GetCurSel(g_hWndTab);
            if (row >= 0 && nTab >= 0 && nTab < g_nTabCount && g_Investigators[nTab]) {
                if (g_Investigators[nTab]->HandleDoubleClick(row)) {
                    return 0;
                }
            }
        } else if (pnmh->hwndFrom == g_hWndListView && pnmh->code == NM_RCLICK) {
            POINT screenPoint;
            GetCursorPos(&screenPoint);

            LVHITTESTINFO hitTest = { 0 };
            hitTest.pt = screenPoint;
            ScreenToClient(g_hWndListView, &hitTest.pt);
            ListView_SubItemHitTest(g_hWndListView, &hitTest);

            int row = hitTest.iItem;
            int column = hitTest.iSubItem;
            int nTab = TabCtrl_GetCurSel(g_hWndTab);
            if (nTab < 0 || nTab >= g_nTabCount || !g_Investigators[nTab]) {
                return 0;
            }

            if (row >= 0) {
                ListView_SetItemState(g_hWndListView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
                ListView_SetItemState(g_hWndListView, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            }

            IInvestigator* investigator = g_Investigators[nTab];
            ContextMenuScope menuScope(*investigator, row);
            auto moduleItems = investigator->GetContextMenuItems(row);
            std::vector<ContextMenuItem> extraItems;

            for (const auto& item : moduleItems) {
                if (item.id == 0 && (extraItems.empty() || extraItems.back().id == 0)) {
                    continue;
                }
                extraItems.push_back(item);
            }
            while (!extraItems.empty() && extraItems.back().id == 0) {
                extraItems.pop_back();
            }

            int itemCount = ListView_GetItemCount(g_hWndListView);
            if (itemCount <= 0 && extraItems.empty()) {
                return 0;
            }

            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, row >= 0 && column >= 0 ? MF_STRING : MF_GRAYED, IDM_CONTEXT_COPY_VALUE, L"复制值");
            AppendMenuW(hMenu, row >= 0 ? MF_STRING : MF_GRAYED, IDM_CONTEXT_COPY_ROW, L"复制行");
            AppendMenuW(hMenu, itemCount > 0 ? MF_STRING : MF_GRAYED, IDM_CONTEXT_COPY_ALL, L"复制全部");

            std::wstring filePath = row >= 0 ? investigator->GetContextFilePath(row) : L"";
            bool hasFilePath = !filePath.empty() && filePath[0] != L'<' && filePath[0] != L'[';
            if (hasFilePath) {
                AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuW(hMenu, MF_STRING, IDM_CONTEXT_FILE_DIRECTORY, L"文件目录");
                AppendMenuW(hMenu, MF_STRING, IDM_CONTEXT_FILE_PROPERTIES, L"文件属性");
            }

            if (!extraItems.empty()) {
                AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                for (const auto& item : extraItems) {
                    if (item.id == 0) {
                        AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                    } else {
                        AppendMenuW(hMenu, MF_STRING, item.id, item.text.c_str());
                    }
                }
            }

            UINT cmd =
                TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);

            switch (cmd) {
            case IDM_CONTEXT_COPY_VALUE:
                CommonUtils::CopyListViewCell(hWnd, g_hWndListView, row, column);
                return 0;
            case IDM_CONTEXT_COPY_ROW:
                CommonUtils::CopyListViewRow(hWnd, g_hWndListView, row);
                return 0;
            case IDM_CONTEXT_COPY_ALL:
                CommonUtils::CopyListViewAll(hWnd, g_hWndListView);
                return 0;
            case IDM_CONTEXT_FILE_DIRECTORY:
                CommonUtils::OpenFileLocation(hWnd, filePath, true, true);
                return 0;
            case IDM_CONTEXT_FILE_PROPERTIES:
                CommonUtils::OpenFileProperties(hWnd, filePath, true);
                return 0;
            default:
                break;
            }

            for (const auto& item : extraItems) {
                if (item.id != cmd || cmd == 0)
                    continue;

                if (g_RiskScanRunning && IsRiskSourceTab(nTab)) {
                    UpdateStatusBar(L"核心模块正在采集，请完成后再执行模块操作");
                    break;
                }
                bool proceed = true;
                if (item.requireConfirm) {
                    int ret = MessageBoxW(hWnd, item.confirmMsg.c_str(), L"确认操作", MB_YESNO | MB_ICONWARNING);
                    proceed = (ret == IDYES);
                }

                if (proceed && investigator->HandleContextMenu(cmd, row)) {
                    if (IsRiskSourceTab(nTab)) {
                        BeginRiskSourceModuleScan(nTab, false);
                    } else {
                        auto result = investigator->Investigate(false);
                        PopulateListView(result);
                        UpdateCollectionStatus(result, nTab, false);
                    }
                }
                break;
            }
            return 0;
        }
    } break;

    case WM_GETMINMAXINFO: {
        LPMINMAXINFO lpMMI = (LPMINMAXINFO)lParam;
        UINT dpi = GetWindowDpiSafe(hWnd);
        int minWidth = MulDiv(UI_MIN_WINDOW_WIDTH, static_cast<int>(dpi), 96);
        int minHeight = MulDiv(UI_MIN_WINDOW_HEIGHT, static_cast<int>(dpi), 96);

        HMONITOR hMonitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
        MONITORINFO monitorInfo = { sizeof(monitorInfo) };
        if (GetMonitorInfoW(hMonitor, &monitorInfo)) {
            int workWidth = monitorInfo.rcWork.right - monitorInfo.rcWork.left;
            int workHeight = monitorInfo.rcWork.bottom - monitorInfo.rcWork.top;
            int maximumMinWidth = workWidth * 96 / 100;
            int maximumMinHeight = workHeight * 96 / 100;
            if (minWidth > maximumMinWidth) {
                minWidth = maximumMinWidth;
            }
            if (minHeight > maximumMinHeight) {
                minHeight = maximumMinHeight;
            }
        }

        lpMMI->ptMinTrackSize.x = minWidth;
        lpMMI->ptMinTrackSize.y = minHeight;
    } break;

    case WM_DPICHANGED: {
        UINT oldDpi = g_UiDpi;
        UINT newDpi = HIWORD(wParam);
        if (newDpi == 0) {
            newDpi = 96;
        }
        g_UiDpi = newDpi;

        RECT* suggestedRect = reinterpret_cast<RECT*>(lParam);
        if (suggestedRect) {
            SetWindowPos(hWnd, NULL, suggestedRect->left, suggestedRect->top,
                         suggestedRect->right - suggestedRect->left, suggestedRect->bottom - suggestedRect->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
        }

        RecreateUiFonts(hWnd);
        ScaleCurrentListColumns(oldDpi, newDpi);
        ResizeControls(hWnd);
        InvalidateRect(hWnd, NULL, TRUE);
    }
        return 0;

    case WM_SIZE:
        ResizeControls(hWnd);
        break;

    case WM_DESTROY:
        KillTimer(hWnd, IDT_RISK_BACKGROUND);
        g_RiskScanJob.Cancel();
        g_RiskScanRunning = false;
        if (hBrushBg) {
            DeleteObject(hBrushBg);
            hBrushBg = NULL;
        }
        if (g_hListFont) {
            DeleteObject(g_hListFont);
            g_hListFont = NULL;
        }
        if (g_hUIFont) {
            DeleteObject(g_hUIFont);
            g_hUIFont = NULL;
        }
        g_RowIcons.Clear();
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

using UpdateCheckJob = wgwc::gui::BackgroundTask<CommonUtils::UpdateCheckResult>;

struct AboutState {
    UpdateCheckJob update;
    HFONT linkFont = nullptr;
    HFONT originalLinkFont = nullptr;

    ~AboutState() {
        if (linkFont)
            DeleteObject(linkFont);
    }
};

void CollectUpdateResult(UpdateCheckJob::State& state) {
    state.Publish(CommonUtils::CheckUpdate(PRODUCT_VERSION_WSTRING));
}

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG: {
        // 版本文本在运行时设置，避免资源编译器对字符串拼接的限制。
        SetWindowTextW(hDlg, L"关于 "
                             L"" PRODUCT_NAME);
        SetDlgItemTextW(hDlg, IDC_ABOUT_VERSION, L"版本 " PRODUCT_VERSION_WSTRING);
        auto* state = new AboutState();
        SetWindowLongPtrW(hDlg, DWLP_USER, reinterpret_cast<LONG_PTR>(state));
        // 设置链接文本颜色（蓝色下划线效果通过字体实现）
        HWND hLink = GetDlgItem(hDlg, IDC_ABOUT_LINK);
        if (hLink) {
            state->originalLinkFont = (HFONT)SendMessage(hLink, WM_GETFONT, 0, 0);
            LOGFONTW lf{};
            if (state->originalLinkFont && GetObjectW(state->originalLinkFont, sizeof(lf), &lf)) {
                lf.lfUnderline = TRUE;
                state->linkFont = CreateFontIndirectW(&lf);
                if (state->linkFont)
                    SendMessage(hLink, WM_SETFONT, (WPARAM)state->linkFont, TRUE);
            }
        }
    }
        return (INT_PTR)TRUE;

    case WM_CTLCOLORSTATIC: {
        HWND hCtrl = (HWND)lParam;
        if (GetDlgCtrlID(hCtrl) == IDC_ABOUT_LINK) {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, RGB(0, 102, 204));
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetStockObject(NULL_BRUSH);
        }
    } break;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        } else if (LOWORD(wParam) == IDC_ABOUT_LINK) {
            // 点击链接打开帮助手册
            ShellExecuteW(NULL, L"open", L"https://secwg.com/archives/019bb7f1-85d2-7799-acfe-70bc2b7064ed", NULL, NULL,
                          SW_SHOWNORMAL);
            return (INT_PTR)TRUE;
        } else if (LOWORD(wParam) == IDC_ABOUT_BTN_CHECK_UPDATE) {
            auto* state = reinterpret_cast<AboutState*>(GetWindowLongPtrW(hDlg, DWLP_USER));
            if (!state || state->update.Active())
                return (INT_PTR)TRUE;
            // 由当前对话框定时接收结果，旧请求不会回写已销毁或重建的窗口。
            if (!SetTimer(hDlg, IDT_UPDATE_BACKGROUND, 100, nullptr)) {
                SetDlgItemTextW(hDlg, IDC_ABOUT_UPDATE_STATUS, L"无法启动更新检查");
                return (INT_PTR)TRUE;
            }
            if (!state->update.Start(CollectUpdateResult)) {
                KillTimer(hDlg, IDT_UPDATE_BACKGROUND);
                SetDlgItemTextW(hDlg, IDC_ABOUT_UPDATE_STATUS, L"无法启动更新检查");
                EnableWindow(GetDlgItem(hDlg, IDC_ABOUT_BTN_CHECK_UPDATE), TRUE);
                return (INT_PTR)TRUE;
            }
            EnableWindow(GetDlgItem(hDlg, IDC_ABOUT_BTN_CHECK_UPDATE), FALSE);
            SetDlgItemTextW(hDlg, IDC_ABOUT_UPDATE_STATUS, L"检查中...");

            return (INT_PTR)TRUE;
        }
        break;

    case WM_TIMER: {
        if (wParam != IDT_UPDATE_BACKGROUND)
            break;
        auto* state = reinterpret_cast<AboutState*>(GetWindowLongPtrW(hDlg, DWLP_USER));
        CommonUtils::UpdateCheckResult result;
        if (state && state->update.Take(result)) {
            KillTimer(hDlg, IDT_UPDATE_BACKGROUND);
            state->update.Cancel();
            std::wstring text = !result.success    ? L"检查失败"
                                : result.hasUpdate ? L"最新：" + result.latestVersion
                                                   : L"已是最新版本";
            SetDlgItemTextW(hDlg, IDC_ABOUT_UPDATE_STATUS, text.c_str());
            EnableWindow(GetDlgItem(hDlg, IDC_ABOUT_BTN_CHECK_UPDATE), TRUE);
        }
        return (INT_PTR)TRUE;
    }
    case WM_DESTROY: {
        KillTimer(hDlg, IDT_UPDATE_BACKGROUND);
        auto* state = reinterpret_cast<AboutState*>(GetWindowLongPtrW(hDlg, DWLP_USER));
        SetWindowLongPtrW(hDlg, DWLP_USER, 0);
        if (state) {
            HWND link = GetDlgItem(hDlg, IDC_ABOUT_LINK);
            if (link && state->originalLinkFont)
                SendMessageW(link, WM_SETFONT, (WPARAM)state->originalLinkFont, FALSE);
            delete state;
        }
        return (INT_PTR)TRUE;
    }

    case WM_SETCURSOR: {
        // 鼠标悬停在链接上时显示手型光标
        HWND hLink = GetDlgItem(hDlg, IDC_ABOUT_LINK);
        if ((HWND)wParam == hLink) {
            SetCursor(LoadCursor(NULL, IDC_HAND));
            return (INT_PTR)TRUE;
        }
    } break;
    }
    return (INT_PTR)FALSE;
}

// 导出当前标签页的 ListView 内容为 CSV
void ExportCurrentTabToCSV() {
    // 确定要导出的ListView
    HWND hListView = g_hWndListView;

    // 事件日志模块使用自己的ListView
    IInvestigator* investigator = g_Investigators[g_nCurrentTab];
    if (investigator && investigator->HasCustomLayout()) {
        EventInvestigator* evtInv = dynamic_cast<EventInvestigator*>(investigator);
        if (evtInv) {
            // 获取事件日志模块的ListView（通过控件ID）
            hListView = GetDlgItem(g_hMainWnd, 9010); // 事件列表控件标识：IDC_EVT_LISTVIEW。
        }
    }

    if (!hListView) {
        UpdateStatusBar(L"导出失败：无法获取列表控件");
        return;
    }

    int itemCount = ListView_GetItemCount(hListView);
    if (itemCount == 0) {
        UpdateStatusBar(L"导出失败：没有数据可导出");
        return;
    }

    // 弹出保存对话框
    wchar_t szFile[MAX_PATH] = L"";
    swprintf_s(szFile, L"%s.csv", g_TabNames[g_nCurrentTab]);

    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = L"CSV文件 (*.csv)\0*.csv\0所有文件 (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (!GetSaveFileNameW(&ofn)) {
        return; // 用户取消
    }

    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
    UpdateStatusBar(L"正在导出...");

    DWORD exportError = ERROR_SUCCESS;
    const bool exported = wgwc::gui::csv::ExportListView(hListView, szFile, exportError);
    SetCursor(hOldCursor);
    if (!exported) {
        const std::wstring message = L"导出失败，原文件未被覆盖（错误码：" + std::to_wstring(exportError) + L"）";
        UpdateStatusBar(message.c_str());
        return;
    }

    const std::wstring message = L"导出完成：" + std::to_wstring(itemCount) + L" 条记录已保存到 " + szFile;
    UpdateStatusBar(message.c_str());
}
