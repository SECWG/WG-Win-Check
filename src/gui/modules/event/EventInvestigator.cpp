// EventInvestigator.cpp - 事件日志排查模块（字段自动映射版）

#include "EventInvestigator.h"

#include <algorithm>
#include <sstream>
#include <shellapi.h>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

// 字段映射定义（每个事件ID单独定义）

// 4624 登录成功
static const FieldMapping s_Fields_4624[] = {
    { L"TargetUserName",   L"用户名",   120, FieldType::Normal,    nullptr },
    { L"TargetDomainName", L"域",       100, FieldType::Normal,    nullptr },
    { L"LogonType",        L"登录类型", 80,  FieldType::LogonType, nullptr },
    { L"IpAddress",        L"来源IP",   130, FieldType::EmptyDash, nullptr },
    { L"WorkstationName",  L"来源主机", 130, FieldType::EmptyDash, nullptr },
};

// 4625 登录失败
static const FieldMapping s_Fields_4625[] = {
    { L"TargetUserName",   L"用户名",   120, FieldType::Normal,    nullptr },
    { L"TargetDomainName", L"域",       100, FieldType::Normal,    nullptr },
    { L"LogonType",        L"登录类型", 80,  FieldType::LogonType, nullptr },
    { L"IpAddress",        L"来源IP",   130, FieldType::EmptyDash, nullptr },
    { L"WorkstationName",  L"来源主机", 130, FieldType::EmptyDash, nullptr },
    { L"FailureReason",    L"失败原因", 180, FieldType::Normal,    nullptr },
};

// 4720 创建用户
static const FieldMapping s_Fields_4720[] = {
    { L"TargetUserName",    L"新账户",   140, FieldType::Normal, nullptr },
    { L"TargetDomainName",  L"域",       100, FieldType::Normal, nullptr },
    { L"SubjectUserName",   L"操作者",   140, FieldType::Normal, nullptr },
    { L"SubjectDomainName", L"操作者域", 100, FieldType::Normal, nullptr },
};

// 7045 服务安装
static const FieldMapping s_Fields_7045[] = {
    { L"ServiceName", L"服务名",   180, FieldType::Normal,    nullptr },
    { L"ImagePath",   L"服务路径", 360, FieldType::Normal,    nullptr },
    { L"ServiceType", L"类型",     80,  FieldType::Normal,    nullptr },
    { L"StartType",   L"启动类型", 90,  FieldType::StartType, nullptr },
    { L"AccountName", L"运行账户", 130, FieldType::Normal,    nullptr },
};

// 4698 计划任务创建
static const FieldMapping s_Fields_4698[] = {
    { L"TaskName",          L"任务名", 240, FieldType::Normal, nullptr },
    { L"SubjectUserName",   L"操作者", 140, FieldType::Normal, nullptr },
    { L"SubjectDomainName", L"域",     100, FieldType::Normal, nullptr },
};

// 4104 PowerShell脚本块
static const FieldMapping s_Fields_4104[] = {
    { L"Path",            L"脚本路径", 260, FieldType::Normal, nullptr },
    { L"ScriptBlockText", L"脚本内容", 560, FieldType::Normal, nullptr },
};

// 400 PowerShell引擎启动（无名Data，Key=Value格式）
// parentNode 格式：__KV__:Key:TruncateAt，xmlName 为包含 Key=Value 大字符串的节点名
// TruncateAt 为可选的截断字符串，提取值时遇到该字符串则截断
static const FieldMapping s_Fields_400[] = {
    { L"Data", L"启动程序", 620, FieldType::EngineData, L"__KV__:HostApplication:EngineVersion=" },
};

// 1102 日志清除
static const FieldMapping s_Fields_1102[] = {
    { L"SubjectUserName",   L"操作者", 170, FieldType::Normal, nullptr },
    { L"SubjectDomainName", L"域",     110, FieldType::Normal, nullptr },
};

// 21 RDP登录（LocalSessionManager）- 使用UserData节点
static const FieldMapping s_Fields_21[] = {
    { L"User",      L"用户",   170, FieldType::Normal, L"UserData" },
    { L"SessionID", L"会话ID", 75,  FieldType::Normal, L"UserData" },
    { L"Address",   L"来源IP", 140, FieldType::Normal, L"UserData" },
};

// 1024 RDP出站连接
static const FieldMapping s_Fields_1024[] = {
    { L"Value", L"目标服务器", 280, FieldType::Normal, nullptr },
};

// 4688 进程创建
static const FieldMapping s_Fields_4688[] = {
    { L"NewProcessId",      L"进程ID",   75,  FieldType::HexToInt, nullptr },
    { L"NewProcessName",    L"进程路径", 280, FieldType::Normal,   nullptr },
    { L"CommandLine",       L"命令行",   420, FieldType::Normal,   nullptr },
    { L"SubjectUserName",   L"用户",     130, FieldType::Normal,   nullptr },
    { L"ParentProcessName", L"父进程",   220, FieldType::FilePath, nullptr },
};

// 4732 用户入组
static const FieldMapping s_Fields_4732[] = {
    { L"MemberName",        L"成员",     180, FieldType::Normal, nullptr },
    { L"TargetUserName",    L"目标组",   150, FieldType::Normal, nullptr },
    { L"SubjectUserName",   L"操作者",   140, FieldType::Normal, nullptr },
    { L"SubjectDomainName", L"操作者域", 100, FieldType::Normal, nullptr },
};

// 5140 共享访问
static const FieldMapping s_Fields_5140[] = {
    { L"SubjectUserName",   L"用户",     140, FieldType::Normal,    nullptr },
    { L"SubjectDomainName", L"域",       100, FieldType::Normal,    nullptr },
    { L"IpAddress",         L"来源IP",   130, FieldType::EmptyDash, nullptr },
    { L"ShareName",         L"共享名",   150, FieldType::Normal,    nullptr },
    { L"ShareLocalPath",    L"本地路径", 260, FieldType::Normal,    nullptr },
};

// 5156 Windows 筛选平台（WFP）允许网络连接
static const FieldMapping s_Fields_5156[] = {
    { L"Application",   L"进程路径", 320, FieldType::Normal,    nullptr },
    { L"ProcessID",     L"进程ID",   75,  FieldType::HexToInt,  nullptr },
    { L"Direction",     L"方向",     90,  FieldType::Normal,    nullptr },
    { L"SourceAddress", L"源地址",   135, FieldType::EmptyDash, nullptr },
    { L"SourcePort",    L"源端口",   80,  FieldType::Normal,    nullptr },
    { L"DestAddress",   L"目标地址", 135, FieldType::EmptyDash, nullptr },
    { L"DestPort",      L"目标端口", 80,  FieldType::Normal,    nullptr },
    { L"Protocol",      L"协议",     75,  FieldType::Normal,    nullptr },
};

// 4672 特权登录
static const FieldMapping s_Fields_4672[] = {
    { L"SubjectUserName",   L"用户",     140, FieldType::Normal, nullptr },
    { L"SubjectDomainName", L"域",       100, FieldType::Normal, nullptr },
    { L"PrivilegeList",     L"特权列表", 380, FieldType::Normal, nullptr },
};

// 1116 Windows Defender 检测到恶意软件
static const FieldMapping s_Fields_1116[] = {
    { L"Threat Name",    L"威胁名称", 240, FieldType::Normal, nullptr },
    { L"Severity Name",  L"严重性",   80,  FieldType::Normal, nullptr },
    { L"Category Name",  L"类别",     100, FieldType::Normal, nullptr },
    { L"Path",           L"路径",     360, FieldType::Normal, nullptr },
    { L"Detection User", L"检测用户", 140, FieldType::Normal, nullptr },
    { L"Process Name",   L"进程",     180, FieldType::Normal, nullptr },
    { L"Action Name",    L"操作",     120, FieldType::Normal, nullptr },
};

// 事件配置表

const EventConfig EventInvestigator::s_EventConfigs[] = {
    { L"登录成功", L"Security",                                                           4624, s_Fields_4624, _countof(s_Fields_4624) },
    { L"登录失败", L"Security",                                                           4625, s_Fields_4625, _countof(s_Fields_4625) },
    { L"创建用户", L"Security",                                                           4720, s_Fields_4720, _countof(s_Fields_4720) },
    { L"用户入组", L"Security",                                                           4732, s_Fields_4732, _countof(s_Fields_4732) },
    { L"特权登录", L"Security",                                                           4672, s_Fields_4672, _countof(s_Fields_4672) },
    { L"共享访问", L"Security",                                                           5140, s_Fields_5140, _countof(s_Fields_5140) },
    { L"网络连接", L"Security",                                                           5156, s_Fields_5156, _countof(s_Fields_5156) },
    { L"服务安装", L"System",                                                             7045, s_Fields_7045, _countof(s_Fields_7045) },
    { L"计划任务", L"Security",                                                           4698, s_Fields_4698, _countof(s_Fields_4698) },
    { L"PS4104",   L"Microsoft-Windows-PowerShell/Operational",                           4104, s_Fields_4104, _countof(s_Fields_4104) },
    { L"PS400",    L"Windows PowerShell",                                                 400,  s_Fields_400,  _countof(s_Fields_400)  },
    { L"日志清除", L"Security",                                                           1102, s_Fields_1102, _countof(s_Fields_1102) },
    { L"RDP登录",  L"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 21,   s_Fields_21,
     _countof(s_Fields_21)                                                                                                             },
    { L"RDP出站",  L"Microsoft-Windows-TerminalServices-RDPClient/Operational",           1024, s_Fields_1024,
     _countof(s_Fields_1024)                                                                                                           },
    { L"进程创建", L"Security",                                                           4688, s_Fields_4688, _countof(s_Fields_4688) },
    { L"杀软检出", L"Microsoft-Windows-Windows Defender/Operational",                     1116, s_Fields_1116, _countof(s_Fields_1116) },
};

const int EventInvestigator::s_EventConfigCount = _countof(s_EventConfigs);

EventInvestigator::EventInvestigator()
    : m_currentIndex(0), m_hCategoryList(NULL), m_hComboTime(NULL), m_hDtpStart(NULL), m_hDtpEnd(NULL),
      m_hComboLimit(NULL), m_hBtnQuery(NULL), m_hBtnPath(NULL), m_hBtnEventVwr(NULL), m_hEditFilter(NULL),
      m_hEventListView(NULL), m_hMainListView(NULL), m_hMainWnd(NULL), m_hInst(NULL), m_categoryWidth(120),
      m_toolbarHeight(38), m_lastError(0), m_statusCallback(NULL) {
    memset(&m_clientRect, 0, sizeof(m_clientRect));
}

EventInvestigator::~EventInvestigator() {
    DestroyToolbar();
}

void EventInvestigator::SetListView(HWND hListView) {
    m_hMainListView = hListView;
}

// 工具栏创建

void EventInvestigator::CreateToolbar(HWND hParent, HINSTANCE hInst) {
    m_hMainWnd = hParent;
    m_hInst = hInst;

    CreateCategoryList();
    CreateFilterToolbar();
    CreateEventListView();
    UpdateTimeRange();
    ShowToolbar(false);
}

// 记住上次选择的分类
static int s_lastCategoryIndex = 0;

void EventInvestigator::CreateCategoryList() {
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    m_hCategoryList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL,
                                      WS_CHILD | WS_VISIBLE | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT | WS_VSCROLL, 0, 0,
                                      m_categoryWidth, 300, m_hMainWnd, (HMENU)IDC_EVT_CATEGORY_LIST, m_hInst, NULL);
    SendMessage(m_hCategoryList, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 添加事件类型
    for (int i = 0; i < s_EventConfigCount; i++) {
        SendMessage(m_hCategoryList, LB_ADDSTRING, 0, (LPARAM)s_EventConfigs[i].name);
    }

    // 恢复上次选择的分类
    m_currentIndex = s_lastCategoryIndex;
    SendMessage(m_hCategoryList, LB_SETCURSEL, m_currentIndex, 0);
}

void EventInvestigator::CreateFilterToolbar() {
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    // 时间快捷
    m_hComboTime = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 0, 0,
                                   80, 200, m_hMainWnd, (HMENU)IDC_EVT_COMBO_TIME, m_hInst, NULL);
    SendMessage(m_hComboTime, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboTime, CB_ADDSTRING, 0, (LPARAM)L"4小时");
    SendMessage(m_hComboTime, CB_ADDSTRING, 0, (LPARAM)L"1天");
    SendMessage(m_hComboTime, CB_ADDSTRING, 0, (LPARAM)L"7天");
    SendMessage(m_hComboTime, CB_ADDSTRING, 0, (LPARAM)L"15天");
    SendMessage(m_hComboTime, CB_ADDSTRING, 0, (LPARAM)L"1个月");
    SendMessage(m_hComboTime, CB_ADDSTRING, 0, (LPARAM)L"3个月");
    SendMessage(m_hComboTime, CB_ADDSTRING, 0, (LPARAM)L"半年");
    SendMessage(m_hComboTime, CB_SETCURSEL, 2, 0); // 默认7天

    // 开始时间
    m_hDtpStart = CreateWindowExW(0, DATETIMEPICK_CLASS, NULL, WS_CHILD | WS_VISIBLE | DTS_SHORTDATECENTURYFORMAT, 0, 0,
                                  165, 26, m_hMainWnd, (HMENU)IDC_EVT_DTP_START, m_hInst, NULL);
    SendMessage(m_hDtpStart, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hDtpStart, DTM_SETFORMAT, 0, (LPARAM)L"yyyy-MM-dd HH:mm");

    // 结束时间
    m_hDtpEnd = CreateWindowExW(0, DATETIMEPICK_CLASS, NULL, WS_CHILD | WS_VISIBLE | DTS_SHORTDATECENTURYFORMAT, 0, 0,
                                165, 26, m_hMainWnd, (HMENU)IDC_EVT_DTP_END, m_hInst, NULL);
    SendMessage(m_hDtpEnd, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hDtpEnd, DTM_SETFORMAT, 0, (LPARAM)L"yyyy-MM-dd HH:mm");

    // 上限
    m_hComboLimit = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 0, 0,
                                    70, 200, m_hMainWnd, (HMENU)IDC_EVT_COMBO_LIMIT, m_hInst, NULL);
    SendMessage(m_hComboLimit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboLimit, CB_ADDSTRING, 0, (LPARAM)L"200");
    SendMessage(m_hComboLimit, CB_ADDSTRING, 0, (LPARAM)L"500");
    SendMessage(m_hComboLimit, CB_ADDSTRING, 0, (LPARAM)L"1000");
    SendMessage(m_hComboLimit, CB_ADDSTRING, 0, (LPARAM)L"2000");
    SendMessage(m_hComboLimit, CB_SETCURSEL, 1, 0);

    // 查询按钮
    m_hBtnQuery = CreateWindowExW(0, L"BUTTON", L"查询", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 60, 26,
                                  m_hMainWnd, (HMENU)IDC_EVT_BTN_QUERY, m_hInst, NULL);
    SendMessage(m_hBtnQuery, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 路径按钮
    m_hBtnPath = CreateWindowExW(0, L"BUTTON", L"路径", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 60, 26, m_hMainWnd,
                                 (HMENU)IDC_EVT_BTN_PATH, m_hInst, NULL);
    SendMessage(m_hBtnPath, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 事件管理器按钮
    m_hBtnEventVwr = CreateWindowExW(0, L"BUTTON", L"事件管理器", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 95, 26,
                                     m_hMainWnd, (HMENU)IDC_EVT_BTN_EVENTVWR, m_hInst, NULL);
    SendMessage(m_hBtnEventVwr, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 过滤框（实时过滤）
    m_hEditFilter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 180,
                                    26, m_hMainWnd, (HMENU)IDC_EVT_EDIT_FILTER, m_hInst, NULL);
    SendMessage(m_hEditFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hEditFilter, EM_SETCUEBANNER, TRUE, (LPARAM)L"过滤...");
}

void EventInvestigator::CreateEventListView() {
    m_hEventListView =
        CreateWindowExW(0, WC_LISTVIEW, NULL, WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, 0,
                        0, 400, 300, m_hMainWnd, (HMENU)IDC_EVT_LISTVIEW, m_hInst, NULL);

    ListView_SetExtendedListViewStyle(m_hEventListView, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

    // 子类化主窗口以拦截 WM_NOTIFY 消息
    SetWindowSubclass(m_hMainWnd, SubclassProc, IDC_EVT_LISTVIEW, (DWORD_PTR)this);

    UpdateColumns();
}

void EventInvestigator::DestroyToolbar() {
    // 移除窗口子类化
    if (m_hMainWnd) {
        RemoveWindowSubclass(m_hMainWnd, SubclassProc, IDC_EVT_LISTVIEW);
    }

    if (m_hCategoryList) {
        DestroyWindow(m_hCategoryList);
        m_hCategoryList = NULL;
    }
    if (m_hComboTime) {
        DestroyWindow(m_hComboTime);
        m_hComboTime = NULL;
    }
    if (m_hDtpStart) {
        DestroyWindow(m_hDtpStart);
        m_hDtpStart = NULL;
    }
    if (m_hDtpEnd) {
        DestroyWindow(m_hDtpEnd);
        m_hDtpEnd = NULL;
    }
    if (m_hComboLimit) {
        DestroyWindow(m_hComboLimit);
        m_hComboLimit = NULL;
    }
    if (m_hBtnQuery) {
        DestroyWindow(m_hBtnQuery);
        m_hBtnQuery = NULL;
    }
    if (m_hBtnPath) {
        DestroyWindow(m_hBtnPath);
        m_hBtnPath = NULL;
    }
    if (m_hBtnEventVwr) {
        DestroyWindow(m_hBtnEventVwr);
        m_hBtnEventVwr = NULL;
    }
    if (m_hEditFilter) {
        DestroyWindow(m_hEditFilter);
        m_hEditFilter = NULL;
    }
    if (m_hEventListView) {
        DestroyWindow(m_hEventListView);
        m_hEventListView = NULL;
    }
}

void EventInvestigator::ShowToolbar(bool show) {
    int cmd = show ? SW_SHOW : SW_HIDE;
    if (m_hCategoryList)
        ShowWindow(m_hCategoryList, cmd);
    if (m_hComboTime)
        ShowWindow(m_hComboTime, cmd);
    if (m_hDtpStart)
        ShowWindow(m_hDtpStart, cmd);
    if (m_hDtpEnd)
        ShowWindow(m_hDtpEnd, cmd);
    if (m_hComboLimit)
        ShowWindow(m_hComboLimit, cmd);
    if (m_hBtnQuery)
        ShowWindow(m_hBtnQuery, cmd);
    if (m_hBtnPath)
        ShowWindow(m_hBtnPath, cmd);
    if (m_hBtnEventVwr)
        ShowWindow(m_hBtnEventVwr, cmd);
    if (m_hEditFilter)
        ShowWindow(m_hEditFilter, cmd);
    if (m_hEventListView)
        ShowWindow(m_hEventListView, cmd);
    if (m_hMainListView)
        ShowWindow(m_hMainListView, show ? SW_HIDE : SW_SHOW);
}

void EventInvestigator::ResizeToolbar(int x, int y, int width) {
    m_clientRect.left = x;
    m_clientRect.top = y;
    m_clientRect.right = x + width;

    RECT rcMain;
    GetClientRect(m_hMainWnd, &rcMain);
    int statusHeight = 22;
    HWND hStatusBar = FindWindowExW(m_hMainWnd, NULL, STATUSCLASSNAMEW, NULL);
    RECT rcStatus = {};
    if (hStatusBar && GetWindowRect(hStatusBar, &rcStatus)) {
        statusHeight = rcStatus.bottom - rcStatus.top;
    }
    m_clientRect.bottom = rcMain.bottom - statusHeight;

    UpdateLayout();
}

void EventInvestigator::UpdateLayout() {
    int x = m_clientRect.left;
    int y = m_clientRect.top;
    int width = m_clientRect.right - m_clientRect.left;
    int height = m_clientRect.bottom - m_clientRect.top;
    if (width <= 0 || height <= 0)
        return;

    UINT dpi = GetDpiForWindow(m_hMainWnd);
    if (dpi == 0)
        dpi = 96;
    auto scale = [dpi](int value) {
        return MulDiv(value, static_cast<int>(dpi), 96);
    };

    int categoryWidth = scale(m_categoryWidth);
    int toolbarHeight = scale(m_toolbarHeight);
    int controlHeight = scale(26);

    // 左侧分类
    if (m_hCategoryList) {
        SetWindowPos(m_hCategoryList, NULL, x, y, categoryWidth, height, SWP_NOZORDER);
    }

    // 右侧区域
    int gap = scale(4);
    int rightX = x + categoryWidth + gap;
    int rightWidth = width - categoryWidth - gap;
    int toolbarY = y + (toolbarHeight - controlHeight) / 2;
    int posX = rightX;

    int smallGap = scale(6);
    if (m_hComboTime) {
        SetWindowPos(m_hComboTime, NULL, posX, toolbarY, scale(80), scale(200), SWP_NOZORDER);
        posX += scale(80) + smallGap;
    }
    if (m_hDtpStart) {
        SetWindowPos(m_hDtpStart, NULL, posX, toolbarY, scale(165), controlHeight, SWP_NOZORDER);
        posX += scale(165) + smallGap;
    }
    if (m_hDtpEnd) {
        SetWindowPos(m_hDtpEnd, NULL, posX, toolbarY, scale(165), controlHeight, SWP_NOZORDER);
        posX += scale(165) + scale(8);
    }
    if (m_hComboLimit) {
        SetWindowPos(m_hComboLimit, NULL, posX, toolbarY, scale(70), scale(200), SWP_NOZORDER);
        posX += scale(70) + smallGap;
    }
    if (m_hBtnQuery) {
        SetWindowPos(m_hBtnQuery, NULL, posX, toolbarY, scale(60), controlHeight, SWP_NOZORDER);
        posX += scale(60) + smallGap;
    }
    if (m_hBtnPath) {
        SetWindowPos(m_hBtnPath, NULL, posX, toolbarY, scale(60), controlHeight, SWP_NOZORDER);
        posX += scale(60) + smallGap;
    }
    if (m_hBtnEventVwr) {
        SetWindowPos(m_hBtnEventVwr, NULL, posX, toolbarY, scale(95), controlHeight, SWP_NOZORDER);
        posX += scale(95) + scale(8);
    }
    if (m_hEditFilter) {
        SetWindowPos(m_hEditFilter, NULL, posX, toolbarY, scale(180), controlHeight, SWP_NOZORDER);
    }

    // 列表控件。
    int listY = y + toolbarHeight;
    int listH = height - toolbarHeight;
    if (m_hEventListView) {
        SetWindowPos(m_hEventListView, NULL, rightX, listY, rightWidth, listH, SWP_NOZORDER);
    }
}

// 命令处理

bool EventInvestigator::HandleToolbarCommand(WORD id, WORD code) {
    switch (id) {
    case IDC_EVT_CATEGORY_LIST:
        if (code == LBN_SELCHANGE) {
            OnCategoryChanged();
            return true;
        }
        break;
    case IDC_EVT_COMBO_TIME:
        if (code == CBN_SELCHANGE) {
            UpdateTimeRange();
            return true;
        }
        break;
    case IDC_EVT_BTN_QUERY:
        DoQuery();
        if (m_hEventListView)
            SetFocus(m_hEventListView);
        return true;
    case IDC_EVT_BTN_PATH:
        // 打开事件日志文件路径
        ShellExecuteW(NULL, L"open", L"C:\\Windows\\System32\\winevt\\Logs", NULL, NULL, SW_SHOWNORMAL);
        return true;
    case IDC_EVT_BTN_EVENTVWR:
        // 打开事件查看器
        ShellExecuteW(NULL, L"open", L"eventvwr.msc", NULL, NULL, SW_SHOWNORMAL);
        return true;
    case IDC_EVT_EDIT_FILTER:
        if (code == EN_CHANGE) {
            // 实时过滤
            ApplyFilter();
            UpdateListView();
            return true;
        }
        break;
    }
    return false;
}

void EventInvestigator::OnCategoryChanged() {
    int sel = (int)SendMessage(m_hCategoryList, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= s_EventConfigCount)
        return;

    m_currentIndex = sel;
    s_lastCategoryIndex = sel; // 记住选择
    m_records.clear();
    m_filtered.clear();
    m_lastError = 0;
    UpdateColumns();
    UpdateListView();

    // 状态栏提示
    const EventConfig& config = s_EventConfigs[m_currentIndex];
    UpdateStatus(L"已选择：%s (事件ID: %d)", config.name, config.eventId);
}

void EventInvestigator::UpdateColumns() {
    if (!m_hEventListView)
        return;

    const EventConfig& config = s_EventConfigs[m_currentIndex];

    SendMessage(m_hEventListView, WM_SETREDRAW, FALSE, 0);
    while (ListView_DeleteColumn(m_hEventListView, 0))
        ;

    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;

    UINT dpi = GetDpiForWindow(m_hMainWnd);
    if (dpi == 0)
        dpi = 96;

    // 第一列：时间
    lvc.iSubItem = 0;
    lvc.pszText = (LPWSTR)L"时间";
    lvc.cx = MulDiv(155, static_cast<int>(dpi), 96);
    ListView_InsertColumn(m_hEventListView, 0, &lvc);

    // 动态字段列
    for (int i = 0; i < config.fieldCount; i++) {
        lvc.iSubItem = i + 1;
        lvc.pszText = (LPWSTR)config.fields[i].displayName;
        lvc.cx = MulDiv(config.fields[i].width, static_cast<int>(dpi), 96);
        ListView_InsertColumn(m_hEventListView, i + 1, &lvc);
    }

    SendMessage(m_hEventListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(m_hEventListView, NULL, TRUE);
}

// 查询

void EventInvestigator::DoQuery() {
    // 显示等待光标
    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));

    m_records.clear();
    m_filtered.clear();
    m_lastError = 0;

    UpdateStatus(L"正在采集...");
    QueryEvents();
    ApplyFilter();
    UpdateListView();

    // 恢复光标
    SetCursor(hOldCursor);

    // 结果反馈
    const EventConfig& config = s_EventConfigs[m_currentIndex];
    if (m_lastError != ERROR_SUCCESS && !m_records.empty()) {
        UpdateStatus(L"事件已采集：共 %d 条 %s 事件，部分读取失败（错误码 %lu）", (int)m_records.size(), config.name,
                     m_lastError);
    } else if (m_lastError == ERROR_ACCESS_DENIED) {
        UpdateStatus(L"查询失败：权限不足，请以管理员身份运行");
    } else if (m_lastError == ERROR_EVT_CHANNEL_NOT_FOUND) {
        UpdateStatus(L"查询失败：日志通道不存在 (%s)", config.channel);
    } else if (m_lastError != 0) {
        UpdateStatus(L"查询失败：错误码 %d", m_lastError);
    } else if (m_records.empty()) {
        UpdateStatus(L"事件已采集：未找到 %s 事件", config.name);
    } else {
        UpdateStatus(L"事件已采集：共 %d 条 %s 事件", (int)m_records.size(), config.name);
    }
}

void EventInvestigator::QueryEvents() {
    const EventConfig& config = s_EventConfigs[m_currentIndex];

    // 获取上限
    int limitSel = (int)SendMessage(m_hComboLimit, CB_GETCURSEL, 0, 0);
    int maxCount = 500;
    switch (limitSel) {
    case 0:
        maxCount = 200;
        break;
    case 1:
        maxCount = 500;
        break;
    case 2:
        maxCount = 1000;
        break;
    case 3:
        maxCount = 2000;
        break;
    }

    // 构建XPath查询
    std::wstring query = BuildXPathQuery();

    // 打开事件日志
    EVT_HANDLE hResults = EvtQuery(NULL, config.channel, query.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);

    if (!hResults) {
        m_lastError = GetLastError();
        return;
    }

    // 保留首个真实读取错误；正常枚举结束不能覆盖之前的失败。
    const auto rememberError = [this](DWORD error) {
        if (m_lastError == ERROR_SUCCESS)
            m_lastError = error ? error : ERROR_READ_FAULT;
    };
    EVT_HANDLE hEvents[100] = {};
    DWORD dwReturned = 0;
    int count = 0;

    while (count < maxCount) {
        const DWORD toFetch = (std::min)(DWORD{ 100 }, static_cast<DWORD>(maxCount - count));
        if (!EvtNext(hResults, toFetch, hEvents, INFINITE, 0, &dwReturned)) {
            const DWORD error = GetLastError();
            if (error != ERROR_NO_MORE_ITEMS)
                rememberError(error);
            break;
        }

        for (DWORD i = 0; i < dwReturned; ++i) {
            DWORD dwBufferUsed = 0, dwPropertyCount = 0;
            const BOOL probed =
                EvtRender(NULL, hEvents[i], EvtRenderEventXml, 0, NULL, &dwBufferUsed, &dwPropertyCount);
            const DWORD probeError = probed ? ERROR_SUCCESS : GetLastError();
            if ((probed || probeError == ERROR_INSUFFICIENT_BUFFER) && dwBufferUsed >= sizeof(wchar_t)) {
                std::vector<wchar_t> buffer(dwBufferUsed / sizeof(wchar_t) + 1);
                if (EvtRender(NULL, hEvents[i], EvtRenderEventXml, dwBufferUsed, buffer.data(), &dwBufferUsed,
                              &dwPropertyCount)) {
                    ParseEventXml(buffer.data());
                    ++count;
                } else {
                    rememberError(GetLastError());
                }
            } else {
                rememberError(probeError == ERROR_SUCCESS || probeError == ERROR_INSUFFICIENT_BUFFER
                                  ? ERROR_INVALID_DATA
                                  : probeError);
            }
            EvtClose(hEvents[i]);
        }
    }
    EvtClose(hResults);
}

std::wstring EventInvestigator::BuildXPathQuery() {
    const EventConfig& config = s_EventConfigs[m_currentIndex];

    // 获取时间范围
    SYSTEMTIME stStart, stEnd, stStartUtc, stEndUtc;
    SendMessage(m_hDtpStart, DTM_GETSYSTEMTIME, 0, (LPARAM)&stStart);
    SendMessage(m_hDtpEnd, DTM_GETSYSTEMTIME, 0, (LPARAM)&stEnd);

    TzSpecificLocalTimeToSystemTime(NULL, &stStart, &stStartUtc);
    TzSpecificLocalTimeToSystemTime(NULL, &stEnd, &stEndUtc);

    wchar_t szStart[64], szEnd[64];
    swprintf_s(szStart, L"%04d-%02d-%02dT%02d:%02d:%02d.000Z", stStartUtc.wYear, stStartUtc.wMonth, stStartUtc.wDay,
               stStartUtc.wHour, stStartUtc.wMinute, stStartUtc.wSecond);
    swprintf_s(szEnd, L"%04d-%02d-%02dT%02d:%02d:%02d.999Z", stEndUtc.wYear, stEndUtc.wMonth, stEndUtc.wDay,
               stEndUtc.wHour, stEndUtc.wMinute, stEndUtc.wSecond);

    // 构建查询
    wchar_t query[768];
    if (config.eventId == 4624) {
        swprintf_s(
            query,
            L"*[System[EventID=%d and TimeCreated[@SystemTime>='%s' and @SystemTime<='%s']] and EventData[Data[@Name='LogonType']!='5']]",
            config.eventId, szStart, szEnd);
    } else {
        swprintf_s(query, L"*[System[EventID=%d and TimeCreated[@SystemTime>='%s' and @SystemTime<='%s']]]",
                   config.eventId, szStart, szEnd);
    }

    return query;
}

// XML解析（自动映射）

void EventInvestigator::ParseEventXml(const wchar_t* xml) {
    const EventConfig& config = s_EventConfigs[m_currentIndex];
    std::wstring xmlStr(xml);

    EventRecord record;
    record.timeCreated = FormatSystemTime(ExtractTimeCreated(xmlStr));
    record.eventId = config.eventId;

    // 按字段映射提取值
    for (int i = 0; i < config.fieldCount; i++) {
        std::wstring value = ExtractDataValue(xmlStr, config.fields[i].xmlName, config.fields[i].parentNode);
        value = ConvertFieldValue(value, config.fields[i].type);
        record.fieldValues.push_back(value);
    }

    m_records.push_back(record);
}

std::wstring EventInvestigator::ExtractTimeCreated(const std::wstring& xml) {
    // 查找 <TimeCreated SystemTime='...'/>
    size_t pos = xml.find(L"<TimeCreated");
    if (pos == std::wstring::npos)
        return L"";

    size_t attrPos = xml.find(L"SystemTime='", pos);
    if (attrPos == std::wstring::npos) {
        attrPos = xml.find(L"SystemTime=\"", pos);
    }
    if (attrPos == std::wstring::npos)
        return L"";

    size_t valueStart = attrPos + 12;
    size_t valueEnd = xml.find_first_of(L"'\"", valueStart);
    if (valueEnd == std::wstring::npos)
        return L"";

    return xml.substr(valueStart, valueEnd - valueStart);
}

std::wstring EventInvestigator::ExtractDataValue(const std::wstring& xml, const std::wstring& name,
                                                 const wchar_t* parentNode) {
    // __KV__:Key[:TruncateAt]：从指定节点的内容中提取 Key=Value 格式的值
    // parentNode 格式为 "__KV__:KeyName" 或 "__KV__:KeyName:TruncateAt"
    // xmlName 为节点标签名
    if (parentNode != nullptr && std::wstring(parentNode).substr(0, 6) == L"__KV__") {
        std::wstring kvParam = std::wstring(parentNode).substr(7); // 取 "__KV__:" 后面的部分

        // 解析 Key 和可选的 TruncateAt
        std::wstring kvKey;
        std::wstring truncateAt;
        size_t colonPos = kvParam.find(L':');
        if (colonPos != std::wstring::npos) {
            kvKey = kvParam.substr(0, colonPos);
            truncateAt = kvParam.substr(colonPos + 1);
        } else {
            kvKey = kvParam;
        }

        // 遍历所有匹配的 <nodeName>...</nodeName>，找到包含 Key= 的那个
        std::wstring startTag = L"<" + name + L">";
        std::wstring endTag = L"</" + name + L">";
        std::wstring searchKey = kvKey + L"=";

        size_t pos = 0;
        while ((pos = xml.find(startTag, pos)) != std::wstring::npos) {
            pos += startTag.length();
            size_t endPos = xml.find(endTag, pos);
            if (endPos == std::wstring::npos)
                break;

            std::wstring content = xml.substr(pos, endPos - pos);

            size_t keyPos = content.find(searchKey);
            if (keyPos != std::wstring::npos) {
                size_t valueStart = keyPos + searchKey.length();
                size_t valueEnd = content.length();

                // 优先使用指定的截断字符串
                if (!truncateAt.empty()) {
                    size_t truncPos = content.find(truncateAt, valueStart);
                    if (truncPos != std::wstring::npos) {
                        // 截断点前去掉尾部空格
                        valueEnd = truncPos;
                        while (valueEnd > valueStart && content[valueEnd - 1] == L' ') {
                            valueEnd--;
                        }
                    }
                } else {
                    // 回退到启发式截断：空格后的单词本身包含 =
                    for (size_t i = valueStart; i + 1 < content.length(); i++) {
                        if (content[i] == L' ' && iswupper(content[i + 1])) {
                            size_t wordEnd = content.find(L' ', i + 1);
                            size_t eqInWord = content.find(L'=', i + 1);
                            if (eqInWord != std::wstring::npos &&
                                (wordEnd == std::wstring::npos || eqInWord < wordEnd)) {
                                valueEnd = i;
                                break;
                            }
                        }
                    }
                }

                return content.substr(valueStart, valueEnd - valueStart);
            }

            pos = endPos + endTag.length();
        }
        return L"";
    }

    // 确定搜索范围
    size_t searchStart = 0;
    size_t searchEnd = xml.length();

    if (parentNode != nullptr) {
        // 指定了父节点，在该节点范围内搜索
        std::wstring parentStart = L"<" + std::wstring(parentNode) + L">";
        std::wstring parentEnd = L"</" + std::wstring(parentNode) + L">";

        size_t parentPos = xml.find(parentStart);
        if (parentPos != std::wstring::npos) {
            searchStart = parentPos;
            size_t endPos = xml.find(parentEnd, searchStart);
            if (endPos != std::wstring::npos) {
                searchEnd = endPos;
            }
        }

        // 在父节点范围内查找 <TagName>value</TagName> 格式
        std::wstring startTag = L"<" + name + L">";
        std::wstring endTag = L"</" + name + L">";

        size_t pos = xml.find(startTag, searchStart);
        if (pos != std::wstring::npos && pos < searchEnd) {
            pos += startTag.length();
            size_t endPos = xml.find(endTag, pos);
            if (endPos != std::wstring::npos && endPos <= searchEnd) {
                return xml.substr(pos, endPos - pos);
            }
        }
        return L"";
    }

    // 默认：查找 <Data Name='xxx'>value</Data> (标准EventData格式)
    std::wstring search1 = L"<Data Name='" + name + L"'>";
    std::wstring search2 = L"<Data Name=\"" + name + L"\">";

    size_t pos = xml.find(search1);
    if (pos != std::wstring::npos) {
        pos += search1.length();
        size_t endPos = xml.find(L"</Data>", pos);
        if (endPos != std::wstring::npos) {
            return xml.substr(pos, endPos - pos);
        }
    }

    pos = xml.find(search2);
    if (pos != std::wstring::npos) {
        pos += search2.length();
        size_t endPos = xml.find(L"</Data>", pos);
        if (endPos != std::wstring::npos) {
            return xml.substr(pos, endPos - pos);
        }
    }

    return L"";
}

std::wstring EventInvestigator::ConvertFieldValue(const std::wstring& value, FieldType type) {
    if (value.empty())
        return value;

    switch (type) {
    case FieldType::LogonType: {
        int t = _wtoi(value.c_str());
        switch (t) {
        case 2:
            return L"交互式";
        case 3:
            return L"网络";
        case 4:
            return L"批处理";
        case 5:
            return L"服务";
        case 7:
            return L"解锁";
        case 8:
            return L"明文";
        case 9:
            return L"新凭据";
        case 10:
            return L"RDP";
        case 11:
            return L"缓存";
        default:
            return value;
        }
    }

    case FieldType::HexToInt: {
        if (value.length() > 2 && value.substr(0, 2) == L"0x") {
            unsigned long v = wcstoul(value.c_str(), nullptr, 16);
            return std::to_wstring(v);
        }
        return value;
    }

    case FieldType::FilePath: {
        size_t pos = value.rfind(L'\\');
        return (pos != std::wstring::npos) ? value.substr(pos + 1) : value;
    }

    case FieldType::EmptyDash:
        return (value == L"-") ? L"" : value;

    case FieldType::StartType: {
        if (value == L"auto start")
            return L"自动";
        if (value == L"demand start")
            return L"手动";
        if (value == L"disabled")
            return L"禁用";
        if (value == L"boot start")
            return L"引导";
        if (value == L"system start")
            return L"系统";
        return value;
    }

    case FieldType::EngineData:
        return value; // 已在 ExtractDataValue 中提取完毕

    default:
        return value;
    }
}

std::wstring EventInvestigator::FormatSystemTime(const std::wstring& utcTime) {
    if (utcTime.length() < 19)
        return utcTime;

    SYSTEMTIME stUtc = { 0 }, stLocal = { 0 };
    swscanf_s(utcTime.c_str(), L"%hd-%hd-%hdT%hd:%hd:%hd", &stUtc.wYear, &stUtc.wMonth, &stUtc.wDay, &stUtc.wHour,
              &stUtc.wMinute, &stUtc.wSecond);

    SystemTimeToTzSpecificLocalTime(NULL, &stUtc, &stLocal);

    wchar_t buffer[32];
    swprintf_s(buffer, L"%04d-%02d-%02d %02d:%02d:%02d", stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour,
               stLocal.wMinute, stLocal.wSecond);

    return buffer;
}

// 显示和过滤

void EventInvestigator::UpdateListView() {
    if (!m_hEventListView)
        return;

    SendMessage(m_hEventListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(m_hEventListView);

    const auto& data = m_filtered;

    for (size_t i = 0; i < data.size(); i++) {
        const EventRecord& rec = data[i];

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.pszText = (LPWSTR)rec.timeCreated.c_str();
        ListView_InsertItem(m_hEventListView, &lvi);

        for (size_t j = 0; j < rec.fieldValues.size(); j++) {
            ListView_SetItemText(m_hEventListView, (int)i, (int)(j + 1), (LPWSTR)rec.fieldValues[j].c_str());
        }
    }

    SendMessage(m_hEventListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(m_hEventListView, NULL, TRUE);
}

void EventInvestigator::ApplyFilter() {
    m_filtered.clear();

    wchar_t filterText[256] = { 0 };
    if (m_hEditFilter)
        GetWindowTextW(m_hEditFilter, filterText, 256);

    std::wstring filter = CommonUtils::ToLower(filterText);
    if (filter.empty()) {
        m_filtered = m_records;
    } else {
        for (const auto& rec : m_records) {
            bool match = false;
            if (CommonUtils::ToLower(rec.timeCreated).find(filter) != std::wstring::npos)
                match = true;

            for (const auto& val : rec.fieldValues) {
                if (CommonUtils::ToLower(val).find(filter) != std::wstring::npos) {
                    match = true;
                    break;
                }
            }

            if (match)
                m_filtered.push_back(rec);
        }
    }

    // 过滤结果反馈（仅当有数据时）
    if (!m_records.empty()) {
        if (filter.empty()) {
            UpdateStatus(L"显示全部：%d 条记录", (int)m_filtered.size());
        } else {
            UpdateStatus(L"过滤结果：%d / %d 条", (int)m_filtered.size(), (int)m_records.size());
        }
    }
}

// 状态输出

void EventInvestigator::UpdateStatus(const wchar_t* format, ...) {
    if (!m_statusCallback)
        return;

    wchar_t buffer[512];
    va_list args;
    va_start(args, format);
    vswprintf_s(buffer, format, args);
    va_end(args);

    m_statusCallback(buffer);
}

// 时间范围

void EventInvestigator::UpdateTimeRange() {
    if (!m_hComboTime || !m_hDtpStart || !m_hDtpEnd)
        return;

    int sel = (int)SendMessage(m_hComboTime, CB_GETCURSEL, 0, 0);
    if (sel < 0)
        return;

    SYSTEMTIME stNow, stStart;
    GetLocalTime(&stNow);
    stStart = stNow;

    // 计算时间偏移（小时）
    int hours[] = { 4, 24, 24 * 7, 24 * 15, 24 * 30, 24 * 90, 24 * 180 };
    int offsetHours = hours[sel];

    FILETIME ft;
    SystemTimeToFileTime(&stStart, &ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    uli.QuadPart -= (ULONGLONG)offsetHours * 60 * 60 * 10000000;
    ft.dwLowDateTime = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;
    FileTimeToSystemTime(&ft, &stStart);

    SendMessage(m_hDtpStart, DTM_SETSYSTEMTIME, GDT_VALID, (LPARAM)&stStart);
    SendMessage(m_hDtpEnd, DTM_SETSYSTEMTIME, GDT_VALID, (LPARAM)&stNow);
}

// 窗口子类化 - 处理右键菜单

LRESULT CALLBACK EventInvestigator::SubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam,
                                                 UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    EventInvestigator* pThis = (EventInvestigator*)dwRefData;

    if (uMsg == WM_NOTIFY && pThis) {
        LPNMHDR pnmh = (LPNMHDR)lParam;

        // 检查是否是事件 ListView 的右键点击
        if (pnmh->hwndFrom == pThis->m_hEventListView && pnmh->code == NM_RCLICK) {
            LPNMITEMACTIVATE pnmia = (LPNMITEMACTIVATE)lParam;
            pThis->HandleListViewRightClick(pnmia);
            return 0;
        }
    }

    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

void EventInvestigator::HandleListViewRightClick(LPNMITEMACTIVATE pnmia) {
    int row = pnmia->iItem;
    m_contextColumn = pnmia->iSubItem;

    auto menuItems = GetContextMenuItems(row);
    if (menuItems.empty()) {
        return;
    }

    HMENU hMenu = CreatePopupMenu();
    for (const auto& item : menuItems) {
        if (item.id == 0) {
            // 分隔符
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
        } else {
            AppendMenuW(hMenu, MF_STRING, item.id, item.text.c_str());
        }
    }

    POINT pt;
    GetCursorPos(&pt);

    // 显示菜单并获取选择
    UINT cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, m_hMainWnd, NULL);

    DestroyMenu(hMenu);

    // 处理菜单命令
    if (cmd != 0) {
        HandleContextMenu(cmd, row);
    }
}

// 右键菜单

std::vector<ContextMenuItem> EventInvestigator::GetContextMenuItems(int row) const {
    std::vector<ContextMenuItem> items;
    if (row >= 0 && row < (int)m_filtered.size()) {
        items.push_back({ IDM_EVT_COPY_CELL, L"复制值", false, L"" });
        items.push_back({ IDM_EVT_COPY_ROW, L"复制行", false, L"" });
    }
    if (m_hEventListView && ListView_GetItemCount(m_hEventListView) > 0) {
        items.push_back({ IDM_EVT_COPY_ALL, L"复制全部", false, L"" });
    }
    return items;
}

bool EventInvestigator::HandleContextMenu(UINT menuId, int row) {
    if (menuId == IDM_EVT_COPY_ALL) {
        CommonUtils::CopyListViewAll(m_hMainWnd, m_hEventListView);
        return false;
    }
    if (row < 0 || row >= (int)m_filtered.size())
        return false;

    switch (menuId) {
    case IDM_EVT_COPY_CELL: {
        CommonUtils::CopyListViewCell(m_hMainWnd, m_hEventListView, row, m_contextColumn);
        return false;
    }

    case IDM_EVT_COPY_ROW: {
        CommonUtils::CopyListViewRow(m_hMainWnd, m_hEventListView, row);
        return false;
    }
    }
    return false;
}

// IInvestigator接口

InvestigationResult EventInvestigator::Investigate(bool resetFilter) {
    (void)resetFilter; // 事件模块通过独立界面查询，不使用主列表的重置参数。

    InvestigationResult result;
    result.moduleName = L"EventInvestigator";
    result.success = true;
    result.errorCode = 0;
    result.totalCount = 0;
    result.suspiciousCount = 0;
    return result;
}
