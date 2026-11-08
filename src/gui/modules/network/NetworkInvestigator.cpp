#include "../../presentation/GuiColumns.h"
#include "../../../core/system/IpLookupService.h"
// NetworkInvestigator.cpp - 网络连接排查模块实现

// winsock2.h 必须在 windows.h 之前包含
#ifndef _WINSOCK2API_
#include <winsock2.h>
#endif
#include <ws2tcpip.h>

#include "NetworkInvestigator.h"

#include "../../resources/resource.h"
#include <tlhelp32.h>
#include <sstream>
#include <algorithm>
#include <windowsx.h>

// 静态列定义
const ColumnDef NetworkInvestigator::s_Columns[] = { WG_COLUMNS_NETWORK };
const int NetworkInvestigator::s_ColumnCount = sizeof(s_Columns) / sizeof(s_Columns[0]);

struct NetworkInvestigator::IpLocationThreadParam {
    HWND hNotifyWnd;
    NetworkInvestigator* self;
    std::vector<std::wstring> ips;
};

static int GetNetworkComboContentWidth(HWND hCombo) {
    if (!hCombo)
        return 80;

    HDC hdc = GetDC(hCombo);
    if (!hdc)
        return 80;

    HFONT hFont = (HFONT)SendMessage(hCombo, WM_GETFONT, 0, 0);
    HGDIOBJ oldFont = hFont ? SelectObject(hdc, hFont) : NULL;
    int maxTextWidth = 0;
    int itemCount = (int)SendMessage(hCombo, CB_GETCOUNT, 0, 0);

    for (int i = 0; i < itemCount; ++i) {
        int length = (int)SendMessage(hCombo, CB_GETLBTEXTLEN, i, 0);
        if (length < 0)
            continue;

        std::vector<wchar_t> text((size_t)length + 1, L'\0');
        SendMessage(hCombo, CB_GETLBTEXT, i, (LPARAM)text.data());

        SIZE textSize = { 0 };
        if (GetTextExtentPoint32W(hdc, text.data(), length, &textSize)) {
            maxTextWidth = (std::max)(maxTextWidth, (int)textSize.cx);
        }
    }

    if (oldFont)
        SelectObject(hdc, oldFont);
    ReleaseDC(hCombo, hdc);

    int width = maxTextWidth + GetSystemMetrics(SM_CXVSCROLL) + 18;
    return (std::max)(width, 72);
}

NetworkInvestigator::NetworkInvestigator() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

NetworkInvestigator::~NetworkInvestigator() {
    m_cancelLocation = true;
    if (m_hLocationThread) {
        WaitForSingleObject(m_hLocationThread, INFINITE);
        CloseHandle(m_hLocationThread);
        m_hLocationThread = NULL;
    }
    DestroyToolbar();
    WSACleanup();
}

void NetworkInvestigator::CreateToolbar(HWND hParent, HINSTANCE hInst) {
    m_hInst = hInst;
    m_hMainWnd = hParent;

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    int baseY = 33;
    int x = 5;
    const DWORD comboStyle = WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL;

    m_hCmbProtocol = CreateWindowExW(0, L"COMBOBOX", NULL, comboStyle, x, baseY, 120, 230, hParent,
                                     (HMENU)IDC_NET_CMB_PROTOCOL, hInst, NULL);
    SendMessage(m_hCmbProtocol, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hCmbProtocol, CB_ADDSTRING, 0, (LPARAM)L"协议: 全部");
    SendMessage(m_hCmbProtocol, CB_ADDSTRING, 0, (LPARAM)L"TCP");
    SendMessage(m_hCmbProtocol, CB_ADDSTRING, 0, (LPARAM)L"UDP");
    SendMessage(m_hCmbProtocol, CB_ADDSTRING, 0, (LPARAM)L"TCP v4");
    SendMessage(m_hCmbProtocol, CB_ADDSTRING, 0, (LPARAM)L"TCP v6");
    SendMessage(m_hCmbProtocol, CB_ADDSTRING, 0, (LPARAM)L"UDP v4");
    SendMessage(m_hCmbProtocol, CB_ADDSTRING, 0, (LPARAM)L"UDP v6");
    SendMessage(m_hCmbProtocol, CB_SETCURSEL, 0, 0);
    int protocolWidth = GetNetworkComboContentWidth(m_hCmbProtocol);
    SetWindowPos(m_hCmbProtocol, NULL, x, baseY, protocolWidth, 230, SWP_NOZORDER);
    SendMessage(m_hCmbProtocol, CB_SETDROPPEDWIDTH, protocolWidth, 0);
    x += protocolWidth + 5;

    m_hCmbState = CreateWindowExW(0, L"COMBOBOX", NULL, comboStyle, x, baseY, 130, 210, hParent,
                                  (HMENU)IDC_NET_CMB_STATE, hInst, NULL);
    SendMessage(m_hCmbState, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hCmbState, CB_ADDSTRING, 0, (LPARAM)L"状态: 全部");
    SendMessage(m_hCmbState, CB_ADDSTRING, 0, (LPARAM)L"LISTENING");
    SendMessage(m_hCmbState, CB_ADDSTRING, 0, (LPARAM)L"ESTABLISHED");
    SendMessage(m_hCmbState, CB_ADDSTRING, 0, (LPARAM)L"TIME_WAIT");
    SendMessage(m_hCmbState, CB_ADDSTRING, 0, (LPARAM)L"其他");
    SendMessage(m_hCmbState, CB_SETCURSEL, 0, 0);
    int stateWidth = GetNetworkComboContentWidth(m_hCmbState);
    SetWindowPos(m_hCmbState, NULL, x, baseY, stateWidth, 210, SWP_NOZORDER);
    SendMessage(m_hCmbState, CB_SETDROPPEDWIDTH, stateWidth, 0);
    x += stateWidth + 5;

    m_hCmbScope = CreateWindowExW(0, L"COMBOBOX", NULL, comboStyle, x, baseY, 120, 180, hParent,
                                  (HMENU)IDC_NET_CMB_SCOPE, hInst, NULL);
    SendMessage(m_hCmbScope, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hCmbScope, CB_ADDSTRING, 0, (LPARAM)L"连接: 全部");
    SendMessage(m_hCmbScope, CB_ADDSTRING, 0, (LPARAM)L"外联");
    SendMessage(m_hCmbScope, CB_ADDSTRING, 0, (LPARAM)L"内网");
    SendMessage(m_hCmbScope, CB_ADDSTRING, 0, (LPARAM)L"本地监听");
    SendMessage(m_hCmbScope, CB_SETCURSEL, 1, 0);
    int scopeWidth = GetNetworkComboContentWidth(m_hCmbScope);
    SetWindowPos(m_hCmbScope, NULL, x, baseY, scopeWidth, 180, SWP_NOZORDER);
    SendMessage(m_hCmbScope, CB_SETDROPPEDWIDTH, scopeWidth, 0);
    x += scopeWidth + 5;

    // 刷新间隔标签和下拉框
    m_hStaticRefresh = CreateWindowExW(0, L"STATIC", L"刷新:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, x, baseY, 35, 22,
                                       hParent, NULL, hInst, NULL);
    SendMessage(m_hStaticRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 38;

    m_hCmbRefresh = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, x,
                                    baseY, 60, 150, hParent, (HMENU)IDC_NET_CMB_REFRESH, hInst, NULL);
    SendMessage(m_hCmbRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hCmbRefresh, CB_ADDSTRING, 0, (LPARAM)L"暂停");
    SendMessage(m_hCmbRefresh, CB_ADDSTRING, 0, (LPARAM)L"1 秒");
    SendMessage(m_hCmbRefresh, CB_ADDSTRING, 0, (LPARAM)L"2 秒");
    SendMessage(m_hCmbRefresh, CB_ADDSTRING, 0, (LPARAM)L"3 秒");
    SendMessage(m_hCmbRefresh, CB_ADDSTRING, 0, (LPARAM)L"5 秒");
    SendMessage(m_hCmbRefresh, CB_SETCURSEL, 0, 0);
    x += 65;

    // 手动刷新按钮
    m_hBtnRefresh = CreateWindowExW(0, L"BUTTON", L"刷新", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 50, 22,
                                    hParent, (HMENU)IDC_NET_BTN_REFRESH, hInst, NULL);
    SendMessage(m_hBtnRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 55;

    // IP 归属查询按钮，仅在手动操作时触发。
    m_hBtnIpLocation = CreateWindowExW(0, L"BUTTON", L"IP归属", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 65, 22,
                                       hParent, (HMENU)IDC_NET_BTN_IP_LOCATION, hInst, NULL);
    SendMessage(m_hBtnIpLocation, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 70;

    // 过滤标签和输入框
    m_hStaticFilter = CreateWindowExW(0, L"STATIC", L"过滤:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, x, baseY, 35, 22,
                                      hParent, NULL, hInst, NULL);
    SendMessage(m_hStaticFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 38;

    m_hEditFilter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, x, baseY,
                                    120, 22, hParent, (HMENU)IDC_NET_EDIT_FILTER, hInst, NULL);
    SendMessage(m_hEditFilter, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 初始隐藏所有控件
    ShowToolbar(false);
}

void NetworkInvestigator::DestroyToolbar() {
    StopRefreshTimer();
    if (m_hCmbProtocol) {
        DestroyWindow(m_hCmbProtocol);
        m_hCmbProtocol = NULL;
    }
    if (m_hCmbState) {
        DestroyWindow(m_hCmbState);
        m_hCmbState = NULL;
    }
    if (m_hCmbScope) {
        DestroyWindow(m_hCmbScope);
        m_hCmbScope = NULL;
    }
    if (m_hStaticRefresh) {
        DestroyWindow(m_hStaticRefresh);
        m_hStaticRefresh = NULL;
    }
    if (m_hCmbRefresh) {
        DestroyWindow(m_hCmbRefresh);
        m_hCmbRefresh = NULL;
    }
    if (m_hBtnRefresh) {
        DestroyWindow(m_hBtnRefresh);
        m_hBtnRefresh = NULL;
    }
    if (m_hBtnIpLocation) {
        DestroyWindow(m_hBtnIpLocation);
        m_hBtnIpLocation = NULL;
    }
    if (m_hStaticFilter) {
        DestroyWindow(m_hStaticFilter);
        m_hStaticFilter = NULL;
    }
    if (m_hEditFilter) {
        DestroyWindow(m_hEditFilter);
        m_hEditFilter = NULL;
    }
}

void NetworkInvestigator::ShowToolbar(bool show) {
    int cmd = show ? SW_SHOW : SW_HIDE;
    if (m_hCmbProtocol)
        ShowWindow(m_hCmbProtocol, cmd);
    if (m_hCmbState)
        ShowWindow(m_hCmbState, cmd);
    if (m_hCmbScope)
        ShowWindow(m_hCmbScope, cmd);
    if (m_hStaticRefresh)
        ShowWindow(m_hStaticRefresh, cmd);
    if (m_hCmbRefresh)
        ShowWindow(m_hCmbRefresh, cmd);
    if (m_hBtnRefresh)
        ShowWindow(m_hBtnRefresh, cmd);
    if (m_hBtnIpLocation)
        ShowWindow(m_hBtnIpLocation, cmd);
    if (m_hStaticFilter)
        ShowWindow(m_hStaticFilter, cmd);
    if (m_hEditFilter)
        ShowWindow(m_hEditFilter, cmd);

    // 显示工具栏不触发采集；进入标签页和刷新各使用一次快照。
    if (show)
        StartRefreshTimer();
    else
        StopRefreshTimer();
}

void NetworkInvestigator::ResizeToolbar(int x, int y, int width) {
    (void)x;
    (void)width;
    int baseY = y + 5;
    int posX = 5;

    if (m_hCmbProtocol) {
        int comboWidth = GetNetworkComboContentWidth(m_hCmbProtocol);
        SetWindowPos(m_hCmbProtocol, NULL, posX, baseY, comboWidth, 230, SWP_NOZORDER);
        posX += comboWidth + 5;
    }
    if (m_hCmbState) {
        int comboWidth = GetNetworkComboContentWidth(m_hCmbState);
        SetWindowPos(m_hCmbState, NULL, posX, baseY, comboWidth, 210, SWP_NOZORDER);
        posX += comboWidth + 5;
    }
    if (m_hCmbScope) {
        int comboWidth = GetNetworkComboContentWidth(m_hCmbScope);
        SetWindowPos(m_hCmbScope, NULL, posX, baseY, comboWidth, 180, SWP_NOZORDER);
        posX += comboWidth + 5;
    }

    if (m_hStaticRefresh) {
        SetWindowPos(m_hStaticRefresh, NULL, posX, baseY, 35, 22, SWP_NOZORDER);
        posX += 38;
    }
    if (m_hCmbRefresh) {
        SetWindowPos(m_hCmbRefresh, NULL, posX, baseY, 60, 150, SWP_NOZORDER);
        posX += 65;
    }
    if (m_hBtnRefresh) {
        SetWindowPos(m_hBtnRefresh, NULL, posX, baseY, 50, 22, SWP_NOZORDER);
        posX += 55;
    }
    if (m_hBtnIpLocation) {
        SetWindowPos(m_hBtnIpLocation, NULL, posX, baseY, 65, 22, SWP_NOZORDER);
        posX += 70;
    }

    if (m_hStaticFilter) {
        SetWindowPos(m_hStaticFilter, NULL, posX, baseY, 35, 22, SWP_NOZORDER);
        posX += 38;
    }
    if (m_hEditFilter) {
        SetWindowPos(m_hEditFilter, NULL, posX, baseY, 120, 22, SWP_NOZORDER);
    }
}

bool NetworkInvestigator::HandleToolbarCommand(WORD id, WORD code) {
    switch (id) {
    case IDC_NET_CMB_PROTOCOL:
    case IDC_NET_CMB_STATE:
    case IDC_NET_CMB_SCOPE:
        if (code == CBN_SELCHANGE) {
            UpdateFilterOptions();
            RefreshFromCache();
            PublishView(2);
            return true;
        }
        break;

    case IDC_NET_CMB_REFRESH:
        if (code == CBN_SELCHANGE) {
            int sel = (int)SendMessage(m_hCmbRefresh, CB_GETCURSEL, 0, 0);
            switch (sel) {
            case 0:
                m_refreshInterval = 0;
                break;
            case 1:
                m_refreshInterval = 1000;
                break;
            case 2:
                m_refreshInterval = 2000;
                break;
            case 3:
                m_refreshInterval = 3000;
                break;
            case 4:
                m_refreshInterval = 5000;
                break;
            default:
                m_refreshInterval = 0;
                break;
            }
            if (m_refreshInterval > 0) {
                StartRefreshTimer();
            } else {
                StopRefreshTimer();
            }
            return true;
        }
        break;

    case IDC_NET_BTN_REFRESH:
        if (code == BN_CLICKED) {
            DoRefresh();
            return true;
        }
        break;

    case IDC_NET_BTN_IP_LOCATION:
        if (code == BN_CLICKED) {
            StartIpLocationQuery();
            return true;
        }
        break;

    case IDC_NET_EDIT_FILTER:
        if (code == EN_CHANGE) {
            UpdateFilterOptions();
            RefreshFromCache();
            PublishView(2);
            return true;
        }
        break;
    }
    return false;
}

void NetworkInvestigator::OnTimer(UINT_PTR timerId) {
    if (timerId == TIMER_NET_REFRESH) {
        DoRefresh();
    }
}

void NetworkInvestigator::DoRefresh() {
    if (m_isRefreshing)
        return;
    m_isRefreshing = true;
    RefreshSnapshot();
    m_isRefreshing = false;
    PublishView();
}

void NetworkInvestigator::RefreshSnapshot() {
    auto connections = CollectAllConnections();
    if (m_collectionStatus == wgwc::core::CollectionStatus::Complete ||
        m_collectionStatus == wgwc::core::CollectionStatus::Partial) {
        m_collectedConnections = std::move(connections);
        m_hasCache = true;
    }
    RebuildFilteredSnapshot();
}

void NetworkInvestigator::RebuildFilteredSnapshot() {
    ApplyLocationCache(m_collectedConnections);
    std::vector<ConnectionInfo> visible;
    for (const auto& connection : m_collectedConnections)
        if (MatchFilter(connection))
            visible.push_back(connection);
    SortConnections(visible);
    m_lastConnections = std::move(visible);
    m_cachedResult = BuildResultFromConnections(m_lastConnections);
}

void NetworkInvestigator::PublishView(WPARAM statusKind) {
    if (m_hMainWnd)
        PostMessageW(m_hMainWnd, WM_NET_RESULTS_CHANGED, statusKind, 0);
}

void NetworkInvestigator::StartRefreshTimer() {
    if (m_hMainWnd && m_refreshInterval > 0) {
        SetTimer(m_hMainWnd, TIMER_NET_REFRESH, m_refreshInterval, NULL);
    }
}

void NetworkInvestigator::StopRefreshTimer() {
    if (m_hMainWnd) {
        KillTimer(m_hMainWnd, TIMER_NET_REFRESH);
    }
}

void NetworkInvestigator::UpdateFilterOptions() {
    if (m_hCmbProtocol) {
        int sel = (int)SendMessage(m_hCmbProtocol, CB_GETCURSEL, 0, 0);
        if (sel >= 0 && sel <= (int)ProtocolFilter::UdpV6) {
            m_filterOptions.protocol = (ProtocolFilter)sel;
        }
    }
    if (m_hCmbState) {
        int sel = (int)SendMessage(m_hCmbState, CB_GETCURSEL, 0, 0);
        if (sel >= 0 && sel <= (int)StateFilter::Other) {
            m_filterOptions.state = (StateFilter)sel;
        }
    }
    if (m_hCmbScope) {
        int sel = (int)SendMessage(m_hCmbScope, CB_GETCURSEL, 0, 0);
        if (sel >= 0 && sel <= (int)ScopeFilter::LocalListen) {
            m_filterOptions.scope = (ScopeFilter)sel;
        }
    }

    if (m_hEditFilter) {
        wchar_t buf[256] = { 0 };
        GetWindowTextW(m_hEditFilter, buf, 255);
        m_filterOptions.searchText = buf;
    }
}

bool NetworkInvestigator::MatchFilter(const ConnectionInfo& conn) {
    WgNetwork::FilterOptions options = m_filterOptions;
    // 归属信息由 GUI 补充，不在 Core 中隐式触发 HTTP 查询。
    if (!options.searchText.empty() && WgNetwork::ContainsInsensitive(conn.location, options.searchText)) {
        options.searchText.clear();
    }
    return WgNetwork::MatchesConnection(conn, options);
}

void NetworkInvestigator::SortConnections(std::vector<ConnectionInfo>& connections) {
    std::sort(connections.begin(), connections.end(), [this](const ConnectionInfo& a, const ConnectionInfo& b) {
        return WgNetwork::LessConnection(a, b, m_filterOptions.sortMode);
    });
}

std::vector<ConnectionInfo> NetworkInvestigator::CollectAllConnections() {
    WgNetwork::NetworkOptions options;
    options.protocol = ProtocolFilter::All;
    wgwc::core::CollectionContext context;
    auto collected = WgNetwork::CollectConnections(options, context);
    m_collectionStatus = collected.status;
    m_collectionErrorCode = 0;
    m_collectionMessage.clear();
    for (const auto& issue : collected.issues) {
        if (!issue.affectsCompleteness)
            continue;
        m_collectionErrorCode = issue.nativeCode;
        m_collectionMessage =
            collected.status == wgwc::core::CollectionStatus::Partial ? L"网络数据已部分采集" : L"网络数据采集失败";
        if (issue.nativeCode)
            m_collectionMessage += L"，错误码: " + std::to_wstring(issue.nativeCode);
        break;
    }
    std::vector<ConnectionInfo> connections;
    connections.reserve(collected.records.size());
    for (const auto& record : collected.records)
        connections.emplace_back(record);
    return connections;
}

// 由主窗口统一发布列表数据并管理嵌套的暂停重绘。

InvestigationResult NetworkInvestigator::Investigate(bool resetFilter) {
    if (resetFilter) {
        const bool wasRefreshing = m_isRefreshing;
        m_isRefreshing = true;
        m_filterOptions = FilterOptions();
        if (m_hCmbProtocol)
            SendMessage(m_hCmbProtocol, CB_SETCURSEL, 0, 0);
        if (m_hCmbState)
            SendMessage(m_hCmbState, CB_SETCURSEL, 0, 0);
        if (m_hCmbScope)
            SendMessage(m_hCmbScope, CB_SETCURSEL, 1, 0);
        if (m_hEditFilter)
            SetWindowTextW(m_hEditFilter, L"");
        m_isRefreshing = wasRefreshing;
    }
    UpdateFilterOptions();
    RefreshSnapshot();
    return m_cachedResult;
}

// 重新应用展示筛选条件，不再次查询系统。
InvestigationResult NetworkInvestigator::RefreshFromCache() {
    UpdateFilterOptions();
    RebuildFilteredSnapshot();
    return m_cachedResult;
}

InvestigationResult
NetworkInvestigator::BuildResultFromConnections(const std::vector<ConnectionInfo>& connections) const {
    InvestigationResult result;
    result.moduleName = GetModuleName();
    result.success = m_collectionStatus == wgwc::core::CollectionStatus::Complete ||
                     m_collectionStatus == wgwc::core::CollectionStatus::Partial;
    result.partial = m_collectionStatus == wgwc::core::CollectionStatus::Partial;
    result.stale = !result.success && m_hasCache;
    result.errorCode = m_collectionErrorCode;
    result.errorMessage = m_collectionMessage;

    for (const auto& conn : connections) {
        std::vector<std::wstring> row;
        std::wstring protocolDisplay = conn.protocol + (conn.isIPv6 ? L" v6" : L" v4");
        row.push_back(protocolDisplay);
        row.push_back(conn.localAddress);
        row.push_back(std::to_wstring(conn.localPort));
        row.push_back(conn.remoteAddress);
        row.push_back(conn.remotePort > 0 ? std::to_wstring(conn.remotePort) : L"*");
        row.push_back(conn.state);
        row.push_back(std::to_wstring(conn.pid));
        row.push_back(conn.processName);
        row.push_back(conn.location);
        result.rows.push_back(row);
    }

    result.totalCount = (DWORD)connections.size();
    return result;
}

void NetworkInvestigator::UpdateStatusText(const std::wstring& text) const {
    if (!m_hMainWnd) {
        return;
    }

    HWND hStatus = GetDlgItem(m_hMainWnd, IDC_STATUSBAR);
    if (hStatus) {
        SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)text.c_str());
    }
}

void NetworkInvestigator::SetIpLocationButtonText(const std::wstring& text) {
    if (m_hBtnIpLocation) {
        SetWindowTextW(m_hBtnIpLocation, text.c_str());
    }
}

void NetworkInvestigator::ApplyLocationCache(std::vector<ConnectionInfo>& connections) {
    for (auto& conn : connections) {
        const auto key = wgwc::core::ip::PublicLookupKey(conn.remoteAddress);
        auto it = m_ipLocationCache.find(key);
        if (it != m_ipLocationCache.end()) {
            conn.location = it->second;
        } else {
            conn.location.clear();
        }
    }
}

std::vector<std::wstring> NetworkInvestigator::CollectQueryableRemoteIps() const {
    std::vector<std::wstring> ips;
    std::set<std::wstring> seen;

    for (const auto& conn : m_lastConnections) {
        // 只对查询地址去重，不改变连接记录和既有外联筛选范围。
        const auto key = wgwc::core::ip::PublicLookupKey(conn.remoteAddress);
        if (key.empty() || m_ipLocationCache.find(key) != m_ipLocationCache.end()) {
            continue;
        }
        if (seen.insert(key).second) {
            ips.push_back(key);
        }
    }

    return ips;
}

void NetworkInvestigator::StartIpLocationQuery() {
    if (m_locationRunning) {
        m_cancelLocation = true;
        SetIpLocationButtonText(L"停止中");
        UpdateStatusText(L"正在停止 IP 归属查询...");
        return;
    }

    if (!m_hasCache) {
        RefreshSnapshot();
        PublishView();
    }

    ApplyLocationCache(m_lastConnections);
    std::vector<std::wstring> ips = CollectQueryableRemoteIps();
    if (ips.empty()) {
        RebuildFilteredSnapshot();
        PublishView(0);
        UpdateStatusText(L"当前没有可查询的外联公网 IP");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_locationMutex);
        m_pendingLocationResult.clear();
        m_pendingLocationError.clear();
        m_pendingLocationCanceled = false;
    }

    m_cancelLocation = false;
    m_locationRunning = true;
    SetIpLocationButtonText(L"停止归属");

    wchar_t statusText[256];
    swprintf_s(statusText, L"正在查询 IP 归属 - %zu 个公网 IP", ips.size());
    UpdateStatusText(statusText);

    IpLocationThreadParam* param = new IpLocationThreadParam();
    param->hNotifyWnd = m_hMainWnd;
    param->self = this;
    param->ips = ips;

    m_hLocationThread = CreateThread(NULL, 0, IpLocationThreadProc, param, 0, NULL);
    if (!m_hLocationThread) {
        delete param;
        m_locationRunning = false;
        SetIpLocationButtonText(L"IP归属");
        UpdateStatusText(L"IP 归属查询启动失败");
    }
}

DWORD WINAPI NetworkInvestigator::IpLocationThreadProc(LPVOID param) {
    IpLocationThreadParam* ctx = static_cast<IpLocationThreadParam*>(param);
    if (!ctx || !ctx->self) {
        delete ctx;
        return 0;
    }

    NetworkInvestigator* self = ctx->self;
    std::map<std::wstring, std::wstring> result;
    std::wstring error;
    bool canceled = false;
    const size_t batchSize = 100;

    for (size_t i = 0; i < ctx->ips.size(); i += batchSize) {
        if (self->m_cancelLocation.load()) {
            canceled = true;
            break;
        }

        std::vector<std::wstring> batch;
        for (size_t j = i; j < ctx->ips.size() && j < i + batchSize; j++) {
            batch.push_back(ctx->ips[j]);
        }

        std::wstring batchError;
        auto batchResult = IpLocationService::QueryBatch(batch, &self->m_cancelLocation, &batchError);
        for (const auto& kv : batchResult) {
            result[kv.first] = kv.second;
        }

        if (!batchError.empty()) {
            error = batchError;
            break;
        }
    }

    if (self->m_cancelLocation.load()) {
        canceled = true;
    }

    {
        std::lock_guard<std::mutex> lock(self->m_locationMutex);
        self->m_pendingLocationResult = result;
        self->m_pendingLocationError = error;
        self->m_pendingLocationCanceled = canceled;
    }

    if (ctx->hNotifyWnd) {
        PostMessageW(ctx->hNotifyWnd, WM_NET_IP_LOCATION_DONE, 0, 0);
    }

    delete ctx;
    return 0;
}

void NetworkInvestigator::OnIpLocationDone(bool refreshListView) {
    std::map<std::wstring, std::wstring> result;
    std::wstring error;
    bool canceled = false;

    {
        std::lock_guard<std::mutex> lock(m_locationMutex);
        result = m_pendingLocationResult;
        error = m_pendingLocationError;
        canceled = m_pendingLocationCanceled;
        m_pendingLocationResult.clear();
        m_pendingLocationError.clear();
        m_pendingLocationCanceled = false;
    }

    if (m_hLocationThread) {
        CloseHandle(m_hLocationThread);
        m_hLocationThread = NULL;
    }

    for (const auto& kv : result) {
        m_ipLocationCache[kv.first] = kv.second;
    }

    RebuildFilteredSnapshot();
    if (refreshListView)
        PublishView(0);

    m_locationRunning = false;
    m_cancelLocation = false;
    SetIpLocationButtonText(L"IP归属");

    wchar_t statusText[256];
    if (canceled) {
        swprintf_s(statusText, L"已停止 IP 归属查询 - 已更新 %zu 个 IP", result.size());
    } else if (!error.empty()) {
        swprintf_s(statusText, L"IP 归属查询失败: %s", error.c_str());
    } else {
        swprintf_s(statusText, L"IP 归属查询完成 - 已更新 %zu 个 IP", result.size());
    }
    UpdateStatusText(statusText);
}

// 右键菜单功能实现

std::vector<ContextMenuItem> NetworkInvestigator::GetContextMenuItems(int row) const {
    std::vector<ContextMenuItem> items;

    const auto* selected = ContextConnection(row);
    if (!selected)
        return items;
    const ConnectionInfo& conn = *selected;

    // 复制远程地址
    items.push_back({ IDM_NET_COPY_REMOTE_ADDR, L"复制远程地址", false, L"" });

    // 远程地址和端口（仅TCP有效）
    if (conn.protocol == L"TCP" && conn.remotePort > 0) {
        items.push_back({ IDM_NET_COPY_REMOTE_FULL, L"复制远程地址和端口", false, L"" });
    }

    // 分隔符
    items.push_back({ 0, L"", false, L"" });

    // 复制所有外联
    items.push_back({ IDM_NET_COPY_ALL_REMOTE, L"复制所有外联", false, L"" });
    items.push_back({ IDM_NET_COPY_ALL_REMOTE_PORT, L"复制所有外联和端口", false, L"" });

    // 在线查询（仅对有效远程IP显示）
    if (!conn.remoteAddress.empty() && conn.remoteAddress != L"*" && !WgNetwork::IsLocalAddress(conn.remoteAddress)) {
        items.push_back({ 0, L"", false, L"" }); // 分隔符
        items.push_back({ IDM_NET_THREATBOOK, L"在线查询（微步）", false, L"" });
        items.push_back({ IDM_NET_VIRUSTOTAL, L"在线查询（VirusTotal）", false, L"" });
    }

    return items;
}

std::wstring NetworkInvestigator::GetContextFilePath(int row) const {
    const auto* selected = ContextConnection(row);
    return selected ? selected->processPath : L"";
}

std::wstring NetworkInvestigator::GetRowIconPath(int row, const InvestigationItem& item) const {
    (void)item;
    return GetContextFilePath(row);
}

// 处理右键菜单命令
bool NetworkInvestigator::HandleContextMenu(UINT menuId, int row) {
    const auto* selected = ContextConnection(row);
    if (!selected)
        return false;
    const ConnectionInfo& conn = *selected;

    switch (menuId) {
    case IDM_NET_COPY_REMOTE_ADDR:
        CommonUtils::CopyToClipboard(m_hMainWnd, conn.remoteAddress);
        return false;

    case IDM_NET_COPY_REMOTE_FULL:
        if (conn.remotePort > 0) {
            CommonUtils::CopyToClipboard(
                m_hMainWnd, WgNetwork::FormatEndpoint({ conn.remoteAddress, conn.isIPv6, conn.remoteScopeId,
                                                        conn.transport, conn.remotePort, true }));
        }
        return false;

    case IDM_NET_COPY_ALL_REMOTE:
    case IDM_NET_COPY_ALL_REMOTE_PORT: {
        const bool addressesOnly = menuId == IDM_NET_COPY_ALL_REMOTE;
        std::vector<const WgNetwork::Connection*> snapshot;
        if (!m_contextMenuActive)
            for (const auto& connection : m_lastConnections)
                snapshot.push_back(&connection);
        const auto endpoints =
            m_contextMenuActive
                ? (addressesOnly ? m_contextAddresses : m_contextEndpoints)
                : WgNetwork::ExtractRemoteEndpoints(snapshot, addressesOnly ? WgNetwork::UniqueBy::Address
                                                                            : WgNetwork::UniqueBy::Endpoint);
        std::wstring result;
        for (const auto& endpoint : endpoints) {
            if (!result.empty())
                result += L"\r\n";
            result += WgNetwork::FormatEndpoint(endpoint);
        }
        CommonUtils::CopyToClipboard(m_hMainWnd, result);
        return false;
    }

    case IDM_NET_THREATBOOK: {
        std::wstring url = L"https://x.threatbook.com/v5/ip/" + conn.remoteAddress;
        ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
        return false;
    }

    case IDM_NET_VIRUSTOTAL: {
        std::wstring url = L"https://www.virustotal.com/gui/ip-address/" + conn.remoteAddress;
        ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
        return false;
    }
    }

    return false;
}

const ConnectionInfo* NetworkInvestigator::ContextConnection(int row) const {
    if (m_contextMenuActive && row == m_contextMenuRow)
        return row >= 0 ? &m_contextConnection : nullptr;
    return row >= 0 && static_cast<size_t>(row) < m_lastConnections.size()
               ? &m_lastConnections[static_cast<size_t>(row)]
               : nullptr;
}

void NetworkInvestigator::BeginContextMenu(int row) {
    m_contextMenuRow = row >= 0 && static_cast<size_t>(row) < m_lastConnections.size() ? row : -1;
    if (m_contextMenuRow >= 0)
        m_contextConnection = m_lastConnections[static_cast<size_t>(row)];
    std::vector<const WgNetwork::Connection*> snapshot;
    snapshot.reserve(m_lastConnections.size());
    for (const auto& connection : m_lastConnections)
        snapshot.push_back(&connection);
    m_contextAddresses = WgNetwork::ExtractRemoteEndpoints(snapshot, WgNetwork::UniqueBy::Address);
    m_contextEndpoints = WgNetwork::ExtractRemoteEndpoints(snapshot, WgNetwork::UniqueBy::Endpoint);
    m_contextMenuActive = true;
}

void NetworkInvestigator::EndContextMenu() {
    m_contextMenuActive = false;
    m_contextMenuRow = -1;
    m_contextConnection = {};
    m_contextAddresses.clear();
    m_contextEndpoints.clear();
}
