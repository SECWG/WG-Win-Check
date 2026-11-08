#pragma once

// winsock2.h 必须在 windows.h 之前包含
#ifndef _WINSOCK2API_
#include <winsock2.h>
#endif
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <udpmib.h>

#include "../../common/IInvestigator.h"
#include "../../common/CommonUtils.h"
#include "IpLocationService.h"
#include "../../../core/modules/network/NetworkModule.h"
#include <atomic>
#include <map>
#include <mutex>
#include <set>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// 工具栏控件ID
#define IDC_NET_CMB_PROTOCOL 3001
#define IDC_NET_CMB_STATE 3002
#define IDC_NET_CMB_SCOPE 3003
#define IDC_NET_CMB_REFRESH 3008
#define IDC_NET_BTN_REFRESH 3009
#define IDC_NET_EDIT_FILTER 3010
#define IDC_NET_BTN_IP_LOCATION 3013

// 网络模块专用窗口消息。
#define WM_NET_IP_LOCATION_DONE (WM_APP + 310)
#define WM_NET_RESULTS_CHANGED (WM_APP + 311)

// 右键菜单ID
#define IDM_NET_COPY_REMOTE_ADDR 3101
#define IDM_NET_COPY_REMOTE_FULL 3102
#define IDM_NET_COPY_ALL_REMOTE 3106
#define IDM_NET_COPY_ALL_REMOTE_PORT 3107
#define IDM_NET_THREATBOOK 3108 // 在线查询（微步）
#define IDM_NET_VIRUSTOTAL 3109 // 在线查询（VirusTotal）

// 定时器ID
#define TIMER_NET_REFRESH 1001

// GUI 默认值和展示设置与共享网络模型分离。
namespace WgNetwork = wgwc::core::network;
using SortMode = WgNetwork::SortMode;
using ProtocolFilter = WgNetwork::ProtocolFilter;
using StateFilter = WgNetwork::StateFilter;
using ScopeFilter = WgNetwork::ScopeFilter;

struct FilterOptions : WgNetwork::FilterOptions {
    FilterOptions() {
        scope = ScopeFilter::External;
    }
};

struct ConnectionInfo : WgNetwork::Connection {
    ConnectionInfo() = default;

    explicit ConnectionInfo(const WgNetwork::Connection& source)
        : WgNetwork::Connection(source), protocol(WgNetwork::ProtocolName(source.transport)),
          state(source.transport == WgNetwork::Transport::Tcp ? WgNetwork::TcpStateName(source.tcpState) : L"") {
        if (processName.empty() && processNameState != wgwc::core::FieldState::NotApplicable)
            processName = L"<unknown>";
    }

    std::wstring protocol;
    std::wstring state;
    std::wstring location;
};

class NetworkInvestigator : public IInvestigator {
public:
    NetworkInvestigator();
    ~NetworkInvestigator() override;

    InvestigationResult Investigate(bool resetFilter = true) override;

    std::wstring GetModuleName() const override {
        return L"NetworkInvestigator";
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
        m_collectedConnections.clear();
        m_lastConnections.clear();
    }

    InvestigationResult RefreshFromCache() override;

    const ColumnDef* GetColumns() const override {
        return s_Columns;
    }

    int GetColumnCount() const override {
        return s_ColumnCount;
    }

    bool GetCellHighlight(int row, int col, const InvestigationResult& result, COLORREF& outColor) const override {
        (void)row;
        (void)col;
        (void)result;
        (void)outColor;
        return false;
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

    void OnTimer(UINT_PTR timerId) override;

    UINT_PTR GetTimerId() const override {
        return TIMER_NET_REFRESH;
    }

    void SetMainWindow(HWND hWnd) {
        m_hMainWnd = hWnd;
    }

    void SetListView(HWND hListView) {
        m_hListView = hListView;
    }

    std::vector<ContextMenuItem> GetContextMenuItems(int row) const override;
    bool HandleContextMenu(UINT menuId, int row) override;
    void BeginContextMenu(int row) override;
    void EndContextMenu() override;
    std::wstring GetContextFilePath(int row) const override;

    bool HasRowIcons() const override {
        return true;
    }

    int GetRowIconColumn() const override {
        return COL_PROCESS;
    }

    std::wstring GetRowIconPath(int row, const InvestigationItem& item) const override;

    // IP 归属后台查询完成后，在界面线程中调用。
    void OnIpLocationDone(bool refreshListView);

private:
#ifdef WGWC_GUI_IP_TESTS
    friend struct GuiIpLocationTestAccess;
#endif
    struct IpLocationThreadParam;

    std::vector<ConnectionInfo> CollectAllConnections();

    bool MatchFilter(const ConnectionInfo& conn);
    void SortConnections(std::vector<ConnectionInfo>& connections);

    void UpdateFilterOptions();
    void StartRefreshTimer();
    void StopRefreshTimer();
    void DoRefresh();
    void RefreshSnapshot();
    void RebuildFilteredSnapshot();
    void PublishView(WPARAM statusKind = 1);
    const ConnectionInfo* ContextConnection(int row) const;
    void StartIpLocationQuery();
    void ApplyLocationCache(std::vector<ConnectionInfo>& connections);
    std::vector<std::wstring> CollectQueryableRemoteIps() const;
    InvestigationResult BuildResultFromConnections(const std::vector<ConnectionInfo>& connections) const;
    void UpdateStatusText(const std::wstring& text) const;
    void SetIpLocationButtonText(const std::wstring& text);
    static DWORD WINAPI IpLocationThreadProc(LPVOID param);

    static const ColumnDef s_Columns[];
    static const int s_ColumnCount;

    // 列索引常量
    static const int COL_PROTOCOL = 0;
    static const int COL_LOCAL_ADDR = 1;
    static const int COL_LOCAL_PORT = 2;
    static const int COL_REMOTE_ADDR = 3;
    static const int COL_REMOTE_PORT = 4;
    static const int COL_STATE = 5;
    static const int COL_PID = 6;
    static const int COL_PROCESS = 7;
    static const int COL_LOCATION = 8;

    // 工具栏控件句柄
    HWND m_hCmbProtocol = NULL;
    HWND m_hCmbState = NULL;
    HWND m_hCmbScope = NULL;
    HWND m_hStaticRefresh = NULL;
    HWND m_hCmbRefresh = NULL;
    HWND m_hBtnRefresh = NULL;
    HWND m_hBtnIpLocation = NULL;
    HWND m_hStaticFilter = NULL;
    HWND m_hEditFilter = NULL;

    // 主窗口和ListView句柄
    HWND m_hMainWnd = NULL;
    HWND m_hListView = NULL;
    HINSTANCE m_hInst = NULL;

    // 过滤选项
    FilterOptions m_filterOptions;

    // 刷新间隔（毫秒，0表示暂停）
    UINT m_refreshInterval = 0;

    // 刷新锁（防止重入）
    bool m_isRefreshing = false;

    // 当前 Core 状态；可选进程字段缺失不应导致连接表采集失败。
    wgwc::core::CollectionStatus m_collectionStatus = wgwc::core::CollectionStatus::Complete;
    DWORD m_collectionErrorCode = 0;
    std::wstring m_collectionMessage;

    std::vector<ConnectionInfo> m_collectedConnections;
    std::vector<ConnectionInfo> m_lastConnections;
    bool m_contextMenuActive = false;
    int m_contextMenuRow = -1;
    ConnectionInfo m_contextConnection;
    std::vector<WgNetwork::RemoteEndpoint> m_contextAddresses;
    std::vector<WgNetwork::RemoteEndpoint> m_contextEndpoints;

    // IP归属缓存和后台查询状态
    std::map<std::wstring, std::wstring> m_ipLocationCache;
    std::map<std::wstring, std::wstring> m_pendingLocationResult;
    std::wstring m_pendingLocationError;
    std::atomic_bool m_cancelLocation{ false };
    bool m_locationRunning = false;
    bool m_pendingLocationCanceled = false;
    HANDLE m_hLocationThread = NULL;
    mutable std::mutex m_locationMutex;

    bool m_hasCache = false;
    InvestigationResult m_cachedResult;
};
