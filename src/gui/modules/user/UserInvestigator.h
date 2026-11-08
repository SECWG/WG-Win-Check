#pragma once
#include "../../common/RiskOverviewItem.h"
#include "../../common/IInvestigator.h"
#include "../../../core/modules/user/UserModule.h"
#include <lm.h>
#include <map>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

// 右键菜单ID
#define IDM_USER_DELETE 9001
#define IDM_USER_DISABLE 9002
#define IDM_USER_ENABLE 9003
#define IDM_USER_OPEN_MGR 9004

struct UserInfo : wgwc::core::users::UserRecord {
    std::wstring hiddenTypes;
};

struct RidInfo {
    std::wstring username;
    DWORD rid;
    DWORD fValue;
};

class UserInvestigator : public IInvestigator {
public:
    UserInvestigator();
    ~UserInvestigator() override = default;

    InvestigationResult Investigate(bool resetFilter = true) override;
    // 仅在主线程应用已经采集的快照，工作线程不访问界面控件。
    InvestigationResult ApplyCollection(const wgwc::core::CollectionResult<wgwc::core::users::UserRecord>& collection,
                                        bool resetFilter = false, const std::wstring& collectedAt = L"");

    std::wstring GetModuleName() const override {
        return L"UserInvestigator";
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
        m_cachedUsers.clear();
        m_collectedAt.clear();
    }

    const ColumnDef* GetColumns() const override {
        return s_Columns;
    }

    int GetColumnCount() const override {
        return s_ColumnCount;
    }

    // 自定义绘制 - 整行着色
    bool GetCellHighlight(int row, int col, const InvestigationResult& result, COLORREF& outColor) const override;

    std::vector<ContextMenuItem> GetContextMenuItems(int row) const override;
    bool HandleContextMenu(UINT menuId, int row) override;

    std::vector<RiskOverviewItem> GetRiskFindings() const override;

    void SetMainWindow(HWND hWnd) {
        m_hMainWnd = hWnd;
    }

    std::vector<UserInfo> EnumerateLocalUsers();
    std::vector<std::wstring> GetAdministrators();
    std::vector<std::wstring> GetHiddenUsers();
    std::vector<std::wstring> GetHiddenUsersBySAM();
    std::vector<std::wstring> GetDollarSuffixUsers();
    std::map<std::wstring, RidInfo> CheckRidHijacking();
    std::wstring GetCurrentUser();

private:
    SuspicionLevel AnalyzeUserSuspicion(const UserInfo& user);
    bool IsUserInAdminGroup(const std::wstring& username);
    std::wstring GetLastErrorMessage(DWORD errorCode);
    std::wstring FormatTimestamp(DWORD timestamp);
    std::wstring FormatDuration(DWORD seconds);
    DWORD GetUserRid(const std::wstring& username);

    // 用户操作
    bool DeleteUser(const std::wstring& username);
    bool DisableUser(const std::wstring& username);
    bool EnableUser(const std::wstring& username);
    bool IsProtectedUser(const std::wstring& username) const;

    static const ColumnDef s_Columns[];
    static const int s_ColumnCount;

    // 列索引常量
    static const int COL_USERNAME = 0;
    static const int COL_DESCRIPTION = 1;
    static const int COL_STATUS = 2;
    static const int COL_ADMIN = 3;
    static const int COL_HIDDEN = 4;
    static const int COL_LASTLOGON = 5;
    static const int COL_LOGONCOUNT = 6;
    static const int COL_BADPWCOUNT = 7;
    static const int COL_RIDHIJACK = 8;
    static const int COL_SUSPICION = 9;

    // 缓存的用户列表（用于右键菜单操作）
    std::vector<UserInfo> m_cachedUsers;
    HWND m_hMainWnd = NULL;

    // 结果缓存
    bool m_hasCache = false;
    InvestigationResult m_cachedResult;
    std::wstring m_collectedAt;
};
