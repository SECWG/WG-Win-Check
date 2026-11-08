#include "../../presentation/GuiColumns.h"
// UserInvestigator.cpp - 用户排查模块实现
#include "UserInvestigator.h"
#include "../../resources/resource.h"

#include <sddl.h>
#include <set>
#include <sstream>
#include <iomanip>
#include <ctime>

// 静态列定义
const ColumnDef UserInvestigator::s_Columns[] = { WG_COLUMNS_USER };
const int UserInvestigator::s_ColumnCount = sizeof(s_Columns) / sizeof(s_Columns[0]);

namespace {
    constexpr size_t MAX_USERNAME_LENGTH = 256;

    std::wstring BuildUserRiskDescription(const UserInfo& user) {
        return wgwc::core::users::RiskReason(user);
    }

    SuspicionLevel GuiUserLevel(wgwc::core::RiskLevel level) {
        switch (level) {
        case wgwc::core::RiskLevel::Critical:
            return SuspicionLevel::Critical;
        case wgwc::core::RiskLevel::High:
            return SuspicionLevel::High;
        case wgwc::core::RiskLevel::Medium:
            return SuspicionLevel::Medium;
        case wgwc::core::RiskLevel::Low:
            return SuspicionLevel::Low;
        default:
            return SuspicionLevel::None;
        }
    }
}

UserInvestigator::UserInvestigator() {}

// 自定义绘制 - 判断单元格是否需要高亮（整行着色）
bool UserInvestigator::GetCellHighlight(int row, int col, const InvestigationResult& result, COLORREF& outColor) const {
    (void)col; // 不再按列区分，整行着色

    if (row < 0 || row >= (int)result.items.size()) {
        return false;
    }

    const auto& item = result.items[row];

    // 根据可疑级别整行着色（与其他模块保持一致）
    switch (item.suspicion) {
    case SuspicionLevel::Critical:
        outColor = RGB(255, 0, 0); // 严重 - 红色
        return true;
    case SuspicionLevel::High:
        outColor = RGB(255, 0, 0); // 高 - 红色
        return true;
    case SuspicionLevel::Medium:
        outColor = RGB(255, 128, 0); // 中 - 橙色
        return true;
    case SuspicionLevel::Low:
        outColor = RGB(128, 128, 0); // 低 - 暗黄色
        return true;
    default:
        return false;
    }
}

std::wstring UserInvestigator::FormatTimestamp(DWORD timestamp) {
    if (timestamp == 0) {
        return L"从未";
    }

    time_t t = static_cast<time_t>(timestamp);
    struct tm timeinfo;
    if (localtime_s(&timeinfo, &t) != 0) {
        return L"无效";
    }

    wchar_t buffer[64];
    wcsftime(buffer, sizeof(buffer) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &timeinfo);
    return buffer;
}

std::wstring UserInvestigator::FormatDuration(DWORD seconds) {
    if (seconds == 0) {
        return L"0秒";
    }

    DWORD days = seconds / 86400;
    DWORD hours = (seconds % 86400) / 3600;
    DWORD mins = (seconds % 3600) / 60;

    std::wstringstream ss;
    if (days > 0)
        ss << days << L"天";
    if (hours > 0)
        ss << hours << L"小时";
    if (mins > 0 && days == 0)
        ss << mins << L"分钟";

    return ss.str();
}

InvestigationResult UserInvestigator::Investigate(bool resetFilter) {
    auto context = MakeCollectionContext();
    const auto collectedAt = RiskOverviewNowString();
    return ApplyCollection(wgwc::core::users::CollectUsers(context), resetFilter, collectedAt);
}

InvestigationResult
UserInvestigator::ApplyCollection(const wgwc::core::CollectionResult<wgwc::core::users::UserRecord>& collected,
                                  bool resetFilter, const std::wstring& collectedAt) {
    (void)resetFilter;
    const bool success = collected.status == wgwc::core::CollectionStatus::Complete ||
                         collected.status == wgwc::core::CollectionStatus::Partial;
    DWORD error = 0;
    for (const auto& issue : collected.issues) {
        if (issue.affectsCompleteness) {
            error = issue.nativeCode;
            break;
        }
    }
    if (!success) {
        InvestigationResult failed = m_hasCache ? m_cachedResult : InvestigationResult();
        failed.moduleName = GetModuleName();
        failed.success = false;
        failed.partial = false;
        failed.stale = m_hasCache;
        failed.errorCode = error;
        failed.errorMessage = L"用户数据未能采集";
        if (m_hasCache)
            m_cachedResult = failed;
        return failed;
    }
    InvestigationResult result;
    result.moduleName = GetModuleName();
    result.success = true;
    result.partial = collected.status == wgwc::core::CollectionStatus::Partial;
    result.errorCode = error;
    if (result.partial)
        result.errorMessage = L"部分用户来源未完整采集";
    std::vector<UserInfo> users;
    for (const auto& record : collected.records) {
        UserInfo user;
        static_cast<wgwc::core::users::UserRecord&>(user) = record;
        user.hiddenTypes = wgwc::core::users::HiddenTypeText(record);
        users.push_back(std::move(user));
    }
    for (const auto& user : users) {
        SuspicionLevel suspicion = AnalyzeUserSuspicion(user);

        InvestigationItem item;
        item.name = user.username;
        item.description = user.description;
        item.suspicion = suspicion;

        // 填充各列数据（按列索引顺序）
        item.details.resize(s_ColumnCount);
        item.details[COL_USERNAME] = user.username;
        item.details[COL_DESCRIPTION] = user.description;

        // 状态
        std::wstring status;
        if (user.isDisabled)
            status += L"已禁用 ";
        if (user.isLocked)
            status += L"已锁定 ";
        if (user.passwordNeverExpires)
            status += L"密码永不过期 ";
        if (user.passwordNotRequired)
            status += L"无需密码 ";
        if (user.metadataState != wgwc::core::FieldState::Available)
            status = L"未知";
        else if (status.empty())
            status = L"正常";
        item.details[COL_STATUS] = status;

        item.details[COL_ADMIN] =
            user.adminState == wgwc::core::FieldState::Available ? (user.isAdmin ? L"是" : L"否") : L"未知";
        item.details[COL_HIDDEN] = user.hiddenState == wgwc::core::FieldState::Available
                                       ? (user.isHidden ? user.hiddenTypes : L"否")
                                       : L"未知";
        item.details[COL_LASTLOGON] =
            user.metadataState == wgwc::core::FieldState::Available ? FormatTimestamp(user.lastLogon) : L"";
        item.details[COL_LOGONCOUNT] =
            user.metadataState == wgwc::core::FieldState::Available ? std::to_wstring(user.numLogons) : L"";
        item.details[COL_BADPWCOUNT] =
            user.metadataState == wgwc::core::FieldState::Available ? std::to_wstring(user.badPasswordCount) : L"";

        if (user.ridHijacked) {
            item.details[COL_RIDHIJACK] = L"是(RID:" + std::to_wstring(user.hijackedRid) + L")";
        } else {
            item.details[COL_RIDHIJACK] = user.ridHijackState == wgwc::core::FieldState::Available ? L"否" : L"未知";
        }

        std::wstring riskDesc = BuildUserRiskDescription(user);

        // 正常级别显示为空
        item.details[COL_SUSPICION] = riskDesc;

        // 可疑原因（保留用于其他用途）
        item.suspicionReason = riskDesc;

        if (suspicion != SuspicionLevel::None) {
            result.suspiciousCount++;
        }

        result.items.push_back(item);
    }

    // 缓存用户列表（用于右键菜单操作）
    m_cachedUsers = users;

    result.totalCount = (DWORD)result.items.size();

    m_cachedResult = result;
    m_hasCache = true;
    m_collectedAt = collectedAt.empty() ? RiskOverviewNowString() : collectedAt;

    return result;
}

std::vector<RiskOverviewItem> UserInvestigator::GetRiskFindings() const {
    std::vector<RiskOverviewItem> findings;
    if (!m_hasCache) {
        return findings;
    }

    const std::wstring& updatedAt = m_collectedAt;

    for (size_t i = 0; i < m_cachedResult.items.size(); i++) {
        const InvestigationItem& item = m_cachedResult.items[i];
        if (item.suspicion == SuspicionLevel::None) {
            continue;
        }

        RiskOverviewItem finding;
        finding.moduleId = L"user";
        finding.moduleName = L"用户排查";
        finding.tabIndex = TAB_USERS;
        finding.level = item.suspicion;
        finding.objectName = item.name;
        finding.reason = item.suspicionReason;
        finding.updatedAt = updatedAt;
        finding.sourceKey = item.name;
        finding.sourceRow = (int)i;

        if (item.details.size() > COL_STATUS) {
            finding.info = item.details[COL_STATUS];
        }
        if (item.details.size() > COL_RIDHIJACK) {
            finding.info2 = L"隐藏类型: ";
            if (item.details.size() > COL_HIDDEN) {
                finding.info2 += item.details[COL_HIDDEN];
            }
            finding.info2 += L"; RID劫持: " + item.details[COL_RIDHIJACK];
        }

        findings.push_back(finding);
    }

    return findings;
}

std::vector<UserInfo> UserInvestigator::EnumerateLocalUsers() {
    std::vector<UserInfo> result;
    for (const auto& record : wgwc::core::users::CollectUsers({}).records) {
        UserInfo user;
        static_cast<wgwc::core::users::UserRecord&>(user) = record;
        user.hiddenTypes = wgwc::core::users::HiddenTypeText(record);
        result.push_back(std::move(user));
    }
    return result;
}

std::vector<std::wstring> UserInvestigator::GetAdministrators() {
    std::vector<std::wstring> result;
    for (const auto& user : EnumerateLocalUsers())
        if (user.isAdmin)
            result.push_back(user.username);
    return result;
}

std::vector<std::wstring> UserInvestigator::GetHiddenUsers() {
    std::vector<std::wstring> result;
    for (const auto& user : EnumerateLocalUsers())
        if (user.loginUiHidden)
            result.push_back(user.username);
    return result;
}

std::vector<std::wstring> UserInvestigator::GetDollarSuffixUsers() {
    std::vector<std::wstring> result;
    for (const auto& user : EnumerateLocalUsers())
        if (user.dollarHidden)
            result.push_back(user.username);
    return result;
}

std::vector<std::wstring> UserInvestigator::GetHiddenUsersBySAM() {
    std::vector<std::wstring> result;
    for (const auto& user : EnumerateLocalUsers())
        if (user.samApiHidden)
            result.push_back(user.username);
    return result;
}

std::map<std::wstring, RidInfo> UserInvestigator::CheckRidHijacking() {
    std::map<std::wstring, RidInfo> result;
    for (const auto& user : EnumerateLocalUsers()) {
        if (user.ridHijacked)
            result[wgwc::core::users::NormalizeName(user.username)] = { user.username, user.rid, user.hijackedRid };
    }
    return result;
}

DWORD UserInvestigator::GetUserRid(const std::wstring& username) {
    for (const auto& user : EnumerateLocalUsers())
        if (wgwc::core::users::NormalizeName(user.username) == wgwc::core::users::NormalizeName(username))
            return user.rid;
    return 0;
}

SuspicionLevel UserInvestigator::AnalyzeUserSuspicion(const UserInfo& user) {
    return GuiUserLevel(user.assessment.level);
}

bool UserInvestigator::IsUserInAdminGroup(const std::wstring& username) {
    for (const auto& user : EnumerateLocalUsers())
        if (wgwc::core::users::NormalizeName(user.username) == wgwc::core::users::NormalizeName(username))
            return user.adminState == wgwc::core::FieldState::Available && user.isAdmin;
    return false;
}

std::wstring UserInvestigator::GetCurrentUser() {
    wchar_t username[MAX_USERNAME_LENGTH];
    DWORD size = ARRAYSIZE(username);

    if (GetUserNameW(username, &size)) {
        return username;
    }

    return L"";
}

std::wstring UserInvestigator::GetLastErrorMessage(DWORD errorCode) {
    if (errorCode == 0) {
        errorCode = GetLastError();
    }

    wchar_t* msg = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                   errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&msg, 0, nullptr);

    std::wstring result;
    if (msg) {
        result = msg;
        LocalFree(msg);
    } else {
        result = L"未知错误 (0x" + std::to_wstring(errorCode) + L")";
    }

    return result;
}

bool UserInvestigator::IsProtectedUser(const std::wstring& username) const {
    std::wstring lowerName = username;
    for (auto& c : lowerName)
        c = towlower(c);

    // 当前登录用户
    std::wstring currentUser = const_cast<UserInvestigator*>(this)->GetCurrentUser();
    std::wstring lowerCurrent = currentUser;
    for (auto& c : lowerCurrent)
        c = towlower(c);
    if (lowerName == lowerCurrent) {
        return true;
    }

    // 默认管理员账户
    if (lowerName == L"administrator" || lowerName == L"管理员") {
        return true;
    }

    // 来宾账户（Guest）
    if (lowerName == L"guest" || lowerName == L"来宾") {
        return true;
    }

    return false;
}

std::vector<ContextMenuItem> UserInvestigator::GetContextMenuItems(int row) const {
    std::vector<ContextMenuItem> items;

    if (row < 0 || row >= (int)m_cachedUsers.size()) {
        return items;
    }

    const auto& user = m_cachedUsers[row];

    if (m_cachedResult.stale || user.metadataState != wgwc::core::FieldState::Available) {
        items.push_back({ IDM_USER_OPEN_MGR, L"本地用户管理", false, L"" });
        return items;
    }

    // 根据用户状态添加启用/禁用菜单
    if (user.isDisabled) {
        ContextMenuItem enableItem;
        enableItem.id = IDM_USER_ENABLE;
        enableItem.text = L"启用用户";
        enableItem.requireConfirm = true;
        enableItem.confirmMsg = L"确定要启用用户 \"" + user.username + L"\" 吗？";
        items.push_back(enableItem);
    } else {
        // 不允许禁用当前登录用户
        std::wstring currentUser = const_cast<UserInvestigator*>(this)->GetCurrentUser();
        std::wstring lowerCurrent = currentUser;
        std::wstring lowerTarget = user.username;
        for (auto& c : lowerCurrent)
            c = towlower(c);
        for (auto& c : lowerTarget)
            c = towlower(c);

        if (lowerCurrent != lowerTarget) {
            ContextMenuItem disableItem;
            disableItem.id = IDM_USER_DISABLE;
            disableItem.text = L"禁用用户";
            disableItem.requireConfirm = true;
            disableItem.confirmMsg = L"确定要禁用用户 \"" + user.username + L"\" 吗？";
            items.push_back(disableItem);
        }
    }

    // 删除用户（受保护用户不显示删除选项）
    if (!IsProtectedUser(user.username)) {
        ContextMenuItem deleteItem;
        deleteItem.id = IDM_USER_DELETE;
        deleteItem.text = L"删除用户";
        deleteItem.requireConfirm = true;
        deleteItem.confirmMsg = L"确定要删除用户 \"" + user.username + L"\" 吗？\n\n此操作不可撤销！";
        items.push_back(deleteItem);
    }

    // 分隔符
    items.push_back({ 0, L"", false, L"" });

    ContextMenuItem mgrItem;
    mgrItem.id = IDM_USER_OPEN_MGR;
    mgrItem.text = L"本地用户管理";
    mgrItem.requireConfirm = false;
    items.push_back(mgrItem);

    return items;
}

bool UserInvestigator::HandleContextMenu(UINT menuId, int row) {
    if (row < 0 || row >= (int)m_cachedUsers.size()) {
        return false;
    }

    const auto& user = m_cachedUsers[row];

    if (menuId != IDM_USER_OPEN_MGR &&
        (m_cachedResult.stale || user.metadataState != wgwc::core::FieldState::Available))
        return false;

    switch (menuId) {
    case IDM_USER_DELETE:
        // 再次检查是否是受保护用户
        if (IsProtectedUser(user.username)) {
            if (m_hMainWnd) {
                MessageBoxW(m_hMainWnd, L"无法删除此用户：该用户受系统保护", L"操作被拒绝", MB_OK | MB_ICONWARNING);
            }
            return false;
        }
        if (DeleteUser(user.username)) {
            if (m_hMainWnd) {
                MessageBoxW(m_hMainWnd, (L"用户 \"" + user.username + L"\" 已成功删除").c_str(), L"成功",
                            MB_OK | MB_ICONINFORMATION);
            }
            return true;
        }
        return false;

    case IDM_USER_DISABLE:
        if (DisableUser(user.username)) {
            if (m_hMainWnd) {
                MessageBoxW(m_hMainWnd, (L"用户 \"" + user.username + L"\" 已被禁用").c_str(), L"成功",
                            MB_OK | MB_ICONINFORMATION);
            }
            return true;
        }
        return false;

    case IDM_USER_ENABLE:
        if (EnableUser(user.username)) {
            if (m_hMainWnd) {
                MessageBoxW(m_hMainWnd, (L"用户 \"" + user.username + L"\" 已被启用").c_str(), L"成功",
                            MB_OK | MB_ICONINFORMATION);
            }
            return true;
        }
        return false;

    case IDM_USER_OPEN_MGR:
        ShellExecuteW(NULL, L"open", L"lusrmgr.msc", NULL, NULL, SW_SHOWNORMAL);
        return false;
    }

    return false;
}

// 删除用户
bool UserInvestigator::DeleteUser(const std::wstring& username) {
    NET_API_STATUS status = NetUserDel(nullptr, username.c_str());

    if (status != NERR_Success) {
        if (m_hMainWnd) {
            std::wstring errMsg = L"删除用户失败: " + GetLastErrorMessage(status);
            MessageBoxW(m_hMainWnd, errMsg.c_str(), L"错误", MB_OK | MB_ICONERROR);
        }
        return false;
    }

    return true;
}

// 禁用用户
bool UserInvestigator::DisableUser(const std::wstring& username) {
    USER_INFO_1008 ui;
    ui.usri1008_flags = UF_ACCOUNTDISABLE;

    // 先获取当前flags
    USER_INFO_1* userInfo = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, username.c_str(), 1, (LPBYTE*)&userInfo);

    if (status == NERR_Success && userInfo) {
        ui.usri1008_flags = userInfo->usri1_flags | UF_ACCOUNTDISABLE;
        NetApiBufferFree(userInfo);
    }

    status = NetUserSetInfo(nullptr, username.c_str(), 1008, (LPBYTE)&ui, nullptr);

    if (status != NERR_Success) {
        if (m_hMainWnd) {
            std::wstring errMsg = L"禁用用户失败: " + GetLastErrorMessage(status);
            MessageBoxW(m_hMainWnd, errMsg.c_str(), L"错误", MB_OK | MB_ICONERROR);
        }
        return false;
    }

    return true;
}

// 启用用户
bool UserInvestigator::EnableUser(const std::wstring& username) {
    USER_INFO_1008 ui;

    // 先获取当前flags
    USER_INFO_1* userInfo = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, username.c_str(), 1, (LPBYTE*)&userInfo);

    if (status == NERR_Success && userInfo) {
        ui.usri1008_flags = userInfo->usri1_flags & ~UF_ACCOUNTDISABLE;
        NetApiBufferFree(userInfo);
    } else {
        ui.usri1008_flags = UF_SCRIPT; // 默认值
    }

    status = NetUserSetInfo(nullptr, username.c_str(), 1008, (LPBYTE)&ui, nullptr);

    if (status != NERR_Success) {
        if (m_hMainWnd) {
            std::wstring errMsg = L"启用用户失败: " + GetLastErrorMessage(status);
            MessageBoxW(m_hMainWnd, errMsg.c_str(), L"错误", MB_OK | MB_ICONERROR);
        }
        return false;
    }

    return true;
}
