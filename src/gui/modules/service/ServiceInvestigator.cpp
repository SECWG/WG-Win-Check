#include "../../presentation/GuiColumns.h"
// ServiceInvestigator.cpp - 服务排查模块实现

#include "../../../core/system/Win32.h"
#include "ServiceInvestigator.h"
#include "../../common/ListViewSupport.h"
#include "../../../core/modules/service/ServiceModule.h"
#include "../../../core/modules/service/ServiceActions.h"

#include "../../resources/resource.h"
#include <algorithm>
#include <commctrl.h>
#include <wintrust.h>
#include <softpub.h>
#include <shellapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "wintrust.lib")

// 静态列定义
const ColumnDef ServiceInvestigator::s_Columns[] = { WG_COLUMNS_SERVICE };
const int ServiceInvestigator::s_ColumnCount = sizeof(s_Columns) / sizeof(s_Columns[0]);

static std::wstring ServiceStateToRiskString(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED:
        return L"已停止";
    case SERVICE_START_PENDING:
        return L"启动中";
    case SERVICE_STOP_PENDING:
        return L"停止中";
    case SERVICE_RUNNING:
        return L"运行中";
    case SERVICE_CONTINUE_PENDING:
        return L"继续中";
    case SERVICE_PAUSE_PENDING:
        return L"暂停中";
    case SERVICE_PAUSED:
        return L"已暂停";
    default:
        return L"未知";
    }
}

static std::wstring ServiceStartTypeToRiskString(DWORD startType) {
    switch (startType) {
    case SERVICE_AUTO_START:
        return L"自动";
    case SERVICE_DEMAND_START:
        return L"手动";
    case SERVICE_DISABLED:
        return L"禁用";
    case SERVICE_BOOT_START:
        return L"启动";
    case SERVICE_SYSTEM_START:
        return L"系统";
    default:
        return L"未知";
    }
}

static std::wstring ServiceAssociatedFile(const ServiceInfo& info) {
    return info.associatedFile;
}

ServiceInvestigator::ServiceInvestigator()
    : m_hComboType(NULL), m_hComboSignature(NULL), m_hComboStartType(NULL), m_hComboState(NULL), m_hStaticKeyword(NULL),
      m_hEditFilter(NULL), m_hBtnFilter(NULL), m_hBtnRefresh(NULL), m_hMainWnd(NULL), m_hListView(NULL), m_hInst(NULL) {
}

ServiceInvestigator::~ServiceInvestigator() {
    DestroyToolbar();
}

std::wstring ServiceInvestigator::StateToString(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED:
        return L"已停止";
    case SERVICE_START_PENDING:
        return L"启动中";
    case SERVICE_STOP_PENDING:
        return L"停止中";
    case SERVICE_RUNNING:
        return L"运行中";
    case SERVICE_CONTINUE_PENDING:
        return L"继续中";
    case SERVICE_PAUSE_PENDING:
        return L"暂停中";
    case SERVICE_PAUSED:
        return L"已暂停";
    default:
        return L"未知";
    }
}

std::wstring ServiceInvestigator::StartTypeToString(DWORD startType) {
    switch (startType) {
    case SERVICE_AUTO_START:
        return L"自动";
    case SERVICE_BOOT_START:
        return L"启动";
    case SERVICE_DEMAND_START:
        return L"手动";
    case SERVICE_DISABLED:
        return L"禁用";
    case SERVICE_SYSTEM_START:
        return L"系统";
    default:
        return L"未知";
    }
}

bool ServiceInvestigator::IsMicrosoftService(const std::wstring& companyName) {
    return wgwc::core::services::IsMicrosoftGroup(companyName);
}

InvestigationResult ServiceInvestigator::Investigate(bool resetFilter) {
    auto context = MakeCollectionContext();
    const auto collectedAt = RiskOverviewNowString();
    return ApplyCollection(wgwc::core::services::CollectServices({}, context), resetFilter, collectedAt);
}

InvestigationResult
ServiceInvestigator::ApplyCollection(const wgwc::core::CollectionResult<wgwc::core::services::Record>& collection,
                                     bool resetFilter, const std::wstring& collectedAt) {
    wgwc::gui::ApplyCollectionOutcome(m_cachedResult, collection, m_hasCache, L"服务采集失败",
                                      L"部分来源或文件信息不可读取");
    m_collectionStale = m_cachedResult.stale;
    m_collectionError = m_cachedResult.errorCode;
    m_collectionMessage = m_cachedResult.errorMessage;
    if (!m_cachedResult.success)
        return RefreshFromCache();
    m_allServices.clear();
    m_collectedAt = collectedAt.empty() ? RiskOverviewNowString() : collectedAt;
    for (const auto& record : collection.records) {
        ServiceInfo info{};
        info.serviceName = record.serviceName;
        info.displayName = record.displayName;
        info.statusKnown = record.statusState == wgwc::core::FieldState::Available;
        info.controlsAccepted = info.statusKnown ? record.controlsAccepted : 0;
        info.configKnown = record.configState == wgwc::core::FieldState::Available;
        info.currentState = info.statusKnown ? record.currentState : 0;
        info.startType = info.configKnown ? record.startType : SERVICE_NO_CHANGE;
        info.processId = record.pidState == wgwc::core::FieldState::Available ? record.processId : 0;
        info.binaryPath = record.binaryPath;
        info.filePath = record.executablePath;
        info.serviceDll = record.serviceDll;
        info.associatedFile = record.associatedFile;
        info.description = record.description;
        info.companyName = record.file.evidence.company;
        info.fileModifyTime = record.file.modifiedAt ? wgwc::core::files::LocalTimeText(record.file.modifiedAt) : L"";
        info.signatureState = record.file.evidence.signature;
        if (record.file.evidence.signatureState == wgwc::core::FieldState::Available)
            info.signatureInfo = CommonUtils::FormatSignatureText(info.signatureState, record.file.evidence.publisher);
        info.risk = ToModuleRiskLevel(record.assessment.level);
        info.riskReason = wgwc::core::services::RiskReasons(record.assessment);
        m_allServices.push_back(std::move(info));
    }
    std::sort(m_allServices.begin(), m_allServices.end(), [](const auto& left, const auto& right) {
        return _wcsicmp(left.serviceName.c_str(), right.serviceName.c_str()) < 0;
    });
    m_filteredServices.clear();

    // 根据参数决定是否重置过滤条件
    if (resetFilter) {
        // 设置默认过滤条件：类型=第三方，签名=全部，启动=全部，状态=全部
        if (m_hComboType)
            SendMessage(m_hComboType, CB_SETCURSEL, 2, 0); // 第三方服务
        if (m_hComboSignature)
            SendMessage(m_hComboSignature, CB_SETCURSEL, 0, 0); // 全部
        if (m_hComboStartType)
            SendMessage(m_hComboStartType, CB_SETCURSEL, 0, 0); // 全部
        if (m_hComboState)
            SendMessage(m_hComboState, CB_SETCURSEL, 0, 0); // 全部
        if (m_hEditFilter)
            SetWindowTextW(m_hEditFilter, L"");
    }
    // 如果 resetFilter = false，则保持当前控件的值不变

    // 标记缓存有效（缓存的是全部数据m_allServices）
    m_hasCache = true;

    // 应用当前过滤并返回结果
    return RefreshFromCache();
}

// 从缓存刷新（重新应用当前过滤条件）
InvestigationResult ServiceInvestigator::RefreshFromCache() {
    InvestigationResult result;
    result.moduleName = L"ServiceInvestigator";
    result.success = m_cachedResult.success;
    result.partial = m_cachedResult.partial;
    result.stale = m_cachedResult.stale;
    result.errorCode = m_collectionError;
    result.errorMessage = m_collectionMessage;
    result.totalCount = 0;
    result.suspiciousCount = 0;

    // 构建结果时只过滤数据，由主窗口统一绘制。
    ApplyFilter(false);

    for (size_t i = 0; i < m_filteredServices.size(); i++) {
        const ServiceInfo& info = m_filteredServices[i];

        InvestigationItem item;
        item.name = info.serviceName;
        item.description = info.displayName;

        // 填充各列数据
        item.details.push_back(info.serviceName);
        item.details.push_back(info.displayName);

        // PID列
        if (info.processId > 0) {
            item.details.push_back(std::to_wstring(info.processId));
        } else {
            item.details.push_back(L"");
        }

        item.details.push_back(StateToString(info.currentState));
        item.details.push_back(StartTypeToString(info.startType));
        item.details.push_back(info.binaryPath);

        // 关联文件（如果是 svchost 服务，显示 DLL 路径）
        std::wstring displayPath = ServiceAssociatedFile(info);
        item.details.push_back(displayPath);

        item.details.push_back(info.companyName);
        item.details.push_back(info.description);
        item.details.push_back(info.fileModifyTime);
        item.details.push_back(info.signatureInfo);

        // 风险描述：正常显示为空，有风险显示拼接的原因
        std::wstring riskText;
        if (info.risk != ServiceRiskLevel::None && !info.riskReason.empty()) {
            riskText = info.riskReason;
        }
        item.details.push_back(riskText);

        item.suspicion = ToModuleRiskLevel(info.risk);
        item.suspicionReason = info.riskReason;

        result.items.push_back(item);
        result.totalCount++;

        if (info.risk != ServiceRiskLevel::None) {
            result.suspiciousCount++;
        }
    }

    m_cachedResult = result;

    return result;
}

std::vector<RiskOverviewItem> ServiceInvestigator::GetRiskFindings() const {
    std::vector<RiskOverviewItem> findings;
    if (!m_hasCache) {
        return findings;
    }

    const std::wstring& updatedAt = m_collectedAt;

    for (size_t i = 0; i < m_allServices.size(); i++) {
        const ServiceInfo& info = m_allServices[i];
        SuspicionLevel level = ToModuleRiskLevel(info.risk);
        if (level == SuspicionLevel::None) {
            continue;
        }

        std::wstring displayPath = ServiceAssociatedFile(info);

        RiskOverviewItem finding;
        finding.moduleId = L"service";
        finding.moduleName = L"服务排查";
        finding.tabIndex = TAB_SERVICES;
        finding.level = level;
        finding.objectName = info.serviceName;
        finding.info = ServiceStateToRiskString(info.currentState) + L" / " +
                       ServiceStartTypeToRiskString(info.startType) + L" / PID: " + std::to_wstring(info.processId);
        finding.info2 = displayPath;
        finding.reason = info.riskReason;
        finding.updatedAt = updatedAt;
        finding.sourceKey = info.serviceName;
        finding.sourceRow = (int)i;

        findings.push_back(finding);
    }

    return findings;
}

std::wstring ServiceInvestigator::GetRowIconPath(int row, const InvestigationItem& item) const {
    if (row >= 0 && row < (int)m_filteredServices.size()) {
        return ServiceAssociatedFile(m_filteredServices[row]);
    }
    if (item.details.size() > COL_RELATED_FILE && !item.details[COL_RELATED_FILE].empty()) {
        return item.details[COL_RELATED_FILE];
    }
    if (item.details.size() > COL_PATH) {
        return item.details[COL_PATH];
    }
    return L"";
}

std::wstring ServiceInvestigator::GetContextFilePath(int row) const {
    if (row < 0 || row >= (int)m_filteredServices.size())
        return L"";
    return ServiceAssociatedFile(m_filteredServices[row]);
}

bool ServiceInvestigator::GetCellHighlight(int row, int col, const InvestigationResult&, COLORREF& outColor) const {
    (void)col;
    // 与显示行共用当前筛选缓存，不再单独维护按行号映射的风险状态。
    const auto& items = m_cachedResult.items;
    if (row < 0 || static_cast<size_t>(row) >= items.size())
        return false;

    switch (items[static_cast<size_t>(row)].suspicion) {
    case SuspicionLevel::High:
        outColor = RGB(255, 0, 0); // 红色
        return true;
    case SuspicionLevel::Medium:
        outColor = RGB(255, 128, 0); // 橙色
        return true;
    case SuspicionLevel::Low:
        outColor = RGB(128, 128, 0); // 暗黄色
        return true;
    default:
        return false;
    }
}

// 应用过滤
void ServiceInvestigator::ApplyFilter(bool updateUi) {
    if (!updateUi) {
        m_filteredServices.clear();
        // 本次遍历只读取一遍控件，全部记录使用同一组筛选条件。
        int typeSel = m_hComboType ? (int)SendMessage(m_hComboType, CB_GETCURSEL, 0, 0) : 2;
        int sigSel = m_hComboSignature ? (int)SendMessage(m_hComboSignature, CB_GETCURSEL, 0, 0) : 0;
        int startSel = m_hComboStartType ? (int)SendMessage(m_hComboStartType, CB_GETCURSEL, 0, 0) : 0;
        int stateSel = m_hComboState ? (int)SendMessage(m_hComboState, CB_GETCURSEL, 0, 0) : 0;
        if (typeSel == CB_ERR)
            typeSel = 2;
        if (sigSel == CB_ERR)
            sigSel = 0;
        if (startSel == CB_ERR)
            startSel = 0;
        if (stateSel == CB_ERR)
            stateSel = 0;

        wchar_t keyword[256] = { 0 };
        GetWindowTextW(m_hEditFilter, keyword, 256);
        std::wstring lowerKeyword = CommonUtils::ToLower(keyword);

        const auto matches = [&](const ServiceInfo& info) {
            // 类型过滤: 0=全部, 1=微软, 2=非微软
            bool isMicrosoft = IsMicrosoftService(info.companyName);
            if (typeSel == 1 && !isMicrosoft)
                return false;
            if (typeSel == 2 && isMicrosoft)
                return false;

            if (!CommonUtils::MatchSignatureFilter(info.signatureState, sigSel))
                return false;

            // 启动类型过滤: 0=全部, 1=自动, 2=手动, 3=禁用
            if (startSel != 0 && !info.configKnown)
                return false;
            if (startSel == 1 && !wgwc::core::services::IsAutoStart(info.startType))
                return false;
            if (startSel == 2 && info.startType != SERVICE_DEMAND_START)
                return false;
            if (startSel == 3 && info.startType != SERVICE_DISABLED)
                return false;

            // 状态过滤: 0=全部, 1=运行中, 2=已停止
            if (stateSel != 0 && !info.statusKnown)
                return false;
            if (stateSel == 1 && info.currentState != SERVICE_RUNNING)
                return false;
            if (stateSel == 2 && info.currentState != SERVICE_STOPPED)
                return false;

            // 关键字过滤
            if (!lowerKeyword.empty()) {
                bool match = false;

                if (CommonUtils::ToLower(info.serviceName).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.displayName).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.binaryPath).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.filePath).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.serviceDll).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.companyName).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.description).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.fileModifyTime).find(lowerKeyword) != std::wstring::npos)
                    match = true;

                if (!match)
                    return false;
            }

            return true;
        };
        for (const auto& info : m_allServices)
            if (matches(info))
                m_filteredServices.push_back(info);
        return;
    }
    RefreshFromCache();
    UpdateListView();
    HWND hStatusBar = GetDlgItem(m_hMainWnd, IDC_STATUSBAR);
    if (hStatusBar) {
        wchar_t message[256];
        swprintf_s(message, L"从 %zu 个服务中 过滤 %zu 个 结果", m_allServices.size(), m_filteredServices.size());
        std::wstring text = message;
        if (!m_collectionMessage.empty())
            text += L"（" + m_collectionMessage + L"）";
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)text.c_str());
    }
}

void ServiceInvestigator::UpdateListView() {
    // 列表直接使用缓存中的展示行，避免字段和着色来源各自维护。
    wgwc::gui::PopulateCachedListView(m_hListView, m_cachedResult);
}

void ServiceInvestigator::CreateToolbar(HWND hParent, HINSTANCE hInst) {
    m_hMainWnd = hParent;
    m_hInst = hInst;

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    int baseY = 33;
    int x = 5;

    // 类型下拉框
    m_hComboType = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, x,
                                   baseY + 1, 90, 200, hParent, (HMENU)IDC_SVC_COMBO_TYPE, hInst, NULL);
    SendMessage(m_hComboType, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"类型:全部");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"微软服务");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"第三方服务");
    SendMessage(m_hComboType, CB_SETCURSEL, 2, 0); // 默认第三方服务
    x += 95;

    // 签名下拉框
    m_hComboSignature = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, x,
                                        baseY + 1, 85, 200, hParent, (HMENU)IDC_SVC_COMBO_SIGNATURE, hInst, NULL);
    SendMessage(m_hComboSignature, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboSignature, CB_ADDSTRING, 0, (LPARAM)L"签名:全部");
    SendMessage(m_hComboSignature, CB_ADDSTRING, 0, (LPARAM)L"已签名");
    SendMessage(m_hComboSignature, CB_ADDSTRING, 0, (LPARAM)L"未匹配");
    SendMessage(m_hComboSignature, CB_ADDSTRING, 0, (LPARAM)L"未签名");
    SendMessage(m_hComboSignature, CB_ADDSTRING, 0, (LPARAM)L"其他");
    SendMessage(m_hComboSignature, CB_SETCURSEL, 0, 0);
    x += 90;

    // 启动类型下拉框
    m_hComboStartType = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, x,
                                        baseY + 1, 80, 200, hParent, (HMENU)IDC_SVC_COMBO_START_TYPE, hInst, NULL);
    SendMessage(m_hComboStartType, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboStartType, CB_ADDSTRING, 0, (LPARAM)L"启动:全部");
    SendMessage(m_hComboStartType, CB_ADDSTRING, 0, (LPARAM)L"自动");
    SendMessage(m_hComboStartType, CB_ADDSTRING, 0, (LPARAM)L"手动");
    SendMessage(m_hComboStartType, CB_ADDSTRING, 0, (LPARAM)L"禁用");
    SendMessage(m_hComboStartType, CB_SETCURSEL, 0, 0);
    x += 85;

    // 状态下拉框
    m_hComboState = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, x,
                                    baseY + 1, 85, 200, hParent, (HMENU)IDC_SVC_COMBO_STATE, hInst, NULL);
    SendMessage(m_hComboState, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)L"状态:全部");
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)L"运行中");
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)L"已停止");
    SendMessage(m_hComboState, CB_SETCURSEL, 0, 0); // 默认全部
    x += 90;

    // 关键字标签
    m_hStaticKeyword = CreateWindowExW(0, L"STATIC", L"过滤:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, x, baseY, 35, 22,
                                       hParent, (HMENU)IDC_SVC_STATIC_KEYWORD, hInst, NULL);
    SendMessage(m_hStaticKeyword, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 38;

    // 关键字输入框
    m_hEditFilter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, x, baseY,
                                    100, 22, hParent, (HMENU)IDC_SVC_EDIT_FILTER, hInst, NULL);
    SendMessage(m_hEditFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 105;

    m_hBtnFilter = CreateWindowExW(0, L"BUTTON", L"过滤", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 50, 22,
                                   hParent, (HMENU)IDC_SVC_BTN_FILTER, hInst, NULL);
    SendMessage(m_hBtnFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 55;

    // 刷新按钮
    m_hBtnRefresh = CreateWindowExW(0, L"BUTTON", L"刷新", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 50, 22,
                                    hParent, (HMENU)IDC_SVC_BTN_REFRESH, hInst, NULL);
    SendMessage(m_hBtnRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 55;

    m_hBtnManager = CreateWindowExW(0, L"BUTTON", L"服务管理", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 80, 22,
                                    hParent, (HMENU)IDC_SVC_BTN_MANAGER, hInst, NULL);
    SendMessage(m_hBtnManager, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 初始隐藏所有控件
    ShowToolbar(false);
}

void ServiceInvestigator::DestroyToolbar() {
    if (m_hComboType) {
        DestroyWindow(m_hComboType);
        m_hComboType = NULL;
    }
    if (m_hComboSignature) {
        DestroyWindow(m_hComboSignature);
        m_hComboSignature = NULL;
    }
    if (m_hComboStartType) {
        DestroyWindow(m_hComboStartType);
        m_hComboStartType = NULL;
    }
    if (m_hComboState) {
        DestroyWindow(m_hComboState);
        m_hComboState = NULL;
    }
    if (m_hStaticKeyword) {
        DestroyWindow(m_hStaticKeyword);
        m_hStaticKeyword = NULL;
    }
    if (m_hEditFilter) {
        DestroyWindow(m_hEditFilter);
        m_hEditFilter = NULL;
    }
    if (m_hBtnFilter) {
        DestroyWindow(m_hBtnFilter);
        m_hBtnFilter = NULL;
    }
    if (m_hBtnRefresh) {
        DestroyWindow(m_hBtnRefresh);
        m_hBtnRefresh = NULL;
    }
    if (m_hBtnManager) {
        DestroyWindow(m_hBtnManager);
        m_hBtnManager = NULL;
    }
}

void ServiceInvestigator::ShowToolbar(bool show) {
    int cmd = show ? SW_SHOW : SW_HIDE;
    if (m_hComboType)
        ShowWindow(m_hComboType, cmd);
    if (m_hComboSignature)
        ShowWindow(m_hComboSignature, cmd);
    if (m_hComboStartType)
        ShowWindow(m_hComboStartType, cmd);
    if (m_hComboState)
        ShowWindow(m_hComboState, cmd);
    if (m_hStaticKeyword)
        ShowWindow(m_hStaticKeyword, cmd);
    if (m_hEditFilter)
        ShowWindow(m_hEditFilter, cmd);
    if (m_hBtnFilter)
        ShowWindow(m_hBtnFilter, cmd);
    if (m_hBtnRefresh)
        ShowWindow(m_hBtnRefresh, cmd);
    if (m_hBtnManager)
        ShowWindow(m_hBtnManager, cmd);
}

void ServiceInvestigator::ResizeToolbar(int x, int y, int width) {
    (void)x;
    (void)width;
    int baseY = y + 5;
    int posX = 5;

    if (m_hComboType)
        SetWindowPos(m_hComboType, NULL, posX, baseY + 1, 90, 200, SWP_NOZORDER);
    posX += 95;
    if (m_hComboSignature)
        SetWindowPos(m_hComboSignature, NULL, posX, baseY + 1, 85, 200, SWP_NOZORDER);
    posX += 95;
    if (m_hComboStartType)
        SetWindowPos(m_hComboStartType, NULL, posX, baseY + 1, 80, 200, SWP_NOZORDER);
    posX += 85;
    if (m_hComboState)
        SetWindowPos(m_hComboState, NULL, posX, baseY + 1, 85, 200, SWP_NOZORDER);
    posX += 90;
    if (m_hStaticKeyword)
        SetWindowPos(m_hStaticKeyword, NULL, posX, baseY, 35, 22, SWP_NOZORDER);
    posX += 38;
    if (m_hEditFilter)
        SetWindowPos(m_hEditFilter, NULL, posX, baseY, 100, 22, SWP_NOZORDER);
    posX += 105;
    if (m_hBtnFilter)
        SetWindowPos(m_hBtnFilter, NULL, posX, baseY, 50, 22, SWP_NOZORDER);
    posX += 55;
    if (m_hBtnRefresh)
        SetWindowPos(m_hBtnRefresh, NULL, posX, baseY, 50, 22, SWP_NOZORDER);
    posX += 55;
    if (m_hBtnManager)
        SetWindowPos(m_hBtnManager, NULL, posX, baseY, 80, 22, SWP_NOZORDER);
}

bool ServiceInvestigator::HandleToolbarCommand(WORD id, WORD code) {
    switch (id) {
    case IDC_SVC_BTN_FILTER:
        ApplyFilter();
        if (m_hListView)
            SetFocus(m_hListView);
        return true;

    case IDC_SVC_BTN_REFRESH:
        // 触发重新扫描
        if (m_hMainWnd) {
            PostMessage(m_hMainWnd, WM_COMMAND, MAKEWPARAM(IDM_REFRESH_KEEP_FILTER, 0), 0);
        }
        if (m_hListView)
            SetFocus(m_hListView);
        return true;

    case IDC_SVC_BTN_MANAGER:
        OpenServicesManager();
        return true;

    case IDC_SVC_COMBO_TYPE:
    case IDC_SVC_COMBO_SIGNATURE:
    case IDC_SVC_COMBO_START_TYPE:
    case IDC_SVC_COMBO_STATE:
        // 下拉框选择变化时自动过滤
        if (code == CBN_SELCHANGE) {
            ApplyFilter();
            return true;
        }
        break;
    }

    return false;
}

// 右键菜单功能

std::vector<ContextMenuItem> ServiceInvestigator::GetContextMenuItems(int row) const {
    std::vector<ContextMenuItem> items;

    if (row < 0 || row >= (int)m_filteredServices.size()) {
        return items;
    }

    const ServiceInfo& info = m_filteredServices[row];

    items.push_back({ IDM_SVC_OPEN_REG_LOC, L"注册表位置", false, L"" });

    // 分隔符
    items.push_back({ 0, L"", false, L"" });

    if (m_collectionStale || !info.configKnown || !info.statusKnown)
        return items;

    // 服务操作类菜单 - 根据状态决定是否添加
    const bool canStart = info.currentState == SERVICE_STOPPED && info.startType != SERVICE_DISABLED;
    const bool canStop = (info.currentState == SERVICE_RUNNING || info.currentState == SERVICE_PAUSED) &&
                         (info.controlsAccepted & SERVICE_ACCEPT_STOP) != 0;
    const bool canSetAuto = info.startType != SERVICE_AUTO_START;
    const bool canSetManual = info.startType != SERVICE_DEMAND_START;
    const bool canDisable = info.startType != SERVICE_DISABLED;
    const bool canDelete = info.currentState == SERVICE_STOPPED;

    if (canStart) {
        items.push_back({ IDM_SVC_START, L"启动服务", false, L"" });
    }
    if (canStop) {
        items.push_back({ IDM_SVC_STOP, L"停止服务", false, L"" });
    }
    if (canSetAuto) {
        items.push_back({ IDM_SVC_SET_AUTO, L"设为自动", false, L"" });
    }
    if (canSetManual) {
        items.push_back({ IDM_SVC_SET_MANUAL, L"设为手动", false, L"" });
    }
    if (canDisable) {
        items.push_back(
            { IDM_SVC_DISABLE, L"禁用服务", true,
              L"确定要禁用服务 " + info.serviceName + L" 吗？\n\n禁用后服务将无法启动，已运行的服务不会因此停止。" });
    }
    if (canDelete) {
        items.push_back({ IDM_SVC_DELETE, L"删除服务", true,
                          L"确定要删除服务 " + info.serviceName + L" 吗？\n\n此操作不可恢复！" });
    }

    return items;
}

bool ServiceInvestigator::HandleContextMenu(UINT menuId, int row) {
    if (row < 0 || row >= (int)m_filteredServices.size()) {
        return false;
    }

    const ServiceInfo& info = m_filteredServices[row];
    if (menuId >= IDM_SVC_START && menuId <= IDM_SVC_DELETE &&
        (m_collectionStale || !info.configKnown || !info.statusKnown))
        return false;

    switch (menuId) {
    case IDM_SVC_OPEN_REG_LOC:
        OpenRegistryLocation(info.serviceName);
        return false; // 不需要刷新

    case IDM_SVC_START:
    case IDM_SVC_STOP:
    case IDM_SVC_SET_AUTO:
    case IDM_SVC_SET_MANUAL:
    case IDM_SVC_DISABLE:
    case IDM_SVC_DELETE:
        return ExecuteServiceAction(menuId, info);
    }

    return false;
}

void ServiceInvestigator::OpenRegistryLocation(const std::wstring& serviceName) {
    if (serviceName.empty())
        return;

    std::wstring regPath = L"计算机\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" + serviceName;

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit", 0,
                      KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"LastKey", 0, REG_SZ, (LPBYTE)regPath.c_str(),
                       (DWORD)((regPath.length() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }

    ShellExecuteW(NULL, L"open", L"regedit.exe", NULL, NULL, SW_SHOWNORMAL);
}

// 服务操作：依据当前状态执行，并区分请求提交与最终状态。
bool ServiceInvestigator::ExecuteServiceAction(UINT menuId, const ServiceInfo& info) {
    namespace actions = wgwc::core::services::actions;
    actions::Operation operation;
    const wchar_t* actionName = nullptr;
    const wchar_t* acceptedText = nullptr;
    switch (menuId) {
    case IDM_SVC_START:
        operation = actions::Operation::Start;
        actionName = L"启动服务";
        acceptedText = L"已发送启动请求";
        break;
    case IDM_SVC_STOP:
        operation = actions::Operation::Stop;
        actionName = L"停止服务";
        acceptedText = L"已发送停止请求";
        break;
    case IDM_SVC_SET_AUTO:
        operation = actions::Operation::SetAuto;
        actionName = L"设置自动启动";
        acceptedText = L"已设为自动启动";
        break;
    case IDM_SVC_SET_MANUAL:
        operation = actions::Operation::SetManual;
        actionName = L"设置手动启动";
        acceptedText = L"已设为手动启动";
        break;
    case IDM_SVC_DISABLE:
        operation = actions::Operation::Disable;
        actionName = L"禁用服务";
        acceptedText = L"服务已禁用（不会停止已运行的服务）";
        break;
    case IDM_SVC_DELETE:
        operation = actions::Operation::Delete;
        actionName = L"删除服务";
        acceptedText = L"服务已标记删除";
        break;
    default:
        return false;
    }

    const auto result = actions::Execute(info.serviceName, operation);
    std::wstring message;
    switch (result.outcome) {
    case actions::Outcome::Accepted:
    case actions::Outcome::Applied:
        message = acceptedText;
        break;
    case actions::Outcome::AlreadySatisfied:
        message = operation == actions::Operation::Start
                      ? L"服务已在运行，无需重复启动"
                      : (operation == actions::Operation::Stop ? L"服务已停止，无需重复停止" : L"服务已标记删除");
        break;
    case actions::Outcome::NotReady:
        message = std::wstring(L"未执行") + actionName + L"：当前状态为" + StateToString(result.currentState);
        if (operation == actions::Operation::Delete)
            message += L"，仅允许删除已停止的服务";
        break;
    case actions::Outcome::StopUnsupported:
        message = L"服务当前不接受停止请求，未执行停止";
        break;
    case actions::Outcome::Failed:
        message = std::wstring(actionName) + L"失败，错误码: " + std::to_wstring(result.error);
        break;
    }
    const HWND statusBar = GetDlgItem(m_hMainWnd, IDC_STATUSBAR);
    if (statusBar)
        SendMessageW(statusBar, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(message.c_str()));
    // 已接受的修改和过期观测均触发刷新；权限错误则不触发
    // 可能开销较大的重复采集。
    return result.outcome != actions::Outcome::Failed || result.error == ERROR_SERVICE_DOES_NOT_EXIST;
}

void ServiceInvestigator::OpenServicesManager() {
    ShellExecuteW(NULL, L"open", L"services.msc", NULL, NULL, SW_SHOWNORMAL);
}
