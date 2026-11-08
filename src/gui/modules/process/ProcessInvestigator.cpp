#include "../../presentation/GuiColumns.h"
// ProcessInvestigator.cpp - 进程排查模块实现

#include "ProcessInvestigator.h"
#include "../../../core/modules/process/ProcessActions.h"
#include "../../../core/modules/process/ProcessModule.h"

#include "../../resources/resource.h"
#include <sddl.h>
#include <algorithm>
#include <sstream>
#include <unordered_map>
#include <winternl.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "wintrust.lib")

// 静态列定义
const ColumnDef ProcessInvestigator::s_Columns[] = { WG_COLUMNS_PROCESS };
const int ProcessInvestigator::s_ColumnCount = sizeof(s_Columns) / sizeof(s_Columns[0]);

ProcessInvestigator::ProcessInvestigator()
    : m_hToolbarPanel(NULL), m_hComboType(NULL), m_hComboSign(NULL), m_hStaticFilter(NULL), m_hEditFilter(NULL),
      m_hBtnFilter(NULL), m_hBtnRefresh(NULL), m_hMainWnd(NULL), m_hListView(NULL), m_hInst(NULL), m_filterType(0),
      m_filterSign(0) // 默认全部
{
    wchar_t buf[MAX_PATH];
    GetSystemDirectoryW(buf, MAX_PATH);
    m_system32Path = buf;

    if (GetWindowsDirectoryW(buf, MAX_PATH) > 0) {
        m_windowsPath = buf;
    }

    // 构建SysWOW64路径（64位系统上存放32位程序的目录）
    // 在64位Windows上：C:\Windows\SysWOW64
    // 在32位Windows上：不存在此目录
    m_sysWow64Path = m_windowsPath + L"\\SysWOW64";
}

ProcessInvestigator::~ProcessInvestigator() {
    DestroyToolbar();
}

std::wstring ProcessInvestigator::GetSystem32Path() {
    return m_system32Path;
}

std::wstring ProcessInvestigator::GetWindowsPath() {
    return m_windowsPath;
}

bool ProcessInvestigator::IsSystemProcess(const std::wstring& name) {
    return wgwc::core::process::IsSystemProcess(name);
}

// 检查是否是微软进程（公司名包含Microsoft）
bool ProcessInvestigator::IsMicrosoftProcess(const std::wstring& companyName) {
    if (companyName.empty()) {
        return false;
    }
    std::wstring lowerCompany = CommonUtils::ToLower(companyName);
    return lowerCompany.find(L"microsoft") != std::wstring::npos;
}

bool ProcessInvestigator::IsValidSystemProcessPath(const std::wstring& name, const std::wstring& path) {
    return wgwc::core::process::IsValidSystemProcessPath(name, path, { m_system32Path, m_sysWow64Path, m_windowsPath });
}

bool ProcessInvestigator::IsSuspiciousPath(const std::wstring& path) {
    std::wstring lowerPath = CommonUtils::ToLower(path);

    const wchar_t* suspiciousPaths[] = { L"\\temp\\",    L"\\tmp\\",    L"\\appdata\\local\\temp\\", L"\\downloads\\",
                                         L"\\desktop\\", L"\\public\\", L"\\programdata\\",          nullptr };

    for (int i = 0; suspiciousPaths[i] != nullptr; i++) {
        if (lowerPath.find(suspiciousPaths[i]) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

void ProcessInvestigator::AnalyzeRisk(ProcessInfo& proc) {
    wgwc::core::process::Metadata metadata;
    metadata.pid = proc.pid;
    metadata.name = proc.name;
    metadata.path = proc.path;
    metadata.commandLine = proc.commandLine;
    metadata.commandLineState =
        proc.commandLine.empty() ? wgwc::core::FieldState::Unknown : wgwc::core::FieldState::Available;
    auto context = MakeCollectionContext();
    const auto file = wgwc::core::files::QueryFile(proc.path, true, &context);
    const auto risk =
        wgwc::core::process::AssessProcess(metadata, file, { m_system32Path, m_sysWow64Path, m_windowsPath });
    proc.risk = ToModuleRiskLevel(risk.level);
    proc.riskReason = wgwc::core::process::RiskReason(risk);
}

std::vector<ProcessInfo> ProcessInvestigator::ConvertProcesses(
    const wgwc::core::CollectionResult<wgwc::core::process::ProcessRecord>& collected) {
    std::vector<ProcessInfo> processes;
    for (const auto& record : collected.records) {
        const auto& metadata = record.process;
        ProcessInfo proc;
        proc.pid = metadata.pid;
        proc.ppid = metadata.ppid;
        proc.threadCount = metadata.threadCount;
        proc.createdAt = metadata.createdAt;
        proc.name = metadata.name;
        proc.path = metadata.pid == 0 ? L"[System Idle Process]" : (metadata.pid == 4 ? L"[System]" : metadata.path);
        proc.commandLine = metadata.commandLine;
        proc.user = metadata.user;
        proc.startTime = metadata.startTimeLocal;
        proc.parentName = metadata.parentName;
        proc.companyName = record.file.evidence.company;
        proc.description = record.file.description;
        proc.signatureState = record.file.evidence.signature;
        proc.signatureInfo = CommonUtils::FormatSignatureText(proc.signatureState, record.file.evidence.publisher);
        proc.fileModifyTime = wgwc::core::files::LocalTimeText(record.file.modifiedAt);
        proc.risk = ToModuleRiskLevel(record.assessment.level);
        proc.riskReason = wgwc::core::process::RiskReason(record.assessment);
        processes.push_back(std::move(proc));
    }

    m_processCollectionSucceeded = collected.status == wgwc::core::CollectionStatus::Complete ||
                                   collected.status == wgwc::core::CollectionStatus::Partial;
    m_processCollectionPartial = collected.status == wgwc::core::CollectionStatus::Partial;
    m_processCollectionError = 0;
    m_processCollectionMessage.clear();
    for (const auto& issue : collected.issues) {
        if (!issue.affectsCompleteness)
            continue;
        m_processCollectionError = issue.nativeCode;
        m_processCollectionMessage = m_processCollectionSucceeded ? L"部分进程来源未完整采集" : L"无法枚举进程";
        break;
    }

    std::sort(processes.begin(), processes.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
        return a.pid < b.pid;
    });
    return processes;
}

bool ProcessInvestigator::MatchFilter(const ProcessInfo& proc, const std::wstring& filter) {
    if (filter.empty())
        return true;

    std::wstring lowerFilter = CommonUtils::ToLower(filter);

    // PID匹配
    wchar_t pidStr[32];
    swprintf_s(pidStr, L"%lu", proc.pid);
    if (CommonUtils::ToLower(pidStr).find(lowerFilter) != std::wstring::npos)
        return true;

    // PPID匹配
    wchar_t ppidStr[32];
    swprintf_s(ppidStr, L"%lu", proc.ppid);
    if (CommonUtils::ToLower(ppidStr).find(lowerFilter) != std::wstring::npos)
        return true;

    // 进程名匹配
    if (CommonUtils::ToLower(proc.name).find(lowerFilter) != std::wstring::npos)
        return true;

    // 路径匹配
    if (CommonUtils::ToLower(proc.path).find(lowerFilter) != std::wstring::npos)
        return true;

    // 命令行匹配
    if (CommonUtils::ToLower(proc.commandLine).find(lowerFilter) != std::wstring::npos)
        return true;

    // 用户匹配
    if (CommonUtils::ToLower(proc.user).find(lowerFilter) != std::wstring::npos)
        return true;

    // 描述匹配
    if (CommonUtils::ToLower(proc.description).find(lowerFilter) != std::wstring::npos)
        return true;

    // 公司名匹配
    if (CommonUtils::ToLower(proc.companyName).find(lowerFilter) != std::wstring::npos)
        return true;

    // 签名匹配
    if (CommonUtils::ToLower(proc.signatureInfo).find(lowerFilter) != std::wstring::npos)
        return true;

    // 启动时间匹配
    if (CommonUtils::ToLower(proc.startTime).find(lowerFilter) != std::wstring::npos)
        return true;

    // 文件修改时间匹配
    if (CommonUtils::ToLower(proc.fileModifyTime).find(lowerFilter) != std::wstring::npos)
        return true;

    // 注意：不匹配风险描述字段（riskReason）

    return false;
}

// 应用过滤
void ProcessInvestigator::ApplyFilter() {
    wchar_t filterText[256] = { 0 };
    GetWindowTextW(m_hEditFilter, filterText, 256);
    m_filterKeyword = filterText;

    m_filterType = (int)SendMessage(m_hComboType, CB_GETCURSEL, 0, 0);
    m_filterSign = (int)SendMessage(m_hComboSign, CB_GETCURSEL, 0, 0);

    m_filteredProcesses.clear();

    for (const auto& proc : m_allProcesses) {
        // 类型过滤
        if (m_filterType == 1) { // 系统进程
            if (!IsSystemProcess(proc.name))
                continue;
        } else if (m_filterType == 2) { // 非系统进程
            if (IsSystemProcess(proc.name))
                continue;
        } else if (m_filterType == 3) { // 微软进程
            if (!IsMicrosoftProcess(proc.companyName))
                continue;
        } else if (m_filterType == 4) { // 非微软进程
            // 排除微软进程和 PPID 为 0 的系统核心进程
            if (IsMicrosoftProcess(proc.companyName) || proc.ppid == 0)
                continue;
        }

        if (!CommonUtils::MatchSignatureFilter(proc.signatureState, m_filterSign))
            continue;

        // 文本过滤
        if (MatchFilter(proc, m_filterKeyword)) {
            m_filteredProcesses.push_back(proc);
        }
    }

    UpdateListView();

    // 更新状态栏显示过滤结果
    HWND hStatusBar = GetDlgItem(m_hMainWnd, IDC_STATUSBAR);
    if (hStatusBar) {
        wchar_t msg[256];
        swprintf_s(msg, L"从 %zu 个进程中 过滤 %zu 个 结果", m_allProcesses.size(), m_filteredProcesses.size());
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)msg);
    }
}

void ProcessInvestigator::UpdateListView() {
    if (!m_hListView)
        return;

    // 禁用重绘，提高性能
    SendMessage(m_hListView, WM_SETREDRAW, FALSE, 0);

    ListView_DeleteAllItems(m_hListView);
    m_riskMap.clear();

    for (size_t i = 0; i < m_filteredProcesses.size(); i++) {
        const ProcessInfo& proc = m_filteredProcesses[i];

        wchar_t pidStr[32], ppidStr[32];
        swprintf_s(pidStr, L"%lu", proc.pid);
        swprintf_s(ppidStr, L"%lu", proc.ppid);

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.iSubItem = 0;
        lvi.pszText = (LPWSTR)proc.name.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        ListView_SetItemText(m_hListView, (int)i, COL_PID, pidStr);
        ListView_SetItemText(m_hListView, (int)i, COL_PPID, ppidStr);
        ListView_SetItemText(m_hListView, (int)i, COL_PATH, (LPWSTR)proc.path.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_CMDLINE, (LPWSTR)proc.commandLine.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_USER, (LPWSTR)proc.user.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_DESC, (LPWSTR)proc.description.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_COMPANY, (LPWSTR)proc.companyName.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_SIGNATURE, (LPWSTR)proc.signatureInfo.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_START_TIME, (LPWSTR)proc.startTime.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_FILE_MODIFY_TIME, (LPWSTR)proc.fileModifyTime.c_str());

        // 风险描述：正常显示为空，有风险显示拼接的原因
        std::wstring riskText;
        if (proc.risk != RiskLevel::None && !proc.riskReason.empty()) {
            riskText = proc.riskReason;
        }
        ListView_SetItemText(m_hListView, (int)i, COL_RISK, (LPWSTR)riskText.c_str());

        m_riskMap[(int)i] = proc.risk;
    }

    // 恢复重绘
    SendMessage(m_hListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(m_hListView, NULL, TRUE);
}

// 内存搜索 - 已移至独立的威胁检索模块

// 执行排查
InvestigationResult ProcessInvestigator::Investigate(bool resetFilter) {
    auto context = MakeCollectionContext();
    const auto collectedAt = RiskOverviewNowString();
    return ApplyCollection(wgwc::core::process::CollectProcesses({}, context), resetFilter, collectedAt);
}

InvestigationResult
ProcessInvestigator::ApplyCollection(const wgwc::core::CollectionResult<wgwc::core::process::ProcessRecord>& collection,
                                     bool resetFilter, const std::wstring& collectedAt) {
    // 失败时保留上一批数据，不将失败解释为空的完整快照。
    auto processes = ConvertProcesses(collection);
    if (m_processCollectionSucceeded) {
        m_allProcesses = std::move(processes);
        m_collectedAt = collectedAt.empty() ? RiskOverviewNowString() : collectedAt;
        m_hasCache = true;
    }

    // 根据参数决定是否重置过滤条件
    if (resetFilter) {
        m_filterKeyword.clear();
        m_filterType = 0; // 全部
        m_filterSign = 0; // 全部

        if (m_hEditFilter) {
            SetWindowTextW(m_hEditFilter, L"");
        }
        if (m_hComboType) {
            SendMessage(m_hComboType, CB_SETCURSEL, 0, 0); // 全部
        }
        if (m_hComboSign) {
            SendMessage(m_hComboSign, CB_SETCURSEL, 0, 0); // 全部
        }
    }
    // 如果 resetFilter = false，则保持当前控件的值不变

    // 应用当前过滤并返回结果
    return RefreshFromCache();
}

// 从缓存刷新（重新应用当前过滤条件）
InvestigationResult ProcessInvestigator::RefreshFromCache() {
    InvestigationResult result;
    result.moduleName = L"ProcessInvestigator";
    result.success = m_processCollectionSucceeded;
    result.partial = m_processCollectionPartial;
    result.stale = !result.success && m_hasCache;
    result.errorCode = m_processCollectionError;
    result.errorMessage = m_processCollectionMessage;
    result.totalCount = 0;
    result.suspiciousCount = 0;

    m_riskMap.clear();

    // 应用当前过滤条件
    ApplyFilter();

    for (size_t i = 0; i < m_filteredProcesses.size(); i++) {
        const ProcessInfo& proc = m_filteredProcesses[i];

        InvestigationItem item;
        item.name = proc.name;
        item.description = proc.path;

        wchar_t pidStr[32], ppidStr[32];
        swprintf_s(pidStr, L"%lu", proc.pid);
        swprintf_s(ppidStr, L"%lu", proc.ppid);

        item.details.push_back(proc.name);
        item.details.push_back(pidStr);
        item.details.push_back(ppidStr);
        item.details.push_back(proc.path);
        item.details.push_back(proc.commandLine);
        item.details.push_back(proc.user);
        item.details.push_back(proc.description);
        item.details.push_back(proc.companyName);
        item.details.push_back(proc.signatureInfo);
        item.details.push_back(proc.startTime);
        item.details.push_back(proc.fileModifyTime);

        // 风险描述：正常显示为空，有风险显示拼接的原因
        std::wstring riskText;
        if (proc.risk != RiskLevel::None && !proc.riskReason.empty()) {
            riskText = proc.riskReason;
        }
        item.details.push_back(riskText);

        switch (proc.risk) {
        case RiskLevel::None:
            item.suspicion = SuspicionLevel::None;
            break;
        case RiskLevel::Low:
            item.suspicion = SuspicionLevel::Low;
            break;
        case RiskLevel::Medium:
            item.suspicion = SuspicionLevel::Medium;
            break;
        case RiskLevel::High:
            item.suspicion = SuspicionLevel::High;
            break;
        }
        item.suspicionReason = proc.riskReason;

        m_riskMap[(int)i] = proc.risk;

        result.items.push_back(item);
        result.totalCount++;

        if (proc.risk != RiskLevel::None) {
            result.suspiciousCount++;
        }
    }

    // 保存当前过滤结果到缓存（用于GetCachedResult）
    m_cachedResult = result;

    return result;
}

std::vector<RiskOverviewItem> ProcessInvestigator::GetRiskFindings() const {
    std::vector<RiskOverviewItem> findings;
    if (!m_hasCache) {
        return findings;
    }

    for (size_t i = 0; i < m_allProcesses.size(); i++) {
        const ProcessInfo& proc = m_allProcesses[i];
        SuspicionLevel level = ToModuleRiskLevel(proc.risk);
        if (level == SuspicionLevel::None) {
            continue;
        }

        RiskOverviewItem finding;
        finding.moduleId = L"process";
        finding.moduleName = L"\u8FDB\u7A0B\u6392\u67E5";
        finding.tabIndex = TAB_PROCESSES;
        finding.level = level;
        finding.objectName = proc.name;
        finding.info = L"PID: " + std::to_wstring(proc.pid) + L" / PPID: " + std::to_wstring(proc.ppid);
        finding.info2 = proc.commandLine.empty() ? proc.path : proc.commandLine;
        finding.reason = proc.riskReason;
        finding.updatedAt = m_collectedAt;
        finding.sourceKey = std::to_wstring(proc.pid);
        finding.sourceRow = (int)i;

        findings.push_back(finding);
    }

    return findings;
}

std::wstring ProcessInvestigator::GetRowIconPath(int row, const InvestigationItem& item) const {
    if (row >= 0 && row < (int)m_filteredProcesses.size()) {
        return m_filteredProcesses[row].path;
    }
    if (item.details.size() > COL_PATH) {
        return item.details[COL_PATH];
    }
    return item.description;
}

std::wstring ProcessInvestigator::GetContextFilePath(int row) const {
    if (row < 0 || row >= (int)m_filteredProcesses.size())
        return L"";
    return m_filteredProcesses[row].path;
}

bool ProcessInvestigator::GetCellHighlight(int row, int col, const InvestigationResult& result,
                                           COLORREF& outColor) const {
    (void)col;
    (void)result;

    auto it = m_riskMap.find(row);
    if (it == m_riskMap.end()) {
        return false;
    }

    switch (it->second) {
    case RiskLevel::High:
        outColor = RGB(255, 0, 0);
        return true;
    case RiskLevel::Medium:
        outColor = RGB(255, 128, 0);
        return true;
    case RiskLevel::Low:
        outColor = RGB(128, 128, 0);
        return true;
    default:
        return false;
    }
}

void ProcessInvestigator::CreateToolbar(HWND hParent, HINSTANCE hInst) {
    m_hMainWnd = hParent;
    m_hInst = hInst;

    // 创建工具栏面板（仅用于布局）
    m_hToolbarPanel = CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | SS_SIMPLE, 0, 0, 0, 0, hParent, NULL, hInst, NULL);

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    // 注意：所有控件的父窗口设为 hParent（主窗口），这样 WM_COMMAND 消息才能正确传递

    int xPos = 5;

    // 类型下拉框
    m_hComboType = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, xPos,
                                   33, 90, 200, hParent, (HMENU)IDC_PROC_COMBO_TYPE, hInst, NULL);
    SendMessage(m_hComboType, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"类型:全部");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"系统进程");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"非系统进程");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"微软进程");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"第三方进程");
    SendMessage(m_hComboType, CB_SETCURSEL, 0, 0); // 默认全部
    xPos += 95;

    // 签名下拉框
    m_hComboSign = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, xPos,
                                   33, 85, 200, hParent, (HMENU)IDC_PROC_COMBO_SIGN, hInst, NULL);
    SendMessage(m_hComboSign, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboSign, CB_ADDSTRING, 0, (LPARAM)L"签名:全部");
    SendMessage(m_hComboSign, CB_ADDSTRING, 0, (LPARAM)L"已签名");
    SendMessage(m_hComboSign, CB_ADDSTRING, 0, (LPARAM)L"未匹配");
    SendMessage(m_hComboSign, CB_ADDSTRING, 0, (LPARAM)L"未签名");
    SendMessage(m_hComboSign, CB_ADDSTRING, 0, (LPARAM)L"其他");
    SendMessage(m_hComboSign, CB_SETCURSEL, 0, 0);
    xPos += 90;

    m_hStaticFilter = CreateWindowExW(0, L"STATIC", L"过滤:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, xPos, 33, 35, 22,
                                      hParent, (HMENU)IDC_PROC_STATIC_FILTER, hInst, NULL);
    SendMessage(m_hStaticFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    xPos += 37;

    m_hEditFilter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, xPos, 33,
                                    150, 22, hParent, (HMENU)IDC_PROC_EDIT_FILTER, hInst, NULL);
    SendMessage(m_hEditFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    xPos += 155;

    m_hBtnFilter = CreateWindowExW(0, L"BUTTON", L"过滤", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, xPos, 33, 50, 22,
                                   hParent, (HMENU)IDC_PROC_BTN_FILTER, hInst, NULL);
    SendMessage(m_hBtnFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    xPos += 55;

    // 刷新按钮
    m_hBtnRefresh = CreateWindowExW(0, L"BUTTON", L"刷新", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, xPos, 33, 50, 22,
                                    hParent, (HMENU)IDC_PROC_BTN_REFRESH, hInst, NULL);
    SendMessage(m_hBtnRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);
    xPos += 55;

    // 初始隐藏所有控件
    ShowToolbar(false);
}

void ProcessInvestigator::DestroyToolbar() {
    if (m_hComboType) {
        DestroyWindow(m_hComboType);
        m_hComboType = NULL;
    }
    if (m_hComboSign) {
        DestroyWindow(m_hComboSign);
        m_hComboSign = NULL;
    }
    if (m_hStaticFilter) {
        DestroyWindow(m_hStaticFilter);
        m_hStaticFilter = NULL;
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
    if (m_hToolbarPanel) {
        DestroyWindow(m_hToolbarPanel);
        m_hToolbarPanel = NULL;
    }
}

void ProcessInvestigator::ShowToolbar(bool show) {
    int cmd = show ? SW_SHOW : SW_HIDE;
    if (m_hComboType)
        ShowWindow(m_hComboType, cmd);
    if (m_hComboSign)
        ShowWindow(m_hComboSign, cmd);
    if (m_hStaticFilter)
        ShowWindow(m_hStaticFilter, cmd);
    if (m_hEditFilter)
        ShowWindow(m_hEditFilter, cmd);
    if (m_hBtnFilter)
        ShowWindow(m_hBtnFilter, cmd);
    if (m_hBtnRefresh)
        ShowWindow(m_hBtnRefresh, cmd);
}

void ProcessInvestigator::ResizeToolbar(int x, int y, int width) {
    (void)x;
    (void)width;
    // 控件位置在创建时已固定，这里只需要调整 y 坐标
    int baseY = y + 5;
    int xPos = 5;

    if (m_hComboType) {
        SetWindowPos(m_hComboType, NULL, xPos, baseY, 90, 22, SWP_NOZORDER);
        xPos += 95;
    }
    if (m_hComboSign) {
        SetWindowPos(m_hComboSign, NULL, xPos, baseY, 85, 22, SWP_NOZORDER);
        xPos += 90;
    }
    if (m_hStaticFilter) {
        SetWindowPos(m_hStaticFilter, NULL, xPos, baseY, 35, 22, SWP_NOZORDER);
        xPos += 37;
    }
    if (m_hEditFilter) {
        SetWindowPos(m_hEditFilter, NULL, xPos, baseY, 150, 22, SWP_NOZORDER);
        xPos += 155;
    }
    if (m_hBtnFilter) {
        SetWindowPos(m_hBtnFilter, NULL, xPos, baseY, 50, 22, SWP_NOZORDER);
        xPos += 55;
    }
    if (m_hBtnRefresh) {
        SetWindowPos(m_hBtnRefresh, NULL, xPos, baseY, 50, 22, SWP_NOZORDER);
        xPos += 55;
    }
}

bool ProcessInvestigator::HandleToolbarCommand(WORD id, WORD code) {
    (void)code;

    switch (id) {
    case IDC_PROC_BTN_FILTER:
        ApplyFilter();
        return true;

    case IDC_PROC_BTN_REFRESH:
        // 触发重新扫描
        if (m_hMainWnd) {
            PostMessage(m_hMainWnd, WM_COMMAND, MAKEWPARAM(IDM_REFRESH_KEEP_FILTER, 0), 0);
        }
        return true;

    case IDC_PROC_COMBO_TYPE:
    case IDC_PROC_COMBO_SIGN:
        // 下拉框选择变化时自动过滤
        if (code == CBN_SELCHANGE) {
            ApplyFilter();
        }
        return true;
    }

    return false;
}

// 右键菜单功能实现

// 受保护进程列表
static const wchar_t* PROTECTED_PROCESSES[] = { L"system",       L"smss.exe",  L"csrss.exe",    L"wininit.exe",
                                                L"services.exe", L"lsass.exe", L"winlogon.exe", nullptr };

bool ProcessInvestigator::IsProtectedProcess(DWORD pid, const std::wstring& name) {
    if (pid == 0 || pid == 4)
        return true;

    if (pid == GetCurrentProcessId())
        return true;

    std::wstring lowerName = name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    for (int i = 0; PROTECTED_PROCESSES[i] != nullptr; i++) {
        if (lowerName == PROTECTED_PROCESSES[i]) {
            return true;
        }
    }

    return false;
}

bool ProcessInvestigator::CanOperateProcess(DWORD pid, const std::wstring& name) const {
    return !IsProtectedProcess(pid, name);
}

std::vector<ContextMenuItem> ProcessInvestigator::GetContextMenuItems(int row) const {
    std::vector<ContextMenuItem> items;

    if (row < 0 || row >= (int)m_filteredProcesses.size()) {
        return items;
    }

    const ProcessInfo& proc = m_filteredProcesses[row];
    bool canOperate = CanOperateProcess(proc.pid, proc.name);
    const bool canTerminate = canOperate && m_hasCache && !m_cachedResult.stale && proc.createdAt != 0;
    bool hasValidPath = !proc.path.empty() && proc.path[0] != L'[';

    // P0 - 核心功能
    if (canTerminate) {
        items.push_back({ IDM_PROC_KILL, L"结束进程", true,
                          L"确定要结束进程 " + proc.name + L" (PID: " + std::to_wstring(proc.pid) + L") 吗？" });
        items.push_back(
            { IDM_PROC_KILL_TREE, L"结束进程树", true, L"确定要结束进程 " + proc.name + L" 及其所有子进程吗？" });
    }

    items.push_back({ 0, L"", false, L"" });

    // P1 - 分析功能
    if (hasValidPath) {
        items.push_back({ IDM_PROC_CALC_HASH, L"计算文件哈希", false, L"" });
        items.push_back({ IDM_PROC_VIRUSTOTAL, L"在线查询 (VirusTotal)", false, L"" });
        items.push_back({ IDM_PROC_THREATBOOK, L"在线查询 (微步)", false, L"" });
    }

    // 分隔符
    items.push_back({ 0, L"", false, L"" });

    // P2 - 查看关联
    items.push_back({ IDM_PROC_VIEW_MODULES, L"查看DLL模块", false, L"" });
    items.push_back({ IDM_PROC_VIEW_TREE, L"查看进程树", false, L"" });

    // 仅对svchost显示查看服务选项
    std::wstring lowerName = CommonUtils::ToLower(proc.name);
    if (lowerName == L"svchost.exe") {
        items.push_back({ IDM_PROC_VIEW_SERVICES, L"查看关联服务", false, L"" });
    }

    // 分隔符
    items.push_back({ 0, L"", false, L"" });

    // P2 - 取证功能
    if (canOperate) {
        items.push_back({ IDM_PROC_DUMP_MEMORY, L"进程转储(fulldump)", false, L"" });
    }

    return items;
}

bool ProcessInvestigator::HandleContextMenu(UINT menuId, int row) {
    if (row < 0 || row >= (int)m_filteredProcesses.size()) {
        return false;
    }

    const ProcessInfo proc = m_filteredProcesses[row];

    switch (menuId) {
    case IDM_PROC_KILL:
        return KillProcess(proc);

    case IDM_PROC_KILL_TREE:
        return KillProcessTree(proc);

    case IDM_PROC_CALC_HASH:
        ShowFileHashes(proc.path);
        return false;

    case IDM_PROC_VIRUSTOTAL: {
        CommonUtils::FileHashResult hashes = CommonUtils::CalculateFileHashes(proc.path);
        if (hashes.sha256.empty()) {
            MessageBoxW(m_hMainWnd, L"无法计算文件哈希", L"错误", MB_OK | MB_ICONERROR);
        } else {
            CommonUtils::QueryVirusTotal(hashes.sha256);
        }
        return false;
    }

    case IDM_PROC_THREATBOOK: {
        CommonUtils::FileHashResult hashes = CommonUtils::CalculateFileHashes(proc.path);
        if (hashes.sha256.empty()) {
            MessageBoxW(m_hMainWnd, L"无法计算文件哈希", L"错误", MB_OK | MB_ICONERROR);
        } else {
            CommonUtils::QueryThreatBook(hashes.sha256);
        }
        return false;
    }

    case IDM_PROC_VIEW_MODULES:
        ShowProcessModules(proc.pid, proc.name);
        return false;

    case IDM_PROC_VIEW_TREE:
        ShowProcessTree(proc.pid);
        return false;

    case IDM_PROC_VIEW_SERVICES:
        ShowSvchostServices(proc.pid);
        return false;

    case IDM_PROC_DUMP_MEMORY:
        DumpProcessMemory(proc.pid, proc.name);
        return false;
    }

    return false;
}

// 结束进程
bool ProcessInvestigator::KillProcess(const ProcessInfo& proc) {
    return TerminateSelectedProcess(proc, false);
}

// 结束进程树
bool ProcessInvestigator::KillProcessTree(const ProcessInfo& proc) {
    return TerminateSelectedProcess(proc, true);
}

bool ProcessInvestigator::TerminateSelectedProcess(const ProcessInfo& proc, bool tree) {
    if (!m_hasCache || m_cachedResult.stale || !proc.createdAt) {
        MessageBoxW(m_hMainWnd, L"进程记录已过期或无法确认身份，请重新采集后再操作。", L"操作未执行",
                    MB_OK | MB_ICONWARNING);
        return false;
    }
    const auto outcome = wgwc::core::process::actions::Terminate({ proc.pid, proc.createdAt, proc.name }, tree,
                                                                 &ProcessInvestigator::IsProtectedProcess);
    if (tree) {
        std::wstring message = L"已提交结束请求：" + std::to_wstring(outcome.requested) + L" 项；已退出：" +
                               std::to_wstring(outcome.exited) + L" 项；失败：" + std::to_wstring(outcome.failed) +
                               L" 项；跳过：" + std::to_wstring(outcome.skipped) + L" 项。";
        if (outcome.skipped)
            message += L"\n受保护或无法确认身份、父子关系的目标及其分支未被处理。";
        if (outcome.failed)
            message += L"\n部分目标无法访问或结束，错误代码：" + std::to_wstring(outcome.firstError);
        MessageBoxW(m_hMainWnd, message.c_str(), L"结束进程树",
                    MB_OK | ((outcome.failed || outcome.skipped) ? MB_ICONWARNING : MB_ICONINFORMATION));
    } else if (!outcome.requested) {
        std::wstring message;
        if (outcome.exited)
            message = L"目标进程已退出，请重新采集。";
        else if (outcome.skipped)
            message = L"目标受保护或身份已变化，未执行结束操作，请重新采集。";
        else
            message = L"无法结束目标进程，错误代码：" + std::to_wstring(outcome.firstError);
        MessageBoxW(m_hMainWnd, message.c_str(), L"操作未完成", MB_OK | MB_ICONWARNING);
    }
    return outcome.requested != 0;
}

// 暂停进程
bool ProcessInvestigator::SuspendProcess(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return false;

    THREADENTRY32 te = { sizeof(te) };
    bool success = false;

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                    success = true;
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);

    return success;
}

// 恢复进程
bool ProcessInvestigator::ResumeProcess(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return false;

    THREADENTRY32 te = { sizeof(te) };
    bool success = false;

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                    success = true;
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);

    return success;
}

void ProcessInvestigator::ShowFileHashes(const std::wstring& path) {
    CommonUtils::FileHashResult hashes = CommonUtils::CalculateFileHashes(path);

    CommonUtils::ShowFileHashDialog(m_hInst, m_hMainWnd, path, hashes);
}

void ProcessInvestigator::ShowSvchostServices(DWORD pid) {
    std::vector<std::wstring> services;

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        MessageBoxW(m_hMainWnd, L"无法打开服务管理器", L"错误", MB_OK | MB_ICONERROR);
        return;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded,
                               &servicesReturned, &resumeHandle, NULL)) {
        // 预期失败，获取所需缓冲区大小
    }

    if (bytesNeeded > 0) {
        std::vector<BYTE> buffer(bytesNeeded);
        ENUM_SERVICE_STATUS_PROCESSW* pServices = (ENUM_SERVICE_STATUS_PROCESSW*)buffer.data();

        resumeHandle = 0;
        if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(),
                                  bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {

            for (DWORD i = 0; i < servicesReturned; i++) {
                if (pServices[i].ServiceStatusProcess.dwProcessId == pid) {
                    std::wstring svcInfo = pServices[i].lpServiceName;
                    if (pServices[i].lpDisplayName && wcslen(pServices[i].lpDisplayName) > 0) {
                        svcInfo += L" - " + std::wstring(pServices[i].lpDisplayName);
                    }
                    services.push_back(svcInfo);
                }
            }
        }
    }

    CloseServiceHandle(hSCM);

    if (services.empty()) {
        MessageBoxW(m_hMainWnd, L"未找到关联的服务", L"关联服务", MB_OK);
        return;
    }

    std::wstring msg = L"PID " + std::to_wstring(pid) + L" 托管的服务:\n\n";
    for (const auto& svc : services) {
        msg += L"• " + svc + L"\n";
    }

    MessageBoxW(m_hMainWnd, msg.c_str(), L"关联服务", MB_OK);
}

// DLL模块信息结构
struct DllModuleInfo {
    std::wstring name;
    std::wstring path;
    std::wstring company;
    CommonUtils::SignatureState signatureState = CommonUtils::SignatureState::Unknown;
    std::wstring signature;
    std::wstring createTime;
    std::wstring modifyTime;
    DWORD_PTR baseAddr = 0;
    DWORD size = 0;
};

// DLL模块对话框数据
struct DllDialogData {
    std::vector<DllModuleInfo> modules;
    std::wstring title;
    HWND hListView = NULL;
    HWND hStatusText = NULL; // 状态文本
};

// DLL模块对话框过程
static INT_PTR CALLBACK DllModulesDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    static DllDialogData* pData = nullptr;
    static HFONT hListFont = NULL;

    switch (message) {
    case WM_INITDIALOG: {
        pData = (DllDialogData*)lParam;
        if (!pData)
            return FALSE;

        SetWindowTextW(hDlg, pData->title.c_str());

        pData->hListView = GetDlgItem(hDlg, IDC_DLL_LISTVIEW);
        if (!pData->hListView)
            return FALSE;

        hListFont = CreateFont(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                               CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei");

        if (hListFont) {
            SendMessage(pData->hListView, WM_SETFONT, (WPARAM)hListFont, TRUE);
        }

        ListView_SetExtendedListViewStyle(pData->hListView,
                                          LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

        LVCOLUMN lvc = { 0 };
        lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
        lvc.fmt = LVCFMT_LEFT;

        lvc.cx = 120;
        lvc.pszText = (LPWSTR)L"模块名称";
        ListView_InsertColumn(pData->hListView, 0, &lvc);

        lvc.cx = 250;
        lvc.pszText = (LPWSTR)L"路径";
        ListView_InsertColumn(pData->hListView, 1, &lvc);

        lvc.cx = 100;
        lvc.pszText = (LPWSTR)L"公司";
        ListView_InsertColumn(pData->hListView, 2, &lvc);

        lvc.cx = 150;
        lvc.pszText = (LPWSTR)L"签名";
        ListView_InsertColumn(pData->hListView, 3, &lvc);

        lvc.cx = 130;
        lvc.pszText = (LPWSTR)L"创建时间";
        ListView_InsertColumn(pData->hListView, 4, &lvc);

        lvc.cx = 130;
        lvc.pszText = (LPWSTR)L"修改时间";
        ListView_InsertColumn(pData->hListView, 5, &lvc);

        // 填充数据
        for (size_t i = 0; i < pData->modules.size(); i++) {
            const DllModuleInfo& mod = pData->modules[i];

            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = (int)i;
            lvi.pszText = (LPWSTR)mod.name.c_str();
            ListView_InsertItem(pData->hListView, &lvi);

            ListView_SetItemText(pData->hListView, (int)i, 1, (LPWSTR)mod.path.c_str());
            ListView_SetItemText(pData->hListView, (int)i, 2, (LPWSTR)mod.company.c_str());
            ListView_SetItemText(pData->hListView, (int)i, 3, (LPWSTR)mod.signature.c_str());
            ListView_SetItemText(pData->hListView, (int)i, 4, (LPWSTR)mod.createTime.c_str());
            ListView_SetItemText(pData->hListView, (int)i, 5, (LPWSTR)mod.modifyTime.c_str());
        }

        return TRUE;
    }

    case WM_NOTIFY: {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->idFrom == IDC_DLL_LISTVIEW) {
            if (pnmh->code == NM_CUSTOMDRAW) {
                LPNMLVCUSTOMDRAW pcd = (LPNMLVCUSTOMDRAW)lParam;

                switch (pcd->nmcd.dwDrawStage) {
                case CDDS_PREPAINT:
                    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, CDRF_NOTIFYITEMDRAW);
                    return TRUE;

                case CDDS_ITEMPREPAINT:
                    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, CDRF_NOTIFYSUBITEMDRAW);
                    return TRUE;

                case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
                    int row = (int)pcd->nmcd.dwItemSpec;
                    if (pData && row >= 0 && row < (int)pData->modules.size()) {
                        const DllModuleInfo& mod = pData->modules[row];

                        // 仅缺少签名不能单独构成 DLL 风险。
                        pcd->clrText = mod.signatureState == CommonUtils::SignatureState::Mismatch
                                           ? RGB(255, 0, 0)
                                           : GetSysColor(COLOR_WINDOWTEXT);
                    }
                    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, CDRF_DODEFAULT);
                    return TRUE;
                }
                }
            } else if (pnmh->code == NM_RCLICK) {
                // 右键菜单
                LPNMITEMACTIVATE pnmia = (LPNMITEMACTIVATE)lParam;
                int row = pnmia->iItem;

                if (pData && row >= 0 && row < (int)pData->modules.size()) {
                    HMENU hMenu = CreatePopupMenu();
                    AppendMenuW(hMenu, MF_STRING, IDC_DLL_COPY_NAME, L"复制模块名");
                    AppendMenuW(hMenu, MF_STRING, IDC_DLL_COPY_PATH, L"复制路径");
                    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                    AppendMenuW(hMenu, MF_STRING, IDC_DLL_OPEN_LOCATION, L"文件目录");

                    POINT pt;
                    GetCursorPos(&pt);

                    int cmd =
                        TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN, pt.x, pt.y, 0, hDlg, NULL);
                    DestroyMenu(hMenu);

                    const DllModuleInfo& mod = pData->modules[row];

                    if (cmd == IDC_DLL_COPY_NAME) {
                        CommonUtils::CopyToClipboard(hDlg, mod.name);
                    } else if (cmd == IDC_DLL_COPY_PATH) {
                        CommonUtils::CopyToClipboard(hDlg, mod.path);
                    } else if (cmd == IDC_DLL_OPEN_LOCATION) {
                        std::wstring param = L"/select,\"" + mod.path + L"\"";
                        ShellExecuteW(NULL, L"open", L"explorer.exe", param.c_str(), NULL, SW_SHOWNORMAL);
                    }
                }
                return TRUE;
            }
        }
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            if (hListFont) {
                DeleteObject(hListFont);
                hListFont = NULL;
            }
            EndDialog(hDlg, LOWORD(wParam));
            return TRUE;
        }
        break;

    case WM_CLOSE:
        if (hListFont) {
            DeleteObject(hListFont);
            hListFont = NULL;
        }
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    }

    return FALSE;
}

// 启用调试特权
static bool EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return result && (err == ERROR_SUCCESS);
}

void ProcessInvestigator::ShowProcessModules(DWORD pid, const std::wstring& processName) {
    // 启用调试特权（只需要执行一次，但多次调用无害）
    static bool debugPrivEnabled = false;
    if (!debugPrivEnabled) {
        debugPrivEnabled = EnableDebugPrivilege();
    }

    DllDialogData dlgData;
    dlgData.title = L"DLL模块 - " + processName + L" (PID: " + std::to_wstring(pid) + L")";

    const auto collected = wgwc::core::process::CollectModules(pid, true, {});
    for (const auto& record : collected.records) {
        DllModuleInfo mod;
        mod.name = record.name;
        mod.path = record.path;
        mod.baseAddr = static_cast<DWORD_PTR>(record.baseAddress);
        mod.size = record.imageSize;
        mod.company = record.file.evidence.company;
        mod.signatureState = record.file.evidence.signature;
        mod.signature = CommonUtils::FormatSignatureText(mod.signatureState, record.file.evidence.publisher);
        mod.createTime = wgwc::core::files::LocalTimeText(record.file.createdAt);
        mod.modifyTime = wgwc::core::files::LocalTimeText(record.file.modifiedAt);
        dlgData.modules.push_back(std::move(mod));
    }

    // 无可展示的模块时保留采集器记录的错误。
    if (dlgData.modules.empty()) {
        DWORD err = collected.issues.empty() ? ERROR_NOT_FOUND : collected.issues.back().nativeCode;
        std::wstring errMsg = L"无法枚举进程模块 (PID: " + std::to_wstring(pid) + L")\n\n";
        errMsg += L"错误代码: " + std::to_wstring(err) + L"\n\n";
        errMsg += L"可能原因：\n";
        errMsg += L"• 进程已退出或正在初始化\n";
        errMsg += L"• 受保护进程（PPL）\n";
        errMsg += L"• 权限不足";

        MessageBoxW(m_hMainWnd, errMsg.c_str(), L"无法访问", MB_OK | MB_ICONWARNING);
        return;
    }

    DialogBoxParamW(m_hInst, MAKEINTRESOURCEW(IDD_DLL_MODULES), m_hMainWnd, DllModulesDialogProc, (LPARAM)&dlgData);
}

// 导出进程内存
void ProcessInvestigator::DumpProcessMemory(DWORD pid, const std::wstring& processName) {
    if (pid == 0 || pid == 4) {
        MessageBoxW(m_hMainWnd, L"无法转储系统进程", L"提示", MB_OK);
        return;
    }

    // 获取程序目录并创建导出目录
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    size_t pos = exeDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        exeDir = exeDir.substr(0, pos + 1);
    }

    std::wstring dumpDir = exeDir + L"data\\exports\\process_dumps\\";
    CreateDirectoryW((exeDir + L"data").c_str(), NULL);
    CreateDirectoryW((exeDir + L"data\\exports").c_str(), NULL);
    CreateDirectoryW(dumpDir.c_str(), NULL);

    // 生成文件名：进程名_PID_时间戳.dmp
    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t timestamp[64];
    swprintf_s(timestamp, L"%04d%02d%02d_%02d%02d%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // 移除进程名中的.exe后缀
    std::wstring baseName = processName;
    size_t extPos = baseName.rfind(L".exe");
    if (extPos != std::wstring::npos) {
        baseName = baseName.substr(0, extPos);
    }

    std::wstring dumpPath = dumpDir + baseName + L"_" + std::to_wstring(pid) + L"_" + timestamp + L".dmp";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (!hProcess) {
        DWORD err = GetLastError();
        std::wstring errMsg = L"无法打开进程\n错误代码: " + std::to_wstring(err);
        if (err == ERROR_ACCESS_DENIED) {
            errMsg += L"\n\n可能原因：\n• 权限不足，请以管理员身份运行\n• 进程受保护（PPL）";
        }
        MessageBoxW(m_hMainWnd, errMsg.c_str(), L"错误", MB_OK | MB_ICONERROR);
        return;
    }

    HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        MessageBoxW(m_hMainWnd, (L"无法创建dump文件:\n" + dumpPath).c_str(), L"错误", MB_OK | MB_ICONERROR);
        return;
    }

    // 执行内存转储（不再显示进度提示，直接执行）
    // 使用 MiniDumpWithFullMemory 获取完整内存
    BOOL result = MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

    DWORD dumpError = GetLastError();

    CloseHandle(hFile);
    CloseHandle(hProcess);

    if (result) {
        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        ULONGLONG fileSize = 0;
        if (GetFileAttributesExW(dumpPath.c_str(), GetFileExInfoStandard, &fileInfo)) {
            fileSize = ((ULONGLONG)fileInfo.nFileSizeHigh << 32) | fileInfo.nFileSizeLow;
        }

        // 格式化文件大小
        std::wstring sizeStr;
        if (fileSize >= 1024 * 1024 * 1024) {
            swprintf_s(timestamp, L"%.2f GB", fileSize / (1024.0 * 1024.0 * 1024.0));
            sizeStr = timestamp;
        } else if (fileSize >= 1024 * 1024) {
            swprintf_s(timestamp, L"%.2f MB", fileSize / (1024.0 * 1024.0));
            sizeStr = timestamp;
        } else if (fileSize >= 1024) {
            swprintf_s(timestamp, L"%.2f KB", fileSize / 1024.0);
            sizeStr = timestamp;
        } else {
            sizeStr = std::to_wstring(fileSize) + L" B";
        }

        std::wstring msg = L"进程内存导出成功\n\n";
        msg += L"文件路径:\n" + dumpPath + L"\n\n";
        msg += L"文件大小: " + sizeStr + L"\n\n";
        msg += L"是否打开所在文件夹？";

        int ret = MessageBoxW(m_hMainWnd, msg.c_str(), L"导出成功", MB_YESNO);

        if (ret == IDYES) {
            std::wstring param = L"/select,\"" + dumpPath + L"\"";
            ShellExecuteW(NULL, L"open", L"explorer.exe", param.c_str(), NULL, SW_SHOWNORMAL);
        }
    } else {
        // 删除失败的文件
        DeleteFileW(dumpPath.c_str());

        std::wstring errMsg = L"进程内存导出失败\n错误代码: " + std::to_wstring(dumpError);

        if (dumpError == ERROR_ACCESS_DENIED) {
            errMsg += L"\n\n进程可能受保护，无法读取内存";
        }

        MessageBoxW(m_hMainWnd, errMsg.c_str(), L"错误", MB_OK | MB_ICONERROR);
    }
}

// 进程树功能

// 进程树对话框过程
INT_PTR CALLBACK ProcessTreeDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_INITDIALOG: {
        std::wstring* pTreeText = (std::wstring*)lParam;
        SetDlgItemTextW(hDlg, IDC_TREE_TEXT, pTreeText->c_str());

        // 取消文本框的选中状态
        HWND hEdit = GetDlgItem(hDlg, IDC_TREE_TEXT);
        SendMessage(hEdit, EM_SETSEL, static_cast<WPARAM>(-1), 0); // 取消选中

        // 将焦点设置到关闭按钮
        SetFocus(GetDlgItem(hDlg, IDOK));

        return FALSE; // 返回 FALSE 表示我们已经设置了焦点
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return TRUE;
        }
        break;
    }
    return FALSE;
}

void ProcessInvestigator::AppendChildren(std::wstring& result, DWORD parentPid,
                                         const std::unordered_map<DWORD, const ProcessInfo*>& pidMap, int indent) {
    std::vector<DWORD> children;

    // 查找所有子进程
    for (const auto& pair : pidMap) {
        if (pair.second->ppid == parentPid) {
            children.push_back(pair.first);
        }
    }

    if (children.empty())
        return;

    // 排序（按 PID）
    std::sort(children.begin(), children.end());

    for (size_t i = 0; i < children.size(); i++) {
        DWORD pid = children[i];
        auto it = pidMap.find(pid);
        std::wstring name = (it != pidMap.end()) ? it->second->name : L"<Unknown>";

        // 缩进
        for (int j = 0; j < indent; j++) {
            result += L"    ";
        }

        // 连接符
        bool isLastChild = (i == children.size() - 1);
        if (isLastChild) {
            result += L"└─ ";
        } else {
            result += L"├─ ";
        }

        // 进程信息
        result += name + L" (" + std::to_wstring(pid) + L")";
        result += L"\r\n";
    }
}

// 构建进程树文本
std::wstring ProcessInvestigator::BuildProcessTreeText(DWORD targetPid) {
    std::unordered_map<DWORD, const ProcessInfo*> pidMap;
    for (const auto& proc : m_allProcesses) {
        pidMap[proc.pid] = &proc;
    }

    // 向上追溯到根
    std::vector<DWORD> chain;
    DWORD current = targetPid;
    std::set<DWORD> visited;

    while (current != 0 && visited.find(current) == visited.end()) {
        chain.insert(chain.begin(), current);
        visited.insert(current);

        auto it = pidMap.find(current);
        if (it == pidMap.end())
            break;
        current = it->second->ppid;
    }

    if (chain.empty()) {
        return L"无法获取进程树信息";
    }

    // 构建文本
    std::wstring result;

    // 显示父进程链
    for (size_t i = 0; i < chain.size(); i++) {
        DWORD pid = chain[i];
        auto it = pidMap.find(pid);
        std::wstring name = (it != pidMap.end()) ? it->second->name : L"<Unknown>";

        // 缩进
        for (size_t j = 0; j < i; j++) {
            result += L"    ";
        }

        // 连接符
        if (i > 0) {
            result += L"└─ ";
        }

        // 进程信息
        result += name + L" (" + std::to_wstring(pid) + L")";
        result += L"\r\n";
    }

    // 显示目标进程的子进程
    int indent = (int)chain.size();
    AppendChildren(result, targetPid, pidMap, indent);

    return result;
}

void ProcessInvestigator::ShowProcessTree(DWORD pid) {
    std::wstring treeText = BuildProcessTreeText(pid);
    DialogBoxParam(m_hInst, MAKEINTRESOURCE(IDD_PROCESS_TREE), m_hMainWnd, ProcessTreeDialogProc, (LPARAM)&treeText);
}
