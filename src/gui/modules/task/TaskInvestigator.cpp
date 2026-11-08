#include "../../presentation/GuiColumns.h"
// TaskInvestigator.cpp - 计划任务排查模块实现

#include "../../../core/system/Win32.h"
#include "TaskInvestigator.h"
#include "../../common/ListViewSupport.h"
#include "../../../core/modules/task/TaskModule.h"
#include "../../../core/modules/task/TaskActions.h"

#include "../../resources/resource.h"
#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <commctrl.h>
#include <oleauto.h>
#include <shellapi.h>
#include <shlwapi.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shlwapi.lib")

// 静态列定义
const ColumnDef TaskInvestigator::s_Columns[] = { WG_COLUMNS_TASK };
const int TaskInvestigator::s_ColumnCount = sizeof(s_Columns) / sizeof(s_Columns[0]);

static std::wstring TaskStateToRiskString(TASK_STATE state) {
    switch (state) {
    case TASK_STATE_UNKNOWN:
        return L"未知";
    case TASK_STATE_DISABLED:
        return L"已禁用";
    case TASK_STATE_QUEUED:
        return L"队列中";
    case TASK_STATE_READY:
        return L"就绪";
    case TASK_STATE_RUNNING:
        return L"运行中";
    default:
        return L"未知";
    }
}

TaskInvestigator::TaskInvestigator()
    : m_hComboType(NULL), m_hComboState(NULL), m_hComboTrigger(NULL), m_hStaticKeyword(NULL), m_hEditFilter(NULL),
      m_hBtnFilter(NULL), m_hBtnRefresh(NULL), m_hMainWnd(NULL), m_hListView(NULL), m_hInst(NULL) {}

TaskInvestigator::~TaskInvestigator() {
    DestroyToolbar();
}

std::wstring TaskInvestigator::StateToString(TASK_STATE state) {
    switch (state) {
    case TASK_STATE_UNKNOWN:
        return L"未知";
    case TASK_STATE_DISABLED:
        return L"已禁用";
    case TASK_STATE_QUEUED:
        return L"已排队";
    case TASK_STATE_READY:
        return L"就绪";
    case TASK_STATE_RUNNING:
        return L"运行中";
    default:
        return L"未知";
    }
}

bool TaskInvestigator::IsMicrosoftTask(const TaskInfo& info) {
    wgwc::core::tasks::Record record;
    record.path = info.path;
    record.author = info.author;
    return wgwc::core::tasks::IsMicrosoftGroup(record);
}

InvestigationResult TaskInvestigator::Investigate(bool resetFilter) {
    auto context = MakeCollectionContext();
    const auto collectedAt = RiskOverviewNowString();
    return ApplyCollection(wgwc::core::tasks::CollectTasks({}, context), resetFilter, collectedAt);
}

InvestigationResult
TaskInvestigator::ApplyCollection(const wgwc::core::CollectionResult<wgwc::core::tasks::Record>& collection,
                                  bool resetFilter, const std::wstring& collectedAt) {
    wgwc::gui::ApplyCollectionOutcome(m_cachedResult, collection, m_hasCache, L"计划任务采集失败",
                                      L"部分任务定义或文件信息不可读取");
    m_collectionStale = m_cachedResult.stale;
    m_collectionError = m_cachedResult.errorCode;
    m_collectionMessage = m_cachedResult.errorMessage;
    if (!m_cachedResult.success)
        return RefreshFromCache();
    m_allTasks.clear();
    m_collectedAt = collectedAt.empty() ? RiskOverviewNowString() : collectedAt;
    for (const auto& record : collection.records) {
        TaskInfo info{};
        info.name = record.name;
        info.path = record.path;
        info.identityKnown = record.pathState == wgwc::core::FieldState::Available;
        info.stateKnown = record.stateState == wgwc::core::FieldState::Available;
        info.definitionKnown = record.definitionState == wgwc::core::FieldState::Available;
        info.enabledKnown = record.enabledState == wgwc::core::FieldState::Available;
        info.enabled = record.enabled;
        info.state = info.stateKnown ? static_cast<TASK_STATE>(record.state) : TASK_STATE_UNKNOWN;
        info.hidden = record.hiddenState == wgwc::core::FieldState::Available && record.hidden;
        info.author = record.author;
        info.description = record.description;
        info.nextRunTime = record.nextRunTimeLocal;
        info.lastRunTime = record.lastRunTimeLocal;
        std::replace(info.nextRunTime.begin(), info.nextRunTime.end(), L'T', L' ');
        std::replace(info.lastRunTime.begin(), info.lastRunTime.end(), L'T', L' ');
        info.actionSummary = wgwc::core::tasks::ActionSummary(record);
        info.triggerInfo = wgwc::core::tasks::TriggerSummary(record);
        for (const auto& trigger : record.triggers)
            if (trigger.typeState == wgwc::core::FieldState::Available)
                info.triggerTypes.push_back(trigger.type);
        for (const auto& action : record.actions) {
            if (action.typeState != wgwc::core::FieldState::Available)
                continue;
            if (action.type == TASK_ACTION_COM_HANDLER) {
                if (info.comClassId.empty())
                    info.comClassId = action.classId;
                if (info.execPath.empty())
                    info.execPath = L"COM:" + action.classId;
            } else if (action.type == TASK_ACTION_EXEC && info.execPath.empty()) {
                info.execPath = action.execPath;
                info.arguments = action.arguments;
                info.workingDirectory = action.workingDirectory;
            }
        }
        for (const auto& related : record.relatedFiles) {
            if (!related.target.path.stable)
                continue;
            const auto& path = related.target.path.value;
            if (std::find(info.relatedFiles.begin(), info.relatedFiles.end(), path) == info.relatedFiles.end())
                info.relatedFiles.push_back(path);
            if (!info.relatedFile.empty())
                continue;
            info.relatedFile = path;
            info.companyName = related.file.evidence.company;
            info.signatureState = related.file.evidence.signature;
            if (related.file.evidence.signatureState == wgwc::core::FieldState::Available)
                info.signatureInfo =
                    CommonUtils::FormatSignatureText(info.signatureState, related.file.evidence.publisher);
        }
        info.risk = ToModuleRiskLevel(record.assessment.level);
        info.riskReason = wgwc::core::tasks::RiskReasons(record.assessment);
        m_allTasks.push_back(std::move(info));
    }
    std::sort(m_allTasks.begin(), m_allTasks.end(), [](const auto& left, const auto& right) {
        const auto name = _wcsicmp(left.name.c_str(), right.name.c_str());
        return name != 0 ? name < 0 : _wcsicmp(left.path.c_str(), right.path.c_str()) < 0;
    });
    m_filteredTasks.clear();

    // 根据参数决定是否重置过滤条件
    if (resetFilter) {
        // 设置默认过滤条件：类型=第三方，状态=全部，触发器=全部
        if (m_hComboType)
            SendMessage(m_hComboType, CB_SETCURSEL, 2, 0); // 第三方任务
        if (m_hComboState)
            SendMessage(m_hComboState, CB_SETCURSEL, 0, 0); // 全部
        if (m_hComboTrigger)
            SendMessage(m_hComboTrigger, CB_SETCURSEL, 0, 0); // 全部
        if (m_hEditFilter)
            SetWindowTextW(m_hEditFilter, L"");
    }
    // 如果 resetFilter = false，则保持当前控件的值不变

    // 标记缓存有效（缓存的是全部数据m_allTasks）
    m_hasCache = true;

    // 应用当前过滤并返回结果
    return RefreshFromCache();
}

// 从缓存刷新（重新应用当前过滤条件）
InvestigationResult TaskInvestigator::RefreshFromCache() {
    InvestigationResult result;
    result.moduleName = L"TaskInvestigator";
    result.success = m_cachedResult.success;
    result.partial = m_cachedResult.partial;
    result.stale = m_cachedResult.stale;
    result.errorCode = m_collectionError;
    result.errorMessage = m_collectionMessage;
    result.totalCount = 0;
    result.suspiciousCount = 0;

    // 缓存转换不绘制共享列表，由主窗口统一展示。
    ApplyFilter(false);

    for (size_t i = 0; i < m_filteredTasks.size(); i++) {
        const TaskInfo& info = m_filteredTasks[i];

        InvestigationItem item;
        item.name = info.name;
        item.description = info.description;

        // 填充各列数据
        item.details.push_back(info.name);
        item.details.push_back(info.path);
        item.details.push_back(StateToString(info.state));
        item.details.push_back(info.execPath);
        item.details.push_back(info.arguments);
        item.details.push_back(info.relatedFile);
        item.details.push_back(info.triggerInfo);
        item.details.push_back(info.nextRunTime);
        item.details.push_back(info.lastRunTime);
        item.details.push_back(info.author);
        item.details.push_back(info.signatureInfo);
        item.details.push_back(info.description);
        item.details.push_back(info.risk == TaskRiskLevel::None ? L"" : info.riskReason);

        // 着色和汇总数量共用本轮采集得到的风险等级。
        item.suspicion = ToModuleRiskLevel(info.risk);
        item.suspicionReason = info.riskReason;
        if (item.suspicion != SuspicionLevel::None) {
            ++result.suspiciousCount;
        }

        result.items.push_back(item);
        result.totalCount++;
    }

    m_cachedResult = result;

    return result;
}

std::vector<RiskOverviewItem> TaskInvestigator::GetRiskFindings() const {
    std::vector<RiskOverviewItem> findings;
    if (!m_hasCache) {
        return findings;
    }

    const std::wstring& updatedAt = m_collectedAt;

    for (size_t i = 0; i < m_allTasks.size(); i++) {
        const TaskInfo& info = m_allTasks[i];
        SuspicionLevel level = ToModuleRiskLevel(info.risk);
        if (level == SuspicionLevel::None) {
            continue;
        }

        RiskOverviewItem finding;
        finding.moduleId = L"task";
        finding.moduleName = L"计划任务";
        finding.tabIndex = TAB_TASKS;
        finding.level = level;
        finding.objectName = info.name;
        finding.info = TaskStateToRiskString(info.state) + L" / " + info.path;
        finding.info2 = info.relatedFile.empty() ? info.execPath : info.relatedFile;
        if (!info.actionSummary.empty()) {
            finding.info2 += L" | " + info.actionSummary;
        } else if (!info.arguments.empty()) {
            finding.info2 += L" | " + info.arguments;
        }
        finding.reason = info.riskReason;
        finding.updatedAt = updatedAt;
        finding.sourceKey = info.path;
        finding.sourceRow = (int)i;

        findings.push_back(finding);
    }

    return findings;
}

std::wstring TaskInvestigator::GetRowIconPath(int row, const InvestigationItem& item) const {
    if (row >= 0 && row < (int)m_filteredTasks.size())
        return m_filteredTasks[row].relatedFile;
    if (item.details.size() > COL_RELATED_FILE)
        return item.details[COL_RELATED_FILE];
    return L"";
}

std::wstring TaskInvestigator::GetContextFilePath(int row) const {
    if (row < 0 || row >= (int)m_filteredTasks.size())
        return L"";
    return m_filteredTasks[row].relatedFile;
}

// 使用当前显示的结果行，确保着色与缓存、筛选结果一致。
bool TaskInvestigator::GetCellHighlight(int row, int col, const InvestigationResult&, COLORREF& outColor) const {
    // 工具栏筛选会在重绘前将当前行发布到此处。
    const InvestigationResult& result = m_cachedResult;
    (void)col;
    if (row < 0 || static_cast<size_t>(row) >= result.items.size())
        return false;
    switch (result.items[static_cast<size_t>(row)].suspicion) {
    case SuspicionLevel::Critical:
    case SuspicionLevel::High:
        outColor = RGB(255, 0, 0);
        return true;
    case SuspicionLevel::Medium:
        outColor = RGB(255, 128, 0);
        return true;
    case SuspicionLevel::Low:
        outColor = RGB(128, 128, 0);
        return true;
    default:
        return false;
    }
}

// 应用过滤
void TaskInvestigator::ApplyFilter(bool updateView) {
    if (!updateView) {
        m_filteredTasks.clear();
        // 本次遍历只读取一遍控件，全部记录使用同一组筛选条件。
        int typeSel = m_hComboType ? (int)SendMessage(m_hComboType, CB_GETCURSEL, 0, 0) : 2;
        int stateSel = m_hComboState ? (int)SendMessage(m_hComboState, CB_GETCURSEL, 0, 0) : 0;
        int triggerSel = m_hComboTrigger ? (int)SendMessage(m_hComboTrigger, CB_GETCURSEL, 0, 0) : 0;
        if (typeSel == CB_ERR)
            typeSel = 2;
        if (stateSel == CB_ERR)
            stateSel = 0;
        if (triggerSel == CB_ERR)
            triggerSel = 0;

        wchar_t keyword[256] = { 0 };
        GetWindowTextW(m_hEditFilter, keyword, 256);
        std::wstring lowerKeyword = CommonUtils::ToLower(keyword);

        const auto matches = [&](const TaskInfo& info) {
            // 类型过滤: 0=全部, 1=微软, 2=非微软
            bool isMicrosoft = IsMicrosoftTask(info);
            if (typeSel == 1 && !isMicrosoft)
                return false;
            if (typeSel == 2 && isMicrosoft)
                return false;

            // 状态过滤: 0=全部, 1=就绪, 2=已停止(已禁用), 3=其他
            if (stateSel == 1 && info.state != TASK_STATE_READY)
                return false;
            if (stateSel == 2 && info.state != TASK_STATE_DISABLED)
                return false;
            if (stateSel == 3) {
                if (info.state == TASK_STATE_READY || info.state == TASK_STATE_DISABLED)
                    return false;
            }

            // 使用全部触发器的原始类型，不再依赖首个触发器文本。
            if (triggerSel > 0) {
                bool match = triggerSel == 6 && info.triggerTypes.empty();
                for (const auto type : info.triggerTypes) {
                    const bool scheduled = type == TASK_TRIGGER_TIME || type == TASK_TRIGGER_DAILY ||
                                           type == TASK_TRIGGER_WEEKLY || type == TASK_TRIGGER_MONTHLY ||
                                           type == TASK_TRIGGER_MONTHLYDOW;
                    if (triggerSel == 1 && type == TASK_TRIGGER_LOGON)
                        match = true;
                    if (triggerSel == 2 && type == TASK_TRIGGER_BOOT)
                        match = true;
                    if (triggerSel == 3 && scheduled)
                        match = true;
                    if (triggerSel == 4 && type == TASK_TRIGGER_IDLE)
                        match = true;
                    if (triggerSel == 5 && type == TASK_TRIGGER_EVENT)
                        match = true;
                    if (triggerSel == 6 && type != TASK_TRIGGER_LOGON && type != TASK_TRIGGER_BOOT && !scheduled &&
                        type != TASK_TRIGGER_IDLE && type != TASK_TRIGGER_EVENT)
                        match = true;
                }
                if (!match)
                    return false;
            }

            // 关键字过滤（包括时间字段）
            if (!lowerKeyword.empty()) {
                bool match = false;

                if (CommonUtils::ToLower(info.name).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.path).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.execPath).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.arguments).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.relatedFile).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.actionSummary).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.triggerInfo).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.nextRunTime).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.lastRunTime).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.author).find(lowerKeyword) != std::wstring::npos)
                    match = true;
                if (CommonUtils::ToLower(info.description).find(lowerKeyword) != std::wstring::npos)
                    match = true;

                if (!match)
                    return false;
            }

            return true;
        };
        for (const auto& info : m_allTasks) {
            if (matches(info))
                m_filteredTasks.push_back(info);
        }
        return;
    }
    // 由缓存构建统一筛选一次，再显示同一批记录。
    RefreshFromCache();
    UpdateListView();

    HWND hStatusBar = GetDlgItem(m_hMainWnd, IDC_STATUSBAR);
    if (hStatusBar) {
        wchar_t msg[256];
        swprintf_s(msg, L"从 %zu 个任务中 过滤 %zu 个 结果", m_allTasks.size(), m_filteredTasks.size());
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)msg);
    }
}

void TaskInvestigator::UpdateListView() {
    // 列表直接使用缓存中的展示行，避免字段和着色来源各自维护。
    wgwc::gui::PopulateCachedListView(m_hListView, m_cachedResult);
}

void TaskInvestigator::CreateToolbar(HWND hParent, HINSTANCE hInst) {
    m_hMainWnd = hParent;
    m_hInst = hInst;

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    int baseY = 33;
    int x = 5;

    // 类型下拉框
    m_hComboType = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, x,
                                   baseY + 1, 90, 200, hParent, (HMENU)IDC_TASK_COMBO_TYPE, hInst, NULL);
    SendMessage(m_hComboType, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"类型:全部");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"微软任务");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"第三方任务");
    SendMessage(m_hComboType, CB_SETCURSEL, 2, 0); // 默认第三方任务
    x += 95;

    // 状态下拉框
    m_hComboState = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, x,
                                    baseY + 1, 85, 200, hParent, (HMENU)IDC_TASK_COMBO_STATE, hInst, NULL);
    SendMessage(m_hComboState, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)L"状态:全部");
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)L"就绪");
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)L"已禁用");
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)L"其他");
    SendMessage(m_hComboState, CB_SETCURSEL, 0, 0); // 默认全部
    x += 90;

    // 触发器下拉框
    m_hComboTrigger = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, x,
                                      baseY + 1, 100, 200, hParent, (HMENU)IDC_TASK_COMBO_TRIGGER, hInst, NULL);
    SendMessage(m_hComboTrigger, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboTrigger, CB_ADDSTRING, 0, (LPARAM)L"触发器:全部");
    SendMessage(m_hComboTrigger, CB_ADDSTRING, 0, (LPARAM)L"登录时");
    SendMessage(m_hComboTrigger, CB_ADDSTRING, 0, (LPARAM)L"启动时");
    SendMessage(m_hComboTrigger, CB_ADDSTRING, 0, (LPARAM)L"计划");
    SendMessage(m_hComboTrigger, CB_ADDSTRING, 0, (LPARAM)L"空闲时");
    SendMessage(m_hComboTrigger, CB_ADDSTRING, 0, (LPARAM)L"事件时");
    SendMessage(m_hComboTrigger, CB_ADDSTRING, 0, (LPARAM)L"其他");
    SendMessage(m_hComboTrigger, CB_SETCURSEL, 0, 0); // 默认全部
    x += 105;

    // 关键字标签
    m_hStaticKeyword = CreateWindowExW(0, L"STATIC", L"过滤:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, x, baseY, 35, 22,
                                       hParent, (HMENU)IDC_TASK_STATIC_KEYWORD, hInst, NULL);
    SendMessage(m_hStaticKeyword, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 38;

    // 关键字输入框
    m_hEditFilter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, x, baseY,
                                    120, 22, hParent, (HMENU)IDC_TASK_EDIT_FILTER, hInst, NULL);
    SendMessage(m_hEditFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 125;

    m_hBtnFilter = CreateWindowExW(0, L"BUTTON", L"过滤", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 50, 22,
                                   hParent, (HMENU)IDC_TASK_BTN_FILTER, hInst, NULL);
    SendMessage(m_hBtnFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 55;

    // 刷新按钮
    m_hBtnRefresh = CreateWindowExW(0, L"BUTTON", L"刷新", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 50, 22,
                                    hParent, (HMENU)IDC_TASK_BTN_REFRESH, hInst, NULL);
    SendMessage(m_hBtnRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 55;

    m_hBtnManager = CreateWindowExW(0, L"BUTTON", L"任务管理", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 80, 22,
                                    hParent, (HMENU)IDC_TASK_BTN_MANAGER, hInst, NULL);
    SendMessage(m_hBtnManager, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 初始隐藏所有控件
    ShowToolbar(false);
}

void TaskInvestigator::DestroyToolbar() {
    if (m_hComboType) {
        DestroyWindow(m_hComboType);
        m_hComboType = NULL;
    }
    if (m_hComboState) {
        DestroyWindow(m_hComboState);
        m_hComboState = NULL;
    }
    if (m_hComboTrigger) {
        DestroyWindow(m_hComboTrigger);
        m_hComboTrigger = NULL;
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

void TaskInvestigator::ShowToolbar(bool show) {
    int cmd = show ? SW_SHOW : SW_HIDE;
    if (m_hComboType)
        ShowWindow(m_hComboType, cmd);
    if (m_hComboState)
        ShowWindow(m_hComboState, cmd);
    if (m_hComboTrigger)
        ShowWindow(m_hComboTrigger, cmd);
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

void TaskInvestigator::ResizeToolbar(int x, int y, int width) {
    (void)x;
    (void)width;
    int baseY = y + 5;
    int posX = 5;

    if (m_hComboType)
        SetWindowPos(m_hComboType, NULL, posX, baseY + 1, 90, 200, SWP_NOZORDER);
    posX += 95;
    if (m_hComboState)
        SetWindowPos(m_hComboState, NULL, posX, baseY + 1, 85, 200, SWP_NOZORDER);
    posX += 90;
    if (m_hComboTrigger)
        SetWindowPos(m_hComboTrigger, NULL, posX, baseY + 1, 100, 200, SWP_NOZORDER);
    posX += 105;
    if (m_hStaticKeyword)
        SetWindowPos(m_hStaticKeyword, NULL, posX, baseY, 35, 22, SWP_NOZORDER);
    posX += 38;
    if (m_hEditFilter)
        SetWindowPos(m_hEditFilter, NULL, posX, baseY, 120, 22, SWP_NOZORDER);
    posX += 125;
    if (m_hBtnFilter)
        SetWindowPos(m_hBtnFilter, NULL, posX, baseY, 50, 22, SWP_NOZORDER);
    posX += 55;
    if (m_hBtnRefresh)
        SetWindowPos(m_hBtnRefresh, NULL, posX, baseY, 50, 22, SWP_NOZORDER);
    posX += 55;
    if (m_hBtnManager)
        SetWindowPos(m_hBtnManager, NULL, posX, baseY, 80, 22, SWP_NOZORDER);
}

bool TaskInvestigator::HandleToolbarCommand(WORD id, WORD code) {
    switch (id) {
    case IDC_TASK_BTN_FILTER:
        ApplyFilter();
        if (m_hListView)
            SetFocus(m_hListView);
        return true;

    case IDC_TASK_BTN_REFRESH:
        // 重新扫描
        if (m_hMainWnd) {
            PostMessage(m_hMainWnd, WM_COMMAND, MAKEWPARAM(IDM_REFRESH_KEEP_FILTER, 0), 0);
        }
        if (m_hListView)
            SetFocus(m_hListView);
        return true;

    case IDC_TASK_BTN_MANAGER:
        ShellExecuteW(NULL, L"open", L"taskschd.msc", NULL, NULL, SW_SHOWNORMAL);
        return true;

    case IDC_TASK_COMBO_TYPE:
    case IDC_TASK_COMBO_STATE:
    case IDC_TASK_COMBO_TRIGGER:
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

// 任务操作：使用完整路径读取当前配置，保留原始 HRESULT。
bool TaskInvestigator::ExecuteTaskAction(UINT menuId, const TaskInfo& info) {
    namespace actions = wgwc::core::tasks::actions;
    actions::Operation operation;
    const wchar_t* actionName = nullptr;
    const wchar_t* appliedText = nullptr;
    switch (menuId) {
    case IDM_TASK_RUN:
        operation = actions::Operation::Run;
        actionName = L"运行任务";
        appliedText = L"已提交运行请求";
        break;
    case IDM_TASK_ENABLE:
        operation = actions::Operation::Enable;
        actionName = L"启用任务";
        appliedText = L"任务已启用";
        break;
    case IDM_TASK_DISABLE:
        operation = actions::Operation::Disable;
        actionName = L"禁用任务";
        appliedText = L"任务已禁用";
        break;
    case IDM_TASK_DELETE:
        operation = actions::Operation::Delete;
        actionName = L"删除任务";
        appliedText = L"任务定义已删除";
        break;
    default:
        return false;
    }

    const auto result = actions::Execute(info.path, operation);
    std::wstring message;
    bool warning = false;
    switch (result.outcome) {
    case actions::Outcome::Accepted:
    case actions::Outcome::Applied:
        message = appliedText;
        break;
    case actions::Outcome::AlreadySatisfied:
        message =
            operation == actions::Operation::Enable ? L"任务已经启用，无需重复设置" : L"任务已经禁用，无需重复设置";
        break;
    case actions::Outcome::Disabled:
        message = L"任务当前已禁用，未运行；程序不会自动启用任务。";
        warning = true;
        break;
    case actions::Outcome::DemandStartDenied:
        message = L"任务不允许按需运行，未提交运行请求。";
        warning = true;
        break;
    case actions::Outcome::Unconfirmed:
        message = L"运行请求未返回任务实例，无法确认是否启动，请查看任务状态。";
        warning = true;
        break;
    case actions::Outcome::Failed: {
        wchar_t code[16]{};
        swprintf_s(code, L"0x%08lX", static_cast<unsigned long>(result.error));
        message = std::wstring(actionName) + L"失败，HRESULT: " + code;
        if (result.error == E_ACCESSDENIED)
            message += L"\n访问被拒绝，当前权限不足。";
        else if (result.error == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
                 result.error == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND))
            message += L"\n任务或任务文件夹不存在，可能已被删除。";
        else {
            const DWORD error = HRESULT_FACILITY(result.error) == FACILITY_WIN32 ? HRESULT_CODE(result.error)
                                                                                 : static_cast<DWORD>(result.error);
            wchar_t text[512]{};
            if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, text, 512,
                               nullptr)) {
                std::wstring detail(text);
                const auto last = detail.find_last_not_of(L" \t\r\n");
                if (last != std::wstring::npos)
                    message += L"\n" + detail.substr(0, last + 1);
            }
        }
        break;
    }
    }
    message += L"\n任务路径: " + info.path;
    if (result.outcome == actions::Outcome::Failed || warning)
        MessageBoxW(m_hMainWnd, message.c_str(), L"任务操作", MB_OK | (warning ? MB_ICONWARNING : MB_ICONERROR));
    else {
        const HWND statusBar = GetDlgItem(m_hMainWnd, IDC_STATUSBAR);
        std::replace(message.begin(), message.end(), L'\n', L' ');
        if (statusBar)
            SendMessageW(statusBar, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(message.c_str()));
    }
    return actions::NeedsRefresh(result);
}

std::vector<ContextMenuItem> TaskInvestigator::GetContextMenuItems(int row) const {
    std::vector<ContextMenuItem> items;

    if (row < 0 || row >= (int)m_filteredTasks.size()) {
        return items;
    }

    const TaskInfo& info = m_filteredTasks[row];
    if (m_collectionStale || !info.identityKnown || !info.stateKnown || !info.definitionKnown || !info.enabledKnown)
        return items;
    bool isDisabled = !info.enabled;

    // 任务操作
    if (!isDisabled) {
        items.push_back({ IDM_TASK_RUN, L"立即运行", true,
                          L"确定要立即运行任务 \"" + info.path +
                              L"\" 吗？\n\n此操作会执行任务中的命令或 COM 动作，请先确认任务内容。" });
    }

    if (isDisabled) {
        items.push_back({ IDM_TASK_ENABLE, L"启用任务", false, L"" });
    } else {
        items.push_back({ IDM_TASK_DISABLE, L"禁用任务", false, L"" });
    }

    items.push_back({ IDM_TASK_DELETE, L"删除任务", true,
                      L"确定要删除任务 \"" + info.path +
                          L"\" 吗？\n此操作删除任务定义，不由本工具额外终止已运行的进程。\n此操作不可恢复！" });

    return items;
}

bool TaskInvestigator::HandleContextMenu(UINT menuId, int row) {
    if (row < 0 || row >= (int)m_filteredTasks.size()) {
        return false;
    }

    const TaskInfo info = m_filteredTasks[row];
    const bool mutation =
        menuId == IDM_TASK_RUN || menuId == IDM_TASK_ENABLE || menuId == IDM_TASK_DISABLE || menuId == IDM_TASK_DELETE;
    if (mutation &&
        (m_collectionStale || !info.identityKnown || !info.stateKnown || !info.definitionKnown || !info.enabledKnown))
        return false;

    switch (menuId) {
    case IDM_TASK_RUN:
    case IDM_TASK_ENABLE:
    case IDM_TASK_DISABLE:
    case IDM_TASK_DELETE:
        return ExecuteTaskAction(menuId, info);
    }

    return false;
}
