#include "../../presentation/GuiColumns.h"
#include "../../presentation/DisplayFormat.h"
#include <limits>
// ActivityTraceInvestigator.cpp - 活动痕迹排查模块实现
#include "ActivityTraceInvestigator.h"

#include "../../resources/resource.h"
#include <algorithm>
#include <cstring>
#include <objbase.h>
#include <vector>
#include <commctrl.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comctl32.lib")

const ColumnDef ActivityTraceInvestigator::s_Columns[] = { WG_COLUMNS_TRACES };
const int ActivityTraceInvestigator::s_ColumnCount = sizeof(s_Columns) / sizeof(s_Columns[0]);

namespace {
    // 保持原有 x64 二进制格式；读写共用边界，超限不截断采集结果。
    constexpr size_t kActivityCacheRecords = 100000;
    constexpr size_t kActivityCacheStringChars = 32768;
    constexpr ULONGLONG kActivityCacheBytes = 128ULL * 1024 * 1024;
    constexpr size_t kActivityRecordMinimum = sizeof(FILETIME) + sizeof(int) + 3 * sizeof(size_t);

    bool ValidActivityType(int value) {
        return value >= static_cast<int>(ActivityType::SystemBoot) &&
               value <= static_cast<int>(ActivityType::SoftwareInstall);
    }

    bool ValidActivityString(const std::wstring& value) {
        return value.size() <= kActivityCacheStringChars && value.find(L'\0') == std::wstring::npos;
    }

    bool ValidActivityCache(const std::vector<ActivityRecord>& records) {
        if (records.size() > kActivityCacheRecords)
            return false;
        ULONGLONG bytes = sizeof(size_t);
        for (const auto& record : records) {
            if (!ValidActivityType(static_cast<int>(record.type)) || !ValidActivityString(record.description) ||
                !ValidActivityString(record.details) || !ValidActivityString(record.source))
                return false;
            bytes += kActivityRecordMinimum +
                     (record.description.size() + record.details.size() + record.source.size()) * sizeof(wchar_t);
            if (bytes > kActivityCacheBytes)
                return false;
        }
        return true;
    }

    // 固定缓冲读取，按剩余字节检查每次分配，不将损坏记录当作成功前缀。
    class ActivityCacheReader {
    public:
        ~ActivityCacheReader() {
            if (file_ != INVALID_HANDLE_VALUE)
                CloseHandle(file_);
        }

        bool Open(const std::wstring& target) {
            file_ = CreateFileW(target.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file_ == INVALID_HANDLE_VALUE)
                return false;
            LARGE_INTEGER size{};
            if (!GetFileSizeEx(file_, &size))
                return false;
            if (size.QuadPart < static_cast<LONGLONG>(sizeof(size_t)) ||
                static_cast<ULONGLONG>(size.QuadPart) > kActivityCacheBytes) {
                SetLastError(ERROR_INVALID_DATA);
                return false;
            }
            remaining_ = static_cast<ULONGLONG>(size.QuadPart);
            return true;
        }

        bool Read(void* target, size_t size) {
            if (size > remaining_)
                return false;
            auto* output = static_cast<BYTE*>(target);
            while (size) {
                if (offset_ == available_) {
                    const DWORD requested =
                        static_cast<DWORD>((std::min)(remaining_, static_cast<ULONGLONG>(sizeof(buffer_))));
                    available_ = 0;
                    if (!ReadFile(file_, buffer_, requested, &available_, nullptr) || !available_ ||
                        available_ > requested)
                        return false;
                    offset_ = 0;
                }
                const size_t count = (std::min)(size, static_cast<size_t>(available_ - offset_));
                std::memcpy(output, buffer_ + offset_, count);
                offset_ += static_cast<DWORD>(count);
                remaining_ -= count;
                output += count;
                size -= count;
            }
            return true;
        }

        bool String(std::wstring& value) {
            size_t length = 0;
            if (!Read(&length, sizeof(length)) || length > kActivityCacheStringChars ||
                length > remaining_ / sizeof(wchar_t))
                return false;
            value.resize(length);
            return Read(value.data(), length * sizeof(wchar_t)) && ValidActivityString(value);
        }

        ULONGLONG Remaining() const {
            return remaining_;
        }

        bool Close() {
            const HANDLE file = file_;
            file_ = INVALID_HANDLE_VALUE;
            return CloseHandle(file) != FALSE;
        }

    private:
        HANDLE file_ = INVALID_HANDLE_VALUE;
        ULONGLONG remaining_ = 0;
        BYTE buffer_[64 * 1024];
        DWORD offset_ = 0, available_ = 0;
    };

    // 临时文件与目标同目录，仅在写入、刷新、关闭均成功后替换旧缓存。
    class ActivityCacheWriter {
    public:
        ~ActivityCacheWriter() {
            if (file_ != INVALID_HANDLE_VALUE)
                CloseHandle(file_);
            if (!temporary_.empty())
                DeleteFileW(temporary_.c_str());
        }

        bool Open(const std::wstring& target) {
            const auto prefix = target + L".tmp-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                std::to_wstring(GetTickCount64()) + L"-";
            for (unsigned attempt = 0; attempt < 32; ++attempt) {
                const auto candidate = prefix + std::to_wstring(attempt);
                file_ = CreateFileW(candidate.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
                if (file_ != INVALID_HANDLE_VALUE) {
                    temporary_ = candidate;
                    return true;
                }
                const DWORD error = GetLastError();
                if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
                    return Fail(error);
            }
            return Fail(ERROR_FILE_EXISTS);
        }

        bool Write(const void* data, size_t size) {
            const auto* bytes = static_cast<const BYTE*>(data);
            while (size) {
                const size_t count = (std::min)(size, sizeof(buffer_) - used_);
                std::memcpy(buffer_ + used_, bytes, count);
                used_ += static_cast<DWORD>(count);
                bytes += count;
                size -= count;
                if (used_ == sizeof(buffer_) && !Flush())
                    return false;
            }
            return true;
        }

        bool String(const std::wstring& value) {
            const size_t length = value.size();
            return Write(&length, sizeof(length)) && Write(value.data(), length * sizeof(wchar_t));
        }

        bool Commit(const std::wstring& target) {
            if (!Flush())
                return false;
            if (!FlushFileBuffers(file_))
                return Fail(GetLastError());
            const BOOL closed = CloseHandle(file_);
            file_ = INVALID_HANDLE_VALUE;
            if (!closed)
                return Fail(GetLastError());
            if (!MoveFileExW(temporary_.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                return Fail(GetLastError());
            temporary_.clear();
            return true;
        }

        DWORD Error() const {
            return error_;
        }

    private:
        bool Fail(DWORD error) {
            error_ = error ? error : ERROR_WRITE_FAULT;
            return false;
        }

        bool Flush() {
            if (!used_)
                return true;
            DWORD written = 0;
            if (!WriteFile(file_, buffer_, used_, &written, nullptr))
                return Fail(GetLastError());
            if (written != used_)
                return Fail(ERROR_WRITE_FAULT);
            used_ = 0;
            return true;
        }

        HANDLE file_ = INVALID_HANDLE_VALUE;
        std::wstring temporary_;
        BYTE buffer_[64 * 1024];
        DWORD used_ = 0, error_ = ERROR_SUCCESS;
    };
}

ActivityTraceInvestigator::ActivityTraceInvestigator() {
    // 初始化 COM（用于读取快捷方式）
    CoInitialize(NULL);

    m_hToolbarPanel = NULL;
    m_hBtnScan = NULL;
    m_hBtnLoad = NULL;
    m_hComboType = NULL;
    m_hComboSource = NULL;
    m_hStaticFilter = NULL;
    m_hEditFilter = NULL;
    m_hBtnFilter = NULL;
    m_hMainWnd = NULL;
    m_hListView = NULL;
    m_hInst = NULL;

    m_filterType = 0;   // 全部
    m_filterSource = 0; // 全部
    m_filterText = L"";
}

ActivityTraceInvestigator::~ActivityTraceInvestigator() {
    DestroyToolbar();
    CoUninitialize();
}

// 主调查函数

InvestigationResult ActivityTraceInvestigator::Investigate(bool resetFilter) {
    // 如果没有数据，返回空结果（首次进入时显示提示）
    if (m_records.empty()) {
        InvestigationResult result;
        result.moduleName = GetModuleName();
        result.success = true;
        result.totalCount = 0;
        result.suspiciousCount = 0;
        return result;
    }

    // 重置过滤条件
    if (resetFilter) {
        m_filterType = 0;
        m_filterSource = 0;
        m_filterText.clear();

        if (m_hComboType) {
            SendMessage(m_hComboType, CB_SETCURSEL, 0, 0);
        }
        if (m_hComboSource) {
            SendMessage(m_hComboSource, CB_SETCURSEL, 0, 0);
        }
        if (m_hEditFilter) {
            SetWindowTextW(m_hEditFilter, L"");
        }
    }

    // 应用当前过滤条件并返回结果
    return BuildFilteredResult();
}

// 执行实际扫描（由"扫描"按钮触发）
void ActivityTraceInvestigator::StartScan() {
    // 清空之前的记录
    m_records.clear();
    m_filteredRecords.clear();

    // 收集各类数据
    wgwc::core::CollectionContext context;
    context.maxRecords = (std::numeric_limits<std::size_t>::max)();
    auto collection = wgwc::core::traces::CollectActivities(context);
    m_records = std::move(collection.records);

    // 按时间倒序排序（最新的在前）
    std::sort(m_records.begin(), m_records.end());

    // 自动保存缓存（供"加载"按钮使用）
    if (!m_records.empty()) {
        SaveToCacheFile();
    }
}

std::wstring ActivityTraceInvestigator::FormatFileTime(const FILETIME& ft) const {
    return wgwc::gui::presentation::LocalTime((static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime);
}

std::wstring ActivityTraceInvestigator::GetActivityTypeString(ActivityType type) const {
    return wgwc::gui::presentation::ActivityName(type);
}

bool ActivityTraceInvestigator::GetCellHighlight(int row, int col, const InvestigationResult& result,
                                                 COLORREF& outColor) const {
    (void)row;
    (void)col;
    (void)result;
    (void)outColor;
    return false;
}

// 工具栏实现

void ActivityTraceInvestigator::CreateToolbar(HWND hParent, HINSTANCE hInst) {
    m_hMainWnd = hParent;
    m_hInst = hInst;

    // 创建工具栏面板（仅用于布局）
    m_hToolbarPanel = CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | SS_SIMPLE, 0, 0, 0, 0, hParent, NULL, hInst, NULL);

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    int xPos = 5;

    // 扫描按钮
    m_hBtnScan = CreateWindowExW(0, L"BUTTON", L"扫描", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, xPos, 33, 50, 22,
                                 hParent, (HMENU)IDC_ACT_BTN_SCAN, hInst, NULL);
    SendMessage(m_hBtnScan, WM_SETFONT, (WPARAM)hFont, TRUE);
    xPos += 55;

    // 加载按钮
    m_hBtnLoad = CreateWindowExW(0, L"BUTTON", L"加载", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, xPos, 33, 50, 22,
                                 hParent, (HMENU)IDC_ACT_BTN_LOAD, hInst, NULL);
    SendMessage(m_hBtnLoad, WM_SETFONT, (WPARAM)hFont, TRUE);
    xPos += 58;

    // 类型下拉框
    m_hComboType = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, xPos,
                                   33, 100, 200, hParent, (HMENU)IDC_ACT_COMBO_TYPE, hInst, NULL);
    SendMessage(m_hComboType, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"类型:全部");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"系统启动");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"系统睡眠");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"系统唤醒");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"用户登录");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"程序执行");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"文档访问");
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)L"软件安装");
    SendMessage(m_hComboType, CB_SETCURSEL, 0, 0); // 默认全部
    xPos += 105;

    // 来源下拉框
    m_hComboSource = CreateWindowExW(0, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, xPos,
                                     33, 110, 200, hParent, (HMENU)IDC_ACT_COMBO_SOURCE, hInst, NULL);
    SendMessage(m_hComboSource, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hComboSource, CB_ADDSTRING, 0, (LPARAM)L"来源:全部");
    SendMessage(m_hComboSource, CB_ADDSTRING, 0, (LPARAM)L"EventLog");
    SendMessage(m_hComboSource, CB_ADDSTRING, 0, (LPARAM)L"Prefetch");
    SendMessage(m_hComboSource, CB_ADDSTRING, 0, (LPARAM)L"UserAssist");
    SendMessage(m_hComboSource, CB_ADDSTRING, 0, (LPARAM)L"Recent");
    SendMessage(m_hComboSource, CB_ADDSTRING, 0, (LPARAM)L"Uninstall");
    SendMessage(m_hComboSource, CB_SETCURSEL, 0, 0); // 默认全部
    xPos += 115;

    m_hStaticFilter = CreateWindowExW(0, L"STATIC", L"过滤:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, xPos, 33, 35, 22,
                                      hParent, (HMENU)IDC_ACT_STATIC_FILTER, hInst, NULL);
    SendMessage(m_hStaticFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    xPos += 37;

    m_hEditFilter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, xPos, 33,
                                    150, 22, hParent, (HMENU)IDC_ACT_EDIT_FILTER, hInst, NULL);
    SendMessage(m_hEditFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    xPos += 155;

    m_hBtnFilter = CreateWindowExW(0, L"BUTTON", L"过滤", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, xPos, 33, 50, 22,
                                   hParent, (HMENU)IDC_ACT_BTN_FILTER, hInst, NULL);
    SendMessage(m_hBtnFilter, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 初始隐藏所有控件
    ShowToolbar(false);
}

void ActivityTraceInvestigator::DestroyToolbar() {
    if (m_hBtnScan) {
        DestroyWindow(m_hBtnScan);
        m_hBtnScan = NULL;
    }
    if (m_hBtnLoad) {
        DestroyWindow(m_hBtnLoad);
        m_hBtnLoad = NULL;
    }
    if (m_hComboType) {
        DestroyWindow(m_hComboType);
        m_hComboType = NULL;
    }
    if (m_hComboSource) {
        DestroyWindow(m_hComboSource);
        m_hComboSource = NULL;
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
    if (m_hToolbarPanel) {
        DestroyWindow(m_hToolbarPanel);
        m_hToolbarPanel = NULL;
    }
}

void ActivityTraceInvestigator::ShowToolbar(bool show) {
    int cmd = show ? SW_SHOW : SW_HIDE;
    if (m_hBtnScan)
        ShowWindow(m_hBtnScan, cmd);
    if (m_hBtnLoad)
        ShowWindow(m_hBtnLoad, cmd);
    if (m_hComboType)
        ShowWindow(m_hComboType, cmd);
    if (m_hComboSource)
        ShowWindow(m_hComboSource, cmd);
    if (m_hStaticFilter)
        ShowWindow(m_hStaticFilter, cmd);
    if (m_hEditFilter)
        ShowWindow(m_hEditFilter, cmd);
    if (m_hBtnFilter)
        ShowWindow(m_hBtnFilter, cmd);
}

void ActivityTraceInvestigator::ResizeToolbar(int x, int y, int width) {
    (void)x;
    (void)width;
    // 控件位置在创建时已固定，这里只需要调整 y 坐标
    int baseY = y + 5;
    int xPos = 5;

    if (m_hBtnScan) {
        SetWindowPos(m_hBtnScan, NULL, xPos, baseY, 50, 22, SWP_NOZORDER);
        xPos += 55;
    }
    if (m_hBtnLoad) {
        SetWindowPos(m_hBtnLoad, NULL, xPos, baseY, 50, 22, SWP_NOZORDER);
        xPos += 58;
    }
    if (m_hComboType) {
        SetWindowPos(m_hComboType, NULL, xPos, baseY, 100, 22, SWP_NOZORDER);
        xPos += 105;
    }
    if (m_hComboSource) {
        SetWindowPos(m_hComboSource, NULL, xPos, baseY, 110, 22, SWP_NOZORDER);
        xPos += 115;
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
    }
}

bool ActivityTraceInvestigator::HandleToolbarCommand(WORD id, WORD code) {
    (void)code;

    switch (id) {
    case IDC_ACT_BTN_SCAN:
        // 执行扫描
        StartScan();
        // 触发刷新显示
        if (m_hMainWnd) {
            PostMessage(m_hMainWnd, WM_COMMAND, MAKEWPARAM(IDM_REFRESH, 0), 0);
        }
        return true;

    case IDC_ACT_BTN_LOAD:
        // 加载失败时不刷新，避免清空当前列表或重置筛选条件。
        if (LoadFromCacheFile() && m_hMainWnd) {
            PostMessage(m_hMainWnd, WM_COMMAND, MAKEWPARAM(IDM_REFRESH, 0), 0);
        }
        return true;

    case IDC_ACT_BTN_FILTER:
        ApplyFilter();
        return true;

    case IDC_ACT_COMBO_TYPE:
    case IDC_ACT_COMBO_SOURCE:
        // 下拉框选择变化时自动过滤
        if (code == CBN_SELCHANGE) {
            ApplyFilter();
        }
        return true;
    }

    return false;
}

void ActivityTraceInvestigator::ApplyFilter() {
    if (m_hComboType) {
        m_filterType = (int)SendMessage(m_hComboType, CB_GETCURSEL, 0, 0);
    }

    if (m_hComboSource) {
        m_filterSource = (int)SendMessage(m_hComboSource, CB_GETCURSEL, 0, 0);
    }

    if (m_hEditFilter) {
        wchar_t buffer[256] = { 0 };
        GetWindowTextW(m_hEditFilter, buffer, 256);
        m_filterText = buffer;

        std::transform(m_filterText.begin(), m_filterText.end(), m_filterText.begin(), ::towlower);
    }

    // 应用过滤并构建结果
    BuildFilteredResult();

    // 直接更新 ListView
    UpdateListView();

    UpdateStatusBar();
}

void ActivityTraceInvestigator::UpdateListView() {
    if (!m_hListView)
        return;

    SendMessage(m_hListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(m_hListView);

    for (size_t i = 0; i < m_filteredRecords.size(); i++) {
        const ActivityRecord& record = m_filteredRecords[i];

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;

        // 需要使用临时变量保存字符串，因为 c_str() 返回的指针会失效
        std::wstring timeStr = FormatFileTime(record.timestamp);
        lvi.pszText = (LPWSTR)timeStr.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        std::wstring typeStr = GetActivityTypeString(record.type);
        ListView_SetItemText(m_hListView, (int)i, COL_TYPE, (LPWSTR)typeStr.c_str());

        ListView_SetItemText(m_hListView, (int)i, COL_DESCRIPTION, (LPWSTR)record.description.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_DETAILS, (LPWSTR)record.details.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_SOURCE, (LPWSTR)record.source.c_str());
    }

    SendMessage(m_hListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(m_hListView, NULL, TRUE);
}

void ActivityTraceInvestigator::UpdateStatusBar() {
    HWND hStatusBar = GetDlgItem(m_hMainWnd, IDC_STATUSBAR);
    if (hStatusBar) {
        wchar_t msg[256];
        swprintf_s(msg, L"活动痕迹 - 从 %zu 条记录中过滤出 %zu 条结果", m_records.size(), m_filteredRecords.size());
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)msg);
    }
}

bool ActivityTraceInvestigator::MatchesFilter(const ActivityRecord& record) const {
    // 1. 类型过滤
    if (m_filterType > 0) {
        int expectedType = m_filterType - 1; // 转换为 ActivityType 枚举值
        if ((int)record.type != expectedType) {
            return false;
        }
    }

    // 2. 来源过滤
    if (m_filterSource > 0) {
        std::wstring sourcePrefix;
        switch (m_filterSource) {
        case 1:
            sourcePrefix = L"EventLog";
            break;
        case 2:
            sourcePrefix = L"Prefetch";
            break;
        case 3:
            sourcePrefix = L"UserAssist";
            break;
        case 4:
            sourcePrefix = L"Recent";
            break;
        case 5:
            sourcePrefix = L"Uninstall";
            break;
        }
        if (record.source.find(sourcePrefix) != 0) {
            return false;
        }
    }

    // 3. 文本过滤（搜索所有字段：时间、类型、描述、详细信息、来源）
    if (!m_filterText.empty()) {
        std::wstring lowerTime = FormatFileTime(record.timestamp);
        std::transform(lowerTime.begin(), lowerTime.end(), lowerTime.begin(), ::towlower);

        std::wstring lowerType = GetActivityTypeString(record.type);
        std::transform(lowerType.begin(), lowerType.end(), lowerType.begin(), ::towlower);

        std::wstring lowerDesc = record.description;
        std::transform(lowerDesc.begin(), lowerDesc.end(), lowerDesc.begin(), ::towlower);

        std::wstring lowerDetails = record.details;
        std::transform(lowerDetails.begin(), lowerDetails.end(), lowerDetails.begin(), ::towlower);

        std::wstring lowerSource = record.source;
        std::transform(lowerSource.begin(), lowerSource.end(), lowerSource.begin(), ::towlower);

        if (lowerTime.find(m_filterText) == std::wstring::npos && lowerType.find(m_filterText) == std::wstring::npos &&
            lowerDesc.find(m_filterText) == std::wstring::npos &&
            lowerDetails.find(m_filterText) == std::wstring::npos &&
            lowerSource.find(m_filterText) == std::wstring::npos) {
            return false;
        }
    }

    return true;
}

InvestigationResult ActivityTraceInvestigator::BuildFilteredResult() {
    InvestigationResult result;
    result.moduleName = GetModuleName();
    result.success = true;

    m_filteredRecords.clear();
    for (const auto& record : m_records) {
        if (MatchesFilter(record)) {
            m_filteredRecords.push_back(record);
        }
    }

    for (const auto& record : m_filteredRecords) {
        std::vector<std::wstring> row;
        row.push_back(FormatFileTime(record.timestamp));
        row.push_back(GetActivityTypeString(record.type));
        row.push_back(record.description);
        row.push_back(record.details);
        row.push_back(record.source);

        result.rows.push_back(row);
    }

    result.totalCount = (DWORD)m_filteredRecords.size();

    return result;
}

static std::wstring GetActivityCacheFilePath() {
    wchar_t exePath[MAX_PATH]{};
    const DWORD copied = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (!copied)
        return {};
    if (copied >= MAX_PATH) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return {};
    }
    std::wstring exeDir(exePath, copied);
    const size_t pos = exeDir.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        SetLastError(ERROR_INVALID_NAME);
        return {};
    }
    exeDir.resize(pos + 1);
    const auto dataDir = exeDir + L"data";
    const auto cacheDir = dataDir + L"\\cache";
    if (!CreateDirectoryW(dataDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        return {};
    if (!CreateDirectoryW(cacheDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        return {};
    return cacheDir + L"\\activity.dat";
}

bool ActivityTraceInvestigator::LoadFromCacheFile() {
    const auto invalidCache = [this]() {
        if (m_hMainWnd)
            MessageBoxW(m_hMainWnd, L"缓存文件无效或读取失败，保留当前结果和筛选条件。", L"提示",
                        MB_OK | MB_ICONWARNING);
        return false;
    };
    const auto filePath = GetActivityCacheFilePath();
    if (filePath.empty())
        return invalidCache();
    ActivityCacheReader reader;
    if (!reader.Open(filePath)) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            if (m_hMainWnd)
                MessageBoxW(m_hMainWnd, L"没有找到历史缓存文件", L"提示", MB_OK | MB_ICONINFORMATION);
            return false;
        }
        return invalidCache();
    }

    size_t recordCount = 0;
    if (!reader.Read(&recordCount, sizeof(recordCount)) || recordCount > kActivityCacheRecords ||
        recordCount > reader.Remaining() / kActivityRecordMinimum)
        return invalidCache();
    std::vector<ActivityRecord> loadedRecords;
    loadedRecords.reserve(recordCount);
    for (size_t i = 0; i < recordCount; ++i) {
        ActivityRecord record;
        int type = 0;
        if (!reader.Read(&record.timestamp, sizeof(record.timestamp)) || !reader.Read(&type, sizeof(type)) ||
            !ValidActivityType(type) || !reader.String(record.description) || !reader.String(record.details) ||
            !reader.String(record.source))
            return invalidCache();
        record.type = static_cast<ActivityType>(type);
        loadedRecords.push_back(std::move(record));
    }
    if (reader.Remaining() != 0 || !reader.Close())
        return invalidCache();

    // 只有整份文件有效时才替换数据；合法空缓存与读取失败分别处理。
    m_records = std::move(loadedRecords);
    m_filteredRecords = m_records;
    return true;
}

void ActivityTraceInvestigator::SaveToCacheFile() {
    if (!ValidActivityCache(m_records)) {
        if (m_hMainWnd)
            MessageBoxW(m_hMainWnd, L"结果超出缓存限制或包含无效字段，未更新历史缓存；当前结果仍可查看和导出。",
                        L"提示", MB_OK | MB_ICONWARNING);
        return;
    }
    const auto filePath = GetActivityCacheFilePath();
    ActivityCacheWriter writer;
    const size_t recordCount = m_records.size();
    bool saved = !filePath.empty() && writer.Open(filePath);
    DWORD error = saved ? ERROR_SUCCESS : (filePath.empty() ? GetLastError() : writer.Error());
    if (saved)
        saved = writer.Write(&recordCount, sizeof(recordCount));
    for (const auto& record : m_records) {
        if (!saved)
            break;
        const int type = static_cast<int>(record.type);
        saved = writer.Write(&record.timestamp, sizeof(record.timestamp)) && writer.Write(&type, sizeof(type)) &&
                writer.String(record.description) && writer.String(record.details) && writer.String(record.source);
    }
    if (saved)
        saved = writer.Commit(filePath);
    if (!saved && m_hMainWnd) {
        if (writer.Error())
            error = writer.Error();
        if (!error)
            error = ERROR_WRITE_FAULT;
        const auto message =
            L"缓存保存失败，未更新历史缓存（错误码: " + std::to_wstring(error) + L"）；当前结果仍可查看和导出。";
        MessageBoxW(m_hMainWnd, message.c_str(), L"提示", MB_OK | MB_ICONWARNING);
    }
}
