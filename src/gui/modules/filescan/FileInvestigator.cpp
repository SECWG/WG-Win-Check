#include "../../presentation/GuiColumns.h"
#include "../../presentation/DisplayFormat.h"
#include <limits>
// FileInvestigator.cpp - 文件排查模块实现
// 使用单线程迭代扫描，避免多线程问题

#include "FileInvestigator.h"

#include "../../resources/resource.h"
#include <algorithm>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <fstream>
#include <cstring>

#ifdef WGWC_FILESCAN_TESTS
// 仅回归构建使用故障注入，产品仍直接调用系统文件接口。
BOOL WINAPI FileCacheTestWriteFile(HANDLE file, LPCVOID data, DWORD size, LPDWORD written);
BOOL WINAPI FileCacheTestFlush(HANDLE file);
#endif

namespace {
    constexpr size_t kMaximumCachedFiles = 100000;

    struct FileResultLock {
        CRITICAL_SECTION& section;

        explicit FileResultLock(CRITICAL_SECTION& value) : section(value) {
            EnterCriticalSection(&section);
        }

        ~FileResultLock() {
            LeaveCriticalSection(&section);
        }

        FileResultLock(const FileResultLock&) = delete;
        FileResultLock& operator=(const FileResultLock&) = delete;
    };

    // 先写入同目录临时文件，确认完整落盘后才替换历史缓存。
    class FileCacheWriter {
    public:
        ~FileCacheWriter() {
            if (file_ != INVALID_HANDLE_VALUE)
                CloseHandle(file_);
            if (temporary_[0])
                DeleteFileW(temporary_);
        }

        bool Open(const std::wstring& target) {
            const auto slash = target.find_last_of(L"\\/");
            if (slash == std::wstring::npos)
                return Fail(ERROR_INVALID_NAME);
            const auto directory = target.substr(0, slash + 1);
            if (!GetTempFileNameW(directory.c_str(), L"wgc", 0, temporary_))
                return Fail(GetLastError());
            file_ = CreateFileW(temporary_, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            return file_ != INVALID_HANDLE_VALUE || Fail(GetLastError());
        }

        bool Write(const void* data, size_t size) {
            const auto* bytes = static_cast<const BYTE*>(data);
            while (size) {
                const size_t count = (std::min)(size, sizeof(buffer_) - used_);
                std::memcpy(buffer_ + used_, bytes, count);
                used_ += static_cast<DWORD>(count);
                bytes += count;
                size -= count;
                if (used_ == sizeof(buffer_) && !FlushBuffer())
                    return false;
            }
            return true;
        }

        bool Commit(const std::wstring& target) {
            if (!FlushBuffer())
                return false;
#ifdef WGWC_FILESCAN_TESTS
            if (!FileCacheTestFlush(file_))
                return Fail(GetLastError());
#else
            if (!FlushFileBuffers(file_))
                return Fail(GetLastError());
#endif
            const BOOL closed = CloseHandle(file_);
            file_ = INVALID_HANDLE_VALUE;
            if (!closed)
                return Fail(GetLastError());
            if (!MoveFileExW(temporary_, target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                return Fail(GetLastError());
            temporary_[0] = L'\0';
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

        bool FlushBuffer() {
            if (!used_)
                return true;
            DWORD written = 0;
#ifdef WGWC_FILESCAN_TESTS
            const BOOL success = FileCacheTestWriteFile(file_, buffer_, used_, &written);
#else
            const BOOL success = WriteFile(file_, buffer_, used_, &written, NULL);
#endif
            if (!success)
                return Fail(GetLastError());
            if (written != used_)
                return Fail(ERROR_WRITE_FAULT);
            used_ = 0;
            return true;
        }

        HANDLE file_ = INVALID_HANDLE_VALUE;
        wchar_t temporary_[MAX_PATH]{};
        // 固定缓冲避免逐字段调用系统写入，也不复制整份扫描结果。
        BYTE buffer_[64 * 1024];
        DWORD used_ = 0;
        DWORD error_ = ERROR_SUCCESS;
    };
}

// 静态后缀分组

const ColumnDef FileInvestigator::s_Columns[] = { WG_COLUMNS_FILES };
const int FileInvestigator::s_ColumnCount = sizeof(s_Columns) / sizeof(s_Columns[0]);

FileInvestigator::FileInvestigator()
    : m_hBtnScan(NULL), m_hBtnStop(NULL), m_hBtnLoad(NULL), m_hBtnScanConfig(NULL), m_hComboLimit(NULL),
      m_hStaticKeyword(NULL), m_hEditFilter(NULL), m_hStaticExclude(NULL), m_hEditExclude(NULL), m_hBtnFilter(NULL),
      m_hMainWnd(NULL), m_hListView(NULL), m_hInst(NULL), m_scanning(false), m_completedDirs(0), m_totalDirs(0),
      m_scannedFiles(0), m_matchedCount(0), m_limitReached(false), m_hScanThread(NULL), m_timerId(7777) {
    InitializeCriticalSection(&m_resultCS);
    // m_scanConfig 使用默认值，不持久化
}

FileInvestigator::~FileInvestigator() {
    DestroyToolbar();
    DeleteCriticalSection(&m_resultCS);
}

// 后缀与路径辅助函数

std::vector<std::wstring> FileInvestigator::ParseMultilineEdit(HWND hEdit) {
    std::vector<std::wstring> lines;
    if (!hEdit)
        return lines;

    int len = GetWindowTextLengthW(hEdit);
    if (len <= 0)
        return lines;

    std::vector<wchar_t> buf(len + 1);
    GetWindowTextW(hEdit, buf.data(), len + 1);

    std::wstring text = buf.data();
    size_t pos = 0;
    while (pos < text.length()) {
        size_t end = text.find(L'\n', pos);
        if (end == std::wstring::npos)
            end = text.length();

        std::wstring line = text.substr(pos, end - pos);
        if (!line.empty() && line.back() == L'\r') {
            line.pop_back();
        }
        // 去除首尾空白
        size_t start = line.find_first_not_of(L" \t");
        size_t lineEnd = line.find_last_not_of(L" \t");
        if (start != std::wstring::npos && lineEnd != std::wstring::npos) {
            line = line.substr(start, lineEnd - start + 1);
            if (!line.empty()) {
                lines.push_back(line);
            }
        }

        pos = end + 1;
    }

    return lines;
}

void FileInvestigator::SetMultilineEdit(HWND hEdit, const std::vector<std::wstring>& lines) {
    if (!hEdit)
        return;

    std::wstring text;
    for (size_t i = 0; i < lines.size(); i++) {
        if (i > 0)
            text += L"\r\n";
        text += lines[i];
    }
    SetWindowTextW(hEdit, text.c_str());
}

// 文件类型匹配

std::wstring FileInvestigator::FormatFileSize(ULONGLONG size) {
    return wgwc::gui::presentation::FileSize(size);
}

std::wstring FileInvestigator::FileTimeToString(const FILETIME& ft) {
    return wgwc::gui::presentation::LocalTime((static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime);
}

// 扫描目录

int FileInvestigator::GetCurrentResultLimit() {
    if (!m_hComboLimit)
        return 3000;
    int sel = (int)SendMessage(m_hComboLimit, CB_GETCURSEL, 0, 0);
    switch (sel) {
    case LIMIT_500:
        return 500;
    case LIMIT_1000:
        return 1000;
    case LIMIT_3000:
        return 3000;
    case LIMIT_5000:
        return 5000;
    case LIMIT_10000:
        return 10000;
    case LIMIT_UNLIMITED:
        return INT_MAX;
    default:
        return 3000;
    }
}

bool FileInvestigator::AddMatchedFile(const FileInfo& info) {
    EnterCriticalSection(&m_resultCS);
    bool added = false;
    if (m_scanning) {
        if (m_matchedFiles.size() < static_cast<size_t>(m_activeResultLimit)) {
            m_matchedFiles.push_back(info);
            m_matchedCount++;
            added = true;
        } else {
            m_limitReached = true;
        }
    }
    LeaveCriticalSection(&m_resultCS);
    return added;
}

// 迭代扫描（单线程，非递归）

void FileInvestigator::ScanAllDirectories() {
    wgwc::core::CollectionContext context;
    context.maxRecords = (std::numeric_limits<std::size_t>::max)();
    wgwc::core::filescan::ScanFiles(
        m_activeScanConfig, context,
        [this](const FileInfo& record) {
            return AddMatchedFile(record);
        },
        [this](const wgwc::core::filescan::Progress& p) {
            m_totalDirs = static_cast<int>(p.totalDirs);
            m_completedDirs = static_cast<int>(p.completedDirs);
            m_scannedFiles = static_cast<int>(p.scannedFiles);
        },
        [this]() {
            return !m_scanning || m_limitReached;
        });
    m_scanning = false;
}

// 扫描线程入口
DWORD WINAPI FileInvestigator::ScanThreadProc(LPVOID param) {
    FileInvestigator* pThis = (FileInvestigator*)param;
    if (pThis) {
        pThis->ScanAllDirectories();
    }
    return 0;
}

// 扫描控制

void FileInvestigator::StartScan() {
    if (m_hScanThread || m_scanning)
        return;

    const int limit = GetCurrentResultLimit();
    if (limit == INT_MAX) {
        int ret = MessageBoxW(m_hMainWnd, L"您选择了\"不限制\"结果数量，这可能导致内存占用过高。\n\n确定要继续吗？",
                              L"警告", MB_YESNO | MB_ICONWARNING);
        if (ret != IDYES)
            return;
    }

    // 固定本轮配置，工作线程不读取界面控件或可修改的配置。
    m_activeScanConfig = m_scanConfig;
    m_activeResultLimit = limit;
    m_stopRequested = false;
    EnterCriticalSection(&m_resultCS);
    m_matchedFiles.clear();
    m_filteredFiles.clear();
    LeaveCriticalSection(&m_resultCS);

    m_scanning = true;
    m_limitReached = false;
    m_completedDirs = 0;
    m_totalDirs = 0;
    m_scannedFiles = 0;
    m_matchedCount = 0;
    UpdateListView();

    m_hScanThread = CreateThread(NULL, 0, ScanThreadProc, this, 0, NULL);
    if (!m_hScanThread) {
        const DWORD error = GetLastError();
        m_scanning = false;
        UpdateScanControls();
        UpdateStatusBar(L"无法启动扫描，错误码: " + std::to_wstring(error));
        return;
    }

    UpdateScanControls();
    if (m_hMainWnd && !SetTimer(m_hMainWnd, m_timerId, 300, NULL)) {
        const DWORD error = GetLastError();
        StopScan(true);
        UpdateScanControls();
        ApplyFilter();
        UpdateStatusBar(L"无法更新扫描进度，错误码: " + std::to_wstring(error));
        return;
    }
    UpdateStatusBar(L"正在扫描...");
}

void FileInvestigator::UpdateScanControls() {
    const bool busy = m_hScanThread != NULL;
    if (m_hBtnScan)
        EnableWindow(m_hBtnScan, !busy);
    if (m_hBtnStop)
        EnableWindow(m_hBtnStop, busy && m_scanning.load());
    if (m_hComboLimit)
        EnableWindow(m_hComboLimit, !busy);
    if (m_hBtnLoad)
        EnableWindow(m_hBtnLoad, !busy);
    if (m_hBtnScanConfig)
        EnableWindow(m_hBtnScanConfig, !busy);
}

void FileInvestigator::StopScan(bool waitForExit) {
    if (!m_hScanThread)
        return;

    if (m_scanning.exchange(false)) {
        if (!m_limitReached)
            m_stopRequested = true;
        CancelSynchronousIo(m_hScanThread);
    }

    // 普通停止不阻塞界面；销毁模块前必须等待线程退出。
    const DWORD waitResult = WaitForSingleObject(m_hScanThread, waitForExit ? INFINITE : 0);
    if (waitResult != WAIT_OBJECT_0) {
        if (!waitForExit) {
            UpdateScanControls();
            UpdateStatusBar(waitResult == WAIT_TIMEOUT ? L"正在停止扫描..." : L"无法确认扫描线程状态");
        }
        return;
    }

    CloseHandle(m_hScanThread);
    m_hScanThread = NULL;
    if (m_hMainWnd)
        KillTimer(m_hMainWnd, m_timerId);

    EnterCriticalSection(&m_resultCS);
    std::sort(m_matchedFiles.begin(), m_matchedFiles.end());
    LeaveCriticalSection(&m_resultCS);

    if (!waitForExit) {
        UpdateScanControls();
        ApplyFilter();
        wchar_t buf[256];
        if (m_limitReached) {
            swprintf_s(buf, L"已达上限 %d 条，扫描已停止 | 显示: %zu（已按修改时间排序）", m_activeResultLimit,
                       m_filteredFiles.size());
        } else {
            swprintf_s(buf, L"%s | 目录: %d | 已扫描: %d | 匹配: %d | 显示: %zu（已按修改时间排序）",
                       m_stopRequested ? L"扫描已停止" : L"扫描已完成", m_completedDirs.load(), m_scannedFiles.load(),
                       m_matchedCount.load(), m_filteredFiles.size());
        }
        UpdateStatusBar(buf);
    }

    if (m_matchedCount > 0)
        SaveToCacheFile();
}

// 定时器和进度

void FileInvestigator::OnTimer(UINT_PTR id) {
    if (id != m_timerId || !m_hScanThread)
        return;
    if (!m_scanning || m_limitReached) {
        StopScan();
    } else {
        UpdateProgress();
    }
}

void FileInvestigator::UpdateStatusBar(const std::wstring& msg) {
    HWND hStatusBar = GetDlgItem(m_hMainWnd, IDC_STATUSBAR);
    if (hStatusBar) {
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)msg.c_str());
    }
}

void FileInvestigator::UpdateProgress() {
    wchar_t buf[256];
    swprintf_s(buf, L"扫描中... 目录: %d/%d | 已扫描: %d | 匹配: %d", m_completedDirs.load(), m_totalDirs.load(),
               m_scannedFiles.load(), m_matchedCount.load());
    UpdateStatusBar(buf);
}

// 过滤功能

bool FileInvestigator::MatchFilter(const FileInfo& info) {
    // 1. 获取包含关键字
    wchar_t keyword[256] = { 0 };
    if (m_hEditFilter) {
        GetWindowTextW(m_hEditFilter, keyword, 256);
    }

    // 2. 获取排除关键字（路径包含此字符串则排除）
    wchar_t exclude[256] = { 0 };
    if (m_hEditExclude) {
        GetWindowTextW(m_hEditExclude, exclude, 256);
    }

    // 3. 先检查排除：如果路径包含排除字符串，直接排除
    if (wcslen(exclude) > 0) {
        std::wstring lowerExclude = CommonUtils::ToLower(exclude);
        if (CommonUtils::ToLower(info.filePath).find(lowerExclude) != std::wstring::npos) {
            return false;
        }
    }

    // 4. 再检查包含：无关键字则全部通过
    if (wcslen(keyword) == 0)
        return true;

    std::wstring lowerKeyword = CommonUtils::ToLower(keyword);

    if (CommonUtils::ToLower(info.fileName).find(lowerKeyword) != std::wstring::npos)
        return true;
    if (CommonUtils::ToLower(info.filePath).find(lowerKeyword) != std::wstring::npos)
        return true;
    std::wstring createStr = FileTimeToString(info.creationTime);
    if (CommonUtils::ToLower(createStr).find(lowerKeyword) != std::wstring::npos)
        return true;
    std::wstring modifyStr = FileTimeToString(info.lastWriteTime);
    if (CommonUtils::ToLower(modifyStr).find(lowerKeyword) != std::wstring::npos)
        return true;

    return false;
}

void FileInvestigator::ApplyFilter() {
    EnterCriticalSection(&m_resultCS);
    m_filteredFiles.clear();
    for (const auto& info : m_matchedFiles) {
        if (MatchFilter(info)) {
            m_filteredFiles.push_back(info);
        }
    }
    std::sort(m_filteredFiles.begin(), m_filteredFiles.end(), [](const FileInfo& a, const FileInfo& b) {
        return CompareFileTime(&a.lastWriteTime, &b.lastWriteTime) > 0;
    });
    // 统计与本次筛选来自同一批记录，解锁后不再读取正在追加的容器。
    const size_t totalCount = m_matchedFiles.size();
    LeaveCriticalSection(&m_resultCS);

    UpdateListView();

    wchar_t msg[256];
    swprintf_s(msg, L"从 %zu 个文件中 过滤 %zu 个 结果（含排除）", totalCount, m_filteredFiles.size());
    UpdateStatusBar(msg);
}

void FileInvestigator::UpdateListView() {
    if (!m_hListView)
        return;

    SendMessage(m_hListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(m_hListView);

    for (size_t i = 0; i < m_filteredFiles.size(); i++) {
        const FileInfo& info = m_filteredFiles[i];

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.pszText = (LPWSTR)info.fileName.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        ListView_SetItemText(m_hListView, (int)i, COL_PATH, (LPWSTR)info.filePath.c_str());

        std::wstring sizeStr = FormatFileSize(info.fileSize);
        ListView_SetItemText(m_hListView, (int)i, COL_SIZE, (LPWSTR)sizeStr.c_str());

        std::wstring createStr = FileTimeToString(info.creationTime);
        ListView_SetItemText(m_hListView, (int)i, COL_CREATION, (LPWSTR)createStr.c_str());

        std::wstring modifyStr = FileTimeToString(info.lastWriteTime);
        ListView_SetItemText(m_hListView, (int)i, COL_MODIFIED, (LPWSTR)modifyStr.c_str());
    }

    SendMessage(m_hListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(m_hListView, NULL, TRUE);
}

// IInvestigator 接口

InvestigationResult FileInvestigator::Investigate(bool resetFilter) {
    (void)resetFilter;
    InvestigationResult result;
    result.moduleName = L"FileInvestigator";
    result.success = true;
    result.errorCode = 0;
    result.totalCount = 0;
    result.suspiciousCount = 0;
    StartScan();
    return result;
}

bool FileInvestigator::GetCellHighlight(int row, int col, const InvestigationResult& result, COLORREF& outColor) const {
    (void)row;
    (void)col;
    (void)result;
    (void)outColor;
    return false;
}

// 工具栏

void FileInvestigator::CreateToolbar(HWND hParent, HINSTANCE hInst) {
    m_hMainWnd = hParent;
    m_hInst = hInst;

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    int baseY = 33;
    int x = 5;

    // 扫描按钮
    m_hBtnScan = CreateWindowExW(0, L"BUTTON", L"扫描", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 50, 22,
                                 hParent, (HMENU)IDC_FILE_BTN_SCAN, hInst, NULL);
    SendMessage(m_hBtnScan, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 55;

    // 停止按钮
    m_hBtnStop = CreateWindowExW(0, L"BUTTON", L"停止", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 50, 22,
                                 hParent, (HMENU)IDC_FILE_BTN_STOP, hInst, NULL);
    SendMessage(m_hBtnStop, WM_SETFONT, (WPARAM)hFont, TRUE);
    EnableWindow(m_hBtnStop, FALSE);
    x += 55;

    // 加载按钮
    m_hBtnLoad = CreateWindowExW(0, L"BUTTON", L"加载", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 50, 22,
                                 hParent, (HMENU)IDC_FILE_BTN_LOAD, hInst, NULL);
    SendMessage(m_hBtnLoad, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 58;

    // 扫描配置按钮
    m_hBtnScanConfig = CreateWindowExW(0, L"BUTTON", L"扫描配置", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 70,
                                       22, hParent, (HMENU)IDC_FILE_BTN_SCAN_CONFIG, hInst, NULL);
    SendMessage(m_hBtnScanConfig, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 78;

    // 结果上限下拉框
    m_hComboLimit = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, x,
                                    baseY, 80, 200, hParent, (HMENU)IDC_FILE_COMBO_LIMIT, hInst, NULL);
    SendMessage(m_hComboLimit, WM_SETFONT, (WPARAM)hFont, TRUE);

    SendMessage(m_hComboLimit, CB_ADDSTRING, 0, (LPARAM)L"500");
    SendMessage(m_hComboLimit, CB_ADDSTRING, 0, (LPARAM)L"1,000");
    SendMessage(m_hComboLimit, CB_ADDSTRING, 0, (LPARAM)L"3,000");
    SendMessage(m_hComboLimit, CB_ADDSTRING, 0, (LPARAM)L"5,000");
    SendMessage(m_hComboLimit, CB_ADDSTRING, 0, (LPARAM)L"10,000");
    SendMessage(m_hComboLimit, CB_ADDSTRING, 0, (LPARAM)L"不限制");
    SendMessage(m_hComboLimit, CB_SETCURSEL, LIMIT_3000, 0);

    x += 88;

    m_hStaticKeyword = CreateWindowExW(0, L"STATIC", L"过滤:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, x, baseY, 35, 22,
                                       hParent, (HMENU)IDC_FILE_STATIC_KEYWORD, hInst, NULL);
    SendMessage(m_hStaticKeyword, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 38;

    m_hEditFilter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, x, baseY,
                                    120, 22, hParent, (HMENU)IDC_FILE_EDIT_FILTER, hInst, NULL);
    SendMessage(m_hEditFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 125;

    // 排除标签
    m_hStaticExclude = CreateWindowExW(0, L"STATIC", L"排除:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, x, baseY, 40, 22,
                                       hParent, (HMENU)IDC_FILE_STATIC_EXCLUDE, hInst, NULL);
    SendMessage(m_hStaticExclude, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 43;

    // 排除输入框
    m_hEditExclude = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, x, baseY,
                                     120, 22, hParent, (HMENU)IDC_FILE_EDIT_EXCLUDE, hInst, NULL);
    SendMessage(m_hEditExclude, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 125;

    m_hBtnFilter = CreateWindowExW(0, L"BUTTON", L"过滤", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 50, 22,
                                   hParent, (HMENU)IDC_FILE_BTN_FILTER, hInst, NULL);
    SendMessage(m_hBtnFilter, WM_SETFONT, (WPARAM)hFont, TRUE);

    ShowToolbar(false);
}

void FileInvestigator::DestroyToolbar() {
    StopScan(true);

    if (m_hBtnScan) {
        DestroyWindow(m_hBtnScan);
        m_hBtnScan = NULL;
    }
    if (m_hBtnStop) {
        DestroyWindow(m_hBtnStop);
        m_hBtnStop = NULL;
    }
    if (m_hBtnLoad) {
        DestroyWindow(m_hBtnLoad);
        m_hBtnLoad = NULL;
    }
    if (m_hBtnScanConfig) {
        DestroyWindow(m_hBtnScanConfig);
        m_hBtnScanConfig = NULL;
    }
    if (m_hComboLimit) {
        DestroyWindow(m_hComboLimit);
        m_hComboLimit = NULL;
    }
    if (m_hStaticKeyword) {
        DestroyWindow(m_hStaticKeyword);
        m_hStaticKeyword = NULL;
    }
    if (m_hEditFilter) {
        DestroyWindow(m_hEditFilter);
        m_hEditFilter = NULL;
    }
    if (m_hStaticExclude) {
        DestroyWindow(m_hStaticExclude);
        m_hStaticExclude = NULL;
    }
    if (m_hEditExclude) {
        DestroyWindow(m_hEditExclude);
        m_hEditExclude = NULL;
    }
    if (m_hBtnFilter) {
        DestroyWindow(m_hBtnFilter);
        m_hBtnFilter = NULL;
    }
}

void FileInvestigator::ShowToolbar(bool show) {
    int cmd = show ? SW_SHOW : SW_HIDE;
    if (m_hBtnScan)
        ShowWindow(m_hBtnScan, cmd);
    if (m_hBtnStop)
        ShowWindow(m_hBtnStop, cmd);
    if (m_hBtnLoad)
        ShowWindow(m_hBtnLoad, cmd);
    if (m_hBtnScanConfig)
        ShowWindow(m_hBtnScanConfig, cmd);
    if (m_hComboLimit)
        ShowWindow(m_hComboLimit, cmd);
    if (m_hStaticKeyword)
        ShowWindow(m_hStaticKeyword, cmd);
    if (m_hEditFilter)
        ShowWindow(m_hEditFilter, cmd);
    if (m_hStaticExclude)
        ShowWindow(m_hStaticExclude, cmd);
    if (m_hEditExclude)
        ShowWindow(m_hEditExclude, cmd);
    if (m_hBtnFilter)
        ShowWindow(m_hBtnFilter, cmd);
}

void FileInvestigator::ResizeToolbar(int x, int y, int width) {
    (void)x;
    (void)width;
    int baseY = y + 5;
    int posX = 5;

    if (m_hBtnScan)
        SetWindowPos(m_hBtnScan, NULL, posX, baseY, 50, 22, SWP_NOZORDER);
    posX += 55;
    if (m_hBtnStop)
        SetWindowPos(m_hBtnStop, NULL, posX, baseY, 50, 22, SWP_NOZORDER);
    posX += 55;
    if (m_hBtnLoad)
        SetWindowPos(m_hBtnLoad, NULL, posX, baseY, 50, 22, SWP_NOZORDER);
    posX += 58;
    if (m_hBtnScanConfig)
        SetWindowPos(m_hBtnScanConfig, NULL, posX, baseY, 70, 22, SWP_NOZORDER);
    posX += 78;
    if (m_hComboLimit)
        SetWindowPos(m_hComboLimit, NULL, posX, baseY, 80, 200, SWP_NOZORDER);
    posX += 88;
    if (m_hStaticKeyword)
        SetWindowPos(m_hStaticKeyword, NULL, posX, baseY, 35, 22, SWP_NOZORDER);
    posX += 38;
    if (m_hEditFilter)
        SetWindowPos(m_hEditFilter, NULL, posX, baseY, 120, 22, SWP_NOZORDER);
    posX += 125;
    if (m_hStaticExclude)
        SetWindowPos(m_hStaticExclude, NULL, posX, baseY, 40, 22, SWP_NOZORDER);
    posX += 43;
    if (m_hEditExclude)
        SetWindowPos(m_hEditExclude, NULL, posX, baseY, 120, 22, SWP_NOZORDER);
    posX += 125;
    if (m_hBtnFilter)
        SetWindowPos(m_hBtnFilter, NULL, posX, baseY, 50, 22, SWP_NOZORDER);
}

bool FileInvestigator::HandleToolbarCommand(WORD id, WORD code) {
    (void)code;
    switch (id) {
    case IDC_FILE_BTN_SCAN:
        StartScan();
        if (m_hListView)
            SetFocus(m_hListView);
        return true;
    case IDC_FILE_BTN_STOP:
        StopScan();
        if (m_hListView)
            SetFocus(m_hListView);
        return true;
    case IDC_FILE_BTN_LOAD:
        LoadFromCacheFile();
        if (m_hListView)
            SetFocus(m_hListView);
        return true;
    case IDC_FILE_BTN_SCAN_CONFIG:
        ShowScanConfigDialog();
        return true;
    case IDC_FILE_BTN_FILTER:
        ApplyFilter();
        if (m_hListView)
            SetFocus(m_hListView);
        return true;
    }
    return false;
}

// 扫描配置对话框

INT_PTR CALLBACK FileInvestigator::ScanConfigDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG: {
        FileInvestigator* pThis = (FileInvestigator*)lParam;
        SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)pThis);

        if (!pThis)
            return FALSE;

        const ScanConfig& cfg = pThis->m_scanConfig;

        // 初始化后缀复选框
        SendDlgItemMessageW(hDlg, IDC_CFG_EXECUTABLE, BM_SETCHECK, cfg.scanExecutables ? BST_CHECKED : BST_UNCHECKED,
                            0);
        SendDlgItemMessageW(hDlg, IDC_CFG_SCRIPTS, BM_SETCHECK, cfg.scanScripts ? BST_CHECKED : BST_UNCHECKED, 0);
        SendDlgItemMessageW(hDlg, IDC_CFG_ARCHIVES, BM_SETCHECK, cfg.scanArchives ? BST_CHECKED : BST_UNCHECKED, 0);
        SendDlgItemMessageW(hDlg, IDC_CFG_OTHER, BM_SETCHECK, cfg.scanOther ? BST_CHECKED : BST_UNCHECKED, 0);

        // 初始化路径复选框
        SendDlgItemMessageW(hDlg, IDC_CFG_DOWNLOADS, BM_SETCHECK, cfg.useUserDownloads ? BST_CHECKED : BST_UNCHECKED,
                            0);
        SendDlgItemMessageW(hDlg, IDC_CFG_USERTEMP, BM_SETCHECK, cfg.useUserTemp ? BST_CHECKED : BST_UNCHECKED, 0);
        SendDlgItemMessageW(hDlg, IDC_CFG_SYSTEMP, BM_SETCHECK, cfg.useSystemTemp ? BST_CHECKED : BST_UNCHECKED, 0);
        SendDlgItemMessageW(hDlg, IDC_CFG_NONSYS, BM_SETCHECK, cfg.useNonSystemCDirs ? BST_CHECKED : BST_UNCHECKED, 0);

        // 填充自定义编辑框
        SetMultilineEdit(GetDlgItem(hDlg, IDC_CFG_CUSTOM_EXT), cfg.customExtensions);
        SetMultilineEdit(GetDlgItem(hDlg, IDC_CFG_CUSTOM_PATH), cfg.customPaths);

        return TRUE;
    }

    case WM_COMMAND: {
        FileInvestigator* pThis = (FileInvestigator*)GetWindowLongPtrW(hDlg, DWLP_USER);

        switch (LOWORD(wParam)) {
        case IDOK: {
            if (!pThis)
                break;

            ScanConfig newCfg;

            newCfg.scanExecutables = (SendDlgItemMessageW(hDlg, IDC_CFG_EXECUTABLE, BM_GETCHECK, 0, 0) == BST_CHECKED);
            newCfg.scanScripts = (SendDlgItemMessageW(hDlg, IDC_CFG_SCRIPTS, BM_GETCHECK, 0, 0) == BST_CHECKED);
            newCfg.scanArchives = (SendDlgItemMessageW(hDlg, IDC_CFG_ARCHIVES, BM_GETCHECK, 0, 0) == BST_CHECKED);
            newCfg.scanOther = (SendDlgItemMessageW(hDlg, IDC_CFG_OTHER, BM_GETCHECK, 0, 0) == BST_CHECKED);

            newCfg.useUserDownloads = (SendDlgItemMessageW(hDlg, IDC_CFG_DOWNLOADS, BM_GETCHECK, 0, 0) == BST_CHECKED);
            newCfg.useUserTemp = (SendDlgItemMessageW(hDlg, IDC_CFG_USERTEMP, BM_GETCHECK, 0, 0) == BST_CHECKED);
            newCfg.useSystemTemp = (SendDlgItemMessageW(hDlg, IDC_CFG_SYSTEMP, BM_GETCHECK, 0, 0) == BST_CHECKED);
            newCfg.useNonSystemCDirs = (SendDlgItemMessageW(hDlg, IDC_CFG_NONSYS, BM_GETCHECK, 0, 0) == BST_CHECKED);

            newCfg.customExtensions = ParseMultilineEdit(GetDlgItem(hDlg, IDC_CFG_CUSTOM_EXT));
            newCfg.customPaths = ParseMultilineEdit(GetDlgItem(hDlg, IDC_CFG_CUSTOM_PATH));

            pThis->m_scanConfig = newCfg;

            EndDialog(hDlg, IDOK);
            return TRUE;
        }

        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    }

    return FALSE;
}

void FileInvestigator::ShowScanConfigDialog() {
    if (m_hScanThread)
        return;
    DialogBoxParamW(m_hInst, MAKEINTRESOURCEW(IDD_SCAN_CONFIG), m_hMainWnd, ScanConfigDlgProc, (LPARAM)this);
}

// 缓存功能

InvestigationResult FileInvestigator::GetScanResult() const {
    InvestigationResult result;
    result.moduleName = L"FileInvestigator";
    result.success = true;
    result.errorCode = 0;

    EnterCriticalSection(const_cast<CRITICAL_SECTION*>(&m_resultCS));
    result.totalCount = (int)m_matchedFiles.size();
    result.suspiciousCount = 0;
    for (const auto& info : m_matchedFiles) {
        std::vector<std::wstring> row;
        row.push_back(info.fileName);
        row.push_back(info.filePath);
        row.push_back(FormatFileSize(info.fileSize));
        row.push_back(FileTimeToString(info.creationTime));
        row.push_back(FileTimeToString(info.lastWriteTime));
        result.rows.push_back(row);
    }
    LeaveCriticalSection(const_cast<CRITICAL_SECTION*>(&m_resultCS));

    return result;
}

static std::wstring GetCacheFilePath() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    size_t pos = exeDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        exeDir = exeDir.substr(0, pos + 1);
    }

    std::wstring cacheDir = exeDir + L"data\\cache\\";
    CreateDirectoryW((exeDir + L"data").c_str(), NULL);
    CreateDirectoryW(cacheDir.c_str(), NULL);

    return cacheDir + L"files.dat";
}

bool FileInvestigator::LoadFromCacheFile() {
    if (m_hScanThread)
        return false;
    const std::wstring filePath = GetCacheFilePath();
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        if (m_hMainWnd)
            MessageBoxW(m_hMainWnd, L"没有找到历史缓存文件", L"提示", MB_OK);
        return false;
    }

    const auto invalidCache = [this]() {
        if (m_hMainWnd)
            MessageBoxW(m_hMainWnd, L"缓存文件数据异常，保留当前结果", L"错误", MB_OK | MB_ICONERROR);
        return false;
    };

    try {
        const auto read = [&file](void* data, size_t size) {
            return size == 0 ||
                   static_cast<bool>(file.read(static_cast<char*>(data), static_cast<std::streamsize>(size)));
        };
        const auto readString = [&read](std::wstring& value, size_t maximum) {
            size_t length = 0;
            if (!read(&length, sizeof(length)) || length == 0 || length > maximum)
                return false;
            value.resize(length);
            return read(value.data(), length * sizeof(wchar_t)) && value.find(L'\0') == std::wstring::npos;
        };

        int totalCount = 0, suspiciousCount = 0, errorCode = 0;
        unsigned char success = 0;
        size_t fileCount = 0;
        if (!read(&totalCount, sizeof(totalCount)) || !read(&suspiciousCount, sizeof(suspiciousCount)) ||
            !read(&success, sizeof(success)) || !read(&errorCode, sizeof(errorCode)) ||
            !read(&fileCount, sizeof(fileCount)) || fileCount > kMaximumCachedFiles || totalCount < 0 ||
            static_cast<size_t>(totalCount) != fileCount || suspiciousCount < 0 || suspiciousCount > totalCount ||
            success > 1)
            return invalidCache();

        std::vector<FileInfo> loadedFiles;
        loadedFiles.reserve(fileCount);
        for (size_t i = 0; i < fileCount; ++i) {
            FileInfo info;
            if (!readString(info.fileName, 1024) || !readString(info.filePath, 4096) ||
                !read(&info.fileSize, sizeof(info.fileSize)) || !read(&info.creationTime, sizeof(info.creationTime)) ||
                !read(&info.lastWriteTime, sizeof(info.lastWriteTime)))
                return invalidCache();
            loadedFiles.push_back(std::move(info));
        }
        if (file.peek() != std::char_traits<char>::eof() || file.bad())
            return invalidCache();
        file.close();

        // 完整读取并校验后才替换列表，坏缓存不会覆盖现有结果。
        std::sort(loadedFiles.begin(), loadedFiles.end());
        EnterCriticalSection(&m_resultCS);
        m_matchedFiles = std::move(loadedFiles);
        m_matchedCount = static_cast<int>(m_matchedFiles.size());
        m_limitReached = false;
        LeaveCriticalSection(&m_resultCS);
        ApplyFilter();

        wchar_t buf[128];
        swprintf_s(buf, L"已加载缓存，共 %zu 个文件，显示 %zu 个", m_matchedFiles.size(), m_filteredFiles.size());
        UpdateStatusBar(buf);
        return true;
    } catch (...) {
        if (m_hMainWnd)
            MessageBoxW(m_hMainWnd, L"缓存文件读取失败", L"错误", MB_OK | MB_ICONERROR);
        return false;
    }
}

void FileInvestigator::SaveToCacheFile() {
    std::wstring message;
    {
        FileResultLock lock(m_resultCS);
        // 采集可以不限制，但历史缓存的读写使用同一个安全上限。
        // 必须在创建或打开任何缓存文件之前检查，超限不截取、不覆盖旧文件。
        if (m_matchedFiles.size() > kMaximumCachedFiles) {
            message = L"本次结果超过历史缓存上限（" + std::to_wstring(kMaximumCachedFiles) +
                      L" 条），未更新缓存；可正常查看和导出";
        } else {
            const std::wstring filePath = GetCacheFilePath();
            FileCacheWriter writer;
            const int totalCount = static_cast<int>(m_matchedFiles.size());
            const int suspiciousCount = 0;
            const bool success = true;
            const int errorCode = 0;
            const size_t fileCount = m_matchedFiles.size();
            // 保持既有二进制格式，旧缓存无需迁移。
            bool saved = writer.Open(filePath) && writer.Write(&totalCount, sizeof(totalCount)) &&
                         writer.Write(&suspiciousCount, sizeof(suspiciousCount)) &&
                         writer.Write(&success, sizeof(success)) && writer.Write(&errorCode, sizeof(errorCode)) &&
                         writer.Write(&fileCount, sizeof(fileCount));
            for (const auto& info : m_matchedFiles) {
                if (!saved)
                    break;
                const size_t nameLength = info.fileName.size();
                const size_t pathLength = info.filePath.size();
                saved = writer.Write(&nameLength, sizeof(nameLength)) &&
                        writer.Write(info.fileName.data(), nameLength * sizeof(wchar_t)) &&
                        writer.Write(&pathLength, sizeof(pathLength)) &&
                        writer.Write(info.filePath.data(), pathLength * sizeof(wchar_t)) &&
                        writer.Write(&info.fileSize, sizeof(info.fileSize)) &&
                        writer.Write(&info.creationTime, sizeof(info.creationTime)) &&
                        writer.Write(&info.lastWriteTime, sizeof(info.lastWriteTime));
            }
            if (saved)
                saved = writer.Commit(filePath);
            if (!saved)
                message = L"缓存保存失败，未更新历史缓存（错误码: " + std::to_wstring(writer.Error()) +
                          L"）；当前结果可正常查看和导出";
        }
    }
    if (!message.empty())
        UpdateStatusBar(message);
}

// 右键菜单功能

void FileInvestigator::ShowFileHashes(const std::wstring& path) {
    if (path.empty())
        return;

    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
    CommonUtils::FileHashResult hashes = CommonUtils::CalculateFileHashes(path);
    SetCursor(hOldCursor);

    CommonUtils::ShowFileHashDialog(m_hInst, m_hMainWnd, path, hashes);
}

std::wstring FileInvestigator::GetContextFilePath(int row) const {
    if (row < 0 || row >= (int)m_filteredFiles.size())
        return L"";
    return m_filteredFiles[row].filePath;
}

std::vector<ContextMenuItem> FileInvestigator::GetContextMenuItems(int row) const {
    std::vector<ContextMenuItem> items;

    if (row < 0 || row >= (int)m_filteredFiles.size()) {
        return items;
    }

    const FileInfo& info = m_filteredFiles[row];
    bool fileExists = GetFileAttributesW(info.filePath.c_str()) != INVALID_FILE_ATTRIBUTES;

    if (fileExists) {
        items.push_back({ IDM_FILE_CALC_HASH, L"计算文件哈希", false, L"" });
        items.push_back({ IDM_FILE_VIRUSTOTAL, L"在线查询 (VirusTotal)", false, L"" });
        items.push_back({ IDM_FILE_THREATBOOK, L"在线查询 (微步)", false, L"" });
    }

    return items;
}

// 处理右键菜单命令
bool FileInvestigator::HandleContextMenu(UINT menuId, int row) {
    if (row < 0 || row >= (int)m_filteredFiles.size()) {
        return false;
    }

    const FileInfo& info = m_filteredFiles[row];

    switch (menuId) {
    case IDM_FILE_CALC_HASH:
        ShowFileHashes(info.filePath);
        return false;

    case IDM_FILE_VIRUSTOTAL: {
        HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
        CommonUtils::FileHashResult hashes = CommonUtils::CalculateFileHashes(info.filePath);
        SetCursor(hOldCursor);
        if (!hashes.sha256.empty()) {
            CommonUtils::QueryVirusTotal(hashes.sha256);
        } else {
            MessageBoxW(m_hMainWnd, L"无法计算文件哈希", L"错误", MB_OK | MB_ICONERROR);
        }
        return false;
    }

    case IDM_FILE_THREATBOOK: {
        HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
        CommonUtils::FileHashResult hashes = CommonUtils::CalculateFileHashes(info.filePath);
        SetCursor(hOldCursor);
        if (!hashes.sha256.empty()) {
            CommonUtils::QueryThreatBook(hashes.sha256);
        } else {
            MessageBoxW(m_hMainWnd, L"无法计算文件哈希", L"错误", MB_OK | MB_ICONERROR);
        }
        return false;
    }
    }

    return false;
}
