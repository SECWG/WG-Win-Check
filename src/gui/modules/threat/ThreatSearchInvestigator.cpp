// ThreatSearchInvestigator.cpp - 威胁检索模块实现
// GUI与CLI共用有界流式匹配器，保留GUI的范围、首次命中和区域大小选项。
#include "ThreatSearchInvestigator.h"
#include "../../../core/modules/threat/ThreatSearch.h"
#include "../../resources/resource.h"
#include <algorithm>
#include <commctrl.h>
#include <limits>

namespace {
    std::wstring ReadThreatProcessPath(HANDLE process) {
        std::vector<wchar_t> buffer(32768);
        DWORD size = static_cast<DWORD>(buffer.size());
        if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size))
            return {};
        return { buffer.data(), size };
    }

    std::wstring NormalizeThreatPath(std::wstring path) {
        std::replace(path.begin(), path.end(), L'/', L'\\');
        if (path.compare(0, 4, L"\\\\?\\") == 0)
            path.erase(0, 4);
        if (path.size() < 3 || path[1] != L':' || path[2] != L'\\' ||
            !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')))
            return {};
        const DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
        if (!needed || needed > 32768)
            return {};
        std::vector<wchar_t> buffer(needed);
        const DWORD size = GetFullPathNameW(path.c_str(), needed, buffer.data(), nullptr);
        if (!size || size >= needed)
            return {};
        return { buffer.data(), size };
    }

    bool ParseThreatNumber(const std::wstring& text, DWORD& value) {
        if (text.empty())
            return false;
        ULONGLONG number = 0;
        for (wchar_t c : text) {
            if (c < L'0' || c > L'9')
                return false;
            number = number * 10 + (c - L'0');
            if (number > MAXDWORD)
                return false;
        }
        value = static_cast<DWORD>(number);
        return value != 0;
    }

    std::wstring TrimThreatInput(std::wstring value) {
        const auto begin = value.find_first_not_of(L" ");
        if (begin == std::wstring::npos)
            return {};
        return value.substr(begin, value.find_last_not_of(L" ") - begin + 1);
    }

    bool ThreatProcessGone(HANDLE process) {
        DWORD code = STILL_ACTIVE;
        return GetExitCodeProcess(process, &code) && code != STILL_ACTIVE;
    }
}

// 常量定义

// 优化: 缓冲区从64KB增大到512KB
static const SIZE_T SCAN_BUFFER_SIZE = 512 * 1024; // 缓冲区大小：512 KB。

// 静态列定义
const ColumnDef ThreatSearchInvestigator::s_Columns[] = {
    { L"PID",      65  },
    { L"进程名",   150 },
    { L"路径",     280 },
    { L"匹配类型", 90  },
    { L"位置",     180 },
    { L"上下文",   420 }
};
const int ThreatSearchInvestigator::s_ColumnCount = sizeof(s_Columns) / sizeof(s_Columns[0]);

ThreatSearchInvestigator::ThreatSearchInvestigator()
    : m_hStaticIOC(NULL), m_hEditIOC(NULL), m_hStaticPID(NULL), m_hEditPID(NULL), m_hBtnScan(NULL), m_hBtnStop(NULL),
      m_hChkNonSystem(NULL), m_hChkFirstOnly(NULL), m_hStaticMemLimit(NULL), m_hEditMemLimit(NULL), m_hMainWnd(NULL),
      m_hListView(NULL), m_hInst(NULL), m_scanning(false), m_scannedProcesses(0), m_totalProcesses(0), m_matchCount(0),
      m_hScanThread(NULL), m_scanNonSystemOnly(true), m_firstMatchOnly(true), m_targetPid(0),
      m_maxRegionSize(256 * 1024 * 1024), m_totalBytesScanned(0), m_regionsScanned(0) {
    InitializeCriticalSection(&m_csResults);

    // 获取自身进程ID，扫描时排除
    m_selfPid = GetCurrentProcessId();

    wchar_t buf[MAX_PATH] = {};
    const UINT length = GetWindowsDirectoryW(buf, MAX_PATH);
    if (length && length < MAX_PATH)
        m_windowsPath.assign(buf, length);
}

ThreatSearchInvestigator::~ThreatSearchInvestigator() {
    DestroyToolbar();
    DeleteCriticalSection(&m_csResults);
}

std::wstring ThreatSearchInvestigator::GetProcessPath(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return {};
    const auto path = ReadThreatProcessPath(process);
    CloseHandle(process);
    return path;
}

std::wstring ThreatSearchInvestigator::FormatAddress(ULONGLONG addr) {
    wchar_t buf[32];
    swprintf_s(buf, L"0x%016llX", addr);
    return buf;
}

bool ThreatSearchInvestigator::ShouldScanRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    // 必须是已提交的内存
    if (mbi.State != MEM_COMMIT)
        return false;

    // 跳过不可访问和守护页
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return false;

    // 必须可读
    DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                     PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & readable))
        return false;

    // 跳过超大区域 (可能是视频内存等)
    if (mbi.RegionSize > m_maxRegionSize)
        return false;

    return true;
}

bool ThreatSearchInvestigator::IsSystemProcess(const std::wstring& name, const std::wstring& path) {
    (void)name;
    // 这是Windows目录范围筛选，不是签名或可信判定；不能仅凭文件名排除。
    const auto fullPath = NormalizeThreatPath(path);
    auto windowsPath = NormalizeThreatPath(m_windowsPath);
    if (fullPath.empty() || windowsPath.empty())
        return false;
    if (windowsPath.back() != L'\\')
        windowsPath.push_back(L'\\');
    return fullPath.size() > windowsPath.size() &&
           CompareStringOrdinal(fullPath.data(), static_cast<int>(windowsPath.size()), windowsPath.data(),
                                static_cast<int>(windowsPath.size()), TRUE) == CSTR_EQUAL;
}

std::vector<ThreatSearchInvestigator::ProcessEntry> ThreatSearchInvestigator::EnumerateProcesses() {
    std::vector<ProcessEntry> processes;
    if (m_cancelRequested)
        return processes;
    if (m_targetPid != 0) {
        if (m_targetPid == m_selfPid) {
            m_scanError = ERROR_INVALID_PARAMETER;
            return processes;
        }
        ProcessEntry entry;
        entry.pid = m_targetPid;
        entry.path = GetProcessPath(entry.pid);
        const auto slash = entry.path.find_last_of(L"\\/");
        entry.name = entry.path.empty() ? L"Unknown" : entry.path.substr(slash == std::wstring::npos ? 0 : slash + 1);
        processes.push_back(std::move(entry));
        return processes;
    }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        m_scanError = GetLastError();
        return processes;
    }
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    BOOL available = Process32FirstW(snapshot, &entry);
    while (available && !m_cancelRequested) {
        if (entry.th32ProcessID != 0 && entry.th32ProcessID != 4 && entry.th32ProcessID != m_selfPid) {
            ProcessEntry process;
            process.pid = entry.th32ProcessID;
            process.name = entry.szExeFile;
            process.path = GetProcessPath(process.pid);
            if (!m_scanNonSystemOnly || !IsSystemProcess(process.name, process.path))
                processes.push_back(std::move(process));
        }
        available = Process32NextW(snapshot, &entry);
    }
    if (!available && !m_cancelRequested) {
        const DWORD error = GetLastError();
        if (error != ERROR_NO_MORE_FILES)
            m_scanError = error;
    }
    CloseHandle(snapshot);
    return processes;
}

void ThreatSearchInvestigator::AddResult(const ThreatSearchResult& result) {
    EnterCriticalSection(&m_csResults);
    m_results.push_back(result);
    m_matchCount++;
    LeaveCriticalSection(&m_csResults);
}

void ThreatSearchInvestigator::UpdateListView() {
    if (!m_toolbarVisible || !m_hListView)
        return;

    EnterCriticalSection(&m_csResults);
    const auto results = m_results;
    LeaveCriticalSection(&m_csResults);

    SendMessage(m_hListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(m_hListView);

    for (size_t i = 0; i < results.size(); i++) {
        const ThreatSearchResult& r = results[i];

        wchar_t pidStr[32];
        swprintf_s(pidStr, L"%lu", r.pid);

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.iSubItem = 0;
        lvi.pszText = pidStr;
        ListView_InsertItem(m_hListView, &lvi);

        ListView_SetItemText(m_hListView, (int)i, COL_PROCESS, (LPWSTR)r.processName.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_PATH, (LPWSTR)r.processPath.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_MATCH_TYPE, (LPWSTR)r.matchType.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_LOCATION, (LPWSTR)r.matchLocation.c_str());
        ListView_SetItemText(m_hListView, (int)i, COL_CONTEXT, (LPWSTR)r.context.c_str());
    }

    SendMessage(m_hListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(m_hListView, NULL, TRUE);
}

void ThreatSearchInvestigator::UpdateProgress() {
    // 进度信息现在通过GetStatusText()获取，由主窗口更新到状态栏
    // 这里不再需要更新内部控件
}

std::wstring ThreatSearchInvestigator::GetStatusText() const {
    if (!m_scanning && !m_hasCache)
        return L"就绪";
    const wchar_t* state =
        m_scanning
            ? (m_cancelRequested ? L"正在停止" : L"检索中")
            : (m_stoppedByUser ? L"已停止"
                               : ((m_scanError != ERROR_SUCCESS || (m_scannedProcesses > 0 && m_readProcesses == 0))
                                      ? L"检索受限"
                                      : L"检索完成"));
    wchar_t text[320] = {};
    swprintf_s(text, L"%s | 进程:%d/%d | 已读:%d | 未读:%d | 读取受限:%d | %.1fMB | 匹配:%d", state,
               m_scannedProcesses.load(), m_totalProcesses.load(), m_readProcesses.load(), m_failedProcesses.load(),
               m_partialProcesses.load(), static_cast<double>(m_totalBytesScanned.load()) / (1024.0 * 1024.0),
               m_matchCount.load());
    std::wstring result = text;
    if (m_scanError != ERROR_SUCCESS)
        result += L" | 错误码:" + std::to_wstring(m_scanError.load());
    return result;
}

InvestigationResult ThreatSearchInvestigator::GetCurrentResult() const {
    InvestigationResult result;
    result.moduleName = L"ThreatSearchInvestigator";
    result.errorCode = m_scanError.load();
    result.success = result.errorCode == ERROR_SUCCESS || m_readProcesses > 0;
    result.partial = m_scanning || m_stoppedByUser || m_failedProcesses > 0 || m_partialProcesses > 0 ||
                     result.errorCode != ERROR_SUCCESS;
    if (!m_scanning && m_scannedProcesses > 0 && m_readProcesses == 0) {
        result.success = false;
        if (!result.errorCode)
            result.errorCode = ERROR_PARTIAL_COPY;
    }
    if (!result.success)
        result.errorMessage = L"未能读取目标进程，请检查进程是否已退出或受到访问保护。";

    EnterCriticalSection(const_cast<CRITICAL_SECTION*>(&m_csResults));

    result.totalCount = (int)m_results.size();
    result.suspiciousCount = result.totalCount; // 所有匹配都是可疑的

    for (const auto& r : m_results) {
        std::vector<std::wstring> row;
        wchar_t pidStr[32];
        swprintf_s(pidStr, L"%lu", r.pid);
        row.push_back(pidStr);
        row.push_back(r.processName);
        row.push_back(r.processPath);
        row.push_back(r.matchType);
        row.push_back(r.matchLocation);
        row.push_back(r.context);
        result.rows.push_back(row);
    }

    LeaveCriticalSection(const_cast<CRITICAL_SECTION*>(&m_csResults));

    return result;
}

// 内存扫描

bool ThreatSearchInvestigator::ScanProcessMemory(DWORD pid, const std::wstring& processName,
                                                 const std::wstring& processPath) {
    if (m_cancelRequested)
        return false;
    if (pid == m_selfPid) {
        ++m_failedProcesses;
        return false;
    }
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        ++m_failedProcesses;
        return false;
    }
#ifndef _WIN64
    BOOL selfWow64 = FALSE, targetWow64 = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &selfWow64) || !IsWow64Process(process, &targetWow64) ||
        (selfWow64 && !targetWow64)) {
        ++m_failedProcesses;
        CloseHandle(process);
        return false;
    }
#endif
    auto path = ReadThreatProcessPath(process);
    if (path.empty())
        path = processPath;
    auto name = processName;
    if (!path.empty()) {
        const auto slash = path.find_last_of(L"\\/");
        name = path.substr(slash == std::wstring::npos ? 0 : slash + 1);
    }
    wgwc::core::CollectionContext context;
    context.externalCancel = &m_cancelRequested;
    wgwc::core::threat::SearchOptions options;
    options.keyword = m_iocString;
    options.contextChars = 32;
    bool found = false;
    wgwc::core::threat::StreamMatcher matcher(options, context, [&](const wgwc::core::threat::BufferMatch& match) {
        ThreatSearchResult row;
        row.pid = pid;
        row.processName = name;
        row.processPath = path;
        row.matchType = match.matchType;
        row.matchLocation = FormatAddress(match.address);
        row.context = match.context;
        AddResult(row);
        found = true;
        return !m_firstMatchOnly;
    });
    if (!matcher.Valid()) {
        ++m_failedProcesses;
        m_scanError = ERROR_NO_UNICODE_TRANSLATION;
        CloseHandle(process);
        return false;
    }

    std::vector<BYTE> buffer(SCAN_BUFFER_SIZE);
    SYSTEM_INFO system = {};
    GetSystemInfo(&system);
    const auto maximum = reinterpret_cast<ULONG_PTR>(system.lpMaximumApplicationAddress);
    const SIZE_T pageSize = system.dwPageSize ? system.dwPageSize : 4096;
    ULONG_PTR address = 0;
    bool readAny = false, incomplete = false, active = true, abandon = false;
    while (address <= maximum && active && !abandon && !m_cancelRequested) {
        MEMORY_BASIC_INFORMATION info = {};
        if (!VirtualQueryEx(process, reinterpret_cast<const void*>(address), &info, sizeof(info))) {
            if (GetLastError() != ERROR_INVALID_PARAMETER || ThreatProcessGone(process))
                incomplete = true;
            break;
        }
        const auto base = reinterpret_cast<ULONG_PTR>(info.BaseAddress);
        if (!info.RegionSize || base > (std::numeric_limits<ULONG_PTR>::max)() - info.RegionSize ||
            base + info.RegionSize <= address) {
            incomplete = true;
            break;
        }
        const auto end = base + info.RegionSize;
        if (!ShouldScanRegion(info)) {
            active = matcher.FinishSegment();
            address = end;
            continue;
        }
        ++m_regionsScanned;
        auto cursor = address;
        while (cursor < end && active && !m_cancelRequested) {
            SIZE_T read = 0;
            SIZE_T requested = (std::min)(SCAN_BUFFER_SIZE, static_cast<SIZE_T>(end - cursor));
            BOOL ok =
                ReadProcessMemory(process, reinterpret_cast<const void*>(cursor), buffer.data(), requested, &read);
            // 大块读取失败时先尝试当前页，非零的已读取前缀仍进入匹配器。
            if (!ok && !read && requested > pageSize) {
                requested = (std::min)(requested, pageSize - static_cast<SIZE_T>(cursor % pageSize));
                ReadProcessMemory(process, reinterpret_cast<const void*>(cursor), buffer.data(), requested, &read);
            }
            if (read > requested) {
                incomplete = true;
                abandon = true;
                break;
            }
            if (read) {
                readAny = true;
                m_totalBytesScanned += read;
                active = matcher.Feed(buffer.data(), read, cursor);
                cursor += read;
                continue;
            }
            incomplete = true;
            active = matcher.FinishSegment();
            if (!active)
                break;
            if (ThreatProcessGone(process)) {
                abandon = true;
                break;
            }
            MEMORY_BASIC_INFORMATION current = {};
            if (!VirtualQueryEx(process, reinterpret_cast<const void*>(cursor), &current, sizeof(current))) {
                abandon = true;
                break;
            }
            const auto currentBase = reinterpret_cast<ULONG_PTR>(current.BaseAddress);
            if (!current.RegionSize || currentBase > (std::numeric_limits<ULONG_PTR>::max)() - current.RegionSize ||
                currentBase + current.RegionSize <= cursor) {
                abandon = true;
                break;
            }
            if (!ShouldScanRegion(current))
                cursor = (std::min)(end, currentBase + current.RegionSize);
            else
                cursor +=
                    (std::min)(static_cast<SIZE_T>(end - cursor), pageSize - static_cast<SIZE_T>(cursor % pageSize));
        }
        address = end;
    }
    if (active && !m_cancelRequested)
        matcher.FinishSegment();
    if (!m_cancelRequested && ThreatProcessGone(process))
        incomplete = true;
    if (readAny) {
        ++m_readProcesses;
        if (incomplete)
            ++m_partialProcesses;
    } else if (!m_cancelRequested) {
        ++m_failedProcesses;
    }
    CloseHandle(process);
    return found;
}

void ThreatSearchInvestigator::DoMemoryScan() {
    const auto processes = EnumerateProcesses();
    m_totalProcesses = static_cast<int>(processes.size());
    for (const auto& process : processes) {
        if (m_cancelRequested)
            break;
        ScanProcessMemory(process.pid, process.name, process.path);
        ++m_scannedProcesses;
    }
    // 线程只产出数据；UI在确认线程退出后发布缓存并恢复控件。
}

DWORD WINAPI ThreatSearchInvestigator::ScanThread(LPVOID lpParam) {
    ThreatSearchInvestigator* pThis = (ThreatSearchInvestigator*)lpParam;
    pThis->DoMemoryScan();
    return 0;
}

// 扫描控制

void ThreatSearchInvestigator::StartScan() {
    if (m_hScanThread || m_scanning)
        return;

    wchar_t iocText[2049] = {};
    GetWindowTextW(m_hEditIOC, iocText, static_cast<int>(std::size(iocText)));
    const auto keyword = TrimThreatInput(iocText);
    if (GetWindowTextLengthW(m_hEditIOC) >= static_cast<int>(std::size(iocText)) || keyword.size() < 3 ||
        !wgwc::core::threat::IsValidKeyword(keyword)) {
        MessageBoxW(m_hMainWnd, L"请输入3至1024个字符的IOC，不支持控制字符。", L"提示", MB_OK);
        return;
    }
    wchar_t input[32] = {};
    GetWindowTextW(m_hEditPID, input, static_cast<int>(std::size(input)));
    const auto pidText = TrimThreatInput(input);
    DWORD targetPid = 0;
    if (!pidText.empty() && (!ParseThreatNumber(pidText, targetPid) || targetPid == m_selfPid)) {
        MessageBoxW(m_hMainWnd, L"请输入有效PID，不能检索本程序自身。", L"提示", MB_OK);
        return;
    }
    GetWindowTextW(m_hEditMemLimit, input, static_cast<int>(std::size(input)));
    const auto limitText = TrimThreatInput(input);
    DWORD limitMB = 256;
    if ((!limitText.empty() && limitText != L"0" && !ParseThreatNumber(limitText, limitMB)) ||
        limitMB > (std::numeric_limits<SIZE_T>::max)() / (1024 * 1024)) {
        MessageBoxW(m_hMainWnd, L"请输入有效的内存区域大小（MB）。", L"提示", MB_OK);
        return;
    }

    m_iocString = keyword;
    m_targetPid = targetPid;
    m_scanNonSystemOnly = SendMessage(m_hChkNonSystem, BM_GETCHECK, 0, 0) == BST_CHECKED;
    m_firstMatchOnly = SendMessage(m_hChkFirstOnly, BM_GETCHECK, 0, 0) == BST_CHECKED;
    m_maxRegionSize = static_cast<SIZE_T>(limitMB) * 1024 * 1024;
    EnterCriticalSection(&m_csResults);
    m_results.clear();
    LeaveCriticalSection(&m_csResults);
    ClearCache();
    m_scannedProcesses = 0;
    m_totalProcesses = 0;
    m_matchCount = 0;
    m_readProcesses = 0;
    m_failedProcesses = 0;
    m_partialProcesses = 0;
    m_totalBytesScanned = 0;
    m_regionsScanned = 0;
    m_scanError = ERROR_SUCCESS;
    m_cancelRequested = false;
    m_stoppedByUser = false;
    m_scanning = true;
    SetScanControls(true);
    UpdateListView();

    if (!m_hMainWnd || !SetTimer(m_hMainWnd, IDT_THREAT_PROGRESS, 500, NULL)) {
        m_scanError = m_hMainWnd ? GetLastError() : ERROR_INVALID_WINDOW_HANDLE;
        if (m_scanError == ERROR_SUCCESS)
            m_scanError = ERROR_NOT_ENOUGH_MEMORY;
        FinishScan();
        return;
    }
    m_hScanThread = CreateThread(NULL, 0, ScanThread, this, 0, NULL);
    if (!m_hScanThread) {
        m_scanError = GetLastError();
        FinishScan();
    }
}

void ThreatSearchInvestigator::SetScanControls(bool running) {
    const HWND inputs[] = { m_hEditIOC, m_hEditPID, m_hChkNonSystem, m_hChkFirstOnly, m_hEditMemLimit, m_hBtnScan };
    for (HWND input : inputs)
        if (input)
            EnableWindow(input, !running);
    if (m_hBtnStop)
        EnableWindow(m_hBtnStop, running && !m_cancelRequested);
}

void ThreatSearchInvestigator::FinishScan(bool updateView) {
    if (m_hScanThread) {
        if (WaitForSingleObject(m_hScanThread, 0) != WAIT_OBJECT_0)
            return;
        CloseHandle(m_hScanThread);
        m_hScanThread = NULL;
    }
    if (m_hMainWnd)
        KillTimer(m_hMainWnd, IDT_THREAT_PROGRESS);
    m_scanning = false;
    m_cachedResult = GetCurrentResult();
    m_hasCache = true;
    SetScanControls(false);
    if (updateView)
        UpdateListView();
}

void ThreatSearchInvestigator::StopScan(bool waitForExit) {
    if (!m_hScanThread)
        return;
    if (WaitForSingleObject(m_hScanThread, 0) != WAIT_OBJECT_0) {
        m_cancelRequested = true;
        m_stoppedByUser = true;
        SetScanControls(true);
        CancelSynchronousIo(m_hScanThread);
    }
    // 点击停止不阻塞UI；销毁时必须等待，不能关闭仍在使用本对象的线程。
    if (waitForExit)
        WaitForSingleObject(m_hScanThread, INFINITE);
    FinishScan(!waitForExit);
}

void ThreatSearchInvestigator::OnTimer(UINT_PTR timerId) {
    if (timerId != IDT_THREAT_PROGRESS)
        return;
    if (m_hScanThread && WaitForSingleObject(m_hScanThread, 0) == WAIT_OBJECT_0)
        FinishScan();
    else if (m_scanning)
        UpdateListView();
}

// 工具栏 - 直接创建在主窗口上

void ThreatSearchInvestigator::CreateToolbar(HWND hParent, HINSTANCE hInst) {
    m_hMainWnd = hParent;
    m_hInst = hInst;

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    int baseY = 33;
    int x = 5;

    // IOC标签
    m_hStaticIOC = CreateWindowExW(0, L"STATIC", L"IOC:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, x, baseY, 30, 22,
                                   hParent, (HMENU)IDC_THREAT_STATIC_IOC, hInst, NULL);
    SendMessage(m_hStaticIOC, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 33;

    // IOC输入框
    m_hEditIOC = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, x, baseY, 180,
                                 22, hParent, (HMENU)IDC_THREAT_EDIT_IOC, hInst, NULL);
    SendMessage(m_hEditIOC, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 185;

    // PID标签
    m_hStaticPID = CreateWindowExW(0, L"STATIC", L"PID:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, x, baseY, 28, 22,
                                   hParent, (HMENU)IDC_THREAT_STATIC_PID, hInst, NULL);
    SendMessage(m_hStaticPID, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 30;

    // PID输入框（较窄）
    m_hEditPID = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_NUMBER, x,
                                 baseY, 60, 22, hParent, (HMENU)IDC_THREAT_EDIT_PID, hInst, NULL);
    SendMessage(m_hEditPID, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 65;

    // 扫描按钮
    m_hBtnScan = CreateWindowExW(0, L"BUTTON", L"扫描", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 55, 22,
                                 hParent, (HMENU)IDC_THREAT_BTN_SCAN, hInst, NULL);
    SendMessage(m_hBtnScan, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 60;

    // 停止按钮
    m_hBtnStop = CreateWindowExW(0, L"BUTTON", L"停止", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, baseY, 45, 22,
                                 hParent, (HMENU)IDC_THREAT_BTN_STOP, hInst, NULL);
    SendMessage(m_hBtnStop, WM_SETFONT, (WPARAM)hFont, TRUE);
    EnableWindow(m_hBtnStop, FALSE);
    x += 55;

    // 仅非系统进程复选框（默认选中）
    m_hChkNonSystem = CreateWindowExW(0, L"BUTTON", L"排除系统进程", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, x,
                                      baseY + 2, 120, 18, hParent, (HMENU)IDC_THREAT_CHK_NONSYSTEM, hInst, NULL);
    SendMessage(m_hChkNonSystem, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hChkNonSystem, BM_SETCHECK, BST_UNCHECKED, 0);
    x += 125;

    // 仅首次匹配复选框（默认选中）
    m_hChkFirstOnly = CreateWindowExW(0, L"BUTTON", L"仅首次匹配", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, x,
                                      baseY + 2, 105, 18, hParent, (HMENU)IDC_THREAT_CHK_FIRSTONLY, hInst, NULL);
    SendMessage(m_hChkFirstOnly, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hChkFirstOnly, BM_SETCHECK, BST_CHECKED, 0);
    x += 110;

    // 内存限制标签
    m_hStaticMemLimit = CreateWindowExW(0, L"STATIC", L"内存限制(MB):", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, x,
                                        baseY, 80, 22, hParent, NULL, hInst, NULL);
    SendMessage(m_hStaticMemLimit, WM_SETFONT, (WPARAM)hFont, TRUE);
    x += 83;

    // 内存限制输入框，默认 256
    m_hEditMemLimit =
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"256", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_NUMBER, x, baseY,
                        50, 22, hParent, (HMENU)IDC_THREAT_EDIT_MEMLIMIT, hInst, NULL);
    SendMessage(m_hEditMemLimit, WM_SETFONT, (WPARAM)hFont, TRUE);

    ShowToolbar(false);
}

void ThreatSearchInvestigator::DestroyToolbar() {
    m_toolbarVisible = false;
    StopScan(true);

    if (m_hStaticIOC) {
        DestroyWindow(m_hStaticIOC);
        m_hStaticIOC = NULL;
    }
    if (m_hEditIOC) {
        DestroyWindow(m_hEditIOC);
        m_hEditIOC = NULL;
    }
    if (m_hStaticPID) {
        DestroyWindow(m_hStaticPID);
        m_hStaticPID = NULL;
    }
    if (m_hEditPID) {
        DestroyWindow(m_hEditPID);
        m_hEditPID = NULL;
    }
    if (m_hBtnScan) {
        DestroyWindow(m_hBtnScan);
        m_hBtnScan = NULL;
    }
    if (m_hBtnStop) {
        DestroyWindow(m_hBtnStop);
        m_hBtnStop = NULL;
    }
    if (m_hChkNonSystem) {
        DestroyWindow(m_hChkNonSystem);
        m_hChkNonSystem = NULL;
    }
    if (m_hChkFirstOnly) {
        DestroyWindow(m_hChkFirstOnly);
        m_hChkFirstOnly = NULL;
    }
    if (m_hStaticMemLimit) {
        DestroyWindow(m_hStaticMemLimit);
        m_hStaticMemLimit = NULL;
    }
    if (m_hEditMemLimit) {
        DestroyWindow(m_hEditMemLimit);
        m_hEditMemLimit = NULL;
    }
}

void ThreatSearchInvestigator::ShowToolbar(bool show) {
    m_toolbarVisible = show;
    if (show && m_hScanThread && WaitForSingleObject(m_hScanThread, 0) == WAIT_OBJECT_0)
        FinishScan(false);
    int cmd = show ? SW_SHOW : SW_HIDE;
    if (m_hStaticIOC)
        ShowWindow(m_hStaticIOC, cmd);
    if (m_hEditIOC)
        ShowWindow(m_hEditIOC, cmd);
    if (m_hStaticPID)
        ShowWindow(m_hStaticPID, cmd);
    if (m_hEditPID)
        ShowWindow(m_hEditPID, cmd);
    if (m_hBtnScan)
        ShowWindow(m_hBtnScan, cmd);
    if (m_hBtnStop)
        ShowWindow(m_hBtnStop, cmd);
    if (m_hChkNonSystem)
        ShowWindow(m_hChkNonSystem, cmd);
    if (m_hChkFirstOnly)
        ShowWindow(m_hChkFirstOnly, cmd);
    if (m_hStaticMemLimit)
        ShowWindow(m_hStaticMemLimit, cmd);
    if (m_hEditMemLimit)
        ShowWindow(m_hEditMemLimit, cmd);
}

void ThreatSearchInvestigator::ResizeToolbar(int x, int y, int width) {
    (void)x;
    (void)width;
    int baseY = y + 5;
    int posX = 5;

    if (m_hStaticIOC)
        SetWindowPos(m_hStaticIOC, NULL, posX, baseY, 30, 22, SWP_NOZORDER);
    posX += 33;
    if (m_hEditIOC)
        SetWindowPos(m_hEditIOC, NULL, posX, baseY, 180, 22, SWP_NOZORDER);
    posX += 185;
    if (m_hStaticPID)
        SetWindowPos(m_hStaticPID, NULL, posX, baseY, 28, 22, SWP_NOZORDER);
    posX += 30;
    if (m_hEditPID)
        SetWindowPos(m_hEditPID, NULL, posX, baseY, 60, 22, SWP_NOZORDER);
    posX += 65;
    if (m_hBtnScan)
        SetWindowPos(m_hBtnScan, NULL, posX, baseY, 55, 22, SWP_NOZORDER);
    posX += 60;
    if (m_hBtnStop)
        SetWindowPos(m_hBtnStop, NULL, posX, baseY, 45, 22, SWP_NOZORDER);
    posX += 55;
    if (m_hChkNonSystem)
        SetWindowPos(m_hChkNonSystem, NULL, posX, baseY + 2, 120, 18, SWP_NOZORDER);
    posX += 125;
    if (m_hChkFirstOnly)
        SetWindowPos(m_hChkFirstOnly, NULL, posX, baseY + 2, 105, 18, SWP_NOZORDER);
    posX += 110;
    if (m_hStaticMemLimit)
        SetWindowPos(m_hStaticMemLimit, NULL, posX, baseY, 80, 22, SWP_NOZORDER);
    posX += 83;
    if (m_hEditMemLimit)
        SetWindowPos(m_hEditMemLimit, NULL, posX, baseY, 50, 22, SWP_NOZORDER);
}

bool ThreatSearchInvestigator::HandleToolbarCommand(WORD id, WORD code) {
    (void)code;
    switch (id) {
    case IDC_THREAT_BTN_SCAN:
        StartScan();
        return true;

    case IDC_THREAT_BTN_STOP:
        StopScan();
        return true;
    }

    return false;
}

// IInvestigator接口实现

InvestigationResult ThreatSearchInvestigator::Investigate(bool resetFilter) {
    (void)resetFilter; // 威胁检索模块无过滤器，忽略此参数

    InvestigationResult result;
    result.moduleName = L"ThreatSearchInvestigator";
    result.success = true;
    result.errorCode = 0;
    result.totalCount = 0;
    result.suspiciousCount = 0;
    return result;
}

bool ThreatSearchInvestigator::GetCellHighlight(int row, int col, const InvestigationResult& result,
                                                COLORREF& outColor) const {
    (void)row;
    (void)col;
    (void)result;
    (void)outColor;
    return false;
}

std::wstring ThreatSearchInvestigator::GetContextFilePath(int row) const {
    EnterCriticalSection(const_cast<CRITICAL_SECTION*>(&m_csResults));
    std::wstring path;
    if (row >= 0 && row < (int)m_results.size()) {
        path = m_results[row].processPath;
    }
    LeaveCriticalSection(const_cast<CRITICAL_SECTION*>(&m_csResults));
    return path;
}

std::wstring ThreatSearchInvestigator::GetRowIconPath(int row, const InvestigationItem& item) const {
    (void)item;
    return GetContextFilePath(row);
}

// 右键菜单
