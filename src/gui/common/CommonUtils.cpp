// CommonUtils.cpp - 通用工具函数实现
#include "CommonUtils.h"
#include "../resources/resource.h"
#include "ListViewSupport.h"
#include <limits>
#include "../presentation/DisplayFormat.h"
#include "../../core/system/FileService.h"
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <vector>
#include <algorithm>
#include <wininet.h>
#include <cwctype>

#pragma comment(lib, "wininet.lib")

namespace CommonUtils {

    // 字符串

    std::wstring ToLower(const std::wstring& str) {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
        return result;
    }

    std::wstring ExpandEnvStrings(const std::wstring& str) {
        if (str.empty())
            return str;

        wchar_t expanded[2048] = { 0 };
        DWORD result = ExpandEnvironmentStringsW(str.c_str(), expanded, 2048);
        if (result > 0 && result < 2048) {
            return expanded;
        }
        return str;
    }

    // 剪贴板

    static bool ClipboardFailure(HWND hWnd, DWORD error) {
        if (error == ERROR_SUCCESS)
            error = ERROR_WRITE_FAULT;
        const std::wstring message = error == ERROR_INSUFFICIENT_BUFFER
                                         ? L"内容过长，未复制，请使用导出功能。"
                                         : L"复制失败，请重试（错误码 " + std::to_wstring(error) + L"）。";
        MessageBoxW(hWnd, message.c_str(), L"复制失败", MB_OK | MB_ICONWARNING);
        SetLastError(error);
        return false;
    }

    bool CopyToClipboard(HWND hWnd, const std::wstring& text) {
        if (text.size() > (std::numeric_limits<size_t>::max)() / sizeof(wchar_t) - 1)
            return ClipboardFailure(hWnd, ERROR_ARITHMETIC_OVERFLOW);

        // 在清空剪贴板之前准备数据，准备失败不影响用户原有内容。
        const size_t size = (text.size() + 1) * sizeof(wchar_t);
        HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, size);
        if (!memory)
            return ClipboardFailure(hWnd, GetLastError());
        auto* destination = static_cast<wchar_t*>(GlobalLock(memory));
        if (!destination) {
            const DWORD error = GetLastError();
            GlobalFree(memory);
            return ClipboardFailure(hWnd, error);
        }
        std::copy(text.begin(), text.end(), destination);
        destination[text.size()] = L'\0';
        GlobalUnlock(memory);

        if (!OpenClipboard(hWnd)) {
            const DWORD error = GetLastError();
            GlobalFree(memory);
            return ClipboardFailure(hWnd, error);
        }
        if (!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT, memory)) {
            const DWORD error = GetLastError();
            CloseClipboard();
            GlobalFree(memory);
            return ClipboardFailure(hWnd, error);
        }
        // 仅发布成功后，内存所有权才转交系统。
        CloseClipboard();
        return true;
    }

    static bool ReadListViewCell(HWND hWnd, HWND list, int row, int column, std::wstring& text) {
        const HWND header = list ? ListView_GetHeader(list) : nullptr;
        if (!header || column < 0 || column >= Header_GetItemCount(header) || row < -1 ||
            (row >= 0 && row >= ListView_GetItemCount(list)))
            return ClipboardFailure(hWnd, ERROR_INVALID_PARAMETER);
        DWORD error = ERROR_SUCCESS;
        if (!wgwc::gui::ReadListViewText(list, row, column, text, error))
            return ClipboardFailure(hWnd, error);
        return true;
    }

    static std::wstring NormalizeClipboardField(const std::wstring& value) {
        std::wstring result = value;
        for (wchar_t& ch : result) {
            if (ch == L'\t' || ch == L'\r' || ch == L'\n')
                ch = L' ';
        }
        return result;
    }

    static int GetListViewColumnCount(HWND list) {
        const HWND header = list ? ListView_GetHeader(list) : nullptr;
        return header ? Header_GetItemCount(header) : 0;
    }

    void CopyListViewCell(HWND hWnd, HWND list, int row, int column) {
        if (row < 0) {
            ClipboardFailure(hWnd, ERROR_INVALID_PARAMETER);
            return;
        }
        std::wstring text;
        if (ReadListViewCell(hWnd, list, row, column, text))
            CopyToClipboard(hWnd, text);
    }

    void CopyListViewRow(HWND hWnd, HWND list, int row) {
        const int columns = GetListViewColumnCount(list);
        if (row < 0 || !list || row >= ListView_GetItemCount(list) || columns <= 0) {
            ClipboardFailure(hWnd, ERROR_INVALID_PARAMETER);
            return;
        }
        std::wstring text, field;
        for (int column = 0; column < columns; ++column) {
            if (!ReadListViewCell(hWnd, list, row, column, field))
                return;
            if (column > 0)
                text += L"\t";
            text += NormalizeClipboardField(field);
        }
        CopyToClipboard(hWnd, text);
    }

    void CopyListViewAll(HWND hWnd, HWND list) {
        const int columns = GetListViewColumnCount(list);
        if (!list || columns <= 0) {
            ClipboardFailure(hWnd, ERROR_INVALID_PARAMETER);
            return;
        }
        const int rows = ListView_GetItemCount(list);
        std::wstring text, field;
        for (int row = -1; row < rows; ++row) {
            if (row >= 0)
                text += L"\r\n";
            for (int column = 0; column < columns; ++column) {
                if (!ReadListViewCell(hWnd, list, row, column, field))
                    return;
                if (column > 0)
                    text += L"\t";
                text += NormalizeClipboardField(field);
            }
        }
        CopyToClipboard(hWnd, text);
    }

    // 文件

    void OpenFileLocation(HWND hWnd, const std::wstring& path, bool expandEnv, bool checkExists) {
        if (path.empty())
            return;

        // 去除首尾空白和引号（计划任务等来源的路径可能带引号）
        std::wstring cleanPath = path;
        size_t start = cleanPath.find_first_not_of(L" \t\r\n");
        size_t end = cleanPath.find_last_not_of(L" \t\r\n");
        if (start != std::wstring::npos && end != std::wstring::npos) {
            cleanPath = cleanPath.substr(start, end - start + 1);
        }
        // 去除首尾双引号
        if (cleanPath.size() >= 2 && cleanPath.front() == L'"' && cleanPath.back() == L'"') {
            cleanPath = cleanPath.substr(1, cleanPath.size() - 2);
        }

        // 跳过特殊路径标记
        if (cleanPath[0] == L'<' || cleanPath[0] == L'[')
            return;

        // 展开环境变量
        std::wstring expandedPath = expandEnv ? ExpandEnvStrings(cleanPath) : cleanPath;

        if (checkExists) {
            if (GetFileAttributesW(expandedPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                MessageBoxW(hWnd, L"文件不存在或无法访问", L"提示", MB_OK | MB_ICONWARNING);
                return;
            }
        }

        // 使用 explorer /select 打开并选中文件
        std::wstring cmd = L"/select,\"" + expandedPath + L"\"";
        ShellExecuteW(NULL, L"open", L"explorer.exe", cmd.c_str(), NULL, SW_SHOWNORMAL);
    }

    void OpenFileProperties(HWND hWnd, const std::wstring& path, bool expandEnv) {
        if (path.empty())
            return;

        std::wstring cleanPath = path;
        size_t start = cleanPath.find_first_not_of(L" \t\r\n");
        size_t end = cleanPath.find_last_not_of(L" \t\r\n");
        if (start == std::wstring::npos || end == std::wstring::npos)
            return;
        cleanPath = cleanPath.substr(start, end - start + 1);

        if (cleanPath.size() >= 2 && cleanPath.front() == L'"' && cleanPath.back() == L'"') {
            cleanPath = cleanPath.substr(1, cleanPath.size() - 2);
        }
        if (cleanPath.empty() || cleanPath[0] == L'<' || cleanPath[0] == L'[')
            return;

        std::wstring expandedPath = expandEnv ? ExpandEnvStrings(cleanPath) : cleanPath;
        if (GetFileAttributesW(expandedPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            MessageBoxW(hWnd, L"文件不存在或无法访问", L"提示", MB_OK | MB_ICONWARNING);
            return;
        }

        if (!SHObjectProperties(hWnd, SHOP_FILEPATH, expandedPath.c_str(), NULL)) {
            MessageBoxW(hWnd, L"无法打开文件属性", L"提示", MB_OK | MB_ICONWARNING);
        }
    }

    std::wstring FormatSignatureText(SignatureState state, const std::wstring& publisher) {
        return wgwc::gui::presentation::Signature(state, publisher);
    }

    bool MatchSignatureFilter(SignatureState state, int filter) {
        switch (filter) {
        case 0:
            return true;
        case 1:
            return state == SignatureState::Signed;
        case 2:
            return state == SignatureState::Mismatch;
        case 3:
            return state == SignatureState::Unsigned;
        case 4:
            return state == SignatureState::Unknown;
        default:
            return true;
        }
    }

    // 计算文件哈希
    FileHashResult CalculateFileHashes(const std::wstring& path) {
        const auto hashes =
            wgwc::core::files::CalculateHashes(path, wgwc::core::files::HashAlgorithm::All, 500ULL * 1024 * 1024, {});
        FileHashResult result;
        result.success = hashes.status == wgwc::core::CollectionStatus::Complete;
        result.md5 = hashes.md5;
        result.sha1 = hashes.sha1;
        result.sha256 = hashes.sha256;
        if (hashes.errorCode == L"FILE_TOO_LARGE")
            result.md5 = result.sha1 = result.sha256 = L"文件过大";
        return result;
    }

    namespace {
        // 模态窗口仅在调用期间引用结果，不重复复制哈希字符串。
        struct HashDialogData {
            const std::wstring& filePath;
            const FileHashResult& hashes;
            bool sha256Copied;
        };

        INT_PTR CALLBACK HashDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
            switch (message) {
            case WM_INITDIALOG: {
                const auto* data = reinterpret_cast<const HashDialogData*>(lParam);
                if (!data)
                    return FALSE;
                SetDlgItemTextW(hDlg, IDC_HASH_FILEPATH, data->filePath.c_str());
                SetDlgItemTextW(hDlg, IDC_HASH_MD5, data->hashes.md5.c_str());
                SetDlgItemTextW(hDlg, IDC_HASH_SHA1, data->hashes.sha1.c_str());
                SetDlgItemTextW(hDlg, IDC_HASH_SHA256, data->hashes.sha256.c_str());
                SetDlgItemTextW(hDlg, IDC_HASH_COPY_STATUS,
                                data->sha256Copied ? L"SHA256 已复制到剪贴板" : L"SHA256 未复制到剪贴板");
                return TRUE;
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
    }

    void ShowFileHashDialog(HINSTANCE instance, HWND owner, const std::wstring& path, const FileHashResult& hashes) {
        if (hashes.md5.empty() && hashes.sha1.empty() && hashes.sha256.empty()) {
            MessageBoxW(owner, L"无法计算文件哈希", L"错误", MB_OK | MB_ICONERROR);
            return;
        }

        // 文件过大等诊断文本照常展示，但不能当作有效哈希复制。
        const bool copied = hashes.success && !hashes.sha256.empty() && CopyToClipboard(owner, hashes.sha256);
        const HashDialogData data{ path, hashes, copied };
        DialogBoxParamW(instance, MAKEINTRESOURCEW(IDD_FILE_HASHES), owner, HashDialogProc,
                        reinterpret_cast<LPARAM>(&data));
    }

    // 更新检查

    namespace {
        constexpr DWORD UpdateTimeoutMs = 8000;
        constexpr ULONGLONG UpdateBudgetMs = 30000;
        constexpr size_t UpdateResponseLimit = 64 * 1024;

        struct UpdateInternetHandle {
            HINTERNET value;

            explicit UpdateInternetHandle(HINTERNET handle) : value(handle) {}

            ~UpdateInternetHandle() {
                if (value)
                    InternetCloseHandle(value);
            }

            UpdateInternetHandle(const UpdateInternetHandle&) = delete;
            UpdateInternetHandle& operator=(const UpdateInternetHandle&) = delete;
        };

        // 仅用于此接口的有界读取器，不是通用 JSON 文档模型。
        class UpdateResponseReader {
        public:
            explicit UpdateResponseReader(const std::wstring& input) : text(input) {}

            bool Read() {
                if (!Object(Scope::Root, 0))
                    return false;
                Space();
                if (position != text.size() || !seenSuccess)
                    return false;
                if (!serverSuccess)
                    return true;
                if (!seenData || !seenVersion || !seenAvailable || latestVersion.empty() || latestVersion.size() > 128)
                    return false;
                for (wchar_t ch : latestVersion)
                    if (ch <= L' ' || ch == 0x7f)
                        return false;
                return true;
            }

            bool serverSuccess = false;
            bool hasUpdate = false;
            std::wstring latestVersion;

        private:
            enum class Scope {
                Root,
                Data,
                Other
            };
            const std::wstring& text;
            size_t position = 0;
            bool seenSuccess = false, seenData = false;
            bool seenVersion = false, seenAvailable = false;

            void Space() {
                while (position < text.size() && (text[position] == L' ' || text[position] == L'\t' ||
                                                  text[position] == L'\r' || text[position] == L'\n'))
                    ++position;
            }

            bool Take(wchar_t ch) {
                Space();
                if (position == text.size() || text[position] != ch)
                    return false;
                ++position;
                return true;
            }

            bool Literal(const wchar_t* value, size_t length) {
                Space();
                if (text.compare(position, length, value, length) != 0)
                    return false;
                position += length;
                return true;
            }

            bool Boolean(bool& value) {
                if (Literal(L"true", 4)) {
                    value = true;
                    return true;
                }
                if (Literal(L"false", 5)) {
                    value = false;
                    return true;
                }
                return false;
            }

            bool Hex(wchar_t& value) {
                unsigned number = 0;
                for (unsigned i = 0; i < 4; ++i) {
                    if (position == text.size())
                        return false;
                    const wchar_t ch = text[position++];
                    unsigned digit = 0;
                    if (ch >= L'0' && ch <= L'9')
                        digit = ch - L'0';
                    else if (ch >= L'a' && ch <= L'f')
                        digit = ch - L'a' + 10;
                    else if (ch >= L'A' && ch <= L'F')
                        digit = ch - L'A' + 10;
                    else
                        return false;
                    number = number * 16 + digit;
                }
                value = static_cast<wchar_t>(number);
                return true;
            }

            bool String(std::wstring& value) {
                if (!Take(L'"'))
                    return false;
                value.clear();
                while (position < text.size()) {
                    wchar_t ch = text[position++];
                    if (ch == L'"')
                        return true;
                    if (ch < L' ')
                        return false;
                    if (ch == L'\\') {
                        if (position == text.size())
                            return false;
                        ch = text[position++];
                        switch (ch) {
                        case L'"':
                        case L'\\':
                        case L'/':
                            break;
                        case L'b':
                            ch = L'\b';
                            break;
                        case L'f':
                            ch = L'\f';
                            break;
                        case L'n':
                            ch = L'\n';
                            break;
                        case L'r':
                            ch = L'\r';
                            break;
                        case L't':
                            ch = L'\t';
                            break;
                        case L'u':
                            if (!Hex(ch))
                                return false;
                            if (ch >= 0xd800 && ch <= 0xdbff) {
                                if (position + 2 > text.size() || text[position] != L'\\' || text[position + 1] != L'u')
                                    return false;
                                position += 2;
                                wchar_t low = 0;
                                if (!Hex(low) || low < 0xdc00 || low > 0xdfff)
                                    return false;
                                value += ch;
                                ch = low;
                            } else if (ch >= 0xdc00 && ch <= 0xdfff)
                                return false;
                            break;
                        default:
                            return false;
                        }
                    }
                    value += ch;
                }
                return false;
            }

            bool Digits() {
                const size_t start = position;
                while (position < text.size() && text[position] >= L'0' && text[position] <= L'9')
                    ++position;
                return position != start;
            }

            bool Number() {
                if (position < text.size() && text[position] == L'-')
                    ++position;
                if (position == text.size())
                    return false;
                if (text[position] == L'0')
                    ++position;
                else if (!Digits())
                    return false;
                if (position < text.size() && text[position] == L'.') {
                    ++position;
                    if (!Digits())
                        return false;
                }
                if (position < text.size() && (text[position] == L'e' || text[position] == L'E')) {
                    ++position;
                    if (position < text.size() && (text[position] == L'+' || text[position] == L'-'))
                        ++position;
                    if (!Digits())
                        return false;
                }
                return true;
            }

            bool Value(unsigned depth) {
                Space();
                if (depth > 16 || position == text.size())
                    return false;
                const wchar_t ch = text[position];
                if (ch == L'{')
                    return Object(Scope::Other, depth);
                if (ch == L'[') {
                    ++position;
                    if (Take(L']'))
                        return true;
                    do {
                        if (!Value(depth + 1))
                            return false;
                        if (Take(L']'))
                            return true;
                    } while (Take(L','));
                    return false;
                }
                if (ch == L'"') {
                    std::wstring ignored;
                    return String(ignored);
                }
                bool ignored = false;
                if (ch == L't' || ch == L'f')
                    return Boolean(ignored);
                if (ch == L'n')
                    return Literal(L"null", 4);
                return Number();
            }

            bool Object(Scope scope, unsigned depth) {
                if (depth > 16 || !Take(L'{'))
                    return false;
                if (Take(L'}'))
                    return true;
                std::vector<std::wstring> keys;
                do {
                    std::wstring key;
                    if (keys.size() >= 128 || !String(key) || std::find(keys.begin(), keys.end(), key) != keys.end() ||
                        !Take(L':'))
                        return false;
                    keys.push_back(key);
                    bool valid = false;
                    if (scope == Scope::Root && key == L"success") {
                        valid = Boolean(serverSuccess);
                        seenSuccess = valid;
                    } else if (scope == Scope::Root && key == L"data") {
                        Space();
                        if (position < text.size() && text[position] == L'{') {
                            valid = Object(Scope::Data, depth + 1);
                            seenData = valid;
                        } else
                            valid = Value(depth + 1);
                    } else if (scope == Scope::Data && key == L"latestVersion") {
                        valid = String(latestVersion);
                        seenVersion = valid;
                    } else if (scope == Scope::Data && key == L"updateAvailable") {
                        valid = Boolean(hasUpdate);
                        seenAvailable = valid;
                    } else
                        valid = Value(depth + 1);
                    if (!valid)
                        return false;
                    if (Take(L'}'))
                        return true;
                } while (Take(L','));
                return false;
            }
        };
    }

    UpdateCheckResult CheckUpdate(const std::wstring& currentVersion) {
        UpdateCheckResult result{};
        const ULONGLONG started = GetTickCount64();

        // 由服务端根据当前版本判断是否存在更新
        std::wstring url = L"/apis/api.secwg.com/v1alpha1/products/wg-win-check/update-check?currentVersion=";
        url += currentVersion;

        UpdateInternetHandle session(InternetOpenW(L"WG-Win-Check", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0));
        if (!session.value) {
            result.errorMsg = L"网络初始化失败";
            return result;
        }
        DWORD timeout = UpdateTimeoutMs;
        for (DWORD option :
             { INTERNET_OPTION_CONNECT_TIMEOUT, INTERNET_OPTION_SEND_TIMEOUT, INTERNET_OPTION_RECEIVE_TIMEOUT }) {
            if (!InternetSetOptionW(session.value, option, &timeout, sizeof(timeout))) {
                result.errorMsg = L"网络超时设置失败";
                return result;
            }
        }

        UpdateInternetHandle connection(InternetConnectW(session.value, L"secwg.com", INTERNET_DEFAULT_HTTPS_PORT, NULL,
                                                         NULL, INTERNET_SERVICE_HTTP, 0, 0));
        if (!connection.value) {
            result.errorMsg = L"连接失败";
            return result;
        }

        const DWORD flags = INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
        UpdateInternetHandle request(
            HttpOpenRequestW(connection.value, L"GET", url.c_str(), NULL, NULL, NULL, flags, 0));
        if (!request.value) {
            result.errorMsg = L"请求创建失败";
            return result;
        }
        if (!HttpSendRequestW(request.value, NULL, 0, NULL, 0)) {
            result.errorMsg = L"请求发送失败";
            return result;
        }

        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        if (!HttpQueryInfoW(request.value, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode,
                            &statusCodeSize, NULL) ||
            statusCode != HTTP_STATUS_OK) {
            result.errorMsg = L"服务器响应异常";
            return result;
        }

        DWORD contentLength = 0;
        DWORD contentLengthSize = sizeof(contentLength);
        const bool hasContentLength = HttpQueryInfoW(request.value, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
                                                     &contentLength, &contentLengthSize, NULL) != FALSE;
        if (!hasContentLength && GetLastError() != ERROR_HTTP_HEADER_NOT_FOUND) {
            result.errorMsg = L"响应长度无效";
            return result;
        }
        if (hasContentLength && contentLength > UpdateResponseLimit) {
            result.errorMsg = L"响应内容过大";
            return result;
        }

        std::string response;
        char buffer[4096];
        for (;;) {
            const ULONGLONG elapsed = GetTickCount64() - started;
            if (elapsed >= UpdateBudgetMs) {
                result.errorMsg = L"更新检查超时";
                return result;
            }
            timeout = static_cast<DWORD>((std::min)(static_cast<ULONGLONG>(UpdateTimeoutMs), UpdateBudgetMs - elapsed));
            if (!InternetSetOptionW(request.value, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout))) {
                result.errorMsg = L"网络超时设置失败";
                return result;
            }
            DWORD bytesRead = 0;
            if (!InternetReadFile(request.value, buffer, sizeof(buffer), &bytesRead)) {
                result.errorMsg = L"响应读取失败";
                return result;
            }
            if (GetTickCount64() - started >= UpdateBudgetMs) {
                result.errorMsg = L"更新检查超时";
                return result;
            }
            if (bytesRead == 0)
                break;
            if (bytesRead > UpdateResponseLimit - response.size()) {
                result.errorMsg = L"响应内容过大";
                return result;
            }
            response.append(buffer, bytesRead);
        }
        if (hasContentLength && response.size() != contentLength) {
            result.errorMsg = L"响应内容不完整";
            return result;
        }
        if (response.empty()) {
            result.errorMsg = L"响应为空";
            return result;
        }

        const int bytes = static_cast<int>(response.size());
        const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, response.data(), bytes, NULL, 0);
        if (length <= 0) {
            result.errorMsg = L"响应编码无效";
            return result;
        }
        std::wstring decoded(static_cast<size_t>(length), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, response.data(), bytes, &decoded[0], length) != length) {
            result.errorMsg = L"响应编码无效";
            return result;
        }
        UpdateResponseReader reader(decoded);
        if (!reader.Read()) {
            result.errorMsg = L"响应格式或更新字段无效";
            return result;
        }
        if (!reader.serverSuccess) {
            result.errorMsg = L"服务器返回失败";
            return result;
        }

        // 只有完整响应通过校验后，才发布服务器给出的更新结果。
        result.latestVersion = reader.latestVersion;
        result.hasUpdate = reader.hasUpdate;
        result.success = true;
        return result;
    }

    // 威胁情报

    void QueryVirusTotal(const std::wstring& sha256) {
        if (sha256.empty())
            return;

        std::wstring url = L"https://www.virustotal.com/gui/file/" + sha256;
        ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
    }

    void QueryThreatBook(const std::wstring& sha256) {
        if (sha256.empty())
            return;

        std::wstring url = L"https://s.threatbook.com/report/file/" + sha256;
        ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
    }

} // 命名空间 CommonUtils 结束。
