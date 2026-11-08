#pragma once
#include <windows.h>
#include "ListViewSupport.h"
#include <commctrl.h>
#include <algorithm>
#include <climits>
#include <string>
#include <vector>

namespace wgwc::gui::csv {
    namespace detail {
        inline DWORD LastFailure(DWORD fallback) {
            const DWORD error = GetLastError();
            return error == ERROR_SUCCESS ? fallback : error;
        }

        inline bool WriteAll(HANDLE file, const void* data, size_t size, DWORD& error) {
            const char* cursor = static_cast<const char*>(data);
            while (size != 0) {
                const DWORD request = static_cast<DWORD>((std::min)(size, size_t(MAXDWORD)));
                DWORD written = 0;
                if (!WriteFile(file, cursor, request, &written, nullptr)) {
                    error = LastFailure(ERROR_WRITE_FAULT);
                    return false;
                }
                if (written == 0 || written > request) {
                    error = ERROR_WRITE_FAULT;
                    return false;
                }
                cursor += written;
                size -= written;
            }
            return true;
        }

        inline bool AppendField(const std::wstring& text, std::string& row, DWORD& error) {
            if (text.size() > static_cast<size_t>(INT_MAX)) {
                error = ERROR_ARITHMETIC_OVERFLOW;
                return false;
            }
            std::string utf8;
            if (!text.empty()) {
                const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                                                       static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
                if (length == 0) {
                    error = LastFailure(ERROR_NO_UNICODE_TRANSLATION);
                    return false;
                }
                utf8.resize(static_cast<size_t>(length));
                if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                                        utf8.data(), length, nullptr, nullptr) != length) {
                    error = LastFailure(ERROR_NO_UNICODE_TRANSLATION);
                    return false;
                }
            }
            if (!row.empty())
                row.push_back(',');
            row.push_back('"');
            for (const char value : utf8) {
                if (value == '"')
                    row.push_back('"');
                row.push_back(value);
            }
            row.push_back('"');
            return true;
        }

        inline bool WriteList(HWND list, HANDLE file, int rows, int columns, DWORD& error) {
            const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
            if (!WriteAll(file, bom, sizeof(bom), error))
                return false;
            std::string encoded;
            std::wstring field;
            for (int row = -1; row < rows; ++row) {
                encoded.clear();
                for (int column = 0; column < columns; ++column) {
                    if (!wgwc::gui::ReadListViewText(list, row, column, field, error) ||
                        !AppendField(field, encoded, error))
                        return false;
                }
                encoded += "\r\n";
                if (!WriteAll(file, encoded.data(), encoded.size(), error))
                    return false;
            }
            if (ListView_GetItemCount(list) != rows || Header_GetItemCount(ListView_GetHeader(list)) != columns) {
                error = ERROR_INVALID_DATA;
                return false;
            }
            return true;
        }

        inline std::wstring ApiPath(const std::wstring& path) {
            if (path.size() < MAX_PATH || path.compare(0, 4, L"\\\\?\\") == 0)
                return path;
            if (path.compare(0, 2, L"\\\\") == 0)
                return L"\\\\?\\UNC\\" + path.substr(2);
            return L"\\\\?\\" + path;
        }

        inline bool AbsolutePath(const wchar_t* path, std::wstring& result, DWORD& error) {
            if (!path || !*path) {
                error = ERROR_INVALID_PARAMETER;
                return false;
            }
            const DWORD size = GetFullPathNameW(path, 0, nullptr, nullptr);
            if (size == 0) {
                error = LastFailure(ERROR_INVALID_NAME);
                return false;
            }
            std::vector<wchar_t> buffer(size);
            const DWORD length = GetFullPathNameW(path, size, buffer.data(), nullptr);
            if (length == 0 || length >= size) {
                error = length == 0 ? LastFailure(ERROR_INVALID_NAME) : ERROR_INSUFFICIENT_BUFFER;
                return false;
            }
            result.assign(buffer.data(), length);
            return true;
        }

        inline bool ReadDestinationDacl(const std::wstring& path, std::vector<BYTE>& descriptor, DWORD& error) {
            DWORD size = 0;
            if (!GetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION, nullptr, 0, &size)) {
                const DWORD failure = GetLastError();
                if (failure == ERROR_FILE_NOT_FOUND)
                    return true;
                if (failure != ERROR_INSUFFICIENT_BUFFER) {
                    error = failure == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : failure;
                    return false;
                }
            }
            if (size == 0) {
                error = ERROR_INVALID_SECURITY_DESCR;
                return false;
            }
            descriptor.resize(size);
            if (!GetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION, descriptor.data(), size, &size)) {
                error = LastFailure(ERROR_ACCESS_DENIED);
                return false;
            }
            return true;
        }
    }

    // 导出当前显示的行，而不是模块未筛选的原始数据；
    // 仅在读取、UTF-8 转换、写入、刷新和关闭全部成功后发布文件。
    inline bool ExportListView(HWND list, const wchar_t* path, DWORD& error) {
        error = ERROR_SUCCESS;
        if (!IsWindow(list)) {
            error = ERROR_INVALID_WINDOW_HANDLE;
            return false;
        }
        const HWND header = ListView_GetHeader(list);
        const int rows = ListView_GetItemCount(list);
        const int columns = header ? Header_GetItemCount(header) : 0;
        if (rows <= 0 || columns <= 0) {
            error = ERROR_NO_DATA;
            return false;
        }

        std::wstring absolute;
        if (!detail::AbsolutePath(path, absolute, error))
            return false;
        const std::wstring destination = detail::ApiPath(absolute);
        std::vector<BYTE> descriptor;
        if (!detail::ReadDestinationDacl(destination, descriptor, error))
            return false;
        SECURITY_ATTRIBUTES security{ sizeof(security), descriptor.empty() ? nullptr : descriptor.data(), FALSE };

        const size_t separator = absolute.find_last_of(L"\\/");
        if (separator == std::wstring::npos) {
            error = ERROR_INVALID_NAME;
            return false;
        }
        const std::wstring directory = absolute.substr(0, separator + 1);
        HANDLE file = INVALID_HANDLE_VALUE;
        std::wstring temporary;
        static volatile LONG sequence = 0;
        for (unsigned attempt = 0; attempt < 16; ++attempt) {
            temporary = detail::ApiPath(directory + L".wgwc-csv-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                        std::to_wstring(GetTickCount64()) + L"-" +
                                        std::to_wstring(InterlockedIncrement(&sequence)) + L".tmp");
            file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, descriptor.empty() ? nullptr : &security,
                               CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file != INVALID_HANDLE_VALUE)
                break;
            error = detail::LastFailure(ERROR_OPEN_FAILED);
            if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
                return false;
        }
        if (file == INVALID_HANDLE_VALUE)
            return false;

        bool success = detail::WriteList(list, file, rows, columns, error);
        if (success && !FlushFileBuffers(file)) {
            error = detail::LastFailure(ERROR_WRITE_FAULT);
            success = false;
        }
        if (!CloseHandle(file) && success) {
            error = detail::LastFailure(ERROR_WRITE_FAULT);
            success = false;
        }
        if (success &&
            !MoveFileExW(temporary.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            error = detail::LastFailure(ERROR_WRITE_FAULT);
            success = false;
        }
        if (!success) {
            DeleteFileW(temporary.c_str());
            return false;
        }
        error = ERROR_SUCCESS;
        return true;
    }
}
