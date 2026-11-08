#include "../../system/Win32.h"
#include "ServiceModule.h"
#include <cwctype>

namespace wgwc::core::services {
    namespace {
        std::wstring Trim(const std::wstring& value) {
            const auto first = value.find_first_not_of(L" \t\r\n");
            if (first == std::wstring::npos)
                return L"";
            return value.substr(first, value.find_last_not_of(L" \t\r\n") - first + 1);
        }

        std::wstring Expanded(const std::wstring& value) {
            auto path = Trim(files::ExpandEnvironment(value));
            if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"')
                path = Trim(path.substr(1, path.size() - 2));
            if (path.compare(0, 4, L"\\??\\") == 0)
                path.erase(0, 4);
            const auto lower = rules::ToLower(path);
            wchar_t windows[MAX_PATH]{};
            const auto length = GetWindowsDirectoryW(windows, MAX_PATH);
            if (length && length < MAX_PATH) {
                if (lower.compare(0, 12, L"\\systemroot\\") == 0)
                    path = std::wstring(windows) + path.substr(11);
                else if (lower.compare(0, 9, L"system32\\") == 0)
                    path = std::wstring(windows) + L"\\" + path;
            }
            return path;
        }

        bool Absolute(const std::wstring& path) {
            return (path.size() >= 3 && iswalpha(path[0]) && path[1] == L':' &&
                    (path[2] == L'\\' || path[2] == L'/')) ||
                   (path.size() > 2 && path[0] == L'\\' && path[1] == L'\\');
        }

        bool ExtensionBoundary(wchar_t value) {
            return iswspace(value) || value == L',' || value == L'&' || value == L'|';
        }
    }

    Path ResolveFile(const std::wstring& value) {
        Path result;
        result.value = Expanded(value);
        auto& path = result.value;
        if (path.empty() || path.size() > 32767 || path.find(L'%') != std::wstring::npos ||
            path.find(L"://") != std::wstring::npos || path.compare(0, 4, L"\\\\.\\") == 0)
            return result;
        if (!Absolute(path) && path.find_first_of(L"\\/:") == std::wstring::npos) {
            wchar_t system[MAX_PATH]{};
            const auto length = GetSystemDirectoryW(system, MAX_PATH);
            if (length && length < MAX_PATH) {
                const auto candidate = std::wstring(system) + L"\\" + path;
                if (rules::IsExistingFile(candidate))
                    path = candidate;
                else if (path.find(L'.') == std::wstring::npos && rules::IsExistingFile(candidate + L".exe"))
                    path = candidate + L".exe";
            }
        }
        if (!Absolute(path))
            return result;
        std::uint32_t error = 0;
        const auto normalized = files::ResolvePath(path, &error);
        if (!normalized.empty() && !error) {
            path = normalized;
            result.stable = true;
        }
        return result;
    }

    Path ResolveExecutable(const std::wstring& command) {
        const auto text = Trim(files::ExpandEnvironment(command));
        if (text.empty())
            return {};
        if (text.front() == L'"') {
            const auto end = text.find(L'"', 1);
            if (end == std::wstring::npos) {
                Path result;
                result.value = text;
                return result;
            }
            return ResolveFile(text.substr(1, end - 1));
        }
        const auto firstSpace = text.find_first_of(L" \t\r\n");
        if (firstSpace != std::wstring::npos && text.substr(0, firstSpace).find_first_of(L"\\/:") == std::wstring::npos)
            return ResolveFile(text.substr(0, firstSpace));
        const auto lower = rules::ToLower(text);
        std::size_t best = std::wstring::npos;
        for (const auto extension : { L".exe", L".sys", L".com", L".scr", L".cmd", L".bat", L".dll" }) {
            std::size_t at = 0;
            while ((at = lower.find(extension, at)) != std::wstring::npos) {
                const auto end = at + wcslen(extension);
                if (end == text.size() || ExtensionBoundary(text[end])) {
                    if (best == std::wstring::npos || end < best)
                        best = end;
                    break;
                }
                at = end;
            }
        }
        if (best != std::wstring::npos)
            return ResolveFile(text.substr(0, best));
        const auto separator = text.find_first_of(L" \t\r\n");
        if (separator == std::wstring::npos)
            return ResolveFile(text);
        const auto first = text.substr(0, separator);
        if (first.find_first_of(L"\\/:") == std::wstring::npos)
            return ResolveFile(first);
        // 未加引号且被重命名的可执行文件路径可能包含空格，仅接受实际存在的文件；
        // 否则保留未解析状态，不猜测缺失的路径前缀。
        auto end = separator;
        for (int attempt = 0; attempt < 64 && end != std::wstring::npos; ++attempt) {
            auto candidate = ResolveFile(text.substr(0, end));
            if (candidate.stable && rules::IsExistingFile(candidate.value))
                return candidate;
            end = text.find_first_of(L" \t\r\n", end + 1);
        }
        auto candidate = ResolveFile(text);
        if (candidate.stable && rules::IsExistingFile(candidate.value))
            return candidate;
        candidate.value = text;
        candidate.stable = false;
        return candidate;
    }

    bool IsSvchost(const std::wstring& executable) {
        auto candidate = Expanded(executable);
        for (auto& ch : candidate)
            if (ch == L'/')
                ch = L'\\';
        if (candidate.compare(0, 4, L"\\\\?\\") == 0)
            candidate.erase(0, 4);
        const auto path = ResolveFile(candidate);
        if (!path.stable)
            return false;
        wchar_t windows[MAX_PATH]{};
        const auto length = GetWindowsDirectoryW(windows, MAX_PATH);
        if (!length || length >= MAX_PATH)
            return false;
        // 其他位置的同名可执行文件不属于系统 ServiceDll 宿主。
        for (const auto suffix : { L"\\System32\\svchost.exe", L"\\SysWOW64\\svchost.exe" }) {
            const auto expected = ResolveFile(std::wstring(windows) + suffix);
            if (expected.stable && _wcsicmp(path.value.c_str(), expected.value.c_str()) == 0)
                return true;
        }
        return false;
    }

    void SelectAssociatedFile(Record& record) {
        record.executablePath.clear();
        record.associatedFile.clear();
        record.associationSource = L"unresolved";
        record.associationStable = false;
        if (record.configState != FieldState::Available)
            return;
        const auto executable = ResolveExecutable(record.binaryPath);
        record.executablePath = executable.value;
        if (IsSvchost(executable.value)) {
            if (record.serviceDllState != FieldState::Available) {
                record.associationSource = L"unresolved-service-dll";
                return;
            }
            if (!record.serviceDll.empty()) {
                const auto dll = ResolveFile(record.serviceDll);
                record.associatedFile = dll.value;
                record.associationStable = dll.stable;
                record.associationSource = L"service-dll";
                return;
            }
            record.associationSource = L"service-executable-fallback";
        } else
            record.associationSource = L"service-executable";
        record.associatedFile = executable.value;
        record.associationStable = executable.stable;
        // 描述资源仅用于展示，不能作为服务实现文件。
    }

    const wchar_t* StateName(std::uint32_t state) {
        switch (state) {
        case SERVICE_RUNNING:
            return L"running";
        case SERVICE_STOPPED:
            return L"stopped";
        case SERVICE_START_PENDING:
            return L"start-pending";
        case SERVICE_STOP_PENDING:
            return L"stop-pending";
        case SERVICE_CONTINUE_PENDING:
            return L"continue-pending";
        case SERVICE_PAUSE_PENDING:
            return L"pause-pending";
        case SERVICE_PAUSED:
            return L"paused";
        default:
            return L"unknown";
        }
    }

    const wchar_t* StartTypeName(std::uint32_t startType) {
        switch (startType) {
        case SERVICE_AUTO_START:
            return L"auto";
        case SERVICE_DEMAND_START:
            return L"manual";
        case SERVICE_DISABLED:
            return L"disabled";
        case SERVICE_BOOT_START:
            return L"boot";
        case SERVICE_SYSTEM_START:
            return L"system";
        default:
            return L"unknown";
        }
    }

    bool IsAutoStart(std::uint32_t startType) {
        return startType == SERVICE_AUTO_START || startType == SERVICE_BOOT_START || startType == SERVICE_SYSTEM_START;
    }

    bool IsMicrosoftGroup(const std::wstring& company) {
        // 保留 GUI 原有的公司名称分类，不将其视为发布者可信校验。
        return rules::ToLower(company).find(L"microsoft") != std::wstring::npos;
    }

    bool Matches(const Record& record, const Filter& filter) {
        if (!filter.name.empty() && _wcsicmp(record.serviceName.c_str(), filter.name.c_str()) != 0)
            return false;
        const bool microsoft = IsMicrosoftGroup(record.file.evidence.company);
        if ((filter.vendor == L"microsoft" && !microsoft) || (filter.vendor == L"third-party" && microsoft))
            return false;
        if (filter.state != L"all") {
            if (record.statusState != FieldState::Available)
                return false;
            const bool pending =
                record.currentState == SERVICE_START_PENDING || record.currentState == SERVICE_STOP_PENDING ||
                record.currentState == SERVICE_CONTINUE_PENDING || record.currentState == SERVICE_PAUSE_PENDING;
            if (filter.state == L"pending") {
                if (!pending)
                    return false;
            } else if (filter.state != StateName(record.currentState))
                return false;
        }
        if (filter.startType != L"all") {
            if (record.configState != FieldState::Available)
                return false;
            if (filter.startType == L"auto") {
                if (!IsAutoStart(record.startType))
                    return false;
            } else if (filter.startType != StartTypeName(record.startType))
                return false;
        }
        return true;
    }

    PageAction NextPage(const EnumerationPage& page) {
        if (page.success)
            return PageAction::Complete;
        if (page.error != ERROR_MORE_DATA)
            return PageAction::Failed;
        if (!page.returned || page.previousResume == page.nextResume)
            return PageAction::Failed;
        return PageAction::Continue;
    }
}
