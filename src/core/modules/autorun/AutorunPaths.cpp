#include "../../system/Win32.h"
#include "AutorunModule.h"
#include <algorithm>
#include <cwctype>
#include <cstring>

namespace wgwc::core::autorun {
    namespace {
        std::wstring Trim(const std::wstring& value) {
            const auto first = value.find_first_not_of(L" \t\r\n");
            if (first == std::wstring::npos)
                return L"";
            return value.substr(first, value.find_last_not_of(L" \t\r\n") - first + 1);
        }

        std::wstring Unquote(const std::wstring& value) {
            auto text = Trim(value);
            while (text.size() >= 2 &&
                   ((text.front() == L'"' && text.back() == L'"') || (text.front() == L'\'' && text.back() == L'\'')))
                text = Trim(text.substr(1, text.size() - 2));
            return text;
        }

        bool Boundary(wchar_t c) {
            return iswspace(c) || c == L'"' || c == L'\'' || c == L'&' || c == L'|' || c == L';' || c == L'(' ||
                   c == L')' || c == L'<' || c == L'>';
        }

        bool Absolute(const std::wstring& path) {
            return (path.size() >= 3 && iswalpha(path[0]) && path[1] == L':' &&
                    (path[2] == L'\\' || path[2] == L'/')) ||
                   (path.size() > 2 && path[0] == L'\\' && path[1] == L'\\');
        }

        bool Wrapper(const std::wstring& value) {
            auto path = rules::ToLower(Unquote(value));
            if (path == L"%comspec%")
                return true;
            const auto slash = path.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
                path.erase(0, slash + 1);
            return path == L"cmd" || path == L"cmd.exe" || path == L"powershell" || path == L"powershell.exe" ||
                   path == L"pwsh" || path == L"pwsh.exe" || path == L"wscript.exe" || path == L"cscript.exe" ||
                   path == L"rundll32.exe" || path == L"mshta.exe";
        }

        std::size_t ExtensionEnd(const std::wstring& value) {
            const auto lower = rules::ToLower(value);
            const wchar_t* extensions[] = { L".exe", L".dll", L".ps1", L".vbs", L".js",  L".wsf",
                                            L".bat", L".cmd", L".hta", L".lnk", L".scr", L".com" };
            auto best = std::wstring::npos;
            for (const auto ext : extensions) {
                std::size_t pos = 0;
                while ((pos = lower.find(ext, pos)) != std::wstring::npos) {
                    const auto end = pos + wcslen(ext);
                    if (end == value.size() || Boundary(value[end]) || value[end] == L',') {
                        if (best == std::wstring::npos || end < best)
                            best = end;
                        break;
                    }
                    pos = end;
                }
            }
            return best;
        }

        std::wstring Expanded(const std::wstring& value) {
            auto path = Unquote(files::ExpandEnvironment(value));
            if (path.compare(0, 4, L"\\??\\") == 0)
                path.erase(0, 4);
            if (rules::ToLower(path).compare(0, 12, L"\\systemroot\\") == 0) {
                wchar_t windows[MAX_PATH]{};
                const auto size = GetWindowsDirectoryW(windows, MAX_PATH);
                if (size && size < MAX_PATH)
                    path = std::wstring(windows) + path.substr(11);
            }
            return path;
        }

        std::wstring StablePath(const std::wstring& raw, const std::wstring& directory, bool& stable) {
            stable = false;
            auto path = Expanded(raw);
            const auto lower = rules::ToLower(path);
            if (path.empty() || path.find(L'%') != std::wstring::npos || lower.find(L"://") != std::wstring::npos ||
                path.compare(0, 4, L"\\\\.\\") == 0)
                return path;
            if (!Absolute(path)) {
                const auto working = Expanded(directory);
                if (Absolute(working)) {
                    if (path.size() > 1 && path[1] == L':')
                        return path;
                    if (path[0] == L'\\' || path[0] == L'/') {
                        if (working.size() < 2 || working[1] != L':')
                            return path;
                        path = working.substr(0, 2) + path;
                    } else
                        path = working + L"\\" + path;
                } else if (path.find_first_of(L"\\/:") == std::wstring::npos) {
                    // 不能将调用者的当前目录当作自启动项的搜索路径。
                    wchar_t roots[2][MAX_PATH]{};
                    GetSystemDirectoryW(roots[0], MAX_PATH);
                    GetWindowsDirectoryW(roots[1], MAX_PATH);
                    for (const auto& root : roots) {
                        if (!root[0])
                            continue;
                        auto candidate = std::wstring(root) + L"\\" + path;
                        if (rules::IsExistingFile(candidate)) {
                            path = candidate;
                            break;
                        }
                        if (path.find(L'.') == std::wstring::npos && rules::IsExistingFile(candidate + L".exe")) {
                            path = candidate + L".exe";
                            break;
                        }
                    }
                }
            }
            if (!Absolute(path) || path.size() > 32767)
                return path;
            const auto needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
            if (!needed || needed > 32768)
                return path;
            std::vector<wchar_t> buffer(needed);
            const auto copied = GetFullPathNameW(path.c_str(), needed, buffer.data(), nullptr);
            if (!copied || copied >= needed)
                return path;
            stable = true;
            return std::wstring(buffer.data(), copied);
        }

        std::wstring Program(const std::wstring& command) {
            const auto text = Trim(files::ExpandEnvironment(command));
            if (text.empty())
                return L"";
            if (text.front() == L'"') {
                const auto end = text.find(L'"', 1);
                return text.substr(1, end == std::wstring::npos ? end : end - 1);
            }
            const auto space = text.find_first_of(L" \t\r\n&|;");
            const auto first = text.substr(0, space);
            if (!Absolute(first) || space == std::wstring::npos || rules::IsExistingFile(first))
                return first;
            const auto end = ExtensionEnd(text);
            if (end != std::wstring::npos)
                return text.substr(0, end);
            return first;
        }

        void AddCandidate(std::vector<std::wstring>& candidates, std::wstring raw) {
            raw = Unquote(raw);
            const auto end = ExtensionEnd(raw);
            if (end == std::wstring::npos)
                return;
            raw = raw.substr(0, end);
            if (rules::ToLower(raw).find(L"://") != std::wstring::npos || Wrapper(raw))
                return;
            // PowerShell 也支持 -File:C:\path\script.ps1 这种写法。
            for (std::size_t i = 0; i + 2 < raw.size(); ++i) {
                if (iswalpha(raw[i]) && raw[i + 1] == L':' && (raw[i + 2] == L'\\' || raw[i + 2] == L'/')) {
                    raw.erase(0, i);
                    break;
                }
            }
            for (const auto& existing : candidates)
                if (_wcsicmp(existing.c_str(), raw.c_str()) == 0)
                    return;
            candidates.push_back(raw);
        }

        std::vector<std::wstring> Candidates(const std::wstring& command) {
            std::vector<std::wstring> result;
            for (std::size_t i = 0; i < command.size(); ++i) {
                if (command[i] != L'"' && command[i] != L'\'')
                    continue;
                const auto end = command.find(command[i], i + 1);
                if (end == std::wstring::npos)
                    break;
                AddCandidate(result, command.substr(i + 1, end - i - 1));
                i = end;
            }
            std::size_t start = 0;
            while (start < command.size()) {
                while (start < command.size() && Boundary(command[start]))
                    ++start;
                auto end = start;
                while (end < command.size() && !Boundary(command[end]))
                    ++end;
                if (end > start)
                    AddCandidate(result, command.substr(start, end - start));
                start = end;
            }
            return result;
        }

        std::size_t ReferenceDot(const std::wstring& reference) {
            const auto quote = reference.find(L'"');
            const auto prefix = reference.substr(0, quote);
            const auto colon = prefix.find_last_of(L':');
            return reference.find(L'.', colon == std::wstring::npos ? 0 : colon + 1);
        }
    }

    const wchar_t* TypeName(Type type) {
        switch (type) {
        case Type::Registry:
            return L"registry";
        case Type::StartupFolder:
            return L"startup-folder";
        case Type::Winlogon:
            return L"winlogon";
        case Type::IFEO:
            return L"ifeo";
        case Type::AppInit:
            return L"appinit";
        case Type::WindowsLoad:
            return L"windows-load";
        case Type::SafeBoot:
            return L"safeboot";
        case Type::RunOnceEx:
            return L"runonceex";
        case Type::WmiSubscription:
            return L"wmi";
        }
        return L"unknown";
    }

    const wchar_t* TypeDisplay(Type type) {
        switch (type) {
        case Type::Registry:
            return L"注册表";
        case Type::StartupFolder:
            return L"启动文件夹";
        case Type::Winlogon:
            return L"Winlogon";
        case Type::IFEO:
            return L"IFEO";
        case Type::AppInit:
            return L"AppInit_DLLs";
        case Type::WindowsLoad:
            return L"Windows Load";
        case Type::SafeBoot:
            return L"SafeBoot";
        case Type::RunOnceEx:
            return L"RunOnceEx";
        case Type::WmiSubscription:
            return L"WMI订阅";
        }
        return L"";
    }

    bool TypeMatches(const std::wstring& filter, Type type) {
        return filter == L"all" || filter == TypeName(type);
    }

    std::wstring SourceKey(Type type, const std::wstring& location, const std::wstring& name,
                           const std::wstring& discriminator) {
        std::wstring key = TypeName(type);
        for (const auto* value : { &location, &name, &discriminator })
            key += L"|" + std::to_wstring(value->size()) + L":" + *value;
        return key;
    }

    Association ResolveFile(const std::wstring& path, const std::wstring& directory) {
        Association value;
        value.associatedFile = StablePath(path, directory, value.stable);
        value.executablePath = value.associatedFile;
        return value;
    }

    Association ResolveCommand(const std::wstring& command, const std::wstring& directory) {
        const auto program = Program(command);
        auto result = ResolveFile(program, directory);
        if (!Wrapper(program))
            return result;
        Association first;
        bool found = false;
        for (const auto& candidate : Candidates(files::ExpandEnvironment(command))) {
            auto related = ResolveFile(candidate, directory);
            if (!found) {
                first = related;
                found = true;
            }
            if (related.stable && rules::IsExistingFile(related.associatedFile)) {
                first = related;
                break;
            }
        }
        if (found) {
            result.associatedFile = first.associatedFile;
            result.stable = first.stable;
        }
        return result;
    }

    bool IsDefaultConfig(Type type, const std::wstring& name, const std::wstring& value) {
        if (value.find(L'\0') != std::wstring::npos)
            return false;
        auto text = Unquote(files::ExpandEnvironment(value));
        const wchar_t* fileName = nullptr;
        const wchar_t* relativePath = nullptr;
        if (type == Type::Winlogon && name == L"Userinit") {
            while (!text.empty() && text.back() == L',') {
                text.pop_back();
                text = Trim(text);
            }
            text = Unquote(text);
            fileName = L"userinit.exe";
            relativePath = L"System32\\userinit.exe";
        } else if (type == Type::Winlogon && name == L"Shell") {
            fileName = L"explorer.exe";
            relativePath = L"explorer.exe";
        } else if (type == Type::SafeBoot) {
            fileName = L"cmd.exe";
            relativePath = L"System32\\cmd.exe";
        } else
            return Trim(value).empty();

        // 保留明确支持的无路径文件名，但不能仅凭路径后缀判定可信。
        if (_wcsicmp(text.c_str(), fileName) == 0)
            return true;
        const auto expanded = Expanded(text);
        if (!Absolute(expanded))
            return false;
        bool stable = false;
        const auto actualPath = StablePath(expanded, L"", stable);
        if (!stable)
            return false;

        wchar_t windows[MAX_PATH]{};
        const auto length = GetWindowsDirectoryW(windows, MAX_PATH);
        if (!length || length >= MAX_PATH)
            return false;
        bool expectedStable = false;
        const auto expectedPath = StablePath(std::wstring(windows, length) + L"\\" + relativePath, L"", expectedStable);
        return expectedStable && _wcsicmp(actualPath.c_str(), expectedPath.c_str()) == 0;
    }

    bool DecodeRegistryString(std::uint32_t type, const unsigned char* bytes, std::size_t size, std::wstring& text) {
        text.clear();
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || size % sizeof(wchar_t) || size > 1024 * 1024 ||
            (size && !bytes))
            return false;
        if (!size)
            return true;
        text.resize(size / sizeof(wchar_t));
        std::memcpy(text.data(), bytes, size);
        while (!text.empty() && text.back() == L'\0')
            text.pop_back();
        if (text.find(L'\0') != std::wstring::npos) {
            text.clear();
            return false;
        }
        return true;
    }

    std::wstring WmiReferenceClass(const std::wstring& reference) {
        // 类名位于第一个键分隔符之前，不能从带引号的键值中提取。
        const auto dot = ReferenceDot(reference);
        if (dot == std::wstring::npos)
            return L"";
        auto prefix = reference.substr(0, dot);
        const auto colon = prefix.find_last_of(L':');
        if (colon != std::wstring::npos)
            prefix.erase(0, colon + 1);
        prefix = Trim(prefix);
        if (prefix.find_first_of(L"\\\"'= ") != std::wstring::npos)
            return L"";
        return rules::ToLower(prefix);
    }

    std::wstring WmiReferenceName(const std::wstring& reference) {
        const auto dot = ReferenceDot(reference);
        if (dot == std::wstring::npos)
            return L"";
        auto key = Trim(reference.substr(dot + 1));
        const auto equals = key.find(L'=');
        if (equals == std::wstring::npos || rules::ToLower(Trim(key.substr(0, equals))) != L"name")
            return L"";
        key = Trim(key.substr(equals + 1));
        if (key.size() < 2 || key.front() != L'"' || key.back() != L'"')
            return L"";
        std::wstring value;
        for (std::size_t i = 1; i + 1 < key.size(); ++i) {
            if (key[i] == L'\\' && i + 2 < key.size())
                ++i;
            else if (key[i] == L'"')
                return L"";
            value.push_back(key[i]);
        }
        return value;
    }
}
