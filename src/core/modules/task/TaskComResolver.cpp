#include "../../system/Win32.h"
#include "TaskModule.h"
#include <objbase.h>
#include <algorithm>
#include <cwctype>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

namespace wgwc::core::tasks {
    namespace {
        bool Missing(std::uint32_t error) {
            return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
        }

        std::uint32_t ReadRegistry(const std::wstring& path, const wchar_t* name, std::uint32_t view,
                                   std::wstring& value) {
            value.clear();
            HKEY key = nullptr;
            auto error = RegOpenKeyExW(HKEY_CLASSES_ROOT, path.c_str(), 0, KEY_QUERY_VALUE | view, &key);
            if (error != ERROR_SUCCESS)
                return error;

            struct Close {
                HKEY key;

                ~Close() {
                    RegCloseKey(key);
                }
            } close{ key };

            for (int attempt = 0; attempt < 3; ++attempt) {
                DWORD type = 0, size = 0;
                error = RegQueryValueExW(key, name, nullptr, &type, nullptr, &size);
                if (error != ERROR_SUCCESS)
                    return error;
                if ((type != REG_SZ && type != REG_EXPAND_SZ) || size % sizeof(wchar_t) || size > 1024 * 1024)
                    return ERROR_INVALID_DATA;
                std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 1, L'\0');
                error = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(buffer.data()), &size);
                if (error == ERROR_MORE_DATA)
                    continue;
                if (error != ERROR_SUCCESS)
                    return error;
                if ((type != REG_SZ && type != REG_EXPAND_SZ) || size % sizeof(wchar_t) ||
                    size > (buffer.size() - 1) * sizeof(wchar_t))
                    return ERROR_INVALID_DATA;
                value.assign(buffer.data(), size / sizeof(wchar_t));
                while (!value.empty() && value.back() == L'\0')
                    value.pop_back();
                if (value.find(L'\0') != std::wstring::npos) {
                    value.clear();
                    return ERROR_INVALID_DATA;
                }
                return ERROR_SUCCESS;
            }
            return ERROR_RETRY;
        }

        Path ServerCommand(const std::wstring& command) {
            const auto first = command.find_first_not_of(L" \t\r\n");
            if (first == std::wstring::npos)
                return {};
            if (command[first] == L'"') {
                const auto end = command.find(L'"', first + 1);
                if (end != std::wstring::npos)
                    return ResolveFile(command.substr(first + 1, end - first - 1));
                return { command, false };
            }
            const auto text = command.substr(first);
            const auto lower = rules::ToLower(text);
            std::size_t best = std::wstring::npos;
            for (const auto extension : { L".exe", L".com", L".scr" }) {
                std::size_t at = 0;
                while ((at = lower.find(extension, at)) != std::wstring::npos) {
                    const auto end = at + wcslen(extension);
                    if (end == text.size() || iswspace(text[end])) {
                        best = (std::min)(best, end);
                        break;
                    }
                    at = end;
                }
            }
            if (best != std::wstring::npos)
                return ResolveFile(text.substr(0, best));
            const auto space = text.find_first_of(L" \t\r\n");
            return ResolveFile(text.substr(0, space));
        }
    }

    bool NormalizeClassId(const std::wstring& value, std::wstring& normalized) {
        normalized.clear();
        const auto first = value.find_first_not_of(L" \t\r\n");
        if (first == std::wstring::npos)
            return false;
        auto text = value.substr(first, value.find_last_not_of(L" \t\r\n") - first + 1);
        if (text.size() >= 2 && text.front() == L'"' && text.back() == L'"')
            text = text.substr(1, text.size() - 2);
        if (text.size() == 36)
            text = L"{" + text + L"}";
        if (text.size() != 38 || text.front() != L'{' || text.back() != L'}')
            return false;
        for (std::size_t i = 1; i < 37; ++i) {
            if (i == 9 || i == 14 || i == 19 || i == 24) {
                if (text[i] != L'-')
                    return false;
            } else if (!iswxdigit(text[i]))
                return false;
        }
        CLSID id{};
        if (FAILED(CLSIDFromString(text.c_str(), &id)))
            return false;
        wchar_t canonical[40]{};
        if (!StringFromGUID2(id, canonical, 40))
            return false;
        normalized = canonical;
        return true;
    }

    ComResolution ResolveComHandler(const std::wstring& classId, const CollectionContext& context,
                                    const RegistryReader& supplied) {
        ComResolution result;
        auto issue = [&](const wchar_t* code, std::uint32_t native, const std::wstring& path, const wchar_t* message) {
            CollectionIssue item;
            item.source = L"HKCR:CLSID:task-handler";
            item.objectKey = path;
            item.code = code;
            item.nativeCode = native;
            item.message = message;
            item.affectsCompleteness = true;
            result.issues.push_back(std::move(item));
        };
        if (context.ShouldStop())
            return result;
        std::wstring id;
        if (!NormalizeClassId(classId, id)) {
            issue(L"task_com_class_id_invalid", ERROR_INVALID_DATA, classId,
                  L"COM action CLSID is not a GUID; no handler is instantiated.");
            return result;
        }
        const RegistryReader reader = supplied ? supplied : RegistryReader(ReadRegistry);
        const auto root = L"CLSID\\" + id;

        struct Probe {
            const wchar_t* suffix;
            const wchar_t* name;
            const wchar_t* source;
            bool command;
        };

        const Probe probes[] = {
            { L"\\InprocServer32",                  nullptr,             L"com-inproc-server",            false },
            { L"\\LocalServer32",                   L"ServerExecutable", L"com-server-executable",        false },
            { L"\\LocalServer32\\ServerExecutable", nullptr,             L"com-server-executable-subkey", false },
            { L"\\LocalServer32",                   nullptr,             L"com-local-server",             true  }
        };
        const std::uint32_t views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY, 0 };
        const wchar_t* viewNames[] = { L"64", L"32", L"default" };
        for (std::size_t i = 0; i < 3 && !context.ShouldStop(); ++i) {
            for (const auto& probe : probes) {
                if (context.ShouldStop())
                    break;
                const auto key = root + probe.suffix;
                std::wstring value;
                const auto error = reader(key, probe.name, views[i], value);
                if (Missing(error) || (error == ERROR_SUCCESS && value.empty()))
                    continue;
                if (error != ERROR_SUCCESS) {
                    issue(L"task_com_registry_failed", error, key,
                          L"COM registration cannot be read; no lower-priority trusted fallback is assumed.");
                    break;
                }
                Target target;
                target.path = probe.command ? ServerCommand(value) : ResolveFile(value);
                target.source = probe.source;
                target.registryPath = L"HKEY_CLASSES_ROOT\\" + key +
                                      (probe.name ? L" [" + std::wstring(probe.name) + L"]" : L" [(Default)]");
                target.registryView = viewNames[i];
                if (!target.path.stable)
                    issue(L"task_com_path_unresolved", ERROR_INVALID_DATA, key,
                          L"COM registration does not resolve to a stable file path.");
                result.targets.push_back(std::move(target));
                // 每个注册表视图只选择一个优先注册项，并保留视图信息作为证据。
                break;
            }
        }
        if (result.targets.empty() && result.issues.empty() && !context.ShouldStop())
            issue(L"task_com_unresolved", ERROR_FILE_NOT_FOUND, root,
                  L"No supported COM server registration was found in the current caller's HKCR views.");
        if (!context.ShouldStop() && !result.targets.empty() && result.issues.empty())
            result.state = FieldState::Available;
        return result;
    }
}
