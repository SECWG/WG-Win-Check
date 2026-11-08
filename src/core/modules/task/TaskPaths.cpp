#include "../../system/Win32.h"
#include "TaskModule.h"
#include <taskschd.h>
#include <algorithm>
#include <cwctype>

namespace wgwc::core::tasks {
    namespace {
        std::wstring Trim(const std::wstring& value) {
            const auto first = value.find_first_not_of(L" \t\r\n");
            if (first == std::wstring::npos)
                return L"";
            return value.substr(first, value.find_last_not_of(L" \t\r\n") - first + 1);
        }

        std::wstring Expanded(const std::wstring& value) {
            auto path = Trim(value);
            if (path.size() >= 2 &&
                ((path.front() == L'"' && path.back() == L'"') || (path.front() == L'\'' && path.back() == L'\'')))
                path = path.substr(1, path.size() - 2);
            path = Trim(files::ExpandEnvironment(path));
            if (path.compare(0, 4, L"\\??\\") == 0)
                path.erase(0, 4);
            wchar_t windows[MAX_PATH]{};
            const auto length = GetWindowsDirectoryW(windows, MAX_PATH);
            if (length && length < MAX_PATH && rules::ToLower(path).compare(0, 12, L"\\systemroot\\") == 0)
                path = std::wstring(windows) + path.substr(11);
            return path;
        }

        bool Absolute(const std::wstring& path) {
            return (path.size() >= 3 && iswalpha(path[0]) && path[1] == L':' &&
                    (path[2] == L'\\' || path[2] == L'/')) ||
                   (path.size() > 2 && path[0] == L'\\' && path[1] == L'\\');
        }

        bool RelatedExtension(const std::wstring& path) {
            const auto dot = path.find_last_of(L'.');
            if (dot == std::wstring::npos)
                return false;
            const auto extension = rules::ToLower(path.substr(dot));
            for (const auto candidate : { L".exe", L".dll", L".ps1", L".vbs", L".js", L".wsf", L".bat", L".cmd",
                                          L".hta", L".lnk", L".scr", L".com" })
                if (extension == candidate)
                    return true;
            return false;
        }

        bool Separator(wchar_t c) {
            return iswspace(c) || c == L'&' || c == L'|' || c == L';' || c == L'(' || c == L')' || c == L'<' ||
                   c == L'>';
        }

        bool Scheduled(std::uint32_t type) {
            return type == TASK_TRIGGER_TIME || type == TASK_TRIGGER_DAILY || type == TASK_TRIGGER_WEEKLY ||
                   type == TASK_TRIGGER_MONTHLY || type == TASK_TRIGGER_MONTHLYDOW;
        }

        bool TriggerMatches(std::uint32_t type, const std::wstring& kind) {
            if (kind == L"logon")
                return type == TASK_TRIGGER_LOGON;
            if (kind == L"boot")
                return type == TASK_TRIGGER_BOOT;
            if (kind == L"scheduled")
                return Scheduled(type);
            if (kind == L"event")
                return type == TASK_TRIGGER_EVENT;
            if (kind == L"idle")
                return type == TASK_TRIGGER_IDLE;
            if (kind == L"other")
                return type != TASK_TRIGGER_LOGON && type != TASK_TRIGGER_BOOT && !Scheduled(type) &&
                       type != TASK_TRIGGER_EVENT && type != TASK_TRIGGER_IDLE;
            return kind == L"all";
        }

        void Append(std::wstring& summary, const std::wstring& text) {
            if (text.empty())
                return;
            if (!summary.empty())
                summary += L" | ";
            summary += text;
        }
    }

    Path ResolveFile(const std::wstring& value, const std::wstring& workingDirectory) {
        Path result;
        result.value = Expanded(value);
        auto& path = result.value;
        if (path.empty() || path.size() > 32767 || path.find(L'\0') != std::wstring::npos ||
            path.find(L'%') != std::wstring::npos || path.find(L"://") != std::wstring::npos ||
            path.compare(0, 4, L"\\\\.\\") == 0 || path.find_first_of(L"\"|<>") != std::wstring::npos)
            return result;
        if (!Absolute(path)) {
            // 盘符相对路径和根目录相对路径需要结合执行上下文解析。
            if (path.find(L':') != std::wstring::npos || path.front() == L'\\' || path.front() == L'/')
                return result;
            if (!workingDirectory.empty()) {
                const auto base = Expanded(workingDirectory);
                if (!Absolute(base) || base.find(L'%') != std::wstring::npos ||
                    base.find_first_of(L"\"|<>") != std::wstring::npos)
                    return result;
                path = base + ((base.back() == L'\\' || base.back() == L'/') ? L"" : L"\\") + path;
            } else if (path.find_first_of(L"\\/") == std::wstring::npos) {
                // 未显式指定工作目录时，只解析实际存在的系统文件。
                wchar_t system[MAX_PATH]{};
                const auto length = GetSystemDirectoryW(system, MAX_PATH);
                if (length && length < MAX_PATH) {
                    auto candidate = std::wstring(system) + L"\\" + path;
                    if (rules::IsExistingFile(candidate))
                        path = candidate;
                    else if (path.find(L'.') == std::wstring::npos && rules::IsExistingFile(candidate + L".exe"))
                        path = candidate + L".exe";
                }
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

    bool IsCommandWrapper(const std::wstring& value) {
        const auto path = rules::ToLower(Expanded(value));
        const auto slash = path.find_last_of(L"\\/");
        const auto name = slash == std::wstring::npos ? path : path.substr(slash + 1);
        for (const auto wrapper : { L"cmd", L"cmd.exe", L"%comspec%", L"powershell", L"powershell.exe", L"pwsh",
                                    L"pwsh.exe", L"wscript.exe", L"cscript.exe", L"rundll32.exe", L"mshta.exe" })
            if (name == wrapper)
                return true;
        return false;
    }

    std::vector<Target> ResolveExec(const Action& action) {
        std::vector<Target> result;
        if (action.execState != FieldState::Available)
            return result;
        const auto workingDirectory =
            action.workingDirectoryState == FieldState::Available ? action.workingDirectory : L"";
        const bool wrapper = IsCommandWrapper(action.execPath);
        auto add = [&](const std::wstring& candidate, const wchar_t* source) {
            if (candidate.empty())
                return;
            Target target;
            target.path = ResolveFile(candidate, workingDirectory);
            target.source = source;
            // 工作目录读取失败时，不能改用采集器当前目录或系统目录查找。
            if (action.workingDirectoryState != FieldState::Available && !Absolute(Expanded(candidate)))
                target.path.stable = false;
            for (const auto& old : result)
                if (_wcsicmp(old.path.value.c_str(), target.path.value.c_str()) == 0)
                    return;
            result.push_back(std::move(target));
        };
        if (!wrapper) {
            add(action.execPath, L"exec-path");
            return result;
        }
        if (action.argumentsState == FieldState::Available) {
            const auto text = files::ExpandEnvironment(action.arguments);
            std::size_t offset = 0;
            while (offset < text.size()) {
                while (offset < text.size() && Separator(text[offset]))
                    ++offset;
                std::wstring token;
                wchar_t quote = 0;
                while (offset < text.size()) {
                    const auto c = text[offset];
                    if (quote) {
                        ++offset;
                        if (c == quote)
                            quote = 0;
                        else
                            token += c;
                    } else if (c == L'"' || c == L'\'') {
                        quote = c;
                        ++offset;
                    } else if (Separator(c))
                        break;
                    else {
                        token += c;
                        ++offset;
                    }
                }
                if (offset < text.size())
                    ++offset;
                if (quote || token.empty() || token.find(L"://") != std::wstring::npos)
                    continue;
                // PowerShell 支持 -File:path；rundll32 会在路径后附加 ,EntryPoint。
                const auto lower = rules::ToLower(token);
                if (lower.compare(0, 6, L"-file:") == 0)
                    token.erase(0, 6);
                const auto comma = token.find(L',');
                if (comma != std::wstring::npos)
                    token.resize(comma);
                if (!RelatedExtension(token) || IsCommandWrapper(token))
                    continue;
                add(token, L"exec-arguments");
            }
        }
        if (result.empty())
            add(action.execPath, L"exec-fallback");
        return result;
    }

    const wchar_t* StateName(std::uint32_t state) {
        switch (state) {
        case TASK_STATE_DISABLED:
            return L"disabled";
        case TASK_STATE_QUEUED:
            return L"queued";
        case TASK_STATE_READY:
            return L"ready";
        case TASK_STATE_RUNNING:
            return L"running";
        default:
            return L"unknown";
        }
    }

    const wchar_t* ActionName(std::uint32_t type) {
        switch (type) {
        case TASK_ACTION_EXEC:
            return L"exec";
        case TASK_ACTION_COM_HANDLER:
            return L"com-handler";
        case TASK_ACTION_SEND_EMAIL:
            return L"send-email";
        case TASK_ACTION_SHOW_MESSAGE:
            return L"show-message";
        default:
            return L"other";
        }
    }

    const wchar_t* TriggerName(std::uint32_t type) {
        switch (type) {
        case TASK_TRIGGER_EVENT:
            return L"event";
        case TASK_TRIGGER_TIME:
            return L"time";
        case TASK_TRIGGER_DAILY:
            return L"daily";
        case TASK_TRIGGER_WEEKLY:
            return L"weekly";
        case TASK_TRIGGER_MONTHLY:
            return L"monthly";
        case TASK_TRIGGER_MONTHLYDOW:
            return L"monthly-day-of-week";
        case TASK_TRIGGER_IDLE:
            return L"idle";
        case TASK_TRIGGER_REGISTRATION:
            return L"registration";
        case TASK_TRIGGER_BOOT:
            return L"boot";
        case TASK_TRIGGER_LOGON:
            return L"logon";
        case TASK_TRIGGER_SESSION_STATE_CHANGE:
            return L"session-state-change";
        default:
            return L"other";
        }
    }

    const wchar_t* TriggerDisplay(std::uint32_t type) {
        switch (type) {
        case TASK_TRIGGER_EVENT:
            return L"事件触发";
        case TASK_TRIGGER_TIME:
            return L"定时";
        case TASK_TRIGGER_DAILY:
            return L"每日";
        case TASK_TRIGGER_WEEKLY:
            return L"每周";
        case TASK_TRIGGER_MONTHLY:
            return L"每月";
        case TASK_TRIGGER_MONTHLYDOW:
            return L"每月(周)";
        case TASK_TRIGGER_IDLE:
            return L"空闲时";
        case TASK_TRIGGER_REGISTRATION:
            return L"注册时";
        case TASK_TRIGGER_BOOT:
            return L"启动时";
        case TASK_TRIGGER_LOGON:
            return L"登录时";
        case TASK_TRIGGER_SESSION_STATE_CHANGE:
            return L"会话变化";
        default:
            return L"其他";
        }
    }

    bool IsMicrosoftGroup(const Record& record) {
        // 保留现有的任务路径及作者分类，不将其视为发布者可信校验。
        return record.path.find(L"\\Microsoft\\") != std::wstring::npos ||
               rules::ToLower(record.author).find(L"microsoft") != std::wstring::npos;
    }

    bool HasTrigger(const Record& record, const std::wstring& kind, bool enabledOnly) {
        for (const auto& trigger : record.triggers) {
            if (trigger.typeState != FieldState::Available)
                continue;
            if (enabledOnly && (trigger.enabledState != FieldState::Available || !trigger.enabled))
                continue;
            if (TriggerMatches(trigger.type, kind))
                return true;
        }
        return false;
    }

    bool Matches(const Record& record, const Filter& filter) {
        if (!filter.name.empty() && _wcsicmp(record.name.c_str(), filter.name.c_str()) != 0)
            return false;
        if (!filter.path.empty() &&
            (record.pathState != FieldState::Available || _wcsicmp(record.path.c_str(), filter.path.c_str()) != 0))
            return false;
        const bool microsoft = IsMicrosoftGroup(record);
        if ((filter.vendor == L"microsoft" && !microsoft) || (filter.vendor == L"third-party" && microsoft))
            return false;
        if (filter.state != L"all") {
            if (filter.state == L"unknown") {
                if (record.stateState == FieldState::Available && record.state != TASK_STATE_UNKNOWN)
                    return false;
            } else if (record.stateState != FieldState::Available || filter.state != StateName(record.state))
                return false;
        }
        if (filter.trigger != L"all") {
            if (filter.trigger == L"none")
                return record.triggersState == FieldState::Available && record.triggers.empty();
            if (!HasTrigger(record, filter.trigger))
                return false;
        }
        return true;
    }

    std::wstring ActionSummary(const Record& record) {
        std::wstring text;
        for (const auto& action : record.actions) {
            if (action.typeState != FieldState::Available)
                Append(text, L"Action[" + std::to_wstring(action.index) + L"]: 未知");
            else if (action.type == TASK_ACTION_EXEC)
                Append(text, L"Exec: " + action.execPath + (action.arguments.empty() ? L"" : L" " + action.arguments));
            else if (action.type == TASK_ACTION_COM_HANDLER)
                Append(text, L"COM:" + action.classId);
            else
                Append(text, ActionName(action.type));
        }
        return text;
    }

    std::wstring TriggerSummary(const Record& record) {
        if (record.triggers.empty())
            return record.triggersState == FieldState::Available ? L"无触发器" : L"未知";
        std::vector<std::wstring> names;
        std::wstring text;
        for (const auto& trigger : record.triggers) {
            std::wstring name = trigger.typeState == FieldState::Available ? TriggerDisplay(trigger.type) : L"未知";
            if (trigger.enabledState == FieldState::Available && !trigger.enabled)
                name += L"(已禁用)";
            if (std::find(names.begin(), names.end(), name) == names.end()) {
                names.push_back(name);
                Append(text, name);
            }
        }
        return text;
    }
}
