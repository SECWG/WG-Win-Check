#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <map>
#include <set>
#include <string>
#include <vector>

// 仅供 GUI 进程操作使用；CLI 命令和自动操作均不调用此辅助函数。
namespace wgwc::core::process::actions {
    struct Target {
        DWORD pid = 0;
        ULONGLONG createdAt = 0;
        std::wstring name;
    };

    struct Result {
        unsigned requested = 0, exited = 0, skipped = 0, failed = 0;
        DWORD firstError = ERROR_SUCCESS;
    };

    using ProtectionCheck = bool (*)(DWORD, const std::wstring&);

    class Handle {
    public:
        explicit Handle(HANDLE value = nullptr) : value_(value) {}

        ~Handle() {
            if (valid())
                CloseHandle(value_);
        }

        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;

        bool valid() const {
            return value_ && value_ != INVALID_HANDLE_VALUE;
        }

        HANDLE get() const {
            return value_;
        }

    private:
        HANDLE value_;
    };

    inline ULONGLONG CreationTime(HANDLE handle, DWORD& error) {
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(handle, &created, &exited, &kernel, &user)) {
            error = GetLastError();
            if (!error)
                error = ERROR_GEN_FAILURE;
            return 0;
        }
        const auto value = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        if (!value)
            error = ERROR_INVALID_DATA;
        return value;
    }

    inline void RecordError(Result& result, DWORD error) {
        if (!error)
            error = ERROR_GEN_FAILURE;
        if (!result.firstError)
            result.firstError = error;
        if (error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_FOUND)
            ++result.exited;
        else if (error == ERROR_INVALID_DATA)
            ++result.skipped;
        else
            ++result.failed;
    }

    inline HANDLE OpenVerified(const Target& target, DWORD& error) {
        error = ERROR_SUCCESS;
        if (!target.createdAt) {
            error = ERROR_INVALID_DATA;
            return nullptr;
        }
        HANDLE handle =
            OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, target.pid);
        if (!handle) {
            error = GetLastError();
            if (!error)
                error = ERROR_GEN_FAILURE;
            return nullptr;
        }
        const auto created = CreationTime(handle, error);
        if (created && created != target.createdAt)
            error = ERROR_INVALID_DATA;
        if (!error) {
            const DWORD state = WaitForSingleObject(handle, 0);
            if (state == WAIT_OBJECT_0)
                error = ERROR_NOT_FOUND;
            else if (state != WAIT_TIMEOUT) {
                error = GetLastError();
                if (!error)
                    error = ERROR_GEN_FAILURE;
            }
        }
        if (error) {
            CloseHandle(handle);
            return nullptr;
        }
        return handle;
    }

    inline Result Terminate(const Target& root, bool tree, ProtectionCheck protectedProcess) {
        Result result;
        if (protectedProcess && protectedProcess(root.pid, root.name)) {
            result.skipped = 1;
            result.firstError = ERROR_ACCESS_DENIED;
            return result;
        }
        DWORD error = 0;
        Handle rootHandle(OpenVerified(root, error));
        if (!rootHandle.valid()) {
            RecordError(result, error);
            return result;
        }
        std::vector<Target> targets{ root };
        if (tree) {
            // 保守排除枚举开始后创建的进程，避免复用的 PID
            // 继承原进程的父子关系。
            FILETIME boundary{};
            GetSystemTimeAsFileTime(&boundary);
            const ULONGLONG snapshotStarted =
                (static_cast<ULONGLONG>(boundary.dwHighDateTime) << 32) | boundary.dwLowDateTime;
            Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            if (!snapshot.valid()) {
                result.failed = 1;
                result.firstError = GetLastError();
                return result;
            }
            std::map<DWORD, std::vector<Target>> children;
            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            if (!Process32FirstW(snapshot.get(), &entry)) {
                result.failed = 1;
                result.firstError = GetLastError();
                return result;
            }
            bool rootPresent = false;
            do {
                if (entry.th32ProcessID == root.pid)
                    rootPresent = true;
                children[entry.th32ParentProcessID].push_back({ entry.th32ProcessID, 0, entry.szExeFile });
            } while (Process32NextW(snapshot.get(), &entry));
            error = GetLastError();
            if (error != ERROR_NO_MORE_FILES || !rootPresent) {
                result.failed = 1;
                result.firstError = error == ERROR_NO_MORE_FILES ? ERROR_NOT_FOUND : error;
                return result;
            }
            std::set<DWORD> visited{ root.pid };
            for (std::size_t i = 0; i < targets.size(); ++i) {
                const DWORD parentPid = targets[i].pid;
                const ULONGLONG parentCreated = targets[i].createdAt;
                const auto found = children.find(parentPid);
                if (found == children.end())
                    continue;
                for (auto child : found->second) {
                    if (!visited.insert(child.pid).second ||
                        (protectedProcess && protectedProcess(child.pid, child.name))) {
                        ++result.skipped;
                        continue;
                    }
                    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, child.pid));
                    if (!process.valid()) {
                        RecordError(result, GetLastError());
                        continue;
                    }
                    const DWORD state = WaitForSingleObject(process.get(), 0);
                    if (state == WAIT_OBJECT_0) {
                        ++result.exited;
                        continue;
                    }
                    if (state != WAIT_TIMEOUT) {
                        RecordError(result, GetLastError());
                        continue;
                    }
                    error = 0;
                    child.createdAt = CreationTime(process.get(), error);
                    if (error) {
                        RecordError(result, error);
                        continue;
                    }
                    if (child.createdAt < parentCreated || child.createdAt > snapshotStarted) {
                        RecordError(result, ERROR_INVALID_DATA);
                        continue;
                    }
                    targets.push_back(std::move(child));
                }
            }
        }
        // 先处理子进程；每次操作前重新打开并校验该子进程，
        // 根进程则在整个操作期间持有已校验的句柄。
        for (std::size_t i = targets.size(); i-- > 0;) {
            const auto& target = targets[i];
            if (protectedProcess && protectedProcess(target.pid, target.name)) {
                ++result.skipped;
                continue;
            }
            error = 0;
            Handle childHandle(i ? OpenVerified(target, error) : nullptr);
            HANDLE handle = i ? childHandle.get() : rootHandle.get();
            if (!handle) {
                RecordError(result, error);
                continue;
            }
            if (WaitForSingleObject(handle, 0) == WAIT_OBJECT_0) {
                ++result.exited;
                continue;
            }
            if (TerminateProcess(handle, 0))
                ++result.requested;
            else {
                error = GetLastError();
                if (WaitForSingleObject(handle, 0) == WAIT_OBJECT_0)
                    ++result.exited;
                else
                    RecordError(result, error);
            }
        }
        return result;
    }
}
