#include "../../system/Win32.h"
#include "ProcessCollector.h"
#include <tlhelp32.h>
#include <winternl.h>
#include <map>
#include <cwchar>

namespace wgwc::core::process {
    namespace {

        typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(HANDLE ProcessHandle,
                                                               PROCESSINFOCLASS ProcessInformationClass,
                                                               PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                               PULONG ReturnLength);

#define ProcessCommandLineInformation ((PROCESSINFOCLASS)60)

        typedef NTSTATUS(NTAPI* PFN_NtWow64QueryInformationProcess64)(HANDLE ProcessHandle,
                                                                      PROCESSINFOCLASS ProcessInformationClass,
                                                                      PVOID ProcessInformation,
                                                                      ULONG ProcessInformationLength,
                                                                      PULONG ReturnLength);

        typedef NTSTATUS(NTAPI* PFN_NtWow64ReadVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer,
                                                                ULONG64 Size, PULONG64 NumberOfBytesRead);

        struct PROCESS_BASIC_INFORMATION64 {
            NTSTATUS ExitStatus;
            ULONG64 PebBaseAddress;
            ULONG64 AffinityMask;
            LONG BasePriority;
            ULONG64 UniqueProcessId;
            ULONG64 InheritedFromUniqueProcessId;
        };

        struct UNICODE_STRING64 {
            USHORT Length;
            USHORT MaximumLength;
            ULONG64 Buffer;
        };

        struct RTL_USER_PROCESS_PARAMETERS64 {
            BYTE Reserved1[16];
            ULONG64 Reserved2[10];
            UNICODE_STRING64 ImagePathName;
            UNICODE_STRING64 CommandLine;
        };

        struct PEB64 {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[21];
            ULONG64 LoaderData;
            ULONG64 ProcessParameters;
        };

        static bool Is64BitProcess(HANDLE hProcess) {
            BOOL isWow64 = FALSE;
            if (IsWow64Process(hProcess, &isWow64)) {
                return !isWow64;
            }
            return false;
        }

        static bool IsRunningUnderWow64() {
            BOOL isWow64 = FALSE;
            IsWow64Process(GetCurrentProcess(), &isWow64);
            return isWow64 != FALSE;
        }

        std::wstring GetProcessPath(HANDLE process) {
            if (!process)
                return L"";
            wchar_t initial[MAX_PATH]{};
            DWORD length = MAX_PATH;
            if (QueryFullProcessImageNameW(process, 0, initial, &length))
                return std::wstring(initial, length);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                return L"";

            constexpr std::size_t maxPathChars = 32768;
            std::vector<wchar_t> path(MAX_PATH * 2);
            for (;;) {
                length = static_cast<DWORD>(path.size());
                if (QueryFullProcessImageNameW(process, 0, path.data(), &length))
                    return std::wstring(path.data(), length);
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || path.size() == maxPathChars)
                    return L"";
                const auto next = path.size() * 2;
                path.resize(next < maxPathChars ? next : maxPathChars);
            }
        }

        using AccountCache = std::map<std::vector<BYTE>, std::wstring>;

        std::wstring GetProcessUser(HANDLE process, AccountCache& accounts) {
            if (!process)
                return L"";
            HANDLE rawToken = nullptr;
            if (!OpenProcessToken(process, TOKEN_QUERY, &rawToken))
                return L"";
            UniqueHandle token(rawToken);
            DWORD tokenInfoLen = 0;
            GetTokenInformation(token.get(), TokenUser, nullptr, 0, &tokenInfoLen);
            if (!tokenInfoLen)
                return L"";
            std::vector<BYTE> tokenInfo(tokenInfoLen);
            if (!GetTokenInformation(token.get(), TokenUser, tokenInfo.data(), tokenInfoLen, &tokenInfoLen))
                return L"";
            const auto* user = reinterpret_cast<const TOKEN_USER*>(tokenInfo.data());
            if (!IsValidSid(user->User.Sid))
                return L"";
            const auto* sid = static_cast<const BYTE*>(user->User.Sid);
            std::vector<BYTE> key(sid, sid + GetLengthSid(user->User.Sid));
            const auto cached = accounts.find(key);
            if (cached != accounts.end())
                return cached->second;

            wchar_t userName[256]{}, domainName[256]{};
            DWORD userNameLen = 256, domainNameLen = 256;
            SID_NAME_USE sidType{};
            std::wstring name;
            if (LookupAccountSidW(nullptr, user->User.Sid, userName, &userNameLen, domainName, &domainNameLen,
                                  &sidType)) {
                name = domainName[0] ? std::wstring(domainName) + L"\\" + userName : std::wstring(userName);
            } else {
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !userNameLen || userNameLen > 32768 ||
                    domainNameLen > 32768)
                    return L"";
                std::vector<wchar_t> largeName(userNameLen);
                std::vector<wchar_t> largeDomain(domainNameLen ? domainNameLen : 1);
                domainNameLen = static_cast<DWORD>(largeDomain.size());
                if (!LookupAccountSidW(nullptr, user->User.Sid, largeName.data(), &userNameLen, largeDomain.data(),
                                       &domainNameLen, &sidType))
                    return L"";
                name = largeDomain[0] ? std::wstring(largeDomain.data()) + L"\\" + largeName.data()
                                      : std::wstring(largeName.data());
            }
            // 成功的 SID 解析结果仅在本次采集中复用，不缓存失败结果。
            if (!name.empty())
                accounts.emplace(std::move(key), name);
            return name;
        }

        std::wstring GetProcessStartTime(HANDLE process, std::uint64_t& createdAt) {
            if (!process)
                return L"";
            FILETIME createTime{}, exitTime{}, kernelTime{}, userTime{};
            if (!GetProcessTimes(process, &createTime, &exitTime, &kernelTime, &userTime))
                return L"";
            createdAt = (static_cast<std::uint64_t>(createTime.dwHighDateTime) << 32) | createTime.dwLowDateTime;
            FILETIME localTime{};
            SYSTEMTIME st{};
            if (!FileTimeToLocalFileTime(&createTime, &localTime) || !FileTimeToSystemTime(&localTime, &st))
                return L"";
            wchar_t buf[64];
            swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                       st.wSecond);
            return buf;
        }

        std::wstring GetParentProcessName(DWORD ppid, const std::map<DWORD, std::wstring>& processNames) {
            const auto found = processNames.find(ppid);
            if (found != processNames.end())
                return found->second;
            // 重新获取快照可能将复用的父进程 PID 关联到无关进程。
            return ppid == 4 ? L"System" : L"";
        }

        // 查询返回的定长字符串必须指向本次分配的输出缓冲区。
        bool QueryCommandLine(HANDLE process, PFN_NtQueryInformationProcess query, std::wstring& value) {
            value.clear();
            constexpr ULONG maxBufferBytes = static_cast<ULONG>(sizeof(UNICODE_STRING)) + 0x10000;
            constexpr NTSTATUS lengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
            constexpr NTSTATUS bufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
            constexpr NTSTATUS bufferOverflow = static_cast<NTSTATUS>(0x80000005L);
            std::vector<BYTE> buffer(4096);
            for (unsigned attempt = 0; attempt < 4; ++attempt) {
                ULONG returned = 0;
                const NTSTATUS status = query(process, ProcessCommandLineInformation, buffer.data(),
                                              static_cast<ULONG>(buffer.size()), &returned);
                if (status == 0) {
                    if (returned < sizeof(UNICODE_STRING) || returned > buffer.size())
                        return false;
                    const auto* text = reinterpret_cast<const UNICODE_STRING*>(buffer.data());
                    if (text->Length % sizeof(wchar_t) || text->Length > text->MaximumLength)
                        return false;
                    if (!text->Length)
                        return true;
                    const auto base = reinterpret_cast<std::uintptr_t>(buffer.data());
                    const auto address = reinterpret_cast<std::uintptr_t>(text->Buffer);
                    if (address < base || address - base < sizeof(UNICODE_STRING) || address - base > returned ||
                        address % alignof(wchar_t) || text->Length > returned - (address - base))
                        return false;
                    value.assign(text->Buffer, text->Length / sizeof(wchar_t));
                    return true;
                }
                if ((status != lengthMismatch && status != bufferTooSmall && status != bufferOverflow) ||
                    returned <= buffer.size() || returned > maxBufferBytes)
                    return false;
                buffer.resize(returned);
            }
            return false;
        }

        std::wstring GetProcessCommandLine(DWORD pid, HANDLE process, FieldState& state) {
            state = FieldState::Unknown;
            if (pid == 0 || pid == 4) {
                state = FieldState::NotApplicable;
                return L"";
            }
            if (!process)
                return L"";
            static const auto query = [] {
                const HMODULE module = GetModuleHandleW(L"ntdll.dll");
                return module ? reinterpret_cast<PFN_NtQueryInformationProcess>(
                                    GetProcAddress(module, "NtQueryInformationProcess"))
                              : nullptr;
            }();
            if (!query)
                return L"";
            std::wstring value;
            if (QueryCommandLine(process, query, value)) {
                state = FieldState::Available;
                return value;
            }

            UniqueHandle readable(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
            if (!readable.valid())
                return L"";
            // 不能将同一 PID 对应的新进程信息混入已采集的旧进程元数据。
            FILETIME originalCreated{}, fallbackCreated{}, exitTime{}, kernelTime{}, userTime{};
            if (!GetProcessTimes(process, &originalCreated, &exitTime, &kernelTime, &userTime) ||
                !GetProcessTimes(readable.get(), &fallbackCreated, &exitTime, &kernelTime, &userTime) ||
                CompareFileTime(&originalCreated, &fallbackCreated) != 0)
                return L"";
            const HANDLE hProc = readable.get();
            if (IsRunningUnderWow64() && Is64BitProcess(hProc)) {
                static const auto query64 = [] {
                    const HMODULE module = GetModuleHandleW(L"ntdll.dll");
                    return module ? reinterpret_cast<PFN_NtWow64QueryInformationProcess64>(
                                        GetProcAddress(module, "NtWow64QueryInformationProcess64"))
                                  : nullptr;
                }();
                static const auto read64 = [] {
                    const HMODULE module = GetModuleHandleW(L"ntdll.dll");
                    return module ? reinterpret_cast<PFN_NtWow64ReadVirtualMemory64>(
                                        GetProcAddress(module, "NtWow64ReadVirtualMemory64"))
                                  : nullptr;
                }();
                if (!query64 || !read64)
                    return L"";
                PROCESS_BASIC_INFORMATION64 basic{};
                ULONG returned = 0;
                if (query64(hProc, ProcessBasicInformation, &basic, sizeof(basic), &returned) != 0 ||
                    !basic.PebBaseAddress)
                    return L"";
                PEB64 peb{};
                ULONG64 bytesRead = 0;
                if (read64(hProc, reinterpret_cast<PVOID64>(basic.PebBaseAddress), &peb, sizeof(peb), &bytesRead) !=
                        0 ||
                    bytesRead != sizeof(peb))
                    return L"";
                RTL_USER_PROCESS_PARAMETERS64 params{};
                if (read64(hProc, reinterpret_cast<PVOID64>(peb.ProcessParameters), &params, sizeof(params),
                           &bytesRead) != 0 ||
                    bytesRead != sizeof(params))
                    return L"";
                const auto& command = params.CommandLine;
                if (command.Length % sizeof(wchar_t) || command.Length > command.MaximumLength)
                    return L"";
                if (!command.Length) {
                    state = FieldState::Available;
                    return L"";
                }
                if (!command.Buffer)
                    return L"";
                std::vector<wchar_t> buffer(command.Length / sizeof(wchar_t));
                if (read64(hProc, reinterpret_cast<PVOID64>(command.Buffer), buffer.data(), command.Length,
                           &bytesRead) != 0 ||
                    bytesRead != command.Length)
                    return L"";
                state = FieldState::Available;
                return std::wstring(buffer.data(), buffer.size());
            }

            PROCESS_BASIC_INFORMATION basic{};
            ULONG returned = 0;
            if (query(hProc, ProcessBasicInformation, &basic, sizeof(basic), &returned) != 0 || !basic.PebBaseAddress)
                return L"";
            PEB peb{};
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(hProc, basic.PebBaseAddress, &peb, sizeof(peb), &bytesRead) ||
                bytesRead != sizeof(peb))
                return L"";
            RTL_USER_PROCESS_PARAMETERS params{};
            if (!ReadProcessMemory(hProc, peb.ProcessParameters, &params, sizeof(params), &bytesRead) ||
                bytesRead != sizeof(params))
                return L"";
            const auto& command = params.CommandLine;
            if (command.Length % sizeof(wchar_t) || command.Length > command.MaximumLength)
                return L"";
            if (!command.Length) {
                state = FieldState::Available;
                return L"";
            }
            if (!command.Buffer)
                return L"";
            std::vector<wchar_t> buffer(command.Length / sizeof(wchar_t));
            if (!ReadProcessMemory(hProc, command.Buffer, buffer.data(), command.Length, &bytesRead) ||
                bytesRead != command.Length)
                return L"";
            state = FieldState::Available;
            return std::wstring(buffer.data(), buffer.size());
        }

    }

    CollectionResult<Metadata> CollectMetadata(const CollectionContext& context, const MetadataObserver& observer,
                                               std::optional<std::uint32_t> targetPid) {
        CollectionResult<Metadata> result;
        result.status = CollectionStatus::Complete;
        result.startedAt = UtcNow();
        result.sources = { { L"toolhelp.process_names" }, { L"toolhelp.processes" } };
        auto finish = [&]() {
            result.collected = result.records.size();
            result.finishedAt = UtcNow();
        };
        auto stopped = [&](std::size_t source) {
            if (!context.ShouldStop())
                return false;
            result.status = context.StopStatus();
            result.sources[source].status = StatusName(result.status);
            result.issues.push_back({ result.sources[source].source, L"",
                                      context.IsCancelled() ? L"CANCELLED" : L"TIMED_OUT", 0,
                                      L"Process enumeration stopped before completion.", true });
            finish();
            return true;
        };
        auto failed = [&](std::size_t source, DWORD code, bool fatal) {
            result.sources[source].status = L"failed";
            result.sources[source].nativeCode = code;
            result.status = fatal ? CollectionStatus::Failed : CollectionStatus::Partial;
            result.issues.push_back({ result.sources[source].source, L"", L"PROCESS_SNAPSHOT_FAILED", code,
                                      L"Unable to complete the process snapshot.", true });
        };
        if (stopped(0))
            return result;
        std::map<DWORD, std::wstring> processNames;
        AccountCache accounts;
        UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot.valid()) {
            failed(0, GetLastError(), true);
            finish();
            return result;
        }
        {
            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            BOOL hasEntry = Process32FirstW(snapshot.get(), &entry);
            if (!hasEntry && GetLastError() != ERROR_NO_MORE_FILES) {
                failed(0, GetLastError(), false);
            } else {
                result.sources[0].status = L"complete";
                while (hasEntry) {
                    if (stopped(0))
                        return result;
                    processNames[entry.th32ProcessID] = entry.szExeFile;
                    ++result.sources[0].collected;
                    hasEntry = Process32NextW(snapshot.get(), &entry);
                    if (!hasEntry) {
                        const DWORD error = GetLastError();
                        if (error != ERROR_NO_MORE_FILES)
                            failed(0, error, false);
                    }
                }
            }
        }
        if (stopped(1))
            return result;
        // 重新遍历同一份快照，确保父进程名称和进程记录来自同一次枚举。
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        BOOL hasEntry = Process32FirstW(snapshot.get(), &entry);
        if (!hasEntry) {
            const DWORD error = GetLastError();
            if (error != ERROR_NO_MORE_FILES)
                failed(1, error, true);
            else
                result.sources[1].status = L"complete";
            finish();
            return result;
        }
        result.sources[1].status = L"complete";
        while (hasEntry) {
            if (stopped(1))
                return result;
            if (targetPid && entry.th32ProcessID != *targetPid) {
                hasEntry = Process32NextW(snapshot.get(), &entry);
                if (!hasEntry) {
                    const DWORD error = GetLastError();
                    if (error != ERROR_NO_MORE_FILES)
                        failed(1, error, result.records.empty());
                }
                continue;
            }
            if (result.records.size() >= context.maxRecords) {
                result.status = CollectionStatus::Partial;
                result.collectionTruncated = true;
                result.sources[1].status = L"partial";
                result.issues.push_back({ L"toolhelp.processes", L"", L"RECORD_BUDGET", 0,
                                          L"Process collection reached the configured record budget.", true });
                break;
            }
            Metadata record;
            record.pid = entry.th32ProcessID;
            record.ppid = entry.th32ParentProcessID;
            record.threadCount = entry.cntThreads;
            record.name = entry.szExeFile;
            record.observedAt = UtcNow();
            const bool system = record.pid == 0 || record.pid == 4;
            if (system) {
                record.user = L"SYSTEM";
                record.commandLineState = FieldState::NotApplicable;
            } else {
                UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, record.pid));
                record.path = GetProcessPath(process.get());
                record.commandLine = GetProcessCommandLine(record.pid, process.get(), record.commandLineState);
                record.user = GetProcessUser(process.get(), accounts);
                record.startTimeLocal = GetProcessStartTime(process.get(), record.createdAt);
            }
            record.parentName = GetParentProcessName(record.ppid, processNames);
            record.pathState = system ? FieldState::NotApplicable
                                      : (record.path.empty() ? FieldState::Unknown : FieldState::Available);
            record.userState = record.user.empty() ? FieldState::Unknown : FieldState::Available;
            record.createdAtState =
                system ? FieldState::NotApplicable : (record.createdAt ? FieldState::Available : FieldState::Unknown);
            if (record.pathState == FieldState::Unknown || record.commandLineState == FieldState::Unknown ||
                record.userState == FieldState::Unknown || record.createdAtState == FieldState::Unknown) {
                result.issues.push_back(
                    { L"process.metadata", std::to_wstring(record.pid), L"PROCESS_METADATA_UNAVAILABLE", 0,
                      L"Some optional metadata is unavailable; field states identify the missing values.", false });
            }
            if (observer)
                observer(record);
            result.records.push_back(std::move(record));
            ++result.sources[1].collected;
            if (context.progress)
                context.progress(L"process", result.records.size());
            hasEntry = Process32NextW(snapshot.get(), &entry);
            if (!hasEntry) {
                const DWORD error = GetLastError();
                if (error != ERROR_NO_MORE_FILES) {
                    failed(1, error, false);
                    result.sources[1].status = L"partial";
                }
            }
        }
        if (context.ShouldStop()) {
            stopped(1);
            return result;
        }
        finish();
        return result;
    }
}
