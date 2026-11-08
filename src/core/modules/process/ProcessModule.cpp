#include "../../system/Win32.h"
#include "ProcessModule.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace wgwc::core::process {
    CollectionResult<ProcessRecord> CollectProcesses(const ProcessOptions& options, const CollectionContext& context) {
        CollectionResult<ProcessRecord> result;
        files::EvidenceCache cache;
        const auto locations = QuerySystemLocations();
        auto metadata = CollectMetadata(
            context,
            [&](const Metadata& value) {
                ProcessRecord record;
                record.process = value;
                if (!value.path.empty())
                    record.file = cache.Get(value.path, options.signature, context);
                else {
                    record.file.evidence.originalValue = value.path;
                    record.file.evidence.signatureState =
                        value.pathState == FieldState::NotApplicable ? FieldState::NotApplicable : FieldState::Unknown;
                }
                record.assessment = AssessProcess(value, record.file, locations);
                result.records.push_back(std::move(record));
            },
            options.pid);
        result.status = metadata.status;
        result.startedAt = std::move(metadata.startedAt);
        result.finishedAt = std::move(metadata.finishedAt);
        result.collected = metadata.collected;
        result.collectionTruncated = metadata.collectionTruncated;
        result.sources = std::move(metadata.sources);
        result.issues = std::move(metadata.issues);
        result.assessment =
            result.status == CollectionStatus::Complete ? AssessmentState::Complete : AssessmentState::Incomplete;
        for (const auto& record : result.records) {
            if (record.assessment.state != AssessmentState::Complete)
                result.assessment = AssessmentState::Incomplete;
            if (!record.assessment.hits.empty()) {
                RiskFinding finding;
                finding.moduleId = L"process";
                finding.sourceKey = SourceKey(record.process);
                finding.objectName = record.process.name;
                finding.updatedAt = record.process.observedAt;
                finding.assessment = record.assessment;
                result.findings.push_back(std::move(finding));
            }
        }
        return result;
    }

    CollectionResult<ModuleRecord> CollectModules(std::uint32_t pid, bool signature, const CollectionContext& context) {
        CollectionResult<ModuleRecord> result;
        result.startedAt = UtcNow();
        result.assessment = AssessmentState::NotRequested;
        result.sources = { { L"toolhelp.modules" }, { L"psapi.modules" } };
        auto finish = [&]() {
            result.collected = result.records.size();
            result.finishedAt = UtcNow();
        };
        auto issue = [&](const wchar_t* source, const wchar_t* code, DWORD native, const wchar_t* text,
                         bool completeness) {
            result.issues.push_back({ source, std::to_wstring(pid), code, native, text, completeness });
        };
        auto stop = [&](std::size_t source) {
            if (!context.ShouldStop())
                return false;
            result.status = context.StopStatus();
            result.sources[source].status = StatusName(result.status);
            issue(result.sources[source].source.c_str(), context.IsCancelled() ? L"CANCELLED" : L"TIMED_OUT", 0,
                  L"Module enumeration stopped before completion.", true);
            return true;
        };
        if (stop(0)) {
            finish();
            return result;
        }
        if (pid == 0) {
            issue(L"process", L"MODULES_NOT_APPLICABLE", ERROR_ACCESS_DENIED,
                  L"PID 0 does not expose a user-mode module list.", true);
            finish();
            return result;
        }
        UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!process.valid()) {
            const DWORD error = GetLastError();
            issue(L"process", error == ERROR_INVALID_PARAMETER ? L"TARGET_NOT_FOUND" : L"PROCESS_OPEN_FAILED", error,
                  L"The target process could not be opened.", true);
            finish();
            return result;
        }
        FILETIME created{}, exited{}, kernel{}, user{};
        std::uint64_t processTime = 0;
        if (GetProcessTimes(process.get(), &created, &exited, &kernel, &user))
            processTime = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        files::EvidenceCache cache;
        auto append = [&](ModuleRecord record, std::size_t source) {
            if (result.records.size() >= context.maxRecords) {
                result.status = CollectionStatus::Partial;
                result.collectionTruncated = true;
                result.sources[source].status = L"partial";
                issue(result.sources[source].source.c_str(), L"RECORD_BUDGET", 0,
                      L"Module collection reached its record budget.", true);
                return false;
            }
            record.pid = pid;
            record.processCreatedAt = processTime;
            if (!record.path.empty())
                record.file = cache.Get(record.path, signature, context);
            result.records.push_back(std::move(record));
            ++result.sources[source].collected;
            return true;
        };
        HANDLE rawSnapshot = INVALID_HANDLE_VALUE;
        DWORD snapshotError = 0;
        for (unsigned retry = 0; retry < 4; ++retry) {
            if (stop(0)) {
                finish();
                return result;
            }
            rawSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (rawSnapshot != INVALID_HANDLE_VALUE)
                break;
            snapshotError = GetLastError();
            if (snapshotError != ERROR_BAD_LENGTH)
                break;
        }
        {
            UniqueHandle snapshot(rawSnapshot);
            if (snapshot.valid()) {
                MODULEENTRY32W entry{};
                entry.dwSize = sizeof(entry);
                BOOL more = Module32FirstW(snapshot.get(), &entry);
                if (!more)
                    snapshotError = GetLastError();
                else {
                    result.status = CollectionStatus::Complete;
                    result.sources[0].status = L"complete";
                    while (more) {
                        if (stop(0)) {
                            finish();
                            return result;
                        }
                        ModuleRecord record;
                        record.name = entry.szModule;
                        record.path = entry.szExePath;
                        record.baseAddress = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
                        record.imageSize = entry.modBaseSize;
                        record.imageSizeState = FieldState::Available;
                        if (!append(std::move(record), 0)) {
                            finish();
                            return result;
                        }
                        entry.dwSize = sizeof(entry);
                        more = Module32NextW(snapshot.get(), &entry);
                        if (!more && GetLastError() != ERROR_NO_MORE_FILES) {
                            const DWORD error = GetLastError();
                            result.status = CollectionStatus::Partial;
                            result.sources[0].status = L"partial";
                            issue(L"toolhelp.modules", L"MODULE_ENUMERATION_FAILED", error,
                                  L"The module snapshot ended unexpectedly.", true);
                        }
                    }
                    if (context.ShouldStop())
                        stop(0);
                    finish();
                    return result;
                }
            }
        }
        result.sources[0].status = L"failed";
        result.sources[0].nativeCode = snapshotError;
        issue(L"toolhelp.modules", L"MODULE_FALLBACK", snapshotError, L"Toolhelp was unavailable; trying PSAPI.",
              false);
        if (stop(1)) {
            finish();
            return result;
        }
        UniqueHandle readable(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        if (!readable.valid()) {
            const DWORD error = GetLastError();
            result.sources[1].status = L"failed";
            result.sources[1].nativeCode = error;
            issue(L"psapi.modules", L"MODULE_ENUMERATION_FAILED", error,
                  L"Unable to read the target process module list.", true);
            finish();
            return result;
        }
        std::vector<HMODULE> handles(128);
        DWORD needed = 0;
        bool success = false;
        for (unsigned retry = 0; retry < 4; ++retry) {
            if (stop(1)) {
                finish();
                return result;
            }
            if (!EnumProcessModulesEx(readable.get(), handles.data(),
                                      static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed,
                                      LIST_MODULES_ALL)) {
                success = false;
                break;
            }
            success = true;
            if (needed <= handles.size() * sizeof(HMODULE))
                break;
            if (retry == 3)
                break;
            const auto count = (static_cast<std::size_t>(needed) + sizeof(HMODULE) - 1) / sizeof(HMODULE);
            handles.resize((std::min)(count, static_cast<std::size_t>(1000000)));
        }
        if (!success) {
            const DWORD error = GetLastError();
            result.sources[1].status = L"failed";
            result.sources[1].nativeCode = error;
            issue(L"psapi.modules", L"MODULE_ENUMERATION_FAILED", error, L"PSAPI could not enumerate the modules.",
                  true);
            finish();
            return result;
        }
        result.status = CollectionStatus::Complete;
        result.sources[1].status = L"complete";
        const std::size_t count = (std::min)(static_cast<std::size_t>(needed) / sizeof(HMODULE), handles.size());
        if (needed > handles.size() * sizeof(HMODULE)) {
            result.status = CollectionStatus::Partial;
            result.sources[1].status = L"partial";
            issue(L"psapi.modules", L"MODULE_LIST_CHANGED", 0, L"The module list exceeded the bounded retry buffer.",
                  true);
        }
        for (std::size_t i = 0; i < count; ++i) {
            if (stop(1)) {
                finish();
                return result;
            }
            ModuleRecord record;
            wchar_t name[32768]{}, path[32768]{};
            if (GetModuleBaseNameW(readable.get(), handles[i], name, static_cast<DWORD>(std::size(name))))
                record.name = name;
            if (GetModuleFileNameExW(readable.get(), handles[i], path, static_cast<DWORD>(std::size(path))))
                record.path = path;
            record.baseAddress = reinterpret_cast<std::uintptr_t>(handles[i]);
            MODULEINFO information{};
            if (GetModuleInformation(readable.get(), handles[i], &information, sizeof(information))) {
                record.baseAddress = reinterpret_cast<std::uintptr_t>(information.lpBaseOfDll);
                record.imageSize = information.SizeOfImage;
                record.imageSizeState = FieldState::Available;
            }
            if (!append(std::move(record), 1)) {
                finish();
                return result;
            }
        }
        if (context.ShouldStop())
            stop(1);
        finish();
        return result;
    }
}
