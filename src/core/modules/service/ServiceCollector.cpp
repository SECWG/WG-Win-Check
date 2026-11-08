#include "../../system/Win32.h"
#include "ServiceModule.h"
#include <algorithm>
#include <cstring>
#include <set>

#pragma comment(lib, "advapi32.lib")

namespace wgwc::core::services {
    namespace {
        constexpr DWORD MaxConfigBytes = 1024 * 1024;

        struct ServiceHandle {
            SC_HANDLE value = nullptr;

            ~ServiceHandle() {
                if (value)
                    CloseServiceHandle(value);
            }
        };

        struct RegistryKey {
            HKEY value = nullptr;

            ~RegistryKey() {
                if (value)
                    RegCloseKey(value);
            }
        };

        bool Missing(LONG code) {
            return code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND;
        }

        bool InBuffer(const std::vector<BYTE>& buffer, const wchar_t* pointer, std::size_t& remaining) {
            if (!pointer) {
                remaining = 0;
                return true;
            }
            const auto begin = reinterpret_cast<std::uintptr_t>(buffer.data());
            const auto address = reinterpret_cast<std::uintptr_t>(pointer);
            if (address < begin || address - begin >= buffer.size() || (address - begin) % sizeof(wchar_t))
                return false;
            remaining = (buffer.size() - (address - begin)) / sizeof(wchar_t);
            return true;
        }

        bool String(const std::vector<BYTE>& buffer, const wchar_t* pointer, std::wstring& value) {
            value.clear();
            std::size_t remaining = 0;
            if (!InBuffer(buffer, pointer, remaining))
                return false;
            if (!pointer)
                return true;
            std::size_t length = 0;
            while (length < remaining && pointer[length])
                ++length;
            if (length == remaining)
                return false;
            value.assign(pointer, length);
            return true;
        }

        bool Dependencies(const std::vector<BYTE>& buffer, const wchar_t* pointer, std::vector<std::wstring>& values) {
            values.clear();
            std::size_t remaining = 0;
            if (!InBuffer(buffer, pointer, remaining))
                return false;
            if (!pointer)
                return true;
            std::size_t offset = 0;
            while (offset < remaining && pointer[offset]) {
                const auto begin = offset;
                while (offset < remaining && pointer[offset])
                    ++offset;
                if (offset == remaining)
                    return false;
                values.emplace_back(pointer + begin, offset - begin);
                ++offset;
            }
            return offset < remaining;
        }

        void Issue(CollectionResult<Record>& result, std::size_t source, const std::wstring& object,
                   const wchar_t* code, std::uint32_t native, const wchar_t* message, bool fatal = false) {
            CollectionIssue issue;
            issue.source = result.sources[source].source;
            issue.objectKey = object;
            issue.code = code;
            issue.nativeCode = native;
            issue.message = message;
            issue.affectsCompleteness = true;
            result.issues.push_back(std::move(issue));
            auto& coverage = result.sources[source];
            coverage.status = fatal && !coverage.collected ? L"failed" : L"partial";
            coverage.nativeCode = native;
        }

        DWORD ConfigBuffer(SC_HANDLE service, DWORD level, std::vector<BYTE>& buffer,
                           const CollectionContext& context) {
            DWORD needed = 0;
            for (int attempt = 0; attempt < 3; ++attempt) {
                if (context.ShouldStop())
                    return ERROR_CANCELLED;
                BOOL ok = level
                              ? QueryServiceConfig2W(service, level, buffer.empty() ? nullptr : buffer.data(),
                                                     static_cast<DWORD>(buffer.size()), &needed)
                              : QueryServiceConfigW(
                                    service,
                                    buffer.empty() ? nullptr : reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data()),
                                    static_cast<DWORD>(buffer.size()), &needed);
                if (ok)
                    return ERROR_SUCCESS;
                const auto error = GetLastError();
                if (error != ERROR_INSUFFICIENT_BUFFER)
                    return error;
                if (!needed || needed > MaxConfigBytes)
                    return ERROR_INVALID_DATA;
                buffer.resize(needed);
            }
            return ERROR_RETRY;
        }

        LONG ReadDll(HKEY root, const std::wstring& path, std::wstring& value) {
            RegistryKey key;
            auto status = RegOpenKeyExW(root, path.c_str(), 0, KEY_QUERY_VALUE, &key.value);
            if (status != ERROR_SUCCESS)
                return status;
            for (int attempt = 0; attempt < 3; ++attempt) {
                DWORD type = 0, size = 0;
                status = RegQueryValueExW(key.value, L"ServiceDll", nullptr, &type, nullptr, &size);
                if (status != ERROR_SUCCESS)
                    return status;
                if ((type != REG_SZ && type != REG_EXPAND_SZ) || size % sizeof(wchar_t) || size > MaxConfigBytes)
                    return ERROR_INVALID_DATA;
                std::vector<wchar_t> text(static_cast<std::size_t>(size) / sizeof(wchar_t) + 1, L'\0');
                status = RegQueryValueExW(key.value, L"ServiceDll", nullptr, &type,
                                          reinterpret_cast<BYTE*>(text.data()), &size);
                if (status == ERROR_MORE_DATA)
                    continue;
                if (status != ERROR_SUCCESS)
                    return status;
                if ((type != REG_SZ && type != REG_EXPAND_SZ) || size % sizeof(wchar_t) ||
                    size > (text.size() - 1) * sizeof(wchar_t))
                    return ERROR_INVALID_DATA;
                value.assign(text.data(), size / sizeof(wchar_t));
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

        void Configuration(SC_HANDLE manager, Record& record, CollectionResult<Record>& result,
                           const CollectionContext& context) {
            ServiceHandle service;
            service.value = OpenServiceW(manager, record.serviceName.c_str(), SERVICE_QUERY_CONFIG);
            if (!service.value) {
                Issue(result, 1, record.sourceKey, L"service_open_failed", GetLastError(),
                      L"Cannot read service configuration; startup type is unknown, not manual.");
                return;
            }
            std::vector<BYTE> buffer;
            auto error = ConfigBuffer(service.value, 0, buffer, context);
            if (error == ERROR_SUCCESS && buffer.size() >= sizeof(QUERY_SERVICE_CONFIGW)) {
                const auto config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(buffer.data());
                std::wstring display, binary, account, group;
                std::vector<std::wstring> dependencies;
                if (String(buffer, config->lpDisplayName, display) &&
                    String(buffer, config->lpBinaryPathName, binary) &&
                    String(buffer, config->lpServiceStartName, account) &&
                    String(buffer, config->lpLoadOrderGroup, group) &&
                    Dependencies(buffer, config->lpDependencies, dependencies)) {
                    record.configState = FieldState::Available;
                    record.startType = config->dwStartType;
                    record.serviceType = config->dwServiceType;
                    record.binaryPath = std::move(binary);
                    record.account = std::move(account);
                    record.loadOrderGroup = std::move(group);
                    record.dependencies = std::move(dependencies);
                    if (record.displayName.empty())
                        record.displayName = std::move(display);
                    ++result.sources[1].collected;
                } else
                    error = ERROR_INVALID_DATA;
            } else if (error == ERROR_SUCCESS)
                error = ERROR_INVALID_DATA;
            if (error && !context.ShouldStop())
                Issue(result, 1, record.sourceKey, L"service_config_failed", error,
                      L"Cannot decode the complete service configuration.");

            if (context.ShouldStop())
                return;
            buffer.clear();
            error = ConfigBuffer(service.value, SERVICE_CONFIG_DESCRIPTION, buffer, context);
            record.descriptionState = FieldState::Unknown;
            if (error == ERROR_SUCCESS && buffer.size() >= sizeof(SERVICE_DESCRIPTIONW)) {
                const auto description = reinterpret_cast<const SERVICE_DESCRIPTIONW*>(buffer.data());
                if (String(buffer, description->lpDescription, record.description))
                    record.descriptionState = FieldState::Available;
                else
                    error = ERROR_INVALID_DATA;
            } else if (error == ERROR_SUCCESS)
                error = ERROR_INVALID_DATA;
            if (error && !context.ShouldStop())
                Issue(result, 1, record.sourceKey, L"service_description_failed", error,
                      L"Cannot read the service description.");
            if (context.ShouldStop())
                return;
            if (record.configState == FieldState::Available && record.startType == SERVICE_AUTO_START) {
                SERVICE_DELAYED_AUTO_START_INFO delayed{};
                DWORD needed = 0;
                if (QueryServiceConfig2W(service.value, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                                         reinterpret_cast<BYTE*>(&delayed), sizeof(delayed), &needed)) {
                    record.delayedAutoStart = delayed.fDelayedAutostart != FALSE;
                    record.delayedAutoStartState = FieldState::Available;
                } else {
                    record.delayedAutoStartState = FieldState::Unknown;
                    Issue(result, 1, record.sourceKey, L"service_delayed_start_failed", GetLastError(),
                          L"Cannot determine delayed automatic startup.");
                }
            } else
                record.delayedAutoStartState =
                    record.configState == FieldState::Available ? FieldState::NotApplicable : FieldState::Unknown;

            if (record.configState != FieldState::Available) {
                record.serviceDllState = FieldState::Unknown;
                return;
            }
            const auto executable = ResolveExecutable(record.binaryPath);
            if (!IsSvchost(executable.value)) {
                record.serviceDllState = FieldState::NotApplicable;
                return;
            }
            record.serviceDllState = FieldState::Unknown;
            const auto key = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + record.serviceName;
            auto status = ReadDll(HKEY_LOCAL_MACHINE, key + L"\\Parameters", record.serviceDll);
            if (Missing(status) || (status == ERROR_SUCCESS && record.serviceDll.empty()))
                status = ReadDll(HKEY_LOCAL_MACHINE, key, record.serviceDll);
            if (status == ERROR_SUCCESS || Missing(status))
                record.serviceDllState = FieldState::Available;
            else
                Issue(result, 1, record.sourceKey, L"service_dll_unknown", status,
                      L"Cannot read ServiceDll; do not substitute a description resource or the host executable.");
        }
    }

    CollectionResult<Record> CollectServices(const Options& options, const CollectionContext& context) {
        CollectionResult<Record> result;
        result.startedAt = UtcNow();
        for (const auto name :
             { L"SCM:EnumServicesStatusExW:SERVICE_WIN32", L"SCM:service-configuration", L"service-file-evidence" }) {
            SourceCoverage source;
            source.source = name;
            result.sources.push_back(std::move(source));
        }
        auto finish = [&]() {
            result.collected = result.records.size();
            result.finishedAt = UtcNow();
            result.assessment = AssessmentState::Complete;
            bool incomplete = result.collectionTruncated, anySuccess = false;
            for (const auto& source : result.sources) {
                incomplete |= source.status != L"complete";
                anySuccess |= source.status == L"complete" || source.status == L"partial" || source.collected != 0;
            }
            for (const auto& issue : result.issues)
                incomplete |= issue.affectsCompleteness;
            for (const auto& record : result.records)
                if (record.assessment.state != AssessmentState::Complete)
                    result.assessment = AssessmentState::Incomplete;
            if (context.ShouldStop())
                result.status = context.StopStatus();
            else if (!anySuccess)
                result.status = CollectionStatus::Failed;
            else
                result.status = incomplete ? CollectionStatus::Partial : CollectionStatus::Complete;
            if (result.status != CollectionStatus::Complete)
                result.assessment = AssessmentState::Incomplete;
        };
        if (context.ShouldStop()) {
            finish();
            return result;
        }
        rules::ClearDllSideLoadingRiskCache();
        ServiceHandle manager;
        manager.value = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (!manager.value) {
            Issue(result, 0, L"", L"scm_open_failed", GetLastError(), L"Cannot enumerate local Win32 services.", true);
            finish();
            return result;
        }
        result.sources[0].status = L"complete";
        std::vector<BYTE> buffer(64 * 1024);
        std::set<std::wstring> names;
        DWORD resume = 0;
        while (!context.ShouldStop() && !result.collectionTruncated) {
            const auto previous = resume;
            DWORD needed = 0, count = 0;
            const BOOL success = EnumServicesStatusExW(
                manager.value, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(),
                static_cast<DWORD>(buffer.size()), &needed, &count, &resume, nullptr);
            const DWORD error = success ? ERROR_SUCCESS : GetLastError();
            if (!success && error == ERROR_MORE_DATA && !count && buffer.size() < 256 * 1024 &&
                needed > buffer.size()) {
                buffer.resize((std::min)(needed, static_cast<DWORD>(256 * 1024)));
                resume = previous;
                continue;
            }
            if (count > buffer.size() / sizeof(ENUM_SERVICE_STATUS_PROCESSW)) {
                Issue(result, 0, L"", L"service_page_invalid", ERROR_INVALID_DATA, L"SCM returned an invalid page.",
                      true);
                break;
            }
            const auto entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
            for (DWORD i = 0; i < count && !context.ShouldStop(); ++i) {
                Record record;
                if (!String(buffer, entries[i].lpServiceName, record.serviceName) || record.serviceName.empty() ||
                    !String(buffer, entries[i].lpDisplayName, record.displayName)) {
                    Issue(result, 0, L"", L"service_name_invalid", ERROR_INVALID_DATA,
                          L"Cannot decode a service identity.");
                    continue;
                }
                if (!names.insert(rules::ToLower(record.serviceName)).second)
                    continue;
                if (result.records.size() >= context.maxRecords) {
                    result.collectionTruncated = true;
                    Issue(result, 0, L"", L"collection_limit", ERROR_MORE_DATA,
                          L"Service enumeration reached the record budget.");
                    break;
                }
                const auto& state = entries[i].ServiceStatusProcess;
                record.currentState = state.dwCurrentState;
                record.serviceType = state.dwServiceType;
                record.processId = state.dwProcessId;
                record.controlsAccepted = state.dwControlsAccepted;
                record.win32ExitCode = state.dwWin32ExitCode;
                record.serviceExitCode = state.dwServiceSpecificExitCode;
                record.statusState = FieldState::Available;
                if (state.dwCurrentState == SERVICE_STOPPED)
                    record.pidState = FieldState::NotApplicable;
                else if (state.dwCurrentState == SERVICE_RUNNING || state.dwCurrentState == SERVICE_PAUSED ||
                         state.dwCurrentState == SERVICE_PAUSE_PENDING ||
                         state.dwCurrentState == SERVICE_CONTINUE_PENDING)
                    record.pidState = FieldState::Available;
                record.sourceKey = record.serviceName;
                record.source = result.sources[0].source;
                record.registryPath = L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" + record.serviceName;
                record.observedAt = result.startedAt;
                result.records.push_back(std::move(record));
                ++result.sources[0].collected;
            }
            if (context.ShouldStop() || result.collectionTruncated)
                break;
            const auto next = NextPage({ success != FALSE, error, previous, resume, count });
            if (next == PageAction::Complete)
                break;
            if (next == PageAction::Failed) {
                Issue(result, 0, L"", error == ERROR_MORE_DATA ? L"service_pagination_stalled" : L"service_enum_failed",
                      error, L"SCM enumeration did not complete; partial pages are retained.", true);
                break;
            }
        }
        if (context.ShouldStop())
            result.sources[0].status = context.IsCancelled() ? L"cancelled" : L"timed_out";
        if (!context.ShouldStop() && (!result.records.empty() || result.sources[0].status == L"complete"))
            result.sources[1].status = result.sources[2].status = L"complete";

        files::EvidenceCache cache;
        for (auto& record : result.records) {
            if (!context.ShouldStop())
                Configuration(manager.value, record, result, context);
            SelectAssociatedFile(record);
            if (record.associationStable && !context.ShouldStop()) {
                record.file = cache.Get(record.associatedFile, options.verifySignatures, context);
                record.file.evidence.source = result.sources[2].source;
                ++result.sources[2].collected;
                for (auto issue : record.file.evidence.issues) {
                    issue.source = result.sources[2].source;
                    issue.objectKey = record.sourceKey;
                    if (issue.affectsCompleteness) {
                        result.sources[2].status = L"partial";
                        result.sources[2].nativeCode = issue.nativeCode;
                    }
                    result.issues.push_back(std::move(issue));
                }
                if (record.file.evidence.existence == FieldState::Available && record.file.evidence.exists &&
                    !record.file.directory && record.file.evidence.signatureState == FieldState::Available &&
                    record.file.evidence.signature == SignatureState::Signed && !context.ShouldStop()) {
                    record.sideLoadingRisk =
                        rules::DetectDllSideLoadingRisk(record.associatedFile, SignatureState::Signed);
                    record.sideLoadingState = FieldState::Available;
                } else if (record.file.evidence.signatureState == FieldState::Available &&
                           record.file.evidence.signature != SignatureState::Unknown)
                    record.sideLoadingState = FieldState::NotApplicable;
            } else {
                record.file.evidence.originalValue = record.associatedFile;
                record.file.evidence.source = result.sources[2].source;
                record.file.evidence.resolution = record.file.evidence.existence = FieldState::Unknown;
                record.file.evidence.signatureState =
                    options.verifySignatures ? FieldState::Unknown : FieldState::NotRequested;
                record.file.versionState = record.file.attributesState = FieldState::Unknown;
                if (!context.ShouldStop())
                    Issue(result, 2, record.sourceKey, L"service_file_unresolved", ERROR_NOT_FOUND,
                          L"No stable service implementation path; no missing-file or unsigned risk is inferred.");
            }
            record.assessment = AssessRisk(record);
            if (!record.assessment.hits.empty()) {
                RiskFinding finding;
                finding.moduleId = L"service";
                finding.sourceKey = record.sourceKey;
                finding.objectName = record.serviceName;
                finding.updatedAt = record.observedAt;
                finding.assessment = record.assessment;
                result.findings.push_back(std::move(finding));
            }
        }
        if (context.ShouldStop())
            for (std::size_t i = 1; i < result.sources.size(); ++i)
                if (result.sources[i].status != L"not_started")
                    result.sources[i].status = context.IsCancelled() ? L"cancelled" : L"timed_out";
        if (context.progress)
            context.progress(L"service", result.records.size());
        finish();
        return result;
    }
}
