#include "../../system/Win32.h"
#include "AutorunModule.h"
#include <shlobj.h>
#include <shobjidl.h>
#include <algorithm>
#include <functional>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace wgwc::core::autorun {
    namespace {
        struct Key {
            HKEY value = nullptr;

            ~Key() {
                if (value)
                    RegCloseKey(value);
            }
        };

        struct ComScope {
            HRESULT status = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

            ~ComScope() {
                if (SUCCEEDED(status))
                    CoUninitialize();
            }
        };

        bool Native64() {
            SYSTEM_INFO info{};
            GetNativeSystemInfo(&info);
            return info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                   info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
        }

        bool Missing(LONG status) {
            return status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
        }

        struct Source {
            CollectionResult<Record>& result;
            const CollectionContext& context;
            std::size_t index, visited = 0;

            Source(CollectionResult<Record>& r, const CollectionContext& c, const std::wstring& name)
                : result(r), context(c), index(r.sources.size()) {
                SourceCoverage value;
                value.source = name;
                r.sources.push_back(std::move(value));
            }

            SourceCoverage& Coverage() {
                return result.sources[index];
            }

            bool Begin() {
                if (context.ShouldStop() || result.collectionTruncated)
                    return false;
                Coverage().status = L"complete";
                return true;
            }

            bool Stop() {
                if (context.ShouldStop()) {
                    Coverage().status = context.IsCancelled() ? L"cancelled" : L"timed_out";
                    return true;
                }
                return result.collectionTruncated;
            }

            void Issue(const std::wstring& object, const wchar_t* code, std::uint32_t native, const wchar_t* message,
                       bool fatal = false) {
                CollectionIssue issue;
                issue.source = Coverage().source;
                issue.objectKey = object;
                issue.code = code;
                issue.nativeCode = native;
                issue.message = message;
                issue.affectsCompleteness = true;
                result.issues.push_back(std::move(issue));
                Coverage().status = fatal && !Coverage().collected ? L"failed" : L"partial";
                Coverage().nativeCode = native;
            }

            bool Visit() {
                if (Stop())
                    return false;
                if (visited++ < context.maxRecords)
                    return true;
                Limit();
                return false;
            }

            void Limit() {
                result.collectionTruncated = true;
                Issue(L"", L"collection_limit", ERROR_MORE_DATA, L"Source enumeration reached the collection budget.");
            }

            bool Add(Record record) {
                if (Stop())
                    return false;
                if (result.records.size() >= context.maxRecords) {
                    Limit();
                    return false;
                }
                record.source = Coverage().source;
                record.observedAt = result.startedAt;
                result.records.push_back(std::move(record));
                ++Coverage().collected;
                return true;
            }
        };

        LONG Open(HKEY root, const std::wstring& path, Key& key) {
            return RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | (Native64() ? KEY_WOW64_64KEY : 0), &key.value);
        }

        LONG ReadString(HKEY key, const std::wstring& name, std::wstring& text) {
            for (int attempt = 0; attempt < 4; ++attempt) {
                DWORD type = 0, size = 0;
                auto status = RegQueryValueExW(key, name.c_str(), nullptr, &type, nullptr, &size);
                if (status != ERROR_SUCCESS)
                    return status;
                if (size > 1024 * 1024)
                    return ERROR_FILE_TOO_LARGE;
                std::vector<unsigned char> bytes(static_cast<std::size_t>(size) + sizeof(wchar_t));
                status = RegQueryValueExW(key, name.c_str(), nullptr, &type, bytes.data(), &size);
                if (status == ERROR_MORE_DATA)
                    continue;
                if (status != ERROR_SUCCESS)
                    return status;
                return DecodeRegistryString(type, bytes.data(), size, text) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
            }
            return ERROR_RETRY;
        }

        std::wstring RootName(HKEY root) {
            return root == HKEY_LOCAL_MACHINE ? L"HKEY_LOCAL_MACHINE\\" : L"HKEY_CURRENT_USER\\";
        }

        Record RegistryRecord(Type type, HKEY root, const std::wstring& path, const std::wstring& name,
                              const std::wstring& command, const std::wstring& label) {
            Record record;
            record.type = type;
            record.name = name.empty() ? L"(默认)" : name;
            record.location = label;
            record.command = command;
            record.registryPath = RootName(root) + path;
            record.registryValue = name;
            record.registryView =
                path.find(L"WOW6432Node") != std::wstring::npos ? L"32" : (Native64() ? L"64" : L"32");
            record.sourceKey = SourceKey(type, record.registryPath, name, record.registryView);
            return record;
        }

        void Values(Source& source, HKEY root, const std::wstring& path, Type type, const std::wstring& label) {
            Key key;
            auto status = Open(root, path, key);
            if (Missing(status))
                return;
            if (status != ERROR_SUCCESS) {
                source.Issue(RootName(root) + path, L"registry_open_failed", status,
                             L"Cannot read autorun registry key.", true);
                return;
            }
            DWORD maxName = 0;
            status = RegQueryInfoKeyW(key.value, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                      &maxName, nullptr, nullptr, nullptr);
            if (status != ERROR_SUCCESS || maxName > 16383) {
                source.Issue(path, L"registry_metadata_failed", status ? status : ERROR_INVALID_DATA,
                             L"Cannot determine registry value name bounds.", true);
                return;
            }
            std::vector<wchar_t> name(static_cast<std::size_t>(maxName) + 2);
            for (DWORD i = 0; !source.Stop(); ++i) {
                DWORD length = static_cast<DWORD>(name.size()), typeCode = 0;
                status = RegEnumValueW(key.value, i, name.data(), &length, nullptr, &typeCode, nullptr, nullptr);
                if (status == ERROR_NO_MORE_ITEMS)
                    break;
                if (status != ERROR_SUCCESS) {
                    source.Issue(path, L"registry_enum_failed", status, L"Registry value enumeration was interrupted.");
                    break;
                }
                if (!source.Visit())
                    break;
                if (typeCode != REG_SZ && typeCode != REG_EXPAND_SZ)
                    continue;
                const std::wstring valueName(name.data(), length);
                std::wstring command;
                status = ReadString(key.value, valueName, command);
                if (status != ERROR_SUCCESS) {
                    source.Issue(path + L"\\" + valueName, L"registry_value_failed", status,
                                 L"Cannot decode the complete registry string value.");
                    continue;
                }
                if (command.empty())
                    continue;
                source.Add(RegistryRecord(type, root, path, valueName, command, label));
            }
        }

        void SubKeys(Source& source, HKEY root, const std::wstring& path,
                     const std::function<void(const std::wstring&)>& callback) {
            Key key;
            auto status = Open(root, path, key);
            if (Missing(status))
                return;
            if (status != ERROR_SUCCESS) {
                source.Issue(RootName(root) + path, L"registry_open_failed", status,
                             L"Cannot enumerate autorun subkeys.", true);
                return;
            }
            DWORD maxName = 0;
            status = RegQueryInfoKeyW(key.value, nullptr, nullptr, nullptr, nullptr, &maxName, nullptr, nullptr,
                                      nullptr, nullptr, nullptr, nullptr);
            if (status != ERROR_SUCCESS || maxName > 32767) {
                source.Issue(path, L"registry_metadata_failed", status ? status : ERROR_INVALID_DATA,
                             L"Cannot determine registry subkey bounds.", true);
                return;
            }
            std::vector<wchar_t> name(static_cast<std::size_t>(maxName) + 2);
            for (DWORD i = 0; !source.Stop(); ++i) {
                DWORD length = static_cast<DWORD>(name.size());
                status = RegEnumKeyExW(key.value, i, name.data(), &length, nullptr, nullptr, nullptr, nullptr);
                if (status == ERROR_NO_MORE_ITEMS)
                    break;
                if (status != ERROR_SUCCESS) {
                    source.Issue(path, L"registry_enum_failed", status,
                                 L"Registry subkey enumeration was interrupted.");
                    break;
                }
                if (!source.Visit())
                    break;
                callback(std::wstring(name.data(), length));
            }
        }

        void Config(Source& source, HKEY root, const std::wstring& path, const std::wstring& valueName, Type type,
                    const std::wstring& label, const std::wstring& objectName = L"") {
            if (source.Stop())
                return;
            Key key;
            auto status = Open(root, path, key);
            if (Missing(status))
                return;
            if (status != ERROR_SUCCESS) {
                source.Issue(RootName(root) + path, L"registry_open_failed", status,
                             L"Cannot read startup configuration.", true);
                return;
            }
            std::wstring command;
            status = ReadString(key.value, valueName, command);
            if (Missing(status))
                return;
            if (status != ERROR_SUCCESS) {
                source.Issue(path + L"\\" + valueName, L"registry_value_failed", status,
                             L"Cannot decode startup configuration.");
                return;
            }
            if (command.empty() && (type == Type::AppInit || type == Type::WindowsLoad || type == Type::IFEO))
                return;
            auto record = RegistryRecord(type, root, path, valueName, command, label);
            if (!objectName.empty())
                record.name = objectName;
            record.specialConfig = true;
            record.configState = FieldState::Available;
            record.defaultConfig = IsDefaultConfig(type, valueName, command);
            if (type == Type::AppInit) {
                DWORD enabled = 0, code = 0, size = sizeof(enabled);
                status = RegQueryValueExW(key.value, L"LoadAppInit_DLLs", nullptr, &code,
                                          reinterpret_cast<BYTE*>(&enabled), &size);
                if (Missing(status))
                    record.defaultConfig = true;
                else if (status == ERROR_SUCCESS && code == REG_DWORD && size == sizeof(enabled))
                    record.defaultConfig = enabled == 0;
                else {
                    record.configState = FieldState::Unknown;
                    source.Issue(path + L"\\LoadAppInit_DLLs", L"config_enable_unknown",
                                 status ? status : ERROR_INVALID_DATA,
                                 L"Cannot determine whether AppInit DLL loading is enabled.");
                }
            }
            source.Add(std::move(record));
        }

        bool Shortcut(const std::wstring& path, std::wstring& command, std::wstring& working, HRESULT& error) {
            ComScope com;
            if (FAILED(com.status) && com.status != RPC_E_CHANGED_MODE) {
                error = com.status;
                return false;
            }
            IShellLinkW* link = nullptr;
            error = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link));
            if (FAILED(error))
                return false;
            IPersistFile* persist = nullptr;
            error = link->QueryInterface(IID_PPV_ARGS(&persist));
            if (SUCCEEDED(error)) {
                error = persist->Load(path.c_str(), STGM_READ);
                persist->Release();
            }
            std::vector<wchar_t> target(32768), args(32768), directory(32768);
            if (SUCCEEDED(error))
                error = link->GetPath(target.data(), static_cast<int>(target.size()), nullptr, SLGP_RAWPATH);
            if (SUCCEEDED(error) && !target[0])
                error = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
            if (SUCCEEDED(error))
                error = link->GetArguments(args.data(), static_cast<int>(args.size()));
            if (SUCCEEDED(error))
                error = link->GetWorkingDirectory(directory.data(), static_cast<int>(directory.size()));
            link->Release();
            if (FAILED(error))
                return false;
            command = L"\"" + std::wstring(target.data()) + L"\"";
            if (args[0])
                command += L" " + std::wstring(args.data());
            working = directory.data();
            return true;
        }

        void Folder(Source& source, int folderId, const std::wstring& label) {
            wchar_t folder[MAX_PATH]{};
            const auto status = SHGetFolderPathW(nullptr, folderId, nullptr, SHGFP_TYPE_CURRENT, folder);
            if (FAILED(status)) {
                source.Issue(label, L"startup_folder_failed", static_cast<std::uint32_t>(status),
                             L"Cannot locate the startup folder for this execution identity.", true);
                return;
            }
            const auto base = std::wstring(folder) + L"\\";
            WIN32_FIND_DATAW data{};
            HANDLE handle =
                FindFirstFileExW((base + L"*").c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, 0);
            if (handle == INVALID_HANDLE_VALUE) {
                const auto error = GetLastError();
                if (!Missing(error))
                    source.Issue(base, L"startup_enum_failed", error, L"Cannot enumerate startup folder.", true);
                return;
            }
            do {
                if (!source.Visit())
                    break;
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || _wcsicmp(data.cFileName, L"desktop.ini") == 0)
                    continue;
                Record record;
                record.type = Type::StartupFolder;
                record.name = data.cFileName;
                record.location = label;
                record.originPath = base + record.name;
                record.sourceKey = SourceKey(record.type, record.originPath, record.name);
                record.originState = FieldState::Available;
                record.originHidden = (data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;
                std::wstring working;
                const auto lower = rules::ToLower(record.name);
                if (lower.size() >= 4 && lower.compare(lower.size() - 4, 4, L".lnk") == 0) {
                    HRESULT error = S_OK;
                    if (!Shortcut(record.originPath, record.command, working, error)) {
                        record.command = record.originPath;
                        record.filePath = record.originPath;
                        source.Issue(record.originPath, L"shortcut_unresolved", static_cast<std::uint32_t>(error),
                                     L"Cannot read the shortcut target; no target file risk is inferred.");
                        source.Add(std::move(record));
                        continue;
                    }
                } else
                    record.command = L"\"" + record.originPath + L"\"";
                const auto association = ResolveCommand(record.command, working);
                record.filePath = association.executablePath;
                record.associatedFile = association.associatedFile;
                record.associationStable = association.stable;
                if (!source.Add(std::move(record)))
                    break;
            } while (FindNextFileW(handle, &data));
            const auto error = GetLastError();
            FindClose(handle);
            if (!source.Stop() && error != ERROR_NO_MORE_FILES)
                source.Issue(base, L"startup_enum_failed", error, L"Startup folder enumeration was interrupted.");
        }

        void NotApplicable(files::FileInfo& file) {
            file.evidence.resolution = file.evidence.existence = file.evidence.signatureState =
                FieldState::NotApplicable;
            file.attributesState = file.versionState = FieldState::NotApplicable;
        }
    }

    CollectionResult<Record> CollectAutoruns(const Options& options, const CollectionContext& context) {
        CollectionResult<Record> result;
        result.startedAt = UtcNow();
        rules::ClearDllSideLoadingRiskCache();
        const auto currentVersion = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\");
        const auto ntVersion = std::wstring(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\");
        auto source = [&](Type type, const std::wstring& name, const std::function<void(Source&)>& action) {
            if (!TypeMatches(options.type, type))
                return;
            Source current(result, context, name);
            if (current.Begin())
                action(current);
        };

        struct RunKey {
            HKEY root;
            const wchar_t* suffix;
            const wchar_t* label;
        };

        const RunKey keys[] = {
            { HKEY_LOCAL_MACHINE, L"Run",                     L"HKLM\\Run"                     },
            { HKEY_LOCAL_MACHINE, L"RunOnce",                 L"HKLM\\RunOnce"                 },
            { HKEY_CURRENT_USER,  L"Run",                     L"HKCU\\Run"                     },
            { HKEY_CURRENT_USER,  L"RunOnce",                 L"HKCU\\RunOnce"                 },
            { HKEY_LOCAL_MACHINE, L"Policies\\Explorer\\Run", L"HKLM\\Policies\\Explorer\\Run" },
            { HKEY_CURRENT_USER,  L"Policies\\Explorer\\Run", L"HKCU\\Policies\\Explorer\\Run" },
            { HKEY_LOCAL_MACHINE, L"RunServices",             L"HKLM\\RunServices"             },
            { HKEY_LOCAL_MACHINE, L"RunServicesOnce",         L"HKLM\\RunServicesOnce"         }
        };
        for (const auto& key : keys)
            source(Type::Registry, RootName(key.root) + currentVersion + key.suffix, [&](Source& s) {
                Values(s, key.root, currentVersion + key.suffix, Type::Registry, key.label);
            });
        if (Native64())
            for (const auto suffix : { L"Run", L"RunOnce" }) {
                const auto path = std::wstring(L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\") + suffix;
                source(Type::Registry, RootName(HKEY_LOCAL_MACHINE) + path, [&](Source& s) {
                    Values(s, HKEY_LOCAL_MACHINE, path, Type::Registry, std::wstring(L"HKLM\\WOW64\\") + suffix);
                });
            }
        source(Type::StartupFolder, L"startup-folder:current-user", [&](Source& s) {
            Folder(s, CSIDL_STARTUP, L"用户启动文件夹");
        });
        source(Type::StartupFolder, L"startup-folder:common", [&](Source& s) {
            Folder(s, CSIDL_COMMON_STARTUP, L"公共启动文件夹");
        });
        for (int view = 0; view < (Native64() ? 2 : 1); ++view) {
            const auto nt =
                view ? std::wstring(L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\") : ntVersion;
            const auto label = view ? std::wstring(L"HKLM\\WOW64\\") : std::wstring(L"HKLM\\");
            source(Type::Winlogon, RootName(HKEY_LOCAL_MACHINE) + nt + L"Winlogon", [&](Source& s) {
                Config(s, HKEY_LOCAL_MACHINE, nt + L"Winlogon", L"Userinit", Type::Winlogon, label + L"Winlogon");
                Config(s, HKEY_LOCAL_MACHINE, nt + L"Winlogon", L"Shell", Type::Winlogon, label + L"Winlogon");
            });
            source(Type::IFEO, RootName(HKEY_LOCAL_MACHINE) + nt + L"Image File Execution Options", [&](Source& s) {
                const auto path = nt + L"Image File Execution Options";
                SubKeys(s, HKEY_LOCAL_MACHINE, path, [&](const std::wstring& child) {
                    Config(s, HKEY_LOCAL_MACHINE, path + L"\\" + child, L"Debugger", Type::IFEO, label + L"IFEO",
                           child);
                });
            });
            source(Type::AppInit, RootName(HKEY_LOCAL_MACHINE) + nt + L"Windows", [&](Source& s) {
                Config(s, HKEY_LOCAL_MACHINE, nt + L"Windows", L"AppInit_DLLs", Type::AppInit,
                       label + L"Windows\\AppInit_DLLs");
            });
        }
        source(Type::WindowsLoad, L"HKEY_CURRENT_USER\\" + ntVersion + L"Windows\\Load", [&](Source& s) {
            Config(s, HKEY_CURRENT_USER, ntVersion + L"Windows", L"Load", Type::WindowsLoad, L"HKCU\\Windows\\Load");
        });
        source(Type::SafeBoot, L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot", [&](Source& s) {
            Config(s, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot", L"AlternateShell",
                   Type::SafeBoot, L"HKLM\\SafeBoot\\AlternateShell");
        });
        for (auto root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER })
            source(Type::RunOnceEx, RootName(root) + currentVersion + L"RunOnceEx", [&](Source& s) {
                const auto path = currentVersion + L"RunOnceEx";
                SubKeys(s, root, path, [&](const std::wstring& child) {
                    Values(s, root, path + L"\\" + child, Type::RunOnceEx,
                           (root == HKEY_LOCAL_MACHINE ? L"HKLM\\RunOnceEx\\" : L"HKCU\\RunOnceEx\\") + child);
                });
            });
        if (TypeMatches(options.type, Type::WmiSubscription))
            CollectWmiSubscriptions(result, context);

        files::EvidenceCache cache;
        for (auto& record : result.records) {
            const bool wmi = record.type == Type::WmiSubscription;
            const bool fileApplicable = !record.specialConfig || (wmi && !record.scriptFilename.empty());
            if (!fileApplicable) {
                NotApplicable(record.file);
                record.sideLoadingState = FieldState::NotApplicable;
            } else {
                if (record.type != Type::StartupFolder && !wmi) {
                    const auto association = ResolveCommand(record.command);
                    record.filePath = association.executablePath;
                    record.associatedFile = association.associatedFile;
                    record.associationStable = association.stable;
                }
                if (record.associationStable && !context.ShouldStop()) {
                    record.file = cache.Get(record.associatedFile, options.verifySignatures, context);
                    record.file.evidence.source = record.source;
                    for (auto issue : record.file.evidence.issues) {
                        issue.objectKey = record.sourceKey;
                        if (wmi)
                            issue.affectsCompleteness = false;
                        result.issues.push_back(std::move(issue));
                    }
                    if (!wmi && record.file.evidence.existence == FieldState::Available &&
                        record.file.evidence.exists && record.file.evidence.signatureState == FieldState::Available &&
                        record.file.evidence.signature == SignatureState::Signed && !context.ShouldStop()) {
                        record.sideLoadingRisk =
                            rules::DetectDllSideLoadingRisk(record.associatedFile, SignatureState::Signed);
                        record.sideLoadingState = FieldState::Available;
                    } else if (wmi || (record.file.evidence.signatureState == FieldState::Available &&
                                       record.file.evidence.signature != SignatureState::Unknown))
                        record.sideLoadingState = FieldState::NotApplicable;
                } else {
                    record.file.evidence.originalValue = record.associatedFile;
                    record.file.evidence.source = record.source;
                    record.file.evidence.resolution = record.file.evidence.existence = FieldState::Unknown;
                    record.file.evidence.signatureState =
                        options.verifySignatures ? FieldState::Unknown : FieldState::NotRequested;
                    if (!context.ShouldStop()) {
                        CollectionIssue issue;
                        issue.source = record.source;
                        issue.objectKey = record.sourceKey;
                        issue.code = L"associated_file_unresolved";
                        issue.message = L"No stable associated file path; the caller's current directory is not used.";
                        issue.affectsCompleteness = !wmi;
                        result.issues.push_back(std::move(issue));
                    }
                }
            }
            record.assessment = AssessRisk(record);
            if (!record.assessment.hits.empty()) {
                RiskFinding finding;
                finding.moduleId = L"autorun";
                finding.sourceKey = record.sourceKey;
                finding.objectName = record.name;
                finding.updatedAt = record.observedAt;
                finding.assessment = record.assessment;
                result.findings.push_back(std::move(finding));
            }
        }
        result.collected = result.records.size();
        result.finishedAt = UtcNow();
        result.assessment = AssessmentState::Complete;
        bool incomplete = result.collectionTruncated, anySuccess = false;
        for (const auto& coverage : result.sources) {
            anySuccess |= coverage.status == L"complete" || coverage.status == L"partial" || coverage.collected != 0;
            incomplete |= coverage.status != L"complete";
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
        return result;
    }
}
