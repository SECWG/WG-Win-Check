#include "../../system/Win32.h"
#include "TaskModule.h"
#include <taskschd.h>
#include <oleauto.h>
#include <algorithm>
#include <set>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace wgwc::core::tasks {
    namespace {
        template <class T> struct ComPtr {
            T* value = nullptr;

            ~ComPtr() {
                if (value)
                    value->Release();
            }

            ComPtr() = default;
            ComPtr(const ComPtr&) = delete;
            ComPtr& operator=(const ComPtr&) = delete;

            T** put() {
                return &value;
            }

            T* operator->() const {
                return value;
            }

            explicit operator bool() const {
                return value != nullptr;
            }
        };

        struct Apartment {
            HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);

            ~Apartment() {
                if (SUCCEEDED(result))
                    CoUninitialize();
            }
        };

        VARIANT Index(LONG value) {
            VARIANT result;
            VariantInit(&result);
            result.vt = VT_I4;
            result.lVal = value;
            return result;
        }

        void Issue(CollectionResult<Record>& result, std::size_t source, const std::wstring& key, const wchar_t* code,
                   HRESULT native, const wchar_t* message, bool fatal = false) {
            CollectionIssue issue;
            issue.source = result.sources[source].source;
            issue.objectKey = key;
            issue.code = code;
            issue.nativeCode = static_cast<std::uint32_t>(native);
            issue.message = message;
            issue.affectsCompleteness = true;
            result.issues.push_back(std::move(issue));
            auto& coverage = result.sources[source];
            coverage.status = fatal && !coverage.collected ? L"failed" : L"partial";
            coverage.nativeCode = static_cast<std::uint32_t>(native);
        }

        bool ReadStatus(HRESULT hr, FieldState& state, CollectionResult<Record>& result, std::size_t source,
                        const std::wstring& key, const wchar_t* code) {
            state = SUCCEEDED(hr) ? FieldState::Available : FieldState::Unknown;
            if (FAILED(hr))
                Issue(result, source, key, code, hr,
                      L"Task Scheduler property could not be read; its value remains unknown.");
            return SUCCEEDED(hr);
        }

        template <class Getter>
        bool ReadString(Getter get, std::wstring& value, FieldState& state, CollectionResult<Record>& result,
                        std::size_t source, const std::wstring& key, const wchar_t* code) {
            BSTR text = nullptr;
            HRESULT hr = get(&text);
            if (SUCCEEDED(hr)) {
                const auto length = text ? SysStringLen(text) : 0;
                if (length > 1024 * 1024 || (text && std::find(text, text + length, L'\0') != text + length))
                    hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                else if (text)
                    value.assign(text, length);
                else
                    value.clear();
            }
            if (text)
                SysFreeString(text);
            if (FAILED(hr))
                value.clear();
            return ReadStatus(hr, state, result, source, key, code);
        }

        void ReadDate(HRESULT hr, DATE date, std::wstring& value, FieldState& state, CollectionResult<Record>& result,
                      const std::wstring& key, const wchar_t* code) {
            if (!ReadStatus(hr, state, result, 1, key, code))
                return;
            if (date == 0) {
                state = FieldState::NotApplicable;
                return;
            }
            SYSTEMTIME time{};
            if (!VariantTimeToSystemTime(date, &time)) {
                state = FieldState::Unknown;
                Issue(result, 1, key, code, E_INVALIDARG, L"Invalid Task Scheduler local date.");
                return;
            }
            if (time.wYear < 1900) {
                state = FieldState::NotApplicable;
                return;
            }
            wchar_t text[40]{};
            swprintf_s(text, L"%04u-%02u-%02uT%02u:%02u:%02u", time.wYear, time.wMonth, time.wDay, time.wHour,
                       time.wMinute, time.wSecond);
            value = text; // 任务计划程序返回的 OLE DATE 使用本地时间，而不是 UTC。
        }

        void ReadActions(ITaskDefinition* definition, Record& record, CollectionResult<Record>& result,
                         const CollectionContext& context) {
            ComPtr<IActionCollection> actions;
            HRESULT hr = definition->get_Actions(actions.put());
            if (FAILED(hr) || !actions) {
                Issue(result, 1, record.sourceKey, L"task_actions_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot read task actions.");
                return;
            }
            LONG count = 0;
            hr = actions->get_Count(&count);
            if (FAILED(hr) || count < 0) {
                Issue(result, 1, record.sourceKey, L"task_action_count_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot read action count.");
                return;
            }
            record.actionsState = FieldState::Available;
            if (count > 256) {
                Issue(result, 1, record.sourceKey, L"task_action_budget", HRESULT_FROM_WIN32(ERROR_MORE_DATA),
                      L"Only the first 256 actions can be collected.");
                count = 256;
                record.actionsState = FieldState::Unknown;
            }
            for (LONG i = 1; i <= count && !context.ShouldStop(); ++i) {
                Action item;
                item.index = static_cast<std::size_t>(i);
                const auto key = record.sourceKey + L"#action:" + std::to_wstring(i);
                ComPtr<IAction> action;
                hr = actions->get_Item(i, action.put());
                if (FAILED(hr) || !action) {
                    Issue(result, 1, key, L"task_action_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                          L"Cannot read this action; its index is retained.");
                    record.actionsState = FieldState::Unknown;
                    record.actions.push_back(std::move(item));
                    continue;
                }
                TASK_ACTION_TYPE type = TASK_ACTION_EXEC;
                hr = action->get_Type(&type);
                ReadStatus(hr, item.typeState, result, 1, key, L"task_action_type_failed");
                if (SUCCEEDED(hr))
                    item.type = static_cast<std::uint32_t>(type);
                FieldState idState = FieldState::Unknown;
                ReadString(
                    [&](BSTR* out) {
                        return action->get_Id(out);
                    },
                    item.id, idState, result, 1, key, L"task_action_id_failed");
                if (item.typeState == FieldState::Available && type == TASK_ACTION_EXEC) {
                    ComPtr<IExecAction> exec;
                    hr = action->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(exec.put()));
                    if (SUCCEEDED(hr) && exec) {
                        ReadString(
                            [&](BSTR* out) {
                                return exec->get_Path(out);
                            },
                            item.execPath, item.execState, result, 1, key, L"task_exec_path_failed");
                        ReadString(
                            [&](BSTR* out) {
                                return exec->get_Arguments(out);
                            },
                            item.arguments, item.argumentsState, result, 1, key, L"task_arguments_failed");
                        ReadString(
                            [&](BSTR* out) {
                                return exec->get_WorkingDirectory(out);
                            },
                            item.workingDirectory, item.workingDirectoryState, result, 1, key,
                            L"task_work_directory_failed");
                        if (item.execState == FieldState::Available && item.argumentsState == FieldState::Available &&
                            item.workingDirectoryState == FieldState::Available && idState == FieldState::Available)
                            item.detailState = FieldState::Available;
                    } else
                        Issue(result, 1, key, L"task_exec_interface_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                              L"Exec action interface is unavailable.");
                } else if (item.typeState == FieldState::Available && type == TASK_ACTION_COM_HANDLER) {
                    ComPtr<IComHandlerAction> com;
                    hr = action->QueryInterface(IID_IComHandlerAction, reinterpret_cast<void**>(com.put()));
                    if (SUCCEEDED(hr) && com) {
                        ReadString(
                            [&](BSTR* out) {
                                return com->get_ClassId(out);
                            },
                            item.classId, item.classIdState, result, 1, key, L"task_class_id_failed");
                        ReadString(
                            [&](BSTR* out) {
                                return com->get_Data(out);
                            },
                            item.data, item.dataState, result, 1, key, L"task_com_data_failed");
                        if (item.classIdState == FieldState::Available && item.dataState == FieldState::Available &&
                            idState == FieldState::Available)
                            item.detailState = FieldState::Available;
                    } else
                        Issue(result, 1, key, L"task_com_interface_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                              L"COM handler action interface is unavailable.");
                } else if (item.typeState == FieldState::Available) {
                    item.detailState = FieldState::NotApplicable;
                    CollectionIssue issue;
                    issue.source = result.sources[1].source;
                    issue.objectKey = key;
                    issue.code = L"task_action_unsupported";
                    issue.message = L"Action type is retained but its payload is not interpreted.";
                    issue.affectsCompleteness = false;
                    result.issues.push_back(std::move(issue));
                }
                if (item.typeState != FieldState::Available || item.detailState == FieldState::Unknown)
                    record.actionsState = FieldState::Unknown;
                record.actions.push_back(std::move(item));
            }
            if (context.ShouldStop())
                record.actionsState = FieldState::Unknown;
        }

        void ReadTriggers(ITaskDefinition* definition, Record& record, CollectionResult<Record>& result,
                          const CollectionContext& context) {
            ComPtr<ITriggerCollection> triggers;
            HRESULT hr = definition->get_Triggers(triggers.put());
            if (FAILED(hr) || !triggers) {
                Issue(result, 1, record.sourceKey, L"task_triggers_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot read task triggers.");
                return;
            }
            LONG count = 0;
            hr = triggers->get_Count(&count);
            if (FAILED(hr) || count < 0) {
                Issue(result, 1, record.sourceKey, L"task_trigger_count_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot read trigger count.");
                return;
            }
            record.triggersState = FieldState::Available;
            if (count > 256) {
                Issue(result, 1, record.sourceKey, L"task_trigger_budget", HRESULT_FROM_WIN32(ERROR_MORE_DATA),
                      L"Only the first 256 triggers can be collected.");
                count = 256;
                record.triggersState = FieldState::Unknown;
            }
            for (LONG i = 1; i <= count && !context.ShouldStop(); ++i) {
                Trigger item;
                item.index = static_cast<std::size_t>(i);
                const auto key = record.sourceKey + L"#trigger:" + std::to_wstring(i);
                ComPtr<ITrigger> trigger;
                hr = triggers->get_Item(i, trigger.put());
                if (FAILED(hr) || !trigger) {
                    Issue(result, 1, key, L"task_trigger_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                          L"Cannot read this trigger; its index is retained.");
                    record.triggersState = FieldState::Unknown;
                    record.triggers.push_back(std::move(item));
                    continue;
                }
                TASK_TRIGGER_TYPE2 type = TASK_TRIGGER_EVENT;
                hr = trigger->get_Type(&type);
                ReadStatus(hr, item.typeState, result, 1, key, L"task_trigger_type_failed");
                if (SUCCEEDED(hr))
                    item.type = static_cast<std::uint32_t>(type);
                VARIANT_BOOL enabled = VARIANT_FALSE;
                hr = trigger->get_Enabled(&enabled);
                ReadStatus(hr, item.enabledState, result, 1, key, L"task_trigger_enabled_failed");
                item.enabled = enabled != VARIANT_FALSE;
                FieldState idState, startState, endState;
                ReadString(
                    [&](BSTR* out) {
                        return trigger->get_Id(out);
                    },
                    item.id, idState, result, 1, key, L"task_trigger_id_failed");
                ReadString(
                    [&](BSTR* out) {
                        return trigger->get_StartBoundary(out);
                    },
                    item.startBoundary, startState, result, 1, key, L"task_trigger_start_failed");
                ReadString(
                    [&](BSTR* out) {
                        return trigger->get_EndBoundary(out);
                    },
                    item.endBoundary, endState, result, 1, key, L"task_trigger_end_failed");
                if (idState == FieldState::Available && startState == FieldState::Available &&
                    endState == FieldState::Available && item.typeState == FieldState::Available &&
                    item.enabledState == FieldState::Available)
                    item.detailState = FieldState::Available;
                else
                    record.triggersState = FieldState::Unknown;
                record.triggers.push_back(std::move(item));
            }
            if (context.ShouldStop())
                record.triggersState = FieldState::Unknown;
        }

        void ReadDefinition(IRegisteredTask* task, Record& record, CollectionResult<Record>& result,
                            const CollectionContext& context) {
            if (context.ShouldStop())
                return;
            TASK_STATE state = TASK_STATE_UNKNOWN;
            HRESULT hr = task->get_State(&state);
            ReadStatus(hr, record.stateState, result, 1, record.sourceKey, L"task_state_failed");
            record.state = static_cast<std::uint32_t>(state);
            VARIANT_BOOL enabled = VARIANT_FALSE;
            hr = task->get_Enabled(&enabled);
            ReadStatus(hr, record.enabledState, result, 1, record.sourceKey, L"task_enabled_failed");
            record.enabled = enabled != VARIANT_FALSE;
            DATE time = 0;
            hr = task->get_NextRunTime(&time);
            ReadDate(hr, time, record.nextRunTimeLocal, record.nextRunState, result, record.sourceKey,
                     L"task_next_run_failed");
            time = 0;
            hr = task->get_LastRunTime(&time);
            ReadDate(hr, time, record.lastRunTimeLocal, record.lastRunState, result, record.sourceKey,
                     L"task_last_run_failed");
            LONG value = 0;
            hr = task->get_LastTaskResult(&value);
            ReadStatus(hr, record.lastResultState, result, 1, record.sourceKey, L"task_last_result_failed");
            record.lastTaskResult = static_cast<std::uint32_t>(value);
            value = 0;
            hr = task->get_NumberOfMissedRuns(&value);
            ReadStatus(hr, record.missedRunsState, result, 1, record.sourceKey, L"task_missed_runs_failed");
            record.missedRuns = static_cast<std::uint32_t>(value);
            if (context.ShouldStop())
                return;
            ComPtr<ITaskDefinition> definition;
            hr = task->get_Definition(definition.put());
            if (FAILED(hr) || !definition) {
                Issue(result, 1, record.sourceKey, L"task_definition_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot read task definition.");
                return;
            }
            record.definitionState = FieldState::Available;
            ++result.sources[1].collected;
            ComPtr<IRegistrationInfo> registration;
            hr = definition->get_RegistrationInfo(registration.put());
            if (SUCCEEDED(hr) && registration) {
                ReadString(
                    [&](BSTR* out) {
                        return registration->get_Author(out);
                    },
                    record.author, record.authorState, result, 1, record.sourceKey, L"task_author_failed");
                ReadString(
                    [&](BSTR* out) {
                        return registration->get_Description(out);
                    },
                    record.description, record.descriptionState, result, 1, record.sourceKey,
                    L"task_description_failed");
            } else
                Issue(result, 1, record.sourceKey, L"task_registration_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot read task registration metadata.");
            ComPtr<ITaskSettings> settings;
            hr = definition->get_Settings(settings.put());
            if (SUCCEEDED(hr) && settings) {
                VARIANT_BOOL hidden = VARIANT_FALSE;
                hr = settings->get_Hidden(&hidden);
                ReadStatus(hr, record.hiddenState, result, 1, record.sourceKey, L"task_hidden_setting_failed");
                record.hidden = hidden != VARIANT_FALSE;
            } else
                Issue(result, 1, record.sourceKey, L"task_settings_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot read task settings.");
            ComPtr<IPrincipal> principal;
            hr = definition->get_Principal(principal.put());
            if (SUCCEEDED(hr) && principal) {
                FieldState userState, groupState, logonState, levelState;
                ReadString(
                    [&](BSTR* out) {
                        return principal->get_UserId(out);
                    },
                    record.principalUser, userState, result, 1, record.sourceKey, L"task_principal_user_failed");
                ReadString(
                    [&](BSTR* out) {
                        return principal->get_GroupId(out);
                    },
                    record.principalGroup, groupState, result, 1, record.sourceKey, L"task_principal_group_failed");
                TASK_LOGON_TYPE logon = TASK_LOGON_NONE;
                hr = principal->get_LogonType(&logon);
                ReadStatus(hr, logonState, result, 1, record.sourceKey, L"task_logon_type_failed");
                record.logonType = static_cast<std::uint32_t>(logon);
                TASK_RUNLEVEL_TYPE level = TASK_RUNLEVEL_LUA;
                hr = principal->get_RunLevel(&level);
                ReadStatus(hr, levelState, result, 1, record.sourceKey, L"task_run_level_failed");
                record.runLevel = static_cast<std::uint32_t>(level);
                if (userState == FieldState::Available && groupState == FieldState::Available &&
                    logonState == FieldState::Available && levelState == FieldState::Available)
                    record.principalState = FieldState::Available;
            } else
                Issue(result, 1, record.sourceKey, L"task_principal_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot read task principal.");
            if (!context.ShouldStop())
                ReadActions(definition.value, record, result, context);
            if (!context.ShouldStop())
                ReadTriggers(definition.value, record, result, context);
        }

        void Enumerate(ITaskFolder* folder, const std::wstring& path, std::size_t depth, std::size_t& folderCount,
                       std::set<std::wstring>& keys, CollectionResult<Record>& result,
                       const CollectionContext& context) {
            if (context.ShouldStop() || result.collectionTruncated)
                return;
            if (depth > 64 || ++folderCount > 100000) {
                result.collectionTruncated = true;
                Issue(result, 0, path, L"task_folder_budget", HRESULT_FROM_WIN32(ERROR_MORE_DATA),
                      L"Task folder traversal reached its safety budget.");
                return;
            }
            ComPtr<IRegisteredTaskCollection> tasks;
            HRESULT hr = folder->GetTasks(TASK_ENUM_HIDDEN, tasks.put());
            if (SUCCEEDED(hr) && tasks) {
                if (result.sources[0].status == L"not_started")
                    result.sources[0].status = L"complete";
                LONG count = 0;
                hr = tasks->get_Count(&count);
                if (FAILED(hr) || count < 0)
                    Issue(result, 0, path, L"task_count_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                          L"Cannot read task count.");
                else
                    for (LONG i = 1; i <= count && !context.ShouldStop() && !result.collectionTruncated; ++i) {
                        if (result.records.size() >= context.maxRecords) {
                            result.collectionTruncated = true;
                            Issue(result, 0, path, L"collection_limit", HRESULT_FROM_WIN32(ERROR_MORE_DATA),
                                  L"Task collection reached its record budget.");
                            break;
                        }
                        ComPtr<IRegisteredTask> task;
                        hr = tasks->get_Item(Index(i), task.put());
                        if (FAILED(hr) || !task) {
                            Issue(result, 0, path + L"#item:" + std::to_wstring(i), L"task_item_failed",
                                  FAILED(hr) ? hr : E_UNEXPECTED, L"Task cannot be opened; other tasks are retained.");
                            continue;
                        }
                        Record record;
                        FieldState nameState;
                        ReadString(
                            [&](BSTR* out) {
                                return task->get_Name(out);
                            },
                            record.name, nameState, result, 0, path, L"task_name_failed");
                        ReadString(
                            [&](BSTR* out) {
                                return task->get_Path(out);
                            },
                            record.path, record.pathState, result, 0, path, L"task_path_failed");
                        if (record.path.empty()) {
                            record.pathState = FieldState::Unknown;
                            if (record.name.empty()) {
                                Issue(result, 0, path, L"task_identity_unavailable", E_UNEXPECTED,
                                      L"Task identity is unavailable.");
                                continue;
                            }
                            record.path = path + (path == L"\\" ? L"" : L"\\") + record.name;
                        }
                        if (record.name.empty())
                            record.name = record.path.substr(record.path.find_last_of(L'\\') + 1);
                        record.sourceKey = record.path;
                        if (!keys.insert(rules::ToLower(record.sourceKey)).second)
                            continue;
                        record.source = result.sources[0].source;
                        record.observedAt = result.startedAt;
                        if (result.sources[1].status == L"not_started")
                            result.sources[1].status = L"complete";
                        ReadDefinition(task.value, record, result, context);
                        result.records.push_back(std::move(record));
                        ++result.sources[0].collected;
                    }
            } else
                Issue(result, 0, path, L"task_folder_tasks_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot enumerate tasks in this folder.");
            if (context.ShouldStop() || result.collectionTruncated)
                return;
            ComPtr<ITaskFolderCollection> folders;
            hr = folder->GetFolders(0, folders.put());
            if (FAILED(hr) || !folders) {
                Issue(result, 0, path, L"task_subfolders_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot enumerate task subfolders.");
                return;
            }
            LONG count = 0;
            hr = folders->get_Count(&count);
            if (FAILED(hr) || count < 0) {
                Issue(result, 0, path, L"task_folder_count_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                      L"Cannot read folder count.");
                return;
            }
            for (LONG i = 1; i <= count && !context.ShouldStop() && !result.collectionTruncated; ++i) {
                ComPtr<ITaskFolder> subfolder;
                hr = folders->get_Item(Index(i), subfolder.put());
                if (FAILED(hr) || !subfolder) {
                    Issue(result, 0, path + L"#folder:" + std::to_wstring(i), L"task_subfolder_failed",
                          FAILED(hr) ? hr : E_UNEXPECTED, L"Cannot open task subfolder.");
                    continue;
                }
                std::wstring childPath;
                FieldState pathState;
                ReadString(
                    [&](BSTR* out) {
                        return subfolder->get_Path(out);
                    },
                    childPath, pathState, result, 0, path, L"task_folder_path_failed");
                if (childPath.empty())
                    childPath = path + L"#folder:" + std::to_wstring(i);
                Enumerate(subfolder.value, childPath, depth + 1, folderCount, keys, result, context);
            }
        }
    }

    CollectionResult<Record> CollectTasks(const Options& options, const CollectionContext& context) {
        CollectionResult<Record> result;
        result.startedAt = UtcNow();
        for (const auto source :
             { L"TaskScheduler:local-folders-and-tasks", L"TaskScheduler:definitions", L"task-file-evidence" }) {
            SourceCoverage coverage;
            coverage.source = source;
            result.sources.push_back(std::move(coverage));
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
        Apartment apartment;
        if (FAILED(apartment.result) && apartment.result != RPC_E_CHANGED_MODE) {
            Issue(result, 0, L"", L"task_com_initialize_failed", apartment.result,
                  L"Cannot initialize COM for Task Scheduler.", true);
            finish();
            return result;
        }
        ComPtr<ITaskService> service;
        HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService,
                                      reinterpret_cast<void**>(service.put()));
        if (FAILED(hr) || !service) {
            Issue(result, 0, L"", L"task_scheduler_unavailable", FAILED(hr) ? hr : E_UNEXPECTED,
                  L"Task Scheduler is unavailable.", true);
            finish();
            return result;
        }
        VARIANT empty;
        VariantInit(&empty);
        hr = service->Connect(empty, empty, empty, empty);
        if (FAILED(hr)) {
            Issue(result, 0, L"", L"task_scheduler_connect_failed", hr, L"Cannot connect to the local Task Scheduler.",
                  true);
            finish();
            return result;
        }
        ComPtr<ITaskFolder> root;
        BSTR rootPath = SysAllocString(L"\\");
        if (!rootPath) {
            Issue(result, 0, L"", L"task_root_allocation_failed", E_OUTOFMEMORY, L"Cannot allocate task root path.",
                  true);
            finish();
            return result;
        }
        hr = service->GetFolder(rootPath, root.put());
        SysFreeString(rootPath);
        if (FAILED(hr) || !root) {
            Issue(result, 0, L"\\", L"task_root_failed", FAILED(hr) ? hr : E_UNEXPECTED,
                  L"Cannot read the root task folder.", true);
            finish();
            return result;
        }
        std::set<std::wstring> keys;
        std::size_t folderCount = 0;
        Enumerate(root.value, L"\\", 0, folderCount, keys, result, context);
        if (!context.ShouldStop()) {
            if (result.sources[1].status == L"not_started")
                result.sources[1].status = L"complete";
            result.sources[2].status = L"complete";
        }
        files::EvidenceCache cache;
        rules::ClearDllSideLoadingRiskCache();
        for (auto& record : result.records) {
            for (auto& action : record.actions) {
                if (context.ShouldStop())
                    break;
                std::vector<Target> targets;
                if (action.typeState == FieldState::Available && action.type == TASK_ACTION_EXEC) {
                    targets = ResolveExec(action);
                    bool stable = !targets.empty() && action.detailState == FieldState::Available;
                    for (const auto& target : targets)
                        stable &= target.path.stable && target.source != L"exec-fallback";
                    action.associationState = stable ? FieldState::Available : FieldState::Unknown;
                } else if (action.typeState == FieldState::Available && action.type == TASK_ACTION_COM_HANDLER &&
                           action.classIdState == FieldState::Available) {
                    auto resolved = ResolveComHandler(action.classId, context);
                    targets = std::move(resolved.targets);
                    action.associationState = resolved.state;
                    for (auto& issue : resolved.issues) {
                        issue.objectKey =
                            record.sourceKey + L"#action:" + std::to_wstring(action.index) + L" " + issue.objectKey;
                        result.sources[2].status = L"partial";
                        result.sources[2].nativeCode = issue.nativeCode;
                        result.issues.push_back(std::move(issue));
                    }
                } else
                    continue;
                if (targets.empty() && action.type == TASK_ACTION_EXEC && !context.ShouldStop())
                    Issue(result, 2, record.sourceKey, L"task_file_unresolved", HRESULT_FROM_WIN32(ERROR_NOT_FOUND),
                          L"No stable executable action file could be identified.");
                for (auto& target : targets) {
                    RelatedFile related;
                    related.actionIndex = action.index;
                    related.target = std::move(target);
                    if (related.target.path.stable && !context.ShouldStop()) {
                        related.file = cache.Get(related.target.path.value, options.verifySignatures, context);
                        related.file.evidence.source = result.sources[2].source;
                        ++result.sources[2].collected;
                        for (auto issue : related.file.evidence.issues) {
                            issue.source = result.sources[2].source;
                            issue.objectKey = record.sourceKey + L"#action:" + std::to_wstring(action.index);
                            if (issue.affectsCompleteness) {
                                result.sources[2].status = L"partial";
                                result.sources[2].nativeCode = issue.nativeCode;
                            }
                            result.issues.push_back(std::move(issue));
                        }
                        const auto& evidence = related.file.evidence;
                        if (evidence.existence == FieldState::Available && evidence.exists && !related.file.directory &&
                            evidence.signatureState == FieldState::Available &&
                            evidence.signature == SignatureState::Signed && !context.ShouldStop()) {
                            related.sideLoadingRisk =
                                rules::DetectDllSideLoadingRisk(related.target.path.value, SignatureState::Signed);
                            related.sideLoadingState = FieldState::Available;
                        } else if (evidence.signatureState == FieldState::Available &&
                                   evidence.signature != SignatureState::Unknown)
                            related.sideLoadingState = FieldState::NotApplicable;
                    } else {
                        related.file.evidence.originalValue = related.target.path.value;
                        related.file.evidence.source = result.sources[2].source;
                        related.file.evidence.resolution = related.file.evidence.existence = FieldState::Unknown;
                        related.file.evidence.signatureState =
                            options.verifySignatures ? FieldState::Unknown : FieldState::NotRequested;
                        related.file.attributesState = related.file.versionState = FieldState::Unknown;
                        if (!context.ShouldStop())
                            Issue(result, 2, record.sourceKey, L"task_file_unresolved",
                                  HRESULT_FROM_WIN32(ERROR_NOT_FOUND),
                                  L"Action path is unresolved; do not infer a missing or unsigned file.");
                    }
                    action.relatedFileIndexes.push_back(record.relatedFiles.size());
                    record.relatedFiles.push_back(std::move(related));
                }
            }
            record.assessment = AssessRisk(record);
            if (!record.assessment.hits.empty()) {
                RiskFinding finding;
                finding.moduleId = L"task";
                finding.sourceKey = record.sourceKey;
                finding.objectName = record.name;
                finding.updatedAt = record.observedAt;
                finding.assessment = record.assessment;
                result.findings.push_back(std::move(finding));
            }
        }
        if (context.ShouldStop())
            for (auto& source : result.sources)
                if (source.status != L"not_started")
                    source.status = context.IsCancelled() ? L"cancelled" : L"timed_out";
        if (context.progress)
            context.progress(L"task", result.records.size());
        finish();
        return result;
    }
}
