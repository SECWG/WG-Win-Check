#include "../../system/Win32.h"
#include "AutorunModule.h"
#include <wbemidl.h>
#include <map>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace wgwc::core::autorun {
    namespace {
        template <class T> struct ComPtr {
            T* value = nullptr;

            ~ComPtr() {
                if (value)
                    value->Release();
            }

            T* operator->() const {
                return value;
            }
        };

        struct Bstr {
            BSTR value;

            explicit Bstr(const std::wstring& text)
                : value(SysAllocStringLen(text.data(), static_cast<UINT>(text.size()))) {}

            ~Bstr() {
                SysFreeString(value);
            }
        };

        struct ComScope {
            HRESULT status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);

            ~ComScope() {
                if (SUCCEEDED(status))
                    CoUninitialize();
            }
        };

        HRESULT String(IWbemClassObject* object, const wchar_t* name, std::wstring& text) {
            VARIANT value;
            VariantInit(&value);
            auto status = object->Get(name, 0, &value, nullptr, nullptr);
            text.clear();
            if (SUCCEEDED(status)) {
                if (value.vt == VT_BSTR && value.bstrVal) {
                    const auto length = SysStringLen(value.bstrVal);
                    if (length > 512 * 1024)
                        status = HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);
                    else {
                        text.assign(value.bstrVal, length);
                        if (text.find(L'\0') != std::wstring::npos) {
                            text.clear();
                            status = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                        }
                    }
                } else if (value.vt != VT_NULL && value.vt != VT_EMPTY)
                    status = WBEM_E_TYPE_MISMATCH;
            }
            VariantClear(&value);
            return status;
        }

        std::wstring RelativeReference(const std::wstring& className, const std::wstring& name) {
            std::wstring path = className + L".Name=\"";
            for (const auto ch : name) {
                if (ch == L'\\' || ch == L'"')
                    path.push_back(L'\\');
                path.push_back(ch);
            }
            return path + L"\"";
        }

        HRESULT Object(IWbemServices* services, const std::wstring& path, const CollectionContext& context,
                       ComPtr<IWbemClassObject>& object) {
            if (context.ShouldStop())
                return HRESULT_FROM_WIN32(ERROR_CANCELLED);
            Bstr reference(path);
            if (!reference.value)
                return E_OUTOFMEMORY;
            ComPtr<IWbemCallResult> call;
            auto status =
                services->GetObject(reference.value, WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, nullptr, &call.value);
            if (FAILED(status))
                return status;
            if (!call.value)
                return E_UNEXPECTED;
            do {
                if (context.ShouldStop())
                    return HRESULT_FROM_WIN32(ERROR_CANCELLED);
                status = call->GetResultObject(250, &object.value);
            } while (status == WBEM_S_TIMEDOUT);
            if (SUCCEEDED(status) && !object.value)
                return E_UNEXPECTED;
            return status;
        }

        struct Consumer {
            std::wstring command, script;
            FieldState state = FieldState::Unknown;
            HRESULT status = S_OK;
        };
    }

    void CollectWmiSubscriptions(CollectionResult<Record>& result, const CollectionContext& context) {
        const auto index = result.sources.size();
        SourceCoverage coverage;
        coverage.source = L"WMI:ROOT\\subscription:__FilterToConsumerBinding";
        result.sources.push_back(std::move(coverage));
        if (context.ShouldStop() || result.collectionTruncated)
            return;
        result.sources[index].status = L"complete";
        auto issue = [&](const std::wstring& object, const wchar_t* code, HRESULT status, const wchar_t* message,
                         bool fatal = false) {
            CollectionIssue value;
            value.source = result.sources[index].source;
            value.objectKey = object;
            value.code = code;
            value.nativeCode = static_cast<std::uint32_t>(status);
            value.message = message;
            value.affectsCompleteness = true;
            result.issues.push_back(std::move(value));
            result.sources[index].status = fatal && !result.sources[index].collected ? L"failed" : L"partial";
            result.sources[index].nativeCode = static_cast<std::uint32_t>(status);
        };
        ComScope com;
        if (FAILED(com.status) && com.status != RPC_E_CHANGED_MODE) {
            issue(L"", L"wmi_com_failed", com.status, L"Cannot initialize COM for local WMI collection.", true);
            return;
        }
        auto status = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                                           RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
        if (FAILED(status) && status != RPC_E_TOO_LATE) {
            issue(L"", L"wmi_security_failed", status, L"Cannot initialize WMI security.", true);
            return;
        }
        ComPtr<IWbemLocator> locator;
        status = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&locator.value));
        if (FAILED(status)) {
            issue(L"", L"wmi_locator_failed", status, L"Cannot create WMI locator.", true);
            return;
        }
        Bstr nameSpace(L"ROOT\\subscription");
        if (!nameSpace.value) {
            issue(L"", L"wmi_allocation_failed", E_OUTOFMEMORY, L"Cannot allocate WMI namespace.", true);
            return;
        }
        ComPtr<IWbemServices> services;
        if (context.ShouldStop()) {
            result.sources[index].status = context.IsCancelled() ? L"cancelled" : L"timed_out";
            return;
        }
        status = locator->ConnectServer(nameSpace.value, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT,
                                        nullptr, nullptr, &services.value);
        if (FAILED(status)) {
            issue(L"", L"wmi_connect_failed", status, L"Cannot read local ROOT\\subscription.", true);
            return;
        }
        status = CoSetProxyBlanket(services.value, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                                   RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        if (FAILED(status)) {
            issue(L"", L"wmi_proxy_failed", status, L"Cannot apply WMI proxy security.", true);
            return;
        }
        Bstr language(L"WQL"), query(L"SELECT Filter, Consumer FROM __FilterToConsumerBinding");
        if (!language.value || !query.value) {
            issue(L"", L"wmi_allocation_failed", E_OUTOFMEMORY, L"Cannot allocate WMI query.", true);
            return;
        }
        ComPtr<IEnumWbemClassObject> enumerator;
        status = services->ExecQuery(language.value, query.value, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                     nullptr, &enumerator.value);
        if (FAILED(status)) {
            issue(L"", L"wmi_query_failed", status, L"Cannot enumerate permanent WMI bindings.", true);
            return;
        }
        std::map<std::wstring, Consumer> consumers;
        std::map<std::wstring, FieldState> filters;
        std::size_t visited = 0;
        while (!context.ShouldStop() && !result.collectionTruncated) {
            ComPtr<IWbemClassObject> binding;
            ULONG count = 0;
            status = enumerator->Next(250, 1, &binding.value, &count);
            if (FAILED(status)) {
                issue(L"", L"wmi_enum_failed", status, L"WMI binding enumeration was interrupted.");
                break;
            }
            if (!count) {
                if (status == WBEM_S_TIMEDOUT)
                    continue;
                if (status == WBEM_S_FALSE)
                    break;
                issue(L"", L"wmi_enum_invalid", E_UNEXPECTED,
                      L"WMI returned no binding without an end-of-results status.");
                break;
            }
            if (!binding.value) {
                issue(L"", L"wmi_enum_invalid", E_UNEXPECTED, L"WMI returned a null binding.");
                break;
            }
            if (visited++ >= context.maxRecords) {
                result.collectionTruncated = true;
                issue(L"", L"collection_limit", HRESULT_FROM_WIN32(ERROR_MORE_DATA),
                      L"WMI binding enumeration reached the collection budget.");
                break;
            }
            Record record;
            record.type = Type::WmiSubscription;
            record.specialConfig = true;
            status = String(binding.value, L"Filter", record.filterReference);
            if (SUCCEEDED(status))
                status = String(binding.value, L"Consumer", record.consumerReference);
            if (FAILED(status)) {
                issue(L"", L"wmi_binding_unresolved", status, L"Cannot decode the WMI binding references.");
                continue;
            }
            const auto consumerClass = WmiReferenceClass(record.consumerReference);
            if (consumerClass != L"commandlineeventconsumer" && consumerClass != L"activescripteventconsumer")
                continue;
            if (result.records.size() >= context.maxRecords) {
                result.collectionTruncated = true;
                issue(L"", L"collection_limit", HRESULT_FROM_WIN32(ERROR_MORE_DATA),
                      L"Autorun collection reached the record budget.");
                break;
            }
            record.filterName = WmiReferenceName(record.filterReference);
            record.consumerName = WmiReferenceName(record.consumerReference);
            record.consumerType = consumerClass == L"commandlineeventconsumer" ? L"CommandLineEventConsumer"
                                                                               : L"ActiveScriptEventConsumer";
            record.sourceKey = SourceKey(record.type, record.filterReference, record.consumerReference);
            record.source = result.sources[index].source;
            record.observedAt = result.startedAt;
            record.location = L"ROOT\\subscription";
            record.name = record.consumerName.empty() ? record.consumerType : record.consumerName;
            record.command = record.filterName + L" -> " + record.name;
            record.consumerState = record.filterState = FieldState::Unknown;
            if (!record.filterName.empty() && WmiReferenceClass(record.filterReference) == L"__eventfilter") {
                const auto key = rules::ToLower(record.filterName);
                auto found = filters.find(key);
                if (found == filters.end()) {
                    ComPtr<IWbemClassObject> object;
                    status =
                        Object(services.value, RelativeReference(L"__EventFilter", record.filterName), context, object);
                    const auto state = SUCCEEDED(status) ? FieldState::Available : FieldState::Unknown;
                    found = filters.emplace(key, state).first;
                    if (FAILED(status) && !context.ShouldStop())
                        issue(record.sourceKey, L"wmi_filter_unresolved", status,
                              L"Binding exists, but its local event filter could not be read.");
                }
                record.filterState = found->second;
            } else
                issue(record.sourceKey, L"wmi_filter_reference_invalid", WBEM_E_INVALID_OBJECT_PATH,
                      L"Cannot resolve the event filter name.");
            if (!record.consumerName.empty() && !context.ShouldStop()) {
                const auto key = consumerClass + L"|" + rules::ToLower(record.consumerName);
                auto found = consumers.find(key);
                if (found == consumers.end()) {
                    Consumer consumer;
                    ComPtr<IWbemClassObject> object;
                    consumer.status = Object(
                        services.value, RelativeReference(record.consumerType, record.consumerName), context, object);
                    if (SUCCEEDED(consumer.status)) {
                        if (consumerClass == L"commandlineeventconsumer") {
                            consumer.status = String(object.value, L"CommandLineTemplate", consumer.command);
                            if (SUCCEEDED(consumer.status) && consumer.command.empty())
                                consumer.status = String(object.value, L"ExecutablePath", consumer.command);
                        } else
                            consumer.status = String(object.value, L"ScriptFilename", consumer.script);
                    }
                    consumer.state = SUCCEEDED(consumer.status) ? FieldState::Available : FieldState::Unknown;
                    found = consumers.emplace(key, std::move(consumer)).first;
                    if (FAILED(found->second.status) && !context.ShouldStop())
                        issue(record.sourceKey, L"wmi_consumer_unresolved", found->second.status,
                              L"Binding exists, but its local consumer details could not be read.");
                }
                record.consumerState = found->second.state;
                record.consumerCommand = found->second.command;
                record.scriptFilename = found->second.script;
                if (consumerClass == L"commandlineeventconsumer" && !record.consumerCommand.empty())
                    record.command += L" | " + record.consumerCommand;
                else if (consumerClass == L"activescripteventconsumer" && !record.scriptFilename.empty()) {
                    const auto association = ResolveFile(record.scriptFilename);
                    record.filePath = record.associatedFile = association.associatedFile;
                    record.associationStable = association.stable;
                }
            } else if (!context.ShouldStop())
                issue(record.sourceKey, L"wmi_consumer_reference_invalid", WBEM_E_INVALID_OBJECT_PATH,
                      L"Cannot resolve the consumer name.");
            result.records.push_back(std::move(record));
            ++result.sources[index].collected;
        }
        if (context.ShouldStop())
            result.sources[index].status = context.IsCancelled() ? L"cancelled" : L"timed_out";
    }
}
