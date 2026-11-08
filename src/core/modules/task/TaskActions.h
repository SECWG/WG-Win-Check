#pragma once

#include <windows.h>
#include <taskschd.h>
#include <oleauto.h>
#include <string>

namespace wgwc::core::tasks::actions {
    enum class Operation {
        Run,
        Enable,
        Disable,
        Delete
    };
    enum class Outcome {
        Failed,
        Accepted,
        Applied,
        AlreadySatisfied,
        Disabled,
        DemandStartDenied,
        Unconfirmed
    };

    struct Result {
        Outcome outcome = Outcome::Failed;
        HRESULT error = S_OK;
    };

    namespace detail {
        template <class T> struct Ptr {
            T* value = nullptr;
            Ptr() = default;
            Ptr(const Ptr&) = delete;
            Ptr& operator=(const Ptr&) = delete;

            ~Ptr() {
                if (value)
                    value->Release();
            }
        };

        struct Apartment {
            HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);

            ~Apartment() {
                if (SUCCEEDED(result))
                    CoUninitialize();
            }
        };

        struct Text {
            BSTR value;

            explicit Text(const std::wstring& text) : value(SysAllocString(text.c_str())) {}

            Text(const Text&) = delete;
            Text& operator=(const Text&) = delete;

            ~Text() {
                SysFreeString(value);
            }
        };

        inline Result Failure(HRESULT error) {
            return { Outcome::Failed, error };
        }

        inline HRESULT PointerError(HRESULT error) {
            return FAILED(error) ? error : E_UNEXPECTED;
        }
    }

    inline bool NeedsRefresh(const Result& result) {
        return result.outcome != Outcome::Failed || result.error == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
               result.error == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    }

    // 这是 GUI 操作辅助函数，不是采集器或 CLI 修改命令。
    // 提交 Run 请求时，不绕过任务约束或多实例策略。
    inline Result Execute(const std::wstring& path, Operation operation) {
        if (operation != Operation::Run && operation != Operation::Enable && operation != Operation::Disable &&
            operation != Operation::Delete)
            return detail::Failure(E_INVALIDARG);
        if (path.size() < 2 || path.front() != L'\\' || path.back() == L'\\' || path.find(L'\0') != std::wstring::npos)
            return detail::Failure(E_INVALIDARG);
        const auto slash = path.find_last_of(L'\\');
        const auto folderPath = slash == 0 ? std::wstring(L"\\") : path.substr(0, slash);
        const auto taskName = path.substr(slash + 1);

        detail::Apartment apartment;
        if (FAILED(apartment.result) && apartment.result != RPC_E_CHANGED_MODE)
            return detail::Failure(apartment.result);
        detail::Ptr<ITaskService> service;
        HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService,
                                      reinterpret_cast<void**>(&service.value));
        if (FAILED(hr) || !service.value)
            return detail::Failure(detail::PointerError(hr));
        VARIANT empty;
        VariantInit(&empty);
        hr = service.value->Connect(empty, empty, empty, empty);
        if (FAILED(hr))
            return detail::Failure(hr);

        detail::Text folderName(folderPath), name(taskName);
        if (!folderName.value || !name.value)
            return detail::Failure(E_OUTOFMEMORY);
        detail::Ptr<ITaskFolder> folder;
        hr = service.value->GetFolder(folderName.value, &folder.value);
        if (FAILED(hr) || !folder.value)
            return detail::Failure(detail::PointerError(hr));
        detail::Ptr<IRegisteredTask> task;
        hr = folder.value->GetTask(name.value, &task.value);
        if (FAILED(hr) || !task.value)
            return detail::Failure(detail::PointerError(hr));

        TASK_STATE currentState = TASK_STATE_UNKNOWN;
        hr = task.value->get_State(&currentState);
        if (FAILED(hr))
            return detail::Failure(hr);
        // 已有运行实例并不直接禁止再次提交 Run；
        // 由任务计划程序的策略决定新请求是执行、排队还是忽略。
        if (operation == Operation::Delete) {
            hr = folder.value->DeleteTask(name.value, 0);
            return FAILED(hr) ? detail::Failure(hr) : Result{ Outcome::Applied, hr };
        }

        VARIANT_BOOL enabled = VARIANT_FALSE;
        hr = task.value->get_Enabled(&enabled);
        if (FAILED(hr))
            return detail::Failure(hr);
        if (operation == Operation::Enable || operation == Operation::Disable) {
            const bool desired = operation == Operation::Enable;
            if ((enabled != VARIANT_FALSE) == desired)
                return { Outcome::AlreadySatisfied, S_OK };
            hr = task.value->put_Enabled(desired ? VARIANT_TRUE : VARIANT_FALSE);
            return FAILED(hr) ? detail::Failure(hr) : Result{ Outcome::Applied, hr };
        }
        if (enabled == VARIANT_FALSE)
            return { Outcome::Disabled, SCHED_E_TASK_DISABLED };

        detail::Ptr<ITaskDefinition> definition;
        hr = task.value->get_Definition(&definition.value);
        if (FAILED(hr) || !definition.value)
            return detail::Failure(detail::PointerError(hr));
        detail::Ptr<ITaskSettings> settings;
        hr = definition.value->get_Settings(&settings.value);
        if (FAILED(hr) || !settings.value)
            return detail::Failure(detail::PointerError(hr));
        VARIANT_BOOL allowed = VARIANT_FALSE;
        hr = settings.value->get_AllowDemandStart(&allowed);
        if (FAILED(hr))
            return detail::Failure(hr);
        if (allowed == VARIANT_FALSE)
            return { Outcome::DemandStartDenied, S_OK };

        detail::Ptr<IRunningTask> instance;
        hr = task.value->Run(empty, &instance.value);
        if (hr == SCHED_E_TASK_DISABLED)
            return { Outcome::Disabled, hr };
        if (FAILED(hr))
            return detail::Failure(hr);
        // 仅返回 S_OK 不能证明任务已经启动；即使返回实例，
        // 也只表示请求已提交，不能证明任务动作执行成功。
        return { instance.value ? Outcome::Accepted : Outcome::Unconfirmed, hr };
    }
}
