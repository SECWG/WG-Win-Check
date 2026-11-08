#pragma once

#include <windows.h>
#include <string>

namespace wgwc::core::services::actions {
    enum class Operation {
        Start,
        Stop,
        SetAuto,
        SetManual,
        Disable,
        Delete
    };
    enum class Outcome {
        Failed,
        Accepted,
        Applied,
        AlreadySatisfied,
        NotReady,
        StopUnsupported
    };

    struct Result {
        Outcome outcome = Outcome::Failed;
        DWORD error = ERROR_SUCCESS;
        DWORD currentState = 0;
    };

    namespace detail {
        struct Handle {
            SC_HANDLE value = nullptr;
            Handle() = default;
            Handle(const Handle&) = delete;
            Handle& operator=(const Handle&) = delete;

            ~Handle() {
                if (value)
                    CloseServiceHandle(value);
            }
        };

        inline Result Failure(Operation operation, DWORD error, DWORD state = 0) {
            const bool satisfied = (operation == Operation::Start && error == ERROR_SERVICE_ALREADY_RUNNING) ||
                                   (operation == Operation::Stop && error == ERROR_SERVICE_NOT_ACTIVE) ||
                                   (operation == Operation::Delete && error == ERROR_SERVICE_MARKED_FOR_DELETE);
            return { satisfied ? Outcome::AlreadySatisfied : Outcome::Failed, error, state };
        }
    }

    // 仅操作刚查询到的服务句柄，不等待进行中的状态转换，
    // 也不终止承载该服务的进程。
    inline Result Execute(const std::wstring& name, Operation operation) {
        if (name.empty())
            return { Outcome::Failed, ERROR_INVALID_NAME, 0 };
        DWORD access = SERVICE_QUERY_STATUS;
        switch (operation) {
        case Operation::Start:
            access |= SERVICE_START;
            break;
        case Operation::Stop:
            access |= SERVICE_STOP;
            break;
        case Operation::SetAuto:
        case Operation::SetManual:
        case Operation::Disable:
            access |= SERVICE_CHANGE_CONFIG;
            break;
        case Operation::Delete:
            access |= DELETE;
            break;
        default:
            return { Outcome::Failed, ERROR_INVALID_PARAMETER, 0 };
        }

        detail::Handle manager;
        manager.value = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!manager.value)
            return detail::Failure(operation, GetLastError());
        detail::Handle service;
        service.value = OpenServiceW(manager.value, name.c_str(), access);
        if (!service.value)
            return detail::Failure(operation, GetLastError());

        SERVICE_STATUS_PROCESS status{};
        DWORD needed = 0;
        if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status),
                                  sizeof(status), &needed))
            return detail::Failure(operation, GetLastError());

        const DWORD state = status.dwCurrentState;
        BOOL ok = FALSE;
        switch (operation) {
        case Operation::Start:
            if (state == SERVICE_RUNNING)
                return { Outcome::AlreadySatisfied, ERROR_SUCCESS, state };
            if (state != SERVICE_STOPPED)
                return { Outcome::NotReady, ERROR_SUCCESS, state };
            ok = StartServiceW(service.value, 0, nullptr);
            break;
        case Operation::Stop: {
            if (state == SERVICE_STOPPED)
                return { Outcome::AlreadySatisfied, ERROR_SUCCESS, state };
            if (state != SERVICE_RUNNING && state != SERVICE_PAUSED)
                return { Outcome::NotReady, ERROR_SUCCESS, state };
            if (!(status.dwControlsAccepted & SERVICE_ACCEPT_STOP))
                return { Outcome::StopUnsupported, ERROR_SUCCESS, state };
            SERVICE_STATUS updated{};
            ok = ControlService(service.value, SERVICE_CONTROL_STOP, &updated);
            break;
        }
        case Operation::Delete:
            if (state != SERVICE_STOPPED)
                return { Outcome::NotReady, ERROR_SUCCESS, state };
            ok = DeleteService(service.value);
            break;
        case Operation::SetAuto:
        case Operation::SetManual:
        case Operation::Disable: {
            const DWORD startType = operation == Operation::SetAuto
                                        ? SERVICE_AUTO_START
                                        : (operation == Operation::SetManual ? SERVICE_DEMAND_START : SERVICE_DISABLED);
            ok = ChangeServiceConfigW(service.value, SERVICE_NO_CHANGE, startType, SERVICE_NO_CHANGE, nullptr, nullptr,
                                      nullptr, nullptr, nullptr, nullptr, nullptr);
            break;
        }
        default:
            return { Outcome::Failed, ERROR_INVALID_PARAMETER, state };
        }
        // 在 RAII 关闭任一句柄之前保存错误码，避免清理操作覆盖原始错误。
        if (!ok)
            return detail::Failure(operation, GetLastError(), state);
        const bool config =
            operation == Operation::SetAuto || operation == Operation::SetManual || operation == Operation::Disable;
        return { config ? Outcome::Applied : Outcome::Accepted, ERROR_SUCCESS, state };
    }
}
