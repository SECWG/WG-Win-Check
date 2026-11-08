#include "../core/system/Win32.h"
#include "CliApplication.h"
#include "output/Output.h"

namespace {
    std::atomic_bool cancelled{ false };
    std::atomic<std::uint64_t> generation{ 0 };

    BOOL WINAPI ConsoleControl(DWORD type) {
        if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
            generation.fetch_add(1);
            cancelled.store(true);
            return TRUE;
        }
        return FALSE;
    }
}

int wmain(int argc, wchar_t* argv[]) {
    // 防止设备或介质错误弹窗阻塞无人值守调用，同时保留调用方的错误模式。
    SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS);
    const bool installed = SetConsoleCtrlHandler(ConsoleControl, TRUE) != FALSE;
    wgwc::cli::DiagnosticScope diagnostics(generation);
    const int code = wgwc::cli::RunCli(argc, argv, cancelled, generation);
    if (installed)
        SetConsoleCtrlHandler(ConsoleControl, FALSE);
    if (diagnostics.Error())
        return diagnostics.Error() == ERROR_CANCELLED ? 4 : 6;
    return code;
}
