#include "ElevationPrompt.h"

#include "../resources/resource.h"

#include <shellapi.h>
#include <cwchar>
#include <string>
#include <vector>

namespace {
    constexpr INT_PTR DIALOG_RESULT_CONTINUE = 20001;
    constexpr INT_PTR DIALOG_RESULT_EXIT = 20002;
    constexpr INT_PTR DIALOG_RESULT_RELAUNCHED = 20003;

    struct PromptDialogState {
        HINSTANCE instance = nullptr;
    };

    enum class RelaunchResult {
        Success,
        Cancelled,
        Failed
    };

    std::wstring LoadResourceString(HINSTANCE instance, UINT resourceId) {
        wchar_t buffer[256] = {};
        const int length = LoadStringW(instance, resourceId, buffer, ARRAYSIZE(buffer));
        return length > 0 ? std::wstring(buffer, length) : std::wstring();
    }

    std::wstring GetExecutablePath() {
        std::vector<wchar_t> buffer(32768);
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));

        if (length == 0 || length >= buffer.size()) {
            return std::wstring();
        }

        return std::wstring(buffer.data(), length);
    }

    std::wstring GetDirectoryName(const std::wstring& path) {
        const size_t separator = path.find_last_of(L"\\/");
        return separator == std::wstring::npos ? std::wstring() : path.substr(0, separator);
    }

    std::wstring QuoteCommandLineArgument(const std::wstring& argument) {
        if (argument.empty()) {
            return L"\"\"";
        }

        if (argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
            return argument;
        }

        std::wstring quoted;
        quoted.push_back(L'\"');
        size_t backslashCount = 0;

        for (const wchar_t character : argument) {
            if (character == L'\\') {
                ++backslashCount;
                continue;
            }

            if (character == L'\"') {
                quoted.append(backslashCount * 2 + 1, L'\\');
                quoted.push_back(L'\"');
            } else {
                quoted.append(backslashCount, L'\\');
                quoted.push_back(character);
            }

            backslashCount = 0;
        }

        quoted.append(backslashCount * 2, L'\\');
        quoted.push_back(L'\"');
        return quoted;
    }

    std::wstring GetOriginalArguments() {
        int argumentCount = 0;
        LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
        if (arguments == nullptr) {
            return std::wstring();
        }

        std::wstring commandLine;
        for (int index = 1; index < argumentCount; ++index) {
            if (!commandLine.empty()) {
                commandLine.push_back(L' ');
            }
            commandLine.append(QuoteCommandLineArgument(arguments[index]));
        }

        LocalFree(arguments);
        return commandLine;
    }

    RelaunchResult RelaunchAsAdministrator(HWND owner, DWORD& errorCode) {
        errorCode = ERROR_SUCCESS;

        const std::wstring executablePath = GetExecutablePath();
        if (executablePath.empty()) {
            errorCode = GetLastError();
            if (errorCode == ERROR_SUCCESS) {
                errorCode = ERROR_FILE_NOT_FOUND;
            }
            return RelaunchResult::Failed;
        }

        const std::wstring arguments = GetOriginalArguments();
        const std::wstring workingDirectory = GetDirectoryName(executablePath);

        SHELLEXECUTEINFOW executeInfo = {};
        executeInfo.cbSize = sizeof(executeInfo);
        executeInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        executeInfo.hwnd = owner;
        executeInfo.lpVerb = L"runas";
        executeInfo.lpFile = executablePath.c_str();
        executeInfo.lpParameters = arguments.empty() ? nullptr : arguments.c_str();
        executeInfo.lpDirectory = workingDirectory.empty() ? nullptr : workingDirectory.c_str();
        executeInfo.nShow = SW_SHOWNORMAL;

        if (!ShellExecuteExW(&executeInfo)) {
            errorCode = GetLastError();
            return errorCode == ERROR_CANCELLED ? RelaunchResult::Cancelled : RelaunchResult::Failed;
        }

        if (executeInfo.hProcess == nullptr) {
            errorCode = ERROR_INVALID_HANDLE;
            return RelaunchResult::Failed;
        }

        CloseHandle(executeInfo.hProcess);
        return RelaunchResult::Success;
    }

    void SetPromptButtonsEnabled(HWND dialog, BOOL enabled) {
        EnableWindow(GetDlgItem(dialog, IDC_ELEVATION_BTN_ADMIN), enabled);
        EnableWindow(GetDlgItem(dialog, IDC_ELEVATION_BTN_CONTINUE), enabled);
        EnableWindow(GetDlgItem(dialog, IDCANCEL), enabled);
    }

    void SetPromptStatus(HWND dialog, const std::wstring& text) {
        HWND status = GetDlgItem(dialog, IDC_ELEVATION_STATUS);
        SetWindowTextW(status, text.c_str());
        UpdateWindow(status);
    }

    INT_PTR CALLBACK ElevationPromptDialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam) {
        PromptDialogState* state = reinterpret_cast<PromptDialogState*>(GetWindowLongPtrW(dialog, DWLP_USER));

        switch (message) {
        case WM_INITDIALOG: {
            state = reinterpret_cast<PromptDialogState*>(lParam);
            SetWindowLongPtrW(dialog, DWLP_USER, reinterpret_cast<LONG_PTR>(state));

            HICON icon = LoadIconW(state->instance, MAKEINTRESOURCEW(IDI_WGWINCHECK));
            if (icon != nullptr) {
                SendMessageW(dialog, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(icon));
                SendMessageW(dialog, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(icon));
            }

            SendMessageW(dialog, DM_SETDEFID, IDC_ELEVATION_BTN_ADMIN, 0);
            SetFocus(GetDlgItem(dialog, IDC_ELEVATION_BTN_ADMIN));
            return FALSE;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
            case IDC_ELEVATION_BTN_ADMIN: {
                SetPromptButtonsEnabled(dialog, FALSE);
                SetPromptStatus(dialog, LoadResourceString(state->instance, IDS_ELEVATION_REQUESTING));

                DWORD errorCode = ERROR_SUCCESS;
                const RelaunchResult result = RelaunchAsAdministrator(dialog, errorCode);
                if (result == RelaunchResult::Success) {
                    EndDialog(dialog, DIALOG_RESULT_RELAUNCHED);
                    return TRUE;
                }

                SetPromptButtonsEnabled(dialog, TRUE);
                if (result == RelaunchResult::Cancelled) {
                    SetPromptStatus(dialog, LoadResourceString(state->instance, IDS_ELEVATION_CANCELLED));
                } else {
                    const std::wstring format = LoadResourceString(state->instance, IDS_ELEVATION_FAILED);
                    wchar_t errorMessage[256] = {};
                    swprintf_s(errorMessage, ARRAYSIZE(errorMessage), format.c_str(), errorCode);
                    SetPromptStatus(dialog, errorMessage);
                }

                SendMessageW(dialog, DM_SETDEFID, IDC_ELEVATION_BTN_ADMIN, 0);
                SetFocus(GetDlgItem(dialog, IDC_ELEVATION_BTN_ADMIN));
                return TRUE;
            }

            case IDC_ELEVATION_BTN_CONTINUE:
                EndDialog(dialog, DIALOG_RESULT_CONTINUE);
                return TRUE;

            case IDCANCEL:
                EndDialog(dialog, DIALOG_RESULT_EXIT);
                return TRUE;
            }
            break;

        case WM_CLOSE:
            EndDialog(dialog, DIALOG_RESULT_EXIT);
            return TRUE;
        }

        return FALSE;
    }
}

ElevationPromptResult ShowElevationPrompt(HINSTANCE hInstance) {
    PromptDialogState state;
    state.instance = hInstance;

    const INT_PTR result = DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_ELEVATION_PROMPT), nullptr,
                                           ElevationPromptDialogProc, reinterpret_cast<LPARAM>(&state));

    if (result == DIALOG_RESULT_RELAUNCHED) {
        return ElevationPromptResult::Relaunched;
    }
    if (result == DIALOG_RESULT_EXIT) {
        return ElevationPromptResult::ExitApplication;
    }
    if (result == DIALOG_RESULT_CONTINUE) {
        return ElevationPromptResult::ContinueNormal;
    }

    const std::wstring message = LoadResourceString(hInstance, IDS_ELEVATION_DIALOG_FAILED);
    const std::wstring caption = LoadResourceString(hInstance, IDS_ELEVATION_CAPTION);
    MessageBoxW(nullptr, message.c_str(), caption.c_str(), MB_OK | MB_ICONWARNING);
    return ElevationPromptResult::ContinueNormal;
}
