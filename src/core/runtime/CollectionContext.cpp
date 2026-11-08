#include "../system/Win32.h"
#include "CollectionContext.h"
#include <sddl.h>
#include <cwchar>

namespace wgwc::core {
    bool CollectionContext::IsCancelled() const {
        return externalCancel && externalCancel->load();
    }

    bool CollectionContext::IsTimedOut() const {
        return deadlineTick && TickNow() >= deadlineTick;
    }

    CollectionStatus CollectionContext::StopStatus() const {
        return IsCancelled() ? CollectionStatus::Cancelled : CollectionStatus::TimedOut;
    }

    std::uint64_t TickNow() {
        return GetTickCount64();
    }

    std::uint64_t CurrentFileTime() {
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        return (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    }

    std::wstring FormatFileTime(std::uint64_t value) {
        if (!value)
            return {};
        FILETIME ft{ static_cast<DWORD>(value), static_cast<DWORD>(value >> 32) };
        SYSTEMTIME st{};
        if (!FileTimeToSystemTime(&ft, &st))
            return {};
        wchar_t text[40]{};
        swprintf_s(text, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                   st.wSecond, st.wMilliseconds);
        return text;
    }

    std::wstring UtcNow() {
        return FormatFileTime(CurrentFileTime());
    }

    ExecutionIdentity GetExecutionIdentity() {
        ExecutionIdentity identity;
        BOOL wow64 = FALSE;
        if (IsWow64Process(GetCurrentProcess(), &wow64) && wow64)
            identity.osBits = 64;
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
            return identity;
        UniqueHandle token(raw);
        TOKEN_ELEVATION elevation{};
        DWORD size = 0;
        if (!GetTokenInformation(raw, TokenElevation, &elevation, sizeof(elevation), &size))
            return identity;
        identity.elevated = elevation.TokenIsElevated != 0;
        identity.elevationState = FieldState::Available;
        GetTokenInformation(raw, TokenUser, nullptr, 0, &size);
        if (!size || size > 65536)
            return identity;
        std::vector<unsigned char> buffer(size);
        if (!GetTokenInformation(raw, TokenUser, buffer.data(), size, &size))
            return identity;
        LPWSTR sid = nullptr;
        if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid)) {
            identity.userSid = sid;
            LocalFree(sid);
            identity.state = FieldState::Available;
        }
        return identity;
    }
}
