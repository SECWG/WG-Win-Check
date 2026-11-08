#include "Win32.h"
#include "IpLookupService.h"
#include <winhttp.h>
#include <algorithm>
#include <deque>
#include <mutex>

#pragma comment(lib, "winhttp.lib")

namespace wgwc::core::ip {
    namespace {
        struct InternetHandle {
            HINTERNET value = nullptr;

            explicit InternetHandle(HINTERNET handle) : value(handle) {}

            ~InternetHandle() {
                if (value)
                    WinHttpCloseHandle(value);
            }

            InternetHandle(const InternetHandle&) = delete;
            InternetHandle& operator=(const InternetHandle&) = delete;
        };

        bool Timeouts(HINTERNET request, const CollectionContext& context) {
            if (context.ShouldStop()) {
                SetLastError(ERROR_CANCELLED);
                return false;
            }
            std::uint64_t remaining = 8000;
            if (context.deadlineTick) {
                const auto now = TickNow();
                if (now >= context.deadlineTick) {
                    SetLastError(ERROR_TIMEOUT);
                    return false;
                }
                remaining = (std::min)(remaining, context.deadlineTick - now);
            }
            const int timeout = static_cast<int>((std::max)(std::uint64_t{ 1 }, remaining));
            return WinHttpSetTimeouts(request, timeout, timeout, timeout, timeout) != FALSE;
        }

        bool HeaderNumber(HINTERNET request, const wchar_t* name, DWORD& value) {
            wchar_t text[32]{};
            DWORD bytes = sizeof(text);
            if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, name, text, &bytes, WINHTTP_NO_HEADER_INDEX))
                return false;
            const std::size_t length = bytes / sizeof(wchar_t);
            if (!length || length >= 32)
                return false;
            std::uint64_t number = 0;
            for (std::size_t i = 0; i < length; ++i) {
                if (text[i] < L'0' || text[i] > L'9')
                    return false;
                number = number * 10 + text[i] - L'0';
                if (number > MAXDWORD)
                    return false;
            }
            value = static_cast<DWORD>(number);
            return true;
        }
    }

    HttpResponse QueryIpApi(const std::vector<std::wstring>& addresses, const CollectionContext& context) {
        HttpResponse result;
        auto fail = [&](const wchar_t* code, const wchar_t* message, DWORD native) {
            result.errorCode = code;
            result.message = message;
            result.nativeCode = native;
            return result;
        };
        if (addresses.empty() || addresses.size() > 100)
            return fail(L"INVALID_BATCH_SIZE", L"The provider accepts 1 to 100 IP literals per batch.",
                        ERROR_INVALID_PARAMETER);
        std::string body = "[";
        for (const auto& input : addresses) {
            const auto address = ParseAddress(input);
            if (address.type != AddressType::Public)
                return fail(L"IP_NOT_PUBLIC", L"Only validated public IP literals may be submitted to the provider.",
                            ERROR_INVALID_PARAMETER);
            if (body.size() > 1)
                body += ',';
            body += '"';
            for (const auto c : address.normalized)
                body += static_cast<char>(c);
            body += '"';
        }
        body += ']';
        // 限额仅在当前进程内共享；不同 CLI 调用仍需遵守服务端的
        // 同一来源 IP 限流，并处理 HTTP 429 和 retryAfterSeconds。
        static std::mutex mutex;
        static std::deque<std::uint64_t> sent;
        static std::uint64_t blockedUntil = 0;
        std::unique_lock<std::mutex> lock(mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return fail(L"IP_LOOKUP_BUSY", L"Another IP lookup is already active in this process.", ERROR_BUSY);
        if (context.ShouldStop())
            return fail(L"IP_LOOKUP_STOPPED", L"The IP lookup was stopped before transmission.", ERROR_CANCELLED);
        const auto now = TickNow();
        while (!sent.empty() && now - sent.front() >= 60000)
            sent.pop_front();
        if (sent.size() >= 15)
            blockedUntil = (std::max)(blockedUntil, sent.front() + 60000);
        if (blockedUntil > now) {
            result.statusCode = 429;
            result.retryAfterSeconds = static_cast<std::uint32_t>((blockedUntil - now + 999) / 1000);
            return result;
        }
        InternetHandle session(WinHttpOpen(L"WG-Win-Check/IP-Lookup", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
        if (!session.value)
            return fail(L"IP_HTTP_OPEN_FAILED", L"Could not initialize WinHTTP.", GetLastError());
        InternetHandle connection(WinHttpConnect(session.value, L"ip-api.com", INTERNET_DEFAULT_HTTP_PORT, 0));
        if (!connection.value)
            return fail(L"IP_HTTP_CONNECT_FAILED", L"Could not create the provider connection.", GetLastError());
        InternetHandle request(WinHttpOpenRequest(
            connection.value, L"POST", L"/batch?lang=zh-CN&fields=status,message,query,country,regionName,city,isp",
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
        if (!request.value)
            return fail(L"IP_HTTP_REQUEST_FAILED", L"Could not create the provider request.", GetLastError());
        DWORD disabled = WINHTTP_DISABLE_REDIRECTS;
        DWORD logon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
        if (!WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)) ||
            !WinHttpSetOption(request.value, WINHTTP_OPTION_AUTOLOGON_POLICY, &logon, sizeof(logon)) ||
            !Timeouts(request.value, context))
            return fail(L"IP_HTTP_POLICY_FAILED", L"Could not apply request safety settings.", GetLastError());
        sent.push_back(TickNow());
        result.networkAttempted = true;
        if (!WinHttpSendRequest(request.value, L"Content-Type: application/json\r\n", static_cast<DWORD>(-1L),
                                body.data(), static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0) ||
            !Timeouts(request.value, context) || !WinHttpReceiveResponse(request.value, nullptr))
            return fail(L"IP_HTTP_REQUEST_FAILED", L"The provider request failed or timed out.", GetLastError());
        DWORD status = 0, statusSize = sizeof(status);
        if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX))
            return fail(L"IP_HTTP_STATUS_FAILED", L"The HTTP response status could not be read.", GetLastError());
        result.statusCode = status;
        DWORD remaining = 0, ttl = 0;
        const bool hasRemaining = HeaderNumber(request.value, L"X-Rl", remaining);
        const bool hasTtl = HeaderNumber(request.value, L"X-Ttl", ttl);
        if (status == 429 || (hasRemaining && remaining == 0)) {
            result.retryAfterSeconds = hasTtl && ttl ? (std::min)(ttl, DWORD{ 86400 }) : 60;
            blockedUntil = TickNow() + static_cast<std::uint64_t>(result.retryAfterSeconds) * 1000;
        }
        if (status != 200) {
            result.complete = true;
            return result;
        }
        DWORD expected = 0;
        const bool hasLength = HeaderNumber(request.value, L"Content-Length", expected);
        constexpr std::size_t maximum = 1024 * 1024;
        if (hasLength && expected > maximum)
            return fail(L"IP_RESPONSE_TOO_LARGE", L"The provider response exceeded 1 MiB.", ERROR_BUFFER_OVERFLOW);
        char buffer[16384];
        for (;;) {
            if (!Timeouts(request.value, context))
                return fail(L"IP_HTTP_STOPPED", L"The provider response was interrupted.", GetLastError());
            DWORD read = 0;
            if (!WinHttpReadData(request.value, buffer, sizeof(buffer), &read))
                return fail(L"IP_HTTP_READ_FAILED", L"The provider response could not be read completely.",
                            GetLastError());
            if (!read)
                break;
            if (result.body.size() + read > maximum)
                return fail(L"IP_RESPONSE_TOO_LARGE", L"The provider response exceeded 1 MiB.", ERROR_BUFFER_OVERFLOW);
            result.body.append(buffer, read);
        }
        if (hasLength && result.body.size() != expected)
            return fail(L"IP_RESPONSE_INCOMPLETE", L"The provider response length did not match Content-Length.",
                        ERROR_INVALID_DATA);
        result.complete = true;
        return result;
    }
}
