#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

namespace wgwc::core {
    class UniqueHandle {
    public:
        explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}

        ~UniqueHandle() {
            if (valid())
                CloseHandle(handle_);
        }

        UniqueHandle(const UniqueHandle&) = delete;
        UniqueHandle& operator=(const UniqueHandle&) = delete;

        HANDLE get() const noexcept {
            return handle_;
        }

        bool valid() const noexcept {
            return handle_ && handle_ != INVALID_HANDLE_VALUE;
        }

    private:
        HANDLE handle_;
    };
}
