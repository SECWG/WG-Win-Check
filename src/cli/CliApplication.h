#pragma once
#include <atomic>
#include <cstdint>

namespace wgwc::cli {
    int RunCli(int argc, wchar_t* argv[], const std::atomic_bool& cancelled,
               const std::atomic<std::uint64_t>& generation);
}
