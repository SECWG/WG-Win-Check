#pragma once
#include "../model/CollectionResult.h"
#include <atomic>
#include <functional>
#include <memory>

namespace wgwc::core {
    namespace files {
        class EvidenceCache;
    }

    // 取消标记由调用方持有，生命周期必须覆盖本次采集及后台任务。
    struct CollectionContext {
        const std::atomic_bool* externalCancel = nullptr;
        std::uint64_t deadlineTick = 0;
        std::size_t maxRecords = 100000;
        std::function<void(const std::wstring&, std::size_t)> progress;
        // 可选文件证据仅由同一轮采集中的模块共享，不跨刷新复用。
        std::shared_ptr<files::EvidenceCache> fileCache;
        bool IsCancelled() const;
        bool IsTimedOut() const;

        bool ShouldStop() const {
            return IsCancelled() || IsTimedOut();
        }

        CollectionStatus StopStatus() const;
    };

    struct ExecutionIdentity {
        std::wstring userSid;
        FieldState state = FieldState::Unknown;
        bool elevated = false;
        unsigned processBits = sizeof(void*) * 8;
        unsigned osBits = sizeof(void*) * 8;
        FieldState elevationState = FieldState::Unknown;
    };

    std::uint64_t CurrentFileTime();
    std::wstring FormatFileTime(std::uint64_t value);
    std::wstring UtcNow();
    std::uint64_t TickNow();
    ExecutionIdentity GetExecutionIdentity();
}
