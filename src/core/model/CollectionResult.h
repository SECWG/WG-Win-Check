#pragma once
#include "CollectionIssue.h"
#include "RiskFinding.h"
#include <cstddef>
#include <vector>

namespace wgwc::core {
    enum class CollectionStatus {
        Complete,
        Partial,
        Failed,
        Cancelled,
        TimedOut
    };

    inline const wchar_t* StatusName(CollectionStatus status) {
        switch (status) {
        case CollectionStatus::Complete:
            return L"complete";
        case CollectionStatus::Partial:
            return L"partial";
        case CollectionStatus::Cancelled:
            return L"cancelled";
        case CollectionStatus::TimedOut:
            return L"timed_out";
        default:
            return L"failed";
        }
    }

    inline int StatusExitCode(CollectionStatus status) {
        switch (status) {
        case CollectionStatus::Complete:
            return 0;
        case CollectionStatus::Partial:
            return 1;
        case CollectionStatus::Cancelled:
            return 4;
        case CollectionStatus::TimedOut:
            return 5;
        default:
            return 3;
        }
    }

    struct SourceCoverage {
        std::wstring source;
        std::wstring status = L"not_started";
        std::size_t collected = 0;
        std::uint32_t nativeCode = 0;
    };

    struct CollectionOutcome {
        CollectionStatus status = CollectionStatus::Failed;
        std::vector<RiskFinding> findings;
        std::vector<CollectionIssue> issues;
        std::vector<SourceCoverage> sources;
        std::wstring startedAt;
        std::wstring finishedAt;
        std::size_t collected = 0;
        bool collectionTruncated = false;
        AssessmentState assessment = AssessmentState::NotRequested;
    };

    template <typename T> struct CollectionResult : CollectionOutcome {
        std::vector<T> records;
    };
}
