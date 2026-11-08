#pragma once
#include "../../runtime/CollectionContext.h"
#include <array>
#include <functional>
#include <string_view>

namespace wgwc::core::threat {
    inline constexpr std::size_t DefaultContextChars = 60;
    inline constexpr std::size_t MaxContextChars = 1024;
    inline constexpr std::size_t MaxKeywordChars = 1024;
    inline constexpr std::size_t ReadChunkBytes = 1024 * 1024;

    struct SearchOptions {
        std::wstring keyword;
        std::uint32_t pid = 0;
        std::size_t contextChars = DefaultContextChars;
    };

    struct BufferMatch {
        std::uint64_t address = 0;
        std::wstring matchType;
        std::wstring context;
    };

    struct Match : BufferMatch {
        std::uint32_t pid = 0;
        std::wstring processName;
        std::wstring processPath;
    };

    struct SearchResult : CollectionOutcome {
        std::size_t processesAttempted = 0;
        std::size_t processesRead = 0;
        std::size_t processesFailed = 0;
        std::size_t processesPartial = 0;
        std::size_t matchedProcesses = 0;
        std::uint64_t bytesRead = 0;
        bool outputStopped = false;
    };

    bool IsValidKeyword(std::wstring_view value);
    std::wstring SanitizeText(std::wstring_view value);
    using BufferSink = std::function<bool(const BufferMatch&)>;
    using MatchSink = std::function<bool(const Match&)>;

    // 有界的连续字节流，不允许跨越不连续区域进行匹配。
    class StreamMatcher {
    public:
        StreamMatcher(const SearchOptions& options, CollectionContext& context, BufferSink sink);

        bool Valid() const {
            return !patterns_.empty();
        }

        bool Feed(const std::uint8_t* data, std::size_t size, std::uint64_t address);
        bool FinishSegment();

    private:
        struct Pattern {
            std::vector<std::uint8_t> bytes;
            std::array<std::size_t, 256> shift{};
            unsigned codePage = 0; // 零表示 UTF-16LE。
            std::wstring name;
            std::size_t Find(const std::vector<std::uint8_t>& data, std::size_t start,
                             const CollectionContext& context) const;
        };

        void AddPattern(std::vector<std::uint8_t> bytes, unsigned codePage, const wchar_t* name);
        bool Drain(bool final);
        std::wstring Context(const Pattern& pattern, std::size_t position) const;
        SearchOptions options_;
        CollectionContext& context_;
        BufferSink sink_;
        std::vector<Pattern> patterns_;
        std::vector<std::uint8_t> buffer_;
        std::size_t maxPatternBytes_ = 0;
        std::size_t contextBytes_ = 0;
        std::uint64_t base_ = 0;
        std::uint64_t segmentStart_ = 0;
        std::uint64_t next_ = 0;
        bool active_ = false;
    };

    SearchResult Search(const SearchOptions& options, CollectionContext& context, const MatchSink& sink);
}
