#include "../../system/Win32.h"
#include "ThreatSearch.h"
#include <algorithm>
#include <limits>

namespace wgwc::core::threat {
    namespace {
        constexpr std::size_t Missing = (std::numeric_limits<std::size_t>::max)();

        bool High(wchar_t c) {
            return c >= 0xd800 && c <= 0xdbff;
        }

        bool Low(wchar_t c) {
            return c >= 0xdc00 && c <= 0xdfff;
        }

        bool Control(wchar_t c) {
            return c < 32 || (c >= 0x7f && c <= 0x9f) || c == 0x2028 || c == 0x2029 || (c >= 0x202a && c <= 0x202e) ||
                   (c >= 0x2066 && c <= 0x2069);
        }

        bool ValidUtf8(const std::vector<std::uint8_t>& data, std::size_t begin, std::size_t end) {
            return begin == end || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                                       reinterpret_cast<const char*>(data.data() + begin),
                                                       static_cast<int>(end - begin), nullptr, 0) > 0;
        }

        std::size_t TrimUtf8End(const std::vector<std::uint8_t>& data, std::size_t begin, std::size_t end) {
            if (begin == end)
                return end;
            auto lead = end - 1;
            while (lead > begin && (data[lead] & 0xc0) == 0x80)
                --lead;
            const auto byte = data[lead];
            const std::size_t length = byte >= 0xc2 && byte <= 0xdf   ? 2
                                       : byte >= 0xe0 && byte <= 0xef ? 3
                                       : byte >= 0xf0 && byte <= 0xf4 ? 4
                                                                      : 0;
            if (!length || end - lead >= length)
                return end;
            // 只移除可能因截断而不完整的 UTF-8 序列，不能随意丢弃无效字节。
            if (end > lead + 1 &&
                ((byte == 0xe0 && data[lead + 1] < 0xa0) || (byte == 0xed && data[lead + 1] >= 0xa0) ||
                 (byte == 0xf0 && data[lead + 1] < 0x90) || (byte == 0xf4 && data[lead + 1] >= 0x90)))
                return end;
            return lead;
        }

        std::wstring Decode(const std::uint8_t* data, std::size_t length, unsigned codePage) {
            if (!length)
                return {};
            if (!codePage) {
                std::wstring text;
                text.reserve(length / 2);
                for (std::size_t i = 0; i + 1 < length; i += 2)
                    text.push_back(static_cast<wchar_t>(data[i] | (static_cast<unsigned>(data[i + 1]) << 8)));
                return SanitizeText(text);
            }
            const int count = MultiByteToWideChar(codePage, 0, reinterpret_cast<const char*>(data),
                                                  static_cast<int>(length), nullptr, 0);
            if (count <= 0)
                return {};
            std::wstring text(static_cast<std::size_t>(count), L'\0');
            if (!MultiByteToWideChar(codePage, 0, reinterpret_cast<const char*>(data), static_cast<int>(length),
                                     text.data(), count))
                return {};
            return SanitizeText(text);
        }

        std::size_t FrontCount(std::wstring_view text, std::size_t count) {
            std::size_t i = 0;
            while (i < text.size() && count--) {
                if (High(text[i]) && i + 1 < text.size() && Low(text[i + 1]))
                    i += 2;
                else
                    ++i;
            }
            return i;
        }

        std::size_t BackStart(std::wstring_view text, std::size_t count) {
            std::size_t i = text.size();
            while (i && count--) {
                --i;
                if (Low(text[i]) && i && High(text[i - 1]))
                    --i;
            }
            return i;
        }
    }

    bool IsValidKeyword(std::wstring_view value) {
        if (value.empty())
            return false;
        std::size_t count = 0;
        bool hasText = false;
        for (std::size_t i = 0; i < value.size(); ++i) {
            if (Control(value[i]))
                return false;
            WORD type = 0;
            if (!GetStringTypeW(CT_CTYPE1, &value[i], 1, &type) || !(type & C1_SPACE))
                hasText = true;
            if (High(value[i])) {
                if (i + 1 == value.size() || !Low(value[i + 1]))
                    return false;
                ++i;
            } else if (Low(value[i]))
                return false;
            if (++count > MaxKeywordChars)
                return false;
        }
        return hasText;
    }

    std::wstring SanitizeText(std::wstring_view value) {
        std::wstring output;
        output.reserve(value.size());
        for (std::size_t i = 0; i < value.size(); ++i) {
            const auto c = value[i];
            if (Control(c))
                output.push_back(L' ');
            else if (High(c)) {
                if (i + 1 < value.size() && Low(value[i + 1])) {
                    output.push_back(c);
                    output.push_back(value[++i]);
                } else
                    output.push_back(static_cast<wchar_t>(0xfffd));
            } else if (Low(c))
                output.push_back(static_cast<wchar_t>(0xfffd));
            else
                output.push_back(c);
        }
        return output;
    }

    std::size_t StreamMatcher::Pattern::Find(const std::vector<std::uint8_t>& data, std::size_t start,
                                             const CollectionContext& context) const {
        if (bytes.empty() || bytes.size() > data.size() || start > data.size() - bytes.size())
            return Missing;
        const auto last = data.size() - bytes.size();
        std::size_t checks = 0;
        while (start <= last) {
            if ((++checks & 1023) == 0 && context.ShouldStop())
                return Missing;
            std::size_t remaining = bytes.size();
            while (remaining && data[start + remaining - 1] == bytes[remaining - 1])
                --remaining;
            if (!remaining)
                return start;
            const auto step = shift[data[start + bytes.size() - 1]];
            if (step > last - start)
                break;
            start += step;
        }
        return Missing;
    }

    void StreamMatcher::AddPattern(std::vector<std::uint8_t> bytes, unsigned codePage, const wchar_t* name) {
        if (bytes.empty())
            return;
        for (const auto& existing : patterns_)
            if (existing.bytes == bytes)
                return;
        Pattern pattern;
        pattern.bytes = std::move(bytes);
        pattern.codePage = codePage;
        pattern.name = name;
        pattern.shift.fill(pattern.bytes.size());
        for (std::size_t i = 0; i + 1 < pattern.bytes.size(); ++i)
            pattern.shift[pattern.bytes[i]] = pattern.bytes.size() - 1 - i;
        maxPatternBytes_ = (std::max)(maxPatternBytes_, pattern.bytes.size());
        patterns_.push_back(std::move(pattern));
    }

    StreamMatcher::StreamMatcher(const SearchOptions& options, CollectionContext& context, BufferSink sink)
        : options_(options), context_(context), sink_(std::move(sink)) {
        if (!IsValidKeyword(options.keyword) || options.contextChars > MaxContextChars || !sink_)
            return;
        contextBytes_ = (options.contextChars + 1) * 4;
        const auto* wide = reinterpret_cast<const std::uint8_t*>(options.keyword.data());
        AddPattern(std::vector<std::uint8_t>(wide, wide + options.keyword.size() * sizeof(wchar_t)), 0, L"UTF-16LE");
        const bool ascii = std::all_of(options.keyword.begin(), options.keyword.end(), [](wchar_t c) {
            return c < 128;
        });
        const unsigned pages[] = { CP_UTF8, GetACP() };
        for (const auto page : pages) {
            const DWORD flags = page == CP_UTF8 ? 0 : WC_NO_BEST_FIT_CHARS;
            BOOL usedDefault = FALSE;
            BOOL* substituted = page == CP_UTF8 ? nullptr : &usedDefault;
            const int length =
                WideCharToMultiByte(page, flags, options.keyword.data(), static_cast<int>(options.keyword.size()),
                                    nullptr, 0, nullptr, substituted);
            if (length <= 0 || usedDefault)
                continue;
            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length));
            if (WideCharToMultiByte(page, flags, options.keyword.data(), static_cast<int>(options.keyword.size()),
                                    reinterpret_cast<char*>(bytes.data()), length, nullptr, substituted) != length ||
                usedDefault)
                continue;
            AddPattern(std::move(bytes), page, ascii ? L"ASCII" : (page == CP_UTF8 ? L"UTF-8" : L"ANSI"));
        }
        buffer_.reserve(ReadChunkBytes + contextBytes_ * 2 + maxPatternBytes_);
    }

    std::wstring StreamMatcher::Context(const Pattern& pattern, std::size_t position) const {
        if (!options_.contextChars)
            return options_.keyword;
        std::size_t begin = position > contextBytes_ ? position - contextBytes_ : 0;
        const auto after = position + pattern.bytes.size();
        std::size_t end = after + (std::min)(contextBytes_, buffer_.size() - after);
        bool leftBoundary = false, rightBoundary = false;
        if (!pattern.codePage) {
            begin += (position - begin) % 2;
            end -= (end - after) % 2;
            for (std::size_t i = position; i >= begin + 2;) {
                i -= 2;
                if (!buffer_[i] && !buffer_[i + 1]) {
                    begin = i + 2;
                    leftBoundary = true;
                    break;
                }
            }
            for (std::size_t i = after; i + 1 < end; i += 2) {
                if (!buffer_[i] && !buffer_[i + 1]) {
                    end = i;
                    rightBoundary = true;
                    break;
                }
            }
        } else {
            for (std::size_t i = position; i > begin;) {
                --i;
                if (!buffer_[i]) {
                    begin = i + 1;
                    leftBoundary = true;
                    break;
                }
            }
            for (std::size_t i = after; i < end; ++i) {
                if (!buffer_[i]) {
                    end = i;
                    rightBoundary = true;
                    break;
                }
            }
        }
        const bool leftClipped = !leftBoundary && (begin > 0 || base_ > segmentStart_);
        const bool rightClipped = !rightBoundary && end < buffer_.size();
        unsigned codePage = pattern.codePage;
        if (codePage == CP_UTF8) {
            auto utf8Begin = begin;
            auto utf8End = end;
            if (leftClipped)
                while (utf8Begin < position && (buffer_[utf8Begin] & 0xc0) == 0x80)
                    ++utf8Begin;
            if (rightClipped)
                utf8End = TrimUtf8End(buffer_, after, end);
            // ASCII 模式在 UTF-8 和 ACP 中的字节相同；应单独解码上下文，
            // 不能让字节模式去重结果决定使用 UTF-8。
            if (pattern.name == L"ASCII" &&
                (!ValidUtf8(buffer_, utf8Begin, position) || !ValidUtf8(buffer_, after, utf8End))) {
                codePage = GetACP();
            } else {
                begin = utf8Begin;
                end = utf8End;
            }
        }
        const auto left = Decode(buffer_.data() + begin, position - begin, codePage);
        const auto right = Decode(buffer_.data() + after, end - after, codePage);
        const auto leftStart = BackStart(left, options_.contextChars);
        const auto rightEnd = FrontCount(right, options_.contextChars);
        const bool leftCut = leftStart > 0 || leftClipped;
        const bool rightCut = rightEnd < right.size() || rightClipped;
        return (leftCut ? L"..." : L"") + left.substr(leftStart) + options_.keyword + right.substr(0, rightEnd) +
               (rightCut ? L"..." : L"");
    }

    bool StreamMatcher::Drain(bool final) {
        if (context_.ShouldStop())
            return false;
        const auto end = base_ + buffer_.size();
        const auto reserve = contextBytes_ + maxPatternBytes_;
        const auto safe = final ? end : base_ + (buffer_.size() > reserve ? buffer_.size() - reserve : 0);
        if (safe <= next_)
            return true;
        const auto start = static_cast<std::size_t>(next_ - base_);
        std::vector<std::size_t> positions;
        positions.reserve(patterns_.size());
        for (const auto& pattern : patterns_)
            positions.push_back(pattern.Find(buffer_, start, context_));
        for (;;) {
            if (context_.ShouldStop())
                return false;
            const auto first = std::min_element(positions.begin(), positions.end());
            if (first == positions.end() || *first == Missing || base_ + *first >= safe)
                break;
            const auto position = *first;
            const auto index = static_cast<std::size_t>(first - positions.begin());
            if (!sink_({ base_ + position, patterns_[index].name, Context(patterns_[index], position) }))
                return false;
            // 同一地址只保留一条记录，即使同一组字节可由多种编码解释。
            for (std::size_t i = 0; i < positions.size(); ++i)
                if (positions[i] == position)
                    positions[i] = patterns_[i].Find(buffer_, position + 1, context_);
        }
        next_ = safe;
        const auto keep = static_cast<std::size_t>(next_ - base_);
        const auto discard = keep > contextBytes_ ? keep - contextBytes_ : 0;
        if (discard) {
            buffer_.erase(buffer_.begin(), buffer_.begin() + discard);
            base_ += discard;
        }
        return true;
    }

    bool StreamMatcher::Feed(const std::uint8_t* data, std::size_t size, std::uint64_t address) {
        if (!Valid() || context_.ShouldStop() || (size && !data) ||
            size > (std::numeric_limits<std::uint64_t>::max)() - address)
            return false;
        if (!size)
            return true;
        if (active_ && address != base_ + buffer_.size() && !FinishSegment())
            return false;
        if (!active_) {
            active_ = true;
            base_ = next_ = segmentStart_ = address;
        }
        // 扫描器和模拟调用方使用相同的边界限制。
        while (size) {
            const auto count = (std::min)(size, ReadChunkBytes);
            buffer_.insert(buffer_.end(), data, data + count);
            if (!Drain(false))
                return false;
            data += count;
            size -= count;
        }
        return true;
    }

    bool StreamMatcher::FinishSegment() {
        if (!active_)
            return !context_.ShouldStop();
        if (!Drain(true))
            return false;
        buffer_.clear();
        active_ = false;
        return true;
    }
}
