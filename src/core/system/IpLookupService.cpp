#include "Win32.h"
#include "IpLookupService.h"
#include <algorithm>
#include <map>
#include <set>

#pragma comment(lib, "ws2_32.lib")

namespace wgwc::core::ip {
    namespace {
        AddressType ClassifyV4(const unsigned char* b) {
            if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0)
                return AddressType::Unspecified;
            if (b[0] == 127)
                return AddressType::Loopback;
            if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168))
                return AddressType::Private;
            if (b[0] == 169 && b[1] == 254)
                return AddressType::LinkLocal;
            if (b[0] == 100 && (b[1] & 0xc0) == 64)
                return AddressType::Shared;
            if (b[0] >= 224 && b[0] <= 239)
                return AddressType::Multicast;
            // 公网查询采用保守策略，与原有连接筛选逻辑分离。
            if (b[0] == 0 || b[0] >= 240 || (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2)) ||
                (b[0] == 192 && b[1] == 88 && b[2] == 99) ||
                (b[0] == 198 && (b[1] == 18 || b[1] == 19 || (b[1] == 51 && b[2] == 100))) ||
                (b[0] == 203 && b[1] == 0 && b[2] == 113))
                return AddressType::Reserved;
            return AddressType::Public;
        }

        bool Zeros(const unsigned char* b, unsigned length) {
            for (unsigned i = 0; i < length; ++i)
                if (b[i])
                    return false;
            return true;
        }

        using ProviderRow = std::map<std::wstring, std::wstring>;

        // 仅使用指定的服务端字段；跳过未知 JSON 值时限制嵌套深度，
        // 并拒绝格式错误、截断响应及重复键。
        class JsonReader {
        public:
            explicit JsonReader(const std::wstring& text) : text_(text) {}

            bool Rows(std::vector<ProviderRow>& rows) {
                if (!Take(L'['))
                    return false;
                if (!Take(L']')) {
                    do {
                        if (rows.size() == 100 || !Take(L'{'))
                            return false;
                        ProviderRow row;
                        std::set<std::wstring> seen;
                        if (!Take(L'}')) {
                            do {
                                std::wstring key, value;
                                if (!String(key) || !seen.insert(key).second || seen.size() > 128 || !Take(L':'))
                                    return false;
                                const bool known = key == L"status" || key == L"query" || key == L"message" ||
                                                   key == L"country" || key == L"regionName" || key == L"city" ||
                                                   key == L"isp";
                                if (known) {
                                    if (!String(value))
                                        return false;
                                    row.emplace(std::move(key), std::move(value));
                                } else if (!Skip(0))
                                    return false;
                            } while (Take(L','));
                            if (!Take(L'}'))
                                return false;
                        }
                        rows.push_back(std::move(row));
                    } while (Take(L','));
                    if (!Take(L']'))
                        return false;
                }
                Space();
                return position_ == text_.size();
            }

        private:
            const std::wstring& text_;
            std::size_t position_ = 0;

            void Space() {
                while (position_ < text_.size() && (text_[position_] == L' ' || text_[position_] == L'\t' ||
                                                    text_[position_] == L'\r' || text_[position_] == L'\n'))
                    ++position_;
            }

            bool Take(wchar_t value) {
                Space();
                if (position_ == text_.size() || text_[position_] != value)
                    return false;
                ++position_;
                return true;
            }

            bool String(std::wstring& value) {
                if (!Take(L'"'))
                    return false;
                value.clear();
                while (position_ < text_.size() && value.size() <= 8192) {
                    wchar_t c = text_[position_++];
                    if (c == L'"') {
                        for (std::size_t i = 0; i < value.size(); ++i) {
                            if (value[i] >= 0xd800 && value[i] <= 0xdbff) {
                                if (++i == value.size() || value[i] < 0xdc00 || value[i] > 0xdfff)
                                    return false;
                            } else if (value[i] >= 0xdc00 && value[i] <= 0xdfff)
                                return false;
                        }
                        return true;
                    }
                    if (c < 0x20)
                        return false;
                    if (c == L'\\') {
                        if (position_ == text_.size())
                            return false;
                        c = text_[position_++];
                        switch (c) {
                        case L'"':
                        case L'\\':
                        case L'/':
                            break;
                        case L'b':
                            c = L'\b';
                            break;
                        case L'f':
                            c = L'\f';
                            break;
                        case L'n':
                            c = L'\n';
                            break;
                        case L'r':
                            c = L'\r';
                            break;
                        case L't':
                            c = L'\t';
                            break;
                        case L'u': {
                            unsigned code = 0;
                            for (unsigned i = 0; i < 4; ++i) {
                                if (position_ == text_.size())
                                    return false;
                                const wchar_t digit = text_[position_++];
                                unsigned part;
                                if (digit >= L'0' && digit <= L'9')
                                    part = digit - L'0';
                                else if (digit >= L'a' && digit <= L'f')
                                    part = digit - L'a' + 10;
                                else if (digit >= L'A' && digit <= L'F')
                                    part = digit - L'A' + 10;
                                else
                                    return false;
                                code = code * 16 + part;
                            }
                            c = static_cast<wchar_t>(code);
                            break;
                        }
                        default:
                            return false;
                        }
                    }
                    value += c;
                }
                return false;
            }

            bool Skip(unsigned depth) {
                if (depth > 16)
                    return false;
                Space();
                if (position_ == text_.size())
                    return false;
                if (text_[position_] == L'"') {
                    std::wstring ignored;
                    return String(ignored);
                }
                if (Take(L'{')) {
                    if (Take(L'}'))
                        return true;
                    do {
                        std::wstring key;
                        if (!String(key) || !Take(L':') || !Skip(depth + 1))
                            return false;
                    } while (Take(L','));
                    return Take(L'}');
                }
                if (Take(L'[')) {
                    if (Take(L']'))
                        return true;
                    do {
                        if (!Skip(depth + 1))
                            return false;
                    } while (Take(L','));
                    return Take(L']');
                }
                for (const auto literal : { L"true", L"false", L"null" }) {
                    const std::size_t length = wcslen(literal);
                    if (text_.compare(position_, length, literal) == 0) {
                        position_ += length;
                        return true;
                    }
                }
                const auto digits = [&]() {
                    const auto start = position_;
                    while (position_ < text_.size() && text_[position_] >= L'0' && text_[position_] <= L'9')
                        ++position_;
                    return position_ > start;
                };
                if (text_[position_] == L'-')
                    ++position_;
                if (position_ == text_.size())
                    return false;
                if (text_[position_] == L'0')
                    ++position_;
                else if (!digits())
                    return false;
                if (position_ < text_.size() && text_[position_] == L'.') {
                    ++position_;
                    if (!digits())
                        return false;
                }
                if (position_ < text_.size() && (text_[position_] == L'e' || text_[position_] == L'E')) {
                    ++position_;
                    if (position_ < text_.size() && (text_[position_] == L'+' || text_[position_] == L'-'))
                        ++position_;
                    if (!digits())
                        return false;
                }
                return true;
            }
        };

        bool ParseResponse(const std::string& body, std::vector<ProviderRow>& rows) {
            if (body.empty() || body.size() > 1024 * 1024)
                return false;
            const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, body.data(),
                                                 static_cast<int>(body.size()), nullptr, 0);
            if (!size)
                return false;
            std::wstring text(size, L'\0');
            if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, body.data(), static_cast<int>(body.size()),
                                    text.data(), size) != size)
                return false;
            return JsonReader(text).Rows(rows);
        }

        std::wstring Location(const Record& record) {
            std::wstring text;
            for (const auto* part : { &record.country, &record.region, &record.city, &record.isp }) {
                if (part->empty())
                    continue;
                if (!text.empty())
                    text += L" ";
                text += *part;
            }
            return text;
        }
    }

    Address ParseAddress(const std::wstring& value) {
        Address result;
        if (value.empty() || value.size() > 45 || value.find(L'\0') != std::wstring::npos)
            return result;
        IN_ADDR v4{};
        IN6_ADDR v6{};
        wchar_t normalized[46]{};
        if (InetPtonW(AF_INET, value.c_str(), &v4) == 1) {
            if (!InetNtopW(AF_INET, &v4, normalized, 46))
                return result;
            result.type = ClassifyV4(reinterpret_cast<const unsigned char*>(&v4));
        } else if (InetPtonW(AF_INET6, value.c_str(), &v6) == 1) {
            if (!InetNtopW(AF_INET6, &v6, normalized, 46))
                return result;
            result.ipv6 = true;
            const auto* b = v6.u.Byte;
            if (Zeros(b, 16))
                result.type = AddressType::Unspecified;
            else if (Zeros(b, 15) && b[15] == 1)
                result.type = AddressType::Loopback;
            else if (Zeros(b, 10) && b[10] == 0xff && b[11] == 0xff)
                result.type = ClassifyV4(b + 12);
            else if ((b[0] & 0xfe) == 0xfc)
                result.type = AddressType::Private;
            else if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
                result.type = AddressType::LinkLocal;
            else if (b[0] == 0xff)
                result.type = AddressType::Multicast;
            else if ((b[0] & 0xe0) != 0x20 || (b[0] == 0x20 && b[1] == 0x01 && b[2] < 2) ||
                     (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) || (b[0] == 0x20 && b[1] == 0x02) ||
                     (b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0))
                result.type = AddressType::Reserved;
            else
                result.type = AddressType::Public;
        } else
            return result;
        result.normalized = normalized;
        return result;
    }

    std::wstring PublicLookupKey(const std::wstring& value) {
        const auto address = ParseAddress(value);
        if (address.type != AddressType::Public)
            return {};
        if (address.ipv6) {
            IN6_ADDR v6{};
            if (InetPtonW(AF_INET6, address.normalized.c_str(), &v6) != 1)
                return {};
            const auto* bytes = v6.u.Byte;
            if (Zeros(bytes, 10) && bytes[10] == 0xff && bytes[11] == 0xff) {
                IN_ADDR v4{};
                std::copy(bytes + 12, bytes + 16, reinterpret_cast<unsigned char*>(&v4));
                wchar_t normalized[16]{};
                return InetNtopW(AF_INET, &v4, normalized, 16) ? std::wstring(normalized) : std::wstring{};
            }
        }
        return address.normalized;
    }

    LocationMap QueryPublicLocations(const std::vector<std::wstring>& addresses, const CollectionContext& context,
                                     const Transport& transport, LocationQuerySummary* summary) {
        LocationQuerySummary query;
        std::set<std::wstring> unique;
        for (const auto& value : addresses) {
            if (context.ShouldStop())
                break;
            auto key = PublicLookupKey(value);
            if (!key.empty())
                unique.insert(std::move(key));
        }
        const std::vector<std::wstring> targets(unique.begin(), unique.end());
        LocationMap locations;
        for (std::size_t offset = 0; offset < targets.size() && !context.ShouldStop();) {
            const auto count = (std::min)(std::size_t{ 100 }, targets.size() - offset);
            const std::vector<std::wstring> batch(targets.begin() + offset, targets.begin() + offset + count);
            const auto result = QueryBatch(batch, context, transport);
            bool stop = false;
            for (const auto& record : result.records) {
                if (record.state == LookupState::Success || record.state == LookupState::NotFound) {
                    ++query.queried;
                    if (!record.location.empty())
                        locations.emplace(record.address.normalized, record.location);
                } else if (record.state != LookupState::LocalOnly) {
                    query.state = record.state;
                    query.networkError = record.state == LookupState::TimedOut ||
                                         (record.state == LookupState::Failed && record.httpStatus == 0);
                    if (query.diagnostic.code.empty()) {
                        const auto issue =
                            std::find_if(result.issues.begin(), result.issues.end(), [&](const CollectionIssue& value) {
                                return value.objectKey == record.input && value.code == record.errorCode;
                            });
                        if (issue != result.issues.end())
                            query.diagnostic = *issue;
                    }
                    stop = true;
                }
            }
            offset += count;
            if (stop || context.ShouldStop())
                break;
        }
        if (context.ShouldStop()) {
            query.state = context.IsCancelled() ? LookupState::Cancelled : LookupState::TimedOut;
            query.networkError = query.state == LookupState::TimedOut;
        }
        if (summary)
            *summary = query;
        return locations;
    }

    const wchar_t* AddressTypeName(AddressType value) {
        switch (value) {
        case AddressType::Unspecified:
            return L"unspecified";
        case AddressType::Loopback:
            return L"loopback";
        case AddressType::Private:
            return L"private";
        case AddressType::LinkLocal:
            return L"link_local";
        case AddressType::Shared:
            return L"shared";
        case AddressType::Multicast:
            return L"multicast";
        case AddressType::Reserved:
            return L"reserved";
        case AddressType::Public:
            return L"public";
        default:
            return L"invalid";
        }
    }

    const wchar_t* LookupStateName(LookupState value) {
        switch (value) {
        case LookupState::LocalOnly:
            return L"local_only";
        case LookupState::Success:
            return L"success";
        case LookupState::NotFound:
            return L"not_found";
        case LookupState::RateLimited:
            return L"rate_limited";
        case LookupState::Cancelled:
            return L"cancelled";
        case LookupState::TimedOut:
            return L"timed_out";
        default:
            return L"failed";
        }
    }

    CollectionResult<Record> QueryBatch(const std::vector<std::wstring>& addresses, const CollectionContext& context,
                                        const Transport& transport) {
        CollectionResult<Record> result;
        result.startedAt = UtcNow();
        result.assessment = AssessmentState::NotRequested;
        if (addresses.empty() || addresses.size() > 100) {
            result.issues.push_back({ L"ip.lookup", L"", L"INVALID_BATCH_SIZE", ERROR_INVALID_PARAMETER,
                                      L"An IP lookup batch must contain 1 to 100 explicit IP literals.", true });
            result.finishedAt = UtcNow();
            return result;
        }
        std::vector<std::wstring> queries;
        std::set<std::wstring> unique;
        for (const auto& input : addresses) {
            Record record;
            record.input = input;
            record.address = ParseAddress(input);
            record.observedAt = result.startedAt;
            if (record.address.type == AddressType::Invalid) {
                record.errorCode = L"INVALID_IP";
                record.nativeCode = ERROR_INVALID_PARAMETER;
                result.issues.push_back(
                    { L"ip.lookup", input, record.errorCode, record.nativeCode,
                      L"Expected a literal IPv4 or IPv6 address, not a hostname, URL, port or scope suffix.", true });
            } else if (record.address.type != AddressType::Public)
                record.state = LookupState::LocalOnly;
            else if (unique.insert(record.address.normalized).second)
                queries.push_back(record.address.normalized);
            result.records.push_back(std::move(record));
        }
        HttpResponse response;
        if (!queries.empty() && !context.ShouldStop())
            response = transport ? transport(queries, context) : QueryIpApi(queries, context);
        const bool stopped = context.ShouldStop();
        std::map<std::wstring, ProviderRow> rows;
        bool parsed = false;
        if (!queries.empty() && !stopped && response.complete && response.statusCode == 200) {
            std::vector<ProviderRow> received;
            parsed = ParseResponse(response.body, received) && received.size() == queries.size();
            for (auto& row : received) {
                const auto key = ParseAddress(row[L"query"]).normalized;
                const auto status = row[L"status"];
                if (key.empty() || unique.find(key) == unique.end() || rows.find(key) != rows.end() ||
                    (status != L"success" && status != L"fail")) {
                    parsed = false;
                    break;
                }
                if (status == L"success" &&
                    (row.find(L"country") == row.end() || row.find(L"regionName") == row.end() ||
                     row.find(L"city") == row.end() || row.find(L"isp") == row.end())) {
                    parsed = false;
                    break;
                }
                rows.emplace(key, std::move(row));
            }
        }
        std::size_t good = 0, bad = 0;
        for (auto& record : result.records) {
            if (record.address.type == AddressType::Public) {
                record.networkAttempted = response.networkAttempted;
                record.httpStatus = response.statusCode;
                record.nativeCode = response.nativeCode;
                record.retryAfterSeconds = response.retryAfterSeconds;
                record.observedAt = UtcNow();
                std::wstring message;
                if (stopped) {
                    record.state = context.IsCancelled() ? LookupState::Cancelled : LookupState::TimedOut;
                    record.errorCode = context.IsCancelled() ? L"CANCELLED" : L"TIMED_OUT";
                    message = L"The IP lookup was interrupted; no unfinished response was accepted.";
                } else if (response.statusCode == 429) {
                    record.state = LookupState::RateLimited;
                    record.errorCode = L"IP_RATE_LIMITED";
                    message =
                        L"The provider request limit was reached. Respect retryAfterSeconds; no automatic retry was made.";
                } else if (!response.complete || response.statusCode != 200) {
                    record.state = response.nativeCode == ERROR_TIMEOUT || response.nativeCode == 12002
                                       ? LookupState::TimedOut
                                       : LookupState::Failed;
                    record.errorCode = response.errorCode.empty() ? L"IP_HTTP_FAILED" : response.errorCode;
                    message = response.message.empty() ? L"The IP attribution HTTP request failed." : response.message;
                } else if (!parsed) {
                    record.state = LookupState::Failed;
                    record.errorCode = L"IP_RESPONSE_INVALID";
                    message = L"The provider returned malformed, incomplete, oversized or mismatched IP data.";
                } else {
                    const auto& row = rows.at(record.address.normalized);
                    if (row.at(L"status") == L"success") {
                        record.country = row.at(L"country");
                        record.region = row.at(L"regionName");
                        record.city = row.at(L"city");
                        record.isp = row.at(L"isp");
                        record.location = Location(record);
                        record.state = record.location.empty() ? LookupState::NotFound : LookupState::Success;
                    } else
                        record.state = LookupState::NotFound;
                    if (record.state == LookupState::NotFound) {
                        record.errorCode = L"IP_LOCATION_UNAVAILABLE";
                        const auto found = row.find(L"message");
                        message = found == row.end() ? L"The provider did not return attribution data." : found->second;
                    }
                }
                if (!record.errorCode.empty())
                    result.issues.push_back(
                        { L"ip.lookup", record.input, record.errorCode, record.nativeCode, message, true });
            }
            if (record.state == LookupState::LocalOnly || record.state == LookupState::Success)
                ++good;
            else
                ++bad;
        }
        if (response.networkAttempted)
            result.issues.push_back(
                { L"ip.lookup", L"", L"PLAINTEXT_IP_LOOKUP", 0,
                  L"The existing free ip-api.com provider uses unencrypted HTTP. Attribution is untrusted reference data, not risk evidence.",
                  false });
        if (stopped)
            result.status = context.StopStatus();
        else if (bad) {
            result.status = good ? CollectionStatus::Partial : CollectionStatus::Failed;
            if (!good && std::any_of(result.records.begin(), result.records.end(), [](const Record& r) {
                    return r.state == LookupState::TimedOut;
                }))
                result.status = CollectionStatus::TimedOut;
        } else
            result.status = CollectionStatus::Complete;
        result.collected = result.records.size();
        result.sources.push_back({ L"ip.classification", L"complete", result.records.size(), 0 });
        if (!queries.empty())
            result.sources.push_back(
                { L"ip-api.com",
                  StatusName(stopped ? context.StopStatus()
                                     : (bad ? (good ? CollectionStatus::Partial : result.status)
                                            : CollectionStatus::Complete)),
                  static_cast<std::size_t>(std::count_if(result.records.begin(), result.records.end(),
                                                         [](const Record& r) {
                                                             return r.state == LookupState::Success;
                                                         })),
                  response.nativeCode });
        result.finishedAt = UtcNow();
        return result;
    }
}
