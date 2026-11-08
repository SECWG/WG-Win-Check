#pragma once
#include "../runtime/CollectionContext.h"
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace wgwc::core::ip {
    enum class AddressType {
        Invalid,
        Unspecified,
        Loopback,
        Private,
        LinkLocal,
        Shared,
        Multicast,
        Reserved,
        Public
    };

    struct Address {
        std::wstring normalized;
        AddressType type = AddressType::Invalid;
        bool ipv6 = false;
    };
    enum class LookupState {
        LocalOnly,
        Success,
        NotFound,
        Failed,
        RateLimited,
        Cancelled,
        TimedOut
    };

    struct Record {
        std::wstring input;
        Address address;
        LookupState state = LookupState::Failed;
        std::wstring country, region, city, isp, location, observedAt;
        std::wstring errorCode;
        std::uint32_t nativeCode = 0, httpStatus = 0, retryAfterSeconds = 0;
        bool networkAttempted = false;
    };

    // 通过可注入的传输接口离线测试解析、隐私边界及错误分支。
    struct HttpResponse {
        std::string body;
        std::wstring errorCode, message;
        std::uint32_t nativeCode = 0, statusCode = 0, retryAfterSeconds = 0;
        bool complete = false;
        bool networkAttempted = false;
    };

    using Transport = std::function<HttpResponse(const std::vector<std::wstring>&, const CollectionContext&)>;
    Address ParseAddress(const std::wstring& value);
    const wchar_t* AddressTypeName(AddressType value);
    const wchar_t* LookupStateName(LookupState value);
    CollectionResult<Record> QueryBatch(const std::vector<std::wstring>& addresses, const CollectionContext& context,
                                        const Transport& transport = {});
    using LocationMap = std::map<std::wstring, std::wstring>;

    struct LocationQuerySummary {
        std::size_t queried = 0;
        LookupState state = LookupState::Success;
        bool networkError = false;
        CollectionIssue diagnostic;
    };

    // 仅为公网地址生成规范化键，同时合并 IPv4 及其映射 IPv6 表示。
    std::wstring PublicLookupKey(const std::wstring& value);
    // 查询前分批去重；查询失败时保留对应字段为空。
    LocationMap QueryPublicLocations(const std::vector<std::wstring>& addresses, const CollectionContext& context,
                                     const Transport& transport = {}, LocationQuerySummary* summary = nullptr);
    // 正式传输接口：现有 ip-api.com 免费批量接口使用 HTTP，而非 HTTPS。
    HttpResponse QueryIpApi(const std::vector<std::wstring>& addresses, const CollectionContext& context);
}
