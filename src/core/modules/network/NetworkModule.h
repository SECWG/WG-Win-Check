#pragma once
#include "../../runtime/CollectionContext.h"
#include <optional>

namespace wgwc::core::network {
    enum class Transport {
        Tcp,
        Udp
    };
    enum class SortMode {
        Default,
        ByPID,
        ByProcess,
        ByLocalPort,
        ByRemoteAddr,
        ByState
    };
    enum class ProtocolFilter {
        All,
        Tcp,
        Udp,
        TcpV4,
        TcpV6,
        UdpV4,
        UdpV6
    };
    enum class StateFilter {
        All,
        Listening,
        Established,
        TimeWait,
        Other
    };
    enum class ScopeFilter {
        All,
        External,
        Intranet,
        LocalListen
    };
    enum class UniqueBy {
        Address,
        Endpoint
    };

    struct FilterOptions {
        ProtocolFilter protocol = ProtocolFilter::All;
        StateFilter state = StateFilter::All;
        ScopeFilter scope = ScopeFilter::All;
        SortMode sortMode = SortMode::ByPID;
        std::wstring searchText;
        std::optional<std::uint32_t> pid;
    };

    struct NetworkOptions {
        ProtocolFilter protocol = ProtocolFilter::All;
        std::optional<std::uint32_t> pid;
        bool resolveProcesses = true;
    };

    struct Connection {
        Transport transport = Transport::Tcp;
        bool isIPv6 = false;
        std::wstring localAddress;
        std::uint16_t localPort = 0;
        std::uint32_t localScopeId = 0;
        std::wstring remoteAddress;
        std::uint16_t remotePort = 0;
        std::uint32_t remoteScopeId = 0;
        std::uint32_t tcpState = 0;
        std::uint32_t pid = 0;
        std::uint64_t observedAt = 0;
        std::wstring processName;
        std::wstring processPath;
        std::uint64_t processCreatedAt = 0;
        FieldState processNameState = FieldState::NotRequested;
        FieldState processPathState = FieldState::NotRequested;
        FieldState processTimeState = FieldState::NotRequested;
        std::uint32_t processError = 0;
    };

    struct RemoteEndpoint {
        std::wstring address;
        bool isIPv6 = false;
        std::uint32_t scopeId = 0;
        Transport transport = Transport::Tcp;
        std::uint16_t port = 0;
        bool hasPort = false;
    };

    CollectionResult<Connection> CollectConnections(const NetworkOptions& options, CollectionContext& context);
    const wchar_t* ProtocolName(Transport transport);
    const wchar_t* TcpStateName(std::uint32_t state);
    bool IsLocalAddress(const std::wstring& address);
    bool IsIntranetAddress(const std::wstring& address);
    bool ContainsInsensitive(const std::wstring& text, const std::wstring& needle);
    bool MatchesConnection(const Connection& connection, const FilterOptions& options);
    bool LessConnection(const Connection& a, const Connection& b, SortMode mode);
    std::vector<RemoteEndpoint> ExtractRemoteEndpoints(const std::vector<Connection>& connections, UniqueBy uniqueBy,
                                                       CollectionContext* context = nullptr);
    std::vector<RemoteEndpoint> ExtractRemoteEndpoints(const std::vector<const Connection*>& connections,
                                                       UniqueBy uniqueBy, CollectionContext* context = nullptr);
    std::wstring FormatEndpoint(const RemoteEndpoint& endpoint);
}
