#include "../../system/Win32.h"
#include "NetworkModule.h"
#include "../../system/IpLookupService.h"
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cstddef>
#include <cwctype>
#include <map>
#include <set>
#include <tuple>

namespace wgwc::core::network {
    namespace {
        std::wstring Lower(std::wstring text) {
            for (auto& c : text)
                c = static_cast<wchar_t>(towlower(c));
            return text;
        }

        bool IncludesProtocol(ProtocolFilter filter, Transport transport, bool ipv6) {
            switch (filter) {
            case ProtocolFilter::Tcp:
                return transport == Transport::Tcp;
            case ProtocolFilter::Udp:
                return transport == Transport::Udp;
            case ProtocolFilter::TcpV4:
                return transport == Transport::Tcp && !ipv6;
            case ProtocolFilter::TcpV6:
                return transport == Transport::Tcp && ipv6;
            case ProtocolFilter::UdpV4:
                return transport == Transport::Udp && !ipv6;
            case ProtocolFilter::UdpV6:
                return transport == Transport::Udp && ipv6;
            default:
                return true;
            }
        }

        std::wstring Address4(DWORD value) {
            IN_ADDR address{};
            address.S_un.S_addr = value;
            wchar_t text[INET_ADDRSTRLEN]{};
            return InetNtopW(AF_INET, &address, text, INET_ADDRSTRLEN) ? text : L"";
        }

        std::wstring Address6(const UCHAR* value) {
            IN6_ADDR address{};
            memcpy(&address, value, sizeof(address));
            wchar_t text[INET6_ADDRSTRLEN]{};
            return InetNtopW(AF_INET6, &address, text, INET6_ADDRSTRLEN) ? text : L"";
        }

        Connection Convert(const MIB_TCPROW_OWNER_PID& row) {
            Connection c;
            c.localAddress = Address4(row.dwLocalAddr);
            c.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
            c.remoteAddress = Address4(row.dwRemoteAddr);
            c.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
            c.tcpState = row.dwState;
            c.pid = row.dwOwningPid;
            return c;
        }

        Connection Convert(const MIB_TCP6ROW_OWNER_PID& row) {
            Connection c;
            c.isIPv6 = true;
            c.localAddress = Address6(row.ucLocalAddr);
            c.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
            c.localScopeId = row.dwLocalScopeId;
            c.remoteAddress = Address6(row.ucRemoteAddr);
            c.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
            c.remoteScopeId = row.dwRemoteScopeId;
            c.tcpState = row.dwState;
            c.pid = row.dwOwningPid;
            return c;
        }

        Connection Convert(const MIB_UDPROW_OWNER_PID& row) {
            Connection c;
            c.transport = Transport::Udp;
            c.localAddress = Address4(row.dwLocalAddr);
            c.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
            c.remoteAddress = L"*";
            c.pid = row.dwOwningPid;
            return c;
        }

        Connection Convert(const MIB_UDP6ROW_OWNER_PID& row) {
            Connection c;
            c.transport = Transport::Udp;
            c.isIPv6 = true;
            c.localAddress = Address6(row.ucLocalAddr);
            c.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
            c.localScopeId = row.dwLocalScopeId;
            c.remoteAddress = L"*";
            c.pid = row.dwOwningPid;
            return c;
        }

        template <class Table, class Query>
        void ReadTable(const NetworkOptions& options, CollectionContext& context, CollectionResult<Connection>& result,
                       SourceCoverage& coverage, Query query) {
            if (context.ShouldStop() || result.collectionTruncated)
                return;
            std::vector<BYTE> buffer;
            DWORD error = ERROR_INSUFFICIENT_BUFFER;
            ULONG size = 0;
            for (unsigned attempt = 0; attempt < 5; ++attempt) {
                if (context.ShouldStop()) {
                    coverage.status = StatusName(context.StopStatus());
                    return;
                }
                size = static_cast<ULONG>(buffer.size());
                error = query(buffer.empty() ? nullptr : buffer.data(), &size);
                if (error != ERROR_INSUFFICIENT_BUFFER)
                    break;
                if (!size || size > 64 * 1024 * 1024) {
                    error = ERROR_NOT_ENOUGH_MEMORY;
                    break;
                }
                if (attempt != 4)
                    buffer.resize(size);
            }
            if (error == NO_ERROR) {
                if (buffer.size() < offsetof(Table, table))
                    error = ERROR_INVALID_DATA;
                else {
                    const auto* table = reinterpret_cast<const Table*>(buffer.data());
                    if (table->dwNumEntries > (buffer.size() - offsetof(Table, table)) / sizeof(table->table[0]))
                        error = ERROR_INVALID_DATA;
                }
            }
            if (error != NO_ERROR) {
                coverage.status = L"failed";
                coverage.nativeCode = error;
                result.issues.push_back({ coverage.source, L"", L"NETWORK_TABLE_FAILED", error,
                                          L"The requested connection table could not be collected.", true });
                return;
            }
            coverage.status = L"complete";
            const auto* table = reinterpret_cast<const Table*>(buffer.data());
            const auto observedAt = CurrentFileTime();
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                if (context.ShouldStop()) {
                    coverage.status = StatusName(context.StopStatus());
                    break;
                }
                if (options.pid && table->table[i].dwOwningPid != *options.pid)
                    continue;
                if (result.records.size() >= context.maxRecords) {
                    result.collectionTruncated = true;
                    coverage.status = L"partial";
                    result.issues.push_back(
                        { coverage.source, L"", L"COLLECTION_LIMIT", 0,
                          L"The collection record budget was reached; additional records may exist.", true });
                    break;
                }
                auto connection = Convert(table->table[i]);
                connection.observedAt = observedAt;
                result.records.push_back(std::move(connection));
                ++coverage.collected;
            }
            if (context.progress)
                context.progress(coverage.source, result.records.size());
        }

        struct ProcessMetadata {
            std::wstring name;
            std::wstring path;
            std::uint64_t createdAt = 0;
            FieldState nameState = FieldState::Unknown;
            FieldState pathState = FieldState::Unknown;
            FieldState timeState = FieldState::Unknown;
            DWORD error = 0;
        };

        void EnrichProcesses(CollectionResult<Connection>& result, CollectionContext& context) {
            std::map<DWORD, ProcessMetadata> processes;
            for (const auto& c : result.records)
                processes.try_emplace(c.pid);
            UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            if (snapshot.valid()) {
                PROCESSENTRY32W entry{};
                entry.dwSize = sizeof(entry);
                if (Process32FirstW(snapshot.get(), &entry)) {
                    do {
                        if (context.ShouldStop())
                            break;
                        const auto found = processes.find(entry.th32ProcessID);
                        if (found != processes.end()) {
                            found->second.name = entry.szExeFile;
                            found->second.nameState = FieldState::Available;
                        }
                    } while (Process32NextW(snapshot.get(), &entry));
                    const DWORD error = GetLastError();
                    if (!context.ShouldStop() && error != ERROR_NO_MORE_FILES)
                        result.issues.push_back({ L"process_snapshot", L"", L"PROCESS_SNAPSHOT_INCOMPLETE", error,
                                                  L"Some process names could not be enumerated.", false });
                } else {
                    result.issues.push_back({ L"process_snapshot", L"", L"PROCESS_SNAPSHOT_FAILED", GetLastError(),
                                              L"Process names could not be enumerated.", false });
                }
            } else {
                result.issues.push_back({ L"process_snapshot", L"", L"PROCESS_SNAPSHOT_FAILED", GetLastError(),
                                          L"Process names could not be enumerated.", false });
            }
            for (auto& entry : processes) {
                if (context.ShouldStop())
                    break;
                auto& info = entry.second;
                if (entry.first == 0 || entry.first == 4) {
                    info.name = entry.first == 0 ? L"System Idle Process" : L"System";
                    info.nameState = FieldState::Available;
                    info.pathState = info.timeState = FieldState::NotApplicable;
                    continue;
                }
                UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.first));
                if (process.valid()) {
                    std::vector<wchar_t> path(32768);
                    DWORD length = static_cast<DWORD>(path.size());
                    if (QueryFullProcessImageNameW(process.get(), 0, path.data(), &length)) {
                        info.path.assign(path.data(), length);
                        info.pathState = FieldState::Available;
                        const auto slash = info.path.find_last_of(L"\\/");
                        info.name = info.path.substr(slash == std::wstring::npos ? 0 : slash + 1);
                        info.nameState = FieldState::Available;
                    } else
                        info.error = GetLastError();
                    FILETIME created{}, exited{}, kernel{}, user{};
                    if (GetProcessTimes(process.get(), &created, &exited, &kernel, &user)) {
                        info.createdAt =
                            (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
                        info.timeState = FieldState::Available;
                    } else if (!info.error)
                        info.error = GetLastError();
                } else
                    info.error = GetLastError();
                if (info.error)
                    result.issues.push_back(
                        { L"process_metadata", std::to_wstring(entry.first), L"PROCESS_METADATA_UNAVAILABLE",
                          info.error, L"Some process metadata is unavailable; the connection itself was collected.",
                          false });
            }
            for (auto& c : result.records) {
                const auto& info = processes.at(c.pid);
                if (info.createdAt && info.createdAt > c.observedAt) {
                    c.processNameState = c.processPathState = c.processTimeState = FieldState::Unknown;
                    c.processError = ERROR_NOT_FOUND;
                    continue;
                }
                c.processName = info.name;
                c.processPath = info.path;
                c.processCreatedAt = info.createdAt;
                c.processNameState = info.nameState;
                c.processPathState = info.pathState;
                c.processTimeState = info.timeState;
                c.processError = info.error;
            }
        }
    }

    CollectionResult<Connection> CollectConnections(const NetworkOptions& options, CollectionContext& context) {
        CollectionResult<Connection> result;
        result.startedAt = UtcNow();
        result.assessment = AssessmentState::NotApplicable;
        WSADATA data{};
        const int startupError = WSAStartup(MAKEWORD(2, 2), &data);
        if (startupError) {
            result.issues.push_back({ L"network", L"", L"NETWORK_INITIALIZATION_FAILED",
                                      static_cast<DWORD>(startupError), L"Winsock initialization failed.", true });
            result.finishedAt = UtcNow();
            return result;
        }

        struct WinsockLifetime {
            ~WinsockLifetime() {
                WSACleanup();
            }
        } winsock;

        for (unsigned table = 0; table < 4; ++table) {
            const auto transport = table < 2 ? Transport::Tcp : Transport::Udp;
            const bool ipv6 = table % 2 != 0;
            if (!IncludesProtocol(options.protocol, transport, ipv6))
                continue;
            SourceCoverage coverage;
            coverage.source = table == 0 ? L"tcp4" : table == 1 ? L"tcp6" : table == 2 ? L"udp4" : L"udp6";
            auto tcp4 = [](PVOID buffer, PDWORD size) {
                return GetExtendedTcpTable(buffer, size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            };
            auto tcp6 = [](PVOID buffer, PDWORD size) {
                return GetExtendedTcpTable(buffer, size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            };
            auto udp4 = [](PVOID buffer, PDWORD size) {
                return GetExtendedUdpTable(buffer, size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            };
            auto udp6 = [](PVOID buffer, PDWORD size) {
                return GetExtendedUdpTable(buffer, size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            };
            switch (table) {
            case 0:
                ReadTable<MIB_TCPTABLE_OWNER_PID>(options, context, result, coverage, tcp4);
                break;
            case 1:
                ReadTable<MIB_TCP6TABLE_OWNER_PID>(options, context, result, coverage, tcp6);
                break;
            case 2:
                ReadTable<MIB_UDPTABLE_OWNER_PID>(options, context, result, coverage, udp4);
                break;
            case 3:
                ReadTable<MIB_UDP6TABLE_OWNER_PID>(options, context, result, coverage, udp6);
                break;
            }
            result.sources.push_back(std::move(coverage));
        }
        if (options.resolveProcesses && !context.ShouldStop())
            EnrichProcesses(result, context);
        bool anyComplete = false, anyFailed = false;
        for (const auto& source : result.sources) {
            anyComplete |= source.status == L"complete";
            anyFailed |= source.status != L"complete";
        }
        if (context.ShouldStop()) {
            result.status = context.StopStatus();
            result.issues.push_back({ L"network", L"", context.IsCancelled() ? L"CANCELLED" : L"TIMED_OUT", 0,
                                      L"Collection stopped before all requested work completed.", true });
        } else if (result.collectionTruncated)
            result.status = CollectionStatus::Partial;
        else if (!anyComplete)
            result.status = CollectionStatus::Failed;
        else
            result.status = anyFailed ? CollectionStatus::Partial : CollectionStatus::Complete;
        result.collected = result.records.size();
        result.finishedAt = UtcNow();
        return result;
    }

    const wchar_t* ProtocolName(Transport transport) {
        return transport == Transport::Tcp ? L"TCP" : L"UDP";
    }

    const wchar_t* TcpStateName(std::uint32_t state) {
        switch (state) {
        case MIB_TCP_STATE_CLOSED:
            return L"CLOSED";
        case MIB_TCP_STATE_LISTEN:
            return L"LISTENING";
        case MIB_TCP_STATE_SYN_SENT:
            return L"SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:
            return L"SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:
            return L"ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:
            return L"FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:
            return L"FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT:
            return L"CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:
            return L"CLOSING";
        case MIB_TCP_STATE_LAST_ACK:
            return L"LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:
            return L"TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB:
            return L"DELETE_TCB";
        default:
            return L"UNKNOWN";
        }
    }

    bool IsLocalAddress(const std::wstring& address) {
        if (address == L"*")
            return true;
        const auto type = ip::ParseAddress(address).type;
        // 无效地址不能作为外联端点。
        return type == ip::AddressType::Invalid || type == ip::AddressType::Unspecified ||
               type == ip::AddressType::Loopback;
    }

    bool IsIntranetAddress(const std::wstring& address) {
        const auto type = ip::ParseAddress(address).type;
        return type == ip::AddressType::Private || type == ip::AddressType::LinkLocal;
    }

    bool ContainsInsensitive(const std::wstring& text, const std::wstring& needle) {
        return Lower(text).find(Lower(needle)) != std::wstring::npos;
    }

    bool MatchesConnection(const Connection& c, const FilterOptions& options) {
        if (!IncludesProtocol(options.protocol, c.transport, c.isIPv6))
            return false;
        if (options.pid && c.pid != *options.pid)
            return false;
        const bool tcp = c.transport == Transport::Tcp;
        const bool listen = tcp && c.tcpState == MIB_TCP_STATE_LISTEN;
        switch (options.state) {
        case StateFilter::Listening:
            if (!listen)
                return false;
            break;
        case StateFilter::Established:
            if (!tcp || c.tcpState != MIB_TCP_STATE_ESTAB)
                return false;
            break;
        case StateFilter::TimeWait:
            if (!tcp || c.tcpState != MIB_TCP_STATE_TIME_WAIT)
                return false;
            break;
        case StateFilter::Other:
            if (!tcp || listen || c.tcpState == MIB_TCP_STATE_ESTAB || c.tcpState == MIB_TCP_STATE_TIME_WAIT)
                return false;
            break;
        default:
            break;
        }
        const bool intranet = IsIntranetAddress(c.remoteAddress);
        switch (options.scope) {
        case ScopeFilter::External:
            if (listen || IsLocalAddress(c.remoteAddress) || intranet)
                return false;
            break;
        case ScopeFilter::Intranet:
            if (!intranet)
                return false;
            break;
        case ScopeFilter::LocalListen:
            if (!listen)
                return false;
            break;
        default:
            break;
        }
        if (options.searchText.empty())
            return true;
        const auto& search = options.searchText;
        return ContainsInsensitive(ProtocolName(c.transport), search) || ContainsInsensitive(c.localAddress, search) ||
               ContainsInsensitive(std::to_wstring(c.localPort), search) ||
               ContainsInsensitive(c.remoteAddress, search) ||
               ContainsInsensitive(std::to_wstring(c.remotePort), search) ||
               ContainsInsensitive(std::to_wstring(c.pid), search) || ContainsInsensitive(c.processName, search) ||
               (tcp && ContainsInsensitive(TcpStateName(c.tcpState), search));
    }

    bool LessConnection(const Connection& a, const Connection& b, SortMode mode) {
        switch (mode) {
        case SortMode::ByPID:
            if (a.pid != b.pid)
                return a.pid < b.pid;
            break;
        case SortMode::ByProcess: {
            const int cmp = _wcsicmp(a.processName.c_str(), b.processName.c_str());
            if (cmp)
                return cmp < 0;
            break;
        }
        case SortMode::ByLocalPort:
            if (a.localPort != b.localPort)
                return a.localPort < b.localPort;
            break;
        case SortMode::ByRemoteAddr:
            if (a.remoteAddress != b.remoteAddress)
                return a.remoteAddress < b.remoteAddress;
            break;
        case SortMode::ByState: {
            const std::wstring sa = a.transport == Transport::Tcp ? TcpStateName(a.tcpState) : L"";
            const std::wstring sb = b.transport == Transport::Tcp ? TcpStateName(b.tcpState) : L"";
            if (sa != sb)
                return sa < sb;
            break;
        }
        default:
            break;
        }
        return std::tie(a.pid, a.transport, a.isIPv6, a.localAddress, a.localScopeId, a.localPort, a.remoteAddress,
                        a.remoteScopeId, a.remotePort,
                        a.tcpState) < std::tie(b.pid, b.transport, b.isIPv6, b.localAddress, b.localScopeId,
                                               b.localPort, b.remoteAddress, b.remoteScopeId, b.remotePort, b.tcpState);
    }

    namespace {
        template <class Range, class Access>
        std::vector<RemoteEndpoint> ExtractEndpoints(const Range& connections, UniqueBy uniqueBy,
                                                     CollectionContext* context, Access access) {
            using Key = std::tuple<std::wstring, bool, std::uint32_t, Transport, std::uint16_t>;
            std::set<Key> seen;
            std::vector<RemoteEndpoint> result;
            for (const auto& value : connections) {
                if (context && context->ShouldStop())
                    break;
                const auto& c = access(value);
                if (c.remoteAddress.empty() || IsLocalAddress(c.remoteAddress))
                    continue;
                const bool full = uniqueBy == UniqueBy::Endpoint;
                if (full && !c.remotePort)
                    continue;
                seen.emplace(c.remoteAddress, c.isIPv6, c.remoteScopeId, full ? c.transport : Transport::Tcp,
                             full ? c.remotePort : static_cast<std::uint16_t>(0));
            }
            result.reserve(seen.size());
            for (const auto& key : seen)
                result.push_back({ std::get<0>(key), std::get<1>(key), std::get<2>(key), std::get<3>(key),
                                   std::get<4>(key), uniqueBy == UniqueBy::Endpoint });
            return result;
        }
    }

    std::vector<RemoteEndpoint> ExtractRemoteEndpoints(const std::vector<Connection>& connections, UniqueBy uniqueBy,
                                                       CollectionContext* context) {
        return ExtractEndpoints(connections, uniqueBy, context, [](const Connection& c) -> const Connection& {
            return c;
        });
    }

    std::vector<RemoteEndpoint> ExtractRemoteEndpoints(const std::vector<const Connection*>& connections,
                                                       UniqueBy uniqueBy, CollectionContext* context) {
        return ExtractEndpoints(connections, uniqueBy, context, [](const Connection* c) -> const Connection& {
            return *c;
        });
    }

    std::wstring FormatEndpoint(const RemoteEndpoint& endpoint) {
        auto address = endpoint.address;
        if (endpoint.scopeId)
            address += L"%" + std::to_wstring(endpoint.scopeId);
        if (!endpoint.hasPort)
            return address;
        if (endpoint.isIPv6)
            address = L"[" + address + L"]";
        return address + L":" + std::to_wstring(endpoint.port);
    }
}
