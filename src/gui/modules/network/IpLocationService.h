#pragma once

#include <atomic>
#include <map>
#include <string>
#include <vector>

class IpLocationService {
public:
    static std::map<std::wstring, std::wstring> QueryBatch(const std::vector<std::wstring>& ips,
                                                           std::atomic_bool* cancelFlag, std::wstring* error);
};
