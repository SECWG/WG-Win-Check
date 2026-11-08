// GUI 兼容适配层；接口传输和结果校验由 Core 负责。
#include "../../../core/system/Win32.h"
#include "../../../core/system/IpLookupService.h"
#include "IpLocationService.h"

std::map<std::wstring, std::wstring> IpLocationService::QueryBatch(const std::vector<std::wstring>& ips,
                                                                   std::atomic_bool* cancelFlag, std::wstring* error) {
    using namespace wgwc::core;
    if (error)
        error->clear();
    if (ips.empty() || (cancelFlag && cancelFlag->load()))
        return {};
    CollectionContext context;
    context.externalCancel = cancelFlag;
    context.deadlineTick = TickNow() + 30000;
    const auto collected = ip::QueryBatch(ips, context);
    std::map<std::wstring, std::wstring> result;
    bool batchFailed = collected.records.empty();
    for (const auto& record : collected.records) {
        // 单条没有归属信息不是传输失败，不能阻断后续批次。
        if (record.state != ip::LookupState::Success && record.state != ip::LookupState::NotFound &&
            record.state != ip::LookupState::LocalOnly)
            batchFailed = true;
        if (record.state == ip::LookupState::Success)
            result[record.input] = record.location;
        if (error && record.state == ip::LookupState::RateLimited)
            *error = L"IP 归属查询过于频繁，请稍后重试";
    }
    if (error && error->empty() && batchFailed && collected.status != CollectionStatus::Complete) {
        if (collected.status == CollectionStatus::Cancelled)
            *error = L"IP 归属查询已取消";
        else if (collected.status == CollectionStatus::TimedOut)
            *error = L"IP 归属查询超时";
        else
            *error = L"IP 归属查询未完成";
    }
    return result;
}
