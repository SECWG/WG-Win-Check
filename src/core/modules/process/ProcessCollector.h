#pragma once
#include "../../runtime/CollectionContext.h"
#include <functional>
#include <optional>

namespace wgwc::core::process {
    // 仅采集元数据，不查询文件签名、不构建 GUI 展示对象，也不进行风险分析。
    // PID 关联为尽力获取结果，查询过程不构成原子化的系统快照。
    struct Metadata {
        std::uint32_t pid = 0;
        std::uint32_t ppid = 0;
        std::uint32_t threadCount = 0;
        std::wstring name;
        std::wstring path;
        std::wstring commandLine;
        std::wstring user;
        std::wstring parentName;
        std::wstring startTimeLocal;
        std::uint64_t createdAt = 0;
        std::wstring observedAt;
        FieldState pathState = FieldState::Unknown;
        FieldState commandLineState = FieldState::Unknown;
        FieldState userState = FieldState::Unknown;
        FieldState createdAtState = FieldState::Unknown;
    };

    // 与风险汇总和 CLI 输出共用；时间为零时，仅以 PID 进行弱身份关联。
    inline std::wstring SourceKey(std::uint32_t pid, std::uint64_t createdAt) {
        return std::to_wstring(pid) + L":" + std::to_wstring(createdAt);
    }

    inline std::wstring SourceKey(const Metadata& record) {
        return SourceKey(record.pid, record.createdAt);
    }

    // 观察回调在处理下一进程前同步执行，
    // 保留 GUI 现有的“元数据、文件信息补全、风险分析”顺序。
    using MetadataObserver = std::function<void(const Metadata&)>;
    CollectionResult<Metadata> CollectMetadata(const CollectionContext& context, const MetadataObserver& observer = {},
                                               std::optional<std::uint32_t> targetPid = std::nullopt);
}
