#pragma once
#include "ProcessRules.h"
#include <optional>

namespace wgwc::core::process {
    struct ProcessRecord {
        Metadata process;
        files::FileInfo file;
        RiskAssessment assessment;
    };

    struct ProcessOptions {
        std::optional<std::uint32_t> pid;
        bool signature = true;
    };

    CollectionResult<ProcessRecord> CollectProcesses(const ProcessOptions& options, const CollectionContext& context);

    struct ModuleRecord {
        std::uint32_t pid = 0;
        std::wstring name, path;
        std::uint64_t baseAddress = 0;
        std::uint32_t imageSize = 0;
        FieldState imageSizeState = FieldState::Unknown;
        std::uint64_t processCreatedAt = 0;
        files::FileInfo file;
    };

    inline std::wstring SourceKey(const ModuleRecord& record) {
        return SourceKey(record.pid, record.processCreatedAt) + L":module:" + std::to_wstring(record.baseAddress);
    }

    CollectionResult<ModuleRecord> CollectModules(std::uint32_t pid, bool signature, const CollectionContext& context);
}
