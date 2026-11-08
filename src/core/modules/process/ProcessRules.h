#pragma once
#include "ProcessCollector.h"
#include "../../system/FileService.h"

namespace wgwc::core::process {
    struct SystemLocations {
        std::wstring system32, sysWow64, windows;
    };

    SystemLocations QuerySystemLocations();
    bool IsSystemProcess(const std::wstring& name);
    bool IsValidSystemProcessPath(const std::wstring& name, const std::wstring& path, const SystemLocations& locations);
    RiskAssessment AssessProcess(const Metadata& process, const files::FileInfo& file,
                                 const SystemLocations& locations);
    std::wstring RiskReason(const RiskAssessment& assessment);
}
