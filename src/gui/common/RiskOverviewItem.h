#pragma once

#include <windows.h>
#include <string>
#include <cstdio>
#include "../../core/model/RiskFinding.h"

using SuspicionLevel = wgwc::core::RiskLevel;

// 模块仍沿用高、中、低三级展示；核心的严重等级按原有行为归入高危。
inline SuspicionLevel ToModuleRiskLevel(wgwc::core::RiskLevel level) {
    switch (level) {
    case wgwc::core::RiskLevel::High:
    case wgwc::core::RiskLevel::Critical:
        return SuspicionLevel::High;
    case wgwc::core::RiskLevel::Medium:
        return SuspicionLevel::Medium;
    case wgwc::core::RiskLevel::Low:
        return SuspicionLevel::Low;
    default:
        return SuspicionLevel::None;
    }
}

struct RiskOverviewItem {
    std::wstring moduleId;
    std::wstring moduleName;
    int tabIndex = -1;
    SuspicionLevel level = SuspicionLevel::None;
    std::wstring objectName;
    std::wstring info;
    std::wstring info2;
    std::wstring reason;
    std::wstring updatedAt;
    std::wstring sourceKey;
    int sourceRow = -1;
};

inline int RiskOverviewSeverityRank(SuspicionLevel level) {
    return static_cast<int>(level);
}

inline std::wstring RiskOverviewNowString() {
    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t buffer[32];
    swprintf_s(buffer, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
               st.wSecond);
    return buffer;
}
