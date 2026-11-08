#pragma once
#include "GuiColumns.h"
#include <string>

namespace wgwc::core {
    enum class SignatureState;

    namespace traces {
        enum class ActivityType;
    }
}

namespace wgwc::gui::presentation {
    std::wstring Signature(core::SignatureState state, const std::wstring& publisher);
    std::wstring FileSize(unsigned long long size);
    std::wstring LocalTime(unsigned long long time);
    const wchar_t* ActivityName(core::traces::ActivityType type);
}
