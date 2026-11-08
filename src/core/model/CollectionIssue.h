#pragma once
#include <cstdint>
#include <string>

namespace wgwc::core {
    enum class FieldState {
        Available,
        Unknown,
        NotRequested,
        NotApplicable
    };

    inline const wchar_t* FieldStateName(FieldState state) {
        switch (state) {
        case FieldState::Available:
            return L"available";
        case FieldState::NotRequested:
            return L"not_requested";
        case FieldState::NotApplicable:
            return L"not_applicable";
        default:
            return L"unknown";
        }
    }

    struct CollectionIssue {
        std::wstring source;
        std::wstring objectKey;
        std::wstring code;
        std::uint32_t nativeCode = 0;
        std::wstring message;
        bool affectsCompleteness = false;
    };
}
