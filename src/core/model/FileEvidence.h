#pragma once
#include "CollectionIssue.h"
#include <vector>

namespace wgwc::core {
    enum class SignatureState {
        Signed,
        Unsigned,
        Mismatch,
        Unknown
    };
    enum class SignatureSource {
        None,
        Embedded,
        Catalog
    };

    struct FileEvidence {
        std::wstring evidenceId;
        std::wstring originalValue;
        std::wstring resolvedPath;
        std::wstring source;
        std::wstring fileIdentity;
        FieldState resolution = FieldState::NotRequested;
        FieldState existence = FieldState::NotRequested;
        bool exists = false;
        SignatureState signature = SignatureState::Unknown;
        FieldState signatureState = FieldState::NotRequested;
        std::wstring publisher;
        std::wstring company;
        std::vector<CollectionIssue> issues;
        SignatureSource signatureSource = SignatureSource::None;
        std::uint32_t signatureNativeCode = 0;
        std::wstring signatureFailureReason;
    };
}
