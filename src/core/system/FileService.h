#pragma once
#include "../model/FileEvidence.h"
#include "../runtime/CollectionContext.h"
#include <map>

namespace wgwc::core::files {
    struct SignatureInfo {
        SignatureState state = SignatureState::Unknown;
        std::wstring publisher;
        std::uint32_t nativeCode = 0;
        SignatureSource source = SignatureSource::None;
        std::wstring failureReason;
    };

    struct FileInfo {
        FileEvidence evidence;
        std::wstring description;
        FieldState versionState = FieldState::NotRequested;
        FieldState attributesState = FieldState::NotRequested;
        std::uint32_t attributes = 0;
        std::uint64_t size = 0;
        std::uint64_t createdAt = 0;
        std::uint64_t modifiedAt = 0;
        bool directory = false;
    };

    inline std::wstring SourceKey(const FileInfo& file) {
        return file.evidence.resolvedPath.empty() ? file.evidence.originalValue : file.evidence.resolvedPath;
    }
    enum class HashAlgorithm {
        All,
        Md5,
        Sha1,
        Sha256
    };

    struct Hashes {
        CollectionStatus status = CollectionStatus::Failed;
        std::wstring md5, sha1, sha256;
        std::uint64_t size = 0;
        std::uint32_t nativeCode = 0;
        std::wstring errorCode;
        std::vector<CollectionIssue> issues;
    };

    std::wstring ExpandEnvironment(const std::wstring& value);
    std::wstring ResolvePath(const std::wstring& value, std::uint32_t* error = nullptr);
    std::wstring LocalTimeText(std::uint64_t timestamp);
    SignatureState SignatureStateFromTrustStatus(std::int32_t status);
    const wchar_t* SignatureFailureReason(std::uint32_t code);
    const wchar_t* SignatureSourceName(SignatureSource source);
    SignatureInfo VerifySignature(const std::wstring& path);
    FileInfo QueryFile(const std::wstring& path, bool signature, const CollectionContext* context = nullptr);
    Hashes CalculateHashes(const std::wstring& path, HashAlgorithm algorithm, std::uint64_t maxBytes,
                           const CollectionContext& context);
    const wchar_t* SignatureName(SignatureState state);

    class EvidenceCache {
    public:
        const FileInfo& Get(const std::wstring& path, bool signature, const CollectionContext& context);

    private:
        struct Entry {
            FileInfo info;
            bool reusable = false;
        };

        // 此缓存由单个采集线程独占；返回的引用仅供立即使用。
        std::map<std::pair<std::wstring, bool>, Entry> entries_;
    };
}
