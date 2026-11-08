#include "Win32.h"
#include "FileService.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <algorithm>
#include <cwchar>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")

namespace wgwc::core::files {
    namespace {
        std::uint64_t Timestamp(const FILETIME& value) {
            return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
        }

        bool Placeholder(const std::wstring& path) {
            return path.empty() || path.front() == L'<' || path.front() == L'[';
        }

        std::wstring VersionValue(const std::vector<BYTE>& bytes, const wchar_t* key) {
            struct Translation {
                WORD language, codepage;
            };

            Translation* translations = nullptr;
            UINT count = 0;
            if (!VerQueryValueW(bytes.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&translations),
                                &count) ||
                count < sizeof(Translation))
                return L"";
            wchar_t block[256]{};
            swprintf_s(block, L"\\StringFileInfo\\%04x%04x\\%s", translations[0].language, translations[0].codepage,
                       key);
            void* value = nullptr;
            UINT length = 0;
            if (!VerQueryValueW(bytes.data(), block, &value, &length) || !value || !length)
                return L"";
            return static_cast<const wchar_t*>(value);
        }

        bool ReadVersion(const std::wstring& path, std::wstring& company, std::wstring& description) {
            DWORD ignored = 0;
            const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
            if (!size || size > 16 * 1024 * 1024)
                return false;
            std::vector<BYTE> bytes(size);
            if (!GetFileVersionInfoW(path.c_str(), 0, size, bytes.data()))
                return false;
            company = VersionValue(bytes, L"CompanyName");
            description = VersionValue(bytes, L"FileDescription");
            return true;
        }

        void FileIssue(FileInfo& info, const wchar_t* code, DWORD native, const wchar_t* message) {
            const auto& object =
                info.evidence.resolvedPath.empty() ? info.evidence.originalValue : info.evidence.resolvedPath;
            info.evidence.issues.push_back({ L"file", object, code, native, message, false });
        }
    }

    std::wstring ExpandEnvironment(const std::wstring& value) {
        if (value.empty())
            return value;
        const DWORD size = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
        if (!size || size > 32768)
            return value;
        std::vector<wchar_t> buffer(size);
        const DWORD copied = ExpandEnvironmentStringsW(value.c_str(), buffer.data(), size);
        return copied && copied <= size ? std::wstring(buffer.data()) : value;
    }

    std::wstring ResolvePath(const std::wstring& value, std::uint32_t* error) {
        if (error)
            *error = 0;
        auto path = ExpandEnvironment(value);
        if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"')
            path = path.substr(1, path.size() - 2);
        if (Placeholder(path)) {
            if (error)
                *error = ERROR_INVALID_NAME;
            return L"";
        }
        const DWORD length = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
        if (!length || length > 32768) {
            if (error)
                *error = GetLastError();
            return L"";
        }
        std::vector<wchar_t> buffer(static_cast<std::size_t>(length) + 1);
        const DWORD copied = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
        if (!copied || copied >= buffer.size()) {
            if (error)
                *error = ERROR_INVALID_NAME;
            return L"";
        }
        std::wstring resolved(buffer.data(), copied);
        if (resolved.size() >= MAX_PATH && resolved.rfind(L"\\\\?\\", 0) != 0) {
            resolved = resolved.rfind(L"\\\\", 0) == 0 ? L"\\\\?\\UNC\\" + resolved.substr(2) : L"\\\\?\\" + resolved;
        }
        return resolved;
    }

    std::wstring LocalTimeText(std::uint64_t timestamp) {
        if (!timestamp)
            return L"";
        FILETIME source{ static_cast<DWORD>(timestamp), static_cast<DWORD>(timestamp >> 32) }, local{};
        SYSTEMTIME value{};
        if (!FileTimeToLocalFileTime(&source, &local) || !FileTimeToSystemTime(&local, &value))
            return L"";
        wchar_t text[64]{};
        swprintf_s(text, L"%04u-%02u-%02u %02u:%02u:%02u", value.wYear, value.wMonth, value.wDay, value.wHour,
                   value.wMinute, value.wSecond);
        return text;
    }

    static std::wstring GetPublisherFromWinTrustState(HANDLE hStateData) {
        if (!hStateData) {
            return L"";
        }

        CRYPT_PROVIDER_DATA* providerData = WTHelperProvDataFromStateData(hStateData);
        if (!providerData) {
            return L"";
        }

        CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(providerData, 0, FALSE, 0);
        if (!signer || signer->csCertChain == 0 || !signer->pasCertChain) {
            return L"";
        }

        PCCERT_CONTEXT certContext = signer->pasCertChain[0].pCert;
        if (!certContext) {
            return L"";
        }

        DWORD nameLen = CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
        if (nameLen <= 1) {
            return L"";
        }

        std::vector<wchar_t> nameBuffer(nameLen);
        DWORD copied =
            CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nameBuffer.data(), nameLen);
        if (copied <= 1) {
            return L"";
        }

        return nameBuffer.data();
    }

    SignatureState SignatureStateFromTrustStatus(std::int32_t status) {
        if (status == ERROR_SUCCESS)
            return SignatureState::Signed;
        if (status == TRUST_E_NOSIGNATURE)
            return SignatureState::Unsigned;
        if (status == TRUST_E_BAD_DIGEST || status == TRUST_E_EXPLICIT_DISTRUST ||
            status == TRUST_E_SUBJECT_NOT_TRUSTED || status == CERT_E_UNTRUSTEDROOT)
            return SignatureState::Mismatch;
        // 缺少校验提供程序或不支持相应操作，不能作为签名损坏的证据。
        return SignatureState::Unknown;
    }

    const wchar_t* SignatureFailureReason(std::uint32_t code) {
        switch (code) {
        case ERROR_SUCCESS:
            return L"";
        case static_cast<std::uint32_t>(TRUST_E_NOSIGNATURE):
            return L"no_signature";
        case static_cast<std::uint32_t>(TRUST_E_BAD_DIGEST):
            return L"digest_mismatch";
        case static_cast<std::uint32_t>(TRUST_E_EXPLICIT_DISTRUST):
            return L"explicit_distrust";
        case static_cast<std::uint32_t>(TRUST_E_SUBJECT_NOT_TRUSTED):
            return L"subject_not_trusted";
        case static_cast<std::uint32_t>(CERT_E_UNTRUSTEDROOT):
            return L"untrusted_root";
        case static_cast<std::uint32_t>(CERT_E_REVOKED):
            return L"certificate_revoked";
        case static_cast<std::uint32_t>(CERT_E_EXPIRED):
            return L"certificate_expired";
        case static_cast<std::uint32_t>(CERT_E_CHAINING):
            return L"certificate_chain_incomplete";
        case static_cast<std::uint32_t>(CERT_E_REVOCATION_FAILURE):
            return L"revocation_check_failed";
        case static_cast<std::uint32_t>(CRYPT_E_NO_REVOCATION_CHECK):
            return L"revocation_check_unavailable";
        case static_cast<std::uint32_t>(CRYPT_E_REVOCATION_OFFLINE):
            return L"revocation_offline";
        case static_cast<std::uint32_t>(TRUST_E_TIME_STAMP):
            return L"timestamp_invalid";
        case static_cast<std::uint32_t>(TRUST_E_PROVIDER_UNKNOWN):
            return L"trust_provider_unavailable";
        case static_cast<std::uint32_t>(TRUST_E_ACTION_UNKNOWN):
            return L"unsupported_trust_action";
        case static_cast<std::uint32_t>(TRUST_E_SUBJECT_FORM_UNKNOWN):
            return L"unsupported_file_type";
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
            return L"file_not_found";
        case ERROR_ACCESS_DENIED:
            return L"access_denied";
        case ERROR_SHARING_VIOLATION:
            return L"sharing_violation";
        case ERROR_INVALID_NAME:
            return L"invalid_path";
        case ERROR_DIRECTORY:
            return L"target_is_directory";
        case ERROR_PROC_NOT_FOUND:
            return L"catalog_api_unavailable";
        case ERROR_RETRY:
            return L"file_changed_during_verification";
        default:
            return L"verification_unavailable";
        }
    }

    const wchar_t* SignatureSourceName(SignatureSource source) {
        switch (source) {
        case SignatureSource::Embedded:
            return L"embedded";
        case SignatureSource::Catalog:
            return L"catalog";
        default:
            return L"";
        }
    }

    namespace {
        SignatureInfo SignatureError(DWORD code, SignatureSource source = SignatureSource::None) {
            SignatureInfo info;
            info.nativeCode = code ? code : ERROR_GEN_FAILURE;
            info.failureReason = SignatureFailureReason(info.nativeCode);
            info.source = source;
            return info;
        }

        SignatureInfo CheckTrust(WINTRUST_DATA& data, SignatureSource source) {
            data.cbStruct = sizeof(data);
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = WTD_REVOKE_NONE;
            data.dwStateAction = WTD_STATEACTION_VERIFY;
            data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
            GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            const LONG status = WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &data);
            SignatureInfo info;
            info.state = SignatureStateFromTrustStatus(status);
            info.nativeCode = static_cast<std::uint32_t>(status);
            info.publisher = GetPublisherFromWinTrustState(data.hWVTStateData);
            info.source = status == TRUST_E_NOSIGNATURE ? SignatureSource::None : source;
            info.failureReason = SignatureFailureReason(info.nativeCode);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &data);
            return info;
        }

        struct CatalogContext {
            HCATADMIN admin = nullptr;
            HCATINFO current = nullptr;

            ~CatalogContext() {
                if (current)
                    CryptCATAdminReleaseCatalogContext(admin, current, 0);
                if (admin)
                    CryptCATAdminReleaseContext(admin, 0);
            }
        };

        void RetainCatalogFailure(SignatureInfo& result, const SignatureInfo& failure) {
            if (result.state == SignatureState::Unsigned ||
                (result.state != SignatureState::Mismatch && failure.state == SignatureState::Mismatch))
                result = failure;
        }

        SignatureInfo CheckCatalog(const std::wstring& path, HANDLE file) {
            // 从已加载的系统依赖中解析函数，不搜索可写目录。
            static const HMODULE wintrust = GetModuleHandleW(L"wintrust.dll");
            static const auto acquire = wintrust ? reinterpret_cast<decltype(&CryptCATAdminAcquireContext2)>(
                                                       GetProcAddress(wintrust, "CryptCATAdminAcquireContext2"))
                                                 : nullptr;
            static const auto hashFile = wintrust
                                             ? reinterpret_cast<decltype(&CryptCATAdminCalcHashFromFileHandle2)>(
                                                   GetProcAddress(wintrust, "CryptCATAdminCalcHashFromFileHandle2"))
                                             : nullptr;
            if (!acquire || !hashFile)
                return SignatureError(ERROR_PROC_NOT_FOUND, SignatureSource::Catalog);

            SignatureInfo result;
            result.state = SignatureState::Unsigned;
            result.nativeCode = static_cast<std::uint32_t>(TRUST_E_NOSIGNATURE);
            result.failureReason = SignatureFailureReason(result.nativeCode);
            const wchar_t* algorithms[] = { L"SHA256", L"SHA1" };
            for (const auto* algorithm : algorithms) {
                CatalogContext context;
                if (!acquire(&context.admin, nullptr, algorithm, nullptr, 0)) {
                    RetainCatalogFailure(result, SignatureError(GetLastError(), SignatureSource::Catalog));
                    continue;
                }
                // 缓冲区足以容纳这两种算法的结果；使用编录/SIP 哈希，而不是原始文件哈希。
                BYTE hash[64]{};
                DWORD hashLength = sizeof(hash);
                LARGE_INTEGER origin{};
                if (!SetFilePointerEx(file, origin, nullptr, FILE_BEGIN) ||
                    !hashFile(context.admin, file, &hashLength, hash, 0)) {
                    RetainCatalogFailure(result, SignatureError(GetLastError(), SignatureSource::Catalog));
                    continue;
                }
                if (!hashLength || hashLength > sizeof(hash)) {
                    RetainCatalogFailure(result, SignatureError(ERROR_INVALID_DATA, SignatureSource::Catalog));
                    continue;
                }
                const wchar_t* digits = L"0123456789ABCDEF";
                std::wstring tag;
                tag.reserve(static_cast<std::size_t>(hashLength) * 2);
                for (DWORD i = 0; i < hashLength; ++i) {
                    tag += digits[hash[i] >> 4];
                    tag += digits[hash[i] & 15];
                }
                SetLastError(ERROR_SUCCESS);
                context.current = CryptCATAdminEnumCatalogFromHash(context.admin, hash, hashLength, 0, nullptr);
                while (context.current) {
                    CATALOG_INFO catalog{};
                    catalog.cbStruct = sizeof(catalog);
                    if (!CryptCATCatalogInfoFromContext(context.current, &catalog, 0)) {
                        RetainCatalogFailure(result, SignatureError(GetLastError(), SignatureSource::Catalog));
                    } else if (!SetFilePointerEx(file, origin, nullptr, FILE_BEGIN)) {
                        RetainCatalogFailure(result, SignatureError(GetLastError(), SignatureSource::Catalog));
                    } else {
                        WINTRUST_CATALOG_INFO member{};
                        member.cbStruct = sizeof(member);
                        member.pcwszCatalogFilePath = catalog.wszCatalogFile;
                        member.pcwszMemberTag = tag.c_str();
                        member.pcwszMemberFilePath = path.c_str();
                        member.hMemberFile = file;
                        member.pbCalculatedFileHash = hash;
                        member.cbCalculatedFileHash = hashLength;
                        member.hCatAdmin = context.admin;
                        WINTRUST_DATA data{};
                        data.dwUnionChoice = WTD_CHOICE_CATALOG;
                        data.pCatalog = &member;
                        auto verified = CheckTrust(data, SignatureSource::Catalog);
                        if (verified.state == SignatureState::Signed)
                            return verified;
                        // 匹配编录的签名无法读取时，不能据此认定成员文件未签名。
                        if (verified.state == SignatureState::Unsigned) {
                            verified.state = SignatureState::Unknown;
                            verified.source = SignatureSource::Catalog;
                            verified.failureReason = L"catalog_signature_unavailable";
                        }
                        RetainCatalogFailure(result, verified);
                    }
                    // 继续枚举时，将前一个上下文的所有权交给编录枚举器。
                    SetLastError(ERROR_SUCCESS);
                    context.current =
                        CryptCATAdminEnumCatalogFromHash(context.admin, hash, hashLength, 0, &context.current);
                }
                const DWORD error = GetLastError();
                if (error != ERROR_SUCCESS && error != ERROR_NOT_FOUND && error != ERROR_NO_MORE_ITEMS &&
                    error != static_cast<DWORD>(CRYPT_E_NOT_FOUND))
                    RetainCatalogFailure(result, SignatureError(error, SignatureSource::Catalog));
            }
            return result;
        }

        bool SameFileObservation(const BY_HANDLE_FILE_INFORMATION& a, const BY_HANDLE_FILE_INFORMATION& b) {
            return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh &&
                   a.nFileIndexLow == b.nFileIndexLow && a.nFileSizeHigh == b.nFileSizeHigh &&
                   a.nFileSizeLow == b.nFileSizeLow && CompareFileTime(&a.ftLastWriteTime, &b.ftLastWriteTime) == 0;
        }
    }

    SignatureInfo VerifySignature(const std::wstring& path) {
        std::uint32_t error = 0;
        const auto resolved = ResolvePath(path, &error);
        if (resolved.empty())
            return SignatureError(error ? error : ERROR_INVALID_NAME);
        const DWORD attributes = GetFileAttributesW(resolved.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
            return SignatureError(GetLastError());
        if (attributes & FILE_ATTRIBUTE_DIRECTORY)
            return SignatureError(ERROR_DIRECTORY);
        UniqueHandle file(CreateFileW(resolved.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0,
                                      nullptr));
        if (!file.valid())
            return SignatureError(GetLastError());
        BY_HANDLE_FILE_INFORMATION before{}, after{};
        if (!GetFileInformationByHandle(file.get(), &before))
            return SignatureError(GetLastError());

        WINTRUST_FILE_INFO target{};
        target.cbStruct = sizeof(target);
        target.pcwszFilePath = resolved.c_str();
        target.hFile = file.get();
        WINTRUST_DATA data{};
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.pFile = &target;
        auto info = CheckTrust(data, SignatureSource::Embedded);
        // 不能用无关的编录结果掩盖无效的嵌入式签名。
        if (info.nativeCode == static_cast<std::uint32_t>(TRUST_E_NOSIGNATURE) && info.publisher.empty())
            info = CheckCatalog(resolved, file.get());
        if (!GetFileInformationByHandle(file.get(), &after))
            return SignatureError(GetLastError());
        if (!SameFileObservation(before, after))
            return SignatureError(ERROR_RETRY);
        return info;
    }

    namespace {
        void PopulateFileSignature(FileInfo& result, const CollectionContext* context) {
            auto& evidence = result.evidence;
            evidence.signatureState = FieldState::Unknown;
            if (context && context->ShouldStop())
                return;
            const auto verified = VerifySignature(evidence.resolvedPath);
            evidence.signature = verified.state;
            evidence.publisher = verified.publisher;
            evidence.signatureSource = verified.source;
            evidence.signatureNativeCode = verified.nativeCode;
            evidence.signatureFailureReason = verified.failureReason;
            evidence.signatureState =
                verified.state == SignatureState::Unknown ? FieldState::Unknown : FieldState::Available;
            if (verified.state == SignatureState::Unknown)
                FileIssue(result, L"SIGNATURE_UNAVAILABLE", verified.nativeCode, verified.failureReason.c_str());
        }

        void OmitFileSignature(FileInfo& result) {
            auto& evidence = result.evidence;
            evidence.signature = SignatureState::Unknown;
            evidence.signatureState = FieldState::NotRequested;
            evidence.publisher.clear();
            evidence.signatureSource = SignatureSource::None;
            evidence.signatureNativeCode = 0;
            evidence.signatureFailureReason.clear();
            evidence.issues.erase(std::remove_if(evidence.issues.begin(), evidence.issues.end(),
                                                 [](const CollectionIssue& issue) {
                                                     return issue.code == L"SIGNATURE_UNAVAILABLE";
                                                 }),
                                  evidence.issues.end());
        }

        bool ReadFileObservation(const std::wstring& path, BY_HANDLE_FILE_INFORMATION& information, bool signature) {
            if (path.empty())
                return false;
            // 仅能读取文件属性，并不代表仍能读取签名字节。
            const DWORD access = signature ? GENERIC_READ : FILE_READ_ATTRIBUTES;
            UniqueHandle file(CreateFileW(path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                          nullptr, OPEN_EXISTING, 0, nullptr));
            return file.valid() && GetFileInformationByHandle(file.get(), &information);
        }

        bool MatchesFileObservation(const FileInfo& file, const BY_HANDLE_FILE_INFORMATION& information) {
            const auto& evidence = file.evidence;
            if (evidence.existence != FieldState::Available || !evidence.exists || file.directory ||
                file.attributesState != FieldState::Available || evidence.fileIdentity.empty())
                return false;
            const auto identity = std::to_wstring(information.dwVolumeSerialNumber) + L":" +
                                  std::to_wstring((static_cast<std::uint64_t>(information.nFileIndexHigh) << 32) |
                                                  information.nFileIndexLow);
            return evidence.fileIdentity == identity && file.attributes == information.dwFileAttributes &&
                   file.size ==
                       ((static_cast<std::uint64_t>(information.nFileSizeHigh) << 32) | information.nFileSizeLow) &&
                   file.createdAt == Timestamp(information.ftCreationTime) &&
                   file.modifiedAt == Timestamp(information.ftLastWriteTime);
        }
    }

    static FileInfo QueryFileUncached(const std::wstring& path, bool signature, const CollectionContext* context) {
        FileInfo result;
        auto& evidence = result.evidence;
        evidence.originalValue = path;
        evidence.source = L"file.path";
        evidence.signatureState = signature ? FieldState::Unknown : FieldState::NotRequested;
        std::uint32_t error = 0;
        evidence.resolvedPath = ResolvePath(path, &error);
        evidence.resolution = evidence.resolvedPath.empty() ? FieldState::Unknown : FieldState::Available;
        evidence.existence = FieldState::Unknown;
        if (evidence.resolvedPath.empty()) {
            FileIssue(result, L"PATH_UNRESOLVED", error, L"The input is not a usable file path.");
            return result;
        }
        evidence.evidenceId = evidence.resolvedPath;
        if (context && context->ShouldStop())
            return result;
        WIN32_FILE_ATTRIBUTE_DATA data{};
        if (!GetFileAttributesExW(evidence.resolvedPath.c_str(), GetFileExInfoStandard, &data)) {
            error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
                evidence.existence = FieldState::Available;
            result.attributesState = FieldState::Unknown;
            evidence.signatureState = signature ? FieldState::Unknown : FieldState::NotRequested;
            FileIssue(result, evidence.existence == FieldState::Available ? L"FILE_NOT_FOUND" : L"FILE_UNAVAILABLE",
                      error, L"File attributes could not be obtained.");
            return result;
        }
        evidence.existence = FieldState::Available;
        evidence.exists = true;
        result.attributesState = FieldState::Available;
        result.attributes = data.dwFileAttributes;
        result.directory = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        result.size = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
        result.createdAt = Timestamp(data.ftCreationTime);
        result.modifiedAt = Timestamp(data.ftLastWriteTime);
        if (result.directory) {
            evidence.signatureState = FieldState::NotApplicable;
            result.versionState = FieldState::NotApplicable;
            FileIssue(result, L"TARGET_IS_DIRECTORY", ERROR_DIRECTORY,
                      L"A file was requested, but the path is a directory.");
            return result;
        }
        result.versionState = ReadVersion(evidence.resolvedPath, evidence.company, result.description)
                                  ? FieldState::Available
                                  : FieldState::Unknown;
        // 文件身份是尽力获取的观测结果，不是内容哈希或事务性快照。
        UniqueHandle identity(CreateFileW(evidence.resolvedPath.c_str(), FILE_READ_ATTRIBUTES,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                          OPEN_EXISTING, 0, nullptr));
        BY_HANDLE_FILE_INFORMATION information{};
        if (identity.valid() && GetFileInformationByHandle(identity.get(), &information)) {
            evidence.fileIdentity = std::to_wstring(information.dwVolumeSerialNumber) + L":" +
                                    std::to_wstring((static_cast<std::uint64_t>(information.nFileIndexHigh) << 32) |
                                                    information.nFileIndexLow);
        }
        if (signature)
            PopulateFileSignature(result, context);
        return result;
    }

    FileInfo QueryFile(const std::wstring& path, bool signature, const CollectionContext* context) {
        if (context && context->fileCache) {
            auto result = context->fileCache->Get(path, signature, *context);
            result.evidence.originalValue = path;
            return result;
        }
        return QueryFileUncached(path, signature, context);
    }

    const wchar_t* SignatureName(SignatureState state) {
        switch (state) {
        case SignatureState::Signed:
            return L"signed";
        case SignatureState::Unsigned:
            return L"unsigned";
        case SignatureState::Mismatch:
            return L"mismatch";
        default:
            return L"unknown";
        }
    }

    const FileInfo& EvidenceCache::Get(const std::wstring& path, bool signature, const CollectionContext& context) {
        if (context.fileCache && context.fileCache.get() != this)
            return context.fileCache->Get(path, signature, context);
        const auto resolved = ResolvePath(path);
        // 不能统一路径大小写，因为 Windows 支持启用目录大小写敏感。
        const auto key = std::make_pair(resolved.empty() ? path : resolved, signature);
        auto& entry = entries_[key];
        if (context.ShouldStop()) {
            entry.reusable = false;
            entry.info = QueryFileUncached(path, signature, &context);
            return entry.info;
        }
        BY_HANDLE_FILE_INFORMATION before{}, after{};
        const bool observed = ReadFileObservation(resolved, before, signature);
        if (entry.reusable && observed && MatchesFileObservation(entry.info, before))
            return entry.info;
        entry.reusable = false;
        auto other = entries_.find(std::make_pair(key.first, !signature));
        if (other != entries_.end() && other->second.reusable &&
            (!observed || !MatchesFileObservation(other->second.info, before)))
            other->second.reusable = false;
        if (other != entries_.end() && other->second.reusable) {
            // 将元数据缓存补全为签名结果时，不重复读取版本信息。
            // 仅请求元数据的视图仍应将签名状态报告为 NotRequested。
            entry.info = other->second.info;
            entry.info.evidence.originalValue = path;
            if (signature)
                PopulateFileSignature(entry.info, &context);
            else
                OmitFileSignature(entry.info);
        } else {
            entry.info = QueryFileUncached(path, signature, &context);
        }
        entry.reusable = !context.ShouldStop() && observed && ReadFileObservation(resolved, after, signature) &&
                         SameFileObservation(before, after) && MatchesFileObservation(entry.info, after) &&
                         (!signature || entry.info.evidence.signatureState == FieldState::Available);
        // 读取失败、信任状态未知或采集期间文件发生变化时，后续调用应重新尝试。
        return entry.info;
    }

    Hashes CalculateHashes(const std::wstring& path, HashAlgorithm algorithm, std::uint64_t maxBytes,
                           const CollectionContext& context) {
        Hashes result;
        auto fail = [&](const wchar_t* code, DWORD native, const wchar_t* message) {
            result.errorCode = code;
            result.nativeCode = native;
            result.issues.push_back({ L"file.hash", path, code, native, message, true });
        };
        auto stopped = [&]() {
            if (!context.ShouldStop())
                return false;
            result.status = context.StopStatus();
            result.md5.clear();
            result.sha1.clear();
            result.sha256.clear();
            fail(context.IsCancelled() ? L"CANCELLED" : L"TIMED_OUT", 0, L"File hashing stopped before completion.");
            return true;
        };
        if (stopped())
            return result;
        const auto resolved = ResolvePath(path);
        UniqueHandle file(CreateFileW(resolved.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                      FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (!file.valid()) {
            fail(L"FILE_OPEN_FAILED", GetLastError(), L"Unable to open the file for hashing.");
            return result;
        }
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file.get(), &size) || size.QuadPart < 0) {
            fail(L"FILE_SIZE_FAILED", GetLastError(), L"Unable to determine the file size.");
            return result;
        }
        result.size = static_cast<std::uint64_t>(size.QuadPart);
        if (result.size > maxBytes) {
            fail(L"FILE_TOO_LARGE", ERROR_FILE_TOO_LARGE, L"File exceeds the configured byte budget.");
            return result;
        }

        struct Provider {
            HCRYPTPROV value = 0;

            ~Provider() {
                if (value)
                    CryptReleaseContext(value, 0);
            }
        } provider;

        if (!CryptAcquireContextW(&provider.value, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            fail(L"HASH_PROVIDER_FAILED", GetLastError(), L"Unable to initialize the hashing provider.");
            return result;
        }

        struct Hash {
            HCRYPTHASH value = 0;

            ~Hash() {
                if (value)
                    CryptDestroyHash(value);
            }
        } hashes[3];

        const ALG_ID algorithms[]{ CALG_MD5, CALG_SHA1, CALG_SHA_256 };
        const bool enabled[]{ algorithm == HashAlgorithm::All || algorithm == HashAlgorithm::Md5,
                              algorithm == HashAlgorithm::All || algorithm == HashAlgorithm::Sha1,
                              algorithm == HashAlgorithm::All || algorithm == HashAlgorithm::Sha256 };
        for (unsigned i = 0; i < 3; ++i)
            if (enabled[i] && !CryptCreateHash(provider.value, algorithms[i], 0, 0, &hashes[i].value)) {
                fail(L"HASH_INIT_FAILED", GetLastError(), L"Unable to initialize a requested hash.");
                return result;
            }
        std::vector<BYTE> buffer(64 * 1024);
        std::uint64_t readTotal = 0;
        while (true) {
            if (stopped())
                return result;
            DWORD count = 0;
            if (!ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr)) {
                fail(L"FILE_READ_FAILED", GetLastError(), L"File content could not be read completely.");
                return result;
            }
            if (!count)
                break;
            readTotal += count;
            if (readTotal > maxBytes || readTotal > result.size) {
                fail(L"FILE_CHANGED", ERROR_INVALID_DATA, L"File size changed while hashing.");
                return result;
            }
            for (unsigned i = 0; i < 3; ++i)
                if (enabled[i] && !CryptHashData(hashes[i].value, buffer.data(), count, 0)) {
                    fail(L"HASH_UPDATE_FAILED", GetLastError(), L"Hash calculation failed.");
                    return result;
                }
        }
        if (readTotal != result.size) {
            fail(L"FILE_CHANGED", ERROR_HANDLE_EOF, L"File content was shorter than the observed size.");
            return result;
        }
        std::wstring values[3];
        for (unsigned i = 0; i < 3; ++i)
            if (enabled[i]) {
                BYTE bytes[32]{};
                DWORD count = sizeof(bytes);
                if (!CryptGetHashParam(hashes[i].value, HP_HASHVAL, bytes, &count, 0)) {
                    fail(L"HASH_FINAL_FAILED", GetLastError(), L"Unable to finalize a requested hash.");
                    return result;
                }
                for (DWORD j = 0; j < count; ++j) {
                    wchar_t text[3]{};
                    swprintf_s(text, L"%02x", bytes[j]);
                    values[i] += text;
                }
            }
        result.md5 = std::move(values[0]);
        result.sha1 = std::move(values[1]);
        result.sha256 = std::move(values[2]);
        result.status = CollectionStatus::Complete;
        return result;
    }
}
