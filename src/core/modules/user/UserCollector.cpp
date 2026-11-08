#include "../../system/Win32.h"
#include "UserModule.h"
#include <lm.h>
#include <sddl.h>
#include <algorithm>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

namespace wgwc::core::users {
    namespace {
        constexpr const wchar_t* LoginKey =
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList";
        constexpr const wchar_t* SamNamesKey = L"SAM\\SAM\\Domains\\Account\\Users\\Names";
        constexpr const wchar_t* SamUsersKey = L"SAM\\SAM\\Domains\\Account\\Users";

        enum SourceIndex : std::size_t {
            MetadataSource,
            NamesSource,
            AdminSource,
            LoginSource,
            SamNamesSource,
            RidSource
        };

        struct NetBuffer {
            LPBYTE value = nullptr;

            ~NetBuffer() {
                if (value)
                    NetApiBufferFree(value);
            }
        };

        struct RegistryKey {
            HKEY value = nullptr;

            ~RegistryKey() {
                if (value)
                    RegCloseKey(value);
            }
        };

        std::wstring SidText(PSID sid) {
            if (!sid || !IsValidSid(sid))
                return {};
            LPWSTR text = nullptr;
            if (!ConvertSidToStringSidW(sid, &text))
                return {};
            std::wstring result = text;
            LocalFree(text);
            return result;
        }

        class Collector {
        public:
            explicit Collector(const CollectionContext& context) : context_(context) {
                result_.startedAt = UtcNow();
                result_.sources = { { L"user.netapi.level3" }, { L"user.netapi.level0" }, { L"user.administrators" },
                                    { L"user.login_ui" },      { L"user.sam_names" },     { L"user.sam_rid" } };
            }

            CollectionResult<UserRecord> Run() {
                ReadNetUsers(3, MetadataSource);
                if (!context_.ShouldStop())
                    ReadNetUsers(0, NamesSource);
                if (!context_.ShouldStop())
                    ReadAdministrators();
                if (!context_.ShouldStop())
                    ReadLoginHidden();
                if (!context_.ShouldStop())
                    ReadSamNames();
                hidden_.apiComplete = Complete(NamesSource);
                hidden_.loginUiComplete = Complete(LoginSource);
                hidden_.samComplete = Complete(SamNamesSource);
                if (hidden_.apiComplete) {
                    for (const auto& entry : samDisplayNames_) {
                        if (context_.ShouldStop())
                            break;
                        if (hidden_.apiNames.count(entry.first) == 0 && userIndexes_.count(entry.first) == 0) {
                            if (result_.records.size() >= context_.maxRecords) {
                                Budget(SamNamesSource);
                                break;
                            }
                            auto& user = AddUser(entry.second, L"user.sam_names");
                            user.description = L"SAM存在但API枚举不到";
                        }
                    }
                }
                if (!context_.ShouldStop())
                    ReadRidEvidence();
                wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
                DWORD computerLength = static_cast<DWORD>(std::size(computer));
                const bool hasComputer = GetComputerNameW(computer, &computerLength) != FALSE;
                result_.assessment = AssessmentState::Complete;
                for (auto& user : result_.records) {
                    if (!context_.ShouldStop() && hasComputer)
                        ResolveSid(user, computer);
                    ApplyHiddenEvidence(user, hidden_);
                    if (user.sidState == FieldState::Available) {
                        user.isAdmin = adminSids_.count(user.sid) != 0;
                        user.adminState =
                            user.isAdmin || Complete(AdminSource) ? FieldState::Available : FieldState::Unknown;
                    }
                    user.assessment = AssessUser(user);
                    if (user.assessment.state != AssessmentState::Complete)
                        result_.assessment = AssessmentState::Incomplete;
                    if (!user.assessment.hits.empty())
                        result_.findings.push_back(
                            { L"user", SourceKey(user), user.username, user.observedAt, user.assessment });
                }
                result_.collected = result_.records.size();
                if (context_.ShouldStop()) {
                    result_.status = context_.StopStatus();
                    result_.issues.push_back({ L"user", L"", context_.IsCancelled() ? L"CANCELLED" : L"TIMED_OUT", 0,
                                               L"User collection stopped before all requested sources completed.",
                                               true });
                } else {
                    const bool anyComplete = Complete(MetadataSource) || Complete(NamesSource);
                    const bool allComplete =
                        std::all_of(result_.sources.begin(), result_.sources.end(), [](const auto& source) {
                            return source.status == L"complete";
                        });
                    result_.status = allComplete ? CollectionStatus::Complete
                                                 : (!result_.records.empty() || anyComplete ? CollectionStatus::Partial
                                                                                            : CollectionStatus::Failed);
                }
                if (result_.status != CollectionStatus::Complete)
                    result_.assessment = AssessmentState::Incomplete;
                result_.finishedAt = UtcNow();
                std::sort(result_.records.begin(), result_.records.end(), [](const auto& a, const auto& b) {
                    return NormalizeName(a.username) < NormalizeName(b.username);
                });
                return std::move(result_);
            }

        private:
            bool Complete(std::size_t index) const {
                return result_.sources[index].status == L"complete";
            }

            bool Stop(std::size_t index) {
                if (!context_.ShouldStop())
                    return false;
                result_.sources[index].status = StatusName(context_.StopStatus());
                return true;
            }

            void Failure(std::size_t index, const wchar_t* code, DWORD native, const wchar_t* message,
                         const std::wstring& key = {}) {
                auto& source = result_.sources[index];
                source.status = source.collected ? L"partial" : L"failed";
                source.nativeCode = native;
                result_.issues.push_back({ source.source, key, code, native, message, true });
            }

            void Budget(std::size_t index) {
                result_.collectionTruncated = true;
                Failure(index, L"RECORD_BUDGET", 0, L"A user evidence source reached its record budget.");
                result_.sources[index].status = L"partial";
            }

            UserRecord& AddUser(const std::wstring& name, const wchar_t* source) {
                const auto normalized = NormalizeName(name);
                auto found = userIndexes_.find(normalized);
                if (found != userIndexes_.end())
                    return result_.records[found->second];
                const auto index = result_.records.size();
                result_.records.emplace_back();
                auto& user = result_.records.back();
                user.username = name;
                user.observedAt = UtcNow();
                user.source = source;
                userIndexes_[normalized] = index;
                return user;
            }

            void ReadNetUsers(DWORD level, std::size_t sourceIndex) {
                if (Stop(sourceIndex))
                    return;
                auto& source = result_.sources[sourceIndex];
                source.status = L"complete";
                DWORD resume = 0;
                for (;;) {
                    if (Stop(sourceIndex))
                        return;
                    NetBuffer buffer;
                    DWORD count = 0, total = 0;
                    const DWORD previous = resume;
                    const auto status = NetUserEnum(nullptr, level, FILTER_NORMAL_ACCOUNT, &buffer.value,
                                                    MAX_PREFERRED_LENGTH, &count, &total, &resume);
                    if (status != NERR_Success && status != ERROR_MORE_DATA) {
                        Failure(sourceIndex, L"USER_ENUMERATION_FAILED", status,
                                L"NetUserEnum could not complete the requested page.");
                        return;
                    }
                    if (count && !buffer.value) {
                        Failure(sourceIndex, L"INVALID_USER_PAGE", ERROR_INVALID_DATA,
                                L"NetUserEnum returned an invalid page.");
                        return;
                    }
                    for (DWORD i = 0; i < count; ++i) {
                        if (Stop(sourceIndex))
                            return;
                        if (source.collected >= context_.maxRecords) {
                            Budget(sourceIndex);
                            return;
                        }
                        const wchar_t* name = level == 3 ? reinterpret_cast<USER_INFO_3*>(buffer.value)[i].usri3_name
                                                         : reinterpret_cast<USER_INFO_0*>(buffer.value)[i].usri0_name;
                        if (!name || !*name) {
                            Failure(sourceIndex, L"INVALID_USER_NAME", ERROR_INVALID_DATA,
                                    L"A user record did not contain a name.");
                            return;
                        }
                        ++source.collected;
                        if (level == 0) {
                            hidden_.apiNames.insert(NormalizeName(name));
                            if (!Complete(MetadataSource) && userIndexes_.count(NormalizeName(name)) == 0) {
                                if (result_.records.size() >= context_.maxRecords) {
                                    Budget(sourceIndex);
                                    return;
                                }
                                AddUser(name, L"user.netapi.level0");
                            }
                            continue;
                        }
                        auto& user = AddUser(name, L"user.netapi.level3");
                        const auto& value = reinterpret_cast<USER_INFO_3*>(buffer.value)[i];
                        user.fullName = value.usri3_full_name ? value.usri3_full_name : L"";
                        user.description = value.usri3_comment ? value.usri3_comment : L"";
                        user.flags = value.usri3_flags;
                        user.rid = value.usri3_user_id;
                        user.originalRid = user.rid;
                        user.isDisabled = (user.flags & UF_ACCOUNTDISABLE) != 0;
                        user.isLocked = (user.flags & UF_LOCKOUT) != 0;
                        user.passwordNeverExpires = (user.flags & UF_DONT_EXPIRE_PASSWD) != 0;
                        user.passwordNotRequired = (user.flags & UF_PASSWD_NOTREQD) != 0;
                        user.lastLogon = value.usri3_last_logon;
                        user.lastLogoff = value.usri3_last_logoff;
                        user.passwordAge = value.usri3_password_age;
                        user.accountExpires = value.usri3_acct_expires;
                        user.numLogons = value.usri3_num_logons;
                        user.badPasswordCount = value.usri3_bad_pw_count;
                        user.metadataState = FieldState::Available;
                        user.ridState = FieldState::Available;
                        if (context_.progress)
                            context_.progress(L"user", result_.records.size());
                    }
                    if (status == NERR_Success)
                        return;
                    if (count == 0 || resume == previous) {
                        Failure(sourceIndex, L"USER_PAGINATION_STALLED", ERROR_INVALID_DATA,
                                L"NetUserEnum pagination did not advance.");
                        return;
                    }
                }
            }

            void ReadAdministrators() {
                if (Stop(AdminSource))
                    return;
                auto& source = result_.sources[AdminSource];
                source.status = L"complete";
                BYTE sid[SECURITY_MAX_SID_SIZE]{};
                DWORD sidSize = sizeof(sid);
                if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid, &sidSize)) {
                    Failure(AdminSource, L"ADMIN_GROUP_UNAVAILABLE", GetLastError(),
                            L"The built-in administrator group SID is unavailable.");
                    return;
                }
                DWORD nameSize = 0, domainSize = 0;
                SID_NAME_USE use{};
                LookupAccountSidW(nullptr, sid, nullptr, &nameSize, nullptr, &domainSize, &use);
                if (!nameSize || nameSize > 32768 || domainSize > 32768) {
                    Failure(AdminSource, L"ADMIN_GROUP_UNAVAILABLE", GetLastError(),
                            L"The localized administrator group name is unavailable.");
                    return;
                }
                std::vector<wchar_t> name(nameSize), domain((std::max)(domainSize, 1UL));
                if (!LookupAccountSidW(nullptr, sid, name.data(), &nameSize, domain.data(), &domainSize, &use)) {
                    Failure(AdminSource, L"ADMIN_GROUP_UNAVAILABLE", GetLastError(),
                            L"The administrator group name could not be resolved.");
                    return;
                }
                DWORD_PTR resume = 0;
                for (;;) {
                    if (Stop(AdminSource))
                        return;
                    NetBuffer buffer;
                    DWORD count = 0, total = 0;
                    const auto previous = resume;
                    const auto status = NetLocalGroupGetMembers(nullptr, name.data(), 0, &buffer.value,
                                                                MAX_PREFERRED_LENGTH, &count, &total, &resume);
                    if (status != NERR_Success && status != ERROR_MORE_DATA) {
                        Failure(AdminSource, L"ADMIN_MEMBERS_UNAVAILABLE", status,
                                L"Administrator membership could not be fully enumerated.");
                        return;
                    }
                    if (count && !buffer.value) {
                        Failure(AdminSource, L"INVALID_ADMIN_PAGE", ERROR_INVALID_DATA,
                                L"Administrator enumeration returned an invalid page.");
                        return;
                    }
                    for (DWORD i = 0; i < count; ++i) {
                        if (Stop(AdminSource))
                            return;
                        if (source.collected >= context_.maxRecords) {
                            Budget(AdminSource);
                            return;
                        }
                        const auto value =
                            SidText(reinterpret_cast<LOCALGROUP_MEMBERS_INFO_0*>(buffer.value)[i].lgrmi0_sid);
                        if (value.empty()) {
                            Failure(AdminSource, L"INVALID_ADMIN_SID", ERROR_INVALID_SID,
                                    L"An administrator member SID was unreadable.");
                            return;
                        }
                        adminSids_.insert(value);
                        ++source.collected;
                    }
                    if (status == NERR_Success)
                        return;
                    if (!count || resume == previous) {
                        Failure(AdminSource, L"ADMIN_PAGINATION_STALLED", ERROR_INVALID_DATA,
                                L"Administrator pagination did not advance.");
                        return;
                    }
                }
            }

            void ReadLoginHidden() {
                if (Stop(LoginSource))
                    return;
                auto& source = result_.sources[LoginSource];
                source.status = L"complete";
                RegistryKey key;
                LONG status =
                    RegOpenKeyExW(HKEY_LOCAL_MACHINE, LoginKey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key.value);
                if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
                    return;
                if (status != ERROR_SUCCESS) {
                    Failure(LoginSource, L"LOGIN_UI_UNAVAILABLE", status,
                            L"Login visibility configuration could not be read.");
                    return;
                }
                std::vector<wchar_t> name(32768);
                for (DWORD i = 0;; ++i) {
                    if (Stop(LoginSource))
                        return;
                    DWORD length = static_cast<DWORD>(name.size()), type = 0, size = 0;
                    status = RegEnumValueW(key.value, i, name.data(), &length, nullptr, &type, nullptr, &size);
                    if (status == ERROR_NO_MORE_ITEMS)
                        return;
                    if (status != ERROR_SUCCESS) {
                        Failure(LoginSource, L"LOGIN_UI_ENUMERATION_FAILED", status,
                                L"Login visibility enumeration ended unexpectedly.");
                        return;
                    }
                    if (source.collected >= context_.maxRecords) {
                        Budget(LoginSource);
                        return;
                    }
                    ++source.collected;
                    if (type != REG_DWORD || size != sizeof(DWORD))
                        continue;
                    DWORD value = 0, actual = sizeof(value);
                    status = RegQueryValueExW(key.value, name.data(), nullptr, &type, reinterpret_cast<BYTE*>(&value),
                                              &actual);
                    if (status != ERROR_SUCCESS || type != REG_DWORD || actual != sizeof(value)) {
                        Failure(LoginSource, L"LOGIN_UI_VALUE_CHANGED", status ? status : ERROR_INVALID_DATA,
                                L"A login visibility value changed while being read.");
                        return;
                    }
                    if (value == 0)
                        hidden_.loginUiHiddenNames.insert(NormalizeName(std::wstring(name.data(), length)));
                }
            }

            void ReadSamNames() {
                if (Stop(SamNamesSource))
                    return;
                auto& source = result_.sources[SamNamesSource];
                source.status = L"complete";
                RegistryKey key;
                LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, SamNamesKey, 0, KEY_ENUMERATE_SUB_KEYS, &key.value);
                if (status != ERROR_SUCCESS) {
                    Failure(SamNamesSource, L"SAM_NAMES_UNAVAILABLE", status,
                            L"SAM account names are not readable with the current token.");
                    return;
                }
                wchar_t name[512]{};
                for (DWORD i = 0;; ++i) {
                    if (Stop(SamNamesSource))
                        return;
                    DWORD length = static_cast<DWORD>(std::size(name));
                    status = RegEnumKeyExW(key.value, i, name, &length, nullptr, nullptr, nullptr, nullptr);
                    if (status == ERROR_NO_MORE_ITEMS)
                        return;
                    if (status != ERROR_SUCCESS) {
                        Failure(SamNamesSource, L"SAM_NAMES_ENUMERATION_FAILED", status,
                                L"SAM account-name enumeration ended unexpectedly.");
                        return;
                    }
                    if (source.collected >= context_.maxRecords) {
                        Budget(SamNamesSource);
                        return;
                    }
                    const std::wstring display(name, length), normalized = NormalizeName(display);
                    hidden_.samNames.insert(normalized);
                    samDisplayNames_[normalized] = display;
                    ++source.collected;
                }
            }

            void ReadRidEvidence() {
                if (Stop(RidSource))
                    return;
                auto& source = result_.sources[RidSource];
                source.status = L"complete";
                if (std::none_of(result_.records.begin(), result_.records.end(), [](const auto& user) {
                        return user.ridState == FieldState::Available;
                    }))
                    return;
                RegistryKey root;
                LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, SamUsersKey, 0, KEY_ENUMERATE_SUB_KEYS, &root.value);
                if (status != ERROR_SUCCESS) {
                    Failure(RidSource, L"SAM_RID_UNAVAILABLE", status,
                            L"SAM RID evidence is not readable with the current token.");
                    return;
                }
                for (auto& user : result_.records) {
                    if (Stop(RidSource))
                        return;
                    if (user.ridState != FieldState::Available)
                        continue;
                    wchar_t name[9]{};
                    swprintf_s(name, L"%08X", static_cast<unsigned>(user.rid));
                    RegistryKey key;
                    status = RegOpenKeyExW(root.value, name, 0, KEY_QUERY_VALUE, &key.value);
                    if (status != ERROR_SUCCESS) {
                        Failure(RidSource, L"SAM_RID_UNAVAILABLE", status,
                                L"The account RID evidence could not be read.", user.username);
                        continue;
                    }
                    DWORD type = 0, size = 0;
                    status = RegQueryValueExW(key.value, L"F", nullptr, &type, nullptr, &size);
                    if (status != ERROR_SUCCESS || type != REG_BINARY || size < 0x34 || size > 65536) {
                        Failure(RidSource, L"SAM_RID_MALFORMED", status ? status : ERROR_INVALID_DATA,
                                L"The account RID evidence has an unsupported shape.", user.username);
                        continue;
                    }
                    std::vector<BYTE> bytes(size);
                    status = RegQueryValueExW(key.value, L"F", nullptr, &type, bytes.data(), &size);
                    std::uint32_t rid = 0;
                    if (status != ERROR_SUCCESS || type != REG_BINARY || size > bytes.size() ||
                        !DecodeSamRid(bytes.data(), size, rid)) {
                        Failure(RidSource, L"SAM_RID_MALFORMED", status ? status : ERROR_INVALID_DATA,
                                L"The account RID evidence was invalid or changed during collection.", user.username);
                        continue;
                    }
                    // 只保留 RID 比较结果，不保留 SAM 原始值。
                    user.samRid = rid;
                    user.ridHijackState = FieldState::Available;
                    user.ridHijacked = rid != user.rid;
                    user.hijackedRid = user.ridHijacked ? rid : 0;
                    ++source.collected;
                }
                if (source.collected && source.status == L"failed")
                    source.status = L"partial";
            }

            void ResolveSid(UserRecord& user, const std::wstring& computer) {
                const std::wstring account = computer + L"\\" + user.username;
                DWORD sidSize = 0, domainSize = 0;
                SID_NAME_USE use{};
                LookupAccountNameW(nullptr, account.c_str(), nullptr, &sidSize, nullptr, &domainSize, &use);
                if (!sidSize || sidSize > SECURITY_MAX_SID_SIZE || domainSize > 32768)
                    return;
                std::vector<BYTE> sid(sidSize);
                std::vector<wchar_t> domain((std::max)(domainSize, 1UL));
                if (!LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sidSize, domain.data(), &domainSize,
                                        &use) ||
                    use != SidTypeUser)
                    return;
                user.sid = SidText(sid.data());
                user.sidState = user.sid.empty() ? FieldState::Unknown : FieldState::Available;
            }

            const CollectionContext& context_;
            CollectionResult<UserRecord> result_;
            HiddenEvidence hidden_;
            std::map<std::wstring, std::size_t> userIndexes_;
            std::map<std::wstring, std::wstring> samDisplayNames_;
            std::set<std::wstring> adminSids_;
        };
    }

    CollectionResult<UserRecord> CollectUsers(const CollectionContext& context) {
        return Collector(context).Run();
    }
}
