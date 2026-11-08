#include "../system/Win32.h"
#include "../system/FileService.h"
#include "RuleHelpers.h"
#include <algorithm>
#include <cwctype>

namespace wgwc::core::rules {
    std::wstring ToLower(const std::wstring& value) {
        std::wstring result = value;
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
        return result;
    }

    std::wstring ExpandEnvStrings(const std::wstring& value) {
        return files::ExpandEnvironment(value);
    }

    static std::wstring TrimForRule(const std::wstring& value) {
        size_t start = value.find_first_not_of(L" \t\r\n\"");
        if (start == std::wstring::npos) {
            return L"";
        }
        size_t end = value.find_last_not_of(L" \t\r\n\"");
        return value.substr(start, end - start + 1);
    }

    static bool StartsWithRule(const std::wstring& value, const std::wstring& prefix) {
        return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
    }

    static bool EndsWithRule(const std::wstring& value, const std::wstring& suffix) {
        return value.size() >= suffix.size() && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    static std::wstring FileNameFromPathForRule(const std::wstring& value) {
        std::wstring clean = TrimForRule(value);
        const size_t slash = clean.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
            clean = clean.substr(slash + 1);
        return ToLower(clean);
    }

    // 保留带空格的引号路径；这里只拆分命令边界，不执行或展开脚本。
    static std::wstring NextCommandTokenForRule(const std::wstring& command, size_t& position,
                                                bool singleQuotes = false) {
        while (position < command.size() && iswspace(command[position]))
            ++position;
        std::wstring token;
        wchar_t quote = 0;
        while (position < command.size()) {
            const wchar_t ch = command[position];
            if (quote) {
                if (ch == quote)
                    quote = 0;
                else
                    token += ch;
            } else if (ch == L'"' || (singleQuotes && ch == L'\'')) {
                quote = ch;
            } else if (iswspace(ch) || ch == L'&' || ch == L'|' || ch == L';') {
                break;
            } else
                token += ch;
            ++position;
        }
        return token;
    }

    static std::wstring FirstCommandTokenForRule(const std::wstring& command) {
        size_t position = 0;
        return FileNameFromPathForRule(NextCommandTokenForRule(command, position));
    }

    bool IsExistingFile(const std::wstring& path) {
        if (path.empty() || path[0] == L'<' || path[0] == L'[') {
            return false;
        }

        std::wstring expanded = ExpandEnvStrings(TrimForRule(path));
        DWORD attrs = GetFileAttributesW(expanded.c_str());
        return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    struct DllSideLoadingDirectoryStats {
        std::wstring directory;
        int fileCount = 0;
        int dllCount = 0;
    };

    static thread_local std::vector<DllSideLoadingDirectoryStats> g_dllSideLoadingDirectoryCache;

    void ClearDllSideLoadingRiskCache() {
        g_dllSideLoadingDirectoryCache.clear();
    }

    DllSideLoadingRisk DetectDllSideLoadingRisk(const std::wstring& imagePath, SignatureState signatureState) {
        if (imagePath.empty() || imagePath[0] == L'<' || imagePath[0] == L'[') {
            return DllSideLoadingRisk::None;
        }

        std::wstring path = ExpandEnvStrings(TrimForRule(imagePath));
        std::wstring lowerPath = ToLower(path);
        if (!IsExistingFile(path)) {
            return DllSideLoadingRisk::None;
        }

        // DLL/SYS 本身不作为白文件候选，其他签名校验通过的目标继续参与判断。
        if (EndsWithRule(lowerPath, L".dll") || EndsWithRule(lowerPath, L".sys")) {
            return DllSideLoadingRisk::None;
        }

        if (signatureState != SignatureState::Signed) {
            return DllSideLoadingRisk::None;
        }

        size_t slash = path.find_last_of(L"\\/");
        if (slash == std::wstring::npos || slash == 0) {
            return DllSideLoadingRisk::None;
        }

        std::wstring dir = path.substr(0, slash);
        std::wstring normalizedDir = ToLower(dir);
        std::replace(normalizedDir.begin(), normalizedDir.end(), L'/', L'\\');
        while (normalizedDir.size() > 3 && normalizedDir.back() == L'\\') {
            normalizedDir.pop_back();
        }

        wchar_t windowsDir[MAX_PATH] = { 0 };
        UINT windowsDirLength = GetWindowsDirectoryW(windowsDir, MAX_PATH);
        if (windowsDirLength > 0 && windowsDirLength < MAX_PATH) {
            std::wstring normalizedWindowsDir = ToLower(windowsDir);
            std::replace(normalizedWindowsDir.begin(), normalizedWindowsDir.end(), L'/', L'\\');
            while (normalizedWindowsDir.size() > 3 && normalizedWindowsDir.back() == L'\\') {
                normalizedWindowsDir.pop_back();
            }

            if (normalizedDir == normalizedWindowsDir + L"\\system32" ||
                normalizedDir == normalizedWindowsDir + L"\\syswow64") {
                return DllSideLoadingRisk::None;
            }
        }

        int fileCount = 0;
        int dllCount = 0;
        auto cacheIt = std::find_if(g_dllSideLoadingDirectoryCache.begin(), g_dllSideLoadingDirectoryCache.end(),
                                    [&normalizedDir](const DllSideLoadingDirectoryStats& stats) {
                                        return stats.directory == normalizedDir;
                                    });

        if (cacheIt != g_dllSideLoadingDirectoryCache.end()) {
            fileCount = cacheIt->fileCount;
            dllCount = cacheIt->dllCount;
        } else {
            std::wstring search = dir + L"\\*";
            WIN32_FIND_DATAW findData = { 0 };
            HANDLE hFind = FindFirstFileW(search.c_str(), &findData);
            if (hFind == INVALID_HANDLE_VALUE) {
                return DllSideLoadingRisk::None;
            }

            do {
                if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                    continue;
                }

                fileCount++;
                std::wstring fileName = ToLower(findData.cFileName);
                if (EndsWithRule(fileName, L".dll")) {
                    dllCount++;
                }

                if (fileCount >= 8) {
                    break;
                }
            } while (FindNextFileW(hFind, &findData));

            // 达到阈值可提前结束；读取异常时不使用或缓存不完整计数。
            const bool countsUsable = fileCount >= 8 || GetLastError() == ERROR_NO_MORE_FILES;
            FindClose(hFind);
            if (!countsUsable)
                return DllSideLoadingRisk::None;
            g_dllSideLoadingDirectoryCache.push_back({ normalizedDir, fileCount, dllCount });
        }

        if (fileCount < 3 && dllCount == 1) {
            return DllSideLoadingRisk::High;
        }

        if (fileCount < 5 && dllCount == 1) {
            return DllSideLoadingRisk::Medium;
        }

        if (fileCount < 8 && dllCount >= 1 && dllCount <= 2) {
            return DllSideLoadingRisk::Low;
        }

        return DllSideLoadingRisk::None;
    }

    bool ContainsBidiOrZeroWidthChar(const std::wstring& text) {
        for (wchar_t ch : text) {
            if ((ch >= 0x202A && ch <= 0x202E) || (ch >= 0x2066 && ch <= 0x2069) || ch == 0x200B || ch == 0x200C ||
                ch == 0x200D || ch == 0xFEFF) {
                return true;
            }
        }
        return false;
    }

    bool HasHiddenNamePrefix(const std::wstring& name) {
        if (name.empty()) {
            return false;
        }

        wchar_t ch = name[0];
        return ch == L' ' || ch == L'\t' || ch == 0 || iswcntrl(ch) || ContainsBidiOrZeroWidthChar(name.substr(0, 1));
    }

    bool HasDoubleExtensionSpoof(const std::wstring& text) {
        if (text.empty()) {
            return false;
        }

        const auto fileName = FileNameFromPathForRule(text);
        if (ContainsBidiOrZeroWidthChar(fileName)) {
            return true;
        }

        const wchar_t* decoyExts[] = { L".doc", L".docx", L".xls",  L".xlsx", L".ppt", L".pptx",
                                       L".pdf", L".jpg",  L".jpeg", L".png",  L".gif", L".zip",
                                       L".rar", L".7z",   L".txt",  L".rtf",  nullptr };
        const wchar_t* execExts[] = { L".exe", L".scr", L".lnk", L".pif", L".com", L".bat", L".cmd",
                                      L".js",  L".jse", L".vbs", L".vbe", L".wsf", L".ps1", nullptr };

        size_t lastDot = fileName.find_last_of(L'.');
        if (lastDot == std::wstring::npos) {
            return false;
        }

        std::wstring lastExt = fileName.substr(lastDot);
        bool executableFinalExt = false;
        for (int i = 0; execExts[i] != nullptr; i++) {
            if (lastExt == execExts[i]) {
                executableFinalExt = true;
                break;
            }
        }
        if (!executableFinalExt) {
            return false;
        }

        std::wstring beforeLast = fileName.substr(0, lastDot);
        size_t prevDot = beforeLast.find_last_of(L'.');
        if (prevDot == std::wstring::npos) {
            return false;
        }

        std::wstring prevExt = beforeLast.substr(prevDot);
        for (int i = 0; decoyExts[i] != nullptr; i++) {
            if (prevExt == decoyExts[i]) {
                return true;
            }
        }
        return false;
    }

    // 字符串常量中的关键词不当作执行指令，避免普通参数触发高等级提示。
    static bool HasPowerShellCodeSignal(std::wstring body) {
        const size_t first = body.find_first_not_of(L" \t\r\n");
        if (first == std::wstring::npos)
            return false;
        body = body.substr(first, body.find_last_not_of(L" \t\r\n") - first + 1);
        if (body.size() > 1 && (body.front() == L'"' || body.front() == L'\'') && body.back() == body.front() &&
            body.find(body.front(), 1) == body.size() - 1)
            body = body.substr(1, body.size() - 2);
        body = ToLower(body);
        wchar_t quote = 0;
        for (size_t i = 0; i < body.size();) {
            const wchar_t ch = body[i];
            if (ch == 0x0060 && i + 1 < body.size()) {
                i += 2;
                continue;
            }
            if (quote) {
                if (ch == quote)
                    quote = 0;
                ++i;
                continue;
            }
            if (ch == L'"' || ch == L'\'') {
                quote = ch;
                ++i;
                continue;
            }
            if (ch == L'#') {
                const auto end = body.find(L'\n', i);
                if (end == std::wstring::npos)
                    break;
                i = end + 1;
                continue;
            }
            if (!iswalpha(ch) && ch != L'_') {
                ++i;
                continue;
            }
            const size_t start = i++;
            while (i < body.size() && (iswalnum(body[i]) || body[i] == L'_' || body[i] == L'-'))
                ++i;
            const auto word = body.substr(start, i - start);
            size_t next = i, previous = start;
            while (next < body.size() && iswspace(body[next]))
                ++next;
            while (previous > 0 && iswspace(body[previous - 1]))
                --previous;
            const bool statement =
                previous == 0 || std::wstring(L";|&({}=\r\n").find(body[previous - 1]) != std::wstring::npos;
            if ((word == L"iex" || word == L"invoke-expression") && statement && next < body.size())
                return true;
            if ((word == L"frombase64string" || word == L"downloadstring" || word == L"downloadfile") && previous > 0 &&
                (body[previous - 1] == L'.' || body[previous - 1] == L':') && next < body.size() && body[next] == L'(')
                return true;
        }
        return false;
    }

    static bool IsPowerShellToken(const std::wstring& token) {
        return token == L"powershell" || token == L"powershell.exe" || token == L"pwsh" || token == L"pwsh.exe";
    }

    static CommandLineAssessment AssessCommandLineImpl(const std::wstring& command, unsigned depth) {
        CommandLineAssessment result;
        size_t position = 0;
        const auto executable = NextCommandTokenForRule(command, position);
        const auto token = FileNameFromPathForRule(executable);
        if (token.empty())
            return result;
        result.scriptExecution = IsScriptFilePath(executable);
        const auto raise = [&](RiskLevel level, const wchar_t* reason) {
            if (level > result.level) {
                result.level = level;
                result.reason = reason;
            }
        };

        if (token == L"cmd" || token == L"cmd.exe" || token == L"%comspec%") {
            // 仅展开明确的命令包装，限制嵌套层数；echo 等普通参数不作为子命令。
            while (position < command.size()) {
                const auto arg = ToLower(NextCommandTokenForRule(command, position));
                if (arg.empty())
                    break;
                if (arg == L"/c" || arg == L"/k") {
                    if (depth >= 3)
                        return result;
                    const auto first = command.find_first_not_of(L" \t\r\n", position);
                    if (first == std::wstring::npos)
                        return result;
                    std::wstring nested = command.substr(first);
                    if (nested.size() > 1 && nested.front() == L'"' && nested.back() == L'"') {
                        const auto inside = nested.substr(1, nested.size() - 2);
                        const auto innerToken = FirstCommandTokenForRule(inside);
                        if (nested[1] == L'"' || IsPowerShellToken(innerToken) || innerToken == L"cmd" ||
                            innerToken == L"cmd.exe" || innerToken == L"mshta" || innerToken == L"mshta.exe" ||
                            innerToken == L"regsvr32" || innerToken == L"regsvr32.exe" || innerToken == L"rundll32" ||
                            innerToken == L"rundll32.exe" || innerToken == L"certutil" ||
                            innerToken == L"certutil.exe" || innerToken == L"bitsadmin" ||
                            innerToken == L"bitsadmin.exe")
                            nested = inside;
                    }
                    return AssessCommandLineImpl(nested, depth + 1);
                }
                if (arg.front() != L'/')
                    break;
            }
            return result;
        }

        if (IsPowerShellToken(token)) {
            while (position < command.size()) {
                const size_t start = position;
                auto arg = ToLower(NextCommandTokenForRule(command, position, true));
                if (arg.empty())
                    break;
                if (arg.front() == L'/')
                    arg.front() = L'-';
                const auto colon = arg.find(L':');
                const auto option = arg.substr(0, colon);
                const auto value = [&]() {
                    return colon == std::wstring::npos ? ToLower(NextCommandTokenForRule(command, position, true))
                                                       : arg.substr(colon + 1);
                };
                if (option == L"-nop" || option == L"-noprofile") {
                    raise(RiskLevel::Low, L"PowerShell 无配置文件启动");
                } else if (option == L"-w" || option == L"-windowstyle") {
                    if (value() == L"hidden")
                        raise(RiskLevel::Medium, L"PowerShell 隐藏窗口启动");
                } else if (option == L"-ep" || option == L"-exec" || option == L"-executionpolicy") {
                    if (value() == L"bypass")
                        raise(RiskLevel::Medium, L"PowerShell 绕过执行策略");
                } else if (option == L"-e" || option == L"-ec" || option == L"-enc" || option == L"-encodedcommand") {
                    if (!value().empty()) {
                        result.scriptExecution = true;
                        raise(RiskLevel::Medium, L"PowerShell 编码命令");
                    }
                } else if (option == L"-f" || option == L"-file") {
                    result.scriptExecution = IsScriptFilePath(value());
                    break; // -File 后是脚本参数，不再按宿主启动选项判断。
                } else if (option == L"-c" || option == L"-command") {
                    const auto body = colon == std::wstring::npos ? command.substr(position)
                                                                  : arg.substr(colon + 1) + command.substr(position);
                    result.scriptExecution = !TrimForRule(body).empty();
                    if (HasPowerShellCodeSignal(body))
                        raise(RiskLevel::High, L"可疑脚本命令");
                    break;
                } else if (option == L"-version" || option == L"-v" || option == L"-inputformat" ||
                           option == L"-outputformat" || option == L"-workingdirectory") {
                    value();
                } else if (option.empty() || option.front() != L'-') {
                    result.scriptExecution = true;
                    if (HasPowerShellCodeSignal(command.substr(start)))
                        raise(RiskLevel::High, L"可疑脚本命令");
                    break;
                }
            }
            return result;
        }

        size_t argumentIndex = 0;
        while (position < command.size()) {
            const auto arg = ToLower(NextCommandTokenForRule(command, position));
            if (arg.empty())
                break;
            if ((token == L"mshta" || token == L"mshta.exe") && argumentIndex == 0) {
                result.scriptExecution = true;
                if (StartsWithRule(arg, L"http://") || StartsWithRule(arg, L"https://") ||
                    StartsWithRule(arg, L"vbscript:") || StartsWithRule(arg, L"javascript:"))
                    raise(RiskLevel::High, L"远程或内联 HTA 脚本启动");
            } else if (token == L"regsvr32" || token == L"regsvr32.exe") {
                if (StartsWithRule(arg, L"/i:http://") || StartsWithRule(arg, L"/i:https://") ||
                    FileNameFromPathForRule(arg) == L"scrobj.dll")
                    raise(RiskLevel::High, L"注册脚本组件命令");
            } else if ((token == L"rundll32" || token == L"rundll32.exe") && argumentIndex == 0) {
                const auto library = FileNameFromPathForRule(arg.substr(0, arg.find(L',')));
                if (StartsWithRule(arg, L"javascript:") || StartsWithRule(arg, L"vbscript:") ||
                    ((library == L"mshtml" || library == L"mshtml.dll") &&
                     arg.find(L",runhtmlapplication") != std::wstring::npos) ||
                    library == L"htmlfile") {
                    result.scriptExecution = true;
                    raise(RiskLevel::High, L"DLL 宿主脚本启动");
                }
            } else if (token == L"certutil" || token == L"certutil.exe") {
                if (arg == L"-urlcache")
                    raise(RiskLevel::Medium, L"证书工具下载命令");
                if (arg == L"-decode" || arg == L"-decodehex")
                    raise(RiskLevel::Medium, L"证书工具解码命令");
            } else if (token == L"bitsadmin" || token == L"bitsadmin.exe") {
                if (arg == L"/transfer")
                    raise(RiskLevel::Medium, L"BITS 文件传输命令");
            } else if ((token == L"wscript" || token == L"wscript.exe" || token == L"cscript" ||
                        token == L"cscript.exe") &&
                       IsScriptFilePath(arg)) {
                result.scriptExecution = true;
            }
            ++argumentIndex;
        }
        return result;
    }

    CommandLineAssessment AssessCommandLine(const std::wstring& command) {
        return AssessCommandLineImpl(command, 0);
    }

    bool IsCommandWrapperLaunch(const std::wstring& command) {
        const auto token = FirstCommandTokenForRule(command);
        return token == L"cmd" || token == L"cmd.exe" || token == L"%comspec%" || IsPowerShellToken(token);
    }

    RiskLevel SignatureRiskLevel(const FileEvidence& evidence) {
        if (evidence.signatureState != FieldState::Available || evidence.signature != SignatureState::Mismatch)
            return RiskLevel::None;
        // 根证书不受信任与摘要损坏分开分级，但不改变底层签名状态。
        return evidence.signatureNativeCode == static_cast<std::uint32_t>(CERT_E_UNTRUSTEDROOT) ||
                       (evidence.signatureNativeCode == 0 && evidence.signatureFailureReason == L"untrusted_root")
                   ? RiskLevel::Medium
                   : RiskLevel::High;
    }

    const wchar_t* SignatureRiskReason(const FileEvidence& evidence) {
        return SignatureRiskLevel(evidence) == RiskLevel::Medium ? L"签名证书根不受信任" : L"签名未匹配";
    }

    RiskLevel HiddenNameRiskLevel(const std::wstring& name) {
        if (!HasHiddenNamePrefix(name))
            return RiskLevel::None;
        if (name.front() != L' ' || ContainsBidiOrZeroWidthChar(name))
            return RiskLevel::High;
        for (const auto ch : name)
            if (iswcntrl(ch))
                return RiskLevel::High;
        return RiskLevel::Low;
    }

    bool IsScriptFilePath(const std::wstring& path) {
        std::wstring lower = ToLower(TrimForRule(path));
        const wchar_t* scriptExts[] = { L".vbs", L".vbe", L".js",  L".jse", L".wsf",
                                        L".wsh", L".ps1", L".bat", L".cmd", nullptr };
        for (int i = 0; scriptExts[i] != nullptr; i++) {
            if (EndsWithRule(lower, scriptExts[i])) {
                return true;
            }
        }
        return false;
    }

    bool IsLikelyMicrosoftCompany(const std::wstring& companyName) {
        std::wstring lower = ToLower(companyName);
        return lower.find(L"microsoft") != std::wstring::npos || lower.find(L"微软") != std::wstring::npos;
    }

    bool IsSystemNameSpoof(const std::wstring& objectName, const std::wstring& filePath) {
        const auto lowerName = FileNameFromPathForRule(objectName);
        const auto lowerFile = FileNameFromPathForRule(filePath);
        const wchar_t* systemNames[] = { L"svchost.exe",       L"lsass.exe",    L"winlogon.exe", L"csrss.exe",
                                         L"services.exe",      L"spoolsv.exe",  L"smss.exe",     L"conhost.exe",
                                         L"rundll32.exe",      L"dllhost.exe",  L"taskhost.exe", L"taskhostw.exe",
                                         L"runtimebroker.exe", L"explorer.exe", nullptr };
        const wchar_t* expectedName = nullptr;
        for (const auto* name : systemNames) {
            if (!name)
                break;
            if (lowerName == name) {
                expectedName = name;
                break;
            }
            if (lowerFile == name)
                expectedName = name;
        }
        if (!expectedName || filePath.empty())
            return false;
        const auto normalize = [](std::wstring value) -> std::wstring {
            value = ExpandEnvStrings(TrimForRule(value));
            std::replace(value.begin(), value.end(), L'/', L'\\');
            if (value.rfind(L"\\\\?\\", 0) == 0 || value.rfind(L"\\??\\", 0) == 0)
                value.erase(0, 4);
            if (value.size() < 3 || !iswalpha(value[0]) || value[1] != L':' || value[2] != L'\\')
                return {};
            wchar_t fullPath[32768]{};
            const DWORD size =
                GetFullPathNameW(value.c_str(), static_cast<DWORD>(std::size(fullPath)), fullPath, nullptr);
            return size && size < std::size(fullPath) ? ToLower(std::wstring(fullPath, size)) : std::wstring{};
        };
        const auto actual = normalize(filePath);
        if (actual.empty())
            return false;
        wchar_t windows[32768]{}, system[32768]{};
        const UINT windowsSize = GetWindowsDirectoryW(windows, static_cast<UINT>(std::size(windows)));
        const UINT systemSize = GetSystemDirectoryW(system, static_cast<UINT>(std::size(system)));
        if (!windowsSize || windowsSize >= std::size(windows) || !systemSize || systemSize >= std::size(system))
            return false;
        const auto expected = [&](const std::wstring& directory) {
            return actual == normalize(directory + L"\\" + expectedName);
        };
        // 必须匹配本机真实系统目录及文件名，不能仅凭路径包含 Windows 字样豁免。
        if (std::wstring(expectedName) == L"explorer.exe")
            return !expected(windows);
        return !expected(system) && !expected(std::wstring(windows) + L"\\SysWOW64");
    }
}
