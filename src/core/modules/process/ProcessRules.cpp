#include "../../system/Win32.h"
#include "ProcessRules.h"
#include "../../rules/RuleHelpers.h"
#include <algorithm>

namespace wgwc::core::process {
    namespace {
        struct SystemProcessDef {
            const wchar_t* name;
            const wchar_t* expectedPath;
        };

        const SystemProcessDef kSystemProcesses[] = {
            { L"smss.exe",      L"System32" },
            { L"csrss.exe",     L"System32" },
            { L"wininit.exe",   L"System32" },
            { L"winlogon.exe",  L"System32" },
            { L"services.exe",  L"System32" },
            { L"lsass.exe",     L"System32" },
            { L"svchost.exe",   L"System32" },
            { L"spoolsv.exe",   L"System32" },
            { L"explorer.exe",  L"Windows"  },
            { L"taskhostw.exe", L"System32" },
            { L"dwm.exe",       L"System32" },
            { L"conhost.exe",   L"System32" },
            { nullptr,          nullptr     }
        };
    }

    SystemLocations QuerySystemLocations() {
        SystemLocations result;
        wchar_t buffer[32768]{};
        UINT size = GetSystemDirectoryW(buffer, static_cast<UINT>(std::size(buffer)));
        if (size && size < std::size(buffer))
            result.system32 = buffer;
        size = GetWindowsDirectoryW(buffer, static_cast<UINT>(std::size(buffer)));
        if (size && size < std::size(buffer)) {
            result.windows = buffer;
            result.sysWow64 = result.windows + L"\\SysWOW64";
        }
        return result;
    }

    bool IsSystemProcess(const std::wstring& name) {
        const auto lower = rules::ToLower(name);
        if (lower == L"system" || lower == L"registry" || lower == L"[system process]")
            return true;
        for (const auto& definition : kSystemProcesses)
            if (definition.name && lower == rules::ToLower(definition.name))
                return true;
        return false;
    }

    bool IsValidSystemProcessPath(const std::wstring& name, const std::wstring& path,
                                  const SystemLocations& locations) {
        const auto normalize = [](std::wstring value) -> std::wstring {
            if (value.empty())
                return {};
            std::replace(value.begin(), value.end(), L'/', L'\\');
            if (value.rfind(L"\\\\?\\", 0) == 0 || value.rfind(L"\\??\\", 0) == 0)
                value.erase(0, 4);
            if (value.size() < 3 || value[1] != L':' || value[2] != L'\\')
                return {};
            wchar_t fullPath[32768]{};
            const DWORD length =
                GetFullPathNameW(value.c_str(), static_cast<DWORD>(std::size(fullPath)), fullPath, nullptr);
            if (!length || length >= std::size(fullPath))
                return {};
            return rules::ToLower(std::wstring(fullPath, length));
        };
        const auto lowerName = rules::ToLower(name);
        for (const auto& definition : kSystemProcesses) {
            if (!definition.name || lowerName != rules::ToLower(definition.name))
                continue;
            const auto actual = normalize(path);
            const auto exact = [&](const std::wstring& directory) {
                return !actual.empty() && !directory.empty() &&
                       actual == normalize(directory + L"\\" + definition.name);
            };
            if (std::wstring(definition.expectedPath) == L"System32")
                return exact(locations.system32) || exact(locations.sysWow64);
            if (std::wstring(definition.expectedPath) == L"Windows")
                return exact(locations.windows);
        }
        return true;
    }

    RiskAssessment AssessProcess(const Metadata& process, const files::FileInfo& file,
                                 const SystemLocations& locations) {
        RiskAssessment result;
        result.state = AssessmentState::Complete;
        if (process.pid == 0 || process.pid == 4)
            return result;
        auto hit = [&](const wchar_t* id, RiskLevel level, const wchar_t* reason, bool fileEvidence) {
            result.level = (std::max)(result.level, level);
            RiskHit item{ id, level, reason, {} };
            if (fileEvidence && !file.evidence.evidenceId.empty())
                item.evidenceIds.push_back(file.evidence.evidenceId);
            result.hits.push_back(std::move(item));
        };
        auto unknown = [&](const wchar_t* id) {
            result.state = AssessmentState::Incomplete;
            result.unevaluatedRules.push_back(id);
        };
        const bool hasPath = !process.path.empty() && process.path.front() != L'[';
        if (file.evidence.signatureState == FieldState::Available) {
            if (file.evidence.signature == SignatureState::Mismatch)
                hit(L"process.signature_mismatch", rules::SignatureRiskLevel(file.evidence),
                    rules::SignatureRiskReason(file.evidence), true);
        } else if (hasPath)
            unknown(L"process.signature_mismatch");
        if (hasPath && file.evidence.existence == FieldState::Available) {
            if (!file.evidence.exists || file.directory)
                hit(L"process.file_missing", RiskLevel::Medium, L"文件缺失", true);
        } else
            unknown(L"process.file_missing");
        if (hasPath && file.attributesState == FieldState::Available) {
            if (file.attributes & FILE_ATTRIBUTE_HIDDEN)
                hit(L"process.hidden_file", RiskLevel::Medium, L"隐藏文件", true);
        } else if (file.evidence.existence != FieldState::Available || file.evidence.exists)
            unknown(L"process.hidden_file");
        if (process.commandLineState == FieldState::Available) {
            const auto command = rules::AssessCommandLine(process.commandLine);
            if (command.level != RiskLevel::None)
                hit(L"process.suspicious_command_line", command.level, command.reason, false);
        } else
            unknown(L"process.suspicious_command_line");
        if (hasPath && IsSystemProcess(process.name)) {
            if (!IsValidSystemProcessPath(process.name, process.path, locations))
                hit(L"process.name_spoof", RiskLevel::Medium, L"名称伪装", true);
        } else if (!hasPath && IsSystemProcess(process.name))
            unknown(L"process.name_spoof");
        if ((hasPath && rules::HasDoubleExtensionSpoof(process.path)) || rules::HasDoubleExtensionSpoof(process.name))
            hit(L"process.double_extension_spoof", RiskLevel::Medium, L"双扩展名伪装", hasPath);
        return result;
    }

    std::wstring RiskReason(const RiskAssessment& assessment) {
        std::wstring result;
        for (const auto& hit : assessment.hits) {
            if (!result.empty())
                result += L"、";
            result += hit.reason;
        }
        return result;
    }
}
