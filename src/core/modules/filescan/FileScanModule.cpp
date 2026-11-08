#include "../../system/Win32.h"
#include "FileScanModule.h"
#include "../../system/FileService.h"
#include <algorithm>
#include <cwctype>
#include <queue>
#include <set>

namespace wgwc::core::filescan {
    namespace {
        std::wstring Lower(std::wstring s) {
            std::transform(s.begin(), s.end(), s.begin(), ::towlower);
            return s;
        }

        std::wstring Join(const std::wstring& dir, const std::wstring& name) {
            return dir + (dir.empty() || dir.back() != L'\\' ? L"\\" : L"") + name;
        }

        bool Absent(DWORD e) {
            return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND;
        }

        std::set<std::wstring> Extensions(const ScanConfig& c) {
            std::set<std::wstring> exts;
            auto add = [&](std::initializer_list<const wchar_t*> list) {
                for (auto s : list)
                    exts.insert(s);
            };
            if (c.scanExecutables)
                add({ L".exe", L".dll", L".bin", L".scr", L".com", L".msi" });
            if (c.scanScripts)
                add({ L".ps1", L".vbs", L".bat", L".cmd", L".wsf", L".hta" });
            if (c.scanArchives)
                add({ L".zip", L".rar", L".7z" });
            if (c.scanOther)
                add({ L".lnk", L".conf", L".config" });
            for (const auto& e : c.customExtensions)
                if (!e.empty())
                    exts.insert(Lower(e.front() == L'.' ? e : L"." + e));
            return exts;
        }
    }

    CollectionResult<Record> ScanFiles(const ScanConfig& config, const CollectionContext& context,
                                       const Observer& observer, const std::function<void(const Progress&)>& progress,
                                       const std::function<bool()>& stop) {
        CollectionResult<Record> result;
        result.status = CollectionStatus::Complete;
        result.assessment = AssessmentState::NotApplicable;
        result.startedAt = UtcNow();
        Progress stats;
        bool stopped = false;
        auto shouldStop = [&]() {
            return stopped || context.ShouldStop() || (stop && stop());
        };
        auto issue = [&](const std::wstring& path, DWORD error) {
            result.status = CollectionStatus::Partial;
            if (result.issues.size() < 32)
                result.issues.push_back({ L"files", path, L"DIRECTORY_READ_FAILED", error, L"无法读取扫描目录", true });
        };

        struct Root {
            std::wstring path;
            bool required;
        };

        std::vector<Root> roots;
        auto enumerateRoots = [&](const std::wstring& path,
                                  const std::function<void(const WIN32_FIND_DATAW&)>& accept) {
            WIN32_FIND_DATAW fd{};
            HANDLE h = FindFirstFileW(Join(path, L"*").c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) {
                auto e = GetLastError();
                if (!Absent(e))
                    issue(path, e);
                return;
            }
            do {
                if (shouldStop())
                    break;
                if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && wcscmp(fd.cFileName, L".") &&
                    wcscmp(fd.cFileName, L".."))
                    accept(fd);
            } while (FindNextFileW(h, &fd));
            auto e = GetLastError();
            FindClose(h);
            if (!shouldStop() && e != ERROR_NO_MORE_FILES)
                issue(path, e);
        };
        if (config.useUserDownloads || config.useUserTemp)
            enumerateRoots(L"C:\\Users", [&](const WIN32_FIND_DATAW& fd) {
                if (!_wcsicmp(fd.cFileName, L"Default User") || !_wcsicmp(fd.cFileName, L"All Users"))
                    return;
                std::wstring base = Join(L"C:\\Users", fd.cFileName);
                if (config.useUserDownloads)
                    roots.push_back({ Join(base, L"Downloads"), false });
                if (config.useUserTemp)
                    roots.push_back({ Join(base, L"AppData\\Local\\Temp"), false });
            });
        if (config.useSystemTemp)
            roots.push_back({ L"C:\\Windows\\Temp", false });
        if (config.useNonSystemCDirs)
            enumerateRoots(L"C:\\", [&](const WIN32_FIND_DATAW& fd) {
                constexpr const wchar_t* excluded[] = { L"windows",       L"users",
                                                        L"program files", L"program files (x86)",
                                                        L"programdata",   L"system volume information",
                                                        L"$recycle.bin",  L"recovery",
                                                        L"config.msi",    L"documents and settings",
                                                        L"msocache",      L"perflogs",
                                                        L"drivers" };
                for (auto name : excluded)
                    if (!_wcsicmp(fd.cFileName, name))
                        return;
                roots.push_back({ Join(L"C:\\", fd.cFileName), false });
            });
        for (const auto& path : config.customPaths)
            if (!path.empty())
                roots.push_back({ path, true });
        auto normalizedDirectory = [](const std::wstring& path) -> std::wstring {
            const DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
            if (!needed)
                return {};
            std::vector<wchar_t> full(static_cast<std::size_t>(needed) + 1);
            const DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
            if (!length || length >= full.size())
                return {};
            auto value = Lower(std::wstring(full.data(), length));
            for (auto& c : value)
                if (c == L'/')
                    c = L'\\';
            while (!value.empty() && value.back() == L'\\')
                value.pop_back();
            return value + L"\\";
        };
        std::vector<std::wstring> explicitRoots;
        for (const auto& path : config.customPaths)
            if (!path.empty()) {
                auto prefix = normalizedDirectory(path);
                if (!prefix.empty())
                    explicitRoots.push_back(std::move(prefix));
            }
        auto withinExplicitScope = [&](const std::wstring& path) {
            const auto candidate = normalizedDirectory(path);
            if (candidate.empty())
                return false;
            for (const auto& prefix : explicitRoots)
                if (candidate.compare(0, prefix.size(), prefix) == 0)
                    return true;
            return false;
        };
        const auto extensions = Extensions(config);
        std::queue<std::wstring> queue;
        std::set<std::wstring> visited;
        auto enqueue = [&](const std::wstring& path) {
            if (visited.insert(Lower(path)).second) {
                queue.push(path);
                ++stats.totalDirs;
            }
        };
        for (const auto& root : roots) {
            if (shouldStop())
                break;
            std::uint32_t error = 0;
            auto path = files::ResolvePath(root.path, &error);
            if (path.empty()) {
                issue(root.path, error ? error : ERROR_INVALID_NAME);
                continue;
            }
            while (path.size() > 3 && path[path.size() - 2] != L':' && (path.back() == L'\\' || path.back() == L'/'))
                path.pop_back();
            const DWORD attr = GetFileAttributesW(path.c_str());
            if (attr == INVALID_FILE_ATTRIBUTES) {
                auto e = GetLastError();
                if (root.required || !Absent(e))
                    issue(path, e);
                continue;
            }
            if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                issue(path, ERROR_DIRECTORY);
                continue;
            }
            // 不遍历目录联接或符号链接根目录，即使该目录由用户显式指定。
            if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
                issue(path, ERROR_CANT_ACCESS_FILE);
                continue;
            }
            enqueue(path);
        }
        while (!queue.empty() && !shouldStop()) {
            auto dir = std::move(queue.front());
            queue.pop();
            WIN32_FIND_DATAW fd{};
            HANDLE h = FindFirstFileW(Join(dir, L"*").c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) {
                auto e = GetLastError();
                if (e != ERROR_FILE_NOT_FOUND)
                    issue(dir, e);
                ++stats.completedDirs;
                continue;
            }
            do {
                if (shouldStop())
                    break;
                if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L".."))
                    continue;
                auto path = Join(dir, fd.cFileName);
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                        (!(fd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) || withinExplicitScope(path)))
                        enqueue(path);
                } else {
                    ++stats.scannedFiles;
                    std::wstring name = fd.cFileName;
                    auto dot = name.find_last_of(L'.');
                    if (dot == std::wstring::npos || !extensions.count(Lower(name.substr(dot))))
                        continue;
                    if (stats.matchedFiles >= context.maxRecords) {
                        result.collectionTruncated = true;
                        stopped = true;
                        break;
                    }
                    Record record{ name, path, (static_cast<ULONGLONG>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow,
                                   fd.ftCreationTime, fd.ftLastWriteTime };
                    if (observer) {
                        if (!observer(record)) {
                            stopped = true;
                            break;
                        }
                    } else
                        result.records.push_back(std::move(record));
                    ++stats.matchedFiles;
                }
                if (progress && !(stats.scannedFiles % 256))
                    progress(stats);
            } while (FindNextFileW(h, &fd));
            auto e = GetLastError();
            FindClose(h);
            if (!shouldStop() && e != ERROR_NO_MORE_FILES)
                issue(dir, e);
            ++stats.completedDirs;
            if (progress)
                progress(stats);
        }
        if (context.ShouldStop())
            result.status = context.StopStatus();
        else if (stopped || (stop && stop()))
            result.status = CollectionStatus::Partial;
        else if (stats.totalDirs == 0 && !result.issues.empty())
            result.status = CollectionStatus::Failed;
        result.collected = stats.matchedFiles;
        result.finishedAt = UtcNow();
        if (progress)
            progress(stats);
        return result;
    }
}
