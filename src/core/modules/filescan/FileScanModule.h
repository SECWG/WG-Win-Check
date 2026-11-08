#pragma once
#include <windows.h>
#include "../../runtime/CollectionContext.h"
#include <functional>

namespace wgwc::core::filescan {
    struct Record {
        std::wstring fileName, filePath;
        ULONGLONG fileSize = 0;
        FILETIME creationTime{}, lastWriteTime{};

        bool operator<(const Record& other) const {
            return CompareFileTime(&lastWriteTime, &other.lastWriteTime) > 0;
        }
    };

    struct ScanConfig {
        bool scanExecutables = true, scanScripts = true, scanArchives = true, scanOther = false;
        std::vector<std::wstring> customExtensions;
        bool useUserDownloads = true, useUserTemp = false, useSystemTemp = false, useNonSystemCDirs = true;
        std::vector<std::wstring> customPaths;
    };

    struct Progress {
        std::size_t scannedFiles = 0, matchedFiles = 0, completedDirs = 0, totalDirs = 0;
    };

    using Observer = std::function<bool(const Record&)>;
    CollectionResult<Record> ScanFiles(const ScanConfig& config, const CollectionContext& context,
                                       const Observer& observer = {},
                                       const std::function<void(const Progress&)>& progress = {},
                                       const std::function<bool()>& stop = {});
}
