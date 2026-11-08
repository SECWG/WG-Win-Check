#pragma once
#include <windows.h>
#include <algorithm>
#include "../../runtime/CollectionContext.h"

namespace wgwc::core::traces {
    enum class ActivityType {
        SystemBoot,
        SystemSleep,
        SystemWake,
        UserLogin,
        ProgramExec,
        DocumentAccess,
        SoftwareInstall
    };

    struct Record {
        FILETIME timestamp{};
        ActivityType type = ActivityType::ProgramExec;
        std::wstring description, details, source;

        bool operator<(const Record& other) const {
            return CompareFileTime(&timestamp, &other.timestamp) > 0;
        }
    };

    CollectionResult<Record> CollectActivities(const CollectionContext& context);

    namespace detail {
        // 注册表值超出任一缓冲区时，扩容后重试同一索引。
        inline LONG ReadUserAssistValue(HKEY key, DWORD index, std::wstring& valueName, std::vector<BYTE>& valueData,
                                        DWORD& valueType, const CollectionContext& context) {
            valueName.clear();
            valueData.clear();
            valueType = REG_NONE;
            std::vector<wchar_t> name(512);
            std::vector<BYTE> data(1024);
            constexpr DWORD maxName = 32768, maxData = 16 * 1024 * 1024;
            for (;;) {
                if (context.ShouldStop())
                    return context.IsCancelled() ? ERROR_CANCELLED : ERROR_TIMEOUT;
                DWORD nameSize = static_cast<DWORD>(name.size()), dataSize = static_cast<DWORD>(data.size());
                DWORD type = REG_NONE;
                const LONG result =
                    RegEnumValueW(key, index, name.data(), &nameSize, nullptr, &type, data.data(), &dataSize);
                if (result == ERROR_SUCCESS) {
                    if (nameSize >= name.size() || dataSize > data.size())
                        return ERROR_INVALID_DATA;
                    valueName.assign(name.data(), nameSize);
                    data.resize(dataSize);
                    valueData.swap(data);
                    valueType = type;
                    return ERROR_SUCCESS;
                }
                if (result != ERROR_MORE_DATA)
                    return result;
                if (nameSize >= maxName || dataSize > maxData)
                    return ERROR_MORE_DATA;
                const auto nextName = (std::min)(std::size_t{ maxName },
                                                 (std::max)(name.size() * 2, static_cast<std::size_t>(nameSize) + 1));
                const auto nextData =
                    (std::min)(std::size_t{ maxData }, (std::max)(data.size() * 2, static_cast<std::size_t>(dataSize)));
                if (nextName == name.size() && nextData == data.size())
                    return ERROR_MORE_DATA;
                name.resize(nextName);
                data.resize(nextData);
            }
        }
    }
}
