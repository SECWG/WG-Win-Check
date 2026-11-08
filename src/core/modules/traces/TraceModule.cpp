#include "../../system/Win32.h"
#include "TraceModule.h"
#include <winternl.h>
#include <winevt.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <algorithm>
#include <cwctype>
#include <iterator>
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

namespace wgwc::core::traces {
    namespace {
        using ActivityRecord = Record;

        std::wstring ToUpperString(std::wstring value) {
            std::transform(value.begin(), value.end(), value.begin(), ::towupper);
            return value;
        }

        std::wstring NormalizePrefetchVolumePrefix(std::wstring value) {
            if (value.rfind(L"\\\\?\\", 0) == 0 || value.rfind(L"\\\\.\\", 0) == 0)
                value = L"\\" + value.substr(4);
            while (value.size() > 1 && (value.back() == L'\\' || value.back() == L'/'))
                value.pop_back();
            return value;
        }

        bool IsPrefetchPrefixMatch(const std::wstring& path, const std::wstring& prefix) {
            return path.size() >= prefix.size() && !_wcsnicmp(path.c_str(), prefix.c_str(), prefix.size()) &&
                   (path.size() == prefix.size() || path[prefix.size()] == L'\\' || path[prefix.size()] == L'/');
        }

        void AddUniquePrefetchString(std::vector<std::wstring>& values, const std::wstring& value) {
            for (const auto& old : values)
                if (!_wcsicmp(old.c_str(), value.c_str()))
                    return;
            values.push_back(value);
        }

        bool PrefetchFileExists(const std::wstring& path) {
            DWORD a = GetFileAttributesW(path.c_str());
            return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
        }

        std::wstring DecodeXml(std::wstring text) {
            struct Pair {
                const wchar_t* from;
                const wchar_t* to;
            };

            constexpr Pair entities[] = {
                { L"&lt;",   L"<"  },
                { L"&gt;",   L">"  },
                { L"&quot;", L"\"" },
                { L"&apos;", L"'"  },
                { L"&amp;",  L"&"  }
            };
            for (const auto& e : entities)
                for (std::size_t p = 0; (p = text.find(e.from, p)) != std::wstring::npos; p += wcslen(e.to))
                    text.replace(p, wcslen(e.from), e.to);
            return text;
        }

        std::wstring Attribute(const std::wstring& xml, const std::wstring& name) {
            auto p = xml.find(name + L"=");
            if (p == std::wstring::npos)
                return L"";
            p += name.size() + 1;
            if (p >= xml.size() || (xml[p] != L'\'' && xml[p] != L'"'))
                return L"";
            auto end = xml.find(xml[p], p + 1);
            return end == std::wstring::npos ? L"" : DecodeXml(xml.substr(p + 1, end - p - 1));
        }

        std::wstring EventData(const std::wstring& xml, const wchar_t* field) {
            std::size_t p = 0;
            while ((p = xml.find(L"<Data", p)) != std::wstring::npos) {
                auto end = xml.find(L'>', p);
                if (end == std::wstring::npos)
                    break;
                if (Attribute(xml.substr(p, end - p), L"Name") == field) {
                    auto close = xml.find(L"</Data>", end);
                    return close == std::wstring::npos ? L"" : DecodeXml(xml.substr(end + 1, close - end - 1));
                }
                p = end + 1;
            }
            return L"";
        }

        class Collector {
        public:
            Collector(CollectionResult<Record>& result, const CollectionContext& context)
                : result_(result), context_(context) {}

            void Run();

        private:
            CollectionResult<Record>& result_;
            const CollectionContext& context_;
            std::size_t source_ = 0;
            std::vector<std::pair<std::wstring, std::wstring>> m_prefetchVolumeMap;
            std::vector<std::wstring> m_prefetchDriveRoots;

            bool Stopped() const {
                return context_.ShouldStop() || result_.collectionTruncated;
            }

            void Problem(DWORD e) {
                if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
                    return;
                result_.status = CollectionStatus::Partial;
                auto& s = result_.sources[source_];
                s.status = L"partial";
                s.nativeCode = e;
                if (result_.issues.size() < 16)
                    result_.issues.push_back(
                        { s.source, L"", L"TRACE_SOURCE_INCOMPLETE", e, L"部分活动痕迹不可读取或解析", true });
            }

            void Append(const Record& r) {
                if (Stopped())
                    return;
                if (result_.records.size() >= context_.maxRecords) {
                    result_.collectionTruncated = true;
                    return;
                }
                result_.records.push_back(r);
                ++result_.sources[source_].collected;
            }

            void Events(const wchar_t* channel, const wchar_t* query, unsigned maximum, unsigned kind);
            std::wstring ExtractPrefetchExeName(const std::wstring& pfPath);
            std::wstring ExtractPrefetchExePath(const BYTE* data, DWORD dataSize, DWORD version,
                                                const std::wstring& exeName);
            void BuildPrefetchVolumeMap();
            std::wstring ResolvePrefetchVolumeFallback(const std::wstring& path) const;
            std::wstring ProcessPrefetchPath(const std::wstring& path);
            bool ParsePrefetchFile(const std::wstring& pfPath);
            void CollectPrefetchRecords();
            std::wstring DecodeROT13(const std::wstring& encoded);
            bool ParseUserAssistValue(const BYTE* data, DWORD dataSize, FILETIME& lastExecTime);
            void CollectUserAssistRecords();
            void CollectRecentDocsRecords();
            void CollectSoftwareInstallRecords();
        };

        void Collector::Events(const wchar_t* channel, const wchar_t* query, unsigned maximum, unsigned kind) {
            EVT_HANDLE queryHandle = EvtQuery(nullptr, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection);
            if (!queryHandle) {
                Problem(GetLastError());
                return;
            }
            unsigned seen = 0;
            while (seen < maximum && !Stopped()) {
                EVT_HANDLE handles[16]{};
                DWORD count = 0;
                if (!EvtNext(queryHandle, 16, handles, 1000, 0, &count)) {
                    DWORD e = GetLastError();
                    if (e == ERROR_TIMEOUT)
                        continue;
                    if (e != ERROR_NO_MORE_ITEMS)
                        Problem(e);
                    break;
                }
                for (DWORD i = 0; i < count; ++i) {
                    if (seen >= maximum || Stopped()) {
                        EvtClose(handles[i]);
                        continue;
                    }
                    ++seen;
                    DWORD required = 0, props = 0;
                    EvtRender(nullptr, handles[i], EvtRenderEventXml, 0, nullptr, &required, &props);
                    DWORD e = GetLastError();
                    std::wstring xml;
                    if (e == ERROR_INSUFFICIENT_BUFFER && required <= 4 * 1024 * 1024) {
                        std::vector<wchar_t> buffer(required / sizeof(wchar_t) + 1, L'\0');
                        if (EvtRender(nullptr, handles[i], EvtRenderEventXml, required, buffer.data(), &required,
                                      &props))
                            xml = buffer.data();
                        else
                            Problem(GetLastError());
                    } else
                        Problem(e == ERROR_INSUFFICIENT_BUFFER ? ERROR_INVALID_DATA : e);
                    EvtClose(handles[i]);
                    if (xml.empty())
                        continue;
                    auto timestamp = Attribute(xml, L"SystemTime");
                    SYSTEMTIME st{};
                    unsigned y = 0, mon = 0, d = 0, h = 0, m = 0, s = 0;
                    if (swscanf_s(timestamp.c_str(), L"%u-%u-%uT%u:%u:%u", &y, &mon, &d, &h, &m, &s) != 6) {
                        Problem(ERROR_INVALID_DATA);
                        continue;
                    }
                    st.wYear = static_cast<WORD>(y);
                    st.wMonth = static_cast<WORD>(mon);
                    st.wDay = static_cast<WORD>(d);
                    st.wHour = static_cast<WORD>(h);
                    st.wMinute = static_cast<WORD>(m);
                    st.wSecond = static_cast<WORD>(s);
                    Record r;
                    if (!SystemTimeToFileTime(&st, &r.timestamp)) {
                        Problem(GetLastError());
                        continue;
                    }
                    r.source = L"EventLog";
                    if (kind == 0) {
                        r.type = ActivityType::SystemBoot;
                        r.description = L"系统启动";
                        r.details = L"系统事件日志服务启动";
                    } else if (kind == 1) {
                        const bool wake = xml.find(L"Microsoft-Windows-Power-Troubleshooter") != std::wstring::npos;
                        r.type = wake ? ActivityType::SystemWake : ActivityType::SystemSleep;
                        r.description = wake ? L"系统唤醒" : L"系统睡眠";
                        r.details = wake ? L"系统从睡眠状态恢复" : L"系统进入睡眠状态";
                    } else {
                        auto user = EventData(xml, L"TargetUserName"), type = EventData(xml, L"LogonType");
                        if (user.empty() || !_wcsicmp(user.c_str(), L"SYSTEM") ||
                            !_wcsicmp(user.c_str(), L"LOCAL SERVICE") || !_wcsicmp(user.c_str(), L"NETWORK SERVICE") ||
                            (type != L"2" && type != L"10"))
                            continue;
                        r.type = ActivityType::UserLogin;
                        r.description = user;
                        r.details = type == L"10" ? L"远程交互式登录" : L"交互式登录";
                        auto address = EventData(xml, L"IpAddress");
                        if (!address.empty() && address != L"-")
                            r.details += L" | IP: " + address;
                    }
                    Append(r);
                }
            }
            EvtClose(queryHandle);
        }

        void Collector::Run() {
            auto begin = [&](const wchar_t* name) {
                result_.sources.push_back({ name, L"complete", 0, 0 });
                source_ = result_.sources.size() - 1;
            };
            begin(L"SystemBoot");
            Events(L"System", L"*[System[(EventID=6005)]]", 100, 0);
            if (Stopped())
                return;
            begin(L"SleepWake");
            Events(
                L"System",
                L"*[System[(Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1) or (Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=42)]]",
                100, 1);
            if (Stopped())
                return;
            begin(L"UserLogon");
            // 先限定查询范围，再应用原有的近期事件窗口。
            Events(
                L"Security",
                L"*[System[EventID=4624] and EventData[(Data[@Name='LogonType']='2') or (Data[@Name='LogonType']='10')]]",
                200, 2);
            if (Stopped())
                return;
            begin(L"Prefetch");
            CollectPrefetchRecords();
            if (Stopped())
                return;
            begin(L"UserAssist");
            CollectUserAssistRecords();
            if (Stopped())
                return;
            begin(L"Recent");
            CollectRecentDocsRecords();
            if (Stopped())
                return;
            begin(L"Uninstall");
            CollectSoftwareInstallRecords();
        }

        std::wstring Collector::ExtractPrefetchExeName(const std::wstring& pfPath) {
            // 从文件名提取程序名：WG-WIN-CHECK.EXE-6C56C276.pf -> WG-WIN-CHECK.EXE
            size_t lastSlash = pfPath.find_last_of(L"\\/");
            std::wstring fileName = (lastSlash != std::wstring::npos) ? pfPath.substr(lastSlash + 1) : pfPath;

            // 查找 .EXE（不区分大小写）
            std::wstring upperFileName = fileName;
            std::transform(upperFileName.begin(), upperFileName.end(), upperFileName.begin(), ::towupper);

            size_t exePos = upperFileName.find(L".EXE");
            if (exePos != std::wstring::npos) {
                // 找到 .EXE，提取到 .EXE 之后（包含 .EXE）
                return fileName.substr(0, exePos + 4); // +4 是 ".EXE" 的长度
            }

            // 文件名不含 .EXE 时，回退到首个连字符前的名称。
            size_t dashPos = fileName.find(L'-');
            if (dashPos != std::wstring::npos) {
                return fileName.substr(0, dashPos);
            }

            // 如果都没有，去掉 .pf 扩展名
            size_t dotPos = fileName.rfind(L".pf");
            if (dotPos != std::wstring::npos) {
                return fileName.substr(0, dotPos);
            }

            return fileName;
        }

        std::wstring Collector::ExtractPrefetchExePath(const BYTE* data, DWORD dataSize, DWORD version,
                                                       const std::wstring& exeName) {
            // 从解压后的 Prefetch 数据中提取可执行文件路径
            if (dataSize < 512) {
                return L"";
            }

            // 根据版本提取路径信息
            DWORD stringsOffset = 0;

            if (version == 30 || version == 31) {
                // Windows 10/11 版本 - 字符串区域偏移在 0x64
                stringsOffset = *(DWORD*)&data[0x64];
            } else if (version == 26) {
                // Windows 8.1 版本
                stringsOffset = *(DWORD*)&data[0x64];
            } else if (version == 23) {
                // Windows Vista/7 版本
                stringsOffset = *(DWORD*)&data[0x64];
            } else if (version == 17) {
                // Windows XP/2003 版本
                stringsOffset = *(DWORD*)&data[0x64];
            } else {
                return L"";
            }

            if (stringsOffset >= dataSize || stringsOffset % sizeof(wchar_t)) {
                return L"";
            }

            // 字符串区域包含多个以 null 结尾的 Unicode 字符串
            // 我们需要找到包含 .exe 的主程序路径
            const wchar_t* strPtr = (const wchar_t*)&data[stringsOffset];
            DWORD maxLen = (dataSize - stringsOffset) / sizeof(wchar_t);

            std::wstring exeNameUpper = exeName;
            std::transform(exeNameUpper.begin(), exeNameUpper.end(), exeNameUpper.begin(), ::towupper);

            // 遍历所有字符串，查找匹配的 .exe 路径
            DWORD pos = 0;
            while (pos < maxLen) {
                // 读取当前字符串
                std::wstring currentStr;
                while (pos < maxLen && strPtr[pos] != L'\0') {
                    currentStr += strPtr[pos];
                    pos++;
                }
                pos++; // 跳过 null 终止符

                if (currentStr.empty()) {
                    continue;
                }

                // 转换为大写以便比较
                std::wstring currentStrUpper = currentStr;
                std::transform(currentStrUpper.begin(), currentStrUpper.end(), currentStrUpper.begin(), ::towupper);

                // 检查是否包含 .EXE 扩展名
                if (currentStrUpper.find(L".EXE") != std::wstring::npos) {
                    // 检查是否包含程序名
                    if (currentStrUpper.find(exeNameUpper) != std::wstring::npos) {
                        // 找到匹配的路径，处理并转换为小写
                        std::wstring processedPath = ProcessPrefetchPath(currentStr);
                        std::transform(processedPath.begin(), processedPath.end(), processedPath.begin(), ::towlower);
                        return processedPath;
                    }
                }
            }

            // 如果没找到匹配的 .exe 路径，返回第一个字符串（处理并转换为小写）
            strPtr = (const wchar_t*)&data[stringsOffset];
            std::wstring firstPath;
            for (DWORD i = 0; i < maxLen && strPtr[i] != L'\0'; i++) {
                firstPath += strPtr[i];
            }

            if (!firstPath.empty()) {
                // 处理并转换为小写
                std::wstring processedPath = ProcessPrefetchPath(firstPath);
                std::transform(processedPath.begin(), processedPath.end(), processedPath.begin(), ::towlower);
                return processedPath;
            }

            return L"";
        }

        void Collector::BuildPrefetchVolumeMap() {
            m_prefetchVolumeMap.clear();
            m_prefetchDriveRoots.clear();

            DWORD required = GetLogicalDriveStringsW(0, NULL);
            if (required == 0) {
                return;
            }

            std::vector<wchar_t> drives(required + 1, L'\0');
            DWORD copied = GetLogicalDriveStringsW(required, drives.data());
            if (copied == 0 || copied > required) {
                return;
            }

            auto addMapping = [this](const std::wstring& rawPrefix, const std::wstring& driveRoot) {
                std::wstring prefix = NormalizePrefetchVolumePrefix(rawPrefix);
                if (prefix.empty()) {
                    return;
                }

                std::wstring drive = driveRoot;
                while (drive.length() > 2 && (drive.back() == L'\\' || drive.back() == L'/')) {
                    drive.pop_back();
                }

                std::wstring upperPrefix = ToUpperString(prefix);
                for (const auto& item : m_prefetchVolumeMap) {
                    if (ToUpperString(item.first) == upperPrefix) {
                        return;
                    }
                }

                m_prefetchVolumeMap.push_back(std::make_pair(prefix, drive));
            };

            for (wchar_t* drive = drives.data(); *drive; drive += wcslen(drive) + 1) {
                std::wstring driveRoot = drive;
                if (driveRoot.length() < 2) {
                    continue;
                }

                AddUniquePrefetchString(m_prefetchDriveRoots, driveRoot);

                std::wstring dosName = driveRoot.substr(0, 2);
                wchar_t deviceName[1024] = { 0 };
                if (QueryDosDeviceW(dosName.c_str(), deviceName, 1024) != 0) {
                    addMapping(deviceName, driveRoot);
                }

                wchar_t volumeName[MAX_PATH] = { 0 };
                if (GetVolumeNameForVolumeMountPointW(driveRoot.c_str(), volumeName, MAX_PATH)) {
                    addMapping(volumeName, driveRoot);
                }
            }

            std::sort(m_prefetchVolumeMap.begin(), m_prefetchVolumeMap.end(),
                      [](const std::pair<std::wstring, std::wstring>& left,
                         const std::pair<std::wstring, std::wstring>& right) {
                          return left.first.length() > right.first.length();
                      });
        }

        std::wstring Collector::ResolvePrefetchVolumeFallback(const std::wstring& path) const {
            std::wstring normalized = NormalizePrefetchVolumePrefix(path);
            std::wstring upperPath = ToUpperString(normalized);

            if (upperPath.rfind(L"\\VOLUME{", 0) != 0) {
                return path;
            }

            size_t closeBrace = normalized.find(L'}');
            if (closeBrace == std::wstring::npos || closeBrace + 1 >= normalized.length()) {
                return path;
            }

            std::wstring suffix = normalized.substr(closeBrace + 1);
            if (suffix.empty() || (suffix[0] != L'\\' && suffix[0] != L'/')) {
                return path;
            }

            for (const auto& driveRoot : m_prefetchDriveRoots) {
                if (driveRoot.length() < 2) {
                    continue;
                }

                std::wstring candidate = driveRoot.substr(0, 2) + suffix;
                if (PrefetchFileExists(candidate)) {
                    return candidate;
                }
            }

            return path;
        }

        std::wstring Collector::ProcessPrefetchPath(const std::wstring& path) {
            if (path.empty()) {
                return path;
            }

            std::wstring normalizedPath = NormalizePrefetchVolumePrefix(path);
            for (const auto& item : m_prefetchVolumeMap) {
                if (IsPrefetchPrefixMatch(normalizedPath, item.first)) {
                    return item.second + normalizedPath.substr(item.first.length());
                }
            }

            return ResolvePrefetchVolumeFallback(path);
        }

        bool Collector::ParsePrefetchFile(const std::wstring& pfPath) {
            // 打开文件
            HANDLE hFile = CreateFileW(pfPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile == INVALID_HANDLE_VALUE) {
                return false;
            }

            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize == INVALID_FILE_SIZE || fileSize < 8 || fileSize > 64 * 1024 * 1024) {
                CloseHandle(hFile);
                return false;
            }

            // 读取整个文件
            std::vector<BYTE> fileData(fileSize);
            DWORD bytesRead = 0;
            if (!ReadFile(hFile, fileData.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
                CloseHandle(hFile);
                return false;
            }
            CloseHandle(hFile);

            BYTE* dataPtr = fileData.data();
            DWORD dataSize = bytesRead;
            std::vector<BYTE> decompressedData;

            // 检查是否是压缩的 Prefetch 文件（MAM 压缩）
            if (bytesRead >= 8 && dataPtr[0] == 'M' && dataPtr[1] == 'A' && dataPtr[2] == 'M') {

                // MAM 压缩格式：
                // 偏移 0x00-0x03: 签名 (包含压缩算法)
                // 偏移 0x04-0x07: 解压后大小 (DWORD)
                // 偏移 0x08+: 压缩数据（可能包含 CRC）

                DWORD signature = *(DWORD*)&dataPtr[0];
                DWORD uncompressedSize = *(DWORD*)&dataPtr[4];
                if (uncompressedSize < 512 || uncompressedSize > 64 * 1024 * 1024)
                    return false;

                // 提取压缩算法和 CRC 标志
                DWORD calgo = (signature & 0x0F000000) >> 24;
                DWORD crcck = (signature & 0xF0000000) >> 28;

                // 跳过 CRC（如果存在）
                BYTE* compressedPtr = dataPtr + 8;
                DWORD compressedSize = bytesRead - 8;

                if (crcck) {
                    if (compressedSize < 4)
                        return false;
                    compressedPtr += 4; // 跳过 4 字节 CRC
                    compressedSize -= 4;
                }

                // 分配解压缓冲区
                decompressedData.resize(uncompressedSize);

                // 使用 RtlDecompressBufferEx 解压
                typedef NTSTATUS(WINAPI * RtlDecompressBufferExFunc)(
                    USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize,
                    PUCHAR CompressedBuffer, ULONG CompressedBufferSize, PULONG FinalUncompressedSize, PVOID WorkSpace);

                typedef NTSTATUS(WINAPI * RtlGetCompressionWorkSpaceSizeFunc)(
                    USHORT CompressionFormat, PULONG CompressBufferWorkSpaceSize, PULONG CompressFragmentWorkSpaceSize);

                HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
                if (!hNtdll) {
                    return false;
                }

                RtlDecompressBufferExFunc RtlDecompressBufferEx =
                    (RtlDecompressBufferExFunc)GetProcAddress(hNtdll, "RtlDecompressBufferEx");

                RtlGetCompressionWorkSpaceSizeFunc RtlGetCompressionWorkSpaceSize =
                    (RtlGetCompressionWorkSpaceSizeFunc)GetProcAddress(hNtdll, "RtlGetCompressionWorkSpaceSize");

                if (!RtlDecompressBufferEx || !RtlGetCompressionWorkSpaceSize) {
                    return false;
                }

                // 获取工作空间大小
                ULONG compressBufferWorkSpaceSize = 0;
                ULONG compressFragmentWorkSpaceSize = 0;

                NTSTATUS status = RtlGetCompressionWorkSpaceSize((USHORT)calgo, &compressBufferWorkSpaceSize,
                                                                 &compressFragmentWorkSpaceSize);

                if (status != 0) {
                    return false;
                }

                // 分配工作空间
                if (compressFragmentWorkSpaceSize > 64 * 1024 * 1024)
                    return false;
                std::vector<BYTE> workspace(compressFragmentWorkSpaceSize);

                ULONG finalSize = 0;
                status = RtlDecompressBufferEx((USHORT)calgo, decompressedData.data(), uncompressedSize, compressedPtr,
                                               compressedSize, &finalSize, workspace.data());

                if (status != 0) {
                    return false;
                }

                // 使用解压后的数据
                dataPtr = decompressedData.data();
                if (finalSize > decompressedData.size())
                    return false;
                dataSize = finalSize;
            }

            // 现在 dataPtr 指向未压缩的 Prefetch 数据
            if (dataSize < 512) {
                return false;
            }

            // 检查签名 "SCCA"
            DWORD signature = *(DWORD*)&dataPtr[0x04];
            if (signature != 0x41434353) { // 文件格式标识："SCCA"。
                return false;
            }

            // 检查版本号
            DWORD version = *(DWORD*)&dataPtr[0x00];

            // Windows 11 使用版本 31 (0x1F)
            // Windows 10 使用版本 30 (0x1E)
            // Windows 8.1 使用版本 26 (0x1A)
            // Windows Vista/7 使用版本 23 (0x17)
            // Windows XP/2003 使用版本 17 (0x11)
            if (version != 31 && version != 30 && version != 26 && version != 23 && version != 17) {
                return false;
            }

            // 提取程序名并转换为小写
            std::wstring exeName = ExtractPrefetchExeName(pfPath);
            std::transform(exeName.begin(), exeName.end(), exeName.begin(), ::towlower);

            // 提取可执行文件路径（传入程序名以便匹配）
            std::wstring exePath = ExtractPrefetchExePath(dataPtr, dataSize, version, exeName);

            // 提取文件名（用于来源字段）
            size_t lastSlash = pfPath.find_last_of(L"\\/");
            std::wstring pfFileName = (lastSlash != std::wstring::npos) ? pfPath.substr(lastSlash + 1) : pfPath;

            // 根据版本提取执行时间
            int validTimeCount = 0;

            if (version == 17) {
                // Windows XP/2003: 只有1个执行时间，在偏移 0x78
                if (dataSize >= 0x78 + sizeof(FILETIME)) {
                    FILETIME* execTime = (FILETIME*)&dataPtr[0x78];
                    if (execTime->dwLowDateTime != 0 || execTime->dwHighDateTime != 0) {
                        ActivityRecord record;
                        record.timestamp = *execTime;
                        record.type = ActivityType::ProgramExec;
                        record.description = exeName;
                        record.details = exePath;
                        record.source = L"Prefetch-" + pfFileName;

                        Append(record);
                        validTimeCount++;
                    }
                }
            } else if (version == 23) {
                // Windows Vista/7: 只有1个执行时间，在偏移 0x80
                if (dataSize >= 0x80 + sizeof(FILETIME)) {
                    FILETIME* execTime = (FILETIME*)&dataPtr[0x80];
                    if (execTime->dwLowDateTime != 0 || execTime->dwHighDateTime != 0) {
                        ActivityRecord record;
                        record.timestamp = *execTime;
                        record.type = ActivityType::ProgramExec;
                        record.description = exeName;
                        record.details = exePath;
                        record.source = L"Prefetch-" + pfFileName;

                        Append(record);
                        validTimeCount++;
                    }
                }
            } else if (version == 26 || version == 30 || version == 31) {
                // Windows 8.1/10/11: 8个执行时间，从偏移 0x80 开始
                if (dataSize >= 0x80 + 8 * sizeof(FILETIME)) {
                    FILETIME* executionTimes = (FILETIME*)&dataPtr[0x80];

                    for (int i = 0; i < 8; i++) {
                        if (executionTimes[i].dwLowDateTime != 0 || executionTimes[i].dwHighDateTime != 0) {
                            ActivityRecord record;
                            record.timestamp = executionTimes[i];
                            record.type = ActivityType::ProgramExec;
                            record.description = exeName;
                            record.details = exePath;
                            record.source = L"Prefetch-" + pfFileName;

                            Append(record);
                            validTimeCount++;
                        }
                    }
                }
            }

            return validTimeCount > 0;
        }

        void Collector::CollectPrefetchRecords() {
            BuildPrefetchVolumeMap();

            // Prefetch 目录
            wchar_t prefetchPath[MAX_PATH];
            GetWindowsDirectoryW(prefetchPath, MAX_PATH);
            wcscat_s(prefetchPath, L"\\Prefetch\\*.pf");

            // 枚举所有 .pf 文件
            WIN32_FIND_DATAW findData;
            HANDLE hFind = FindFirstFileW(prefetchPath, &findData);

            if (hFind == INVALID_HANDLE_VALUE) {
                Problem(GetLastError());
                return;
            }

            // 构建目录路径
            wchar_t dirPath[MAX_PATH];
            GetWindowsDirectoryW(dirPath, MAX_PATH);
            wcscat_s(dirPath, L"\\Prefetch\\");

            do {
                if (Stopped())
                    break;
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::wstring fullPath = std::wstring(dirPath) + findData.cFileName;
                    if (!ParsePrefetchFile(fullPath))
                        Problem(ERROR_INVALID_DATA);
                }
            } while (FindNextFileW(hFind, &findData));

            const DWORD findError = GetLastError();
            FindClose(hFind);
            if (!Stopped() && findError != ERROR_NO_MORE_FILES)
                Problem(findError);
        }

        std::wstring Collector::DecodeROT13(const std::wstring& encoded) {
            std::wstring decoded;
            for (wchar_t c : encoded) {
                if (c >= L'A' && c <= L'Z') {
                    decoded += (wchar_t)((c - L'A' + 13) % 26 + L'A');
                } else if (c >= L'a' && c <= L'z') {
                    decoded += (wchar_t)((c - L'a' + 13) % 26 + L'a');
                } else {
                    decoded += c;
                }
            }
            return decoded;
        }

        bool Collector::ParseUserAssistValue(const BYTE* data, DWORD dataSize, FILETIME& lastExecTime) {
            // UserAssist 数据结构：
            // Windows 7/8: 版本 3, 数据大小 72 字节 (0x48)
            // Windows 10/11: 版本 5, 数据大小 72 字节 (0x48)
            //
            // 结构（版本 5）：
            // 偏移 0x00: 版本号 (4字节) - 通常是 0x00000003 或 0x00000005
            // 偏移 0x04: 执行次数 (4字节)
            // 偏移 0x08: 焦点次数 (4字节)
            // 偏移 0x0C: 焦点时长 (4字节)
            // ...
            // 偏移 0x3C: 最后执行时间 (8字节 FILETIME)

            // 最小数据大小检查
            if (dataSize < 0x44) {
                return false;
            }

            // 读取最后执行时间（偏移0x3C）
            lastExecTime = *(FILETIME*)&data[0x3C];

            // 检查是否是有效时间（FILETIME 不能全为0）
            if (lastExecTime.dwLowDateTime == 0 && lastExecTime.dwHighDateTime == 0) {
                return false;
            }

            // 验证时间戳是否在合理范围内
            // FILETIME 是从 1601年1月1日开始的 100纳秒间隔数
            // 2000年1月1日 ≈ 0x01BF53EB256D4000
            // 2100年1月1日 ≈ 0x02E3B77E8B3E4000
            ULONGLONG fileTime = ((ULONGLONG)lastExecTime.dwHighDateTime << 32) | lastExecTime.dwLowDateTime;

            // 如果时间戳小于 2000年 或大于 2100年，认为无效
            if (fileTime < 0x01BF53EB256D4000ULL || fileTime > 0x02E3B77E8B3E4000ULL) {
                return false;
            }

            return true;
        }

        void Collector::CollectUserAssistRecords() {
            // UserAssist 注册表路径
            const wchar_t* userAssistPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";

            // 两个主要的 GUID
            const wchar_t* guids[] = {
                L"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", // 可执行文件
                L"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"  // 快捷方式
            };

            for (int g = 0; g < 2 && !Stopped(); g++) {
                // 打开 GUID 键
                std::wstring guidPath = std::wstring(userAssistPath) + L"\\" + guids[g] + L"\\Count";

                HKEY hKey;
                LONG openResult = RegOpenKeyExW(HKEY_CURRENT_USER, guidPath.c_str(), 0, KEY_READ, &hKey);
                if (openResult != ERROR_SUCCESS) {
                    Problem(openResult);
                    continue;
                }

                // 枚举所有值
                DWORD index = 0;
                std::wstring valueName;
                std::vector<BYTE> valueData;
                DWORD valueType = REG_NONE;

                while (!Stopped()) {
                    const LONG result =
                        detail::ReadUserAssistValue(hKey, index, valueName, valueData, valueType, context_);

                    if (result == ERROR_NO_MORE_ITEMS) {
                        break;
                    }

                    if (result != ERROR_SUCCESS) {
                        if (Stopped())
                            break;
                        Problem(result);
                        if (result != ERROR_MORE_DATA)
                            break;
                        index++;
                        continue;
                    }

                    // 解码 ROT13
                    std::wstring decodedName = DecodeROT13(valueName);

                    // 跳过特殊的计数器条目
                    if (decodedName == L"UEME_CTLSESSION" || decodedName == L"UEME_CTLCUACount:ctor") {
                        index++;
                        continue;
                    }

                    // 解析值数据
                    FILETIME lastExecTime;
                    if (valueType == REG_BINARY &&
                        ParseUserAssistValue(valueData.data(), static_cast<DWORD>(valueData.size()), lastExecTime)) {
                        // 提取程序名（从路径中）
                        std::wstring exeName = decodedName;
                        size_t lastSlash = decodedName.find_last_of(L"\\/");
                        if (lastSlash != std::wstring::npos) {
                            exeName = decodedName.substr(lastSlash + 1);
                        }

                        // 记录所有类型的条目（.exe、.lnk、UWP应用等）
                        ActivityRecord record;
                        record.timestamp = lastExecTime;
                        record.type = ActivityType::ProgramExec;
                        record.description = exeName;
                        record.details = decodedName;

                        // 来源：UserAssist-GUID前8位
                        std::wstring guidShort = guids[g];
                        if (guidShort.length() > 9) {
                            guidShort = guidShort.substr(1, 8); // 去掉 { 并取前8位
                        }
                        record.source = L"UserAssist-" + guidShort;

                        Append(record);
                    }

                    index++;
                }

                RegCloseKey(hKey);
            }
        }

        void Collector::CollectRecentDocsRecords() {
            // 获取 Recent 文件夹路径
            wchar_t recentPath[MAX_PATH];
            if (SHGetFolderPathW(NULL, CSIDL_RECENT, NULL, 0, recentPath) != S_OK) {
                return;
            }

            // 构建搜索路径
            std::wstring searchPath = std::wstring(recentPath) + L"\\*.lnk";

            // 枚举所有 .lnk 文件
            WIN32_FIND_DATAW findData;
            HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

            if (hFind == INVALID_HANDLE_VALUE) {
                Problem(GetLastError());
                return;
            }

            do {
                if (Stopped())
                    break;
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::wstring lnkFileName = findData.cFileName;
                    std::wstring fullPath = std::wstring(recentPath) + L"\\" + lnkFileName;

                    // 获取 .lnk 文件的修改时间
                    FILETIME lnkModifyTime = findData.ftLastWriteTime;

                    // 提取文件名（去掉 .lnk 扩展名）
                    std::wstring fileName = lnkFileName;
                    if (fileName.length() > 4 && fileName.substr(fileName.length() - 4) == L".lnk") {
                        fileName = fileName.substr(0, fileName.length() - 4);
                    }

                    // 尝试解析快捷方式获取目标路径
                    std::wstring targetPath;
                    IShellLinkW* psl = NULL;
                    IPersistFile* ppf = NULL;

                    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                                   (void**)&psl))) {
                        if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf))) {
                            if (SUCCEEDED(ppf->Load(fullPath.c_str(), STGM_READ))) {
                                wchar_t targetPathBuf[MAX_PATH];
                                if (SUCCEEDED(psl->GetPath(targetPathBuf, MAX_PATH, NULL, 0))) {
                                    targetPath = targetPathBuf;
                                }
                            }
                            ppf->Release();
                        }
                        psl->Release();
                    }

                    ActivityRecord record;
                    record.timestamp = lnkModifyTime; // 使用 .lnk 文件的修改时间
                    record.type = ActivityType::DocumentAccess;
                    record.description = fileName;
                    record.details = targetPath; // 如果解析失败，为空字符串
                    record.source = L"Recent";

                    Append(record);
                }
            } while (FindNextFileW(hFind, &findData));

            const DWORD findError = GetLastError();
            FindClose(hFind);
            if (!Stopped() && findError != ERROR_NO_MORE_FILES)
                Problem(findError);
        }

        void Collector::CollectSoftwareInstallRecords() {
            // 辅助函数：去掉字符串首尾引号和空格
            auto stripQuotes = [](const std::wstring& s) -> std::wstring {
                std::wstring r = s;
                // 去首尾空格
                size_t start = r.find_first_not_of(L" \t");
                if (start == std::wstring::npos)
                    return L"";
                r = r.substr(start);
                size_t end = r.find_last_not_of(L" \t");
                if (end != std::wstring::npos)
                    r = r.substr(0, end + 1);
                // 去首尾引号
                if (r.size() >= 2 && r.front() == L'"' && r.back() == L'"') {
                    r = r.substr(1, r.size() - 2);
                }
                return r;
            };

            // 辅助函数：从命令行字符串提取文件路径（去参数）
            auto extractPathFromCmd = [](const std::wstring& cmd) -> std::wstring {
                if (cmd.empty())
                    return L"";
                if (cmd[0] == L'"') {
                    // 带引号：取第一对引号内的内容
                    size_t end = cmd.find(L'"', 1);
                    if (end != std::wstring::npos)
                        return cmd.substr(1, end - 1);
                    return cmd.substr(1);
                } else {
                    // 不带引号：取第一个空格前的内容
                    size_t sp = cmd.find(L' ');
                    if (sp != std::wstring::npos)
                        return cmd.substr(0, sp);
                    return cmd;
                }
            };

            // 辅助函数：获取目录创建时间
            auto getDirCreateTime = [](const std::wstring& dir, FILETIME& ft) -> bool {
                if (dir.empty())
                    return false;
                WIN32_FILE_ATTRIBUTE_DATA attr;
                if (!GetFileAttributesExW(dir.c_str(), GetFileExInfoStandard, &attr))
                    return false;
                if (!(attr.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    return false;
                ft = attr.ftCreationTime;
                return true;
            };

            // 枚举的注册表位置：HKLM x2 + HKCU x1
            struct RegLocation {
                HKEY hRoot;
                const wchar_t* path;
            };

            RegLocation locations[] = {
                { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"              },
                { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
                { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"              },
            };

            for (const auto& loc : locations) {
                if (Stopped())
                    break;
                HKEY hKey;
                LONG opened = RegOpenKeyExW(loc.hRoot, loc.path, 0, KEY_READ, &hKey);
                if (opened != ERROR_SUCCESS) {
                    Problem(opened);
                    continue;
                }

                DWORD index = 0;
                wchar_t subKeyName[256];
                DWORD subKeyNameSize;

                while (!Stopped()) {
                    subKeyNameSize = _countof(subKeyName);
                    LONG enumerated = RegEnumKeyExW(hKey, index++, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL);
                    if (enumerated != ERROR_SUCCESS) {
                        if (enumerated != ERROR_NO_MORE_ITEMS)
                            Problem(enumerated);
                        break;
                    }

                    HKEY hSub;
                    LONG childOpened = RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hSub);
                    if (childOpened != ERROR_SUCCESS) {
                        Problem(childOpened);
                        continue;
                    }

                    // ① 检查 DisplayName，没有则跳过
                    wchar_t displayName[512] = { 0 };
                    DWORD sz = sizeof(displayName) - sizeof(wchar_t), type = 0;
                    if (RegQueryValueExW(hSub, L"DisplayName", NULL, &type, (BYTE*)displayName, &sz) != ERROR_SUCCESS ||
                        displayName[0] == L'\0') {
                        RegCloseKey(hSub);
                        continue;
                    }

                    // 读取 Publisher
                    wchar_t publisher[256] = { 0 };
                    sz = sizeof(publisher) - sizeof(wchar_t);
                    RegQueryValueExW(hSub, L"Publisher", NULL, &type, (BYTE*)publisher, &sz);

                    FILETIME ft = { 0 };
                    bool gotTime = false;

                    // ② 尝试 InstallLocation
                    wchar_t installLocation[1024] = { 0 };
                    sz = sizeof(installLocation) - sizeof(wchar_t);
                    if (RegQueryValueExW(hSub, L"InstallLocation", NULL, &type, (BYTE*)installLocation, &sz) ==
                        ERROR_SUCCESS) {
                        std::wstring dir = stripQuotes(installLocation);
                        if (!dir.empty()) {
                            gotTime = getDirCreateTime(dir, ft);
                        }
                    }

                    // ③ 如果 InstallLocation 无效，尝试 UninstallString
                    if (!gotTime) {
                        wchar_t uninstallStr[1024] = { 0 };
                        sz = sizeof(uninstallStr) - sizeof(wchar_t);
                        DWORD uninstallType = 0;
                        LONG ret =
                            RegQueryValueExW(hSub, L"UninstallString", NULL, &uninstallType, (BYTE*)uninstallStr, &sz);

                        if (ret == ERROR_SUCCESS && uninstallType == REG_SZ && uninstallStr[0] != L'\0') {
                            // REG_SZ：提取路径 → 取父目录
                            std::wstring filePath = extractPathFromCmd(uninstallStr);
                            if (!filePath.empty()) {
                                size_t slash = filePath.find_last_of(L"\\/");
                                if (slash != std::wstring::npos) {
                                    std::wstring dir = filePath.substr(0, slash);
                                    gotTime = getDirCreateTime(dir, ft);
                                }
                            }
                        } else if (ret == ERROR_SUCCESS && uninstallType == REG_EXPAND_SZ) {
                            // hex(2) 类型直接跳过
                        }
                    }

                    RegCloseKey(hSub);

                    if (!gotTime)
                        continue;

                    ActivityRecord record;
                    record.timestamp = ft;
                    record.type = ActivityType::SoftwareInstall;
                    record.description = displayName;
                    record.details = publisher[0] ? publisher : L"";
                    record.source = L"Uninstall";
                    Append(record);
                }

                RegCloseKey(hKey);
            }
        }
    }

    CollectionResult<Record> CollectActivities(const CollectionContext& context) {
        CollectionResult<Record> result;
        result.status = CollectionStatus::Complete;
        result.assessment = AssessmentState::NotApplicable;
        result.startedAt = UtcNow();
        const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        Collector collector(result, context);
        collector.Run();
        if (SUCCEEDED(com))
            CoUninitialize();
        if (context.ShouldStop())
            result.status = context.StopStatus();
        else if (result.collectionTruncated)
            result.status = CollectionStatus::Partial;
        result.collected = result.records.size();
        result.finishedAt = UtcNow();
        return result;
    }
}
