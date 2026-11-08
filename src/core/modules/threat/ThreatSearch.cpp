#include "../../system/Win32.h"
#include "ThreatSearch.h"
#include <tlhelp32.h>
#include <algorithm>
#include <limits>

namespace wgwc::core::threat {
    namespace {
        void Issue(SearchResult& result, std::uint32_t pid, const wchar_t* code, DWORD native, const wchar_t* message) {
            // 统计值保持准确，诊断样本数量则设置上限。
            if (result.issues.size() < 16)
                result.issues.push_back({ L"threat", pid ? std::to_wstring(pid) : L"", code, native, message, true });
        }

        bool Readable(const MEMORY_BASIC_INFORMATION& mbi) {
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
                return false;
            switch (mbi.Protect & 0xff) {
            case PAGE_READONLY:
            case PAGE_READWRITE:
            case PAGE_WRITECOPY:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY:
                return true;
            default:
                return false;
            }
        }

        std::wstring ImagePath(HANDLE process) {
            std::vector<wchar_t> buffer(32768);
            DWORD size = static_cast<DWORD>(buffer.size());
            if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size))
                return {};
            return { buffer.data(), size };
        }

        bool ProcessGone(HANDLE process) {
            DWORD code = STILL_ACTIVE;
            return GetExitCodeProcess(process, &code) && code != STILL_ACTIVE;
        }

        struct ScanSession {
            CollectionContext& context;
            const MatchSink& sink;
            SearchResult& result;
            Match current;
            bool matched = false;
            std::vector<std::uint8_t> buffer;
            StreamMatcher matcher;
            ULONGLONG nextProgress;

            ScanSession(const SearchOptions& options, CollectionContext& ctx, const MatchSink& output,
                        SearchResult& outcome)
                : context(ctx), sink(output), result(outcome), buffer(ReadChunkBytes),
                  matcher(options, context,
                          [this](const BufferMatch& bufferMatch) {
                              Match record = current;
                              static_cast<BufferMatch&>(record) = bufferMatch;
                              if (!sink(record)) {
                                  result.outputStopped = true;
                                  return false;
                              }
                              ++result.collected;
                              if (!matched) {
                                  matched = true;
                                  ++result.matchedProcesses;
                              }
                              return true;
                          }),
                  nextProgress(GetTickCount64() + 2000) {}

            void Progress() {
                const auto now = GetTickCount64();
                if (now < nextProgress)
                    return;
                nextProgress = now + 2000;
                if (context.progress)
                    context.progress(L"threat", result.processesAttempted);
            }
        };

        bool ScanProcess(std::uint32_t pid, const std::wstring& enumeratedName, ScanSession& session) {
            auto& context = session.context;
            auto& result = session.result;
            auto& buffer = session.buffer;
            auto& matcher = session.matcher;
            if (context.ShouldStop())
                return false;
            ++result.processesAttempted;
            UniqueHandle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
            if (!process.valid()) {
                const DWORD error = GetLastError();
                ++result.processesFailed;
                Issue(result, pid, L"PROCESS_OPEN_FAILED", error, L"无法读取该进程，检索结果不完整。");
                return true;
            }
#ifndef _WIN64
            BOOL selfWow64 = FALSE, targetWow64 = FALSE;
            if (!IsWow64Process(GetCurrentProcess(), &selfWow64) || !IsWow64Process(process.get(), &targetWow64) ||
                (selfWow64 && !targetWow64)) {
                ++result.processesFailed;
                Issue(result, pid, L"PROCESS_ARCH_UNSUPPORTED", ERROR_NOT_SUPPORTED,
                      L"当前构建无法完整读取目标进程，请使用 x64 版本。");
                return true;
            }
#endif
            const auto path = ImagePath(process.get());
            auto name = enumeratedName;
            if (name.empty() && !path.empty()) {
                const auto slash = path.find_last_of(L"\\/");
                name = slash == std::wstring::npos ? path : path.substr(slash + 1);
            }
            if (name.empty())
                name = L"未知进程";
            session.current = {};
            session.current.pid = pid;
            session.current.processName = std::move(name);
            session.current.processPath = path;
            session.matched = false;
            SYSTEM_INFO system{};
            GetSystemInfo(&system);
            const auto maximum = reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
            const auto pageSize = static_cast<std::size_t>(system.dwPageSize ? system.dwPageSize : 4096);
            std::uintptr_t address = 0;
            bool readAny = false, incomplete = false, continueScan = true, abandonProcess = false;
            DWORD firstError = 0;
            auto markIncomplete = [&](DWORD error) {
                incomplete = true;
                if (!firstError)
                    firstError = error ? error : ERROR_PARTIAL_COPY;
            };
            while (address <= maximum && !abandonProcess && !context.ShouldStop()) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQueryEx(process.get(), reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) {
                    const DWORD error = GetLastError();
                    if (error != ERROR_INVALID_PARAMETER || ProcessGone(process.get()))
                        markIncomplete(error);
                    break;
                }
                const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                if (!mbi.RegionSize || base > (std::numeric_limits<std::uintptr_t>::max)() - mbi.RegionSize) {
                    markIncomplete(ERROR_INVALID_DATA);
                    break;
                }
                const auto end = base + mbi.RegionSize;
                if (end <= address) {
                    markIncomplete(ERROR_INVALID_DATA);
                    break;
                }
                if (Readable(mbi)) {
                    auto cursor = address;
                    while (cursor < end && !context.ShouldStop()) {
                        session.Progress();
                        if (context.ShouldStop())
                            break;
                        SIZE_T read = 0;
                        const auto wanted = (std::min)(ReadChunkBytes, static_cast<std::size_t>(end - cursor));
                        BOOL ok = ReadProcessMemory(process.get(), reinterpret_cast<const void*>(cursor), buffer.data(),
                                                    wanted, &read);
                        DWORD error = ok ? ERROR_SUCCESS : GetLastError();
                        // 大块内存读取失败时，内部仍可能包含可读页面；跳过前先重试当前页。
                        std::size_t requested = wanted;
                        if (!ok && !read && wanted > pageSize) {
                            requested = (std::min)(wanted, pageSize - static_cast<std::size_t>(cursor % pageSize));
                            ok = ReadProcessMemory(process.get(), reinterpret_cast<const void*>(cursor), buffer.data(),
                                                   requested, &read);
                            error = ok ? ERROR_SUCCESS : GetLastError();
                        }
                        if (read > requested) {
                            markIncomplete(ERROR_INVALID_DATA);
                            abandonProcess = true;
                            break;
                        }
                        if (read) {
                            readAny = true;
                            result.bytesRead += read;
                            if (!matcher.Feed(buffer.data(), read, cursor)) {
                                continueScan = false;
                                break;
                            }
                            cursor += read;
                        }
                        if (!read) {
                            // 已读取的部分前缀可以与下一次成功读取的数据连续拼接。
                            // 只有确实需要跳过字节时，才中断连续数据流。
                            markIncomplete(error);
                            if (!matcher.FinishSegment()) {
                                continueScan = false;
                                break;
                            }
                            if (ProcessGone(process.get())) {
                                markIncomplete(ERROR_PROCESS_ABORTED);
                                abandonProcess = true;
                                break;
                            }
                            // 重新查询失败地址，避免进程退出或大块映射已释放、受保护时，
                            // 仍对过期范围中的每一页重复调用失败的 ReadProcessMemory。
                            MEMORY_BASIC_INFORMATION current{};
                            if (!VirtualQueryEx(process.get(), reinterpret_cast<const void*>(cursor), &current,
                                                sizeof(current))) {
                                markIncomplete(GetLastError());
                                abandonProcess = true;
                                break;
                            }
                            const auto currentBase = reinterpret_cast<std::uintptr_t>(current.BaseAddress);
                            if (!current.RegionSize ||
                                currentBase > (std::numeric_limits<std::uintptr_t>::max)() - current.RegionSize ||
                                currentBase + current.RegionSize <= cursor) {
                                markIncomplete(ERROR_INVALID_DATA);
                                abandonProcess = true;
                                break;
                            }
                            if (!Readable(current)) {
                                cursor = (std::min)(end, currentBase + current.RegionSize);
                                continue;
                            }
                            const auto skip = (std::min)(static_cast<std::size_t>(end - cursor),
                                                         pageSize - static_cast<std::size_t>(cursor % pageSize));
                            cursor += skip;
                        }
                    }
                } else if (!matcher.FinishSegment()) {
                    continueScan = false;
                }
                if (!continueScan)
                    break;
                address = end;
            }
            if (continueScan && !context.ShouldStop())
                continueScan = matcher.FinishSegment();
            if (!context.ShouldStop() && ProcessGone(process.get()))
                markIncomplete(ERROR_PROCESS_ABORTED);
            if (readAny) {
                ++result.processesRead;
                if (incomplete)
                    ++result.processesPartial;
            } else if (!context.ShouldStop()) {
                ++result.processesFailed;
                if (!firstError)
                    firstError = ERROR_PARTIAL_COPY;
                incomplete = true;
            }
            if (incomplete)
                Issue(result, pid, L"PROCESS_MEMORY_INCOMPLETE", firstError,
                      L"部分内存无法读取或进程已退出，已有匹配仍会保留。");
            if (context.progress)
                context.progress(L"threat", result.processesAttempted);
            return continueScan && !result.outputStopped && !context.ShouldStop();
        }
    }

    SearchResult Search(const SearchOptions& options, CollectionContext& context, const MatchSink& sink) {
        SearchResult result;
        result.startedAt = UtcNow();
        result.assessment = AssessmentState::NotApplicable;
        bool enumerationIncomplete = false;
        if (!IsValidKeyword(options.keyword) || options.contextChars > MaxContextChars || !sink) {
            Issue(result, 0, L"INVALID_SEARCH_OPTIONS", ERROR_INVALID_PARAMETER, L"关键词或上下文长度无效。");
        } else if (context.ShouldStop()) {
            result.status = context.StopStatus();
        } else if (options.pid == GetCurrentProcessId()) {
            Issue(result, options.pid, L"SELF_SEARCH_UNSUPPORTED", ERROR_INVALID_PARAMETER,
                  L"不能检索当前检索进程自身。");
        } else {
            // 每次检索只构建一次关键字编码，并预分配读取缓冲区和滚动缓冲区。
            ScanSession session(options, context, sink, result);
            if (!session.matcher.Valid()) {
                Issue(result, 0, L"PATTERN_ENCODING_FAILED", ERROR_NO_UNICODE_TRANSLATION, L"无法生成检索模式。");
            } else if (options.pid) {
                ScanProcess(options.pid, {}, session);
            } else {
                UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
                if (!snapshot.valid()) {
                    Issue(result, 0, L"PROCESS_ENUM_FAILED", GetLastError(), L"无法枚举进程。");
                } else {
                    PROCESSENTRY32W entry{};
                    entry.dwSize = sizeof(entry);
                    BOOL available = Process32FirstW(snapshot.get(), &entry);
                    if (!available) {
                        const DWORD error = GetLastError();
                        enumerationIncomplete = error != ERROR_NO_MORE_FILES;
                        if (enumerationIncomplete)
                            Issue(result, 0, L"PROCESS_ENUM_FAILED", error, L"无法枚举进程。");
                    }
                    while (available && !context.ShouldStop()) {
                        session.Progress();
                        if (entry.th32ProcessID && entry.th32ProcessID != GetCurrentProcessId() &&
                            !ScanProcess(entry.th32ProcessID, entry.szExeFile, session))
                            break;
                        available = Process32NextW(snapshot.get(), &entry);
                        if (!available) {
                            const DWORD error = GetLastError();
                            if (error != ERROR_NO_MORE_FILES) {
                                enumerationIncomplete = true;
                                Issue(result, 0, L"PROCESS_ENUM_INCOMPLETE", error, L"进程枚举未完整结束。");
                            }
                        }
                    }
                }
            }
        }
        if (context.ShouldStop())
            result.status = context.StopStatus();
        else if (result.outputStopped || !result.processesRead)
            result.status = CollectionStatus::Failed;
        else if (result.processesFailed || result.processesPartial || enumerationIncomplete)
            result.status = CollectionStatus::Partial;
        else
            result.status = CollectionStatus::Complete;
        result.finishedAt = UtcNow();
        return result;
    }
}
