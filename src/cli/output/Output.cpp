#include "Output.h"
#include <algorithm>
#include <cwchar>

namespace wgwc::cli {
    namespace {
        thread_local const std::atomic<std::uint64_t>* diagnosticGeneration = nullptr;
        thread_local DWORD diagnosticError = ERROR_SUCCESS;
        const std::atomic<std::uint64_t> noDiagnosticCancellation{ 0 };

        bool WriteHandle(HANDLE handle, bool console, std::wstring_view text, DWORD& error) {
            if (text.empty())
                return true;
            if (console) {
                std::size_t offset = 0;
                while (offset < text.size()) {
                    const auto count =
                        static_cast<DWORD>((std::min)(text.size() - offset, static_cast<std::size_t>(16384)));
                    DWORD written = 0;
                    if (!WriteConsoleW(handle, text.data() + offset, count, &written, nullptr) || !written) {
                        error = GetLastError();
                        if (!error)
                            error = ERROR_WRITE_FAULT;
                        return false;
                    }
                    offset += written;
                }
                return true;
            }
            const int length = static_cast<int>(text.size());
            const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), length, nullptr, 0, nullptr, nullptr);
            if (size <= 0) {
                error = GetLastError();
                return false;
            }
            std::string bytes(static_cast<std::size_t>(size), '\0');
            if (!WideCharToMultiByte(CP_UTF8, 0, text.data(), length, bytes.data(), size, nullptr, nullptr)) {
                error = GetLastError();
                return false;
            }
            std::size_t offset = 0;
            while (offset < bytes.size()) {
                DWORD written = 0;
                if (!WriteFile(handle, bytes.data() + offset, static_cast<DWORD>(bytes.size() - offset), &written,
                               nullptr) ||
                    !written) {
                    error = GetLastError();
                    if (!error)
                        error = ERROR_WRITE_FAULT;
                    return false;
                }
                offset += written;
            }
            return true;
        }

        bool AppendUnicode(std::wstring& output, std::wstring_view value, std::size_t& index) {
            const wchar_t c = value[index];
            if (c >= 0xd800 && c <= 0xdbff) {
                if (index + 1 < value.size() && value[index + 1] >= 0xdc00 && value[index + 1] <= 0xdfff) {
                    output += c;
                    output += value[++index];
                    return true;
                }
            } else if (c < 0xdc00 || c > 0xdfff) {
                output += c;
                return true;
            }
            output += static_cast<wchar_t>(0xfffd);
            return false;
        }

        std::wstring SafeTerminalText(std::wstring_view value) {
            std::wstring text;
            for (wchar_t c : value) {
                if (c < 32 || (c >= 0x7f && c <= 0x9f) || (c >= 0x202a && c <= 0x202e) ||
                    (c >= 0x2066 && c <= 0x2069)) {
                    wchar_t escaped[8]{};
                    swprintf_s(escaped, L"\\u%04x", static_cast<unsigned>(c));
                    text += escaped;
                } else
                    text += c;
            }
            return text;
        }
    }

    OutputSink::~OutputSink() {
        StopCancellationWatcher();
        if (ownsHandle_ && handle_ != INVALID_HANDLE_VALUE)
            CloseHandle(handle_);
        if (!temporary_.empty())
            DeleteFileW(temporary_.c_str());
    }

    bool OutputSink::OpenStandard(DWORD standardHandle) {
        if (standardHandle != STD_OUTPUT_HANDLE && standardHandle != STD_ERROR_HANDLE) {
            error_ = ERROR_INVALID_PARAMETER;
            return false;
        }
        handle_ = GetStdHandle(standardHandle);
        if (!handle_ || handle_ == INVALID_HANDLE_VALUE) {
            error_ = ERROR_INVALID_HANDLE;
            return false;
        }
        DWORD mode = 0;
        console_ = GetConsoleMode(handle_, &mode) != FALSE;
        return true;
    }

    bool OutputSink::Open(const std::wstring& path, bool overwrite) {
        overwrite_ = overwrite;
        if (path.empty())
            return OpenStandard(STD_OUTPUT_HANDLE);
        const DWORD size = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
        if (!size) {
            error_ = GetLastError();
            return false;
        }
        std::vector<wchar_t> full(static_cast<std::size_t>(size) + 1);
        const DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
        if (!length || length >= full.size()) {
            error_ = ERROR_INVALID_NAME;
            return false;
        }
        target_.assign(full.data(), length);
        if (target_.rfind(L"\\\\?\\", 0) != 0) {
            if (target_.rfind(L"\\\\", 0) == 0)
                target_ = L"\\\\?\\UNC\\" + target_.substr(2);
            else
                target_ = L"\\\\?\\" + target_;
        }
        const DWORD attributes = GetFileAttributesW(target_.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (!overwrite || (attributes & FILE_ATTRIBUTE_DIRECTORY))) {
            error_ = ERROR_FILE_EXISTS;
            return false;
        }
        for (unsigned i = 0; i < 32; ++i) {
            const auto separator = target_.find_last_of(L"\\/");
            temporary_ = target_.substr(0, separator + 1) + L".wgwc-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                         std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(i) + L".tmp";
            handle_ =
                CreateFileW(temporary_.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle_ != INVALID_HANDLE_VALUE) {
                ownsHandle_ = true;
                return true;
            }
            const DWORD error = GetLastError();
            temporary_.clear();
            if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
                error_ = error;
                return false;
            }
        }
        error_ = ERROR_FILE_EXISTS;
        return false;
    }

    bool OutputSink::Write(std::wstring_view text) {
        if (memory_) {
            memory_->append(text);
            return true;
        }
        if (error_)
            return false;
        if (CancellationRequested()) {
            error_ = InterruptionError();
            return false;
        }
        buffer_.append(text);
        return buffer_.size() < 16384 || Flush();
    }

    bool OutputSink::Flush() {
        if (error_)
            return false;
        if (CancellationRequested()) {
            error_ = InterruptionError();
            return false;
        }
        writing_.store(true);
        const bool written = WriteHandle(handle_, console_, buffer_, error_);
        writing_.store(false);
        if (!written) {
            if (CancellationRequested())
                error_ = InterruptionError();
            return false;
        }
        buffer_.clear();
        return true;
    }

    bool OutputSink::Finish() {
        if (!Flush())
            return false;
        if (!ownsHandle_)
            return true;
        if (CancellationRequested()) {
            error_ = InterruptionError();
            return false;
        }
        writing_.store(true);
        const BOOL flushed = FlushFileBuffers(handle_);
        const DWORD flushError = flushed ? 0 : GetLastError();
        writing_.store(false);
        if (!flushed) {
            error_ = CancellationRequested() ? InterruptionError() : flushError;
            return false;
        }
        if (!CloseHandle(handle_)) {
            error_ = GetLastError();
            return false;
        }
        handle_ = INVALID_HANDLE_VALUE;
        ownsHandle_ = false;
        if (CancellationRequested()) {
            error_ = InterruptionError();
            return false;
        }
        const DWORD flags = MOVEFILE_WRITE_THROUGH | (overwrite_ ? MOVEFILE_REPLACE_EXISTING : 0);
        writing_.store(true);
        const BOOL published = MoveFileExW(temporary_.c_str(), target_.c_str(), flags);
        const DWORD publishError = published ? 0 : GetLastError();
        writing_.store(false);
        if (!published) {
            error_ = CancellationRequested() ? InterruptionError() : publishError;
            return false;
        }
        temporary_.clear();
        return true;
    }

    DWORD OutputSink::InterruptionError() const {
        if (cancellationGeneration_ && (cancellationGeneration_->load() != cancellationBaseline_ ||
                                        (cancellationGraceDeadline_ && GetTickCount64() >= cancellationGraceDeadline_)))
            return ERROR_CANCELLED;
        if (deadlineTick_ && GetTickCount64() >= deadlineTick_)
            return ERROR_TIMEOUT;
        return 0;
    }

    bool OutputSink::CancellationRequested() const {
        return InterruptionError() != 0;
    }

    DWORD WINAPI OutputSink::WatchCancellation(LPVOID parameter) {
        auto* self = static_cast<OutputSink*>(parameter);
        while (WaitForSingleObject(self->watcherStop_, 10) == WAIT_TIMEOUT) {
            if (self->writing_.load() && self->CancellationRequested())
                CancelSynchronousIo(self->writerThread_);
        }
        return 0;
    }

    void OutputSink::StopCancellationWatcher() {
        if (watcherStop_)
            SetEvent(watcherStop_);
        if (watcherThread_) {
            WaitForSingleObject(watcherThread_, INFINITE);
            CloseHandle(watcherThread_);
            watcherThread_ = nullptr;
        }
        if (writerThread_) {
            CloseHandle(writerThread_);
            writerThread_ = nullptr;
        }
        if (watcherStop_) {
            CloseHandle(watcherStop_);
            watcherStop_ = nullptr;
        }
    }

    bool OutputSink::ArmCancellation(const std::atomic<std::uint64_t>& generation, std::uint64_t baseline,
                                     bool cancelledReport, ULONGLONG deadlineTick) {
        deadlineTick_ = deadlineTick;
        cancellationGeneration_ = &generation;
        cancellationBaseline_ = baseline;
        cancellationGraceDeadline_ = cancelledReport ? GetTickCount64() + 1000 : 0;
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &writerThread_,
                             THREAD_TERMINATE, FALSE, 0)) {
            error_ = GetLastError();
            return false;
        }
        watcherStop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!watcherStop_) {
            error_ = GetLastError();
            StopCancellationWatcher();
            return false;
        }
        watcherThread_ = CreateThread(nullptr, 0, WatchCancellation, this, 0, nullptr);
        if (!watcherThread_) {
            error_ = GetLastError();
            StopCancellationWatcher();
            return false;
        }
        return true;
    }

    bool OutputSink::BeginCancellationFinalization() {
        if (error_ || !cancellationGeneration_)
            return !error_;
        const auto* generation = cancellationGeneration_;
        const auto baseline = generation->load();
        const auto deadline = deadlineTick_;
        StopCancellationWatcher();
        return ArmCancellation(*generation, baseline, true, deadline);
    }

    DiagnosticScope::DiagnosticScope(const std::atomic<std::uint64_t>& generation)
        : previousGeneration_(diagnosticGeneration), previousError_(diagnosticError) {
        diagnosticGeneration = &generation;
        diagnosticError = ERROR_SUCCESS;
    }

    DiagnosticScope::~DiagnosticScope() {
        diagnosticGeneration = previousGeneration_;
        diagnosticError = previousError_;
    }

    DWORD DiagnosticScope::Error() const {
        return diagnosticError;
    }

    void WriteDiagnostic(const std::wstring& text) {
        // 调用方可能单独停止读取标准错误，写入不能无限阻塞。
        // 首次写入失败后停止后续诊断输出，避免反复等待超时。
        if (diagnosticError)
            return;
        OutputSink output;
        const auto& generation = diagnosticGeneration ? *diagnosticGeneration : noDiagnosticCancellation;
        const auto baseline = generation.load();
        if (!output.OpenStandard(STD_ERROR_HANDLE) ||
            !output.ArmCancellation(generation, baseline, baseline != 0, GetTickCount64() + 1000) ||
            !output.Write(SafeTerminalText(text) + L"\r\n") || !output.Finish()) {
            diagnosticError = output.Error() ? output.Error() : ERROR_WRITE_FAULT;
        }
    }

    void JsonWriter::BeforeValue() {
        if (stack_.empty()) {
            if (root_)
                valid_ = false;
            root_ = true;
            return;
        }
        auto& top = stack_.back();
        if (top.array) {
            if (!top.first)
                sink_.Write(L",");
            top.first = false;
        } else {
            if (!top.expectsValue)
                valid_ = false;
            top.expectsValue = false;
        }
    }

    void JsonWriter::Quoted(std::wstring_view value) {
        sink_.Write(L"\"");
        std::wstring escaped;
        escaped.reserve(value.size());
        for (std::size_t i = 0; i < value.size(); ++i) {
            const wchar_t c = value[i];
            switch (c) {
            case L'"':
                escaped += L"\\\"";
                break;
            case L'\\':
                escaped += L"\\\\";
                break;
            case L'\b':
                escaped += L"\\b";
                break;
            case L'\f':
                escaped += L"\\f";
                break;
            case L'\n':
                escaped += L"\\n";
                break;
            case L'\r':
                escaped += L"\\r";
                break;
            case L'\t':
                escaped += L"\\t";
                break;
            default:
                if (c < 32) {
                    wchar_t code[8]{};
                    swprintf_s(code, L"\\u%04x", static_cast<unsigned>(c));
                    escaped += code;
                } else if (!AppendUnicode(escaped, value, i)) {
                    replacedUnicode_ = true;
                    sink_.NoteUnicodeReplacement();
                }
                break;
            }
        }
        sink_.Write(escaped);
        sink_.Write(L"\"");
    }

    void JsonWriter::Object() {
        BeforeValue();
        sink_.Write(L"{");
        stack_.push_back({ false });
    }

    void JsonWriter::Array() {
        BeforeValue();
        sink_.Write(L"[");
        stack_.push_back({ true });
    }

    void JsonWriter::EndObject() {
        if (stack_.empty() || stack_.back().array || stack_.back().expectsValue) {
            valid_ = false;
            return;
        }
        stack_.pop_back();
        sink_.Write(L"}");
    }

    void JsonWriter::EndArray() {
        if (stack_.empty() || !stack_.back().array) {
            valid_ = false;
            return;
        }
        stack_.pop_back();
        sink_.Write(L"]");
    }

    void JsonWriter::Key(std::wstring_view name) {
        if (stack_.empty() || stack_.back().array || stack_.back().expectsValue) {
            valid_ = false;
            return;
        }
        auto& top = stack_.back();
        if (!top.first)
            sink_.Write(L",");
        top.first = false;
        Quoted(name);
        sink_.Write(L":");
        top.expectsValue = true;
    }

    void JsonWriter::String(std::wstring_view value) {
        BeforeValue();
        Quoted(value);
    }

    void JsonWriter::Number(unsigned long long value) {
        BeforeValue();
        sink_.Write(std::to_wstring(value));
    }

    void JsonWriter::Bool(bool value) {
        BeforeValue();
        sink_.Write(value ? L"true" : L"false");
    }

    void JsonWriter::Null() {
        BeforeValue();
        sink_.Write(L"null");
    }

    void WriteCsvRow(OutputSink& sink, const std::vector<std::wstring>& values) {
        bool first = true;
        for (const auto& value : values) {
            if (!first)
                sink.Write(L",");
            first = false;
            sink.Write(L"\"");
            std::wstring escaped;
            for (std::size_t i = 0; i < value.size(); ++i) {
                if (value[i] == L'"')
                    escaped += L'"';
                if (!AppendUnicode(escaped, value, i))
                    sink.NoteUnicodeReplacement();
            }
            sink.Write(escaped);
            sink.Write(L"\"");
        }
        sink.Write(L"\r\n");
    }
}
