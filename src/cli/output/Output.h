#pragma once
#include "../../core/system/Win32.h"
#include <string>
#include <string_view>
#include <vector>
#include <atomic>
#include <cstdint>

namespace wgwc::cli {
    class OutputSink {
    public:
        OutputSink() = default;
        ~OutputSink();
        OutputSink(const OutputSink&) = delete;
        OutputSink& operator=(const OutputSink&) = delete;
        bool Open(const std::wstring& path, bool overwrite);
        bool OpenStandard(DWORD standardHandle);

        // 仅缓存单条记录中 CSV 嵌套字段的 JSON，不缓存整个采集快照。
        void OpenMemory(std::wstring& text) {
            memory_ = &text;
            text.clear();
        }

        bool Write(std::wstring_view text);
        bool Finish();
        bool ArmCancellation(const std::atomic<std::uint64_t>& generation, std::uint64_t baseline,
                             bool cancelledReport = false, ULONGLONG deadlineTick = 0);
        // 首次取消后，为 JSON 或文本的收尾输出设置时间上限。
        bool BeginCancellationFinalization();

        DWORD Error() const {
            return error_;
        }

        void NoteUnicodeReplacement() {
            unicodeReplaced_ = true;
        }

        bool UnicodeReplaced() const {
            return unicodeReplaced_;
        }

    private:
        bool Flush();
        bool CancellationRequested() const;
        DWORD InterruptionError() const;
        void StopCancellationWatcher();
        static DWORD WINAPI WatchCancellation(LPVOID parameter);
        HANDLE handle_ = INVALID_HANDLE_VALUE;
        bool ownsHandle_ = false;
        bool console_ = false;
        bool overwrite_ = false;
        DWORD error_ = 0;
        bool unicodeReplaced_ = false;
        std::wstring target_;
        std::wstring temporary_;
        std::wstring buffer_;
        std::wstring* memory_ = nullptr;
        const std::atomic<std::uint64_t>* cancellationGeneration_ = nullptr;
        std::uint64_t cancellationBaseline_ = 0;
        ULONGLONG cancellationGraceDeadline_ = 0;
        ULONGLONG deadlineTick_ = 0;
        HANDLE writerThread_ = nullptr;
        HANDLE watcherThread_ = nullptr;
        HANDLE watcherStop_ = nullptr;
        std::atomic_bool writing_{ false };
    };

    // 将诊断绑定到本次 CLI 调用，不改变业务数据的输出通道。
    class DiagnosticScope {
    public:
        explicit DiagnosticScope(const std::atomic<std::uint64_t>& generation);
        ~DiagnosticScope();
        DiagnosticScope(const DiagnosticScope&) = delete;
        DiagnosticScope& operator=(const DiagnosticScope&) = delete;
        DWORD Error() const;

    private:
        const std::atomic<std::uint64_t>* previousGeneration_;
        DWORD previousError_;
    };

    void WriteDiagnostic(const std::wstring& text);

    class JsonWriter {
    public:
        explicit JsonWriter(OutputSink& sink) : sink_(sink) {}

        void Object();
        void EndObject();
        void Array();
        void EndArray();
        void Key(std::wstring_view name);
        void String(std::wstring_view value);
        void Number(unsigned long long value);
        void Bool(bool value);
        void Null();

        bool Complete() const {
            return valid_ && root_ && stack_.empty();
        }

        bool ReplacedUnicode() const {
            return replacedUnicode_;
        }

    private:
        struct Frame {
            bool array;
            bool first = true;
            bool expectsValue = false;
        };

        void BeforeValue();
        void Quoted(std::wstring_view value);
        OutputSink& sink_;
        std::vector<Frame> stack_;
        bool valid_ = true;
        bool root_ = false;
        bool replacedUnicode_ = false;
    };

    void WriteCsvRow(OutputSink& sink, const std::vector<std::wstring>& values);
}
