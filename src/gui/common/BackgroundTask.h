#pragma once
#include <windows.h>
#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <utility>

namespace wgwc::gui {
    // 工作线程只持有独立状态；窗口关闭后可放弃接收，不等待系统调用返回。
    template <class Result> class BackgroundTask {
    public:
        struct State {
            std::atomic_bool cancelled{ false };
            std::atomic_bool done{ false };
            std::atomic_int progress{ 0 };

            void Publish(Result result) {
                std::lock_guard<std::mutex> lock(mutex);
                if (!cancelled.load())
                    ready.push_back(std::move(result));
            }

        private:
            friend class BackgroundTask;
            std::mutex mutex;
            std::deque<Result> ready;
        };

        using Work = void (*)(State&);
        using ThreadFactory = decltype(&CreateThread);

        BackgroundTask() = default;

        ~BackgroundTask() {
            Cancel();
        }

        BackgroundTask(const BackgroundTask&) = delete;
        BackgroundTask& operator=(const BackgroundTask&) = delete;

        bool Start(Work work, ThreadFactory create = &CreateThread) {
            if (state_) {
                SetLastError(ERROR_BUSY);
                return false;
            }
            auto state = std::make_shared<State>();
            auto input = std::make_unique<Input>();
            input->state = state;
            input->work = work;
            HANDLE thread = create(nullptr, 0, Execute, input.get(), 0, nullptr);
            if (!thread)
                return false;
            input.release();
            // 线程入口持有状态的所有权，不需要将内核句柄留给窗口。
            CloseHandle(thread);
            state_ = std::move(state);
            return true;
        }

        void Cancel() {
            if (state_)
                state_->cancelled.store(true);
            state_.reset();
        }

        bool Take(Result& result) {
            if (!state_)
                return false;
            std::lock_guard<std::mutex> lock(state_->mutex);
            if (state_->ready.empty())
                return false;
            result = std::move(state_->ready.front());
            state_->ready.pop_front();
            return true;
        }

        bool Active() const {
            return state_ != nullptr;
        }

        bool Done() const {
            return state_ && state_->done.load();
        }

        int Progress() const {
            return state_ ? state_->progress.load() : 0;
        }

    private:
        struct Input {
            std::shared_ptr<State> state;
            Work work = nullptr;
        };

        static DWORD WINAPI Execute(LPVOID pointer) {
            std::unique_ptr<Input> input(static_cast<Input*>(pointer));
            auto state = std::move(input->state);
            const auto work = input->work;
            input.reset();
            if (!state->cancelled.load() && work)
                work(*state);
            state->done.store(true);
            return 0;
        }

        std::shared_ptr<State> state_;
    };
}
