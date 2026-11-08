#include "../../core/system/Win32.h"
#include "DisplayFormat.h"
#include "../../core/system/FileService.h"
#include "../../core/modules/traces/TraceModule.h"

namespace wgwc::gui::presentation {
    std::wstring Signature(core::SignatureState state, const std::wstring& publisher) {
        // 签名展示只使用证书发布者，不使用文件版本资源中的公司名称。
        switch (state) {
        case core::SignatureState::Signed:
            return publisher.empty() ? L"(Verified)" : L"(Verified) " + publisher;
        case core::SignatureState::Unsigned:
            return L"(Unsigned)";
        case core::SignatureState::Mismatch:
            return L"(Invalid)";
        default:
            return L"";
        }
    }

    std::wstring FileSize(unsigned long long size) {
        wchar_t text[64]{};
        if (size < 1024)
            swprintf_s(text, L"%llu B", size);
        else if (size < 1024ULL * 1024)
            swprintf_s(text, L"%.1f KB", size / 1024.0);
        else if (size < 1024ULL * 1024 * 1024)
            swprintf_s(text, L"%.1f MB", size / (1024.0 * 1024));
        else
            swprintf_s(text, L"%.2f GB", size / (1024.0 * 1024 * 1024));
        return text;
    }

    std::wstring LocalTime(unsigned long long time) {
        return time ? core::files::LocalTimeText(time) : L"";
    }

    const wchar_t* ActivityName(core::traces::ActivityType type) {
        switch (type) {
        case core::traces::ActivityType::SystemBoot:
            return L"系统启动";
        case core::traces::ActivityType::SystemSleep:
            return L"系统睡眠";
        case core::traces::ActivityType::SystemWake:
            return L"系统唤醒";
        case core::traces::ActivityType::UserLogin:
            return L"用户登录";
        case core::traces::ActivityType::ProgramExec:
            return L"程序执行";
        case core::traces::ActivityType::DocumentAccess:
            return L"最近访问";
        case core::traces::ActivityType::SoftwareInstall:
            return L"软件安装";
        default:
            return L"未知";
        }
    }
}
