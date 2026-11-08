#pragma once
#include <windows.h>
#include <commctrl.h>
#include <algorithm>
#include <vector>
#include <map>
#include <string>

struct InvestigationResult;

namespace wgwc::gui {
    // 复制与导出共用文本读取，row 为 -1 时读取表头。
    inline bool ReadListViewText(HWND list, int row, int column, std::wstring& text, DWORD& error) {
        // 控件数据异常过长时明确失败，不能静默截断。
        constexpr size_t MaxBufferChars = 1024 * 1024;
        std::vector<wchar_t> buffer(256);
        for (;;) {
            std::fill(buffer.begin(), buffer.end(), L'\0');
            if (row < 0) {
                LVCOLUMNW item{};
                item.mask = LVCF_TEXT;
                item.pszText = buffer.data();
                item.cchTextMax = static_cast<int>(buffer.size());
                if (!SendMessageW(list, LVM_GETCOLUMNW, static_cast<WPARAM>(column), reinterpret_cast<LPARAM>(&item))) {
                    error = ERROR_INVALID_DATA;
                    return false;
                }
            } else {
                LVITEMW item{};
                item.iSubItem = column;
                item.pszText = buffer.data();
                item.cchTextMax = static_cast<int>(buffer.size());
                const LRESULT copied =
                    SendMessageW(list, LVM_GETITEMTEXTW, static_cast<WPARAM>(row), reinterpret_cast<LPARAM>(&item));
                if (copied < 0) {
                    error = ERROR_INVALID_DATA;
                    return false;
                }
            }
            size_t length = 0;
            while (length < buffer.size() && buffer[length] != L'\0')
                ++length;
            if (length < buffer.size() - 1) {
                text.assign(buffer.data(), length);
                return true;
            }
            if (buffer.size() >= MaxBufferChars) {
                error = ERROR_INSUFFICIENT_BUFFER;
                return false;
            }
            buffer.resize(buffer.size() * 2);
        }
    }

    // 只显示已构建的缓存行，不再解释模块字段或重新判定风险。
    void PopulateCachedListView(HWND listView, const InvestigationResult& result);

    // 图标句柄由缓存独占；缺失文件统一复用默认图标。
    class RowIconCache {
    public:
        RowIconCache() = default;
        ~RowIconCache();
        RowIconCache(const RowIconCache&) = delete;
        RowIconCache& operator=(const RowIconCache&) = delete;
        HICON Get(const std::wstring& path);
        void Clear();

    private:
        HICON GetDefault();
        // 空句柄记录本轮提取失败；刷新时统一清理，默认图标仍仅持有一份。
        std::map<std::wstring, HICON> icons_;
        HICON defaultIcon_ = nullptr;
    };
}
