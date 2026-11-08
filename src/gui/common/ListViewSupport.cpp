#include "ListViewSupport.h"
#include "IInvestigator.h"
#include <commctrl.h>
#include <shellapi.h>

namespace wgwc::gui {
    void PopulateCachedListView(HWND listView, const InvestigationResult& result) {
        if (!listView)
            return;
        SendMessageW(listView, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(listView);
        for (std::size_t index = 0; index < result.items.size(); ++index) {
            const auto& item = result.items[index];
            LVITEMW entry{};
            entry.mask = LVIF_TEXT;
            entry.iItem = static_cast<int>(index);
            const auto& first = item.details.empty() ? item.name : item.details.front();
            entry.pszText = const_cast<wchar_t*>(first.c_str());
            const int row = ListView_InsertItem(listView, &entry);
            if (row < 0)
                continue;
            for (std::size_t column = 1; column < item.details.size(); ++column) {
                entry.iSubItem = static_cast<int>(column);
                entry.pszText = const_cast<wchar_t*>(item.details[column].c_str());
                SendMessageW(listView, LVM_SETITEMTEXTW, row, reinterpret_cast<LPARAM>(&entry));
            }
        }
        SendMessageW(listView, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(listView, nullptr, TRUE);
    }

    RowIconCache::~RowIconCache() {
        Clear();
    }

    static std::wstring NormalizeIconCacheKey(const std::wstring& path) {
        std::wstring key = path;
        if (!key.empty()) {
            CharLowerBuffW(&key[0], (DWORD)key.length());
        }
        return key;
    }

    void RowIconCache::Clear() {
        for (auto& entry : icons_) {
            if (entry.second) {
                DestroyIcon(entry.second);
            }
        }

        icons_.clear();

        if (defaultIcon_) {
            DestroyIcon(defaultIcon_);
            defaultIcon_ = NULL;
        }
    }

    HICON RowIconCache::GetDefault() {
        if (defaultIcon_) {
            return defaultIcon_;
        }

        SHFILEINFOW fileInfo = { 0 };
        DWORD_PTR result = SHGetFileInfoW(L"C:\\WG-Win-Check-Missing-File.exe", FILE_ATTRIBUTE_NORMAL, &fileInfo,
                                          sizeof(fileInfo), SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);

        if (result && fileInfo.hIcon) {
            defaultIcon_ = fileInfo.hIcon;
            return defaultIcon_;
        }

        HICON hSharedIcon = LoadIconW(NULL, IDI_APPLICATION);
        defaultIcon_ = hSharedIcon ? CopyIcon(hSharedIcon) : NULL;
        return defaultIcon_;
    }

    HICON RowIconCache::Get(const std::wstring& path) {
        if (path.empty() || path[0] == L'<' || path[0] == L'[') {
            return GetDefault();
        }

        if (path.rfind(L"COM:", 0) == 0 || path.rfind(L"com:", 0) == 0) {
            return GetDefault();
        }

        std::wstring key = NormalizeIconCacheKey(path);
        auto it = icons_.find(key);
        if (it != icons_.end()) {
            return it->second ? it->second : GetDefault();
        }

        HICON hIcon = NULL;
        DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            icons_.emplace(std::move(key), nullptr);
            return GetDefault();
        }

        SHFILEINFOW fileInfo = { 0 };
        DWORD_PTR result = SHGetFileInfoW(path.c_str(), 0, &fileInfo, sizeof(fileInfo), SHGFI_ICON | SHGFI_SMALLICON);

        if (result && fileInfo.hIcon) {
            hIcon = fileInfo.hIcon;
        }

        if (!hIcon) {
            icons_.emplace(std::move(key), nullptr);
            return GetDefault();
        }

        icons_[key] = hIcon;
        return hIcon;
    }

}
