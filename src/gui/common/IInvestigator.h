#pragma once
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include "RiskOverviewItem.h"
#include "../../core/system/FileService.h"

struct ColumnDef {
    const wchar_t* name;
    int width;
};

struct ContextMenuItem {
    UINT id;                 // 菜单项ID
    std::wstring text;       // 菜单文本
    bool requireConfirm;     // 是否需要二次确认
    std::wstring confirmMsg; // 确认消息
};

struct InvestigationItem {
    std::wstring name;
    std::wstring description;
    std::vector<std::wstring> details; // 各列数据
    SuspicionLevel suspicion = SuspicionLevel::None;
    std::wstring suspicionReason;
};

struct InvestigationResult {
    std::wstring moduleName;
    bool success = false;
    bool partial = false;
    bool stale = false;
    DWORD errorCode = 0;
    std::wstring errorMessage;
    std::vector<InvestigationItem> items;
    std::vector<std::vector<std::wstring>> rows; // 简化的行数据格式（用于网络模块等）
    DWORD totalCount = 0;
    DWORD suspiciousCount = 0;
};

namespace wgwc::gui {
    // 采集状态只影响展示反馈，不修改数据行、风险原因或风险等级。
    inline void ApplyCollectionOutcome(InvestigationResult& view, const core::CollectionOutcome& outcome, bool hasCache,
                                       const wchar_t* failedText, const wchar_t* partialText) {
        view.success =
            outcome.status == core::CollectionStatus::Complete || outcome.status == core::CollectionStatus::Partial;
        view.partial = outcome.status == core::CollectionStatus::Partial;
        view.stale = !view.success && hasCache;
        view.errorCode = 0;
        view.errorMessage.clear();
        for (const auto& issue : outcome.issues) {
            if (issue.affectsCompleteness && issue.nativeCode) {
                view.errorCode = issue.nativeCode;
                break;
            }
        }
        if (!view.success) {
            view.errorMessage = failedText;
            if (view.stale)
                view.errorMessage += L"，保留上次结果";
            if (!view.errorCode)
                view.errorCode = ERROR_READ_FAULT;
        } else if (view.partial) {
            view.errorMessage = partialText;
            if (!view.errorCode)
                view.errorCode = ERROR_PARTIAL_COPY;
        }
    }
}

inline const wchar_t* SuspicionLevelToString(SuspicionLevel level) {
    switch (level) {
    case SuspicionLevel::None:
        return L"正常";
    case SuspicionLevel::Low:
        return L"低";
    case SuspicionLevel::Medium:
        return L"中";
    case SuspicionLevel::High:
        return L"高";
    case SuspicionLevel::Critical:
        return L"严重";
    default:
        return L"未知";
    }
}

class IInvestigator {
public:
    virtual ~IInvestigator() = default;

    // resetFilter: true=重置过滤条件为默认值（首次加载/切换标签页），false=保持当前过滤条件（右键操作后刷新）
    virtual InvestigationResult Investigate(bool resetFilter = true) = 0;

    // 缓存

    virtual bool HasCache() const {
        return false;
    }

    virtual InvestigationResult GetCachedResult() const {
        return InvestigationResult();
    }

    virtual void ClearCache() {}

    // 按当前过滤条件重新构建缓存视图。
    virtual InvestigationResult RefreshFromCache() {
        return GetCachedResult();
    }

    virtual std::vector<RiskOverviewItem> GetRiskFindings() const {
        return {};
    }

    // 行图标支持（可选）。模块只提供图标来源路径，主窗口统一维护图标缓存。
    virtual bool HasRowIcons() const {
        return false;
    }

    virtual int GetRowIconColumn() const {
        return 0;
    }

    virtual std::wstring GetRowIconPath(int row, const InvestigationItem& item) const {
        (void)row;
        (void)item;
        return L"";
    }

    virtual std::wstring GetModuleName() const = 0;

    virtual const ColumnDef* GetColumns() const = 0;
    virtual int GetColumnCount() const = 0;

    // 返回 true 时使用 outColor 高亮当前单元格。
    virtual bool GetCellHighlight(int row, int col, const InvestigationResult& result, COLORREF& outColor) const {
        (void)row;
        (void)col;
        (void)result;
        (void)outColor;
        return false; // 默认不高亮
    }

    // 右键菜单

    // 共享主列表仅返回模块专属操作；复制、文件目录和文件属性由主窗口提供。
    // 使用独立列表的模块可自行提供完整菜单。
    virtual std::vector<ContextMenuItem> GetContextMenuItems(int row) const {
        (void)row;
        return {}; // 默认无菜单
    }

    // 返回 true 表示命令已处理。
    virtual bool HandleContextMenu(UINT menuId, int row) {
        (void)menuId;
        (void)row;
        return false;
    }

    // 返回当前行对应的规范文件路径，用于主窗口统一提供“文件目录/文件属性”。
    virtual std::wstring GetContextFilePath(int row) const {
        (void)row;
        return L"";
    }

    virtual void BeginContextMenu(int row) {
        (void)row;
    }

    virtual void EndContextMenu() {}

    // 处理行双击事件；已处理时返回 true。
    virtual bool HandleDoubleClick(int row) {
        (void)row;
        return false;
    }

    // 工具栏与布局

    virtual bool HasToolbar() const {
        return false;
    }

    // 自行管理列表等控件布局的模块返回 true。
    virtual bool HasCustomLayout() const {
        return false;
    }

    virtual int GetToolbarHeight() const {
        return 0;
    }

    virtual void CreateToolbar(HWND hParent, HINSTANCE hInst) {
        (void)hParent;
        (void)hInst;
    }

    virtual void DestroyToolbar() {}

    virtual void ShowToolbar(bool show) {
        (void)show;
    }

    virtual void ResizeToolbar(int x, int y, int width) {
        (void)x;
        (void)y;
        (void)width;
    }

    virtual bool HandleToolbarCommand(WORD id, WORD code) {
        (void)id;
        (void)code;
        return false;
    }

    virtual void OnTimer(UINT_PTR timerId) {
        (void)timerId;
    }

    // 返回 0 表示不使用定时器。
    virtual UINT_PTR GetTimerId() const {
        return 0;
    }

    virtual void SetMainWindow(HWND hWnd) {
        (void)hWnd;
    }

    virtual void SetListView(HWND hListView) {
        (void)hListView;
    }

protected:
    // 每次手动采集使用独立缓存；批量采集在后台任务中共享上下文。
    wgwc::core::CollectionContext MakeCollectionContext() const {
        wgwc::core::CollectionContext context;
        context.fileCache = std::make_shared<wgwc::core::files::EvidenceCache>();
        return context;
    }
};
