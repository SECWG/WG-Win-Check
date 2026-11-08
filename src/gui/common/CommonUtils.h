#pragma once
#include <windows.h>
#include <string>
#include "../../core/model/FileEvidence.h"

namespace CommonUtils {

    using SignatureState = wgwc::core::SignatureState;

    struct FileHashResult {
        std::wstring md5;
        std::wstring sha1;
        std::wstring sha256;
        bool success;
    };

    std::wstring ToLower(const std::wstring& str);

    std::wstring ExpandEnvStrings(const std::wstring& str);

    // 剪贴板

    // 复制失败会提示并返回 false；只有发布成功才转交内存所有权。
    bool CopyToClipboard(HWND hWnd, const std::wstring& text);
    void CopyListViewCell(HWND hWnd, HWND hListView, int row, int column);
    void CopyListViewRow(HWND hWnd, HWND hListView, int row);
    void CopyListViewAll(HWND hWnd, HWND hListView);

    // 文件

    // 在资源管理器中选中文件。
    void OpenFileLocation(HWND hWnd, const std::wstring& path, bool expandEnv = false, bool checkExists = true);

    void OpenFileProperties(HWND hWnd, const std::wstring& path, bool expandEnv = true);

    std::wstring FormatSignatureText(SignatureState state, const std::wstring& publisher);

    // 签名过滤匹配: 0=全部, 1=已签名, 2=未匹配, 3=未签名, 4=其他
    bool MatchSignatureFilter(SignatureState state, int filter);

    FileHashResult CalculateFileHashes(const std::wstring& path);

    // 使用已计算的哈希，不重新读取文件。
    void ShowFileHashDialog(HINSTANCE instance, HWND owner, const std::wstring& path, const FileHashResult& hashes);

    // 更新与情报查询

    struct UpdateCheckResult {
        bool hasUpdate = false;
        std::wstring latestVersion;
        bool success = false;
        std::wstring errorMsg;
    };

    // 同步网络请求，建议在工作线程调用。
    UpdateCheckResult CheckUpdate(const std::wstring& currentVersion);

    // 以下查询在浏览器中打开，不直接调用情报接口。
    void QueryVirusTotal(const std::wstring& sha256);

    void QueryThreatBook(const std::wstring& sha256);

}
