#pragma once

#include "../Core/InjectionDetectionMechanism.h"

#include <Windows.h>

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace target
{
class MainWindow
{
public:
    explicit MainWindow(HINSTANCE instance);

    bool Create(int show_command);
    int RunMessageLoop();

private:
    struct ColumnLayout
    {
        int name_width = 0;
        int category_width = 0;
        int details_width = 0;
    };

    struct MechanismRow
    {
        std::unique_ptr<IInjectionDetectionMechanism> mechanism;
        DetectionResult result = DetectionResult::NotRun();
        std::wstring last_checked;

        HWND action_control = nullptr;
        HWND name_label = nullptr;
        HWND category_label = nullptr;
        HWND status_label = nullptr;
        HWND detail_label = nullptr;
        HWND last_checked_label = nullptr;
    };

    static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);

    LRESULT HandleMessage(UINT message, WPARAM wparam, LPARAM lparam);

    void CreateControls();
    void CreateHeaderControls();
    bool StartAlertableApcWorker();
    void StopAlertableApcWorker();
    void UpdateHintText();
    void LoadMechanisms();
    void CreateMechanismRow(size_t index);
    void LayoutControls(int width, int height);
    void LayoutHeader(int y, int width);
    void LayoutRow(size_t index, int y, int width);
    void UpdateVerticalScroll(int height);
    void SetFirstVisibleRow(int row_index);
    int VisibleRowCapacity(int height) const;
    int MaximumFirstVisibleRow(int height) const;
    void SetMechanismRowVisible(size_t index, bool visible);
    ColumnLayout ComputeColumnLayout(int width) const;
    int MeasureTextWidth(HFONT font, std::wstring_view text) const;
    void RefreshMechanismRow(size_t index);
    void RunLiveMechanisms();
    void RunMechanism(size_t index);
    void ResetBaselines(bool show_status);
    void ArmBaselineAfterWarmup();
    void SetStatusText(const std::wstring& text);
    void UpdateStatusFromResults();
    COLORREF TextColorForStatic(HWND control) const;
    void ApplyUIFont(HWND control);
    void ApplyHeaderFont(HWND control);
    bool IsRowChecked(size_t index) const;
    bool IsActionControlId(WORD control_id, size_t* index) const;

    HINSTANCE instance_ = nullptr;
    HWND window_ = nullptr;
    HWND hint_label_ = nullptr;
    HWND reset_button_ = nullptr;
    HWND header_action_label_ = nullptr;
    HWND header_name_label_ = nullptr;
    HWND header_category_label_ = nullptr;
    HWND header_status_label_ = nullptr;
    HWND header_details_label_ = nullptr;
    HWND header_last_checked_label_ = nullptr;
    HWND status_label_ = nullptr;
    HANDLE apc_worker_stop_event_ = nullptr;
    HANDLE apc_worker_thread_ = nullptr;
    DWORD apc_worker_thread_id_ = 0;
    HFONT ui_font_ = nullptr;
    HFONT header_font_ = nullptr;
    HFONT status_font_ = nullptr;
    HBRUSH window_brush_ = nullptr;
    bool is_running_ = false;
    bool baseline_armed_ = false;
    int first_visible_row_ = 0;
    int visible_row_capacity_ = 1;
    std::vector<MechanismRow> mechanisms_;
};
}
