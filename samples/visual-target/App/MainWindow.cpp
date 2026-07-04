#include "MainWindow.h"

#include "../Core/MechanismRegistry.h"

#include <CommCtrl.h>
#include <Uxtheme.h>

#include <algorithm>
#include <cstring>
#include <exception>
#include <string>

namespace
{
constexpr int kResetButtonId = 1002;
constexpr int kActionBaseId = 4000;
constexpr UINT_PTR kLiveTimerId = 2001;
constexpr UINT_PTR kBaselineWarmupTimerId = 2002;
constexpr UINT kLiveIntervalMs = 1000;
constexpr UINT kBaselineWarmupMs = 1500;

constexpr int kOuterMargin = 14;
constexpr int kHintHeight = 28;
constexpr int kButtonHeight = 30;
constexpr int kHeaderHeight = 24;
constexpr int kRowHeight = 36;
constexpr int kStatusHeight = 24;
constexpr int kMinWindowWidth = 1060;
constexpr int kMinWindowHeight = 360;
constexpr int kRowsStatusGap = 8;
constexpr int kMouseWheelRows = 3;

constexpr int kActionWidth = 92;
constexpr int kNameMinWidth = 170;
constexpr int kNameMaxWidth = 320;
constexpr int kCategoryMinWidth = 96;
constexpr int kCategoryMaxWidth = 220;
constexpr int kMeasuredColumnPadding = 22;
constexpr int kStatusWidth = 174;
constexpr int kLastCheckedWidth = 92;
constexpr int kMinDetailsWidth = 220;
constexpr int kColumnGap = 8;

constexpr COLORREF kDefaultTextColor = RGB(32, 32, 32);
constexpr COLORREF kCleanTextColor = RGB(18, 128, 75);
constexpr COLORREF kDetectedTextColor = RGB(190, 32, 38);
constexpr COLORREF kSuspiciousTextColor = RGB(178, 98, 0);

std::wstring Copy(std::wstring_view value)
{
    return std::wstring(value.data(), value.size());
}

HMENU ControlId(int id)
{
    return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id));
}

HFONT CreateUIFont(HWND owner, int point_size, int weight)
{
    HDC dc = GetDC(owner);
    const int dpi_y = GetDeviceCaps(dc, LOGPIXELSY);
    ReleaseDC(owner, dc);

    return CreateFontW(
        -MulDiv(point_size, dpi_y, 72),
        0,
        0,
        0,
        weight,
        FALSE,
        FALSE,
        FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Segoe UI");
}

std::wstring CurrentTimeText()
{
    SYSTEMTIME now = {};
    GetLocalTime(&now);

    wchar_t buffer[16] = {};
    swprintf_s(buffer, L"%02u:%02u:%02u", now.wHour, now.wMinute, now.wSecond);
    return buffer;
}

std::wstring ExceptionText(const std::exception& error)
{
    const char* what = error.what();
    return std::wstring(what, what + std::strlen(what));
}

std::wstring WindowText(HWND control)
{
    const int length = GetWindowTextLengthW(control);
    std::wstring text(static_cast<std::size_t>(length + 1), L'\0');
    GetWindowTextW(control, text.data(), length + 1);
    text.resize(static_cast<std::size_t>(length));
    return text;
}

void SetControlTextIfChanged(HWND control, const std::wstring& text)
{
    if (WindowText(control) != text)
    {
        SetWindowTextW(control, text.c_str());
    }
}

void SetControlTextIfChanged(HWND control, const wchar_t* text)
{
    SetControlTextIfChanged(control, std::wstring(text));
}

void SetControlFontIfChanged(HWND control, HFONT font)
{
    const auto current_font = reinterpret_cast<HFONT>(SendMessageW(control, WM_GETFONT, 0, 0));
    if (current_font != font)
    {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
}

HWND CreateStaticLabel(HWND parent, HINSTANCE instance, const wchar_t* text)
{
    return CreateWindowExW(
        0,
        L"STATIC",
        text,
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | SS_LEFT | SS_CENTERIMAGE | SS_NOPREFIX | SS_ENDELLIPSIS,
        0,
        0,
        0,
        0,
        parent,
        nullptr,
        instance,
        nullptr);
}

DWORD WINAPI AlertableApcWorkerProc(LPVOID parameter)
{
    HANDLE stop_event = static_cast<HANDLE>(parameter);

    for (;;)
    {
        const DWORD wait_result = WaitForSingleObjectEx(stop_event, 1000, TRUE);
        if (wait_result == WAIT_OBJECT_0)
        {
            return 0;
        }

        if (wait_result == WAIT_TIMEOUT || wait_result == WAIT_IO_COMPLETION)
        {
            continue;
        }

        return 1;
    }
}

DWORD WINAPI HijackDemoWorkerProc(LPVOID parameter)
{
    auto* stop_requested = static_cast<volatile LONG*>(parameter);
    volatile unsigned long long counter = 0;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

    while (InterlockedCompareExchange(stop_requested, 0, 0) == 0)
    {
        for (int i = 0; i < 100000; ++i)
        {
            ++counter;
            YieldProcessor();
        }
    }

    return static_cast<DWORD>(counter & 0xFF);
}

std::wstring RuntimeIdentityText(DWORD apc_worker_thread_id, DWORD hijack_worker_thread_id)
{
    std::wstring text = L"TargetApp PID " + std::to_wstring(GetCurrentProcessId());

    if (apc_worker_thread_id != 0)
    {
        text += L" | alertable APC worker TID " + std::to_wstring(apc_worker_thread_id);
    }
    else
    {
        text += L" | alertable APC worker unavailable";
    }

    if (hijack_worker_thread_id != 0)
    {
        text += L" | hijack demo worker TID " + std::to_wstring(hijack_worker_thread_id);
    }
    else
    {
        text += L" | hijack demo worker unavailable";
    }

    return text;
}
}

namespace target
{
MainWindow::MainWindow(HINSTANCE instance)
    : instance_(instance)
{
}

bool MainWindow::Create(int show_command)
{
    INITCOMMONCONTROLSEX controls = {};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&controls);

    const wchar_t* class_name = L"InjectorTrainingTargetAppWindow";

    WNDCLASSEXW window_class = {};
    window_class.cbSize = sizeof(window_class);
    window_class.hInstance = instance_;
    window_class.lpfnWndProc = &MainWindow::WindowProc;
    window_class.lpszClassName = class_name;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    RegisterClassExW(&window_class);

    window_ = CreateWindowExW(
        0,
        class_name,
        L"InjectorTraining TargetApp",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_VSCROLL,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        1100,
        520,
        nullptr,
        nullptr,
        instance_,
        this);

    if (window_ == nullptr)
    {
        return false;
    }

    ShowWindow(window_, show_command);
    UpdateWindow(window_);
    return true;
}

int MainWindow::RunMessageLoop()
{
    MSG message = {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return static_cast<int>(message.wParam);
}

LRESULT CALLBACK MainWindow::WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    MainWindow* self = nullptr;

    if (message == WM_NCCREATE)
    {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
        self = static_cast<MainWindow*>(create->lpCreateParams);
        self->window_ = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    else
    {
        self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    }

    if (self != nullptr)
    {
        return self->HandleMessage(message, wparam, lparam);
    }

    return DefWindowProcW(window, message, wparam, lparam);
}

LRESULT MainWindow::HandleMessage(UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message)
    {
    case WM_CREATE:
        CreateControls();
        StartAlertableApcWorker();
        StartHijackDemoWorker();
        UpdateHintText();
        LoadMechanisms();
        SetTimer(window_, kBaselineWarmupTimerId, kBaselineWarmupMs, nullptr);
        return 0;

    case WM_SIZE:
        LayoutControls(LOWORD(lparam), HIWORD(lparam));
        RedrawWindow(window_, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE);
        return 0;

    case WM_VSCROLL: {
        SCROLLINFO scroll = {};
        scroll.cbSize = sizeof(scroll);
        scroll.fMask = SIF_ALL;
        GetScrollInfo(window_, SB_VERT, &scroll);

        int next_row = first_visible_row_;
        switch (LOWORD(wparam))
        {
        case SB_LINEUP:
            next_row -= 1;
            break;
        case SB_LINEDOWN:
            next_row += 1;
            break;
        case SB_PAGEUP:
            next_row -= visible_row_capacity_;
            break;
        case SB_PAGEDOWN:
            next_row += visible_row_capacity_;
            break;
        case SB_THUMBPOSITION:
        case SB_THUMBTRACK:
            next_row = scroll.nTrackPos;
            break;
        case SB_TOP:
            next_row = 0;
            break;
        case SB_BOTTOM: {
            RECT client = {};
            GetClientRect(window_, &client);
            next_row = MaximumFirstVisibleRow(client.bottom - client.top);
            break;
        }
        default:
            return 0;
        }

        SetFirstVisibleRow(next_row);
        return 0;
    }

    case WM_MOUSEWHEEL: {
        const int wheel_delta = GET_WHEEL_DELTA_WPARAM(wparam);
        if (wheel_delta > 0)
        {
            SetFirstVisibleRow(first_visible_row_ - kMouseWheelRows);
        }
        else if (wheel_delta < 0)
        {
            SetFirstVisibleRow(first_visible_row_ + kMouseWheelRows);
        }
        return 0;
    }

    case WM_GETMINMAXINFO: {
        auto* min_max = reinterpret_cast<MINMAXINFO*>(lparam);
        min_max->ptMinTrackSize.x = kMinWindowWidth;
        min_max->ptMinTrackSize.y = kMinWindowHeight;
        return 0;
    }

    case WM_COMMAND: {
        const WORD control_id = LOWORD(wparam);
        size_t row_index = 0;

        if (control_id == kResetButtonId)
        {
            ResetBaselines(true);
            return 0;
        }

        if (IsActionControlId(control_id, &row_index))
        {
            if (IsRowChecked(row_index) && baseline_armed_)
            {
                RunMechanism(row_index);
            }
            else
            {
                mechanisms_[row_index].result = DetectionResult::NotRun();
                mechanisms_[row_index].last_checked.clear();
                RefreshMechanismRow(row_index);
                UpdateStatusFromResults();
            }

            return 0;
        }

        break;
    }

    case WM_TIMER:
        if (wparam == kBaselineWarmupTimerId)
        {
            ArmBaselineAfterWarmup();
            return 0;
        }

        if (wparam == kLiveTimerId)
        {
            RunLiveMechanisms();
            return 0;
        }
        break;

    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wparam);
        SetBkColor(dc, RGB(250, 250, 250));
        SetTextColor(dc, TextColorForStatic(reinterpret_cast<HWND>(lparam)));
        return reinterpret_cast<LRESULT>(window_brush_);
    }

    case WM_ERASEBKGND: {
        RECT client = {};
        GetClientRect(window_, &client);
        FillRect(reinterpret_cast<HDC>(wparam), &client, window_brush_);
        return 1;
    }

    case WM_DESTROY:
        StopAlertableApcWorker();
        StopHijackDemoWorker();
        KillTimer(window_, kBaselineWarmupTimerId);
        KillTimer(window_, kLiveTimerId);
        if (ui_font_ != nullptr)
        {
            DeleteObject(ui_font_);
            ui_font_ = nullptr;
        }
        if (header_font_ != nullptr)
        {
            DeleteObject(header_font_);
            header_font_ = nullptr;
        }
        if (status_font_ != nullptr)
        {
            DeleteObject(status_font_);
            status_font_ = nullptr;
        }
        if (window_brush_ != nullptr)
        {
            DeleteObject(window_brush_);
            window_brush_ = nullptr;
        }
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return DefWindowProcW(window_, message, wparam, lparam);
}

void MainWindow::CreateControls()
{
    window_brush_ = CreateSolidBrush(RGB(250, 250, 250));
    ui_font_ = CreateUIFont(window_, 9, FW_NORMAL);
    header_font_ = CreateUIFont(window_, 9, FW_SEMIBOLD);
    status_font_ = CreateUIFont(window_, 9, FW_BOLD);

    hint_label_ = CreateStaticLabel(
        window_,
        instance_,
        (L"Live rows poll after startup baseline. " +
         RuntimeIdentityText(apc_worker_thread_id_, hijack_worker_thread_id_))
            .c_str());
    ApplyUIFont(hint_label_);

    reset_button_ = CreateWindowExW(
        0,
        L"BUTTON",
        L"Reset baseline",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | BS_PUSHBUTTON,
        0,
        0,
        0,
        0,
        window_,
        ControlId(kResetButtonId),
        instance_,
        nullptr);
    ApplyUIFont(reset_button_);
    SetWindowTheme(reset_button_, L"Explorer", nullptr);

    CreateHeaderControls();

    status_label_ = CreateStaticLabel(window_, instance_, L"Preparing startup baseline...");
    ApplyUIFont(status_label_);
}

void MainWindow::CreateHeaderControls()
{
    header_action_label_ = CreateStaticLabel(window_, instance_, L"Action");
    header_name_label_ = CreateStaticLabel(window_, instance_, L"Mechanism");
    header_category_label_ = CreateStaticLabel(window_, instance_, L"Category");
    header_status_label_ = CreateStaticLabel(window_, instance_, L"Status");
    header_details_label_ = CreateStaticLabel(window_, instance_, L"Details");
    header_last_checked_label_ = CreateStaticLabel(window_, instance_, L"Last check");

    ApplyHeaderFont(header_action_label_);
    ApplyHeaderFont(header_name_label_);
    ApplyHeaderFont(header_category_label_);
    ApplyHeaderFont(header_status_label_);
    ApplyHeaderFont(header_details_label_);
    ApplyHeaderFont(header_last_checked_label_);
}

bool MainWindow::StartAlertableApcWorker()
{
    apc_worker_stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (apc_worker_stop_event_ == nullptr)
    {
        return false;
    }

    apc_worker_thread_ = CreateThread(nullptr,
                                      0,
                                      &AlertableApcWorkerProc,
                                      apc_worker_stop_event_,
                                      0,
                                      &apc_worker_thread_id_);
    if (apc_worker_thread_ == nullptr)
    {
        CloseHandle(apc_worker_stop_event_);
        apc_worker_stop_event_ = nullptr;
        apc_worker_thread_id_ = 0;
        return false;
    }

    return true;
}

void MainWindow::StopAlertableApcWorker()
{
    if (apc_worker_stop_event_ != nullptr)
    {
        SetEvent(apc_worker_stop_event_);
    }

    if (apc_worker_thread_ != nullptr)
    {
        WaitForSingleObject(apc_worker_thread_, 2000);
        CloseHandle(apc_worker_thread_);
        apc_worker_thread_ = nullptr;
    }

    if (apc_worker_stop_event_ != nullptr)
    {
        CloseHandle(apc_worker_stop_event_);
        apc_worker_stop_event_ = nullptr;
    }

    apc_worker_thread_id_ = 0;
}

bool MainWindow::StartHijackDemoWorker()
{
    InterlockedExchange(&hijack_worker_stop_requested_, 0);

    hijack_worker_thread_ = CreateThread(nullptr,
                                         0,
                                         &HijackDemoWorkerProc,
                                         const_cast<LONG*>(&hijack_worker_stop_requested_),
                                         0,
                                         &hijack_worker_thread_id_);
    if (hijack_worker_thread_ == nullptr)
    {
        hijack_worker_thread_id_ = 0;
        return false;
    }

    return true;
}

void MainWindow::StopHijackDemoWorker()
{
    InterlockedExchange(&hijack_worker_stop_requested_, 1);

    if (hijack_worker_thread_ != nullptr)
    {
        WaitForSingleObject(hijack_worker_thread_, 2000);
        CloseHandle(hijack_worker_thread_);
        hijack_worker_thread_ = nullptr;
    }

    hijack_worker_thread_id_ = 0;
}

void MainWindow::UpdateHintText()
{
    if (hint_label_ != nullptr)
    {
        SetControlTextIfChanged(
            hint_label_,
            L"Live rows poll after startup baseline. " +
                RuntimeIdentityText(apc_worker_thread_id_, hijack_worker_thread_id_));
    }
}

void MainWindow::LoadMechanisms()
{
    auto registered = MechanismRegistry::Instance().CreateMechanisms();
    mechanisms_.reserve(registered.size());

    for (auto& mechanism : registered)
    {
        MechanismRow row;
        row.mechanism = std::move(mechanism);
        mechanisms_.push_back(std::move(row));
        CreateMechanismRow(mechanisms_.size() - 1);
        RefreshMechanismRow(mechanisms_.size() - 1);
    }

    RECT client = {};
    GetClientRect(window_, &client);
    LayoutControls(client.right - client.left, client.bottom - client.top);
}

void MainWindow::CreateMechanismRow(size_t index)
{
    MechanismRow& row = mechanisms_.at(index);
    const int control_id = kActionBaseId + static_cast<int>(index);

    row.action_control = CreateWindowExW(
        0,
        L"BUTTON",
        L"Live",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | BS_AUTOCHECKBOX,
        0,
        0,
        0,
        0,
        window_,
        ControlId(control_id),
        instance_,
        nullptr);
    SendMessageW(row.action_control, BM_SETCHECK, BST_CHECKED, 0);
    ApplyUIFont(row.action_control);
    SetWindowTheme(row.action_control, L"Explorer", nullptr);

    row.name_label = CreateStaticLabel(window_, instance_, L"");
    row.category_label = CreateStaticLabel(window_, instance_, L"");
    row.status_label = CreateStaticLabel(window_, instance_, L"");
    row.detail_label = CreateStaticLabel(window_, instance_, L"");
    row.last_checked_label = CreateStaticLabel(window_, instance_, L"");

    ApplyUIFont(row.name_label);
    ApplyUIFont(row.category_label);
    ApplyUIFont(row.status_label);
    ApplyUIFont(row.detail_label);
    ApplyUIFont(row.last_checked_label);
}

void MainWindow::LayoutControls(int width, int height)
{
    const int content_width = width - (kOuterMargin * 2);
    const int top = kOuterMargin;
    const int hint_width = content_width > 150 ? content_width - 150 : content_width;
    UpdateVerticalScroll(height);

    MoveWindow(hint_label_, kOuterMargin, top, hint_width > 20 ? hint_width : 20, kHintHeight, TRUE);
    MoveWindow(reset_button_, width - kOuterMargin - 132, top, 132, kButtonHeight, TRUE);

    const int header_y = top + kHintHeight + 12;
    LayoutHeader(header_y, content_width);

    const int first_row_y = header_y + kHeaderHeight + 4;
    const int rows_bottom = height - kOuterMargin - kStatusHeight - kRowsStatusGap;
    for (size_t i = 0; i < mechanisms_.size(); ++i)
    {
        const int visible_index = static_cast<int>(i) - first_visible_row_;
        const int row_y = first_row_y + visible_index * kRowHeight;
        const bool visible = visible_index >= 0 && row_y + kRowHeight <= rows_bottom;

        SetMechanismRowVisible(i, visible);
        if (visible)
        {
            LayoutRow(i, row_y, content_width);
        }
    }

    const int footer_y = height - kOuterMargin - kStatusHeight;
    MoveWindow(status_label_, kOuterMargin, footer_y, content_width, kStatusHeight, TRUE);
}

void MainWindow::LayoutHeader(int y, int width)
{
    const ColumnLayout columns = ComputeColumnLayout(width);
    int x = kOuterMargin;

    MoveWindow(header_action_label_, x, y, kActionWidth, kHeaderHeight, TRUE);
    x += kActionWidth + kColumnGap;
    MoveWindow(header_name_label_, x, y, columns.name_width, kHeaderHeight, TRUE);
    x += columns.name_width + kColumnGap;
    MoveWindow(header_category_label_, x, y, columns.category_width, kHeaderHeight, TRUE);
    x += columns.category_width + kColumnGap;
    MoveWindow(header_status_label_, x, y, kStatusWidth, kHeaderHeight, TRUE);
    x += kStatusWidth + kColumnGap;
    MoveWindow(header_details_label_, x, y, columns.details_width, kHeaderHeight, TRUE);
    x += columns.details_width + kColumnGap;
    MoveWindow(header_last_checked_label_, x, y, kLastCheckedWidth, kHeaderHeight, TRUE);
}

void MainWindow::LayoutRow(size_t index, int y, int width)
{
    const ColumnLayout columns = ComputeColumnLayout(width);
    MechanismRow& row = mechanisms_.at(index);
    int x = kOuterMargin;

    MoveWindow(row.action_control, x, y + 4, kActionWidth, kButtonHeight, TRUE);
    x += kActionWidth + kColumnGap;
    MoveWindow(row.name_label, x, y, columns.name_width, kRowHeight, TRUE);
    x += columns.name_width + kColumnGap;
    MoveWindow(row.category_label, x, y, columns.category_width, kRowHeight, TRUE);
    x += columns.category_width + kColumnGap;
    MoveWindow(row.status_label, x, y, kStatusWidth, kRowHeight, TRUE);
    x += kStatusWidth + kColumnGap;
    MoveWindow(row.detail_label, x, y, columns.details_width, kRowHeight, TRUE);
    x += columns.details_width + kColumnGap;
    MoveWindow(row.last_checked_label, x, y, kLastCheckedWidth, kRowHeight, TRUE);
}

void MainWindow::UpdateVerticalScroll(int height)
{
    visible_row_capacity_ = VisibleRowCapacity(height);

    const int maximum_first_visible_row = MaximumFirstVisibleRow(height);
    first_visible_row_ = std::clamp(first_visible_row_, 0, maximum_first_visible_row);

    SCROLLINFO scroll = {};
    scroll.cbSize = sizeof(scroll);
    scroll.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    scroll.nMin = 0;
    scroll.nMax = mechanisms_.empty() ? 0 : static_cast<int>(mechanisms_.size()) - 1;
    scroll.nPage = static_cast<UINT>(visible_row_capacity_);
    scroll.nPos = first_visible_row_;
    SetScrollInfo(window_, SB_VERT, &scroll, TRUE);
    ShowScrollBar(window_, SB_VERT, mechanisms_.size() > static_cast<size_t>(visible_row_capacity_));
}

void MainWindow::SetFirstVisibleRow(int row_index)
{
    RECT client = {};
    GetClientRect(window_, &client);

    const int next_row = std::clamp(row_index, 0, MaximumFirstVisibleRow(client.bottom - client.top));

    if (next_row == first_visible_row_)
    {
        return;
    }

    first_visible_row_ = next_row;

    SCROLLINFO scroll = {};
    scroll.cbSize = sizeof(scroll);
    scroll.fMask = SIF_POS;
    scroll.nPos = first_visible_row_;
    SetScrollInfo(window_, SB_VERT, &scroll, TRUE);

    LayoutControls(client.right - client.left, client.bottom - client.top);
    RedrawWindow(window_, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE);
}

int MainWindow::VisibleRowCapacity(int height) const
{
    const int header_y = kOuterMargin + kHintHeight + 12;
    const int first_row_y = header_y + kHeaderHeight + 4;
    const int rows_bottom = height - kOuterMargin - kStatusHeight - kRowsStatusGap;
    const int rows_height = rows_bottom - first_row_y;
    return (std::max)(1, rows_height / kRowHeight);
}

int MainWindow::MaximumFirstVisibleRow(int height) const
{
    const int row_count = static_cast<int>(mechanisms_.size());
    return (std::max)(0, row_count - VisibleRowCapacity(height));
}

void MainWindow::SetMechanismRowVisible(size_t index, bool visible)
{
    MechanismRow& row = mechanisms_.at(index);
    const int show_command = visible ? SW_SHOWNA : SW_HIDE;

    ShowWindow(row.action_control, show_command);
    ShowWindow(row.name_label, show_command);
    ShowWindow(row.category_label, show_command);
    ShowWindow(row.status_label, show_command);
    ShowWindow(row.detail_label, show_command);
    ShowWindow(row.last_checked_label, show_command);
}

MainWindow::ColumnLayout MainWindow::ComputeColumnLayout(int width) const
{
    int measured_name_width = MeasureTextWidth(header_font_, L"Mechanism");
    int measured_category_width = MeasureTextWidth(header_font_, L"Category");

    for (const MechanismRow& row : mechanisms_)
    {
        measured_name_width = (std::max)(measured_name_width, MeasureTextWidth(ui_font_, row.mechanism->Name()));
        measured_category_width = (std::max)(measured_category_width, MeasureTextWidth(ui_font_, row.mechanism->Category()));
    }

    ColumnLayout columns;
    columns.name_width = std::clamp(
        measured_name_width + kMeasuredColumnPadding,
        kNameMinWidth,
        kNameMaxWidth);
    columns.category_width = std::clamp(
        measured_category_width + kMeasuredColumnPadding,
        kCategoryMinWidth,
        kCategoryMaxWidth);

    const int fixed_width = kActionWidth + kStatusWidth + kLastCheckedWidth + (kColumnGap * 5);
    const int available_for_variable_columns = width - fixed_width;
    const int maximum_name_and_category_width = available_for_variable_columns - kMinDetailsWidth;

    int excess_width = columns.name_width + columns.category_width - maximum_name_and_category_width;
    if (excess_width > 0)
    {
        const int name_reduction = (std::min)(columns.name_width - kNameMinWidth, excess_width);
        columns.name_width -= name_reduction;
        excess_width -= name_reduction;
    }

    if (excess_width > 0)
    {
        const int category_reduction = (std::min)(columns.category_width - kCategoryMinWidth, excess_width);
        columns.category_width -= category_reduction;
    }

    columns.details_width = available_for_variable_columns - columns.name_width - columns.category_width;
    columns.details_width = (std::max)(20, columns.details_width);
    return columns;
}

int MainWindow::MeasureTextWidth(HFONT font, std::wstring_view text) const
{
    if (window_ == nullptr || text.empty())
    {
        return 0;
    }

    HDC dc = GetDC(window_);
    HFONT previous_font = nullptr;
    if (font != nullptr)
    {
        previous_font = reinterpret_cast<HFONT>(SelectObject(dc, font));
    }

    SIZE size = {};
    GetTextExtentPoint32W(dc, text.data(), static_cast<int>(text.size()), &size);

    if (previous_font != nullptr)
    {
        SelectObject(dc, previous_font);
    }
    ReleaseDC(window_, dc);
    return size.cx;
}

void MainWindow::RefreshMechanismRow(size_t index)
{
    const MechanismRow& row = mechanisms_.at(index);

    SetControlTextIfChanged(row.name_label, Copy(row.mechanism->Name()));
    SetControlTextIfChanged(row.category_label, Copy(row.mechanism->Category()));
    SetControlTextIfChanged(row.status_label, ToDisplayText(row.result.state));
    SetControlTextIfChanged(row.detail_label, row.result.detail);
    SetControlTextIfChanged(row.last_checked_label, row.last_checked);

    const HFONT status_font =
        row.result.state == DetectionState::Detected || row.result.state == DetectionState::Suspicious
            ? status_font_
            : ui_font_;
    SetControlFontIfChanged(row.status_label, status_font);
}

void MainWindow::RunLiveMechanisms()
{
    if (is_running_ || !baseline_armed_)
    {
        return;
    }

    if (mechanisms_.empty())
    {
        SetStatusText(L"No mechanisms registered yet.");
        return;
    }

    is_running_ = true;
    bool any_live_enabled = false;

    for (size_t i = 0; i < mechanisms_.size(); ++i)
    {
        if (!IsRowChecked(i))
        {
            continue;
        }

        any_live_enabled = true;
        RunMechanism(i);
    }

    if (!any_live_enabled)
    {
        SetStatusText(L"No live rows enabled.");
    }
    else
    {
        UpdateStatusFromResults();
    }

    is_running_ = false;
}

void MainWindow::RunMechanism(size_t index)
{
    try
    {
        mechanisms_[index].result = mechanisms_[index].mechanism->Run();
    }
    catch (const std::exception& error)
    {
        mechanisms_[index].result = DetectionResult::Error(L"exception: " + ExceptionText(error));
    }
    catch (...)
    {
        mechanisms_[index].result = DetectionResult::Error(L"unknown exception");
    }

    mechanisms_[index].last_checked = CurrentTimeText();
    RefreshMechanismRow(index);
}

void MainWindow::ResetBaselines(bool show_status)
{
    for (size_t i = 0; i < mechanisms_.size(); ++i)
    {
        mechanisms_[i].mechanism->Reset();
        mechanisms_[i].result = DetectionResult::NotRun();
        mechanisms_[i].last_checked.clear();
        RefreshMechanismRow(i);
    }

    if (show_status)
    {
        SetStatusText(L"Baselines reset.");
    }
}

void MainWindow::ArmBaselineAfterWarmup()
{
    KillTimer(window_, kBaselineWarmupTimerId);
    ResetBaselines(false);
    baseline_armed_ = true;
    SetTimer(window_, kLiveTimerId, kLiveIntervalMs, nullptr);
    SetStatusText(L"Baseline armed.");
    RunLiveMechanisms();
}

void MainWindow::SetStatusText(const std::wstring& text)
{
    const HFONT font =
        text == L"injection artifact detected" || text == L"suspicious artifact observed"
            ? status_font_
            : ui_font_;
    SetControlTextIfChanged(status_label_, text);
    SetControlFontIfChanged(status_label_, font);
}

void MainWindow::UpdateStatusFromResults()
{
    if (mechanisms_.empty())
    {
        SetStatusText(L"No mechanisms registered yet.");
        return;
    }

    bool any_run = false;
    bool detected = false;
    bool suspicious = false;
    bool error = false;

    for (const MechanismRow& row : mechanisms_)
    {
        if (row.result.state == DetectionState::NotRun)
        {
            continue;
        }

        any_run = true;
        detected = detected || row.result.state == DetectionState::Detected;
        suspicious = suspicious || row.result.state == DetectionState::Suspicious;
        error = error || row.result.state == DetectionState::Error;
    }

    if (!any_run)
    {
        SetStatusText(L"No results yet.");
    }
    else if (detected)
    {
        SetStatusText(L"injection artifact detected");
    }
    else if (suspicious)
    {
        SetStatusText(L"suspicious artifact observed");
    }
    else if (error)
    {
        SetStatusText(L"Completed with errors.");
    }
    else
    {
        SetStatusText(L"clean");
    }
}

COLORREF MainWindow::TextColorForStatic(HWND control) const
{
    for (const MechanismRow& row : mechanisms_)
    {
        if (row.status_label != control)
        {
            continue;
        }

        if (row.result.state == DetectionState::Detected)
        {
            return kDetectedTextColor;
        }

        if (row.result.state == DetectionState::Suspicious)
        {
            return kSuspiciousTextColor;
        }

        if (row.result.state == DetectionState::Clean)
        {
            return kCleanTextColor;
        }

        return kDefaultTextColor;
    }

    if (control == status_label_)
    {
        const std::wstring text = WindowText(control);
        if (text == L"injection artifact detected")
        {
            return kDetectedTextColor;
        }

        if (text == L"suspicious artifact observed")
        {
            return kSuspiciousTextColor;
        }

        if (text == L"clean")
        {
            return kCleanTextColor;
        }
    }

    return kDefaultTextColor;
}

void MainWindow::ApplyUIFont(HWND control)
{
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(ui_font_), TRUE);
}

void MainWindow::ApplyHeaderFont(HWND control)
{
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(header_font_), TRUE);
}

bool MainWindow::IsRowChecked(size_t index) const
{
    return SendMessageW(mechanisms_.at(index).action_control, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

bool MainWindow::IsActionControlId(WORD control_id, size_t* index) const
{
    if (control_id < kActionBaseId)
    {
        return false;
    }

    const size_t candidate = static_cast<size_t>(control_id - kActionBaseId);
    if (candidate >= mechanisms_.size())
    {
        return false;
    }

    *index = candidate;
    return true;
}
}
