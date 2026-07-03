#include "App/MainWindow.h"

#include <windows.h>

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int show_command)
{
    target::MainWindow main_window(instance);

    if (!main_window.Create(show_command))
    {
        MessageBoxW(nullptr, L"Unable to create TargetApp window.", L"InjectorTraining", MB_OK | MB_ICONERROR);
        return 1;
    }

    return main_window.RunMessageLoop();
}
