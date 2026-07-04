#include "common/TargetProcess.h"
#include "common/Win32Helpers.h"
#include "impl/LoadLibraryRemoteThread.h"

#include <windows.h>

#include <cstdio>
#include <cwchar>
#include <string>

namespace
{
constexpr const wchar_t* kDefaultTarget = L"app";
constexpr const wchar_t* kDefaultLoadMethod = L"LoadLibraryW";
constexpr const wchar_t* kDefaultLaunchMethod = L"CreateRemoteThread";

struct LabOptions
{
    const wchar_t* dllPath = nullptr;
    const wchar_t* target = kDefaultTarget;
    const wchar_t* loadMethod = kDefaultLoadMethod;
    const wchar_t* launchMethod = kDefaultLaunchMethod;
    bool showHelp = false;
};

void PrintUsage(const wchar_t* programName)
{
    wprintf(L"Usage:\n");
    wprintf(L"  %s --dll <path> [--target app|image.exe] [--load LoadLibraryW|LdrLoadDll] [--launch CreateRemoteThread|NtCreateThreadEx|QueueUserAPC]\n",
            programName);
    wprintf(L"  %s <path-to-dll>  (legacy shorthand)\n\n", programName);
    wprintf(L"Defaults:\n");
    wprintf(L"  --target app                 alias for TargetApp.exe\n");
    wprintf(L"  --load LoadLibraryW\n");
    wprintf(L"  --launch CreateRemoteThread\n");
}

bool IsOption(const wchar_t* value, const wchar_t* optionName)
{
    return _wcsicmp(value, optionName) == 0;
}

bool ReadOptionValue(int argc, wchar_t** argv, int& index, const wchar_t* optionName, const wchar_t** value)
{
    if (index + 1 >= argc)
    {
        wprintf(L"Missing value for %s.\n", optionName);
        return false;
    }

    *value = argv[++index];
    return true;
}

bool ParseOptions(int argc, wchar_t** argv, LabOptions& options)
{
    if (argc == 2 && argv[1][0] != L'-')
    {
        options.dllPath = argv[1];
        return true;
    }

    for (int i = 1; i < argc; ++i)
    {
        if (IsOption(argv[i], L"--help") || IsOption(argv[i], L"-h") || IsOption(argv[i], L"/?"))
        {
            options.showHelp = true;
            return true;
        }

        if (IsOption(argv[i], L"--dll"))
        {
            if (!ReadOptionValue(argc, argv, i, L"--dll", &options.dllPath))
            {
                return false;
            }
        }
        else if (IsOption(argv[i], L"--target"))
        {
            if (!ReadOptionValue(argc, argv, i, L"--target", &options.target))
            {
                return false;
            }
        }
        else if (IsOption(argv[i], L"--load"))
        {
            if (!ReadOptionValue(argc, argv, i, L"--load", &options.loadMethod))
            {
                return false;
            }
        }
        else if (IsOption(argv[i], L"--launch"))
        {
            if (!ReadOptionValue(argc, argv, i, L"--launch", &options.launchMethod))
            {
                return false;
            }
        }
        else
        {
            wprintf(L"Unknown argument: %s\n", argv[i]);
            return false;
        }
    }

    if (options.dllPath == nullptr)
    {
        wprintf(L"Missing required --dll <path>.\n");
        return false;
    }

    return true;
}

std::wstring NormalizeTargetImageName(const wchar_t* target)
{
    if (_wcsicmp(target, L"app") == 0 || _wcsicmp(target, L"targetapp") == 0)
    {
        return L"TargetApp.exe";
    }

    std::wstring imageName = target;
    if (imageName.find(L'.') == std::wstring::npos)
    {
        imageName += L".exe";
    }

    return imageName;
}

bool TryParseLaunchMethod(const wchar_t* value, lab::LaunchMethod& launchMethod)
{
    if (_wcsicmp(value, L"CreateRemoteThread") == 0)
    {
        launchMethod = lab::LaunchMethod::CreateRemoteThread;
        return true;
    }

    if (_wcsicmp(value, L"NtCreateThreadEx") == 0)
    {
        launchMethod = lab::LaunchMethod::NtCreateThreadEx;
        return true;
    }

    if (_wcsicmp(value, L"QueueUserAPC") == 0 || _wcsicmp(value, L"APC") == 0)
    {
        launchMethod = lab::LaunchMethod::QueueUserAPC;
        return true;
    }

    return false;
}

bool TryParseLoadMethod(const wchar_t* value, lab::LoadMethod& loadMethod)
{
    if (_wcsicmp(value, L"LoadLibraryW") == 0)
    {
        loadMethod = lab::LoadMethod::LoadLibraryW;
        return true;
    }

    if (_wcsicmp(value, L"LdrLoadDll") == 0)
    {
        loadMethod = lab::LoadMethod::LdrLoadDll;
        return true;
    }

    return false;
}

bool ValidateMethodSelection(const LabOptions& options,
                             lab::LoadMethod& loadMethod,
                             lab::LaunchMethod& launchMethod)
{
    if (!TryParseLoadMethod(options.loadMethod, loadMethod))
    {
        wprintf(L"Unsupported --load %s. Available now: LoadLibraryW, LdrLoadDll.\n",
                options.loadMethod);
        return false;
    }

    if (!TryParseLaunchMethod(options.launchMethod, launchMethod))
    {
        wprintf(L"Unsupported --launch %s. Available now: CreateRemoteThread, NtCreateThreadEx, QueueUserAPC.\n",
                options.launchMethod);
        return false;
    }

    return true;
}
}

int wmain(int argc, wchar_t** argv)
{
    LabOptions options;
    if (!ParseOptions(argc, argv, options))
    {
        PrintUsage(argv[0]);
        return 1;
    }

    if (options.showHelp)
    {
        PrintUsage(argv[0]);
        return 0;
    }

    lab::LoadMethod loadMethod = lab::LoadMethod::LoadLibraryW;
    lab::LaunchMethod launchMethod = lab::LaunchMethod::CreateRemoteThread;
    if (!ValidateMethodSelection(options, loadMethod, launchMethod))
    {
        return 1;
    }

    const std::wstring targetImageName = NormalizeTargetImageName(options.target);

    wchar_t dllPath[MAX_PATH] = {};
    if (!lab::GetFullFilePath(options.dllPath, dllPath, _countof(dllPath)))
    {
        return 1;
    }

    wprintf(L"Target: %s\n", targetImageName.c_str());
    wprintf(L"Load method: %s\n", options.loadMethod);
    wprintf(L"Launch method: %s\n", options.launchMethod);
    wprintf(L"DLL: %s\n", dllPath);

    DWORD targetPid = 0;
    if (!lab::FindExistingProcessByImageName(targetImageName.c_str(), targetPid))
    {
        return 1;
    }

    if (!lab::InjectDll(targetPid, dllPath, loadMethod, launchMethod))
    {
        return 1;
    }

    return 0;
}
