#include "common/TargetProcess.h"
#include "common/Win32Helpers.h"
#include "impl/LoadLibraryRemoteThread.h"

#include <windows.h>

#include <cstdio>
#include <cwchar>
#include <cstdlib>
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
    DWORD apcThreadId = 0;
    DWORD hijackThreadId = 0;
    bool manualMapEraseHeaders = false;
    bool showHelp = false;
};

void PrintUsage(const wchar_t* programName)
{
    wprintf(L"Usage:\n");
    wprintf(L"  %s --dll <path> [--target app|image.exe] [--load LoadLibraryW|LdrLoadDll|LdrpLoadDll|LdrpLoadDllInternal|ManualMap] [--launch CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|ThreadHijack] [--apc-thread tid] [--hijack-thread tid] [--manualmap-erase-headers]\n",
            programName);
    wprintf(L"  %s <path-to-dll>  (legacy shorthand)\n\n", programName);
    wprintf(L"Defaults:\n");
    wprintf(L"  --target app                 alias for TargetApp.exe\n");
    wprintf(L"  --load LoadLibraryW\n");
    wprintf(L"  --launch CreateRemoteThread\n");
    wprintf(L"  --apc-thread 0               QueueUserAPC uses all target threads\n");
    wprintf(L"  --hijack-thread 0            ThreadHijack requires an explicit target thread\n");
    wprintf(L"  --manualmap-erase-headers    disabled unless explicitly requested\n");
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

bool TryParseThreadId(const wchar_t* value, DWORD& threadId)
{
    wchar_t* end = nullptr;
    const unsigned long parsed = wcstoul(value, &end, 10);
    if (value[0] == L'\0' || end == value || *end != L'\0' || parsed == 0)
    {
        return false;
    }

    threadId = static_cast<DWORD>(parsed);
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
        else if (IsOption(argv[i], L"--apc-thread"))
        {
            const wchar_t* value = nullptr;
            if (!ReadOptionValue(argc, argv, i, L"--apc-thread", &value))
            {
                return false;
            }

            if (!TryParseThreadId(value, options.apcThreadId))
            {
                wprintf(L"Invalid --apc-thread value: %s\n", value);
                return false;
            }
        }
        else if (IsOption(argv[i], L"--hijack-thread"))
        {
            const wchar_t* value = nullptr;
            if (!ReadOptionValue(argc, argv, i, L"--hijack-thread", &value))
            {
                return false;
            }

            if (!TryParseThreadId(value, options.hijackThreadId))
            {
                wprintf(L"Invalid --hijack-thread value: %s\n", value);
                return false;
            }
        }
        else if (IsOption(argv[i], L"--manualmap-erase-headers") ||
                 IsOption(argv[i], L"--manualmap-erase-peh"))
        {
            options.manualMapEraseHeaders = true;
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

    if (_wcsicmp(value, L"ThreadHijack") == 0 || _wcsicmp(value, L"Hijack") == 0)
    {
        launchMethod = lab::LaunchMethod::ThreadHijack;
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

    if (_wcsicmp(value, L"LdrpLoadDll") == 0)
    {
        loadMethod = lab::LoadMethod::LdrpLoadDll;
        return true;
    }

    if (_wcsicmp(value, L"LdrpLoadDllInternal") == 0)
    {
        loadMethod = lab::LoadMethod::LdrpLoadDllInternal;
        return true;
    }

    if (_wcsicmp(value, L"ManualMap") == 0 || _wcsicmp(value, L"ManualMapping") == 0)
    {
        loadMethod = lab::LoadMethod::ManualMap;
        return true;
    }

    return false;
}

bool ValidateMethodSelection(const LabOptions& options, lab::InjectorConfig& config)
{
    if (!TryParseLoadMethod(options.loadMethod, config.loadMethod))
    {
        wprintf(L"Unsupported --load %s. Available now: LoadLibraryW, LdrLoadDll, LdrpLoadDll, LdrpLoadDllInternal, ManualMap.\n",
                options.loadMethod);
        return false;
    }

    if (!TryParseLaunchMethod(options.launchMethod, config.launchMethod))
    {
        wprintf(L"Unsupported --launch %s. Available now: CreateRemoteThread, NtCreateThreadEx, QueueUserAPC, ThreadHijack.\n",
                options.launchMethod);
        return false;
    }

    if (options.apcThreadId != 0 && config.launchMethod != lab::LaunchMethod::QueueUserAPC)
    {
        wprintf(L"--apc-thread only applies to --launch QueueUserAPC.\n");
        return false;
    }

    if (options.hijackThreadId != 0 && config.launchMethod != lab::LaunchMethod::ThreadHijack)
    {
        wprintf(L"--hijack-thread only applies to --launch ThreadHijack.\n");
        return false;
    }

    if (config.launchMethod == lab::LaunchMethod::ThreadHijack && options.hijackThreadId == 0)
    {
        wprintf(L"--launch ThreadHijack requires --hijack-thread <tid>. Use the hijack demo worker TID shown in TargetApp.\n");
        return false;
    }

    if (config.loadMethod == lab::LoadMethod::ManualMap &&
        config.launchMethod != lab::LaunchMethod::CreateRemoteThread &&
        config.launchMethod != lab::LaunchMethod::NtCreateThreadEx)
    {
        wprintf(L"--load ManualMap currently supports --launch CreateRemoteThread or NtCreateThreadEx. "
                L"APC and thread-hijack completion need a different observation path because manual-mapped DLLs are not loader-visible.\n");
        return false;
    }

    if (options.manualMapEraseHeaders && config.loadMethod != lab::LoadMethod::ManualMap)
    {
        wprintf(L"--manualmap-erase-headers only applies to --load ManualMap.\n");
        return false;
    }

    config.queueUserApc.threadId = options.apcThreadId;
    config.threadHijack.threadId = options.hijackThreadId;
    config.manualMap.eraseHeaders = options.manualMapEraseHeaders;
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

    lab::InjectorConfig config;
    if (!ValidateMethodSelection(options, config))
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
    if (options.apcThreadId != 0)
    {
        wprintf(L"APC thread: %lu\n", options.apcThreadId);
    }
    if (options.hijackThreadId != 0)
    {
        wprintf(L"Hijack thread: %lu\n", options.hijackThreadId);
    }
    if (config.manualMap.eraseHeaders)
    {
        wprintf(L"ManualMap PE header erase: enabled\n");
    }
    wprintf(L"DLL: %s\n", dllPath);

    DWORD targetPid = 0;
    if (!lab::FindExistingProcessByImageName(targetImageName.c_str(), targetPid))
    {
        return 1;
    }

    if (!lab::InjectDll(targetPid, dllPath, config))
    {
        return 1;
    }

    return 0;
}
