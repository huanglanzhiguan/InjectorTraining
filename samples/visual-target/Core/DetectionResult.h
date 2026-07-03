#pragma once

#include <string>
#include <utility>

namespace target
{
// A mechanism reports one of these states after each check.
//
// Keep the states intentionally small for the course UI:
// - Clean means the mechanism did not observe its artifact.
// - Detected means the mechanism saw the artifact it is designed to teach.
// - Suspicious means the artifact deserves attention, but is weaker or more
//   context-dependent than a direct loader/thread event.
// - Error means the mechanism could not complete the observation.
enum class DetectionState
{
    NotRun,
    Clean,
    Detected,
    Suspicious,
    Error
};

// Result object shown in the TargetApp row.
//
// The detail string should explain the exact observation, not just repeat the
// state. For example, "new module: Debug\TrainingDll.dll" is useful because it
// tells the student what changed and which Windows artifact produced the row.
struct DetectionResult
{
    DetectionState state = DetectionState::NotRun;
    std::wstring detail;

    static DetectionResult NotRun()
    {
        return { DetectionState::NotRun, L"not run" };
    }

    static DetectionResult Clean(std::wstring detail = L"clean")
    {
        return { DetectionState::Clean, std::move(detail) };
    }

    static DetectionResult Detected(std::wstring detail)
    {
        return { DetectionState::Detected, std::move(detail) };
    }

    static DetectionResult Suspicious(std::wstring detail)
    {
        return { DetectionState::Suspicious, std::move(detail) };
    }

    static DetectionResult Error(std::wstring detail)
    {
        return { DetectionState::Error, std::move(detail) };
    }
};

const wchar_t* ToDisplayText(DetectionState state) noexcept;
}
