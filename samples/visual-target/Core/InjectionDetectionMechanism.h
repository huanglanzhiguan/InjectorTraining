#pragma once

#include "DetectionResult.h"

#include <string_view>

namespace target
{
// Base interface for a target-side anti-injection observation.
//
// A mechanism is deliberately framed as an observation, not as an absolute
// verdict. Each row watches one Windows artifact that injection techniques may
// create: loader-visible modules, DLL load notifications, thread start
// addresses, executable private memory, and so on.
//
// The TargetApp UI owns the lifecycle:
// 1. Create each registered mechanism.
// 2. Let the process finish normal startup.
// 3. Call Reset() to capture a teaching baseline.
// 4. Poll Run() while the row is enabled.
//
// This makes the lab progressive: students can inject a DLL, watch which rows
// change, and then reason about why that specific technique left those
// artifacts.
class IInjectionDetectionMechanism
{
public:
    virtual ~IInjectionDetectionMechanism() = default;

    // Stable identifier for code, logs, and future saved results.
    // This should not change when the display name is reworded.
    virtual std::wstring_view Id() const noexcept = 0;

    // Short label shown in the UI row.
    virtual std::wstring_view Name() const noexcept = 0;

    // High-level grouping such as Loader, Thread, or Memory.
    virtual std::wstring_view Category() const noexcept = 0;

    // One-sentence explanation of what artifact this mechanism watches.
    virtual std::wstring_view Description() const noexcept = 0;

    // Perform one observation pass and return the current state.
    //
    // Run() should be side-effect-light. It may take snapshots or query process
    // state, but it should not "fix" or modify the process being inspected.
    virtual DetectionResult Run() = 0;

    // Re-capture the mechanism's baseline.
    //
    // Mechanisms that compare "current state" with "normal startup state" use
    // this to forget previous observations. Event-style mechanisms use it to
    // clear counters. Stateless mechanisms can keep the default no-op.
    virtual void Reset()
    {
    }
};
}
