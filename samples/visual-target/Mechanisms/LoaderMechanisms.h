#pragma once

#include "../Core/InjectionDetectionMechanism.h"
#include "../Inspection/ProcessInspection.h"

#include <windows.h>

#include <set>
#include <string>
#include <vector>

namespace target
{
// Detects a new module in the normal loader-visible module list.
//
// What it teaches:
// Classic LoadLibrary-style injection asks the Windows loader to map a DLL.
// Once that succeeds, the DLL appears in normal module enumeration, PEB loader
// lists, debuggers, and many inspection tools.
//
// Expected result for the first lab:
// Clean before injection, detected after any DLL is loader-loaded into
// TargetApp, regardless of the DLL filename.
//
// Limitations:
// This is a baseline-diff signal, not proof of malicious injection. Real
// applications legitimately load DLLs after startup for plugins, graphics,
// input methods, accessibility, security tools, and delayed features. The row is
// a visualization of "the loader-visible module set changed."
class ModuleBaselineMechanism final : public IInjectionDetectionMechanism
{
public:
    ModuleBaselineMechanism();

    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    DetectionResult Run() override;
    void Reset() override;

private:
    // Capture the module paths considered normal for the current lab baseline.
    void CaptureBaseline();

    std::set<std::wstring> baseline_paths_;
};

// Observes DLL load events delivered by the Windows loader.
//
// What it teaches:
// Loader-based injection is not only visible after the fact in module lists; it
// also creates a live loader event while the DLL is being loaded. This mechanism
// uses LdrRegisterDllNotification so students can see that event directly from
// inside the target process.
//
// Expected result for the first lab:
// Clean before injection, detected when LoadLibraryW loads the injected DLL.
//
// Limitations:
// This only covers normal loader activity. Manual mapping can avoid this event
// because the Windows loader is not asked to load the final DLL image in the
// usual way. Also, legitimate delayed DLL loads produce the same kind of event,
// so real detection needs policy and context.
class DllNotificationMechanism final : public IInjectionDetectionMechanism
{
public:
    DllNotificationMechanism();
    ~DllNotificationMechanism() override;

    DllNotificationMechanism(const DllNotificationMechanism&) = delete;
    DllNotificationMechanism& operator=(const DllNotificationMechanism&) = delete;

    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    DetectionResult Run() override;
    void Reset() override;

private:
    // Static callback required by LdrRegisterDllNotification. The context
    // pointer is the owning DllNotificationMechanism instance.
    static void NTAPI NotificationCallback(ULONG reason, const void* data, void* context);

    // Store a small event summary for the UI. The callback can run while the UI
    // thread is polling, so access is guarded by lock_.
    void RecordLoad(std::wstring_view full_path);

    CRITICAL_SECTION lock_ = {};
    void* cookie_ = nullptr;
    bool available_ = false;
    DWORD load_count_ = 0;
    wchar_t last_path_[MAX_PATH] = {};
};

// Detects threads whose start address belongs to a module that was not present
// in the baseline module set.
//
// What it teaches:
// Injection often needs execution inside the target. In the current training
// DLL, DllMain quickly creates a worker thread to show a message box outside the
// loader lock. That worker thread starts inside the newly loaded DLL, which is a
// useful and visible thread artifact.
//
// Expected result for the first lab:
// Usually detected while the message-box worker thread is alive.
//
// Limitations:
// This observes thread start addresses, not every possible execution path.
// A remote LoadLibrary thread can be too short-lived to catch by polling, and
// techniques such as APC or thread hijacking may execute without a new thread
// whose original start address points at the injected module.
class ThreadStartModuleMechanism final : public IInjectionDetectionMechanism
{
public:
    ThreadStartModuleMechanism();

    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    DetectionResult Run() override;
    void Reset() override;

private:
    // Store module paths that were present before the injection experiment.
    void CaptureBaseline();

    std::set<std::wstring> baseline_module_paths_;
};

// Detects new executable MEM_PRIVATE regions.
//
// What it teaches:
// Loader-loaded DLLs are normally image-backed mappings, not executable private
// allocations. Manual mapping, shellcode stubs, trampolines, and some hook
// implementations often create executable private memory instead. This row is
// intended to become interesting when the course moves away from the normal
// Windows loader path.
//
// Expected result for the first lab:
// Clean for LoadLibraryW-based DLL injection, because the DLL is mapped as a
// normal image by the loader.
//
// Limitations:
// Some legitimate runtimes and platform features create executable private
// memory too, such as JIT engines or dynamically generated thunks. For that
// reason this mechanism baselines existing executable private regions and only
// reports new regions that appear after the lab baseline.
class PrivateExecutableMemoryMechanism final : public IInjectionDetectionMechanism
{
public:
    PrivateExecutableMemoryMechanism();

    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    DetectionResult Run() override;
    void Reset() override;

private:
    // Store executable private region bases that are normal at baseline time.
    void CaptureBaseline();

    std::set<std::uintptr_t> baseline_region_bases_;
};

// Detects private memory allocations that look like mapped PE images.
//
// What it teaches:
// Manual mapping avoids the normal Windows loader view, but the mapped DLL is
// still usually laid out like a PE image in process memory: an MZ header, a PE
// header, section headers, and executable section pages inside the same private
// allocation. This is a stronger and more specific signal than "some private
// executable memory exists."
//
// Expected result for the manual-map lab:
// Clean before injection, then detected after our simple manual mapper places a
// DLL image into MEM_PRIVATE memory.
//
// Limitations:
// This is deliberately generic and does not depend on TrainingDll.dll or any
// specific exported function. A more evasive mapper can erase PE headers, map
// sections into separate allocations, or avoid a normal PE layout after
// initialization. Legitimate protectors, packers, and some runtimes may also
// create PE-like private images, so production tools combine this with policy,
// provenance, signatures, and behavioral context.
class PrivatePeImageMechanism final : public IInjectionDetectionMechanism
{
public:
    PrivatePeImageMechanism();

    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    DetectionResult Run() override;
    void Reset() override;

private:
    // Store private PE-like allocation bases that are normal at baseline time.
    void CaptureBaseline();

    std::set<std::uintptr_t> baseline_allocation_bases_;
};

// Detects private executable allocations whose PE header story does not match
// the actual memory protections.
//
// What it teaches:
// Erasing PE headers breaks detectors that require MZ/PE at the allocation
// base. Fake PE headers break detectors that parse MZ/PE and trust the section
// table. A stronger detector compares two views: what the header claims and
// what VirtualQuery says is executable inside the same private allocation.
//
// Expected result for the PE-header countermeasure labs:
// Clean for the baseline manual-map layout, then suspicious after
// --manualmap-erase-headers or --manualmap-fake-headers.
//
// Limitations:
// This is still a heuristic. Shellcode, JIT code, injected stubs, packed code,
// and other private executable allocations may have no PE header at all. Real
// products combine this with provenance, module ownership, signing policy,
// execution telemetry, and allowlists.
class PrivateHeaderMismatchMechanism final : public IInjectionDetectionMechanism
{
public:
    PrivateHeaderMismatchMechanism();

    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    DetectionResult Run() override;
    void Reset() override;

private:
    // Store already-present mismatching allocations so legitimate runtime
    // thunks or JIT regions do not immediately light up the training UI.
    void CaptureBaseline();

    std::set<std::uintptr_t> baseline_allocation_bases_;
};
}
