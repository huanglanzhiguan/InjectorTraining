# InjectorTraining

InjectorTraining is a Windows internals and reverse-engineering lab project about process injection. It explains the common injector families, why they work, where they break, and how defenders or reverse engineers can recognize their artifacts.

The project treats injection as a Windows process and loader lesson, not as a payload-delivery exercise. Every lab should run against a local target process owned by the student, with a benign training DLL or no-op test code.

## What This Lab Demonstrates

Process injection is a way to make one process influence code or data inside another process. Each technique can be understood by asking:

1. What object does the injector need to control?
2. Where does the injected code or DLL live in the target?
3. Which component starts execution: the Windows loader, a new thread, an existing thread, APC dispatch, a message hook, or a patched call site?
4. What does the target process record afterward: loader entries, private executable memory, thread state, handles, changed code bytes, or mapped sections?
5. Which artifacts are reliable enough to detect, and which are only weak clues?

By the end, students should be able to explain the difference between loading a DLL, mapping a PE image manually, creating execution in a remote process, and installing hooks after code is already present.

## Scope

This project is intentionally educational and defensive. It focuses on controlled local labs, reverse-engineering vocabulary, and detection thinking.

In scope:

- Windows process, thread, memory, handle, and loader concepts
- DLL loading and manual PE mapping at a conceptual level
- Common user-mode injection families and their observable artifacts
- Limitations caused by bitness, integrity level, sessions, mitigations, loader behavior, and process protection
- Detection ideas based on API telemetry, memory layout, thread state, loader state, and code integrity
- Case-study reading from ScyllaHide's injector and hook code

Out of scope:

- Payloads, persistence, credential access, or lateral movement
- Security-tool tampering or bypass instructions
- Injection into unrelated third-party processes
- Kernel drivers, exploit chains, PPL bypasses, or anti-EDR evasion
- General-purpose or stealth-focused injector frameworks

## Recommended Lab Setup

Use a disposable Windows VM or a local reverse-engineering lab machine.

Recommended tools:

- Visual Studio with C++ desktop development
- x64dbg
- Process Explorer or Process Hacker/System Informer
- WinDbg Preview for deeper thread and loader inspection
- Sysmon or ETW tracing for process, image-load, thread, and memory events
- A benign target application created for this lab
- A benign DLL that only logs, increments a counter, or calls `OutputDebugString`

Use separate x86 and x64 builds. Many injection bugs are architecture bugs disguised as logic bugs.

## Current Lab Contents

The repository currently contains the first complete lab:

- `InjectorTraining.sln`
- `lessons/01-classic-dll-injection.md`
- `samples/visual-target/*`
- `samples/classic-dll-injection/main.cpp`
- `samples/classic-dll-injection/common/*`
- `samples/classic-dll-injection/impl/*`
- `samples/classic-dll-injection/TrainingDll.cpp`

This first lab demonstrates classic DLL injection into `TargetApp.exe`, a lab-owned visual target process that the student starts before running the injector. The target app polls simple anti-injection observations so the classic loader-based injection becomes visible immediately. The DLL is benign and only displays a message box.

Build with Visual Studio or MSBuild:

```powershell
MSBuild InjectorTraining.sln /p:Configuration=Debug /p:Platform=x64 /m
```

Run the demo:

```powershell
.\x64\Debug\TargetApp.exe
.\x64\Debug\InjectorLab.exe --dll .\x64\Debug\TrainingDll.dll
```

`InjectorLab` defaults to the first lesson's most direct method:

```text
--target app
--load LoadLibraryW
--launch CreateRemoteThread
```

You can also run the same load method through the native thread launch path:

```powershell
.\x64\Debug\InjectorLab.exe --target app --load LoadLibraryW --launch NtCreateThreadEx --dll .\x64\Debug\TrainingDll.dll
```

That is a launch-method comparison, not a stealth upgrade. Both commands write a DLL path into `TargetApp.exe`, run `LoadLibraryW` inside the target, and should produce the same loader-visible target detections.

The APC launch lab uses the same staged DLL path and loader call, but asks an existing target thread to run it:

```powershell
.\x64\Debug\InjectorLab.exe --target app --load LoadLibraryW --launch QueueUserAPC --dll .\x64\Debug\TrainingDll.dll
```

`TargetApp.exe` includes one alertable APC worker thread so this beginner lab is deterministic. Against an arbitrary already-running process, `QueueUserAPC` may queue successfully and still never execute if no target thread enters an alertable wait.

For a controlled APC run, copy the `alertable APC worker TID` shown in the `TargetApp.exe` header and pass it explicitly:

```powershell
.\x64\Debug\InjectorLab.exe --target app --load LoadLibraryW --launch QueueUserAPC --apc-thread <tid> --dll .\x64\Debug\TrainingDll.dll
```

To compare the next load method, keep the launch method familiar and switch the loader entry point:

```powershell
.\x64\Debug\InjectorLab.exe --target app --load LdrLoadDll --launch CreateRemoteThread --dll .\x64\Debug\TrainingDll.dll
```

This path stages a small x64 adapter stub and a native `UNICODE_STRING` context in `TargetApp.exe`. The stub is needed because `LdrLoadDll` takes four parameters, while the launch methods in this beginner lab provide one pointer-sized argument.

## Mental Model

Most user-mode injectors are combinations of five steps:

1. Find a target process or create one suspended.
2. Obtain a handle with enough rights.
3. Place bytes, a path string, or a mapped image in the target address space.
4. Trigger execution inside the target.
5. Optionally clean up or install hooks.

The technique name usually describes step 4, not the whole operation. For example, "remote thread injection" still needs memory staging, and "manual mapping" still needs some execution trigger for `DllMain` or an exported entry point.

Important Windows objects and concepts:

- A process owns a virtual address space, handle table, PEB, loader lists, and one or more threads.
- A thread owns register context, a stack, TLS state, APC queues, and a start address.
- A DLL loaded by the Windows loader is normally visible in loader structures and image-load telemetry.
- A manually mapped PE may execute without a normal loader entry, but then the injector has to do loader work itself.
- Page protections matter. `PAGE_EXECUTE_READWRITE` is convenient for labs, but it is also noisy and often unnecessary.

## Injection Method Model

InjectorTraining separates two ideas that students often blur together:

- DLL injection method: how the DLL is loaded or mapped.
- Launch method: how code is made to run inside the target so the selected DLL method can happen.

The lab demonstrates five DLL injection methods:

- `LoadLibraryExW`
- `LdrLoadDll`
- `LdrpLoadDll`
- `LdrpLoadDllInternal`
- `ManualMapping`

The lab discusses these launch methods:

- `NtCreateThreadEx`
- Thread hijacking
- `SetWindowsHookEx`
- `QueueUserAPC`
- `KernelCallback`
- `FakeVEH`

Teach those as two axes. For example, `LdrLoadDll` plus `NtCreateThreadEx` means "use the native loader routine as the DLL loading method, and use a remote native thread as the launch method." `ManualMapping` plus thread hijacking means "perform loader work manually, and enter that mapped code through an existing thread."

The lab stays defensive and local: one owned target process, one benign DLL, and observable artifacts for each method.

## Lab Outline

### Module 1: Windows Process and DLL Foundations

Goal: make sure students can describe what injection changes.

Topics:

- Process handles and access rights
- Virtual address spaces and page protections
- Thread creation, suspension, APC dispatch, and context
- PEB, TEB, and loader lists
- DLL loading through `LoadLibraryExW`, `LdrLoadDll`, and lower loader routines
- PE sections, imports, relocations, TLS callbacks, and `DllMain`
- x86, x64, and WOW64 boundaries

Student questions:

- Why is a DLL path string not the same thing as a mapped DLL image?
- Why does a remote thread need an address meaningful in the target process?
- What changes when a DLL is loaded by the Windows loader?
- Why is `DllMain` a fragile place to do complex work?

### Module 2: Loader-Based DLL Injection Methods

These are four of the lab's five DLL injection methods. They all ask the Windows loader to load a DLL, but they enter the loader at different layers.

The four loader-based methods:

- `LoadLibraryExW`: documented Win32 loader API, normally reached through `kernel32` or `kernelbase`.
- `LdrLoadDll`: native `ntdll` loader export used below Win32 loader wrappers.
- `LdrpLoadDll`: private loader routine below the exported native API.
- `LdrpLoadDllInternal`: deeper private loader routine, even more version- and symbol-dependent.

Beginner lesson:

- `LoadLibraryExW` is the safest conceptual starting point.
- `LdrLoadDll` teaches that Win32 loader calls eventually reach native loader machinery.
- `Ldrp*` methods are internals lessons. They can be useful for research, but they are brittle because private loader routines change across Windows versions.

How it works:

- The injector opens the target process.
- It stages a DLL path and any call data the selected loader routine expects.
- It starts code in the target with one of the launch methods.
- The in-target code calls the selected loader entry point.
- The Windows loader maps the DLL, resolves imports, runs TLS callbacks, and calls `DllMain`.

Current implemented load commands:

```powershell
.\x64\Debug\InjectorLab.exe --target app --load LoadLibraryW --launch CreateRemoteThread --dll .\x64\Debug\TrainingDll.dll
.\x64\Debug\InjectorLab.exe --target app --load LdrLoadDll --launch CreateRemoteThread --dll .\x64\Debug\TrainingDll.dll
```

`LoadLibraryW` can be launched directly with the DLL path as the one argument. `LdrLoadDll` needs the remote adapter stub because it expects native call data such as `UNICODE_STRING`.

What to observe:

- A process handle with VM and thread-creation rights
- New writable memory containing the DLL path
- A launch method that reaches loader code
- A new module visible in the target's loader list
- Image-load telemetry for the DLL

Limitations:

- The DLL bitness must match the target process.
- The target must be accessible under the caller's integrity level, session, privileges, and process protection.
- The DLL path is visible and can fail because of filesystem, quoting, path, or search-order issues.
- Starting work from `DllMain` can deadlock or break under loader lock.
- Using a local loader address as if it always matches the target is not robust; a reliable injector must reason about the target's loaded modules.
- `Ldrp*` routines are private implementation details. They may require symbol resolution and can break when `ntdll` changes.
- Going lower than `LoadLibraryExW` may change user-mode API telemetry, but it does not remove the core loader artifacts.

Detection ideas:

- Correlate `OpenProcess`, remote allocation, remote write, and the selected launch method.
- Watch for execution entering `LoadLibraryExW`, `LdrLoadDll`, or private loader routines from unusual call sites.
- Watch image-load events for unusual DLL paths, user-writable directories, or unexpected modules in sensitive processes.
- Scan recent private writable memory for DLL path strings when investigating live systems.

ScyllaHide anchor:

- `PluginGeneric/Injector.cpp` contains `NormalDllInjection`, which demonstrates the classic shape: allocate path memory, write the path, run loader code remotely, then free the path buffer.

### Module 3: Launch Method - Native Remote Thread

`NtCreateThreadEx` is a launch method. It is the way to run a loader stub or manual-mapping stub inside the target, not the DLL loading method by itself.

Common APIs:

- `CreateRemoteThread`
- `CreateRemoteThreadEx`
- `NtCreateThreadEx`
- `RtlCreateUserThread`

How it works:

- The core idea is still "create a thread in another process."
- Native APIs expose additional flags and behavior, such as creating the thread suspended.
- Some implementations create a tiny remote stub first, then start the thread at that stub.

What to observe:

- A new thread object in the target
- Thread start address outside normal module entry points, or at a loader routine
- Possible `CREATE_SUSPENDED` behavior followed by resume
- New executable private memory if a stub is used

Limitations:

- API availability and behavior vary across Windows versions.
- Hiding a thread from a debugger does not make the thread invisible to the OS.
- Cross-architecture injection is hard. A 32-bit injector cannot directly create a normal 64-bit remote thread without special handling.
- Thread creation is noisy and often logged by security tooling.

Detection ideas:

- Alert on remote thread creation into unrelated processes.
- Compare thread start addresses against loaded image ranges.
- Investigate start addresses in `MEM_PRIVATE` executable regions.
- Correlate a thread start with earlier memory writes into the same process.

ScyllaHide anchor:

- `PluginGeneric/Injector.cpp` contains `CreateAndWaitForThread`, which chooses `NtCreateThreadEx` when available and falls back to `CreateRemoteThread` on older systems.

### Module 4: APC-Based Injection

APC injection uses an existing thread as the execution vehicle. In this lab, `QueueUserAPC` is treated as a launch method.

The current lab command is:

```powershell
.\x64\Debug\InjectorLab.exe --target app --load LoadLibraryW --launch QueueUserAPC --dll .\x64\Debug\TrainingDll.dll
```

To queue only to the known alertable worker thread, copy its TID from the `TargetApp.exe` header:

```powershell
.\x64\Debug\InjectorLab.exe --target app --load LoadLibraryW --launch QueueUserAPC --apc-thread <tid> --dll .\x64\Debug\TrainingDll.dll
```

How it works:

- The injector queues a user-mode APC to a target thread.
- The APC routine runs when the target thread enters an alertable wait.
- `TargetApp.exe` creates one lab-owned worker thread that waits with `WaitForSingleObjectEx(..., TRUE)` so students can observe a reliable dispatch case.
- Without `--apc-thread`, the injector queues to every thread in the target for the naive comparison.
- Early-bird APC variants queue work before the main thread begins normal execution, then resume the process.

What to observe:

- A queued APC against an existing thread
- Memory staged in the target before the APC fires
- Execution that appears under an existing thread rather than a new one
- Early execution in a just-created suspended process for early-bird variants

Limitations:

- Normal user-mode APCs require alertable execution.
- Many target threads never enter an alertable wait at the right time.
- The APC routine address must be valid in the target.
- Freeing the remote argument buffer is unsafe while any queued APC might still run later. Even in single-thread mode, `QueueUserAPC` does not provide a completion handle for the APC routine, so this lab intentionally leaves APC arguments allocated.
- Complex work can corrupt program assumptions if it runs at an unexpected time.
- Cross-bitness and WOW64 transitions add complexity.

Detection ideas:

- Correlate `QueueUserAPC` or native APC APIs with prior remote writes.
- Watch newly resumed suspended processes that immediately execute from unusual memory.
- Investigate existing threads whose instruction pointer moves into private executable pages.
- Prefer correlation over single API names, because APCs are legitimate in many applications.

### Module 5: Thread Hijacking and Context Manipulation

Thread hijacking avoids creating a new thread by redirecting an existing one. In this lab, it is another launch method.

How it works:

- The injector suspends one or more target threads.
- It reads a thread context.
- It stages code or a call frame in target memory.
- It changes the thread instruction pointer or stack so the thread runs the staged code.
- It later attempts to restore the original context.

What to observe:

- `SuspendThread` or native suspend calls
- `GetThreadContext` and `SetThreadContext`
- A thread resuming into memory that is not a normal loaded image
- Possible stack anomalies or broken call chains

Limitations:

- It is crash-prone. The chosen thread may hold locks or be in the middle of fragile code.
- Correct stack alignment, register preservation, and exception behavior are architecture-specific.
- Control-flow protections, CET, CFG, and process mitigations can interfere.
- Debugging the failure mode is often harder than writing the first proof of concept.

Detection ideas:

- Correlate thread suspension with remote memory writes and context changes.
- Inspect resumed instruction pointers that land in private executable memory.
- Look for sudden changes in call stacks or return addresses.
- Monitor high-risk targets for unusual suspend/resume storms.

### Module 6: Windows Message Hooks

Windows hook injection uses the GUI subsystem to load a DLL into GUI-capable processes. In this lab, `SetWindowsHookEx` is treated as a launch method because it can be the trigger that gets code running in the target context.

How it works:

- `SetWindowsHookEx` registers a hook procedure.
- For some hook types, the hook procedure must live in a DLL.
- Windows loads that DLL into processes whose threads receive relevant messages.

What to observe:

- Hook registration by type and target thread or desktop
- DLL loads into GUI processes that process messages
- Hook callbacks running inside the target context

Limitations:

- It applies to GUI/message-loop scenarios, not arbitrary services or console processes.
- Session, desktop, bitness, and integrity-level boundaries matter.
- x86 hooks need x86 DLLs; x64 hooks need x64 DLLs.
- Modern Windows integrity isolation and UIPI reduce cross-boundary reach.
- Hook callbacks can destabilize unrelated GUI apps if written poorly.

Detection ideas:

- Inventory global and thread-specific hooks.
- Watch DLL loads caused by hook registration.
- Flag unusual hook DLL paths or unexpected hook types.
- Correlate hook creator process, target desktop/session, and loaded module.

### Module 7: Loader-Assisted and Configuration-Based Loading

Some approaches make Windows load code at process start or under a specific subsystem behavior. These are important to recognize, but they sit close to persistence and should be taught from a defensive angle.

Examples:

- `AppInit_DLLs`
- Image File Execution Options debugger values
- AppCert DLLs
- DLL search-order hijacking and side-loading
- COM, shell extension, and plug-in loading surfaces
- Accessibility and input method extension points

How it works:

- The injector does not necessarily write memory into an already-running process.
- Instead, it changes how a future process starts or which DLL a legitimate loader path resolves.
- Execution usually happens through normal loader mechanisms.

What to observe:

- Registry or configuration changes
- DLL loads from unusual locations
- Parent-child process relationships that do not match normal use
- A process loading an unexpected dependency early in startup

Limitations:

- Many mechanisms require administrative rights or specific process characteristics.
- Some are disabled or constrained on modern Windows.
- They often leave durable configuration artifacts.
- Because they can become persistence, they should be handled carefully in lab design.

Detection ideas:

- Baseline and monitor high-risk registry locations.
- Compare loaded module paths against known-good install directories.
- Watch for unsigned or user-writable DLLs loaded by privileged or high-value processes.
- Investigate startup-time image loads that precede normal application behavior.

### Module 8: Section Mapping

Section mapping uses memory section objects to place shared or image-backed memory in another process.

How it works:

- The injector creates a section object.
- It maps a view into itself and a view into the target.
- It writes or prepares contents through one view and arranges execution through the target view.
- With `SEC_IMAGE`, Windows maps memory using image-section semantics.

What to observe:

- Section objects mapped into multiple processes
- Views with different protections, such as writable locally and executable remotely
- Execution from mapped memory that may not look like a normal loader-loaded DLL

Limitations:

- Mapping memory is only staging; an execution trigger is still required.
- Image sections and data sections have different behavior and detection artifacts.
- Incorrect page protections or relocation assumptions cause failures.
- Cross-process cleanup and lifetime can be subtle because section objects outlive individual views while handles remain.

Detection ideas:

- Correlate section creation/mapping with remote execution.
- Look for executable views mapped into unexpected processes.
- Compare VAD metadata against loader module lists.
- Investigate memory that is executable, shared, and not associated with expected image loads.

### Module 9: Manual Mapping and Reflective Loading

Manual mapping is the lab's fifth DLL injection method. It is where injection becomes a PE-loader lesson.

How it works:

- The injector reads a DLL from disk or memory.
- It allocates memory in the target for the full PE image.
- It copies headers and sections.
- It applies base relocations if the preferred base is unavailable.
- It resolves imports.
- It handles TLS callbacks and calls the entry point.
- It may skip normal loader registration.

What to observe:

- A PE-like image in private memory
- Executable memory not represented in normal loader lists
- Imports resolved without a normal `LoadLibrary` event for the injected DLL
- Optional wiped headers or missing PE headers
- A thread or hijacked execution path entering the manually mapped image

Limitations:

- A full Windows loader is difficult to reimplement correctly.
- Delay imports, API sets, forwarded exports, TLS, exception tables, SEH, resources, activation contexts, and C++ runtime behavior can break.
- Unloading is difficult because the loader does not own the image in the usual way.
- Wiping headers makes debugging and exception handling harder, not just detection harder.
- Modern mitigations such as CFG and CET can expose incorrect assumptions.

Detection ideas:

- Scan for executable `MEM_PRIVATE` regions with PE-like layout.
- Compare thread instruction pointers and call stacks against loader-known modules.
- Look for private executable memory with import-table-like pointer clusters.
- Detect code regions whose bytes resemble known DLLs but are not file-backed.
- Hunt for missing loader entries when executable memory contains image-like sections.

ScyllaHide anchor:

- `InjectorCLI/DynamicMapping.cpp` contains `MapModuleToProcess`, which copies sections, applies relocations, resolves imports, optionally wipes headers, and writes the image into the target.
- This is an excellent case study for what manual mapping must do and what it still does not fully replicate from the Windows loader.

Manual-mapping checklist:

- section mapping
- base relocation
- import resolution
- delayed imports
- SEH support
- TLS initialization
- security-cookie initialization
- loader-lock behavior
- image shifting
- data-directory cleanup

Use this as a checklist for what a serious manual mapper has to consider, not as a beginner implementation target.

### Module 10: Process Hollowing and Process Replacement

Process hollowing is not just DLL injection, but students will encounter it in the same family of ideas.

How it works:

- A process is created suspended.
- Its original image mapping is replaced or bypassed.
- A different image is mapped or written into its address space.
- The main thread context is changed to start the replacement image.
- The process is resumed.

What to observe:

- A newly created suspended process
- Image path, command line, and in-memory image mismatch
- Unusual writes or mappings near the image base
- Main thread context changes before first resume

Limitations:

- Correctly initializing a replacement process image is complex.
- PEB fields, loader state, command-line metadata, and VADs can disagree.
- Process mitigations and protected-process rules can block or expose the technique.
- It is noisy at process-creation time and often detectable by correlation.

Detection ideas:

- Compare on-disk image identity with in-memory image content.
- Watch for suspended process creation followed by memory replacement and context changes.
- Check whether the main module's VAD is image-backed by the expected file.
- Correlate parent process, command line, image path, and first executable region.

### Module 11: Hooking After Injection

Many injectors are only the delivery step. The post-injection goal may be API monitoring, anti-debug hiding, instrumentation, or behavior modification.

Common hook forms:

- Inline detours
- Import Address Table hooks
- Export Address Table hooks
- VTable or callback replacement
- VEH or exception-dispatch hooks
- Syscall stub hooks

How it works:

- Code inside the process modifies future control flow.
- Inline hooks overwrite the beginning of a function with a jump.
- Trampolines preserve original bytes and jump back after the overwritten prologue.
- IAT hooks change imported function pointers rather than code bytes.

What to observe:

- Code pages temporarily made writable
- Function prologues that no longer match the image on disk
- IAT entries pointing outside the expected provider DLL
- Trampoline memory near or inside private executable pages
- Repeated hooks across `ntdll`, `kernel32`, `kernelbase`, `user32`, or `win32u`

Limitations:

- Instruction boundaries must be decoded correctly.
- Relative addressing makes trampoline generation harder on x64.
- Other hooks may already be installed.
- CFG/CET and signed-code policies can interfere.
- Hooking native syscall paths across WOW64 boundaries is especially fragile.

Detection ideas:

- Compare executable pages to clean image mappings.
- Validate import tables and function pointers.
- Inspect prologue bytes of high-risk APIs.
- Look for recently changed page protections on code sections.
- Treat hooks as context: security products, debuggers, overlays, and profilers also hook.

ScyllaHide anchor:

- `InjectorCLI/RemoteHook.cpp` contains remote detour logic, trampoline creation, syscall-stub handling, and WOW64-specific complications.
- `InjectorCLI/ApplyHooking.cpp` shows how many individual anti-debug-related hooks are installed once ScyllaHide's hook DLL is mapped.

### Module 12: Other Variations to Recognize

This module is for classification and detection vocabulary. These techniques are useful to recognize in traces and write-ups, but they are not beginner lab requirements.

Module stomping or DLL hollowing:

- A legitimate DLL is loaded first, then parts of its image are overwritten or repurposed.
- It can make execution appear to come from a known module range.
- Detection depends on comparing in-memory image pages to the clean file mapping, watching copy-on-write executable pages, and validating entry points or exports.

Code cave injection:

- Existing unused space inside a module or allocated region is repurposed for new code.
- It avoids creating an obvious new large region, but it modifies memory that should be stable.
- Detection focuses on changed image-backed pages, suspicious jumps into padding, and prologue or control-flow changes.

Callback-based execution:

- Windows APIs that accept callback pointers can execute staged code when the target process invokes the callback path.
- In cross-process scenarios, code usually has to be present in the target already; the callback is the trigger, not the whole injection method.
- Detection should connect staged executable memory with unusual callback registration or dispatch.

CLR or managed runtime injection:

- The injector causes a native process to load the .NET runtime and execute managed code.
- This is common in tooling as well as malicious tradecraft.
- Detection can look for CLR modules, runtime initialization, and managed assemblies in processes that normally never host .NET.

Atom, window property, or clipboard staging:

- Data is staged through OS-managed storage instead of a direct obvious write path.
- An execution trigger is still required.
- Detection is usually correlation-heavy: unusual staging API use plus later execution from decoded or copied memory.

Process doppelganging, herpaderping, and related image identity tricks:

- These target the relationship between files, image sections, transactions, and what a process appears to be.
- They are process creation and image identity lessons more than beginner DLL-injection lessons.
- Detection compares file identity, section identity, command line, image load telemetry, and in-memory bytes over time.

Fiber-based execution:

- Fibers are user-mode scheduled execution contexts.
- They are more often relevant after code is already running inside a process.
- Detection is difficult from one signal alone; focus on how the code entered the process and where execution begins.

Kernel callback launch:

- User-mode callback paths can be used as an execution trigger in GUI-related contexts.
- This is version-sensitive and depends on details of Windows user/kernel callback dispatch.
- Detection should focus on unusual GUI callback state, unexpected execution during callback dispatch, and the earlier memory staging that made the callback useful.

Fake VEH launch:

- Vectored exception handling can be abused as a control-flow trigger by arranging exception dispatch to reach prepared code.
- The important lesson is exception routing, not the mechanics of a particular implementation.
- Detection can look for suspicious VEH registration or exception-driven execution that lands in private executable memory.

Kernel-assisted injection:

- A driver can write memory, map sections, or manipulate process/thread state from kernel mode.
- This project keeps kernel-assisted injection out of scope.
- Detection shifts toward driver trust, kernel telemetry, protected-process boundaries, and memory forensics.

## Technique Comparison Table

| Technique | Execution trigger | Loader-visible DLL? | Common strengths | Common limitations | Stronger detection angles |
| --- | --- | --- | --- | --- | --- |
| `LoadLibraryExW` DLL load | Any launch method | Yes | Documented, easiest loader lesson | Path visible, bitness constraints | Launch sequence plus image load |
| `LdrLoadDll` DLL load | Any launch method | Yes | Teaches native loader layer | Native structures and version details | Execution into `ntdll` loader plus image load |
| `LdrpLoadDll` / `LdrpLoadDllInternal` | Any launch method | Yes | Teaches private loader internals | Symbol-dependent, brittle across Windows versions | Private loader entry from unusual call site plus image load |
| `NtCreateThreadEx` launch | New native thread | Depends on DLL method | More control over thread flags | Still creates a thread, version quirks | Thread start address and prior memory writes |
| APC launch | Existing thread APC dispatch | Depends on DLL method | Avoids new thread | Requires alertable timing, unreliable | APC queue plus suspicious memory staging |
| Thread hijacking launch | Existing thread context | Depends on DLL method | Avoids new thread creation | Crash-prone, stack/register complexity | Suspend/context changes plus RIP in private memory |
| `SetWindowsHookEx` launch | GUI message hook | Usually yes | Uses documented GUI mechanism | GUI/session/integrity/bitness constraints | Hook registration plus unexpected DLL loads |
| `KernelCallback` / `FakeVEH` launch | Callback or exception dispatch | Depends on DLL method | Useful advanced control-flow lessons | Version-sensitive and fragile | Callback/exception route plus staged memory |
| Section mapping | Mapped section view | Depends | Flexible staging, shared views | Needs separate execution trigger | Executable mapped views and VAD anomalies |
| Manual mapping | Thread, APC, hijack, or callback | Usually no | Teaches PE loader internals | Hard to implement correctly | Executable private PE-like memory missing loader entries |
| Process hollowing | Main thread resume | Main image may disagree | Good process-creation case study | Complex and noisy | Image/path mismatch plus early memory replacement |
| Post-injection hooks | Patched call sites | Not itself | Teaches control-flow modification | Fragile with mitigations and other hooks | Prologue/IAT mismatch and page-protection changes |
| Module stomping | Existing or redirected execution | Looks like known module range | Hides inside loaded module address space | Modifies image pages, can break module behavior | In-memory image mismatch and dirty executable pages |
| CLR/runtime loading | Runtime initialization | Runtime modules are visible | Useful for managed tooling lessons | Runtime version and host assumptions | CLR loaded into unusual native processes |

## Detection Framework

Good detection is a timeline, not a single indicator.

### Handle Layer

Ask:

- Who opened the target process?
- Which access rights were requested?
- Was the target high-value, higher-integrity, cross-session, or unusual for the caller?

Signals:

- `PROCESS_VM_WRITE`
- `PROCESS_VM_OPERATION`
- `PROCESS_CREATE_THREAD`
- `PROCESS_SUSPEND_RESUME`
- `PROCESS_SET_INFORMATION`
- `THREAD_SET_CONTEXT`
- `THREAD_SUSPEND_RESUME`

### Memory Layer

Ask:

- Did new memory appear in the target?
- Is it writable, executable, image-backed, private, shared, or mapped?
- Does it contain a PE header, DLL path, shell stub, trampoline, or wiped-header image?

Signals:

- `MEM_PRIVATE` plus executable protection
- `PAGE_EXECUTE_READWRITE`
- Executable memory not covered by a loaded module
- PE-like regions missing from loader lists
- Code pages that differ from their image files

### Thread Layer

Ask:

- Was a thread created remotely?
- Did an existing thread get suspended and redirected?
- Is the instruction pointer inside expected image memory?
- Does the call stack make sense?

Signals:

- Remote thread start in loader routines or private memory
- `SetThreadContext` followed by resume
- APC dispatch into staged memory
- Threads hidden from debuggers but visible to the OS

### Loader Layer

Ask:

- Did a new module load?
- Is the DLL expected for that process?
- Is the module path trusted, signed, and in a normal install location?
- Are there executable regions that look like modules but are absent from loader lists?

Signals:

- Unexpected image-load events
- DLLs loaded from user-writable directories
- Loader list entries that do not match VADs
- VADs that look image-like but have no loader entry

### Code Integrity Layer

Ask:

- Do function prologues match the file-backed image?
- Do IAT entries point to the expected module exports?
- Are there trampolines or jumps into private memory?

Signals:

- Inline jumps at API entry points
- IAT pointers outside provider module ranges
- Code pages recently changed to writable
- Trampoline regions with copied prologue bytes

## Suggested Labs

### Lab 1: Observe a Normal DLL Load

Build a tiny DLL that only calls `OutputDebugString` in a safe, minimal way. Load it normally from a test program. Observe the module in Process Explorer, x64dbg, and loader lists.

Deliverable:

- Explain which artifacts came from the Windows loader.
- Identify the DLL base address, path, imports, and `DllMain` call timing.

### Lab 2: Injection Method Matrix

Build a comparison matrix for the five DLL injection methods: `LoadLibraryExW`, `LdrLoadDll`, `LdrpLoadDll`, `LdrpLoadDllInternal`, and `ManualMapping`.

Deliverable:

- Identify which methods use the Windows loader and which method implements loader responsibilities manually.
- For each method, list expected loader, memory, and thread artifacts.
- Explain why the two `Ldrp*` methods are private-internals lessons rather than beginner implementation targets.

### Lab 3: Classic Loader-Based Injection

In a local target process that the student owns, reproduce the concept of staging a DLL path and asking the target to call the loader. Keep the DLL benign.

Deliverable:

- Draw the timeline from process handle acquisition through image-load event.
- List the minimum observable artifacts a defender could correlate.
- Explain why x86 to x64 and x64 to x86 cases differ.

### Lab 4: Remote Thread Detection

Instrument the lab from the defender side. Record process access, memory allocation, memory write, thread creation, and image-load events.

Deliverable:

- Show why each individual event can be benign.
- Explain why the sequence is stronger than any one event.

### Lab 5: APC Timing

Use the controlled `TargetApp.exe` alertable APC worker first. Then compare that reliable case with a process or target mode that does not enter alertable waits.

Deliverable:

- Explain why APC injection can be unreliable.
- Identify the thread state that allowed the APC to dispatch.

### Lab 6: Thread Context Inspection

Do not build a full hijacker first. Instead, use a debugger to suspend a target thread, inspect registers, and reason about what would happen if the instruction pointer changed.

Deliverable:

- Identify the register and stack values that must be preserved.
- Explain why redirecting an arbitrary thread is dangerous.

### Lab 7: Manual Mapping Case Study

Read ScyllaHide's `MapModuleToProcess` and map each code block to a loader responsibility: headers, sections, relocations, imports, and remote write.

Deliverable:

- Explain what the function implements.
- Explain what the real Windows loader does that this simplified mapper does not fully cover.
- List memory artifacts that would distinguish this from a normal `LoadLibrary` load.

### Lab 8: Hook Detection

Compare a clean process with one where a training hook is installed inside the same process. Inspect function prologues, IAT entries, page protections, and trampoline memory.

Deliverable:

- Explain how an inline hook differs from an IAT hook.
- Identify which artifact is strongest for each hook type.

### Lab 9: Final Analysis Report

Given an unknown lab sample or trace, classify the injection family and defend the classification.

Deliverable:

- Timeline of events
- Technique hypothesis
- Supporting artifacts
- Alternative explanations
- Limitations and confidence level

## Common Student Pitfalls

- Confusing memory staging with execution.
- Assuming a pointer from the injector process is valid in the target.
- Ignoring x86, x64, and WOW64 differences.
- Treating `PAGE_EXECUTE_READWRITE` as normal because it works in a lab.
- Doing too much work in `DllMain`.
- Forgetting that many legitimate tools inject or hook for benign reasons.
- Relying on one detection signal instead of correlation.
- Thinking manual mapping is stealthy by default. It removes some loader artifacts while adding other memory artifacts.

## Instructor Notes

Start with the loader. Students understand injection faster when they first understand normal DLL loading.

Keep the first labs boring on purpose:

- one target process
- one benign DLL
- one bitness at a time
- one execution trigger at a time

Introduce ScyllaHide as a case study after the students know the vocabulary. Its injector is valuable because it includes both normal DLL injection and manual mapping, then uses the injected code to install anti-debug hooks.

Useful source anchors in this workspace:

- `../scyllahide/PluginGeneric/Injector.cpp`
- `../scyllahide/PluginGeneric/Injector.h`
- `../scyllahide/InjectorCLI/CliMain.cpp`
- `../scyllahide/InjectorCLI/DynamicMapping.cpp`
- `../scyllahide/InjectorCLI/RemoteHook.cpp`
- `../scyllahide/InjectorCLI/ApplyHooking.cpp`

Suggested order:

1. Teach normal `LoadLibrary` behavior.
2. Teach the five DLL injection methods as loader/mapping choices.
3. Teach `NtCreateThreadEx`, APC, thread hijacking, and Windows hooks as launch choices.
4. Teach section mapping and manual mapping as alternative staging/loading models.
5. Teach hooks as the common post-injection behavior.
6. Finish with detection timelines and tradeoff analysis.

## Assessment Questions

1. What are the lab's five DLL injection methods?
2. What is the difference between a DLL injection method and a launch method?
3. Why do `LoadLibraryExW`, `LdrLoadDll`, `LdrpLoadDll`, and `LdrpLoadDllInternal` still leave loader-visible artifacts?
4. Why does manual mapping leave different artifacts than loader-based DLL injection?
5. What must be true for a user-mode APC to execute?
6. Why is thread hijacking riskier than creating a new remote thread?
7. How can a defender distinguish a normal loaded DLL from a manually mapped image?
8. Why does bitness matter for `SetWindowsHookEx` and remote thread injection?
9. Which detection signals would you combine to reduce false positives for remote thread injection?
10. Why is `DllMain` a poor place for complex logic?
11. What does a trampoline preserve in an inline hook?
12. Why can wiping PE headers make an injected DLL less reliable?
13. How can legitimate debuggers, profilers, overlays, and accessibility tools complicate injection detection?

## Glossary

APC:
Asynchronous Procedure Call. A mechanism that can run a function in the context of a thread when dispatch conditions are met.

CFG:
Control Flow Guard. A Windows mitigation that restricts indirect calls to valid call targets.

CET:
Control-flow Enforcement Technology. Hardware-backed protections such as shadow stacks that can affect control-flow manipulation.

DLL:
Dynamic-link library. A PE image loaded into a process and linked at runtime.

IAT:
Import Address Table. The table a PE uses to call imported functions after the loader resolves them.

Loader list:
PEB-linked structures that track modules loaded by the Windows loader.

Manual mapping:
Loading a PE image without relying on the normal `LoadLibrary` path, requiring the mapper to copy sections, relocate, resolve imports, and call initialization code.

Remote thread:
A thread created in one process by a different process.

Section object:
A kernel memory object that can be mapped into one or more process address spaces.

Trampoline:
Generated code used by a hook to preserve overwritten instructions and continue execution after a detour.

VAD:
Virtual Address Descriptor. Kernel memory-management metadata describing a process memory region.

WOW64:
The Windows subsystem that runs 32-bit processes on 64-bit Windows.

## Future Extensions

Good follow-up labs or standalone projects:

- PE loader internals in more detail
- ETW-based injection telemetry
- Building a memory-region scanner for defensive analysis
- Hook detection and clean-image comparison
- WOW64 internals for reverse engineers
- Controlled malware unpacking case studies
