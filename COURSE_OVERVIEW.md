# InjectorTraining Course Overview

This is the instructor-facing roadmap for the injector lab. The student-facing lessons should be written in a friendly order: first teach complete timelines, then introduce the two-axis abstraction after students have seen several concrete examples.

The goal is not to build a payload framework. The goal is to help students understand Windows processes, DLL loading, remote execution triggers, loader artifacts, and detection tradeoffs in a controlled local lab.

## Core Teaching Model

Injector techniques are easiest to reason about as a lifecycle:

1. Where is the payload initially?
2. How does the payload or payload reference become accessible inside the target process?
3. What is the first instruction executed inside the target?
4. How does execution reach that instruction?
5. When does the actual payload logic begin?
6. What artifacts are left behind?
7. How could a defender detect those artifacts?
8. What mitigation or alternative reduces those artifacts, and what new artifacts does it introduce?

After students understand complete timelines, we introduce the two independent axes.

Axis 1: DLL Load Or Mapping Method

- `LoadLibraryExW`
- `LdrLoadDll`
- `LdrpLoadDll`
- `LdrpLoadDllInternal`
- `ManualMapping`

Axis 2: Launch Method

- `NtCreateThreadEx` or `CreateRemoteThread`
- thread hijacking
- `QueueUserAPC`
- `SetWindowsHookEx`
- callback-based execution
- VEH or exception-based launch

Every lesson should keep asking:

1. Where are the bytes or DLL path staged?
2. Which loader or mapper turns that into executable code?
3. Which launch method causes execution in the target?
4. What artifacts appear in handles, memory, threads, loader lists, and telemetry?
5. What breaks across bitness, sessions, mitigations, or Windows versions?

## Progression Strategy

Start from stable, visible, complete timelines, then move toward fragile and subtle variations.

Early lessons should be boring on purpose:

- one local target process
- one benign DLL
- same bitness first
- clear logging with `OutputDebugString`
- obvious artifacts students can inspect with Process Explorer, x64dbg, WinDbg, Sysmon, or ETW

Later lessons can introduce ambiguity:

- the two-axis abstraction
- native loader routines
- private loader internals
- APC timing
- thread context manipulation
- manual mapping gaps
- detection false positives

## Lesson Plan

### Lesson 0: Lab Rules And Environment

Purpose:
Establish the safety boundary and set up the lab machine.

Student builds:

- a benign target process
- a benign DLL
- optional x86 and x64 variants

Concepts:

- authorized local-only testing
- no persistence, no payloads, no unrelated target processes
- x86, x64, and WOW64 separation
- expected tools and logging workflow

Deliverable:

- screenshot or notes showing the solution, target process, and benign DLL built successfully

### Lesson 1: Classic DLL Injection Timeline

Purpose:
Teach the full timeline from local DLL path string to `DllMain`.

Student learns:

- a pointer is only meaningful in the process address space that owns it
- the DLL path must exist inside the target process before target code can read it
- `VirtualAllocEx` creates target-owned memory
- `WriteProcessMemory` creates the second copy of the DLL path
- `CreateRemoteThread` starts a thread; it does not magically load a DLL
- `LoadLibraryW` runs inside the target and asks the Windows loader to load the DLL
- the training DLL's first normal execution point is `DllMain(DLL_PROCESS_ATTACH)`

Artifacts to inspect:

- process handle rights
- remote allocation
- cross-process write
- remote thread
- loader-visible DLL
- message box side effect

Deliverable:

- draw the full timeline from local DLL path to `DllMain`

Status:

- Drafted in `lessons/01-classic-dll-injection.md`
- Implemented in `samples/classic-dll-injection`
- Buildable through `InjectorTraining.sln`
- Shared helpers live in `samples/classic-dll-injection/common`
- Injection implementations live in `samples/classic-dll-injection/impl`
- Visual target app implemented in `samples/visual-target`

### Lesson 2: Visual Target MessageBox Demo

Purpose:
Turn Lesson 1 into a small Visual Studio lab students can build and run.

Student learns:

- how to build the injector and training DLL
- why the student starts `TargetApp.exe` before running the injector
- how to keep the DLL behavior benign and visible
- why `DllMain` should stay small
- how target-side detection rows make injection artifacts obvious

Artifacts to inspect:

- existing `TargetApp.exe` process
- target-side detection rows
- `TrainingDll.dll` in the module list
- message box from the injected DLL
- output from the injector

Deliverable:

- build and run the demo, then explain each line of the timeline using the observed behavior

### Lesson 3: Detection Surface Of Classic DLL Injection

Purpose:
Teach attack and defense as consequences of the same mechanism.

Student learns:

- every implementation step leaves a corresponding artifact
- defenders should correlate a sequence rather than rely on one event
- visible artifacts are not bugs in the lesson; they are the lesson

Detection pattern:

```text
Technique -> Mechanism -> Observable artifacts -> Detection ideas -> Mitigations -> New artifacts introduced
```

Artifacts to inspect:

- `OpenProcess` rights
- `VirtualAllocEx`
- `WriteProcessMemory`
- remote thread creation
- thread start at loader code
- new DLL in loader lists
- image-load telemetry
- DLL path and `DllMain` side effects

Deliverable:

- write a detection timeline for the visual target demo

### Lesson 4: Why Mitigations Motivate Other Techniques

Purpose:
Show that technique evolution is artifact tradeoff, not magic.

Student learns:

- using `LdrLoadDll` changes API surface but still uses the loader
- using APC avoids a new thread but introduces APC timing artifacts
- using thread hijacking avoids a new thread but introduces suspend/context artifacts
- using manual mapping avoids normal loader registration but introduces private executable image-like memory
- every mitigation introduces a new thing to reason about

Deliverable:

- compare classic DLL injection with at least three alternatives using the artifact tradeoff pattern

### Lesson 5: The Two-Axis Injection Model

Purpose:
Introduce the abstraction only after students have seen full examples.

Student learns:

- load method means "how the DLL becomes executable in the target"
- launch method means "how execution starts in the target"
- many injectors are combinations of the two axes

Matrix to introduce:

| Load or mapping method | Typical launch choices | Loader-visible? | Main lesson |
| --- | --- | --- | --- |
| `LoadLibraryExW` | remote thread, APC, hijack | yes | documented loader baseline |
| `LdrLoadDll` | remote thread, APC, hijack | yes | native loader path |
| `LdrpLoadDll` | remote thread, APC, hijack | yes | private loader internals |
| `LdrpLoadDllInternal` | remote thread, APC, hijack | yes | deeper private internals |
| `ManualMapping` | remote thread, APC, hijack, callback | usually no | PE loader responsibilities |

Deliverable:

- classify several example timelines by load method and launch method

### Lesson 6: Native Loader Method: `LdrLoadDll`

Purpose:
Show the native loader layer below Win32 APIs.

Student learns:

- `LdrLoadDll` still uses the Windows loader
- native structures and calling conventions matter
- loader artifacts remain even if the Win32 API layer is skipped

Artifacts to compare against Lesson 5:

- same module visibility
- similar image-load telemetry
- different call path into `ntdll`
- different setup data for the loader call

Deliverable:

- explain what changed and what did not change compared with `LoadLibraryExW`

### Lesson 7: Private Loader Internals: `LdrpLoadDll` And `LdrpLoadDllInternal`

Purpose:
Teach why private loader methods are interesting but brittle.

Recommended depth:

- recognition and analysis first
- optional advanced lab only after students understand `LdrLoadDll`

Student learns:

- private `Ldrp*` routines are not stable public contracts
- implementations may require symbols or version-specific knowledge
- loader-visible artifacts still exist
- "lower-level" does not automatically mean better

Artifacts to inspect:

- call path into private loader routines
- dependency on `ntdll` version
- failure modes when symbols or signatures change

Deliverable:

- write a short risk assessment explaining why this is a poor beginner default

### Lesson 8: Launch Method: APC

Purpose:
Show execution through an existing thread.

Student learns:

- a queued user APC is a request, not immediate execution
- normal APC dispatch depends on alertable waits
- early-bird APC changes the timing by using a newly created suspended process

Lab shape:

- one target thread that enters alertable wait
- one target thread that does not
- compare whether the queued routine runs

Artifacts to inspect:

- queued APC
- thread wait state
- execution under an existing thread
- prior staged memory

Deliverable:

- explain why APC launch can be unreliable but useful to understand

### Lesson 9: Launch Method: Thread Hijacking

Purpose:
Show execution by redirecting an existing thread.

Student learns:

- suspend a thread
- inspect context
- reason about instruction pointer, stack, and register preservation
- understand why arbitrary thread hijacking is crash-prone

Friendly approach:

- first do this as a debugger reasoning exercise
- only later demonstrate a controlled benign redirect in the lab target

Artifacts to inspect:

- suspend/resume events
- context read/write
- instruction pointer landing in staged memory
- unusual call stack

Deliverable:

- identify what must be preserved for the thread to continue safely afterward

### Lesson 10: Launch Method: Windows Hooks

Purpose:
Show GUI-driven loading and execution.

Student learns:

- `SetWindowsHookEx` is tied to GUI threads, desktops, sessions, integrity, and bitness
- hook DLLs are loader-visible
- this is useful for teaching constraints, not as a universal injector

Lab shape:

- controlled GUI target with a message loop
- thread-specific hook before global hook
- x86 and x64 comparison if time allows

Artifacts to inspect:

- hook registration
- DLL load into GUI process
- hook callback execution
- desktop/session constraints

Deliverable:

- explain why this method does not apply to arbitrary service or console targets

### Lesson 11: Advanced Launch Concepts: Callbacks And Exceptions

Purpose:
Give recognition vocabulary without making this the core lab path.

Topics:

- callback-based execution
- kernel/user callback dispatch as a concept
- VEH or exception-based launch
- why exception routing matters

Student learns:

- these are launch triggers, not DLL loading methods
- they still need code or a DLL present in the target
- they are fragile and highly context-dependent

Deliverable:

- classify callback and exception techniques on the two-axis model

### Lesson 12: Manual Mapping, Part 1: PE Loader Responsibilities

Purpose:
Teach manual mapping locally before remote mapping.

Student learns:

- DOS and NT headers
- sections
- image base and relocations
- import resolution
- TLS callbacks
- entry point
- exception metadata and runtime concerns

Manual-mapping checklist:

- section mapping
- base relocation
- imports
- delayed imports
- SEH or exception support
- TLS initialization
- security cookie initialization
- loader-lock behavior
- optional header/data-directory cleanup

Deliverable:

- map each manual-mapper responsibility to the equivalent thing the Windows loader normally does

### Lesson 13: Manual Mapping, Part 2: Remote Manual Mapping

Purpose:
Show how manual mapping changes artifacts.

Student learns:

- manually mapped code may not appear in normal loader lists
- private executable memory becomes a strong artifact
- incomplete mapping breaks real programs quickly
- header wiping and unlinking trade one artifact for another

Artifacts to inspect:

- `MEM_PRIVATE` executable image-like region
- missing loader entry
- import pointer clusters
- thread start or hijacked execution into mapped image
- differences from `LoadLibraryExW` and `LdrLoadDll`

Deliverable:

- compare detection artifacts for loader-based injection versus manual mapping

### Lesson 14: Post-Injection Hooking

Purpose:
Connect injection to why people inject DLLs in reverse-engineering tools.

Student learns:

- inline detours
- trampolines
- IAT hooks
- export or callback replacement
- syscall-stub and native API hook complications

Artifacts to inspect:

- modified function prologue
- trampoline memory
- IAT pointer outside expected module
- temporary writable code pages

Deliverable:

- explain how the hook artifact differs from the injection artifact

### Lesson 15: Detection Timeline Lab

Purpose:
End with analysis instead of implementation.

Student receives:

- one or more recorded traces
- memory maps
- module lists
- thread lists
- selected event logs

Student produces:

- timeline
- load/mapping method hypothesis
- launch method hypothesis
- supporting artifacts
- alternative explanations
- confidence level

Deliverable:

- final analysis report using the two-axis model

## Recommended Writing Order

Write these first:

1. Lesson 0: Lab Rules And Environment
2. Lesson 1: Classic DLL Injection Timeline
3. Lesson 2: Visual Target MessageBox Demo
4. Lesson 3: Detection Surface Of Classic DLL Injection
5. Lesson 4: Why Mitigations Motivate Other Techniques
6. Lesson 5: The Two-Axis Injection Model

Then write the intermediate loader and launch lessons:

7. Lesson 6: Native Loader Method: `LdrLoadDll`
8. Lesson 8: Launch Method: APC
9. Lesson 9: Launch Method: Thread Hijacking
10. Lesson 10: Launch Method: Windows Hooks

Then write advanced lessons:

11. Lesson 7: Private Loader Internals: `LdrpLoadDll` And `LdrpLoadDllInternal`
12. Lesson 12: Manual Mapping, Part 1
13. Lesson 13: Manual Mapping, Part 2
14. Lesson 11: Callbacks And Exceptions
15. Lesson 14: Post-Injection Hooking
16. Lesson 15: Detection Timeline Lab

This order keeps the student moving from visible, stable mechanics toward fragile internals and detection tradeoffs.

## Implementation Guidance

Keep each technique in a small, named demo module. Avoid one giant injector UI early in the project.

Suggested lab binaries:

- `TargetConsole`: simple process with controllable threads and logging
- `TargetGui`: simple message-loop target for Windows hook lessons
- `TrainingDll`: benign DLL that records load/unload and exposes simple exports
- `InjectorLab`: command-line runner for one technique at a time
- `InspectorLab`: helper that prints process, thread, module, and memory observations

Suggested command style:

```text
InjectorLab.exe --target app --load LoadLibraryW --launch CreateRemoteThread --dll TrainingDll.dll
InjectorLab.exe --target app --load LoadLibraryW --launch NtCreateThreadEx --dll TrainingDll.dll
InjectorLab.exe --target app --load LoadLibraryW --launch QueueUserAPC --dll TrainingDll.dll
InjectorLab.exe --target app --load LdrLoadDll --launch QueueUserAPC --dll TrainingDll.dll
InjectorLab.exe --target app --load ManualMap --launch ThreadHijack --dll TrainingDll.dll
```

The command syntax should make the two axes obvious.

The first implementation supports `--load LoadLibraryW` with `--launch CreateRemoteThread`, `--launch NtCreateThreadEx`, or `--launch QueueUserAPC`. That gives students early same-load/different-launch comparisons before the course moves into other load methods, hijacking, hooks, and manual mapping. The unsupported combinations are intentionally named early so the CLI can grow with the lessons.

## What To Avoid In The Lessons

- Do not frame private loader routines as magic or universally better.
- Do not combine every load method with every launch method in the first pass.
- Do not start with manual mapping.
- Do not hide artifacts before students know what the artifacts are.
- Do not teach security-tool tampering or unrelated-process targeting.
- Do not let `DllMain` become the place where complex lab behavior lives.

## Course Thesis

The student's final mental model should be:

Injection is not one trick. It is a combination of staging, loading or mapping, launching execution, and leaving artifacts. The most reliable method is often the most visible; the less visible methods tend to be more fragile, more version-dependent, or easier to detect through different artifacts.
