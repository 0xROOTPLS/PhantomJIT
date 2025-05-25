# PhantomJIT

**Hybrid C++ in-memory shellcode loader**  
Allocates RWX pages with `NtAllocateVirtualMemory`, copies arbitrary shellcode, then jumps to it via a JIT-generated delegate. **No remote threads, no disk writes, no BS.**

---
## Why It’s Unique

PhantomJIT executes shellcode by emitting a JIT-compiled delegate via `System::Reflection::Emit`, directly jumping to the shellcode address with `calli`.  
This avoids threads, callbacks, APCs, and traditional API execution paths; using the .NET JIT engine itself as the runner.

---

### Comparison to Common Execution Techniques

| Technique                 | Uses API | Creates Thread | Monitored | Requires Callback | Requires Alertable State | RWX Memory | Novel |
|--------------------------|:--------:|:--------------:|:---------:|:-----------------:|:-------------------------:|:----------:|:-----:|
| `CreateThread`           |    X     |       X        |     X     |                   |                           |     X      |       |
| `NtCreateThreadEx`       |    X     |       X        |     X     |                   |                           |     X      |       |
| `QueueUserAPC`           |    X     |                |     X     |         X         |             X             |     X      |       |
| `EnumWindows` Callback   |    X     |                |     X     |         X         |                           |     X      |       |
| Fiber Switching          |          |                |     X     |                   |                           |     X      |       |
| Syscall Stubs            |          |       X        |     X     |                   |                           |     X      |       |
| Manual Map  |          |       X        |     X     |                   |                           |     X      |       |
| **PhantomJIT**|          |                |           |                   |                           |     X      |   X   |

X = Applies

## How It Works

1. **Load shellcode** – Read bytes from the file passed as the first argument.  
2. **Resolves exports** – Grab pointers to `NtAllocateVirtualMemory` and `NtProtectVirtualMemory` from *ntdll.dll*.  
3. **Allocate RWX** – Reserve + commit RWX memory in the current process. (This can be done a number ways, current simple implementation works fine)
4. **Copy** – `memcpy` the shellcode into the new region.  
5. **Emit delegate** – Build a `DynamicMethod` whose IL loads the shellcode address and performs a `calli`.  
6. **Execute** – Cast the dynamic method to `Action` and invoke it.

Execution never leaves the current process; no extra handles or threads are created.

---

## Build

```powershell
cl /EHsc inj.cpp /link mscoree.lib
