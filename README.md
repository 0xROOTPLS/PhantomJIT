# PhantomJIT

**Hybrid C++ in-memory shellcode loader**  
Allocates RWX pages with `NtAllocateVirtualMemory`, copies arbitrary shellcode, then jumps to it via a JIT-generated delegate—no remote threads, no disk writes, no BS.

---

## Key Features

| Capability        | Details                                                                                                     |
|-------------------|-------------------------------------------------------------------------------------------------------------|
| Pure user-mode    | Direct NT syscalls; bypasses high-level Win32 hooks.                                                        |
| RWX allocation    | Single call to `NtAllocateVirtualMemory` with `MEM_COMMIT | MEM_RESERVE` + `PAGE_EXECUTE_READWRITE`.        |
| Minimal CLR use   | CLR is leveraged only for `System::Reflection::Emit` to build the one-shot delegate.                        |
| x64 only          | Targets 64-bit Windows processes.                                                                           |

---

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
