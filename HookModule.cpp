#pragma once 

#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <winternl.h>
#include "HookModule.h"

DllInfo NtdllInfo;
PCONTEXT SavedContext;
PVOID h1, h2;
ULONG_PTR SyscallEntryAddr;
ULONG_PTR FuncAddress;
BOOL ExtendedArgs = FALSE;
int IsSubRsp = 0;
int SyscallNo = 0;
int OPCODE_SYSCALL_OFF = 0;
DWORD runtime_hash(unsigned char* str)
{
    DWORD hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}
int OPCODE_SYSCALL_RET_OFF = 0;

LPVOID LdrFunction(UINT_PTR Module, UINT_PTR FunctionHash)
{
    PIMAGE_NT_HEADERS       NtHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY ExpDirectory = NULL;
    PDWORD                  AddrOfFunctions = NULL;
    PDWORD                  AddrOfNames = NULL;
    PWORD                   AddrOfOrdinals = NULL;
    PVOID                   FunctionAddr = NULL;
    PCHAR                   FunctionName = NULL;
    ANSI_STRING             AnsiString = { 0 };

    NtHeader = (PIMAGE_NT_HEADERS)(Module + ((PIMAGE_DOS_HEADER)Module)->e_lfanew);
    ExpDirectory = (PIMAGE_EXPORT_DIRECTORY)(Module + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    AddrOfNames = (PDWORD)(Module + ExpDirectory->AddressOfNames);
    AddrOfFunctions = (PDWORD)(Module + ExpDirectory->AddressOfFunctions);
    AddrOfOrdinals = (PWORD)(Module + ExpDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < ExpDirectory->NumberOfNames; i++)
    {
        FunctionName = (PCHAR)Module + AddrOfNames[i];
        if (runtime_hash((unsigned char*)FunctionName) == FunctionHash)
        {
            return (PVOID)(Module + AddrOfFunctions[AddrOfOrdinals[i]]);
        }
    }
}

void customRtlSecureZeroMemory(void* ptr, size_t cnt) {
    // Cast the input pointer to a volatile unsigned char pointer
    volatile unsigned char* vptr = (volatile unsigned char*)ptr;

    // Zero out memory byte by byte
    while (cnt--) {
        *vptr++ = 0;
    }
}

void ConvertPWSTRToUnsignedChar(unsigned char* dest, size_t destSize, const wchar_t* src, size_t srcLength) {
    if (dest == NULL || src == NULL) {
        return;
    }

    size_t i;
    for (i = 0; i < srcLength && i < destSize - 1; ++i) {
        wchar_t wc = src[i];

        // Simple conversion, truncating wide character to unsigned char
        if (wc < 256) {
            dest[i] = (unsigned char)wc;
        }
        else {
            // Handle characters outside the ASCII range (or other conversion logic as needed)
            dest[i] = '?';  // Use '?' or any placeholder for non-ASCII characters
        }
    }

    dest[i] = '\0'; // Null-terminate the string
}

UINT64 LdrModulePeb(UINT_PTR hModuleHash)
{
    unsigned char cstr_module_name[256] = { 0 };
    PLDR_DATA_TABLE_ENTRY Module = (PLDR_DATA_TABLE_ENTRY)((PPEB)PPEB_PTR)->Ldr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY FirstModule = Module;

    do
    {
        ConvertPWSTRToUnsignedChar((unsigned char*)cstr_module_name, sizeof(cstr_module_name), Module->FullDllName.Buffer, Module->FullDllName.Length - 1);
        DWORD ModuleHash = runtime_hash(cstr_module_name);// , Module->FullDllName.Length);ConvertPWSTRToUnsignedChar
        if (ModuleHash == hModuleHash)
            return (UINT64)Module->Reserved2[0];

        Module = (PLDR_DATA_TABLE_ENTRY)Module->Reserved1[0];
    } while (Module && Module != FirstModule);

    return (UINT64)INVALID_HANDLE_VALUE;
}


void InitializeDllInfo(DllInfo* obj, const char* DllName) {
    HMODULE hModuledll = GetModuleHandleA(DllName);

    MODULEINFO ModuleInfo;
    if (GetModuleInformation(GetCurrentProcess(), hModuledll, &ModuleInfo, sizeof(MODULEINFO)) == 0) {
        //printf("[!] GetModuleInformation failed\n");
        return;
    }

    obj->DllBaseAddress = (ULONG64)ModuleInfo.lpBaseOfDll;
    obj->DllEndAddress = obj->DllBaseAddress + ModuleInfo.SizeOfImage;
}

LONG WINAPI AddHwBp(
    struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
       // printf("\n[*] Hardware Breakpoint at address: %#llx (syscall)\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);// (ULONG_PTR)ExceptionInfo->ContextRecord->Dr0);
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

            SyscallEntryAddr = FuncAddress;

            for (int i = 0; i < 25; i++) {
                // find syscall ret opcode offset
                if (*(BYTE*)(SyscallEntryAddr + i) == 0x0F && *(BYTE*)(SyscallEntryAddr + i + 1) == 0x05) {
                    OPCODE_SYSCALL_OFF = i;
                    OPCODE_SYSCALL_RET_OFF = i + 2;
                    break;
                }
            }

            // Set hwbp at the syscall opcode
            ExceptionInfo->ContextRecord->Dr0 = (SyscallEntryAddr);
            ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 | (1 << 0);

            ExceptionInfo->ContextRecord->Rip += OPCODE_SZ_ACC_VIO;
            //printf("\n[*] Hardware Breakpoint added at address: %#llx (syscall)\n", (ULONG_PTR)ExceptionInfo->ContextRecord->Dr0);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)SyscallEntryAddr)
        {
            //printf("[*] Hardware Breakpoint hit and ntfunction address %#llx\n", SyscallEntryAddr);

            //printf("[*] OPCODE_SYSCALL_OFF %#llx\n", OPCODE_SYSCALL_OFF);

            ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
            ExceptionInfo->ContextRecord->Rax = SyscallNo;
            ExceptionInfo->ContextRecord->Rip = SyscallEntryAddr + OPCODE_SYSCALL_OFF;
            // Clear hwbp
            ExceptionInfo->ContextRecord->Dr0 = 0;
            ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 & ~(1 << 0);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void IntializeHooks() {
    UINT64 ntdll_addr = LdrModulePeb(ntdll_hash);
    RtlAddVectoredExceptionHandler_t pAddVectoredExceptionHandler =(RtlAddVectoredExceptionHandler_t)LdrFunction(ntdll_addr, 0x554bafa9);
    h1 = pAddVectoredExceptionHandler(CALL_FIRST, AddHwBp);
    SavedContext = (PCONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof CONTEXT);
    InitializeDllInfo(&NtdllInfo, "ntdll.dll");

    //printf("[*] Ntdll Start Address: %#llx\n", NtdllInfo.DllBaseAddress);
    //printf("[*] Ntdll End Address: %#llx\n\n", NtdllInfo.DllEndAddress);
}

void DestroyHooks() {
    UINT64 ntdll_addr = LdrModulePeb(ntdll_hash);
    RtlRemoveVectoredExceptionHandler_t pRemoveVectoredExceptionHandler = (RtlRemoveVectoredExceptionHandler_t)LdrFunction(ntdll_addr, 0x880c210e);
    if (h1 != NULL)    pRemoveVectoredExceptionHandler(h1);
}

void _SetHwBp(ULONG_PTR FAddress) {
    FuncAddress = FAddress;
    TRIGGER_ACCESS_VIOLOATION_EXCEPTION;
}

void SetHwBp(ULONG_PTR FuncAddress, int flag, int ssn) {
    ExtendedArgs = flag;
    SyscallNo = ssn;
    _SetHwBp(FuncAddress);
}

// https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/
//int GetSsnByName(PCHAR syscall) {
int GetSsnByNTHash(DWORD ntHash){
    PPEB_LDR_DATA Ldr = (PPEB_LDR_DATA)(((PTEB)PTEB_PTR)->ProcessEnvironmentBlock->Ldr);
    PLIST_ENTRY Head = (PLIST_ENTRY)&Ldr->Reserved2[1];
    PLIST_ENTRY Next = Head->Flink;

    while (Next != Head) {
        PLDR_DATA_TABLE_ENTRY ent = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
        Next = Next->Flink;

        PBYTE m = (PBYTE)ent->DllBase;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(m + ((PIMAGE_DOS_HEADER)m)->e_lfanew);
        DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!rva) continue;

        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(m + rva);
        if (!exp->NumberOfNames) continue;

        PDWORD dll = (PDWORD)(m + exp->Name);

        // check if it's ntdll.dll
        if ((dll[0] | 0x20202020) != 'ldtn') continue;
        if ((dll[1] | 0x20202020) != 'ld.l') continue;
        if ((*(USHORT*)&dll[2] | 0x0020) != '\x00l') continue;

        // load exception directory
        rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        if (!rva) return -1;
        PIMAGE_RUNTIME_FUNCTION_ENTRY rtf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(m + rva);

        // load export info
        rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PDWORD adr = (PDWORD)(m + exp->AddressOfFunctions);
        PDWORD sym = (PDWORD)(m + exp->AddressOfNames);
        PWORD ord = (PWORD)(m + exp->AddressOfNameOrdinals);

        int ssn = 0;

        for (int i = 0; rtf[i].BeginAddress; i++) {
            for (int j = 0; j < exp->NumberOfFunctions; j++) {
                if (adr[ord[j]] == rtf[i].BeginAddress) {
                    unsigned char* api = (unsigned char*)(m + sym[j]);
                    if(ntHash ==runtime_hash(api))
                        return ssn;
                    /*
                    PCHAR s1 = api;
                    PCHAR s2 = syscall;

                    while (*s1 && (*s1 == *s2)) {
                        s1++;
                        s2++;
                    }

                    int cmp = (int)(*(PBYTE)s1) - *(PBYTE)s2;
                    if (!cmp) return ssn;
                    */
                    if (*(USHORT*)api == 'wZ') ssn++;
                }
            }
        }
    }

    return -1;
}