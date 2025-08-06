
#pragma once
#include <Windows.h>
#include <stdio.h>
#include "FuncWrappers.h"
#include "HookModule.h"
#include "imports.h"

//#define WIN32_FUNC( x )     __typeof__( x ) * x //only gcc/mingw


LPVOID wrptVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect)
{
        UINT64 kernel32_addr = LdrModulePeb(kernel32_hash);
    UINT64 ntdll_addr = LdrModulePeb(ntdll_hash);
    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)LdrFunction(kernel32_addr, 0x382c0f97);
   //printf("function addr: %#llx\n", pVirtualAlloc);

    orgNtAllocateVirtualMemory pNtAllocateVirtualMemory = (orgNtAllocateVirtualMemory)LdrFunction(ntdll_addr, 0x6793c34c);

    if (pNtAllocateVirtualMemory == NULL) {
        //printf("[!] Unable to resolve ntdll.dll!NtAllocateVirtualMemory\n");
        return NULL;
    }
    //printf("[*] preparing breakpoints for function ntdll.dll!NtAllocateVirtualMemory\n");
    int ssn = GetSsnByNTHash(0x6793c34c); //GetSsnByName((PCHAR)"NtAllocateVirtualMemory");
    //printf("ssn: %d\n", ssn);
    SetHwBp((ULONG_PTR)pNtAllocateVirtualMemory, TRUE, ssn);
    return pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}


BOOL   wrpCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    UINT64 kernel32_addr = LdrModulePeb(kernel32_hash);
    UINT64 ntdll_addr = LdrModulePeb(ntdll_hash);
    CreateProcessA_t pCreateProcessA = (CreateProcessA_t)LdrFunction(kernel32_addr, 0xaeb52e19);//changehash
    //printf("function addr: %#llx\n", pCreateProcessA);

    orgNtCreateUserProcess pNtCreateUserProcess = (orgNtCreateUserProcess)LdrFunction(ntdll_addr, 0x5f8e4559);//changehash

    if (pNtCreateUserProcess == NULL) {
        //printf("[!] Unable to resolve ntdll.dll!NtAllocateVirtualMemory\n");
        return NULL;
    }
    //printf("[*] preparing breakpoints for function ntdll.dll!NtAllocateVirtualMemory\n");
    int ssn = GetSsnByNTHash(0x5f8e4559); //GetSsnByName((PCHAR)"NtCreateUserProcess");
    //printf("ssn: %d\n", ssn);
    SetHwBp((ULONG_PTR)pNtCreateUserProcess, TRUE, ssn);
    return pCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}
