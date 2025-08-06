#pragma once
#include "imports.h"

///////////////////////////////////////////////
//          Function Prototypes	            //
/////////////////////////////////////////////

typedef NTSTATUS(NTAPI* orgNtCreateProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
typedef NTSTATUS(NTAPI* orgNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
typedef NTSTATUS(NTAPI* orgNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* orgNtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS(NTAPI* orgNtOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* orgNtSuspendProcess)(HANDLE);
typedef NTSTATUS(NTAPI* orgNtSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* orgNtResumeProcess)(HANDLE);
typedef NTSTATUS(NTAPI* orgNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* orgNtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* orgNtSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* orgNtClose)(HANDLE);
typedef NTSTATUS(NTAPI* orgNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* orgNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* orgNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* orgNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* orgNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* orgNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* orgNtQueryDirectoryFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
typedef NTSTATUS(NTAPI* orgNtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* orgNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* orgNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* orgNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* orgNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* orgNtMapViewOfSection)(HANDLE, HANDLE, PVOID, ULONG, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS(NTAPI* orgNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* orgNtAdjustPrivilegesToken)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG);
typedef NTSTATUS(NTAPI* orgNtDeviceIoControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* orgNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI* orgNtWaitForMultipleObjects)(ULONG, PHANDLE, WAIT_TYPE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* orgNtCreateUserProcess)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PPS_CREATE_INFO, PPS_ATTRIBUTE_LIST);
typedef NTSTATUS(NTAPI* orgNtAlertResumeThread)(HANDLE, PULONG);

typedef LPVOID(WINAPI* VirtualAlloc_t)(
    _In_opt_ LPVOID lpAddress,
    _In_     SIZE_T dwSize,
    _In_     DWORD  flAllocationType,
    _In_     DWORD  flProtect
    );

typedef BOOL(WINAPI* CreateProcessA_t)(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);


LPVOID wrptVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
BOOL   wrpCreateProcessA(LPCSTR lpApplicationName,LPSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);