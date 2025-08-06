#pragma once
#define X64_PEB_OFFSET 0x60
#ifdef _WIN64
#define PPEB_PTR __readgsqword( 0x60 )
#define PTEB_PTR __readgsqword( 0x30 )
#else
#define PPEB_PTR __readfsdword( 0x30 )
#define PTEB_PTR __readgsqword( 0x18 )
#endif

// Modules
#define ntdll_hash 0x22d3b5ed
#define kernel32_hash 0x6ddb9555
#define kernelbase_hash 0xa721952b


#define OPCODE_SUB_RSP 0xec8348
#define OPCODE_RET_CC 0xccc3
#define OPCODE_RET 0xc3
#define OPCODE_CALL 0xe8
#define OPCODE_JMP 0xe9
#define OPCODE_JMP_LEN 8
#define MAX_SEARCH_LIMIT 20
#define CALL_FIRST 1
#define RESUME_FLAG 0x10000
#define TRACE_FLAG 0x100
#define OPCODE_SYSCALL 0x050F
#define OPCODE_SZ_DIV 4
#define OPCODE_SZ_ACC_VIO 2
//#define OPCODE_SYSCALL_OFF 0x12
//#define OPCODE_SYSCALL_RET_OFF 0x14
#define FIFTH_ARGUMENT 0x8*0x5
#define SIXTH_ARGUMENT 0x8*0x6
#define SEVENTH_ARGUMENT 0x8*0x7
#define EIGHTH_ARGUMENT 0x8*0x8
#define NINTH_ARGUMENT 0x8*0x9
#define TENTH_ARGUMENT 0x8*0xa
#define ELEVENTH_ARGUMENT 0x8*0xb
#define TWELVETH_ARGUMENT 0x8*0xc

#define TRIGGER_INT_DIV_EXCEPTION int a = 2; int b = 0; int c = a / b;
#define TRIGGER_ACCESS_VIOLOATION_EXCEPTION int *a = 0; int b = *a;
#define TRIGGER_INT_DIV_EXCEPTION_NEW int zero = 0; int crash = 1 / zero;

typedef struct _DllInfo {
	ULONG64 DllBaseAddress;
	ULONG64 DllEndAddress;
} DllInfo;

typedef ULONG(WINAPI* RtlRemoveVectoredExceptionHandler_t) (PVOID Handle);
//typedef long(NTAPI* RemoveVectoredExceptionHandler_t)(PVOID Handle);
typedef PVOID(WINAPI* RtlAddVectoredExceptionHandler_t) (ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
//typedef void* (NTAPI* AddVectoredExceptionHandler_t)(ULONG  First,	PVECTORED_EXCEPTION_HANDLER Handler	);

void IntializeHooks();
void DestroyHooks();
void SetHwBp(ULONG_PTR FuncAddress, int flag, int ssn);
//int GetSsnByName(PCHAR syscall);
int GetSsnByNTHash(DWORD ntHash);
UINT64 LdrModulePeb(UINT_PTR hModuleHash);
LPVOID LdrFunction(UINT_PTR Module, UINT_PTR FunctionHash);
