#pragma once

#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <string>
#include <iostream>
#include <Windows.h>
#include "HookModule.h"
#include "FuncWrappers.h"
#include "imports.h"

#pragma comment(lib, "ntdll.lib")

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
extern "C" __declspec(dllexport) int UpdateEvents();
int UpdateEvents()
{

	IntializeHooks();

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);

	// Hardcoded path to the target EXE
	const char* exePath = "demo.exe";

	BOOL result = wrpCreateProcessA(
		exePath,          // Application name
		NULL,             // Command line
		NULL,             // Process handle not inheritable
		NULL,             // Thread handle not inheritable
		FALSE,            // Set handle inheritance to FALSE
		CREATE_SUSPENDED, // Creation flags
		NULL,             // Use parent's environment block
		NULL,             // Use parent's starting directory 
		&si,              // Pointer to STARTUPINFO structure
		&pi               // Pointer to PROCESS_INFORMATION structure
	);

	DestroyHooks();
	return 1;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH: {
		break;
	}
	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}