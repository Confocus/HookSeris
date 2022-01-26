#pragma once
#include "stdafx.h"

#define HOOK_API_DLL	"C:\\Code\\R3UnhookDemo\\R3UnhookDemo\\x64\\Debug\\HookApi.dll"
#define INLINE_HOOK_THREAD_SIZE	1024
#define HOOK_LEN		0x10


typedef DWORD(*LPZwCreateThreadEx)(

	PHANDLE ThreadHandle,

	ACCESS_MASK DesiredAccess,

	LPVOID ObjectAttributes,

	HANDLE ProcessHandle,

	LPTHREAD_START_ROUTINE lpStartAddress,

	LPVOID lpParameter,

	ULONG CreateThreadFlags,

	SIZE_T ZeroBits,

	SIZE_T StackSize,

	SIZE_T MaximumStackSize,

	LPVOID pUnkown);

typedef HMODULE(*LPLoadLibraryA)(
	LPCSTR lpLibFileName
	);

typedef struct APIPARAM_SET {
	PVOID pMessageBoxAddr;
	CHAR szMessageBoxTitle[64];
	CHAR szMessageBoxBody[64];
	PVOID pLoadLibraryAddr;
	BYTE szDllPath[500];
	PVOID pGetProcAddressAddr;
	BYTE	szFuncName[0x10];
}APIPARAM_SET, * PAPIPARAM_SET;


BOOL EnableDebugPriv(LPCSTR name);
BOOL WINAPI InjectDll(DWORD dwProcessId);
BOOL WINAPI InjectCode(DWORD dwProcessId);
