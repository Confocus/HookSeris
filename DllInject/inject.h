#pragma once
#include "stdafx.h"

#define HOOK_API_DLL	"C:\\Code\\R3UnhookDemo\\R3UnhookDemo\\x64\\Debug\\HookApi.dll"
#define INLINE_HOOK_THREAD_SIZE	1024 * 4
#define HOOK_LEN		0x10
#define	MAX_LEN			64
#define MAX_PATH_LEN	100

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

typedef struct MESSAGEBOXA_PARAM
{
	PVOID pMessageBoxAddr;
	CHAR szMessageBoxTitle[MAX_LEN];
	CHAR szMessageBoxBody[MAX_LEN];
	CHAR szOriginCode[HOOK_LEN];
}MESSAGEBOXA_PARAM, *PMESSAGEBOXA_PARAM;

typedef struct LOADLIBRARYA_PARAM
{
	PVOID pLoadLibraryA;
	CHAR szDllPath[MAX_PATH_LEN];
}LOADLIBRARYA_PARAM, *PLOADLIBRARYA_PARAM;

typedef struct GETPROCADDRA_PARAM
{
	PVOID pGetProcAddr;
	CHAR szAPIName[MAX_LEN];
}GETPROCADDRA_PARAM, *PGETPROCADDRA_PARAM;

typedef struct VIRTUALPROTECTEX_PARAM
{
	PVOID pVirtualProtectEx;
}VIRTUALPROTECTEX_PARAM, *PVIRTUALPROTECTEX_PARAM;

typedef struct VIRTUALPROTECT_PARAM
{
	PVOID pVirtualProtect;
}VIRTUALPROTECT_PARAM, * PVIRTUALPROTECT_PARAM;

typedef struct APIPARAM_SET {
	MESSAGEBOXA_PARAM MsgBoxAParam;
	LOADLIBRARYA_PARAM LoadLibraryAParm;
	GETPROCADDRA_PARAM GetProcAddrAParam;
	VIRTUALPROTECT_PARAM VirtualProtectParam;
	VIRTUALPROTECTEX_PARAM VirtualProtectExParam;
}APIPARAM_SET, * PAPIPARAM_SET;


BOOL EnableDebugPriv(LPCSTR name);
BOOL WINAPI InjectDll(DWORD dwProcessId);
BOOL WINAPI InjectCode(DWORD dwProcessId);
