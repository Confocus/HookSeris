#include <stdio.h>
#include <Windows.h>

//#define MAX_DLLNAME_LEN	0x20
//#define HOOK_API_DLL	"HookApi.dll"
//#define HOOK_API_DLL	"C:/Code/R3UnhookDemo/R3UnhookDemo/x64/Debug/HookApi64.dll"
#define HOOK_API_DLL	"D:\\Coding\\HookSeries\\HookSeries\\x64\\Debug\\HookApi.dll"

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

BOOL EnableDebugPriv(LPCSTR name);

#ifdef WIN32
BOOL WINAPI InjectTargetProcess(DWORD dwProcessId);
#else
BOOL __fastcall InjectTargetProcess(DWORD dwProcessId);
#endif

int main()
{
	BOOL bSuccess = FALSE;
	EnableDebugPriv("SeDebugPrivilege");
	printf("path:%s\n", HOOK_API_DLL);
	bSuccess = InjectTargetProcess(2616);
	return 1;
}

#ifdef WIN32
BOOL WINAPI InjectTargetProcess(DWORD dwProcessId)
#else
BOOL __fastcall InjectTargetProcess(DWORD dwProcessId)
#endif
{
	BOOL bRet = FALSE;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	HANDLE hRemoteThread = NULL;
	LPVOID pTargetMem = NULL;
	SIZE_T dwWritten = 0;
	HMODULE hModNtdll = NULL;
	HMODULE hMod = NULL;
	DWORD dwLastError = 0;
	DWORD dwStatus = 0;
	LPLoadLibraryA pLoadLibraryA = NULL;
	LPZwCreateThreadEx pZwCreateThreadEx = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		return FALSE;
	}

	do
	{
		pTargetMem = VirtualAllocEx(hProcess, NULL, strlen(HOOK_API_DLL) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (NULL == pTargetMem)
		{
			break;
		}

		if (!WriteProcessMemory(hProcess, pTargetMem, HOOK_API_DLL, strlen(HOOK_API_DLL) + 1, &dwWritten))
		{
			break;
		}
		hMod = LoadLibraryA("kernel32.dll");
		if (NULL == hMod)
		{
			break;
		}

		pLoadLibraryA = (LPLoadLibraryA)GetProcAddress(hMod, "LoadLibraryA");
		if (NULL == pLoadLibraryA)
		{
			break;
		}

		hModNtdll = LoadLibraryA("ntdll.dll");
		if (NULL == hModNtdll)
		{
			break;
		}

		pZwCreateThreadEx = (LPZwCreateThreadEx)GetProcAddress(hModNtdll, "ZwCreateThreadEx");
		if (NULL == pZwCreateThreadEx)
		{
			break;
		}

		dwStatus = pZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pTargetMem, 0, 0, 0, 0, NULL);
		dwLastError = GetLastError();

		/*hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pTargetMem, 0, NULL);
		dwLastError = GetLastError();
		if (NULL == hThread)
		{
			break;
		}*/

		WaitForSingleObject(hThread, INFINITE);
		bRet = TRUE;
	} while (FALSE);

	if (hProcess)
	{
		CloseHandle(hProcess);
	}

	if (hThread)
	{
		CloseHandle(hThread);
	}

	return bRet;
}

BOOL EnableDebugPriv(LPCSTR name)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;
	// 打开进程令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		printf("[!]Get Process Token Error!\n");
		return false;
	}
	// 获取权限Luid
	if (!LookupPrivilegeValueA(NULL, name, &luid))
	{
		printf("[!]Get Privilege Error!\n");
		return false;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// 修改进程权限
	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		printf("[!]Adjust Privilege Error!\n");
		return false;
	}
	return true;
}



