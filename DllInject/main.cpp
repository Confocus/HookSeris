#include <stdio.h>
#include <Windows.h>
#include <string>
//#define MAX_DLLNAME_LEN	0x20
//#define HOOK_API_DLL	"HookApi.dll"
//#define HOOK_API_DLL	"C:/Code/R3UnhookDemo/R3UnhookDemo/x64/Debug/HookApi64.dll"
#define HOOK_API_DLL	"C:\\Code\\R3UnhookDemo\\R3UnhookDemo\\x64\\Debug\\HookApi.dll"
#define INLINE_HOOK_THREAD_SIZE	1024

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

BOOL WINAPI InjectTargetProcess(DWORD dwProcessId);
BOOL WINAPI InjectTargetProcess2(DWORD dwProcessId);

int main()
{
	OutputDebugStringA("[HookSeris]main start.\n");

	BOOL bSuccess = FALSE;
	EnableDebugPriv("SeDebugPrivilege");
	//bSuccess = InjectTargetProcess(2616);
	bSuccess = InjectTargetProcess2(15028);
	return 1;
}

BOOL WINAPI InjectTargetProcess(DWORD dwProcessId)
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

		//ZwCreateThreadEx����ע��Win10�µļ�����
		dwStatus = pZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pTargetMem, 0, 0, 0, 0, NULL);
		if (0 != dwStatus)
		{
			dwLastError = GetLastError();
			break;
		}

		//CreateRemoteThread�޷�ע��Win10�µļ�����
		/*hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pTargetMem, 0, NULL);
		dwLastError = GetLastError();
		if (NULL == hThread)
		{
			break;
		}*/

		WaitForSingleObject(hRemoteThread, INFINITE);
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

	if (hRemoteThread)
	{
		CloseHandle(hRemoteThread);
	}

	return bRet;
}

//�������������Ϊstatic����printf("InlineHookThread:0x%016I64x\n", ::InlineHookThread);��ӡ�ĵ�ַ�����Ǵ����
static DWORD WINAPI InlineHookThread(LPVOID pParam)
{
	//OutputDebugStringA("[HookSeris]CreateThread InlineHookThread.\n");
	/*std::string s = "ttt";
	MessageBoxA(0, s.c_str(), s.c_str(), 0);*/
	return 1;
}

BOOL WINAPI InjectTargetProcess2(DWORD dwProcessId)
{
	BOOL bRet = FALSE;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	HANDLE hRemoteThread = NULL;
	LPVOID pThreadMem = NULL;
	SIZE_T dwWritten = 0;
	HMODULE hModNtdll = NULL;
	HMODULE hMod = NULL;
	DWORD dwLastError = 0;
	DWORD dwStatus = 0;
	LPZwCreateThreadEx pZwCreateThreadEx = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		return FALSE;
	}

	do
	{
		pThreadMem = VirtualAllocEx(hProcess, NULL, INLINE_HOOK_THREAD_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NULL == pThreadMem)
		{
			break;
		}

		printf("InlineHookThread:0x%016I64x\n", ::InlineHookThread);
		printf("InlineHookThread:0x%016I64x\n", *InlineHookThread);
		printf("InlineHookThread:0x%llx\n", &InlineHookThread);//һ��
		//����ֱ�Ӵ�ӡ����jmp     InlineHookThread ָ��ĵ�ַ��jmp     InlineHookThreadΪE9 96 0C

		if (!WriteProcessMemory(hProcess, pThreadMem, InlineHookThread, INLINE_HOOK_THREAD_SIZE, &dwWritten))
		{
			dwLastError = GetLastError();
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

		/*dwStatus = pZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pThreadMem, NULL, 0, 0, 0, 0, NULL);
		if (0 != dwStatus)
		{
			dwLastError = GetLastError();
			break;
		}*/

		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pThreadMem, NULL, 0, NULL);
		dwLastError = GetLastError();
		if (NULL == hThread)
		{
			break;
		}

		WaitForSingleObject(hRemoteThread, INFINITE);
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

	if (hRemoteThread)
	{
		CloseHandle(hRemoteThread);
	}

	return bRet;
}

BOOL EnableDebugPriv(LPCSTR name)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;
	// �򿪽�������
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		printf("[!]Get Process Token Error!\n");
		return false;
	}
	// ��ȡȨ��Luid
	if (!LookupPrivilegeValueA(NULL, name, &luid))
	{
		printf("[!]Get Privilege Error!\n");
		return false;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// �޸Ľ���Ȩ��
	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		printf("[!]Adjust Privilege Error!\n");
		return false;
	}
	return true;
}



