#include "inject.h"

BOOL WINAPI InjectDll(DWORD dwProcessId)
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

int WINAPI MyMessageBoxW(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	return 1;
}

void HookMessageBoxA(PVOID pMessageBoxA)
{
	BYTE szOriginCode[HOOK_LEN] = { 0x00 };
	BYTE szHookCode[HOOK_LEN] = { 0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xE0 };
	DWORD OldProtect = 0;
	if (VirtualProtect(pMessageBoxA, HOOK_LEN, PAGE_EXECUTE_READWRITE, &OldProtect))
	{
		memcpy(szOriginCode, pMessageBoxA, HOOK_LEN);         // ����ԭʼ������ָ��
		*(PINT64)(szHookCode + 2) = (INT64)&MyMessageBoxW;    // ���90Ϊָ����ת��ַ
	}
	memcpy(pMessageBoxA, &szHookCode, sizeof(szHookCode));    // ����Hook����ָ��
}

void UnHookMessageBoxA(PVOID pMessageBoxA)
{

}


//�������������Ϊstatic����printf("InlineHookThread:0x%016I64x\n", ::InlineHookThread);��ӡ�ĵ�ַ�����Ǵ����
static DWORD WINAPI InlineHookThread(LPVOID pParam)
{
	//OutputDebugStringA("[HookSeris]CreateThread InlineHookThread.\n");
	/*std::string s = "ttt";
	MessageBoxA(0, s.c_str(), s.c_str(), 0);*/
	typedef int (WINAPI* PFUNC_MESSAGEBOXA)(
		_In_opt_ HWND hWnd,
		_In_opt_ LPCSTR lpText,
		_In_opt_ LPCSTR lpCaption,
		_In_ UINT uType);

	typedef HMODULE (WINAPI *PFUNC_LOADLIBRARYA)(
			_In_ LPCSTR lpLibFileName
		);

	typedef PVOID64 (WINAPI *PFUNC_GETPROCADDRA)(
			_In_ HMODULE hModule,
			_In_ LPCSTR lpProcName
		);

	typedef BOOL (WINAPI *PFUNC_VIRTUALPROTECTEX)(
			_In_ HANDLE hProcess,
			_In_ LPVOID lpAddress,
			_In_ SIZE_T dwSize,
			_In_ DWORD flNewProtect,
			_Out_ PDWORD lpflOldProtect
		);

	typedef BOOL (WINAPI *PFUNC_VIRTUALPROTECT)(
			_In_ LPVOID lpAddress,
			_In_ SIZE_T dwSize,
			_In_ DWORD flNewProtect,
			_Out_ PDWORD lpflOldProtect
		);

	PAPIPARAM_SET pAPIParamSet = (PAPIPARAM_SET)pParam;
	PFUNC_MESSAGEBOXA pMessageBoxA = (PFUNC_MESSAGEBOXA)(pAPIParamSet->MsgBoxAParam.pMessageBoxAddr);
	PFUNC_LOADLIBRARYA pLoadLibraryA = (PFUNC_LOADLIBRARYA)(pAPIParamSet->LoadLibraryAParm.pLoadLibraryA);
	PFUNC_GETPROCADDRA pGetProcAddrA = (PFUNC_GETPROCADDRA)(pAPIParamSet->GetProcAddrAParam.pGetProcAddrA);
	PFUNC_VIRTUALPROTECTEX pVirtualProtectEx = (PFUNC_VIRTUALPROTECTEX)(pAPIParamSet->VirtualProtectExParam.pVirtualProtectEx);
	PFUNC_VIRTUALPROTECT pVirtualProtect = (PFUNC_VIRTUALPROTECT)(pAPIParamSet->VirtualProtectParam.pVirtualProtect);
	CHAR szOriginCode[HOOK_LEN] = { 0x00 };
	//BYTE szHookCode[HOOK_LEN] = { 0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xE0 };
	CHAR szHookCode[HOOK_LEN] = { 0xE9, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	DWORD OldProtect = 0;
	PCHAR pMessageBoxAAddr = reinterpret_cast<CHAR*>(pMessageBoxA);
	if (!pVirtualProtect(pMessageBoxA, HOOK_LEN, PAGE_EXECUTE_READWRITE, &OldProtect))
	{
		return 0;
	}

	for (UINT i = 0; i < HOOK_LEN; i++)// ����ԭʼ������ָ�������memcpy_s����ע����̻����
	{
		szOriginCode[i] = pMessageBoxAAddr[i];
	}
	//memcpy_s(szOriginCode, HOOK_LEN, pMessageBoxA, HOOK_LEN);
		//*(PINT64)(szHookCode + 2) = (INT64)&MyMessageBoxW;    // ���90Ϊָ����ת��ַ
	for (UINT i = 0; i < sizeof(szHookCode); i++)
	{
		pMessageBoxAAddr[i] = szHookCode[i];
	}
	//memcpy_s(pMessageBoxA, sizeof(szHookCode), &szHookCode, sizeof(szHookCode));    // ����Hook����ָ��

	return 1;
}

BOOL WINAPI InjectCode(DWORD dwProcessId)
{
	BOOL bRet = FALSE;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	HANDLE hRemoteThread = NULL;
	LPVOID pThreadMem = NULL;
	LPVOID pThreadParam = NULL;
	SIZE_T dwWritten = 0;
	HMODULE hModNtdll = NULL, hModUser32 = NULL, hModKernel32 = NULL;
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

		//printf("InlineHookThread:0x%016I64x\n", ::InlineHookThread);
		//printf("InlineHookThread:0x%016I64x\n", *InlineHookThread);
		//printf("InlineHookThread:0x%llx\n", &InlineHookThread);//һ��
		//����ֱ�Ӵ�ӡ����jmp     InlineHookThread ָ��ĵ�ַ��jmp     InlineHookThreadΪE9 96 0C

		if (!WriteProcessMemory(hProcess, pThreadMem, InlineHookThread, INLINE_HOOK_THREAD_SIZE, &dwWritten))
		{
			dwLastError = GetLastError();
			break;
		}

		hModNtdll = LoadLibraryA("ntdll.dll");//�ظ����룬�����ú����
		if (NULL == hModNtdll)
		{
			break;
		}

		hModUser32 = LoadLibraryA("user32.dll");
		if (NULL == hModUser32)
		{
			break;
		}

		hModKernel32 = LoadLibraryA("kernel32.dll");
		if (NULL == hModKernel32)
		{
			break;
		}

		APIPARAM_SET APIParamSet = { 0 };
		ZeroMemory(&APIParamSet, sizeof(APIPARAM_SET));
		APIParamSet.MsgBoxAParam.pMessageBoxAddr = GetProcAddress(hModUser32, "MessageBoxA");//�ظ����룬�����ú����
		if (NULL == APIParamSet.MsgBoxAParam.pMessageBoxAddr)
		{
			break;
		}
		strcpy_s(APIParamSet.MsgBoxAParam.szMessageBoxTitle, strlen("ttt") + 1, "ttt");
		strcpy_s(APIParamSet.MsgBoxAParam.szMessageBoxBody, strlen("ttt") + 1, "ttt");

		APIParamSet.LoadLibraryAParm.pLoadLibraryA = GetProcAddress(hModKernel32, "LoadLibraryA");
		if (NULL == APIParamSet.LoadLibraryAParm.pLoadLibraryA)
		{
			break;
		}

		APIParamSet.VirtualProtectExParam.pVirtualProtectEx = GetProcAddress(hModKernel32, "VirtualProtectEx");
		if (NULL == APIParamSet.VirtualProtectExParam.pVirtualProtectEx)
		{
			break;
		}

		APIParamSet.VirtualProtectParam.pVirtualProtect = GetProcAddress(hModKernel32, "VirtualProtect");
		if (NULL == APIParamSet.VirtualProtectParam.pVirtualProtect)
		{
			break;
		}
		//strcpy_s(APIParamSet.LoadLibraryAParm.szDllPath, strlen("ttt") + 1, "ttt");

		pThreadParam = VirtualAllocEx(hProcess, NULL, sizeof(APIPARAM_SET), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!pThreadParam)
		{
			break;
		}

		if (!WriteProcessMemory(hProcess, pThreadParam, &APIParamSet, sizeof(APIPARAM_SET), &dwWritten))
		{
			dwLastError = GetLastError();
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

		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pThreadMem, pThreadParam, 0, NULL);
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