#include "CR3APIHookScanner.h"
#include <TlHelp32.h>

vector<PROCESS_INFO*> CR3APIHookScanner::m_vecProcessInfo;//无法解析的外部符号
//vector<MODULE_INFO*> CR3APIHookScanner::m_vecModuleInfo;

CR3APIHookScanner::CR3APIHookScanner()
{
	Init();
}

CR3APIHookScanner::~CR3APIHookScanner()
{
	Release();
}

BOOL CR3APIHookScanner::Init()
{
	EnableDebugPrivelege();
	return TRUE;
}

BOOL CR3APIHookScanner::ScanAllProcesses()
{
	//清空上一次扫描的内容
	Clear();
	//获取到所有进程
	if (!EmurateProcesses(CbCollectProcessInfo))
	{
		return FALSE;
	}

	//获取到所有进程的所有模块
	for (PPROCESS_INFO pProcessInfo : m_vecProcessInfo)
	{
		EmurateModules(pProcessInfo, CbCollectModuleInfo);
		//todo：考虑进程消失的情况和进程ID变动的情况
		//ScanSingleProcessById(pProcessInfo->dwProcessId);
		ScanSingle(pProcessInfo);
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanSingleProcessById(DWORD dwProcessId)
{
	return TRUE;
}

BOOL CR3APIHookScanner::ScanSingleProcessByName(CONST PCHAR pProcessName)
{
	return TRUE;
}

BOOL CR3APIHookScanner::Release()
{
	if (m_vecProcessInfo.size() > 0)
	{
		for (auto pProcessInfo : m_vecProcessInfo)
		{
			if (pProcessInfo)
			{
				for (auto pMoudleInfo : pProcessInfo->m_vecModuleInfo)
				{
					if (pMoudleInfo)
					{
						delete pMoudleInfo;
						pMoudleInfo = NULL;
					}
				}

				delete pProcessInfo;
				pProcessInfo = NULL;
			}
		}
	}

	//if (m_vecModuleInfo.size() > 0)
	//{
	//	for (auto pModuleInfo : m_vecModuleInfo)
	//	{
	//		if (pModuleInfo)
	//		{
	//			delete pModuleInfo;
	//			pModuleInfo = NULL;
	//		}
	//	}
	//}

	return TRUE;
}

BOOL CR3APIHookScanner::Clear()
{
	return TRUE;
}

BOOL CR3APIHookScanner::EmurateProcesses(CALLBACK_EMUNPROCESS pCallbackFunc)
{
	BOOL bNext = FALSE;
	BOOL bCbRet = FALSE;
	BOOL bBreak = FALSE;
	DWORD dwErrCode = 0;

	PROCESSENTRY32	ProcessEntry32;
	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapShot)
	{
		dwErrCode = GetLastError();
		return FALSE;
	}

	bNext = Process32First(hSnapShot, &ProcessEntry32);
	while (bNext)
	{
		bBreak = FALSE;
		PPROCESS_INFO pProcessInfo = NULL;
		pProcessInfo = new(std::nothrow) PROCESS_INFO();
		if (pProcessInfo)
		{
			pProcessInfo->dwProcessId = ProcessEntry32.th32ProcessID;
			wmemcpy_s(pProcessInfo->szProcessName, MAX_PROCESS_LEN, ProcessEntry32.szExeFile, wcslen(ProcessEntry32.szExeFile));
		}
		
		if (pCallbackFunc && pProcessInfo)
		{
			bCbRet = pCallbackFunc(pProcessInfo, &bBreak);
		}

		if (bBreak)
		{
			break;
		}
		bNext = Process32Next(hSnapShot, &ProcessEntry32);
	}

	CloseHandle(hSnapShot);
	return TRUE;
}

BOOL CR3APIHookScanner::EmurateModules(PPROCESS_INFO pProcessInfo, CALLBACK_EMUNMODULE pCallbackFunc)
{
	//todo：貌似有区别	TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE ??
	if (NULL == pProcessInfo)
	{
		return FALSE;
	}

	BOOL bNext = FALSE;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pProcessInfo->dwProcessId);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return FALSE;
	}

	MODULEENTRY32 ModuleEntry32 = { 0 };
	ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
	bNext = Module32FirstW(hSnapshot, &ModuleEntry32);
	while (bNext)
	{
		PMODULE_INFO pModuleInfo = NULL;
		pModuleInfo = new(std::nothrow) MODULE_INFO();
		if (pModuleInfo)
		{
			//保存ModuleInfo中必要的数据
			ZeroMemory(pModuleInfo, sizeof(PMODULE_INFO));
			pModuleInfo->pDllBaseAddr = ModuleEntry32.modBaseAddr;
			pModuleInfo->dwSizeOfImage = ModuleEntry32.modBaseSize;
			wmemcpy_s(pModuleInfo->szModuleName, MAX_MODULE_LEN, ModuleEntry32.szModule, wcslen(ModuleEntry32.szModule));
			wmemcpy_s(pModuleInfo->szModulePath, MAX_MODULE_PATH, ModuleEntry32.szExePath, wcslen(ModuleEntry32.szExePath));
		}

		if (pCallbackFunc && pModuleInfo)
		{
			pCallbackFunc(pProcessInfo, pModuleInfo);
		}

		bNext = Module32Next(hSnapshot, &ModuleEntry32);
	}

	CloseHandle(hSnapshot);
	return TRUE;
}

BOOL CR3APIHookScanner::ScanSingle(PPROCESS_INFO pProcessInfo)
{
	if (NULL == pProcessInfo)
	{
		return FALSE;
	}

	//todo：验证这个pid对应的是之前的那个程序
	BOOL bIsWow64 = FALSE;
	DWORD dwErrCode = 0;
	HANDLE hProcess = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pProcessInfo->dwProcessId);
	if (NULL == hProcess)
	{
		dwErrCode = GetLastError();
		return FALSE;
	}

	IsWow64Process(hProcess, &bIsWow64);
	for (auto pModuleInfo : pProcessInfo->m_vecModuleInfo)
	{
		LoadDllImage(pModuleInfo->szModulePath);
	}

	CloseHandle(hProcess);

	return TRUE;
}

BOOL CR3APIHookScanner::LoadDllImage(PWCHAR pDllPath)
{
	if (NULL == pDllPath)
	{
		return FALSE;
	}

	printf("Dll path:%ls\n", pDllPath);
	/*HANDLE hFile = NULL;
	hFile = CreateFile(pDllPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);*/

	return TRUE;
}

BOOL CR3APIHookScanner::FixRelocData()
{
	return TRUE;
}

BOOL CR3APIHookScanner::EnableDebugPrivelege()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
	{
		CloseHandle(hToken);
	}

	return TRUE;
}

BOOL CR3APIHookScanner::CbCollectProcessInfo(PPROCESS_INFO pProcessInfo, PBOOL pBreak)
{
	if (NULL == pProcessInfo || NULL == pBreak)
	{
		return FALSE;
	}

	printf("Process:%ls		Id:%d\n", pProcessInfo->szProcessName, pProcessInfo->dwProcessId);
	m_vecProcessInfo.push_back(pProcessInfo);

	return TRUE;
}

BOOL CR3APIHookScanner::CbCollectModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo)
{
	if (NULL == pModuleInfo || NULL == pProcessInfo)
	{
		return FALSE;
	}

	printf("Module:%ls\n", pModuleInfo->szModuleName);
	pProcessInfo->m_vecModuleInfo.push_back(pModuleInfo);

	return TRUE;
}
