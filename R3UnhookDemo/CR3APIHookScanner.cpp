#include "CR3APIHookScanner.h"
#include <TlHelp32.h>

vector<PROCESS_INFO*> CR3APIHookScanner::m_vecProcessInfo;//无法解析的外部符号

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
	return TRUE;
}

BOOL CR3APIHookScanner::ScanAllProcesses()
{
	EmurateProcesses(CbCollectProcessInfo);
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
				delete pProcessInfo;
				pProcessInfo = NULL;
			}
		}
	}

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

BOOL CR3APIHookScanner::EmurateModules()
{
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
