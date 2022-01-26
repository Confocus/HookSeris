#pragma once
#include "stdafx.h"
#define MAX_PROCESS_LEN	520
#define MAX_MODULE_LEN	520

#include <vector>

using namespace std;

typedef struct PROCESS_INFO_
{
	DWORD dwProcessId;
	WCHAR szProcessName[MAX_PROCESS_LEN];
}PROCESS_INFO, * PPROCESS_INFO;

typedef struct MODULE_INFO_
{
	WCHAR szModuleName[MAX_MODULE_LEN];
}MODULE_INFO, *PMODULE_INFO;

//class PROCESS_INFO
//{
//public:
//	DWORD dwProcessId;
//	WCHAR szProcessName[MAX_PROCESS_LEN];
//};
//
//typedef PROCESS_INFO* PPROCESS_INFO;

typedef BOOL (WINAPI* CALLBACK_EMUNPROCESS)(
	PPROCESS_INFO pProcessInfo,
	PBOOL pBreak);

typedef BOOL (WINAPI* CALLBACK_EMUNMODULE)(
	PMODULE_INFO pModuleInfo);

class CR3APIHookScanner
{
public:
	CR3APIHookScanner();
	~CR3APIHookScanner();

	BOOL ScanAllProcesses();
	BOOL ScanSingleProcessById(DWORD dwProcessId);
	BOOL ScanSingleProcessByName(CONST PCHAR pProcessName);

private:
	BOOL Init();
	BOOL Release();
	BOOL EmurateProcesses(CALLBACK_EMUNPROCESS pCallbackFunc);
	BOOL EmurateModules(DWORD dwProcessId, CALLBACK_EMUNMODULE pCallbackFunc);
	static BOOL CbCollectProcessInfo(PPROCESS_INFO pProcessInfo, PBOOL pBreak);
	static BOOL CbCollectModuleInfo(PMODULE_INFO pModuleInfo);

private:
	static vector<PROCESS_INFO*> m_vecProcessInfo;
	static vector<MODULE_INFO*> m_vecModuleInfo;
	static int m_test;
};