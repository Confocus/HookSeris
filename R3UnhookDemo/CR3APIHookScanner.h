#pragma once
#include "stdafx.h"
#define MAX_PROCESS_LEN	520
#define MAX_MODULE_LEN	520
#define MAX_MODULE_PATH	1024

#include <vector>

using namespace std;

typedef struct _MODULE_INFO
{
	BYTE* pDllBaseAddr;
	DWORD dwSizeOfImage;
	WCHAR szModuleName[MAX_MODULE_LEN];
	WCHAR szModulePath[MAX_MODULE_PATH];
}MODULE_INFO, * PMODULE_INFO;

//todo：改成类
typedef struct _PROCESS_INFO
{
	DWORD dwProcessId;
	WCHAR szProcessName[MAX_PROCESS_LEN];
	//todo：智能指针？
	vector<MODULE_INFO*> m_vecModuleInfo;
	_PROCESS_INFO()
	{
		
	}

	~_PROCESS_INFO()
	{
		printf("Deconstruct _PROCESS_INFO.\n");
		if (m_vecModuleInfo.size() > 0)
		{
			for (auto pMoudleInfo : m_vecModuleInfo)
			{
				if (pMoudleInfo)
				{
					delete pMoudleInfo;
					pMoudleInfo = NULL;
				}
			}
		}
	}
}PROCESS_INFO, * PPROCESS_INFO;


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
	PPROCESS_INFO pProcessInfo,
	PMODULE_INFO pModuleInfo);

class CR3APIHookScanner
{
public:
	CR3APIHookScanner();
	~CR3APIHookScanner();
	
	//todo:实现单例、禁止拷贝或拷贝上的深拷贝

	/**
	* 扫描全部进程是否挂钩
	*
	* @return
	*/
	BOOL ScanAllProcesses();

	/**
	* 扫描指定Id的进程是否挂钩
	*
	* @param szPath : 待扫描进程的进程Id
	* @return
	*/
	BOOL ScanSingleProcessById(DWORD dwProcessId);
	BOOL ScanSingleProcessByName(CONST PCHAR pProcessName);

private:
	BOOL Init();
	BOOL Release();
	BOOL Clear();
	BOOL EmurateProcesses(CALLBACK_EMUNPROCESS pCallbackFunc);
	BOOL EmurateModules(PPROCESS_INFO pProcessInfo, CALLBACK_EMUNMODULE pCallbackFunc);
	BOOL ScanSingle(PPROCESS_INFO pProcessInfo);
	BOOL LoadDllImage(PWCHAR pDllPath);

	/**
	* 根据Dll实际加载到的地址，修复Dll映像的地址
	*
	* @return
	*/
	BOOL FixRelocData();

	BOOL EnableDebugPrivelege();
	//回调函数
	static BOOL CbCollectProcessInfo(PPROCESS_INFO pProcessInfo, PBOOL pBreak);
	static BOOL CbCollectModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo);

private:
	static vector<PROCESS_INFO*> m_vecProcessInfo;
	//static vector<MODULE_INFO*> m_vecModuleInfo;
	static int m_test;
};


//参考：
//https://github.com/czp541308303/AntiHook/blob/main/scanhook.cpp
//https://github.com/NtRaiseHardError/Antimalware-Research/blob/master/Generic/Userland%20Hooking/AntiHook/AntiHook/AntiHook/AntiHook.c