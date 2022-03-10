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
	DWORD dwModuleCount;
	WCHAR szProcessName[MAX_PROCESS_LEN];
	//todo：智能指针？
	vector<MODULE_INFO*> m_vecModuleInfo;
	_PROCESS_INFO():dwModuleCount(0)
	{
		ZeroMemory(szProcessName, MAX_PROCESS_LEN);
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

//存储用得到的关键PE信息
typedef struct _PE_INFO {
	WORD wOptionalHeaderMagic;
	PIMAGE_NT_HEADERS pPeHeader;
	PIMAGE_SECTION_HEADER szSectionHeader;
	DWORD dwExportDirRVA;
	DWORD dwExportDirSize;
	DWORD dwImportDirRVA;
	DWORD dwImportDirSize;
	DWORD dwRelocDirRVA;
	DWORD dwRelocDirSize;
	DWORD dwSectionCnt;
	DWORD dwSectionAlign;
	DWORD dwFileAlign;
}PE_INFO, *PPE_INFO;
//class PROCESS_INFO
//{
//public:
//	DWORD dwProcessId;
//	WCHAR szProcessName[MAX_PROCESS_LEN];
//};
//
//typedef PROCESS_INFO* PPROCESS_INFO;

//遍历过程中的回调函数
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
	//todo:实现多线程安全

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

	/**
	* 模拟DLL文件载入内存后的样子
	*
	* @param pModuleInfo : 指向DLL信息相关数据
	* @return
	*/
	LPVOID SimulateLoadDLL(PMODULE_INFO pModuleInfo);
	VOID ReleaseDllMemoryBuffer(LPVOID* ppDllMemoryBuffer);
	BOOL AnalyzePEInfo(LPVOID pBuffer, PPE_INFO pPeInfo);
	/**
	* 根据Dll实际加载到的地址，修复Dll映像的地址
	*
	* @return
	*/
	BOOL FixBaseReloc(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase);

	/**
	* 重定位段是一个数组，每个成员表示待修复的一块内容，这里修复其中的一块数据
	*
	* @return
	*/
	BOOL FixBaseRelocBlock(LPVOID, LPVOID);

	BOOL EnableDebugPrivelege();

	/**
	* pDllMemoryBuffer模拟从Disk载入到内存后并修复重定向数据之后的DLL的Buffer
	*
	* @return
	*/
	BOOL DetectSingleModuleInlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);
	DWORD AlignSize(const DWORD dwSize, const DWORD dwAlign);
	
	//回调函数
	static BOOL CbCollectProcessInfo(PPROCESS_INFO pProcessInfo, PBOOL pBreak);
	static BOOL CbCollectModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo);

private:
	static vector<PROCESS_INFO*> m_vecProcessInfo;
	BOOL m_bIsWow64;
	//static vector<MODULE_INFO*> m_vecModuleInfo;
	static int m_test;
};


//参考：
//https://github.com/czp541308303/AntiHook/blob/main/scanhook.cpp
//https://github.com/NtRaiseHardError/Antimalware-Research/blob/master/Generic/Userland%20Hooking/AntiHook/AntiHook/AntiHook/AntiHook.c