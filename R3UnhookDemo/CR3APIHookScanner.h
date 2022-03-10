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

//todo���ĳ���
typedef struct _PROCESS_INFO
{
	DWORD dwProcessId;
	DWORD dwModuleCount;
	WCHAR szProcessName[MAX_PROCESS_LEN];
	//todo������ָ�룿
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

//�洢�õõ��Ĺؼ�PE��Ϣ
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

//���������еĻص�����
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
	
	//todo:ʵ�ֵ�������ֹ�����򿽱��ϵ����
	//todo:ʵ�ֶ��̰߳�ȫ

	/**
	* ɨ��ȫ�������Ƿ�ҹ�
	*
	* @return
	*/
	BOOL ScanAllProcesses();

	/**
	* ɨ��ָ��Id�Ľ����Ƿ�ҹ�
	*
	* @param szPath : ��ɨ����̵Ľ���Id
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
	* ģ��DLL�ļ������ڴ�������
	*
	* @param pModuleInfo : ָ��DLL��Ϣ�������
	* @return
	*/
	LPVOID SimulateLoadDLL(PMODULE_INFO pModuleInfo);
	VOID ReleaseDllMemoryBuffer(LPVOID* ppDllMemoryBuffer);
	BOOL AnalyzePEInfo(LPVOID pBuffer, PPE_INFO pPeInfo);
	/**
	* ����Dllʵ�ʼ��ص��ĵ�ַ���޸�Dllӳ��ĵ�ַ
	*
	* @return
	*/
	BOOL FixBaseReloc(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase);

	/**
	* �ض�λ����һ�����飬ÿ����Ա��ʾ���޸���һ�����ݣ������޸����е�һ������
	*
	* @return
	*/
	BOOL FixBaseRelocBlock(LPVOID, LPVOID);

	BOOL EnableDebugPrivelege();

	/**
	* pDllMemoryBufferģ���Disk���뵽�ڴ���޸��ض�������֮���DLL��Buffer
	*
	* @return
	*/
	BOOL DetectSingleModuleInlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);
	DWORD AlignSize(const DWORD dwSize, const DWORD dwAlign);
	
	//�ص�����
	static BOOL CbCollectProcessInfo(PPROCESS_INFO pProcessInfo, PBOOL pBreak);
	static BOOL CbCollectModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo);

private:
	static vector<PROCESS_INFO*> m_vecProcessInfo;
	BOOL m_bIsWow64;
	//static vector<MODULE_INFO*> m_vecModuleInfo;
	static int m_test;
};


//�ο���
//https://github.com/czp541308303/AntiHook/blob/main/scanhook.cpp
//https://github.com/NtRaiseHardError/Antimalware-Research/blob/master/Generic/Userland%20Hooking/AntiHook/AntiHook/AntiHook/AntiHook.c