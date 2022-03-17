#pragma once
#include "stdafx.h"
#define MAX_PROCESS_LEN	520
#define MAX_MODULE_LEN	520
#define MAX_MODULE_PATH	1024
#define INLINE_HOOK_LEN	0x10

#include <vector>
#include <unordered_map>

using namespace std;

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
}PE_INFO, * PPE_INFO;

typedef struct _MODULE_INFO
{
	BYTE* pDllBaseAddr;
	DWORD dwSizeOfImage;
	WCHAR szModuleName[MAX_MODULE_LEN];
	WCHAR szModulePath[MAX_MODULE_PATH];
}MODULE_INFO, * PMODULE_INFO;

//todo���ĳ���
//������������Ϣ
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

	template<typename PApiSetMap, typename PApiSetEntry, typename PHostArray, typename PHostEntry>
	BOOL InitApiSchema();
	/**
	* ģ��DLL�ļ������ڴ�������
	*
	* @param pModuleInfo : ָ��DLL��Ϣ�������
	* @return
	*/
	LPVOID SimulateLoadDLL(PMODULE_INFO pModuleInfo);

	VOID FreeSimulateDLL(PMODULE_INFO pModuleInfo);

	VOID ReleaseDllMemoryBuffer(LPVOID* ppDllMemoryBuffer);
	BOOL AnalyzePEInfo(LPVOID pBuffer, PPE_INFO pPeInfo);

	/**
	* ����Dllʵ�ʼ��ص��ĵ�ַ���޸�Dllӳ��ĵ�ַ
	*
	* @return
	*/
	BOOL FixBaseReloc(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase);

	/**
	* �������ڴ���ģ���DLL�ĵ����
	*
	* @return
	*/
	BOOL BuildImportTable(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase);

	/**
	* �ض�λ����һ�����飬ÿ����Ա��ʾ���޸���һ�����ݣ������޸����е�һ������
	*
	* @return
	*/
	BOOL FixBaseRelocBlock(LPVOID, LPVOID);

	BOOL EnableDebugPrivelege();

	/**
	* ��ĳ��ģ�����IATHookɨ��
	* pDllMemoryBufferģ���Disk���뵽�ڴ���޸��ض�������֮���DLL��Buffer
	*
	* @return
	*/
	BOOL ScanSingleModuleIATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	/**
	* ��ĳ��ģ�����EATHookɨ��
	* pDllMemoryBufferģ���Disk���뵽�ڴ���޸��ض�������֮���DLL��Buffer
	*
	* ˵��������ڹ���ĳ��DLL�ĵ����֮ǰ���ṩ������DLL�ĵ�����Hook�ˣ�Ҳ���ܻ�۸�֮��ĺ������õ�ַ
	* @return
	*/
	BOOL ScanSingleModuleEATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	/**
	* ��ĳ��ģ�����InlineHookɨ��
	* pDllMemoryBufferģ���Disk���뵽�ڴ���޸��ض�������֮���DLL��Buffer
	*
	* @return
	*/
	BOOL ScanSingleModuleInlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	BOOL ScanSingleModuleInlineHook2(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	BOOL GetExportFuncsBoundary(PMODULE_INFO pModuleInfo, std::vector<UINT64>& vecOffsets);

	DWORD AlignSize(const DWORD dwSize, const DWORD dwAlign);

	LPVOID GetExportFuncAddrByName(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, const wchar_t* pDLLName, const wchar_t* pFuncName, const wchar_t* pPreHostDLL);

	LPVOID GetExportFuncAddrByOrdinal(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, const wchar_t* pDLLName, WORD wOrdinal);
	
	//�ص�����
	static BOOL CbCollectProcessInfo(PPROCESS_INFO pProcessInfo, PBOOL pBreak);
	static BOOL CbCollectModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo);

	wchar_t* ConvertCharToWchar(const char* p);
	VOID FreeConvertedWchar(wchar_t* &p);

	std::wstring RedirectDLLPath(const wchar_t* path, const wchar_t* pPreHostDLL);
	BOOL ProbeSxSRedirect(std::wstring& path);//, Process& proc, HANDLE actx /*= INVALID_HANDLE_VALUE*/
	LPVOID RedirectionExportFuncAddr(const char* lpExportFuncAddr, const wchar_t* pPreHostDLL);

	BOOL LoadALLModuleSimCache(PPROCESS_INFO pProcessInfo);
	VOID ReleaseALLModuleSimCache();
	LPVOID GetSimCache(const wchar_t* p);

private:
	static vector<PROCESS_INFO*> m_vecProcessInfo;

	//��ǰ���ڱ�ɨ����Ǹ�Process
	PROCESS_INFO* m_pCurProcess;
	BOOL m_bIsWow64;
	static int m_test;

	//�ڴ���ʵ�ʵ�ĳ��DLL��PE��Ϣ
	PE_INFO m_OriginDLLInfo;

	//�ڴ���ʵ�ʵĶ�Ӧ��DLL��PE��Ϣ
	PE_INFO m_SimulateDLLInfo;

	//���̾����ļ���PE��Ϣ
	PE_INFO m_ImageInfo;
	std::unordered_map<std::wstring, std::vector<std::wstring>> m_mapApiSchema;

	//����ģ�������DLL����
	std::unordered_map<std::wstring, LPVOID> m_mapSimDLLCache;
};