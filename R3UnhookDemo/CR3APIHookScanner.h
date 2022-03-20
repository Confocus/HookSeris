#pragma once
#include "stdafx.h"
#include "COSVersionHelper.h"
#include <TlHelp32.h>

#define MAX_PROCESS_LEN		520
#define MAX_MODULE_NAME_LEN		520
#define MAX_MODULE_PATH_LEN		1024
#define INLINE_HOOK_LEN		0x10
#define MAX_FUNCTION_NAME	0x50

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
	WCHAR szModuleName[MAX_MODULE_NAME_LEN];
	WCHAR szModulePath[MAX_MODULE_PATH_LEN];
}MODULE_INFO, * PMODULE_INFO;

enum  class HOOK_TYPE
{
	IATHook = 0,
	EATHook,
	InlineHook,
};

typedef struct _HOOK_RESULT
{
	BOOL bIsHooked;
	DWORD dwHookId;
	HOOK_TYPE type;
	const wchar_t szModule[MAX_MODULE_PATH_LEN];
	const wchar_t szFuncName[MAX_FUNCTION_NAME];
	LPVOID lpHookedAddr;
	LPVOID lpRecoverAddr;
}HOOK_RESULT, *PHOOK_RESULT;

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
	
	//consider:ʵ�ֵ����򿽱��ϵ����
	//consider:ʵ�ֶ��̰߳�ȫ����ʱû��ʹ��ȫ�ֵĶ�����

	/**
	* ɨ��ȫ�������Ƿ�ҹ�
	*
	* @return
	*/
	BOOL ScanAllProcesses();

	/**
	* ɨ��ָ��Id�Ľ����Ƿ�ҹ�
	*
	* @param dwProcessId : ��ɨ����̵Ľ���Id
	* @return
	*/
	BOOL ScanProcessById(DWORD dwProcessId);

private:
	/**
	* ��ֹ�����͸�ֵ
	*/
	CR3APIHookScanner(const CR3APIHookScanner&); 
	CR3APIHookScanner& operator = (const CR3APIHookScanner&);

	BOOL Init();
	BOOL Release();

	/**
	* ��ս����б�
	*/
	BOOL Clear();

	/**
	* ������ǰ���н���
	* 
	* @param pCallbackFunc ����ʱ���õĻص�����
	*/
	BOOL EmurateProcesses(CALLBACK_EMUNPROCESS pCallbackFunc);
	BOOL GetProcessesSnapshot(CALLBACK_EMUNPROCESS pCallbackFunc);

	/**
	* ������ǰ�����е�����ģ��
	*
	* @param pProcessInfo ������Ϣ
	*/
	BOOL EmurateModules(PPROCESS_INFO pProcessInfo);

	BOOL GetModulesSnapshot(DWORD dwFlags, PPROCESS_INFO pProcessInfo, CALLBACK_EMUNMODULE pCallbackFunc);

	/**
	* ������ǰ�����е�����ģ��
	*
	* @param pProcessInfo ������Ϣ
	* @param pCallbackFunc ����ʱ���õĻص�����
	*/
	BOOL ScanSingleProcess(PPROCESS_INFO pProcessInfo);

	/**
	* �����Ҫ��Module Info����
	*/
	VOID SaveModuleInfo(PMODULE_INFO pModuleInfo, MODULEENTRY32& ModuleEntry32);

	//todo����������ϵͳ
	template<typename PApiSetMap, typename PApiSetEntry, typename PHostArray, typename PHostEntry>
	BOOL InitApiSchema();

	/**
	* ���浱ǰ����ɨ����Ǹ����̵Ľ�����Ϣ
	*/
	BOOL SetScanedProcess(PPROCESS_INFO pProcessInfo);
	PPROCESS_INFO GetScannedProcess();

	/**
	* ģ��DLL�ļ������ڴ�������
	*
	* @param pModuleInfo : ָ��DLL��Ϣ�������
	* @return
	*/
	LPVOID SimulateLoadDLL(PMODULE_INFO pModuleInfo);

	/**
	* �ͷ�ģ�������DLL
	*
	* @param ppDllMemoryBuffer : ������ͷŵĵ�ַ��ָ��
	* @return
	*/
	VOID FreeSimulateDLL(LPVOID* ppDllMemoryBuffer);

	/**
	* ����PE��ʽ
	*
	* @param pBuffer : �ڴ�
	* @param pPeInfo : ����PE��Ϣ�ĵ�ַ
	* @return
	*/
	BOOL AnalyzePEInfo(LPVOID pBuffer, PPE_INFO pPeInfo);

	/**
	* �޸�ģ�������DLL���ض������ݵ�����
	*
	* @param pBuffer:ģ������DLL�ĵ�ַ
	* @param pPeInfo:DLL�����PE�ṹ��Ϣ
	* @param lpDLLBase:DLL���ڴ�����ʵ��ַ
	* @return
	*/
	BOOL FixBaseReloc(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase);

	/**
	* �������ڴ���ģ���DLL�ĵ����
	*
	* @param pBuffer:ģ������DLL�ĵ�ַ
	* @param pPeInfo:DLL�����PE�ṹ��Ϣ
	* @param pModuleInfo:�洢DLL��Ϣ�Ľṹ��
	* @return
	*/
	BOOL BuildImportTable(LPVOID pBuffer, PPE_INFO pPeInfo, PMODULE_INFO pModuleInfo);

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

	LPVOID GetExportFuncAddrByName(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, const wchar_t* pFuncName, const wchar_t* pBaseDLL, const wchar_t* pPreHostDLL);

	LPVOID GetExportFuncAddrByOrdinal(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, WORD wOrdinal);
	
	//�ص�����
	static BOOL CbCollectProcessInfo(PPROCESS_INFO pProcessInfo, PBOOL pBreak);
	static BOOL CbCollectModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo);
	static BOOL CbRemoveWow64ModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo);

	wchar_t* ConvertCharToWchar(const char* p);
	VOID FreeConvertedWchar(wchar_t* &p);

	std::wstring RedirectDLLPath(const wchar_t* path, const wchar_t* pBaseDLL, const wchar_t* pPreHostDLL);
	BOOL ProbeSxSRedirect(std::wstring& path);//, Process& proc, HANDLE actx /*= INVALID_HANDLE_VALUE*/
	LPVOID RedirectionExportFuncAddr(const char* lpExportFuncAddr, const wchar_t* pBaseDLL,  const wchar_t* pPreHostDLL);

	BOOL LoadALLModuleSimCache(PPROCESS_INFO pProcessInfo);
	VOID ReleaseALLModuleSimCache();
	LPVOID GetModuleSimCache(const wchar_t* p);

	VOID SaveHookResult(HOOK_TYPE type, const wchar_t* pModulePath, const wchar_t* pFunc, LPVOID pHookedAddr, LPVOID lpRecoverAddr);

	BOOL UnHook();

	//��ָ�����̵�ָ��ģ���ָ����������UnHook
	BOOL UnHook(DWORD dwProcessId, LPVOID lpModule, LPVOID lpFunc);

private:
	COSVersionHelper m_OSVerHelper;
	//todo������
	static vector<PROCESS_INFO*> m_vecProcessInfo;

	//��ǰ���ڱ�ɨ����Ǹ�Process
	PROCESS_INFO* m_pScannedProcess;
	BOOL m_bIsWow64;

	//�ڴ���ʵ�ʵ�ĳ��DLL��PE��Ϣ
	PE_INFO m_OriginDLLInfo;

	//�ڴ���ʵ�ʵĶ�Ӧ��DLL��PE��Ϣ
	PE_INFO m_SimulateDLLInfo;

	//���̾����ļ���PE��Ϣ
	PE_INFO m_ImageInfo;
	std::unordered_map<std::wstring, std::vector<std::wstring>> m_mapApiSchema;

	//����ģ�������DLL����
	std::unordered_map<std::wstring, LPVOID> m_mapSimDLLCache;
	std::vector<HOOK_RESULT> m_vecHookRes;
};