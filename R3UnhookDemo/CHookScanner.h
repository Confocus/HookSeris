#pragma once
#include "stdafx.h"
#include "COSVersionHelper.h"
#include "IHookScanner.h"
#include <TlHelp32.h>

#define MAX_PROCESS_LEN		520
#define MAX_MODULE_NAME_LEN		520
#define INLINE_HOOK_LEN		10

#include <vector>
#include <unordered_map>

using namespace std;

//�洢�õõ��Ĺؼ�PE��Ϣ
//todo�������x64ʱ����Щ����
typedef struct _PE_INFO{
	WORD wOptionalHeaderMagic;
	PIMAGE_NT_HEADERS32 pPe32Header;
	PIMAGE_NT_HEADERS64 pPe64Header;
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

typedef struct _MODULE_INFO
{
	_MODULE_INFO():
		pDllBaseAddr(NULL),
		pDllWow64BaseAddr(NULL),
		dwSizeOfImage(0)
	{

	}

	~_MODULE_INFO()
	{
		if (pDllWow64BaseAddr)
		{
			delete[] pDllWow64BaseAddr;
			pDllWow64BaseAddr = NULL;
		}
	}

	BYTE* pDllBaseAddr;
	BYTE* pDllWow64BaseAddr;
	DWORD dwSizeOfImage;
	WCHAR szModuleName[MAX_MODULE_NAME_LEN];
	WCHAR szModulePath[MAX_MODULE_PATH_LEN];
}MODULE_INFO, * PMODULE_INFO;

//������������Ϣ
typedef struct _PROCESS_INFO
{
	HANDLE hProcess;
	DWORD dwProcessId;
	DWORD dwModuleCount;
	WCHAR szProcessName[MAX_PROCESS_LEN];
	//todo������ָ�룿
	vector<MODULE_INFO*> m_vecModuleInfo;
	_PROCESS_INFO():
		hProcess(NULL),
		dwModuleCount(0)
	{
		ZeroMemory(szProcessName, MAX_PROCESS_LEN);
	}

	~_PROCESS_INFO()
	{
		if (hProcess)
		{
			CloseHandle(hProcess);
		}

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

class CHookScanner : public IHookScanner
{
public:
	CHookScanner();
	~CHookScanner();

	BOOL Init();
	BOOL Clear();

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

	BOOL UnHook(DWORD dwHookId);

	BOOL UnHook();
	BOOL GetHookResult(std::vector<HOOK_RESULT>& vecHookRes);

private:
	/**
	* ��ֹ�����͸�ֵ
	*/
	CHookScanner(const CHookScanner&); 
	CHookScanner& operator = (const CHookScanner&);

	BOOL _Init();
	BOOL _Release();

	/**
	* ��ս����б�
	*/
	BOOL _Clear();

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
	BOOL ScanProcess(PPROCESS_INFO pProcessInfo);

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

	VOID FixBaseReloc64Inner(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase, LPVOID lpImageBase);
	VOID FixBaseReloc32Inner(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase, LPVOID lpImageBase);

	/**
	* �������ڴ���ģ���DLL�ĵ����
	*
	* @param pBuffer:ģ������DLL�ĵ�ַ
	* @param pPeInfo:DLL�����PE�ṹ��Ϣ
	* @param pModuleInfo:�洢DLL��Ϣ�Ľṹ��
	* @return
	*/
	BOOL BuildImportTable(LPVOID pBuffer, PPE_INFO pPeInfo, PMODULE_INFO pModuleInfo);
	BOOL BuildImportTable32Inner(LPVOID pBuffer, PPE_INFO pPeInfo, PMODULE_INFO pModuleInfo);
	BOOL BuildImportTable64Inner(LPVOID pBuffer, PPE_INFO pPeInfo, PMODULE_INFO pModuleInfo);

	VOID SetSimFunctionZero(LPVOID pDllMemoryBuffer, PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA);
	LPVOID FindWow64BaseAddrByName(const wchar_t* pName);
	LPVOID FindBaseAddrByName(const wchar_t* pName);


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
	BOOL ScanModuleIATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	BOOL ScanModule32IATHookInner(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);
	BOOL ScanModule64IATHookInner(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);


	/**
	* ��ĳ��ģ�����EATHookɨ��
	* pDllMemoryBufferģ���Disk���뵽�ڴ���޸��ض�������֮���DLL��Buffer
	*
	* ˵��������ڹ���ĳ��DLL�ĵ����֮ǰ���ṩ������DLL�ĵ�����Hook�ˣ�Ҳ���ܻ�۸�֮��ĺ������õ�ַ
	* @return
	*/
	BOOL ScanModuleEATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);
	BOOL ScanModuleEATHook32Inner(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);
	BOOL ScanModuleEATHook64Inner(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	/**
	* ��ĳ��ģ�����InlineHookɨ��
	* pDllMemoryBufferģ���Disk���뵽�ڴ���޸��ض�������֮���DLL��Buffer
	*
	* @return
	*/
	//BOOL ScanModuleInlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	BOOL ScanModuleInlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);
	BOOL ScanModule32InlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);
	BOOL ScanModule64InlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	BOOL GetExportFuncsBoundary(PMODULE_INFO pModuleInfo, std::vector<UINT64>& vecOffsets);

	DWORD AlignSize(const DWORD dwSize, const DWORD dwAlign);

	LPVOID GetExportFuncAddrByName(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, const wchar_t* pFuncName, const wchar_t* pBaseDLL, const wchar_t* pPreHostDLL);

	LPVOID GetWow64ExportFuncAddrByName(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, LPVOID lpx86BaseAddr, const wchar_t* pFuncName, const wchar_t* pBaseDLL, const wchar_t* pPreHostDLL);

	LPVOID GetExportFuncAddrByOrdinal(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, WORD wOrdinal);
	LPVOID GetWow64ExportFuncAddrByOrdinal(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, LPVOID lpx86BasAeAddr, WORD wOrdinal);
	
	//�ص�����
	static BOOL WINAPI CbCollectProcessInfo(PPROCESS_INFO pProcessInfo, PBOOL pBreak);
	static BOOL WINAPI CbCollectModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo);
	static BOOL WINAPI CbCollectWow64ModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo);
	static BOOL WINAPI CbRemoveModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo);

	wchar_t* ConvertCharToWchar(const char* p);
	VOID FreeConvertedWchar(wchar_t* &p);

	std::wstring RedirectDLLPath(const wchar_t* path, const wchar_t* pBaseDLL, const wchar_t* pPreHostDLL);
	BOOL ProbeSxSRedirect(std::wstring& path);//, Process& proc, HANDLE actx /*= INVALID_HANDLE_VALUE*/
	LPVOID RedirectionExportFuncAddr(const char* lpExportFuncAddr, const wchar_t* pBaseDLL,  const wchar_t* pPreHostDLL);

	BOOL LoadALLModuleSimCache(PPROCESS_INFO pProcessInfo);
	VOID ReleaseALLModuleSimCache();
	LPVOID GetModuleSimCache(const wchar_t* p);

	VOID SaveHookResult(HOOK_TYPE type, const wchar_t* pModulePath, const wchar_t* pFunc, LPVOID pHookedAddr, LPVOID lpRecoverAddr);

	BOOL UnHookInner(PPROCESS_INFO pProcessInfo, PHOOK_RESULT pHookResult);

	BOOL UnHookWirteProcessMemory(HANDLE hProcess, PHOOK_RESULT pHookResult, UINT32 uLen);
private:
	BOOL m_bIsWow64;

	DWORD dwHookResCount;
	COSVersionHelper m_OSVerHelper;
	//todo������
	static vector<PROCESS_INFO*> m_vecProcessInfo;

	//��ǰ���ڱ�ɨ����Ǹ�Process
	PROCESS_INFO* m_pScannedProcess;

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