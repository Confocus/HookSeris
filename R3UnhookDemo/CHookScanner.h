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

//存储用得到的关键PE信息
//todo：编译成x64时还有些问题
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

//保存进程相关信息
typedef struct _PROCESS_INFO
{
	HANDLE hProcess;
	DWORD dwProcessId;
	DWORD dwModuleCount;
	WCHAR szProcessName[MAX_PROCESS_LEN];
	//todo：智能指针？
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

//遍历过程中的回调函数
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

	//consider:实现单例或拷贝上的深拷贝
	//consider:实现多线程安全。暂时没有使用全局的东西。

	/**
	* 扫描全部进程是否挂钩
	*
	* @return
	*/
	BOOL ScanAllProcesses();

	/**
	* 扫描指定Id的进程是否挂钩
	*
	* @param dwProcessId : 待扫描进程的进程Id
	* @return
	*/
	BOOL ScanProcessById(DWORD dwProcessId);

	BOOL UnHook(DWORD dwHookId);

	BOOL UnHook();
	BOOL GetHookResult(std::vector<HOOK_RESULT>& vecHookRes);

private:
	/**
	* 禁止拷贝和赋值
	*/
	CHookScanner(const CHookScanner&); 
	CHookScanner& operator = (const CHookScanner&);

	BOOL _Init();
	BOOL _Release();

	/**
	* 清空进程列表
	*/
	BOOL _Clear();

	/**
	* 遍历当前所有进程
	* 
	* @param pCallbackFunc 遍历时调用的回调函数
	*/
	BOOL EmurateProcesses(CALLBACK_EMUNPROCESS pCallbackFunc);
	BOOL GetProcessesSnapshot(CALLBACK_EMUNPROCESS pCallbackFunc);

	/**
	* 遍历当前进程中的所有模块
	*
	* @param pProcessInfo 进程信息
	*/
	BOOL EmurateModules(PPROCESS_INFO pProcessInfo);

	BOOL GetModulesSnapshot(DWORD dwFlags, PPROCESS_INFO pProcessInfo, CALLBACK_EMUNMODULE pCallbackFunc);

	/**
	* 遍历当前进程中的所有模块
	*
	* @param pProcessInfo 进程信息
	* @param pCallbackFunc 遍历时调用的回调函数
	*/
	BOOL ScanProcess(PPROCESS_INFO pProcessInfo);

	/**
	* 保存必要的Module Info数据
	*/
	VOID SaveModuleInfo(PMODULE_INFO pModuleInfo, MODULEENTRY32& ModuleEntry32);

	//todo：兼容其它系统
	template<typename PApiSetMap, typename PApiSetEntry, typename PHostArray, typename PHostEntry>
	BOOL InitApiSchema();

	/**
	* 保存当前正在扫描的那个进程的进程信息
	*/
	BOOL SetScanedProcess(PPROCESS_INFO pProcessInfo);
	PPROCESS_INFO GetScannedProcess();

	/**
	* 模拟DLL文件载入内存后的样子
	*
	* @param pModuleInfo : 指向DLL信息相关数据
	* @return
	*/
	LPVOID SimulateLoadDLL(PMODULE_INFO pModuleInfo);

	/**
	* 释放模拟载入的DLL
	*
	* @param ppDllMemoryBuffer : 保存待释放的地址的指针
	* @return
	*/
	VOID FreeSimulateDLL(LPVOID* ppDllMemoryBuffer);

	/**
	* 解析PE格式
	*
	* @param pBuffer : 内存
	* @param pPeInfo : 保存PE信息的地址
	* @return
	*/
	BOOL AnalyzePEInfo(LPVOID pBuffer, PPE_INFO pPeInfo);

	/**
	* 修复模拟载入的DLL的重定向数据的内容
	*
	* @param pBuffer:模拟载入DLL的地址
	* @param pPeInfo:DLL镜像的PE结构信息
	* @param lpDLLBase:DLL在内存中真实地址
	* @return
	*/
	BOOL FixBaseReloc(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase);

	VOID FixBaseReloc64Inner(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase, LPVOID lpImageBase);
	VOID FixBaseReloc32Inner(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase, LPVOID lpImageBase);

	/**
	* 构建在内存中模拟的DLL的导入表
	*
	* @param pBuffer:模拟载入DLL的地址
	* @param pPeInfo:DLL镜像的PE结构信息
	* @param pModuleInfo:存储DLL信息的结构体
	* @return
	*/
	BOOL BuildImportTable(LPVOID pBuffer, PPE_INFO pPeInfo, PMODULE_INFO pModuleInfo);
	BOOL BuildImportTable32Inner(LPVOID pBuffer, PPE_INFO pPeInfo, PMODULE_INFO pModuleInfo);
	BOOL BuildImportTable64Inner(LPVOID pBuffer, PPE_INFO pPeInfo, PMODULE_INFO pModuleInfo);

	VOID SetSimFunctionZero(LPVOID pDllMemoryBuffer, PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA);
	LPVOID FindWow64BaseAddrByName(const wchar_t* pName);
	LPVOID FindBaseAddrByName(const wchar_t* pName);


	/**
	* 重定位段是一个数组，每个成员表示待修复的一块内容，这里修复其中的一块数据
	*
	* @return
	*/
	BOOL FixBaseRelocBlock(LPVOID, LPVOID);

	BOOL EnableDebugPrivelege();

	/**
	* 对某个模块进行IATHook扫描
	* pDllMemoryBuffer模拟从Disk载入到内存后并修复重定向数据之后的DLL的Buffer
	*
	* @return
	*/
	BOOL ScanModuleIATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	BOOL ScanModule32IATHookInner(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);
	BOOL ScanModule64IATHookInner(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);


	/**
	* 对某个模块进行EATHook扫描
	* pDllMemoryBuffer模拟从Disk载入到内存后并修复重定向数据之后的DLL的Buffer
	*
	* 说明：如果在构建某个DLL的导入表之前，提供导出的DLL的导出表被Hook了，也可能会篡改之后的函数调用地址
	* @return
	*/
	BOOL ScanModuleEATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);
	BOOL ScanModuleEATHook32Inner(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);
	BOOL ScanModuleEATHook64Inner(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	/**
	* 对某个模块进行InlineHook扫描
	* pDllMemoryBuffer模拟从Disk载入到内存后并修复重定向数据之后的DLL的Buffer
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
	
	//回调函数
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
	//todo：加锁
	static vector<PROCESS_INFO*> m_vecProcessInfo;

	//当前正在被扫描的那个Process
	PROCESS_INFO* m_pScannedProcess;

	//内存中实际的某个DLL的PE信息
	PE_INFO m_OriginDLLInfo;

	//内存中实际的对应的DLL的PE信息
	PE_INFO m_SimulateDLLInfo;

	//磁盘镜像文件的PE信息
	PE_INFO m_ImageInfo;
	std::unordered_map<std::wstring, std::vector<std::wstring>> m_mapApiSchema;

	//缓存模拟载入的DLL镜像
	std::unordered_map<std::wstring, LPVOID> m_mapSimDLLCache;
	std::vector<HOOK_RESULT> m_vecHookRes;
};