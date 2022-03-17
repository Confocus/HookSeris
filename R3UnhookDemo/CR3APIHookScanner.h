#pragma once
#include "stdafx.h"
#define MAX_PROCESS_LEN	520
#define MAX_MODULE_LEN	520
#define MAX_MODULE_PATH	1024
#define INLINE_HOOK_LEN	0x10

#include <vector>
#include <unordered_map>

using namespace std;

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
}PE_INFO, * PPE_INFO;

typedef struct _MODULE_INFO
{
	BYTE* pDllBaseAddr;
	DWORD dwSizeOfImage;
	WCHAR szModuleName[MAX_MODULE_LEN];
	WCHAR szModulePath[MAX_MODULE_PATH];
}MODULE_INFO, * PMODULE_INFO;

//todo：改成类
//保存进程相关信息
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

	template<typename PApiSetMap, typename PApiSetEntry, typename PHostArray, typename PHostEntry>
	BOOL InitApiSchema();
	/**
	* 模拟DLL文件载入内存后的样子
	*
	* @param pModuleInfo : 指向DLL信息相关数据
	* @return
	*/
	LPVOID SimulateLoadDLL(PMODULE_INFO pModuleInfo);

	VOID FreeSimulateDLL(PMODULE_INFO pModuleInfo);

	VOID ReleaseDllMemoryBuffer(LPVOID* ppDllMemoryBuffer);
	BOOL AnalyzePEInfo(LPVOID pBuffer, PPE_INFO pPeInfo);

	/**
	* 根据Dll实际加载到的地址，修复Dll映像的地址
	*
	* @return
	*/
	BOOL FixBaseReloc(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase);

	/**
	* 构建在内存中模拟的DLL的导入表
	*
	* @return
	*/
	BOOL BuildImportTable(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase);

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
	BOOL ScanSingleModuleIATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	/**
	* 对某个模块进行EATHook扫描
	* pDllMemoryBuffer模拟从Disk载入到内存后并修复重定向数据之后的DLL的Buffer
	*
	* 说明：如果在构建某个DLL的导入表之前，提供导出的DLL的导出表被Hook了，也可能会篡改之后的函数调用地址
	* @return
	*/
	BOOL ScanSingleModuleEATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	/**
	* 对某个模块进行InlineHook扫描
	* pDllMemoryBuffer模拟从Disk载入到内存后并修复重定向数据之后的DLL的Buffer
	*
	* @return
	*/
	BOOL ScanSingleModuleInlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	BOOL ScanSingleModuleInlineHook2(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer);

	BOOL GetExportFuncsBoundary(PMODULE_INFO pModuleInfo, std::vector<UINT64>& vecOffsets);

	DWORD AlignSize(const DWORD dwSize, const DWORD dwAlign);

	LPVOID GetExportFuncAddrByName(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, const wchar_t* pDLLName, const wchar_t* pFuncName, const wchar_t* pPreHostDLL);

	LPVOID GetExportFuncAddrByOrdinal(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, const wchar_t* pDLLName, WORD wOrdinal);
	
	//回调函数
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

	//当前正在被扫描的那个Process
	PROCESS_INFO* m_pCurProcess;
	BOOL m_bIsWow64;
	static int m_test;

	//内存中实际的某个DLL的PE信息
	PE_INFO m_OriginDLLInfo;

	//内存中实际的对应的DLL的PE信息
	PE_INFO m_SimulateDLLInfo;

	//磁盘镜像文件的PE信息
	PE_INFO m_ImageInfo;
	std::unordered_map<std::wstring, std::vector<std::wstring>> m_mapApiSchema;

	//缓存模拟载入的DLL镜像
	std::unordered_map<std::wstring, LPVOID> m_mapSimDLLCache;
};