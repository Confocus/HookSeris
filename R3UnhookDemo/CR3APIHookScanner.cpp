#include "CR3APIHookScanner.h"
#include <string.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "nativestructure.h"
#include "ApiSet.h"
#include <algorithm>
#include <winternl.h>

using namespace blackbone;
vector<PROCESS_INFO*> CR3APIHookScanner::m_vecProcessInfo;//无法解析的外部符号

CR3APIHookScanner::CR3APIHookScanner():
	m_bIsWow64(FALSE)
{
	Init();
}

CR3APIHookScanner::~CR3APIHookScanner()
{
	Release();
}

BOOL CR3APIHookScanner::Init()
{
	m_OriginDLLInfo = { 0 };
	m_SimulateDLLInfo = { 0 };
	m_ImageInfo = { 0 };

	EnableDebugPrivelege();

	if (m_OSVerHelper.IsWindows10OrGreater())
	{
		InitApiSchema< PAPI_SET_NAMESPACE_ARRAY_10,
			PAPI_SET_NAMESPACE_ENTRY_10,
			PAPI_SET_VALUE_ARRAY_10,
			PAPI_SET_VALUE_ENTRY_10 >();
	}
	else if (m_OSVerHelper.IsWindows8Point1OrGreater())
	{
		//todo：测试其它版本是否正确，xp是否需要
		InitApiSchema< PAPI_SET_NAMESPACE_ARRAY,
			PAPI_SET_NAMESPACE_ENTRY,
			PAPI_SET_VALUE_ARRAY,
			PAPI_SET_VALUE_ENTRY >();
	}
	else if (m_OSVerHelper.IsWindows7OrGreater())
	{
		InitApiSchema< PAPI_SET_NAMESPACE_ARRAY_V2,
			PAPI_SET_NAMESPACE_ENTRY_V2,
			PAPI_SET_VALUE_ARRAY_V2,
			PAPI_SET_VALUE_ENTRY_V2 >();
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanAllProcesses()
{
	//清空上一次扫描的内容
	Clear();
	//获取到所有进程
	if (!EmurateProcesses(CbCollectProcessInfo))
	{
		return FALSE;
	}

	//获取到所有进程的所有模块
	for (PPROCESS_INFO pProcessInfo : m_vecProcessInfo)
	{
		if (!SetScanedProcess(pProcessInfo))
		{
			continue;
		}
		
		if (!EmurateModules(pProcessInfo))
		{
			continue;
		}

		//todo：考虑进程消失的情况和进程ID变动的情况，将扫描的进程挂起
		//ScanSingleProcessById(pProcessInfo->dwProcessId);
		ScanProcess(pProcessInfo);
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanProcessById(DWORD dwProcessId)
{
	BOOL bRet = FALSE;

	Clear();
	//获取到所有进程
	//todo：这里拿到一个pProcessInfo即可，不必拿到全部的vector
	if (!EmurateProcesses(CbCollectProcessInfo))
	{
		return FALSE;
	}

	//获取到所有进程的所有模块
	for (PPROCESS_INFO pProcessInfo : m_vecProcessInfo)
	{
		//找到我们要扫描的那个进程
		if (dwProcessId == pProcessInfo->dwProcessId)
		{
			//记住当前正在扫描的那个进程
			if (!SetScanedProcess(pProcessInfo))
			{
				break;
			}

			if (!EmurateModules(pProcessInfo))
			{
				break;
			}

			ScanProcess(pProcessInfo);
			bRet = TRUE;
			break;
		}
	}

	return bRet;
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

BOOL CR3APIHookScanner::Clear()
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

	m_vecProcessInfo.clear();

	return TRUE;
}

BOOL CR3APIHookScanner::EmurateProcesses(CALLBACK_EMUNPROCESS pCallbackFunc)
{
	return GetProcessesSnapshot(pCallbackFunc);
}

BOOL CR3APIHookScanner::GetProcessesSnapshot(CALLBACK_EMUNPROCESS pCallbackFunc)
{
	BOOL bNext = FALSE;
	BOOL bCbRet = FALSE;
	BOOL bBreak = FALSE;
	DWORD dwErrCode = 0;
	HANDLE hSnapShot = NULL;
	PROCESSENTRY32	ProcessEntry32;

	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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

BOOL CR3APIHookScanner::EmurateModules(PPROCESS_INFO pProcessInfo)
{
	CHECK_POINTER_NULL(pProcessInfo, FALSE);

	if (m_bIsWow64)
	{
		if (!GetModulesSnapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pProcessInfo, CbCollectWow64ModuleInfo) || 
			!GetModulesSnapshot(TH32CS_SNAPMODULE, pProcessInfo, CbRemoveModuleInfo))
		{
			return FALSE;
		}
	}
	else
	{
		if (!GetModulesSnapshot(TH32CS_SNAPMODULE, pProcessInfo, CbCollectModuleInfo))
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOL CR3APIHookScanner::GetModulesSnapshot(DWORD dwFlags, PPROCESS_INFO pProcessInfo, CALLBACK_EMUNMODULE pCallbackFunc)
{
	BOOL bNext = FALSE;
	wstring wcsSuffix;
	HANDLE hSnapshot = NULL;

	hSnapshot = CreateToolhelp32Snapshot(dwFlags, pProcessInfo->dwProcessId);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		//如果这个ID的进程退出了，那么这里返回FALSE
		return FALSE;
	}

	MODULEENTRY32 ModuleEntry32 = { 0 };
	ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
	bNext = Module32FirstW(hSnapshot, &ModuleEntry32);
	while (bNext)
	{
		PMODULE_INFO pModuleInfo = NULL;
		wstring wcsModuleName = ModuleEntry32.szModule;
		transform(wcsModuleName.begin(), wcsModuleName.end(), wcsModuleName.begin(), tolower);
		wcsSuffix = wcsModuleName.substr(wcsModuleName.find_last_of('.') + 1);
		//todo：这里是否需要去掉exe
		if (0 != wcsSuffix.compare(L"dll"))
		{
			bNext = Module32Next(hSnapshot, &ModuleEntry32);
			continue;
		}

		pModuleInfo = new(std::nothrow) MODULE_INFO();
		if (pModuleInfo)
		{
			pProcessInfo->dwModuleCount++;
			SaveModuleInfo(pModuleInfo, ModuleEntry32);
		}

		if (pCallbackFunc && pModuleInfo)
		{
			pCallbackFunc(pProcessInfo, pModuleInfo);
		}

		bNext = Module32Next(hSnapshot, &ModuleEntry32);
	}

	CloseHandle(hSnapshot);

	return TRUE;
}

VOID CR3APIHookScanner::SaveModuleInfo(PMODULE_INFO pModuleInfo, MODULEENTRY32& ModuleEntry32)
{
	CHECK_POINTER_NULL(pModuleInfo, );
	std::wstring wsModuleName;
	std::wstring wsModulePath;
	ZeroMemory(pModuleInfo, sizeof(PMODULE_INFO));
	pModuleInfo->pDllBaseAddr = ModuleEntry32.modBaseAddr;
	pModuleInfo->dwSizeOfImage = ModuleEntry32.modBaseSize;
	//todo：全部转换成小写
	wsModuleName = ModuleEntry32.szModule;
	wsModulePath = ModuleEntry32.szExePath;

	transform(wsModuleName.begin(), wsModuleName.end(), wsModuleName.begin(), tolower);
	transform(wsModulePath.begin(), wsModulePath.end(), wsModulePath.begin(), tolower);

	ZeroMemory(pModuleInfo->szModuleName, MAX_MODULE_NAME_LEN);
	wmemcpy_s(pModuleInfo->szModuleName, MAX_MODULE_NAME_LEN, wsModuleName.c_str(), wcslen(ModuleEntry32.szModule));
	ZeroMemory(pModuleInfo->szModulePath, MAX_MODULE_PATH_LEN);
	wmemcpy_s(pModuleInfo->szModulePath, MAX_MODULE_PATH_LEN, wsModulePath.c_str(), wcslen(ModuleEntry32.szExePath));

	return;
}

BOOL CR3APIHookScanner::ScanProcess(PPROCESS_INFO pProcessInfo)
{
	CHECK_POINTER_NULL(pProcessInfo, FALSE);

	DWORD dwErrCode = 0;
	HANDLE hProcess = NULL;

	/*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pProcessInfo->dwProcessId);
	if (NULL == hProcess)
	{
		dwErrCode = GetLastError();
		return FALSE;
	}
	pProcessInfo->hProcess = hProcess;*/
	//缓存下这个exe中所有载入的DLL对应的模拟载入
	LoadALLModuleSimCache(pProcessInfo);

	//遍历这个进程中的所有模块
	//todo:也要考虑快照的时效性的问题
	for (auto pModuleInfo : pProcessInfo->m_vecModuleInfo)
	{
		LPVOID pDllMemBuffer = NULL;
		if (m_bIsWow64)
		{
			if (!AnalyzePEInfo(pModuleInfo->pDllWow64BaseAddr, &m_OriginDLLInfo))
			{
				continue;
			}
		}
		else
		{
			if (!AnalyzePEInfo(pModuleInfo->pDllBaseAddr, &m_OriginDLLInfo))
			{
				continue;
			}
		}
		
		pDllMemBuffer = GetModuleSimCache(pModuleInfo->szModulePath);
		if (NULL == pDllMemBuffer)
		{
			continue;
		}

		ScanModuleIATHook(pModuleInfo, pDllMemBuffer);
		/*ScanModuleEATHook(pModuleInfo, pDllMemBuffer);
		ScanModuleInlineHook(pModuleInfo, pDllMemBuffer);*/
	}

	//CloseHandle(hProcess);
	ReleaseALLModuleSimCache();

	return TRUE;
}

template<typename PApiSetMap, typename PApiSetEntry, typename PHostArray, typename PHostEntry>
BOOL CR3APIHookScanner::InitApiSchema()
{
	if (!m_mapApiSchema.empty())
		return true;

	PEB_T* ppeb = reinterpret_cast<PEB_T*>(reinterpret_cast<TEB_T*>(NtCurrentTeb())->ProcessEnvironmentBlock);
	PApiSetMap pSetMap = reinterpret_cast<PApiSetMap>(ppeb->ApiSetMap);

	for (DWORD i = 0; i < pSetMap->Count; i++)
	{
		PApiSetEntry pDescriptor = pSetMap->entry(i);

		std::vector<std::wstring> vhosts;
		wchar_t dllName[MAX_PATH] = { 0 };

		auto nameSize = pSetMap->apiName(pDescriptor, dllName);
		std::transform(dllName, dllName + nameSize / sizeof(wchar_t), dllName, ::towlower);

		PHostArray pHostData = pSetMap->valArray(pDescriptor);

		for (DWORD j = 0; j < pHostData->Count; j++)
		{
			PHostEntry pHost = pHostData->entry(pSetMap, j);
			std::wstring hostName(
				reinterpret_cast<wchar_t*>(reinterpret_cast<uint8_t*>(pSetMap) + pHost->ValueOffset),
				pHost->ValueLength / sizeof(wchar_t)
			);

			if (!hostName.empty())
				vhosts.emplace_back(std::move(hostName));
		}

		m_mapApiSchema.emplace(dllName, std::move(vhosts));
	}
	
	return TRUE;
}

BOOL CR3APIHookScanner::SetScanedProcess(PPROCESS_INFO pProcessInfo)
{
	HANDLE hProcess = NULL;
	DWORD dwErrCode = 0;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pProcessInfo->dwProcessId);
	if (NULL == hProcess)
	{
		dwErrCode = GetLastError();
		return FALSE;
	}
	pProcessInfo->hProcess = hProcess;
	m_pScannedProcess = pProcessInfo;

	IsWow64Process(hProcess, &m_bIsWow64);

	return TRUE;
}

PPROCESS_INFO CR3APIHookScanner::GetScannedProcess()
{
	return m_pScannedProcess;
}

LPVOID CR3APIHookScanner::SimulateLoadDLL(PMODULE_INFO pModuleInfo)
{
	CHECK_POINTER_NULL(pModuleInfo, NULL);

	BOOL bRet = FALSE;
	HANDLE hFile = NULL;
	DWORD dwBytesRead = 0;
	const DWORD dwBufferSize = pModuleInfo->dwSizeOfImage;
	LPVOID pDllImageBuffer = NULL;//DLL磁盘上的样子
	LPVOID pDllMemoryBuffer = NULL;//DLL模拟载入内存中的样子
	PE_INFO PEImageInfo = { 0 };

	do 
	{
		hFile = CreateFile(pModuleInfo->szModulePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			break;
		}

		pDllImageBuffer = new(std::nothrow) BYTE[dwBufferSize];
		pDllMemoryBuffer = new(std::nothrow) BYTE[dwBufferSize];

		if (pDllImageBuffer && pDllMemoryBuffer)
		{
			ZeroMemory(pDllMemoryBuffer, dwBufferSize);
			if (!ReadFile(hFile, pDllImageBuffer, dwBufferSize, &dwBytesRead, NULL))
			{
				break;
			}

			if (!AnalyzePEInfo(pDllImageBuffer, &PEImageInfo))
			{
				break;
			}

			for (int i = 0; i < PEImageInfo.dwSectionCnt; i++)
			{
				DWORD dwSizeOfRawData = AlignSize(PEImageInfo.szSectionHeader[i].SizeOfRawData, PEImageInfo.dwFileAlign);
				memcpy_s((LPVOID)((UINT64)pDllMemoryBuffer + PEImageInfo.szSectionHeader[i].VirtualAddress),
					dwSizeOfRawData,
					(LPVOID)((UINT64)pDllImageBuffer + PEImageInfo.szSectionHeader[i].PointerToRawData),
					dwSizeOfRawData);
			}
		}

		//修复重定位表
		if (!FixBaseReloc(pDllMemoryBuffer, &PEImageInfo, pModuleInfo->pDllBaseAddr))
		{
			break;
		}
		//建立导入表
		if (!BuildImportTable(pDllMemoryBuffer, &PEImageInfo, pModuleInfo))
		{
			break;
		}

		bRet = TRUE;
	} while (FALSE);

	if (pDllImageBuffer)
	{
		delete[] pDllImageBuffer;
		pDllImageBuffer = NULL;
	}

	CloseHandle(hFile);

	return bRet ? pDllMemoryBuffer : NULL;
}

VOID CR3APIHookScanner::FreeSimulateDLL(LPVOID* ppDllMemoryBuffer)
{
	if (*ppDllMemoryBuffer)
	{
		delete[] *ppDllMemoryBuffer;
		*ppDllMemoryBuffer = NULL;
	}
}

BOOL CR3APIHookScanner::AnalyzePEInfo(LPVOID pBuffer, PPE_INFO pPeInfo)
{
	CHECK_POINTER_NULL(pBuffer, FALSE);
	CHECK_POINTER_NULL(pPeInfo, FALSE);

	BOOL bRet = FALSE;

	/*try
	{*/
		if (m_bIsWow64)
		{
			//这里使用32位地址空间会出现错误，所以 必须编译出来32位的来解析32位对应的exe，所以为什么xdbg会提供一个x64和一个x86版本
			//todo：拆分成两个版本
			PIMAGE_DOS_HEADER pDosHeader = NULL;
			PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = NULL;
			pDosHeader = (PIMAGE_DOS_HEADER)((UINT64)pBuffer);
			if (IMAGE_DOS_SIGNATURE == pDosHeader->e_magic)
			{
				pPeInfo->pPe32Header = (PIMAGE_NT_HEADERS32)((UINT64)pBuffer + pDosHeader->e_lfanew);
				if (IMAGE_NT_SIGNATURE == pPeInfo->pPe32Header->Signature)
				{
					pPeInfo->szSectionHeader = IMAGE_FIRST_SECTION(pPeInfo->pPe32Header);
					pPeInfo->dwSectionCnt = pPeInfo->pPe32Header->FileHeader.NumberOfSections;
					pOptionalHeader32 = &(pPeInfo->pPe32Header->OptionalHeader);
					pPeInfo->wOptionalHeaderMagic = pOptionalHeader32->Magic;
					pPeInfo->dwFileAlign = pOptionalHeader32->FileAlignment;
					pPeInfo->dwSectionAlign = pOptionalHeader32->SectionAlignment;
					pPeInfo->dwExportDirRVA = pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
					pPeInfo->dwExportDirSize = pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
					pPeInfo->dwImportDirRVA = pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
					pPeInfo->dwImportDirSize = pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
					pPeInfo->dwRelocDirRVA = pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
					pPeInfo->dwRelocDirSize = pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
					bRet = TRUE;
				}
			}
		}
		else
		{
			//64bit-exe load 64bit-DLL
			PIMAGE_DOS_HEADER pDosHeader = NULL;
			PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = NULL;
			pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
			if (IMAGE_DOS_SIGNATURE == pDosHeader->e_magic)
			{
				pPeInfo->pPe64Header = (PIMAGE_NT_HEADERS64)((UINT64)pBuffer + pDosHeader->e_lfanew);
				if (IMAGE_NT_SIGNATURE == pPeInfo->pPe64Header->Signature)
				{
					pPeInfo->szSectionHeader = IMAGE_FIRST_SECTION(pPeInfo->pPe64Header);
					pPeInfo->dwSectionCnt = pPeInfo->pPe64Header->FileHeader.NumberOfSections;
					pOptionalHeader64 = &(pPeInfo->pPe64Header->OptionalHeader);
					pPeInfo->wOptionalHeaderMagic = pOptionalHeader64->Magic;
					pPeInfo->dwFileAlign = pOptionalHeader64->FileAlignment;
					pPeInfo->dwSectionAlign = pOptionalHeader64->SectionAlignment;
					pPeInfo->dwExportDirRVA = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
					pPeInfo->dwExportDirSize = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
					pPeInfo->dwImportDirRVA = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
					pPeInfo->dwImportDirSize = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
					pPeInfo->dwRelocDirRVA = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
					pPeInfo->dwRelocDirSize = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
					bRet = TRUE;
				}
			}
		}
		/*}
		catch (...)
		{
			printf("AnalyzePEInfo exception.\n");
			bRet = FALSE;
		}*/
	
	return bRet;
}

BOOL CR3APIHookScanner::FixBaseReloc(const LPVOID pMemoryBuffer, const PPE_INFO const pPeImageInfo, const LPVOID lpDLLBase)
{
	CHECK_POINTER_NULL(pMemoryBuffer, FALSE);
	CHECK_POINTER_NULL(pPeImageInfo, FALSE);
	CHECK_POINTER_NULL(lpDLLBase, FALSE);
	
	LPVOID lpImageBase = NULL;

	try
	{
		if (m_bIsWow64)
		{
			if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == pPeImageInfo->wOptionalHeaderMagic)
			{
				lpImageBase = (LPVOID)((PIMAGE_NT_HEADERS32)pPeImageInfo->pPe32Header)->OptionalHeader.ImageBase;
			}

			FixBaseRelocInner(pMemoryBuffer, pPeImageInfo, lpDLLBase, lpImageBase);
		}
		else
		{
			if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == pPeImageInfo->wOptionalHeaderMagic)
			{
				lpImageBase = (LPVOID)((PIMAGE_NT_HEADERS64)pPeImageInfo->pPe64Header)->OptionalHeader.ImageBase;
			}

			FixBaseRelocInner(pMemoryBuffer, pPeImageInfo, lpDLLBase, lpImageBase);
		}
	}
	catch (...)
	{
		printf("FixBaseReloc exception.\n");
		return FALSE;
	}

	return TRUE;
}

VOID CR3APIHookScanner::FixBaseRelocInner(LPVOID pBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase, LPVOID lpImageBase)
{
	DWORD dwBaseRelocTotalSize = 0;
	LPVOID lpRelocVA = NULL;
	PUSHORT pNextRelocOffset = NULL;
	INT64 uDiff = 0;
	PIMAGE_BASE_RELOCATION pBaseRelocBlock = NULL;

	//todo：为什么要判断大小???
	if (lpDLLBase > lpImageBase)
	{
		uDiff = (UINT64)lpDLLBase - (UINT64)lpImageBase;
	}

	pBaseRelocBlock = (PIMAGE_BASE_RELOCATION)((UINT64)pBuffer + pPeInfo->dwRelocDirRVA);
	dwBaseRelocTotalSize = pPeInfo->dwRelocDirSize;
	pNextRelocOffset = (PUSHORT)((UINT64)pBaseRelocBlock + sizeof(IMAGE_BASE_RELOCATION));//指向一个重定位块中的偏移数据处
	if (NULL == pBaseRelocBlock || 0 == dwBaseRelocTotalSize)
	{
		return;
	}

	//遍历重定位块
	while (dwBaseRelocTotalSize)
	{
		DWORD dwBaseRelocBlockSize = 0;
		DWORD dwBaseRelocCount = 0;

		//余下的数据
		dwBaseRelocTotalSize -= pBaseRelocBlock->SizeOfBlock;

		//本次遍历需要重定位的数据
		dwBaseRelocBlockSize = pBaseRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
		dwBaseRelocCount = dwBaseRelocBlockSize / sizeof(USHORT);//需要重定位的数据有多少个

		lpRelocVA = (LPVOID)((UINT64)pBuffer + (UINT64)pBaseRelocBlock->VirtualAddress);//指向了一个4K的页，需要重定位的数据
		for (int i = 0; i < dwBaseRelocCount; i++)
		{
			LPVOID lpRelocAddr = NULL;
			LPVOID lpUnFixedAddr = NULL;
			WORD wOffset = *(pNextRelocOffset) & 0x0FFF;
			lpUnFixedAddr = (LPVOID)((UINT64)lpRelocVA + wOffset);
			*((PINT64)lpUnFixedAddr) += uDiff;

			//todo：这些选项有待完善
			switch (*(pNextRelocOffset) >> 12)
			{
			case IMAGE_REL_BASED_HIGHLOW:
			{
				printf("");
				break;
			}
			case IMAGE_REL_BASED_HIGH:
			{
				printf("");
				break;
			}
			case IMAGE_REL_BASED_HIGHADJ:
			{
				printf("");
				break;
			}
			case IMAGE_REL_BASED_LOW:
			{
				printf("");
				break;
			}
			case IMAGE_REL_BASED_IA64_IMM64:
			{
				printf("");
				break;
			}
			case IMAGE_REL_BASED_DIR64:
			{
				printf("");
				break;
			}
			case IMAGE_REL_BASED_MIPS_JMPADDR:
			{
				printf("");
				break;
			}
			case IMAGE_REL_BASED_ABSOLUTE:
			{
				printf("");
				break;
			}
			default:
				break;
			}
			pNextRelocOffset++;
		}

		pBaseRelocBlock = (PIMAGE_BASE_RELOCATION)((UINT64)pBaseRelocBlock + pBaseRelocBlock->SizeOfBlock);
		pNextRelocOffset = (PUSHORT)((UINT64)pBaseRelocBlock + sizeof(IMAGE_BASE_RELOCATION));//指向一个重定位块中的偏移数据处
	}

	return;
}

BOOL CR3APIHookScanner::BuildImportTable(const LPVOID pDllMemoryBuffer, const PPE_INFO pPeInfo, const PMODULE_INFO pModuleInfo)
{
	//1、去遍历自己依赖的DLL，就能拿到每个依赖的DLL中的函数名；
	//2、去内存中找那些载入的DLL的导出表，然后拿到地址；
	//3、然后填充导入表；
	//4、这里会产生一个问题，就是如果导出表被Hook了怎么办？就由专门的EATHook检测；
	CHECK_POINTER_NULL(pDllMemoryBuffer, FALSE);
	CHECK_POINTER_NULL(pPeInfo, FALSE);
	CHECK_POINTER_NULL(pModuleInfo, FALSE);

	WORD wOrdinal = 0;
	DWORD dwImportTableCount = 0;
	DWORD dwOriginImportTableSize = pPeInfo->dwImportDirSize;
	PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA = NULL;
	PE_INFO SimulateDLLInfo = { 0 };
	PIMAGE_IMPORT_BY_NAME pName = NULL;
	PIMAGE_IMPORT_BY_NAME pSimulateName = NULL;
	char* pDLLName = NULL;
	wchar_t* wcsDLLName = NULL;

	//没有导入表直接返回
	if (NULL == pPeInfo->dwImportDirRVA || 0 == pPeInfo->dwImportDirSize)
	{
		return TRUE;
	}

	try 
	{
		if (m_bIsWow64)
		{
			BuildImportTable32Inner(pDllMemoryBuffer, pPeInfo, pModuleInfo);
		}
		else
		{
			BuildImportTable64Inner(pDllMemoryBuffer, pPeInfo, pModuleInfo);
		}
	}
	catch (...)
	{
		printf("BuildImportTable exception.\n");
		return FALSE;
	}

	return TRUE;
}

BOOL CR3APIHookScanner::BuildImportTable32Inner(LPVOID pDllMemoryBuffer, PPE_INFO pPeInfo, PMODULE_INFO pModuleInfo)
{
	WORD wOrdinal = 0;
	DWORD dwImportTableCount = 0;
	DWORD dwOriginImportTableSize = pPeInfo->dwImportDirSize;
	PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA = NULL;
	PIMAGE_IMPORT_BY_NAME pName = NULL;
	char* pDLLName = NULL;
	wchar_t* wcsDLLName = NULL;
	PIMAGE_THUNK_DATA32 pSimulateFirstThunk = NULL;
	PIMAGE_THUNK_DATA32 pSimulateOriginFirstThunk = NULL;
	
	pSimulateOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer + pPeInfo->dwImportDirRVA);
	dwImportTableCount = pPeInfo->dwImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);

	for (int i = 0; i < dwImportTableCount && pSimulateOriginImportTableVA->Name; i++)
	{
		LPVOID lpWow64BaseAddr = NULL;
		LPVOID lpBaseAddr = NULL;
		std::wstring wsRedirectedDLLName;
		pDLLName = (char*)pDllMemoryBuffer + pSimulateOriginImportTableVA->Name;
		if (strcmp(pDLLName, "api-ms-win-core-processthreads-l1-1-0.dll") == 0)
		{
			printf("");
		}
		PE_INFO ImportDLLInfo = { 0 };
		wcsDLLName = ConvertCharToWchar(pDLLName);

		//pModuleInfo->szModuleName此时是DLL自身，我们在重定向的时候要避免重定向为自身
		wsRedirectedDLLName = RedirectDLLPath(wcsDLLName, pModuleInfo->szModuleName, NULL);//这里是第一次调用RedirectDLLPath
		if (0 != wsRedirectedDLLName.size())
		{
			transform(wsRedirectedDLLName.begin(), wsRedirectedDLLName.end(), wsRedirectedDLLName.begin(), tolower);
			lpWow64BaseAddr = FindWow64BaseAddrByName(wsRedirectedDLLName.c_str());
			lpBaseAddr = FindBaseAddrByName(wsRedirectedDLLName.c_str());
		}
		else
		{
			std::wstring wsDLLName = wcsDLLName;
			transform(wsDLLName.begin(), wsDLLName.end(), wsDLLName.begin(), tolower);
			lpWow64BaseAddr = FindWow64BaseAddrByName(wsDLLName.c_str());
			lpBaseAddr = FindBaseAddrByName(wsDLLName.c_str());
		}
		//获取"已经映射到调用进程中"的模块的句柄

		if (!lpWow64BaseAddr || !lpBaseAddr)
		{
			FreeConvertedWchar(wcsDLLName);
			return FALSE;
		}

		if (!AnalyzePEInfo(lpWow64BaseAddr, &ImportDLLInfo))
		{
			FreeConvertedWchar(wcsDLLName);
			return FALSE;
		}

		pSimulateFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pDllMemoryBuffer +
			pSimulateOriginImportTableVA->FirstThunk);
		pSimulateOriginFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pDllMemoryBuffer +
			pSimulateOriginImportTableVA->OriginalFirstThunk);

		while (pSimulateFirstThunk->u1.Function)
		{
			LPVOID ExportAddr = NULL;

			if (pSimulateOriginFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
			{
				wOrdinal = pSimulateFirstThunk->u1.Ordinal & 0xFFFF;
				ExportAddr = GetWow64ExportFuncAddrByOrdinal(lpWow64BaseAddr, &ImportDLLInfo, lpBaseAddr, wOrdinal);
			}
			else
			{
				wchar_t* wcsFuncName = NULL;
				pName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDllMemoryBuffer + pSimulateOriginFirstThunk->u1.AddressOfData);
				wcsFuncName = ConvertCharToWchar(pName->Name);
				ExportAddr = GetWow64ExportFuncAddrByName(lpWow64BaseAddr, &ImportDLLInfo, lpBaseAddr, wcsFuncName, pModuleInfo->szModuleName, wsRedirectedDLLName.c_str());
				FreeConvertedWchar(wcsFuncName);
			}

			pSimulateFirstThunk->u1.AddressOfData = (DWORD)ExportAddr;
			pSimulateOriginFirstThunk++;
			pSimulateFirstThunk++;
		}

		FreeConvertedWchar(wcsDLLName);
		pSimulateOriginImportTableVA++;
	}

	return TRUE;
}

BOOL CR3APIHookScanner::BuildImportTable64Inner(LPVOID pDllMemoryBuffer, PPE_INFO pPeInfo, PMODULE_INFO pModuleInfo)
{
	WORD wOrdinal = 0;
	DWORD dwImportTableCount = 0;
	DWORD dwOriginImportTableSize = pPeInfo->dwImportDirSize;
	PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA = NULL;
	PE_INFO SimulateDLLInfo = { 0 };
	PIMAGE_IMPORT_BY_NAME pName = NULL;
	PIMAGE_IMPORT_BY_NAME pSimulateName = NULL;
	char* pDLLName = NULL;
	wchar_t* wcsDLLName = NULL;
	PIMAGE_THUNK_DATA64 pSimulateFirstThunk = NULL;
	PIMAGE_THUNK_DATA64 pSimulateOriginFirstThunk = NULL;

	pSimulateOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer + pPeInfo->dwImportDirRVA);
	dwImportTableCount = pPeInfo->dwImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);//相当于获取DLL的个数

	//遍历要修复的DLL所依赖的DLL
	for (int i = 0; i < dwImportTableCount && pSimulateOriginImportTableVA->Name; i++)
	{
		//找到依赖的DLL
		HMODULE lpImportDLLAddr = NULL;
		std::wstring wsRedirectedDLLName;
		pDLLName = (char*)pDllMemoryBuffer + pSimulateOriginImportTableVA->Name;
		PE_INFO ImportDLLInfo = { 0 };
		wcsDLLName = ConvertCharToWchar(pDLLName);

		//pModuleInfo->szModuleName此时是DLL自身，我们在重定向的时候要避免重定向为自身
		wsRedirectedDLLName = RedirectDLLPath(wcsDLLName, pModuleInfo->szModuleName, NULL);//这里是第一次调用RedirectDLLPath

		//todo：这里也改成从列表中查取？
		if (0 != wsRedirectedDLLName.size())
		{
			lpImportDLLAddr = GetModuleHandle(wsRedirectedDLLName.c_str());
		}
		else
		{
			lpImportDLLAddr = GetModuleHandle(wcsDLLName);//GetModuleHandle得到的是导入这个DLL的那个DLL的基地址
		}
		//获取"已经映射到调用进程中"的模块的句柄

		if (!lpImportDLLAddr)
		{
			FreeConvertedWchar(wcsDLLName);
			return FALSE;
		}

		if (!AnalyzePEInfo(lpImportDLLAddr, &ImportDLLInfo))
		{
			FreeConvertedWchar(wcsDLLName);
			return FALSE;
		}

		pSimulateFirstThunk = (PIMAGE_THUNK_DATA64)((BYTE*)pDllMemoryBuffer +
			pSimulateOriginImportTableVA->FirstThunk);
		pSimulateOriginFirstThunk = (PIMAGE_THUNK_DATA64)((BYTE*)pDllMemoryBuffer +
			pSimulateOriginImportTableVA->OriginalFirstThunk);

		while (pSimulateFirstThunk->u1.Function)
		{
			LPVOID ExportAddr = NULL;

			if (pSimulateOriginFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)//无名函数的情况，靠Ordinal
			{
				wOrdinal = pSimulateFirstThunk->u1.Ordinal & 0xFFFF;
				ExportAddr = GetExportFuncAddrByOrdinal(lpImportDLLAddr, &ImportDLLInfo, wOrdinal);
			}
			else
			{
				//拿到导入函数名，根据导入函数名，去查对应的DLL的导出函数地址
				wchar_t* wcsFuncName = NULL;
				pName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDllMemoryBuffer + pSimulateOriginFirstThunk->u1.AddressOfData);
				wcsFuncName = ConvertCharToWchar(pName->Name);

				ExportAddr = GetExportFuncAddrByName(lpImportDLLAddr, &ImportDLLInfo, wcsFuncName, pModuleInfo->szModuleName, wsRedirectedDLLName.c_str());
				FreeConvertedWchar(wcsFuncName);
			}

			//3、将导出表的函数填充到导入表中
			pSimulateFirstThunk->u1.AddressOfData = (ULONGLONG)ExportAddr;
			//2、遍历其导出表
			pSimulateOriginFirstThunk++;
			pSimulateFirstThunk++;
		}

		FreeConvertedWchar(wcsDLLName);
		pSimulateOriginImportTableVA++;
	}

	return TRUE;
}

LPVOID CR3APIHookScanner::FindWow64BaseAddrByName(const wchar_t* pName)
{
	CHECK_POINTER_NULL(pName, NULL);

	for (auto p : m_pScannedProcess->m_vecModuleInfo)
	{
		if (wcscmp(p->szModuleName, pName) == 0)
		{
			return p->pDllWow64BaseAddr;
		}
	}

	return NULL;
}

LPVOID CR3APIHookScanner::FindBaseAddrByName(const wchar_t* pName)
{
	CHECK_POINTER_NULL(pName, NULL);

	for (auto p : m_pScannedProcess->m_vecModuleInfo)
	{
		if (wcscmp(p->szModuleName, pName) == 0)
		{
			return p->pDllBaseAddr;
		}
	}

	return NULL;
}

BOOL CR3APIHookScanner::FixBaseRelocBlock(LPVOID, LPVOID)
{
	return TRUE;
}

BOOL CR3APIHookScanner::EnableDebugPrivelege()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
	{
		CloseHandle(hToken);
	}

	return TRUE;
}

//todo：突然想到32位程序模拟64位DLL可能还有问题
//todo：PE文件自己的导入表可能被Hook
BOOL CR3APIHookScanner::ScanModuleIATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
{
	CHECK_POINTER_NULL(pModuleInfo, FALSE);
	CHECK_POINTER_NULL(pDllMemoryBuffer, FALSE);

	try 
	{
		if (m_bIsWow64)
		{
			ScanModule32IATHookInner(pModuleInfo, pDllMemoryBuffer);
		}
		else
		{
			ScanModule64IATHookInner(pModuleInfo, pDllMemoryBuffer);
		}
	}
	catch (...)
	{
		printf("ScanModuleIATHook exception.\n");
		return FALSE;
	}
	

	return TRUE;
}

BOOL CR3APIHookScanner::ScanModule32IATHookInner(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
{
	DWORD dwOrdinal = 0;
	DWORD dwImportTableCount = 0;
	PIMAGE_IMPORT_DESCRIPTOR pOriginImportTableVA = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA = NULL;
	DWORD dwOriginImportTableSize = 0;
	PE_INFO SimulateDLLInfo = { 0 };
	PIMAGE_IMPORT_BY_NAME pName = NULL;
	PIMAGE_IMPORT_BY_NAME pSimulateName = NULL;
	PIMAGE_THUNK_DATA32 pFirstThunk = NULL;
	PIMAGE_THUNK_DATA32 pOriginFirstThunk = NULL;
	PIMAGE_THUNK_DATA32 pSimulateFirstThunk = NULL;
	PIMAGE_THUNK_DATA32 pSimulateOriginFirstThunk = NULL;

	if (m_OriginDLLInfo.dwImportDirRVA && m_OriginDLLInfo.dwImportDirSize > 0)
	{
		dwOriginImportTableSize = m_OriginDLLInfo.dwImportDirSize;
		pOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)(pModuleInfo->pDllWow64BaseAddr +
			m_OriginDLLInfo.dwImportDirRVA);
		pSimulateOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer +
			m_OriginDLLInfo.dwImportDirRVA);
		dwImportTableCount = m_OriginDLLInfo.dwImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);//相当于获取DLL的个数

		for (int i = 0; i < dwImportTableCount && pOriginImportTableVA->Name; i++)
		{
			char* pn = (char*)((BYTE*)pModuleInfo->pDllWow64BaseAddr + pOriginImportTableVA->Name);
			pFirstThunk = (PIMAGE_THUNK_DATA32)(pModuleInfo->pDllWow64BaseAddr +
				pOriginImportTableVA->FirstThunk);
			pOriginFirstThunk = (PIMAGE_THUNK_DATA32)(pModuleInfo->pDllWow64BaseAddr +
				pOriginImportTableVA->OriginalFirstThunk);
			pSimulateFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pDllMemoryBuffer +
				pOriginImportTableVA->FirstThunk);
			pSimulateOriginFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pDllMemoryBuffer +
				pOriginImportTableVA->OriginalFirstThunk);
			int j = 0;
			while (pFirstThunk->u1.Function)
			{
				j++;
				if (j == 572)
				{
					printf("");
				}
				BOOL bNoNameFunc = FALSE;
				if (pOriginFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
				{
					dwOrdinal = pOriginFirstThunk->u1.Ordinal & 0xFFFF;
					bNoNameFunc = TRUE;
				}
				else
				{
					pName = (PIMAGE_IMPORT_BY_NAME)(pModuleInfo->pDllWow64BaseAddr + pOriginFirstThunk->u1.AddressOfData);
					pSimulateName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDllMemoryBuffer + pOriginFirstThunk->u1.AddressOfData);

					/*printf("%d.%s		", j, pName->Name);
					printf("%d. 0x%016I64X\n", j, pFirstThunk->u1.Function);
					printf("%d.%s		", j, pSimulateName->Name);
					printf("%d. 0x%016I64X\n", j++, pSimulateFirstThunk->u1.Function);*/
				}

				if ((pFirstThunk->u1.Function != pSimulateFirstThunk->u1.Function) && (0 != pSimulateFirstThunk->u1.Function))
				{
					if (!bNoNameFunc)
					{
						wchar_t* wpName = ConvertCharToWchar(pName->Name);
						//todo：这里的LPVOID指针可能有问题
						SaveHookResult(HOOK_TYPE::IATHook, pModuleInfo->szModulePath, wpName, (LPVOID)&pFirstThunk->u1.Function, (LPVOID)pSimulateFirstThunk->u1.Function);
						FreeConvertedWchar(wpName);
					}
					else
					{
						SaveHookResult(HOOK_TYPE::IATHook, pModuleInfo->szModulePath, L"No Name", (LPVOID)&pFirstThunk->u1.Function, (LPVOID)pSimulateFirstThunk->u1.Function);
					}
				}

				pFirstThunk++;
				pOriginFirstThunk++;
				pSimulateFirstThunk++;
				pSimulateOriginFirstThunk++;
			}
			pOriginImportTableVA++;
		}
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanModule64IATHookInner(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
{
	DWORD dwOrdinal = 0;
	DWORD dwImportTableCount = 0;
	PIMAGE_IMPORT_DESCRIPTOR pOriginImportTableVA = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA = NULL;
	DWORD dwOriginImportTableSize = 0;
	PE_INFO SimulateDLLInfo = { 0 };
	PIMAGE_IMPORT_BY_NAME pName = NULL;
	PIMAGE_IMPORT_BY_NAME pSimulateName = NULL;
	PIMAGE_THUNK_DATA64 pFirstThunk = NULL;
	PIMAGE_THUNK_DATA64 pOriginFirstThunk = NULL;
	PIMAGE_THUNK_DATA64 pSimulateFirstThunk = NULL;
	PIMAGE_THUNK_DATA64 pSimulateOriginFirstThunk = NULL;

	//拿到内存中真实的DLL的信息
	//AnalyzePEInfo(pModuleInfo->pDllBaseAddr, &OriginDLLInfo); //IMAGE_IMPORT_DESCRIPTOR
	//检测exe的每个载入的DLL的导入函数的地址；为什么不是只检测exe的导入函数？
	if (m_OriginDLLInfo.dwImportDirRVA && m_OriginDLLInfo.dwImportDirSize > 0)
	{
		dwOriginImportTableSize = m_OriginDLLInfo.dwImportDirSize;
		pOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)(pModuleInfo->pDllBaseAddr +
			m_OriginDLLInfo.dwImportDirRVA);
		pSimulateOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer +
			m_OriginDLLInfo.dwImportDirRVA);
		dwImportTableCount = m_OriginDLLInfo.dwImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);//相当于获取DLL的个数

		for (int i = 0; i < dwImportTableCount && pOriginImportTableVA->Name; i++)
		{
			pFirstThunk = (PIMAGE_THUNK_DATA64)(pModuleInfo->pDllBaseAddr +
				pOriginImportTableVA->FirstThunk);
			pOriginFirstThunk = (PIMAGE_THUNK_DATA64)(pModuleInfo->pDllBaseAddr +
				pOriginImportTableVA->OriginalFirstThunk);
			pSimulateFirstThunk = (PIMAGE_THUNK_DATA64)((BYTE*)pDllMemoryBuffer +
				pOriginImportTableVA->FirstThunk);
			pSimulateOriginFirstThunk = (PIMAGE_THUNK_DATA64)((BYTE*)pDllMemoryBuffer +
				pOriginImportTableVA->OriginalFirstThunk);

			while (pFirstThunk->u1.Function)
			{
				BOOL bNoNameFunc = FALSE;
				if (pOriginFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)//无名函数的情况，靠Ordinal
				{
					dwOrdinal = pOriginFirstThunk->u1.Ordinal & 0xFFFF;
					bNoNameFunc = TRUE;
				}
				else
				{
					pName = (PIMAGE_IMPORT_BY_NAME)(pModuleInfo->pDllBaseAddr + pOriginFirstThunk->u1.AddressOfData);
					pSimulateName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDllMemoryBuffer + pOriginFirstThunk->u1.AddressOfData);

					/*printf("%d.%s		", j, pName->Name);
					printf("%d. 0x%016I64X\n", j, pFirstThunk->u1.Function);
					printf("%d.%s		", j, pSimulateName->Name);
					printf("%d. 0x%016I64X\n", j++, pSimulateFirstThunk->u1.Function);*/
				}

				if (pFirstThunk->u1.Function != pSimulateFirstThunk->u1.Function)
				{
					if (!bNoNameFunc)
					{
						wchar_t* wpName = ConvertCharToWchar(pName->Name);
						SaveHookResult(HOOK_TYPE::IATHook, pModuleInfo->szModulePath, wpName, (LPVOID)&pFirstThunk->u1.Function, (LPVOID)pSimulateFirstThunk->u1.Function);
						FreeConvertedWchar(wpName);
					}
					else
					{
						SaveHookResult(HOOK_TYPE::IATHook, pModuleInfo->szModulePath, L"No Name", (LPVOID)&pFirstThunk->u1.Function, (LPVOID)pSimulateFirstThunk->u1.Function);
					}
				}

				pFirstThunk++;
				pOriginFirstThunk++;
				pSimulateFirstThunk++;
				pSimulateOriginFirstThunk++;
			}
			pOriginImportTableVA++;
		}
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanModuleEATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
{
	CHECK_POINTER_NULL(pModuleInfo, FALSE);
	CHECK_POINTER_NULL(pDllMemoryBuffer, FALSE);
	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	PIMAGE_EXPORT_DIRECTORY pSimulateExportTable = NULL;
	DWORD* pExportFuncAddr = NULL;
	DWORD* pSimulateExportFuncAddr = NULL;
	DWORD* pExportFuncName = NULL;
	DWORD* pSimulateExportFuncName = NULL;
	WORD* pOrdinalAddr = NULL;
	WORD wOrdinal = 0;
	DWORD dwExportSize = 0;
	DWORD dwNoNameCount = 0;

	if (NULL == m_OriginDLLInfo.dwExportDirRVA || 0 == m_OriginDLLInfo.dwExportDirSize)
	{
		return FALSE;
	}

	try
	{
		//todo：检验这里对于Wow64的正确性
		pSimulateExportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pDllMemoryBuffer + m_OriginDLLInfo.dwExportDirRVA);
		pExportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pModuleInfo->pDllBaseAddr + m_OriginDLLInfo.dwExportDirRVA);
		pSimulateExportFuncAddr = (DWORD*)((BYTE*)pDllMemoryBuffer + pExportTable->AddressOfFunctions);
		pExportFuncAddr = (DWORD*)((BYTE*)pModuleInfo->pDllBaseAddr + pExportTable->AddressOfFunctions);
		pSimulateExportFuncName = (DWORD*)((BYTE*)pDllMemoryBuffer + pExportTable->AddressOfNames);
		pExportFuncName = (DWORD*)((BYTE*)pModuleInfo->pDllBaseAddr + pExportTable->AddressOfNames);
		pOrdinalAddr = (WORD*)((BYTE*)pModuleInfo->pDllBaseAddr + pExportTable->AddressOfNameOrdinals);
		dwNoNameCount = pExportTable->NumberOfFunctions - pExportTable->NumberOfNames;

		//AddressOfFunctions的无名导出函数是排在前几个的。
		for (int i = 0; i < dwNoNameCount; i++)
		{
			if (pSimulateExportFuncAddr[i] != pExportFuncAddr[i])
			{
				SaveHookResult(HOOK_TYPE::EATHook, pModuleInfo->szModulePath, L"No Name", (LPVOID)pExportFuncAddr[i], (LPVOID)pSimulateExportFuncAddr[i]);
				printf("EAT Hook found.\n");
			}
		}

		for (int i = 0; i < pExportTable->NumberOfNames; i++)
		{
			//实验证明pExportFuncName和pExportFuncAddr并不是根据i对应的，而是根据Ordinal联系上的

			//由于有无名导出函数在，这里这样拿名字会访问越界
			wOrdinal = pOrdinalAddr[i];
			char* pName = (char*)pModuleInfo->pDllBaseAddr + pExportFuncName[i];
			char* pSimName = (char*)pDllMemoryBuffer + pSimulateExportFuncName[i];
			/*char* pFunc = (char*)pModuleInfo->pDllBaseAddr + pExportFuncAddr[wOrdinal];
			char* pSimFunc = (char*)pDllMemoryBuffer + pSimulateExportFuncAddr[wOrdinal];*/

			//if ((((DWORD*)Eat)[NameOrd[i]] != ((DWORD*)OriEat)[NameOrd[i]]) && (OriApiAddress != ApiAddress))
			//这里必须要求是偏移和实际地址都相等。前者得到的是偏移。
			//

			//todo：未解决redirection的问题
			printf("ori name:%s		", pName);
			//printf("0x%016I64X\n", pFunc);
			printf("0x%016I64X\n", pExportFuncAddr[wOrdinal]);

			printf("sim name:%s		", pSimName);
			//printf("0x%016I64X\n", pSimFunc);
			printf("0x%016I64X\n\n", pSimulateExportFuncAddr[wOrdinal]);

			if (pSimulateExportFuncAddr[i] != pExportFuncAddr[i])
			{
				wchar_t* wpName = ConvertCharToWchar(pName);
				SaveHookResult(HOOK_TYPE::EATHook, pModuleInfo->szModulePath, wpName, (LPVOID)pExportFuncAddr[wOrdinal], (LPVOID)pSimulateExportFuncAddr[i]);
				FreeConvertedWchar(wpName);

				printf("EAT Hook found.\n");
			}
		}
	}
	catch (...)
	{
		printf("ScanModuleEATHook exception.\n");
		return FALSE;
	}

	return TRUE;
}
//
//BOOL CR3APIHookScanner::ScanModuleInlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
//{
//	CHECK_POINTER_NULL(pModuleInfo, FALSE);
//	CHECK_POINTER_NULL(pDllMemoryBuffer, FALSE);
//	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
//	PIMAGE_EXPORT_DIRECTORY pSimulateExportTable = NULL;
//	DWORD* pExportFuncAddr = NULL;
//	DWORD* pSimulateExportFuncAddr = NULL;
//	BYTE* pSimulateFuncEntry = NULL;
//	BYTE* pOriginFuncEntry = NULL;
//
//	if (NULL == m_OriginDLLInfo.dwExportDirRVA || 0 == m_OriginDLLInfo.dwExportDirSize)
//	{
//		return FALSE;
//	}
//
//	//todo：验证这里对于WOW64的正确性
//	pSimulateExportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pDllMemoryBuffer + m_OriginDLLInfo.dwExportDirRVA);
//	pExportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pModuleInfo->pDllBaseAddr + m_OriginDLLInfo.dwExportDirRVA);
//	pSimulateExportFuncAddr = (DWORD*)((BYTE*)pDllMemoryBuffer + pExportTable->AddressOfFunctions);
//	pExportFuncAddr = (DWORD*)((BYTE*)pModuleInfo->pDllBaseAddr + pExportTable->AddressOfFunctions);
//	DWORD* pSimulateExportFuncName = (DWORD*)((BYTE*)pDllMemoryBuffer + pExportTable->AddressOfNames);
//	DWORD* pExportFuncName = (DWORD*)((BYTE*)pModuleInfo->pDllBaseAddr + pExportTable->AddressOfNames);
//	WORD* pOrdinalAddr = (WORD*)((BYTE*)pModuleInfo->pDllBaseAddr + pExportTable->AddressOfNameOrdinals);
//
//	//todo：No Name
//	for (int i = 0; i < pExportTable->NumberOfNames; i++)
//	{
//		WORD wOrdinal = pOrdinalAddr[i];
//		char* pName = (char*)((UINT64)pModuleInfo->pDllBaseAddr + (UINT64)pExportFuncName[i]);
//		char* pSimName = (char*)((UINT64)pDllMemoryBuffer + (UINT64)pExportFuncName[i]);
//
//		pSimulateFuncEntry = (BYTE*)((UINT64)pDllMemoryBuffer + (UINT64)pSimulateExportFuncAddr[wOrdinal]);
//		pOriginFuncEntry = (BYTE*)((UINT64)pModuleInfo->pDllBaseAddr + (UINT64)pExportFuncAddr[wOrdinal]);
//
//		//todo：这里的检测长度需要更合理一些
//		if (memcmp(pSimulateFuncEntry, pOriginFuncEntry, INLINE_HOOK_LEN) != 0)
//		{
//			wchar_t* wpName = ConvertCharToWchar(pName);
//			SaveHookResult(HOOK_TYPE::InlineHook, pModuleInfo->szModulePath, wpName, pOriginFuncEntry, pSimulateFuncEntry);
//			FreeConvertedWchar(wpName);
//			printf("INLINE Hook found.\n");
//		}
//
//		printf("");
//	}
//
//	return TRUE;
//}

BOOL CR3APIHookScanner::ScanModuleInlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
{
	CHECK_POINTER_NULL(pModuleInfo, FALSE);
	CHECK_POINTER_NULL(pDllMemoryBuffer, FALSE);

	if (!m_OriginDLLInfo.dwImportDirRVA && m_OriginDLLInfo.dwImportDirSize <= 0)
	{
		return TRUE;
	}

	try
	{
		if (m_bIsWow64)
		{
			ScanModule32InlineHook(pModuleInfo, pDllMemoryBuffer);
		}
		else
		{
			ScanModule64InlineHook(pModuleInfo, pDllMemoryBuffer);
		}
	}
	catch (...)
	{
		printf("ScanModuleInlineHook exception.\n");
		return FALSE;
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanModule32InlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
{
	WORD wOrdinal = 0;
	DWORD dwImportTableCount = 0;
	PIMAGE_IMPORT_DESCRIPTOR pOriginImportTableVA = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA = NULL;
	DWORD dwOriginImportTableSize = 0;
	PIMAGE_IMPORT_BY_NAME pName = NULL;
	/*PIMAGE_THUNK_DATA pFirstThunk = NULL;
	PIMAGE_THUNK_DATA pOriginFirstThunk = NULL;*/
	PIMAGE_IMPORT_BY_NAME pSimulateName = NULL;
	PIMAGE_THUNK_DATA32 pSimulateFirstThunk = NULL;
	PIMAGE_THUNK_DATA32 pSimulateOriginFirstThunk = NULL;
	UINT64 ImportFuncOffset = 0;
	const char* pDLLName = NULL;
	wchar_t* wcsDLLName = NULL;

	dwOriginImportTableSize = m_OriginDLLInfo.dwImportDirSize;
	pSimulateOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer +
		m_OriginDLLInfo.dwImportDirRVA);
	pOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer +
		m_OriginDLLInfo.dwImportDirRVA);
	dwImportTableCount = m_OriginDLLInfo.dwImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);//相当于获取DLL的个数

	for (int i = 0; i < dwImportTableCount && pSimulateOriginImportTableVA->Name; i++)
	{
		HMODULE lpImportDLLAddr = NULL;
		std::wstring wsRedirectedDLLName;
		pDLLName = (char*)pDllMemoryBuffer + pSimulateOriginImportTableVA->Name;
		printf("Import DLL:%s\n", pDLLName);
		PE_INFO ImportDLLInfo = { 0 };
		wcsDLLName = ConvertCharToWchar(pDLLName);
		wsRedirectedDLLName = RedirectDLLPath(wcsDLLName, pModuleInfo->szModuleName, NULL);
		if (0 != wsRedirectedDLLName.size())
		{
			lpImportDLLAddr = GetModuleHandle(wsRedirectedDLLName.c_str());
		}
		else
		{
			lpImportDLLAddr = GetModuleHandle(wcsDLLName);
		}

		if (!lpImportDLLAddr)
		{
			FreeConvertedWchar(wcsDLLName);
			return FALSE;
		}
		AnalyzePEInfo(lpImportDLLAddr, &ImportDLLInfo);

		pSimulateFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pDllMemoryBuffer +
			pSimulateOriginImportTableVA->FirstThunk);
		pSimulateOriginFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pDllMemoryBuffer +
			pSimulateOriginImportTableVA->OriginalFirstThunk);

		while (pSimulateFirstThunk->u1.Function)
		{
			//todo：32位这里需要修改UINT64、LPVOID吗
			LPVOID ExportAddr = NULL;
			LPVOID lpSimDLLBase = NULL;

			if (pSimulateOriginFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)//无名函数的情况，靠Ordinal
			{
				wOrdinal = pSimulateOriginFirstThunk->u1.Ordinal & 0xFFFF;
				ExportAddr = GetExportFuncAddrByOrdinal(lpImportDLLAddr, &ImportDLLInfo, wOrdinal);
			}
			else
			{
				//拿到导入函数名，根据导入函数名，去查对应的DLL的导出函数地址
				wchar_t* wcsFuncName = NULL;
				pName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDllMemoryBuffer + pSimulateOriginFirstThunk->u1.AddressOfData);
				wcsFuncName = ConvertCharToWchar(pName->Name);
				ExportAddr = GetExportFuncAddrByName(lpImportDLLAddr, &ImportDLLInfo, wcsFuncName, pModuleInfo->szModuleName, wsRedirectedDLLName.c_str());
				FreeConvertedWchar(wcsFuncName);
			}

			for (auto p : m_pScannedProcess->m_vecModuleInfo)
			{
				if ((UINT64)ExportAddr > (UINT64)p->pDllBaseAddr && (UINT64)ExportAddr < (UINT64)p->pDllBaseAddr + p->dwSizeOfImage)
				{
					ImportFuncOffset = (UINT64)ExportAddr - (UINT64)p->pDllBaseAddr;
					lpSimDLLBase = GetModuleSimCache(p->szModulePath);
					break;
				}
			}

			if (!lpSimDLLBase)
			{
				continue;
			}

			if (memcmp((BYTE*)lpSimDLLBase + ImportFuncOffset, ExportAddr, INLINE_HOOK_LEN) != 0)
			{
				printf("IAT Inlie Hook.\n");
			}

			//2、遍历其导出表
			pSimulateOriginFirstThunk++;
			pSimulateFirstThunk++;
		}

		FreeConvertedWchar(wcsDLLName);
		pOriginImportTableVA++;
		pSimulateOriginImportTableVA++;
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanModule64InlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
{
	WORD wOrdinal = 0;
	DWORD dwImportTableCount = 0;
	PIMAGE_IMPORT_DESCRIPTOR pOriginImportTableVA = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA = NULL;
	DWORD dwOriginImportTableSize = 0;
	PIMAGE_IMPORT_BY_NAME pName = NULL;
	/*PIMAGE_THUNK_DATA pFirstThunk = NULL;
	PIMAGE_THUNK_DATA pOriginFirstThunk = NULL;*/
	PIMAGE_IMPORT_BY_NAME pSimulateName = NULL;
	PIMAGE_THUNK_DATA64 pSimulateFirstThunk = NULL;
	PIMAGE_THUNK_DATA64 pSimulateOriginFirstThunk = NULL;
	UINT64 ImportFuncOffset = 0;
	const char* pDLLName = NULL;
	wchar_t* wcsDLLName = NULL;

	dwOriginImportTableSize = m_OriginDLLInfo.dwImportDirSize;
	pSimulateOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer +
		m_OriginDLLInfo.dwImportDirRVA);
	pOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer +
		m_OriginDLLInfo.dwImportDirRVA);
	dwImportTableCount = m_OriginDLLInfo.dwImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);//相当于获取DLL的个数

	for (int i = 0; i < dwImportTableCount && pSimulateOriginImportTableVA->Name; i++)
	{
		HMODULE lpImportDLLAddr = NULL;
		std::wstring wsRedirectedDLLName;
		pDLLName = (char*)pDllMemoryBuffer + pSimulateOriginImportTableVA->Name;
		printf("Import DLL:%s\n", pDLLName);
		PE_INFO ImportDLLInfo = { 0 };
		wcsDLLName = ConvertCharToWchar(pDLLName);
		wsRedirectedDLLName = RedirectDLLPath(wcsDLLName, pModuleInfo->szModuleName, NULL);
		if (0 != wsRedirectedDLLName.size())
		{
			lpImportDLLAddr = GetModuleHandle(wsRedirectedDLLName.c_str());
		}
		else
		{
			lpImportDLLAddr = GetModuleHandle(wcsDLLName);//GetModuleHandle得到的是导入这个DLL的那个DLL的基地址
		}

		if (!lpImportDLLAddr)
		{
			FreeConvertedWchar(wcsDLLName);
			return FALSE;
		}
		AnalyzePEInfo(lpImportDLLAddr, &ImportDLLInfo);

		pSimulateFirstThunk = (PIMAGE_THUNK_DATA64)((BYTE*)pDllMemoryBuffer +
			pSimulateOriginImportTableVA->FirstThunk);
		pSimulateOriginFirstThunk = (PIMAGE_THUNK_DATA64)((BYTE*)pDllMemoryBuffer +
			pSimulateOriginImportTableVA->OriginalFirstThunk);

		//遍历导入函数
		while (pSimulateFirstThunk->u1.Function)
		{
			LPVOID ExportAddr = NULL;
			LPVOID lpSimDLLBase = NULL;

			if (pSimulateOriginFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)//无名函数的情况，靠Ordinal
			{
				wOrdinal = pSimulateOriginFirstThunk->u1.Ordinal & 0xFFFF;
				ExportAddr = GetExportFuncAddrByOrdinal(lpImportDLLAddr, &ImportDLLInfo, wOrdinal);
			}
			else
			{
				//拿到导入函数名，根据导入函数名，去查对应的DLL的导出函数地址
				wchar_t* wcsFuncName = NULL;
				pName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDllMemoryBuffer + pSimulateOriginFirstThunk->u1.AddressOfData);
				wcsFuncName = ConvertCharToWchar(pName->Name);
				ExportAddr = GetExportFuncAddrByName(lpImportDLLAddr, &ImportDLLInfo, wcsFuncName, pModuleInfo->szModuleName, wsRedirectedDLLName.c_str());
				FreeConvertedWchar(wcsFuncName);
			}

			for (auto p : m_pScannedProcess->m_vecModuleInfo)
			{
				if ((UINT64)ExportAddr > (UINT64)p->pDllBaseAddr && (UINT64)ExportAddr < (UINT64)p->pDllBaseAddr + p->dwSizeOfImage)
				{
					ImportFuncOffset = (UINT64)ExportAddr - (UINT64)p->pDllBaseAddr;
					lpSimDLLBase = GetModuleSimCache(p->szModulePath);
					break;
				}
			}

			if (!lpSimDLLBase)
			{
				continue;
			}

			//todo：待解决NlsMbCodePageTag这类函数不再code节的问题
			if (memcmp((BYTE*)lpSimDLLBase + ImportFuncOffset, ExportAddr, INLINE_HOOK_LEN) != 0)
			{
				printf("IAT Inlie Hook.\n");
			}

			//2、遍历其导出表
			pSimulateOriginFirstThunk++;
			pSimulateFirstThunk++;
		}

		FreeConvertedWchar(wcsDLLName);
		pOriginImportTableVA++;
		pSimulateOriginImportTableVA++;
	}

	return TRUE;
}
//
//BOOL CR3APIHookScanner::GetExportFuncsBoundary(PMODULE_INFO pModuleInfo, std::vector<UINT64>& vecOffsets)
//{
//	CHECK_POINTER_NULL(pModuleInfo, FALSE);
//	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
//	DWORD* pExportFuncAddr = NULL;
//	DWORD* pExportFuncName = NULL;
//	WORD* pOrdinalAddr = NULL;
//	WORD wOrdinal = 0;
//	DWORD dwExportSize = 0;
//	DWORD dwNoNameCount = 0;
//
//	if (NULL == m_OriginDLLInfo.dwExportDirRVA || 0 == m_OriginDLLInfo.dwExportDirSize)
//	{
//		return TRUE;
//	}
//
//	if ()//Wow64
//	{
//
//	}
//	else
//	{
//		pExportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pModuleInfo->pDllBaseAddr + m_OriginDLLInfo.dwExportDirRVA);
//		pExportFuncAddr = (DWORD*)((BYTE*)pModuleInfo->pDllBaseAddr + pExportTable->AddressOfFunctions);
//		for (int i = 0; i < pExportTable->NumberOfFunctions; i++)
//		{
//			vecOffsets.push_back(pExportFuncAddr[i]);
//		}
//	}
//
//	std::sort(vecOffsets.begin(), vecOffsets.end());
//
//	return TRUE;
//}

DWORD CR3APIHookScanner::AlignSize(const DWORD dwSize, const DWORD dwAlign)
{
	return ((dwSize + dwAlign - 1) / dwAlign * dwAlign);
}

LPVOID CR3APIHookScanner::GetExportFuncAddrByName(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, const wchar_t* pFuncName, const wchar_t* pBaseDLL, const wchar_t* pPreHostDLL)
{
	//这个pOriginDLLBase是用来查询导出表的DLL，不是需要修复的DLL
	CHECK_POINTER_NULL(pFuncName, NULL);
	CHECK_POINTER_NULL(pExportDLLBase, NULL);
	CHECK_POINTER_NULL(pExportDLLInfo, NULL);
	CHECK_POINTER_NULL(pBaseDLL, NULL);

	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	DWORD dwExportSize = 0;
	LPVOID lpExportFuncAddr = NULL;

	if (pExportDLLInfo->dwExportDirSize > 0 && pExportDLLInfo->dwExportDirRVA > 0)
	{
		pExportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pExportDLLBase + pExportDLLInfo->dwExportDirRVA);
		dwExportSize = pExportDLLInfo->dwExportDirSize;

		DWORD* pFuncAddresses = (DWORD*)((BYTE*)pExportDLLBase + pExportTable->AddressOfFunctions);
		WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)pExportDLLBase + pExportTable->AddressOfNameOrdinals);
		DWORD* pFuncNames = (DWORD*)((BYTE*)pExportDLLBase + pExportTable->AddressOfNames);

		for (int i = 0; i < pExportTable->NumberOfNames; i++)
		{
			char* pName = (char*)((BYTE*)pExportDLLBase + pFuncNames[i]);
			wchar_t* wcsFuncName = ConvertCharToWchar(pName);
			if (wcscmp(pFuncName, wcsFuncName) == 0)
			{
				WORD wOrdinal = pAddressOfNameOrdinals[i];
				FreeConvertedWchar(wcsFuncName);
				lpExportFuncAddr = (DWORD*)((BYTE*)pExportDLLBase + pFuncAddresses[wOrdinal]);

				break;
			}
			FreeConvertedWchar(wcsFuncName);
		}
	}

	//todo：这里32bit要改成UINT32吗
	if (((UINT64)lpExportFuncAddr > (UINT64)pExportTable) && ((UINT64)lpExportFuncAddr < (UINT64)pExportTable + dwExportSize))
	{
		//todo：redirection
		printf("");
		lpExportFuncAddr = RedirectionExportFuncAddr((char*)lpExportFuncAddr, pBaseDLL, pPreHostDLL);
	}

	return lpExportFuncAddr;
}

LPVOID CR3APIHookScanner::GetWow64ExportFuncAddrByName(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, LPVOID lpx86BaseAddr, const wchar_t* pFuncName, const wchar_t* pBaseDLL, const wchar_t* pPreHostDLL)
{
	LPVOID lpExportAddr = GetExportFuncAddrByName(pExportDLLBase, pExportDLLInfo, pFuncName, pBaseDLL, pPreHostDLL);
	if (NULL == lpExportAddr)
	{
		return NULL;
	}

	return (LPVOID)((UINT64)lpExportAddr - (UINT64)pExportDLLBase + (UINT64)lpx86BaseAddr);
}

LPVOID CR3APIHookScanner::GetExportFuncAddrByOrdinal(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, WORD wOrdinal)
{
	CHECK_POINTER_NULL(pExportDLLBase, NULL);
	CHECK_POINTER_NULL(pExportDLLInfo, NULL);

	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	DWORD dwExportSize = 0;

	if (pExportDLLInfo->dwExportDirSize > 0 && pExportDLLInfo->dwExportDirRVA > 0)
	{
		pExportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pExportDLLBase + pExportDLLInfo->dwExportDirRVA);
		dwExportSize = pExportDLLInfo->dwExportDirSize;
		DWORD* pFuncAddresses = (DWORD*)((BYTE*)pExportDLLBase + pExportTable->AddressOfFunctions);
		WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)pExportDLLBase + pExportTable->AddressOfNameOrdinals);
		DWORD* pFuncNames = (DWORD*)((BYTE*)pExportDLLBase + pExportTable->AddressOfNames);

		//todo：这里32bit要改成UINT32吗
		return (LPVOID)((UINT64)pExportDLLBase + (UINT64)pFuncAddresses[wOrdinal - pExportTable->Base]);
	}

	return NULL;
}

LPVOID CR3APIHookScanner::GetWow64ExportFuncAddrByOrdinal(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, LPVOID lpx86BaseAddr, WORD wOrdinal)
{
	LPVOID lpExportAddr = GetExportFuncAddrByOrdinal(pExportDLLBase, pExportDLLInfo, wOrdinal);
	if (NULL == lpExportAddr)
	{
		return NULL;
	}

	return (LPVOID)((UINT64)lpExportAddr - (UINT64)pExportDLLBase + (UINT64)lpx86BaseAddr);
}

BOOL CR3APIHookScanner::CbCollectProcessInfo(PPROCESS_INFO pProcessInfo, PBOOL pBreak)
{
	if (NULL == pProcessInfo || NULL == pBreak)
	{
		return FALSE;
	}

	//printf("Process:%ls		Id:%d\n", pProcessInfo->szProcessName, pProcessInfo->dwProcessId);
	m_vecProcessInfo.push_back(pProcessInfo);

	return TRUE;
}

BOOL CR3APIHookScanner::CbCollectModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo)
{
	CHECK_POINTER_NULL(pProcessInfo, FALSE);
	CHECK_POINTER_NULL(pModuleInfo, FALSE);

	pProcessInfo->m_vecModuleInfo.push_back(pModuleInfo);

	return TRUE;
}

typedef
NTSTATUS(NTAPI* Ptr_NtReadVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL);

typedef NTSTATUS(NTAPI* pfnNtWow64ReadVirtualMemory64)(
	IN HANDLE ProcessHandle,
	IN PVOID64 BaseAddress,
	OUT PVOID Buffer,
	IN ULONG64 Size,
	OUT PULONG64 NumberOfBytesRead
	);

BOOL WINAPI CR3APIHookScanner::CbCollectWow64ModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo)
{
	CHECK_POINTER_NULL(pProcessInfo, FALSE);
	CHECK_POINTER_NULL(pModuleInfo, FALSE);
	ULONG dwReadByte = 0;
	DWORD dwErrCode = 0;
	DWORD dwOldAttr = 0;
	pModuleInfo->pDllWow64BaseAddr = new(std::nothrow) BYTE[pModuleInfo->dwSizeOfImage];
	ZeroMemory(pModuleInfo->pDllWow64BaseAddr, pModuleInfo->dwSizeOfImage);
	if (NULL == pModuleInfo->pDllWow64BaseAddr)
	{
		return FALSE;
	}

	/*HMODULE hMods[1024];
	DWORD cbNeeded;*/
	//EnumProcessModulesEx(pProcessInfo->hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL);
	//for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	//{
	//	TCHAR szModName[MAX_PATH];

	//	// Get the full path to the module's file.

	//	if (GetModuleFileNameEx(pProcessInfo->hProcess, hMods[i], szModName,
	//		sizeof(szModName) / sizeof(TCHAR)))
	//	{
	//		// Print the module name and handle value.
	//		std::wstring s = szModName;
	//		printf("");
	//		//_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
	//	}
	//}

	/*HMODULE hModule = LoadLibrary(TEXT("Ntdll.dll "));
	Ptr_NtReadVirtualMemory NtReadVirtualMemory = (Ptr_NtReadVirtualMemory)GetProcAddress(hModule, "NtReadVirtualMemory");*/

	//pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
	//pfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (pfnNtWow64ReadVirtualMemory64)GetProcAddress(hModule, "NtWow64ReadVirtualMemory64");
	
	/*PMEMORY_BASIC_INFORMATION pmbi = new MEMORY_BASIC_INFORMATION;
	if (VirtualQueryEx(pProcessInfo->hProcess, (LPVOID)pModuleInfo->pDllBaseAddr, pmbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		cout << "protection :" << pmbi->AllocationProtect << endl;
	}*/

	VirtualProtectEx(pProcessInfo->hProcess, pModuleInfo->pDllBaseAddr, pModuleInfo->dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldAttr);
	/*dwErrCode = GetLastError();
	NtReadVirtualMemory(pProcessInfo->hProcess, pModuleInfo->pDllBaseAddr, pModuleInfo->pDllWow64BaseAddr, pModuleInfo->dwSizeOfImage, NULL);
	dwErrCode = GetLastError();*/
	//todo：读取kernel32.dll内存失败
	ReadProcessMemory(pProcessInfo->hProcess, pModuleInfo->pDllBaseAddr, pModuleInfo->pDllWow64BaseAddr, pModuleInfo->dwSizeOfImage, 0);
	dwErrCode = GetLastError();
	//NtWow64ReadVirtualMemory64(pProcessInfo->hProcess, pModuleInfo->pDllBaseAddr, pModuleInfo->pDllWow64BaseAddr, pModuleInfo->dwSizeOfImage, NULL);
	VirtualProtectEx(pProcessInfo->hProcess, pModuleInfo->pDllBaseAddr, pModuleInfo->dwSizeOfImage, dwOldAttr, NULL);
	pProcessInfo->m_vecModuleInfo.push_back(pModuleInfo);

	//FreeLibrary(hModule);
	return TRUE;
}

BOOL CR3APIHookScanner::CbRemoveModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo)
{
	CHECK_POINTER_NULL(pProcessInfo, FALSE);
	CHECK_POINTER_NULL(pModuleInfo, FALSE);

	std::vector<MODULE_INFO*>::iterator iter = pProcessInfo->m_vecModuleInfo.begin();
	while (iter != pProcessInfo->m_vecModuleInfo.end())
	{
		if (wcscmp(pModuleInfo->szModulePath, (*iter)->szModulePath) == 0)
		{
			if ((*iter)->pDllWow64BaseAddr)
			{
				delete[](*iter)->pDllWow64BaseAddr;
				(*iter)->pDllWow64BaseAddr = NULL;
			}
			pProcessInfo->m_vecModuleInfo.erase(iter);
			
			break;
		}
		iter++;
	}

	return TRUE;
}

wchar_t* CR3APIHookScanner::ConvertCharToWchar(const char* p)
{
	wchar_t* wp = NULL;
	size_t len = strlen(p) + 1;
	size_t nConverted = 0;
	wp = (wchar_t*)malloc(len * sizeof(wchar_t));
	if (!wp)
	{
		return NULL;
	}

	mbstowcs_s(&nConverted, wp, len, p, _TRUNCATE);
	if (0 == nConverted)
	{
		free(wp);
		return NULL;
	}

	return wp;
}

VOID CR3APIHookScanner::FreeConvertedWchar(wchar_t* &p)
{
	if (p)
	{
		free(p);
		p = NULL;
	}
	
	return;
}

std::wstring CR3APIHookScanner::RedirectDLLPath(const wchar_t* path, const wchar_t* pBaseDLL, const wchar_t* pPreHostDLL)
{
	CHECK_POINTER_NULL(path, L"");
	CHECK_POINTER_NULL(pBaseDLL, L"");

	std::wstring filename = path;
	std::wstring wsPreHostDLL;
	std::wstring wsBaseDLL;
	wsBaseDLL = pBaseDLL;
	if (!pPreHostDLL)
	{
		wsPreHostDLL = L"";
	}
	else
	{
		wsPreHostDLL = pPreHostDLL;
	}
	//
	// ApiSchema redirection
	//
	auto iter = std::find_if(m_mapApiSchema.begin(), m_mapApiSchema.end(), [&filename](const auto& val) {
		return filename.find(val.first.c_str()) != filename.npos; });

	//todo：列表中如果不止有一个该怎么办
	if (iter != m_mapApiSchema.end())
	{
		// Select appropriate api host
		if (_wcsicmp(iter->second.front().c_str(), wsBaseDLL.c_str()) != 0 &&
			_wcsicmp(iter->second.front().c_str() , wsPreHostDLL.c_str()) != 0)
		{
			return iter->second.front();
		}

		return iter->second.back();
		//return _wcsicmp(iter->second.front().c_str(), wsBaseDLL.c_str()) != 0 ? iter->second.front() : iter->second.back();
		//return iter->second.front() != wsBaseDLL ? iter->second.front() : iter->second.back();
	}

	return L"";
}
//
//typedef NTSTATUS(NTAPI* fnRtlDosApplyFileIsolationRedirection_Ustr)(
//	IN ULONG Flags,
//	IN PUNICODE_STRING OriginalName,
//	IN PUNICODE_STRING Extension,
//	IN OUT PUNICODE_STRING StaticString,
//	IN OUT PUNICODE_STRING DynamicString,
//	IN OUT PUNICODE_STRING* NewName,
//	IN PULONG  NewFlags,
//	IN PSIZE_T FileNameSize,
//	IN PSIZE_T RequiredLength
//	);
//

typedef NTSTATUS(NTAPI* fnRtlDosApplyFileIsolationRedirection_Ustr)(
	IN ULONG Flags,
	IN PUNICODE_STRING OriginalName,
	IN PUNICODE_STRING Extension,
	IN OUT PUNICODE_STRING StaticString,
	IN OUT PUNICODE_STRING DynamicString,
	IN OUT PUNICODE_STRING* NewName,
	IN PULONG  NewFlags,
	IN PSIZE_T FileNameSize,
	IN PSIZE_T RequiredLength
	);
typedef VOID(NTAPI* fnRtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

BOOL CR3APIHookScanner::ProbeSxSRedirect(std::wstring& path)
{
	UNICODE_STRING OriginalName = { 0 };
	UNICODE_STRING DllName1 = { 0 };
	UNICODE_STRING DllName2 = { 0 };
	PUNICODE_STRING pPath = nullptr;
	ULONG_PTR cookie = 0;
	wchar_t wBuf[255];
	path = L"C://Windows//WinSxS//amd64_microsoft-windows-m..namespace-downlevel_31bf3856ad364e35_10.0.19041.1_none_f1842539350f99e4//api-ms-win-eventing-provider-l1-1-0.dll";
	//// No underlying function
	////if (GET_IMPORT(RtlDosApplyFileIsolationRedirection_Ustr) == nullptr)
	////	return STATUS_ORDINAL_NOT_FOUND;
	fnRtlInitUnicodeString pRtlInitUnicodeString = NULL;
	HMODULE hMod = LoadLibrary(L"ntdll.dll");
	pRtlInitUnicodeString = (fnRtlInitUnicodeString)GetProcAddress(hMod, "RtlInitUnicodeString");
	pRtlInitUnicodeString(&OriginalName, path.c_str());

	DllName1.Buffer = wBuf;
	DllName1.Length = NULL;
	DllName1.MaximumLength = sizeof(wBuf);

	// Use activation context
	/*if (actx != INVALID_HANDLE_VALUE)
		ActivateActCtx(actx, &cookie);*/
	//ActivateActCtx(actx, &cookie);
		 //SxS resolve
		/*NTSTATUS status = SAFE_NATIVE_CALL(
			RtlDosApplyFileIsolationRedirection_Ustr, TRUE, &OriginalName, (PUNICODE_STRING)NULL,
			&DllName1, &DllName2, &pPath,
			nullptr, nullptr, nullptr
		);*/
	fnRtlDosApplyFileIsolationRedirection_Ustr RtlDosApplyFileIsolationRedirection_Ustr = NULL;
	RtlDosApplyFileIsolationRedirection_Ustr = (fnRtlDosApplyFileIsolationRedirection_Ustr)GetProcAddress(hMod, "RtlDosApplyFileIsolationRedirection_Ustr");
	RtlDosApplyFileIsolationRedirection_Ustr(TRUE, &OriginalName, (PUNICODE_STRING)NULL,
		&DllName1, &DllName2, &pPath,
		nullptr, nullptr, nullptr);

	//if (cookie != 0 && actx != INVALID_HANDLE_VALUE)
	//	DeactivateActCtx(0, cookie);

	//if (status == STATUS_SUCCESS)
	//{
	//	// Arch mismatch, local SxS redirection is incorrect
	//	if (proc.barrier().mismatch)
	//		return STATUS_SXS_IDENTITIES_DIFFERENT;
	//	else
	//		path = pPath->Buffer;
	//}
	//else
	//{
	//	if (DllName2.Buffer)
	//		SAFE_CALL(RtlFreeUnicodeString, &DllName2);
	//}

	return TRUE;
}

LPVOID CR3APIHookScanner::RedirectionExportFuncAddr(const char* lpExportFuncAddr, const wchar_t* pBaseDLL, const wchar_t* pPreHostDLL)
{
	CHECK_POINTER_NULL(lpExportFuncAddr, FALSE);
	UINT uLen = 0;
	char* ptr = NULL;
	char* pDLLName = NULL;
	char* pFuncName = NULL;
	wchar_t* wpDLLName = NULL;
	wchar_t* wpFuncName = NULL;
	HMODULE pExportDLLAddr = NULL;
	char szFuncName[0x50] = { 0 };
	PE_INFO ExportDLLINfo = { 0 };
	LPVOID lpRedirectedExportFuncAddr = NULL;
	std::wstring wsRedirectedDLLName;

	uLen = strlen(lpExportFuncAddr);
	memcpy_s(szFuncName, uLen, lpExportFuncAddr, uLen);
	ptr = strchr(szFuncName, '.');
	if (!ptr)
	{
		return NULL;
	}

	*ptr = 0;
	pDLLName = szFuncName;
	pFuncName = ptr + 1;

	wpDLLName = ConvertCharToWchar(pDLLName);
	wpFuncName = ConvertCharToWchar(pFuncName);

	wsRedirectedDLLName = RedirectDLLPath(wpDLLName, pBaseDLL, pPreHostDLL);
	if (0 != wsRedirectedDLLName.size())
	{
		pExportDLLAddr = GetModuleHandle(wsRedirectedDLLName.c_str());
	}
	else
	{
		pExportDLLAddr = GetModuleHandle(wpDLLName);//GetModuleHandle得到的是导入这个DLL的那个DLL的基地址
	}

	//todo：是否可以把用到的都缓存下来
	AnalyzePEInfo(pExportDLLAddr, &ExportDLLINfo);
	lpRedirectedExportFuncAddr = GetExportFuncAddrByName(pExportDLLAddr, &ExportDLLINfo, wpFuncName, pBaseDLL, wsRedirectedDLLName.c_str());
	FreeConvertedWchar(wpDLLName);
	FreeConvertedWchar(wpFuncName);

	return lpRedirectedExportFuncAddr;
}

BOOL CR3APIHookScanner::LoadALLModuleSimCache(PPROCESS_INFO pProcessInfo)
{
	CHECK_POINTER_NULL(pProcessInfo, FALSE);

	//直接把待分析的DLL都缓存下来
	for (auto pModuleInfo : pProcessInfo->m_vecModuleInfo)
	{
		LPVOID lpSimDLLBuffer = SimulateLoadDLL(pModuleInfo);
		m_mapSimDLLCache.insert(std::make_pair(pModuleInfo->szModulePath, lpSimDLLBuffer));
	}

	return TRUE;
}

VOID CR3APIHookScanner::ReleaseALLModuleSimCache()
{
	for (auto p : m_mapSimDLLCache) {
		FreeSimulateDLL(&p.second);
	}
}

LPVOID CR3APIHookScanner::GetModuleSimCache(const wchar_t* pModulePath)
{
	return m_mapSimDLLCache[pModulePath];
}

VOID CR3APIHookScanner::SaveHookResult(HOOK_TYPE type, const wchar_t* pModulePath, const wchar_t* pFunc, LPVOID pHookedAddr, LPVOID lpRecoverAddr)
{
	HOOK_RESULT HookResult = { 0 };
	HookResult.lpHookedAddr = pHookedAddr;
	HookResult.lpRecoverAddr = lpRecoverAddr;
	HookResult.bIsHooked = TRUE;
	HookResult.type = HOOK_TYPE::IATHook;
	
	memset((void*)HookResult.szModule, 0, sizeof(wchar_t) * MAX_MODULE_PATH_LEN);
	if (pModulePath)
	{
		int n = wcslen(pModulePath);
		wcscpy_s((wchar_t*)HookResult.szModule, wcslen(pModulePath) + 1, (wchar_t*)pModulePath);
	}

	memset((void*)HookResult.szFuncName, 0, sizeof(wchar_t) * MAX_FUNCTION_NAME);
	if (pFunc)
	{
		wcscpy_s((wchar_t*)HookResult.szFuncName, wcslen(pFunc) + 1, (wchar_t*)pFunc);

	}

	m_vecHookRes.push_back(HookResult);

	return;
}

//todo:摘钩子时要考虑挂起线程的情况
BOOL CR3APIHookScanner::UnHook()
{
	PPROCESS_INFO pProcessInfo = GetScannedProcess();
	if (!pProcessInfo)
	{
		return FALSE;
	}

	for (auto p : m_vecHookRes)
	{
		DWORD dwOldAttr = 0;

		switch (p.type)
		{
		case HOOK_TYPE::IATHook:
		{
			//todo：这里的代码是否可以抽象
			if (m_bIsWow64)
			{
				VirtualProtectEx(pProcessInfo, p.lpHookedAddr, 4, PAGE_EXECUTE_READWRITE, &dwOldAttr);
				//todo：检测32bit这里的数据是否正确p.lpRecoverAddr
				WriteProcessMemory(pProcessInfo, p.lpHookedAddr, p.lpRecoverAddr, 4, NULL);
				VirtualProtectEx(pProcessInfo, p.lpHookedAddr, 4, dwOldAttr, NULL);
			}
			else
			{
				//恢复导入表中的VA
				VirtualProtectEx(pProcessInfo, p.lpHookedAddr, 8, PAGE_EXECUTE_READWRITE, &dwOldAttr);
				WriteProcessMemory(pProcessInfo, p.lpHookedAddr, p.lpRecoverAddr, 8, NULL);
				VirtualProtectEx(pProcessInfo, p.lpHookedAddr, 8, dwOldAttr, NULL);
			}
			
			break;
		}
		case HOOK_TYPE::EATHook:
		{
			//恢复导出表中的偏移
			VirtualProtectEx(pProcessInfo, p.lpHookedAddr, 4, PAGE_EXECUTE_READWRITE, &dwOldAttr);
			WriteProcessMemory(pProcessInfo, p.lpHookedAddr, p.lpRecoverAddr, 4, NULL);
			VirtualProtectEx(pProcessInfo, p.lpHookedAddr, 4, dwOldAttr, NULL);
			break;
		}
		case HOOK_TYPE::InlineHook:
		{
			//todo：恢复时挂起所有线程
			//todo：如何修复InlineHook？不能只是粗暴的替换text节区，使用INLINE_HOOK_LEN又可能有遗漏
			VirtualProtectEx(pProcessInfo, p.lpHookedAddr, INLINE_HOOK_LEN, PAGE_EXECUTE_READWRITE, &dwOldAttr);
			WriteProcessMemory(pProcessInfo, p.lpHookedAddr, p.lpRecoverAddr, INLINE_HOOK_LEN, NULL);
			VirtualProtectEx(pProcessInfo, p.lpHookedAddr, INLINE_HOOK_LEN, dwOldAttr, NULL);
			break;
		}
		default:
			break;
		}
	}
	return TRUE;
}

BOOL CR3APIHookScanner::UnHook(DWORD dwProcessId, LPVOID lpModule, LPVOID lpFunc)
{

	return TRUE;
}