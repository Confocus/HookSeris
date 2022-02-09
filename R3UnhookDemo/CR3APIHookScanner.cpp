#include "CR3APIHookScanner.h"
#include <TlHelp32.h>

vector<PROCESS_INFO*> CR3APIHookScanner::m_vecProcessInfo;//无法解析的外部符号
//vector<MODULE_INFO*> CR3APIHookScanner::m_vecModuleInfo;

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
	EnableDebugPrivelege();
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
		EmurateModules(pProcessInfo, CbCollectModuleInfo);
		//todo：考虑进程消失的情况和进程ID变动的情况
		//ScanSingleProcessById(pProcessInfo->dwProcessId);
		//ScanSingle(pProcessInfo);
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanSingleProcessById(DWORD dwProcessId)
{
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
		if (dwProcessId == pProcessInfo->dwProcessId)
		{
			EmurateModules(pProcessInfo, CbCollectModuleInfo);
			//todo：考虑进程消失的情况和进程ID变动的情况
			//ScanSingleProcessById(pProcessInfo->dwProcessId);
			ScanSingle(pProcessInfo);
		}
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanSingleProcessByName(CONST PCHAR pProcessName)
{
	return TRUE;
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
	BOOL bNext = FALSE;
	BOOL bCbRet = FALSE;
	BOOL bBreak = FALSE;
	DWORD dwErrCode = 0;

	PROCESSENTRY32	ProcessEntry32;
	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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

BOOL CR3APIHookScanner::EmurateModules(PPROCESS_INFO pProcessInfo, CALLBACK_EMUNMODULE pCallbackFunc)
{
	//todo：貌似有区别	TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE ??
	if (NULL == pProcessInfo)
	{
		return FALSE;
	}

	BOOL bNext = FALSE;
	wstring wcsSuffix;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pProcessInfo->dwProcessId);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return FALSE;
	}

	MODULEENTRY32 ModuleEntry32 = { 0 };
	ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
	bNext = Module32FirstW(hSnapshot, &ModuleEntry32);
	while (bNext)
	{
		wstring wcsModuleName = ModuleEntry32.szModule;
		wcsSuffix = wcsModuleName.substr(wcsModuleName.find_last_of('.') + 1);
		if (0 != wcsSuffix.compare(L"dll"))
		{
			bNext = Module32Next(hSnapshot, &ModuleEntry32);
			continue;
		}
		
		PMODULE_INFO pModuleInfo = NULL;
		pModuleInfo = new(std::nothrow) MODULE_INFO();
		if (pModuleInfo)
		{
			//保存ModuleInfo中必要的数据
			pProcessInfo->dwModuleCount++;
			ZeroMemory(pModuleInfo, sizeof(PMODULE_INFO));
			pModuleInfo->pDllBaseAddr = ModuleEntry32.modBaseAddr;
			pModuleInfo->dwSizeOfImage = ModuleEntry32.modBaseSize;
			wmemcpy_s(pModuleInfo->szModuleName, MAX_MODULE_LEN, ModuleEntry32.szModule, wcslen(ModuleEntry32.szModule));
			wmemcpy_s(pModuleInfo->szModulePath, MAX_MODULE_PATH, ModuleEntry32.szExePath, wcslen(ModuleEntry32.szExePath));
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

BOOL CR3APIHookScanner::ScanSingle(PPROCESS_INFO pProcessInfo)
{
	if (NULL == pProcessInfo)
	{
		return FALSE;
	}

	//todo：验证这个pid对应的是之前的那个程序
	BOOL bIsWow64 = FALSE;
	DWORD dwErrCode = 0;
	HANDLE hProcess = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pProcessInfo->dwProcessId);
	if (NULL == hProcess)
	{
		dwErrCode = GetLastError();
		return FALSE;
	}

	IsWow64Process(hProcess, &bIsWow64);
	for (auto pModuleInfo : pProcessInfo->m_vecModuleInfo)
	{
		//peLoad(Info.FullName, Info.DllBase, Info.DiskImage, Info.SizeOfImage);
		LPVOID pDllMemBuffer = NULL;
		pDllMemBuffer = LoadDllImage(pModuleInfo);
		if (NULL != pDllMemBuffer)
		{
			//用模拟载入内存后的dll和内存中真实的dll进行比较
			DetectSingleModuleInlineHook(pModuleInfo, pDllMemBuffer);
			ReleaseDllMemoryBuffer(&pDllMemBuffer);
		}
	}

	CloseHandle(hProcess);

	return TRUE;
}

LPVOID CR3APIHookScanner::LoadDllImage(PMODULE_INFO pModuleInfo)
{
	if (NULL == pModuleInfo)
	{
		return NULL;
	}
	printf("Load Dll path:%ls\n", pModuleInfo->szModulePath);

	HANDLE hFile = NULL;
	DWORD dwNumberOfBytesRead = 0;
	const DWORD dwBufferSize = pModuleInfo->dwSizeOfImage;
	//DLL磁盘上的样子
	LPVOID pDllImageBuffer = NULL;
	//DLL模拟载入内存中的样子
	LPVOID pDllMemoryBuffer = NULL;
	PE_INFO PEInfo = { 0 };

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
			if (!ReadFile(hFile, pDllImageBuffer, dwBufferSize, &dwNumberOfBytesRead, NULL))
			{
				break;
			}

			AnalyzePEInfo(pDllImageBuffer, &PEInfo);

			//DLL镜像模拟DLL内存展开后的格式
			//将所有节区的数据保存
			for (int i = 0; i < PEInfo.dwSectionCnt; i++)
			{
				DWORD dwSizeOfRawData = AlignSize(PEInfo.szSectionHeader[i].SizeOfRawData, PEInfo.dwFileAlign);
				//printf("ddd:%d", dwSizeOfRawData);
				memcpy_s((LPVOID)((UINT64)pDllMemoryBuffer + PEInfo.szSectionHeader[i].VirtualAddress),
					dwSizeOfRawData,
					(LPVOID)((UINT64)pDllImageBuffer + PEInfo.szSectionHeader[i].PointerToRawData),
					dwSizeOfRawData);
			}

		}

		//FixRelocData();

	} while (FALSE);

	if (pDllImageBuffer)
	{
		delete[] pDllImageBuffer;
		pDllImageBuffer = NULL;
	}

	/*if (pDllMemoryBuffer)
	{
		delete[] pDllMemoryBuffer;
		pDllMemoryBuffer = NULL;
	}*/

	CloseHandle(hFile);

	return pDllMemoryBuffer;
}

VOID CR3APIHookScanner::ReleaseDllMemoryBuffer(LPVOID* ppDllMemoryBuffer)
{
	if (*ppDllMemoryBuffer)
	{
		delete[] *ppDllMemoryBuffer;
		*ppDllMemoryBuffer = NULL;
	}
}

BOOL CR3APIHookScanner::AnalyzePEInfo(LPVOID pBuffer, PPE_INFO pPeInfo)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = NULL;
	if (m_bIsWow64)
	{

	}
	else
	{
		pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
		if (IMAGE_DOS_SIGNATURE == pDosHeader->e_magic)
		{
			pPeInfo->pPeHeader = (PIMAGE_NT_HEADERS64)((UINT64)pBuffer + pDosHeader->e_lfanew);
			if (IMAGE_NT_SIGNATURE == pPeInfo->pPeHeader->Signature)
			{
				pPeInfo->szSectionHeader = IMAGE_FIRST_SECTION(pPeInfo->pPeHeader);
				pPeInfo->dwSectionCnt = pPeInfo->pPeHeader->FileHeader.NumberOfSections;
				pOptionalHeader64 = &(pPeInfo->pPeHeader->OptionalHeader);

				//后面在内存中展开需要用到Align
				pPeInfo->dwFileAlign = pOptionalHeader64->FileAlignment;
				pPeInfo->dwSectionAlign = pOptionalHeader64->SectionAlignment;

				//后面获取函数地址要用到
				pPeInfo->dwExportDirRVA = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
				pPeInfo->dwExportDirSize = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
				pPeInfo->dwImportDirRVA = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
				pPeInfo->dwImportDirSize = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
			}
		}
	}

	return TRUE;
}

BOOL CR3APIHookScanner::FixRelocData(LPVOID pBuffer, PPE_INFO pPeInfo)
{
	if (NULL == pBuffer || NULL == pPeInfo)
	{
		return FALSE;
	}

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

BOOL CR3APIHookScanner::DetectSingleModuleInlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
{
	return TRUE;
}

DWORD CR3APIHookScanner::AlignSize(const DWORD dwSize, const DWORD dwAlign)
{
	return ((dwSize + dwAlign - 1) / dwAlign * dwAlign);
}

BOOL CR3APIHookScanner::CbCollectProcessInfo(PPROCESS_INFO pProcessInfo, PBOOL pBreak)
{
	if (NULL == pProcessInfo || NULL == pBreak)
	{
		return FALSE;
	}

	printf("Process:%ls		Id:%d\n", pProcessInfo->szProcessName, pProcessInfo->dwProcessId);
	m_vecProcessInfo.push_back(pProcessInfo);

	return TRUE;
}

BOOL CR3APIHookScanner::CbCollectModuleInfo(PPROCESS_INFO pProcessInfo, PMODULE_INFO pModuleInfo)
{
	if (NULL == pModuleInfo || NULL == pProcessInfo)
	{
		return FALSE;
	}

	printf("Module:%ls\n", pModuleInfo->szModuleName);
	pProcessInfo->m_vecModuleInfo.push_back(pModuleInfo);

	return TRUE;
}