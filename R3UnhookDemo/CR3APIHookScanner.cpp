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
	m_OriginDLLInfo = { 0 };
	m_SimulateDLLInfo = { 0 };
	m_ImageInfo = { 0 };

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
		//记住当前正在扫描的那个进程
		m_pCurProcess = pProcessInfo;
		//找到我们要扫描的那个进程
		if (dwProcessId == pProcessInfo->dwProcessId)
		{
			EmurateModules(pProcessInfo, CbCollectModuleInfo);
			//todo：考虑进程消失的情况和进程ID变动的情况
			//ScanSingleProcessById(pProcessInfo->dwProcessId);
			ScanSingle(pProcessInfo);
			break;
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

	//遍历这个进程中的所有模块
	//todo:也要考虑快照的时效性的问题
	for (auto pModuleInfo : pProcessInfo->m_vecModuleInfo)
	{
		//peLoad(Info.FullName, Info.DllBase, Info.DiskImage, Info.SizeOfImage);
		LPVOID pDllMemBuffer = NULL;
		AnalyzePEInfo(pModuleInfo->pDllBaseAddr, &m_OriginDLLInfo);

		pDllMemBuffer = SimulateLoadDLL(pModuleInfo);
		if (NULL != pDllMemBuffer)
		{
			//IAT HOOK扫描，所谓的IAT Hook，是篡改了导入表导入函数的地址
			ScanSingleModuleIATHook(pModuleInfo, pDllMemBuffer);
			//用模拟载入内存后的dll和内存中真实的dll进行比较
			//这里的InlineHook其实就是EAT Hook，所谓的EAT Hook，就是跳转到函数执行的内部，然后修改了指令。PE从导入表中拿到一个函数的地址
			//然后跳到这个函数的内部执行
			//ScanSingleModuleInlineHook(pModuleInfo, pDllMemBuffer);
			//ReleaseDllMemoryBuffer(&pDllMemBuffer);
		}
	}

	CloseHandle(hProcess);

	return TRUE;
}

LPVOID CR3APIHookScanner::SimulateLoadDLL(PMODULE_INFO pModuleInfo)
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
	PE_INFO PEImageInfo = { 0 };

	do 
	{
		hFile = CreateFile(pModuleInfo->szModulePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			break;
		}

		//todo：其实这里是否只需要载入导入表的数据就行，不必把全部镜像的数据载入
		pDllImageBuffer = new(std::nothrow) BYTE[dwBufferSize];
		pDllMemoryBuffer = new(std::nothrow) BYTE[dwBufferSize];

		if (pDllImageBuffer && pDllMemoryBuffer)
		{
			ZeroMemory(pDllMemoryBuffer, dwBufferSize);
			//将DLL的二进制文件读入内存
			if (!ReadFile(hFile, pDllImageBuffer, dwBufferSize, &dwNumberOfBytesRead, NULL))
			{
				break;
			}

			//解析的是DLL的文件镜像的PE结构
			if (!AnalyzePEInfo(pDllImageBuffer, &PEImageInfo))
			{
				break;
			}

			//DLL镜像模拟DLL内存展开后的格式
			//将所有节区的数据保存
			for (int i = 0; i < PEImageInfo.dwSectionCnt; i++)
			{
				DWORD dwSizeOfRawData = AlignSize(PEImageInfo.szSectionHeader[i].SizeOfRawData, PEImageInfo.dwFileAlign);
				//printf("ddd:%d", dwSizeOfRawData);
				memcpy_s((LPVOID)((UINT64)pDllMemoryBuffer + PEImageInfo.szSectionHeader[i].VirtualAddress),
					dwSizeOfRawData,
					(LPVOID)((UINT64)pDllImageBuffer + PEImageInfo.szSectionHeader[i].PointerToRawData),
					dwSizeOfRawData);
			}
		}

		//todo：修复导入表
		//todo：修复重定位数据
		FixBaseReloc(pDllMemoryBuffer, &PEImageInfo, pModuleInfo->pDllBaseAddr);
		BuildImportTable(pDllMemoryBuffer, &PEImageInfo, pModuleInfo->pDllBaseAddr);
	} while (FALSE);

	if (pDllImageBuffer)
	{
		delete[] pDllImageBuffer;
		pDllImageBuffer = NULL;
	}

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
	BOOL bRet = FALSE;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = NULL;

	//todo：测试这里错误指针是否会捕获异常
	try
	{
		//todo：Wow64会的区别
		//todo：Wow64进程有无影响——有影响，32位进程和64位进程地址空间不同
		//这里要判断的是被打开的进程是32位还是64位，被打开的进程是64位我们就要模拟64位空间
		if (m_bIsWow64)
		{

		}
		else
		{
			//这里假设载入的是64位的DLL
			pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
			if (IMAGE_DOS_SIGNATURE == pDosHeader->e_magic)
			{
				pPeInfo->pPeHeader = (PIMAGE_NT_HEADERS64)((UINT64)pBuffer + pDosHeader->e_lfanew);
				if (IMAGE_NT_SIGNATURE == pPeInfo->pPeHeader->Signature)
				{
					pPeInfo->szSectionHeader = IMAGE_FIRST_SECTION(pPeInfo->pPeHeader);
					pPeInfo->dwSectionCnt = pPeInfo->pPeHeader->FileHeader.NumberOfSections;
					pOptionalHeader64 = &(pPeInfo->pPeHeader->OptionalHeader);
					pPeInfo->wOptionalHeaderMagic = pOptionalHeader64->Magic;
					//后面在内存中展开需要用到Align
					pPeInfo->dwFileAlign = pOptionalHeader64->FileAlignment;
					pPeInfo->dwSectionAlign = pOptionalHeader64->SectionAlignment;

					//后面获取函数地址要用到
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
	}
	catch (...)
	{
		bRet = FALSE;
	}
	
	return bRet;
}

BOOL CR3APIHookScanner::FixBaseReloc(LPVOID pMemoryBuffer, const PPE_INFO const pPeImageInfo, LPVOID lpDLLBase)
{
	if (NULL == pMemoryBuffer || NULL == pPeImageInfo)
	{
		return FALSE;
	}

	
	PIMAGE_BASE_RELOCATION pBaseRelocBlock = NULL;
	DWORD dwBaseRelocTotalSize = 0;
	//todo：Wow64进程有无影响——有影响，32位进程和64位进程地址空间不同
	//这里要判断的是被打开的进程是32位还是64位，被打开的进程是64位我们就要模拟64位空间
	if (0)
	{

	}
	else
	{
		//模拟64位进程，都得用64位数据进行计算地址空间
		LPVOID lpOriginImageBase = NULL;
		INT64 uDiff = 0;
		LPVOID lpRelocVA = NULL;
		PUSHORT pNextRelocOffset = NULL;
		if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == pPeImageInfo->wOptionalHeaderMagic)
		{
			lpOriginImageBase = (LPVOID)((PIMAGE_NT_HEADERS64)pPeImageInfo->pPeHeader)->OptionalHeader.ImageBase;
		}

		if (lpDLLBase > lpOriginImageBase)
		{
			uDiff = (UINT64)lpDLLBase - (UINT64)lpOriginImageBase;
		}

		pBaseRelocBlock = (PIMAGE_BASE_RELOCATION)((UINT64)pMemoryBuffer + pPeImageInfo->dwRelocDirRVA);
		dwBaseRelocTotalSize = pPeImageInfo->dwRelocDirSize;
		pNextRelocOffset = (PUSHORT)((UINT64)pBaseRelocBlock + sizeof(IMAGE_BASE_RELOCATION));//指向一个重定位块中的偏移数据处
		if (NULL == pBaseRelocBlock || 0 == dwBaseRelocTotalSize)
		{
			return FALSE;
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

			lpRelocVA = (LPVOID)((UINT64)pMemoryBuffer + (UINT64)pBaseRelocBlock->VirtualAddress);//指向了一个4K的页，需要重定位的数据
			for (int i = 0; i < dwBaseRelocCount; i++)
			{
				LPVOID lpRelocAddr = NULL;
				LPVOID lpUnFixedAddr = NULL;
				WORD wOffset = *(pNextRelocOffset) & 0x0FFF;
				lpUnFixedAddr = (LPVOID)((UINT64)lpRelocVA + wOffset);
				*((PINT64)lpUnFixedAddr) += uDiff;
				switch (*(pNextRelocOffset) >> 12)
				{
				case IMAGE_REL_BASED_HIGHLOW:
					printf("");
					break;
				case IMAGE_REL_BASED_HIGH:
					printf("");
					break;
				case IMAGE_REL_BASED_HIGHADJ:
					printf("");
					break;
				case IMAGE_REL_BASED_LOW:
					printf("");
					break;
				case IMAGE_REL_BASED_IA64_IMM64:
					printf("");
					break;
				case IMAGE_REL_BASED_DIR64:
					printf("");
					break;
				case IMAGE_REL_BASED_MIPS_JMPADDR:
					printf("");
					break;
				case IMAGE_REL_BASED_ABSOLUTE:
					printf("");
					break;
				default:
					//return (PIMAGE_BASE_RELOCATION)NULL;
					break;
					//IMAGE_REL_BASED_HIGH
					//处理各种type
				}
				pNextRelocOffset++;

			}
			pBaseRelocBlock = (PIMAGE_BASE_RELOCATION)((UINT64)pBaseRelocBlock + pBaseRelocBlock->SizeOfBlock);
			pNextRelocOffset = (PUSHORT)((UINT64)pBaseRelocBlock + sizeof(IMAGE_BASE_RELOCATION));//指向一个重定位块中的偏移数据处
		}
	}

	return TRUE;
}

BOOL CR3APIHookScanner::BuildImportTable(LPVOID pDllMemoryBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase)
{
	//1、去遍历自己依赖的DLL，就能拿到每个依赖的DLL中的函数名
	//2、去内存中找那些载入的DLL的导出表，然后拿到地址
	//3、然后填充导入表
	//4、这里会产生一个问题，就是如果导出表被Hook了怎么办？所以有专门的EATHook检测
	CHECK_POINTER_NULL(pDllMemoryBuffer, FALSE);
	CHECK_POINTER_NULL(pPeInfo, FALSE);
	CHECK_POINTER_NULL(lpDLLBase, FALSE);

	PE_INFO OriginPEInfo = { 0 };

	if (0)//Wow64
	{

	}
	else
	{
		DWORD dwOrdinal = 0;
		DWORD dwImportTableCount = 0;
		PIMAGE_IMPORT_DESCRIPTOR pOriginImportTableVA = NULL;
		PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA = NULL;
		DWORD dwOriginImportTableSize = 0;
		PE_INFO SimulateDLLInfo = { 0 };
		PIMAGE_IMPORT_BY_NAME pName = NULL;
		PIMAGE_THUNK_DATA pFirstThunk = NULL;
		PIMAGE_THUNK_DATA pOriginFirstThunk = NULL;
		PIMAGE_IMPORT_BY_NAME pSimulateName = NULL;
		PIMAGE_THUNK_DATA pSimulateFirstThunk = NULL;
		PIMAGE_THUNK_DATA pSimulateOriginFirstThunk = NULL;
		const char* pDLLName = NULL;
		wchar_t* wcsDLLName = NULL;
		//拿到内存中真实的DLL的信息
		//AnalyzePEInfo(pModuleInfo->pDllBaseAddr, &OriginDLLInfo); //IMAGE_IMPORT_DESCRIPTOR

		if (m_OriginDLLInfo.dwImportDirRVA && m_OriginDLLInfo.dwImportDirSize > 0)
		{
			dwOriginImportTableSize = m_OriginDLLInfo.dwImportDirSize;
			pSimulateOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer +
				m_OriginDLLInfo.dwImportDirRVA);
			pOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer +
				m_OriginDLLInfo.dwImportDirRVA);
			dwImportTableCount = m_OriginDLLInfo.dwImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);//相当于获取DLL的个数

			for (int i = 0; i < dwImportTableCount && pSimulateOriginImportTableVA->Name; i++)
			{
				//找到依赖的DLL
				pDLLName = (char*)pDllMemoryBuffer + pSimulateOriginImportTableVA->Name;
				printf("Import DLL:%s\n", pDLLName);
				for (auto p : m_pCurProcess->m_vecModuleInfo)
				{
					wcsDLLName = ConvertCharToWchar(pDLLName);
					
					//找到了对应的DLL
					if (wcscmp(p->szModuleName, wcsDLLName) == 0)
					{
						
						pSimulateFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pDllMemoryBuffer +
							pOriginImportTableVA->FirstThunk);
						pSimulateOriginFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pDllMemoryBuffer +
							pOriginImportTableVA->OriginalFirstThunk);

						while (pSimulateFirstThunk->u1.Function)
						{
							LPVOID ExportAddr = NULL;

							if (pSimulateFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)//无名函数的情况，靠Ordinal
							{
								dwOrdinal = pSimulateFirstThunk->u1.Ordinal & 0xFFFF;
								ExportAddr = GetExportFuncAddrByOrdinal(p->pDllBaseAddr, wcsDLLName, dwOrdinal);
							}
							else
							{
								//拿到导入函数名，根据导入函数名，去查对应的DLL的导出函数地址
								wchar_t* wcsFuncName = NULL;
								pName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDllMemoryBuffer + pSimulateOriginFirstThunk->u1.AddressOfData);
								wcsFuncName = ConvertCharToWchar(pName->Name);
								ExportAddr = GetExportFuncAddrByName(p->pDllBaseAddr, wcsDLLName, wcsFuncName);
								FreeConvertedWchar(wcsFuncName);
							}
							
							//3、将导出表的函数填充到导入表中
							pSimulateFirstThunk->u1.AddressOfData = (ULONGLONG)ExportAddr;
							//2、遍历其导出表
							pSimulateOriginFirstThunk++;
							pSimulateFirstThunk++;
						}

						FreeConvertedWchar(wcsDLLName);
						break;
					}

					FreeConvertedWchar(wcsDLLName);
				}
				
				pSimulateOriginImportTableVA++;
			}
		}
	}

	return TRUE;
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

//todo：PE文件自己的导入表可能被Hook
BOOL CR3APIHookScanner::ScanSingleModuleIATHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
{
	CHECK_POINTER_NULL(pModuleInfo, FALSE);
	CHECK_POINTER_NULL(pDllMemoryBuffer, FALSE);

	if (0)//Wow64
	{

	}
	else
	{
		DWORD dwOrdinal = 0;
		DWORD dwImportTableCount = 0;
		PIMAGE_IMPORT_DESCRIPTOR pOriginImportTableVA = NULL;
		PIMAGE_IMPORT_DESCRIPTOR pSimulateOriginImportTableVA = NULL;
		DWORD dwOriginImportTableSize = 0;
		//PE_INFO OriginDLLInfo = { 0 };
		PE_INFO SimulateDLLInfo = { 0 };
		PIMAGE_IMPORT_BY_NAME pName = NULL;
		PIMAGE_THUNK_DATA pFirstThunk = NULL;
		PIMAGE_THUNK_DATA pOriginFirstThunk = NULL;
		PIMAGE_IMPORT_BY_NAME pSimulateName = NULL;
		PIMAGE_THUNK_DATA pSimulateFirstThunk = NULL;
		PIMAGE_THUNK_DATA pSimulateOriginFirstThunk = NULL;

		//拿到内存中真实的DLL的信息
		//AnalyzePEInfo(pModuleInfo->pDllBaseAddr, &OriginDLLInfo); //IMAGE_IMPORT_DESCRIPTOR

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
				pFirstThunk = (PIMAGE_THUNK_DATA)(pModuleInfo->pDllBaseAddr + 
					pOriginImportTableVA->FirstThunk);
				pOriginFirstThunk = (PIMAGE_THUNK_DATA)(pModuleInfo->pDllBaseAddr + 
					pOriginImportTableVA->OriginalFirstThunk);
				pSimulateFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pDllMemoryBuffer + 
					pOriginImportTableVA->FirstThunk);
				pSimulateOriginFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pDllMemoryBuffer + 
					pOriginImportTableVA->OriginalFirstThunk);

				while (pFirstThunk->u1.Function)
				{
					static int j = 1;
					__try
					{
						if (pOriginFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)//无名函数的情况，靠Ordinal
						{
							dwOrdinal = pOriginFirstThunk->u1.Ordinal & 0xFFFF;
						}
						else
						{
							pName = (PIMAGE_IMPORT_BY_NAME)(pModuleInfo->pDllBaseAddr + pOriginFirstThunk->u1.AddressOfData);
							pSimulateName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDllMemoryBuffer + pOriginFirstThunk->u1.AddressOfData);
							//IsBadReadPtr()
							if (strcmp("__C_specific_handler", pName->Name) == 0)
							{
								printf("");
							}
							printf("%d.%s		", j, pName->Name);
							printf("%d. 0x%08X\n", j, pFirstThunk->u1.Function);
							printf("%d.%s		", j, pSimulateName->Name);
							printf("%d. 0x%08X\n", j++, pSimulateFirstThunk->u1.Function);
						}
						
						if (pFirstThunk->u1.Function != pSimulateFirstThunk->u1.Function)
						{
							printf("IAT Hook found!\n");
						}
					}
					__except(EXCEPTION_EXECUTE_HANDLER)
					{
						//printf("catch exception");
						/*printf("%d.%d		", j, pName->Hint);
						printf("%d. 0x%08X\n", j++, pFirstThunk->u1.Function);*/
					}
					pFirstThunk++;
					pOriginFirstThunk++;
					pSimulateFirstThunk++;
					pSimulateOriginFirstThunk++;
				}
				pOriginImportTableVA++;
			}
		}
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanSingleModuleInlineHook(PMODULE_INFO pModuleInfo, LPVOID pDllMemoryBuffer)
{
	CHECK_POINTER_NULL(pModuleInfo, FALSE);
	CHECK_POINTER_NULL(pDllMemoryBuffer, FALSE);

	if (0)//Wow64
	{

	}
	else
	{

	}

	return TRUE;
}

DWORD CR3APIHookScanner::AlignSize(const DWORD dwSize, const DWORD dwAlign)
{
	return ((dwSize + dwAlign - 1) / dwAlign * dwAlign);
}

LPVOID CR3APIHookScanner::GetExportFuncAddrByName(LPVOID pExportDLLBase, const wchar_t* pDLLName, const wchar_t* pFuncName)
{
	//这个pOriginDLLBase是用来查询导出表的DLL，不是需要修复的DLL
	CHECK_POINTER_NULL(pDLLName, NULL);
	CHECK_POINTER_NULL(pFuncName, NULL);
	CHECK_POINTER_NULL(pExportDLLBase, NULL);

	PE_INFO ExportDLLInfo = { 0 };
	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	DWORD dwExportSize = 0;

	//todo：这里可以优化，不用每次都调用
	AnalyzePEInfo(pExportDLLBase, &ExportDLLInfo);
	if (ExportDLLInfo.dwExportDirSize > 0 && ExportDLLInfo.dwExportDirRVA > 0)
	{
		pExportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pExportDLLBase + ExportDLLInfo.dwExportDirRVA);
		dwExportSize = ExportDLLInfo.dwExportDirSize;
		printf("Number Name:%d\n", pExportTable->NumberOfNames);
		printf("Number Function:%d\n", pExportTable->NumberOfFunctions);
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
				DWORD* pExportFuncAddr = (DWORD*)((BYTE*)pExportDLLBase + pFuncAddresses[wOrdinal]);
				FreeConvertedWchar(wcsFuncName);
				return pExportFuncAddr;
			}
			FreeConvertedWchar(wcsFuncName);

		}
	}

	return NULL;
}

LPVOID CR3APIHookScanner::GetExportFuncAddrByOrdinal(LPVOID pExportDLLBase, const wchar_t* pDLLName, DWORD dwOrdinal)
{
	CHECK_POINTER_NULL(pExportDLLBase, NULL);
	CHECK_POINTER_NULL(pDLLName, NULL);

	return NULL;
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
	if (NULL == pModuleInfo || NULL == pProcessInfo)
	{
		return FALSE;
	}

	//printf("Module:%ls\n", pModuleInfo->szModuleName);
	pProcessInfo->m_vecModuleInfo.push_back(pModuleInfo);

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
		return FALSE;
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
