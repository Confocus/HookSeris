#include "CR3APIHookScanner.h"
#include <string.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "nativestructure.h"
#include "ApiSet.h"
#include <algorithm>
#include <winternl.h>

using namespace blackbone;
vector<PROCESS_INFO*> CR3APIHookScanner::m_vecProcessInfo;//�޷��������ⲿ����

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

	//����Win10�����
	InitApiSchema< PAPI_SET_NAMESPACE_ARRAY_10,
		PAPI_SET_NAMESPACE_ENTRY_10,
		PAPI_SET_VALUE_ARRAY_10,
		PAPI_SET_VALUE_ENTRY_10 >();
	//RedirectDLLPath(L"api-ms-win-core-processthreads-l1-1-0.dll");
	/*std::wstring str = L"api-ms-win-eventing-controller-l1-1-0.dll";
	ProbeSxSRedirect(str);
	RedirectDLLPath(L"api-ms-win-eventing-controller-l1-1-0.dll");*/
	return TRUE;
}

BOOL CR3APIHookScanner::ScanAllProcesses()
{
	//�����һ��ɨ�������
	Clear();
	//��ȡ�����н���
	if (!EmurateProcesses(CbCollectProcessInfo))
	{
		return FALSE;
	}

	//��ȡ�����н��̵�����ģ��
	for (PPROCESS_INFO pProcessInfo : m_vecProcessInfo)
	{
		EmurateModules(pProcessInfo, CbCollectModuleInfo);
		//todo�����ǽ�����ʧ������ͽ���ID�䶯�����
		//ScanSingleProcessById(pProcessInfo->dwProcessId);
		//ScanSingle(pProcessInfo);
	}

	return TRUE;
}

BOOL CR3APIHookScanner::ScanSingleProcessById(DWORD dwProcessId)
{
	Clear();
	//��ȡ�����н���
	//todo�������õ�һ��pProcessInfo���ɣ������õ�ȫ����vector
	if (!EmurateProcesses(CbCollectProcessInfo))
	{
		return FALSE;
	}

	//��ȡ�����н��̵�����ģ��
	for (PPROCESS_INFO pProcessInfo : m_vecProcessInfo)
	{
		//��ס��ǰ����ɨ����Ǹ�����
		m_pCurProcess = pProcessInfo;
		//�ҵ�����Ҫɨ����Ǹ�����
		if (dwProcessId == pProcessInfo->dwProcessId)
		{
			EmurateModules(pProcessInfo, CbCollectModuleInfo);
			//todo�����ǽ�����ʧ������ͽ���ID�䶯�����
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
	//todo��ò��������	TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE ??
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
			//����ModuleInfo�б�Ҫ������
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

	//todo����֤���pid��Ӧ����֮ǰ���Ǹ�����
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

	//������������е�����ģ��
	//todo:ҲҪ���ǿ��յ�ʱЧ�Ե�����
	for (auto pModuleInfo : pProcessInfo->m_vecModuleInfo)
	{
		//peLoad(Info.FullName, Info.DllBase, Info.DiskImage, Info.SizeOfImage);
		LPVOID pDllMemBuffer = NULL;
		AnalyzePEInfo(pModuleInfo->pDllBaseAddr, &m_OriginDLLInfo);

		pDllMemBuffer = SimulateLoadDLL(pModuleInfo);
		if (NULL != pDllMemBuffer)
		{
			//IAT HOOKɨ�裬��ν��IAT Hook���Ǵ۸��˵�����뺯���ĵ�ַ
			ScanSingleModuleIATHook(pModuleInfo, pDllMemBuffer);
			//��ģ�������ڴ���dll���ڴ�����ʵ��dll���бȽ�
			//�����InlineHook��ʵ����EAT Hook����ν��EAT Hook��������ת������ִ�е��ڲ���Ȼ���޸���ָ�PE�ӵ�������õ�һ�������ĵ�ַ
			//Ȼ����������������ڲ�ִ��
			//ScanSingleModuleInlineHook(pModuleInfo, pDllMemBuffer);
			//ReleaseDllMemoryBuffer(&pDllMemBuffer);
		}
	}

	CloseHandle(hProcess);

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
	//DLL�����ϵ�����
	LPVOID pDllImageBuffer = NULL;
	//DLLģ�������ڴ��е�����
	LPVOID pDllMemoryBuffer = NULL;
	PE_INFO PEImageInfo = { 0 };

	do 
	{
		hFile = CreateFile(pModuleInfo->szModulePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			break;
		}

		//todo����ʵ�����Ƿ�ֻ��Ҫ���뵼�������ݾ��У����ذ�ȫ���������������
		pDllImageBuffer = new(std::nothrow) BYTE[dwBufferSize];
		pDllMemoryBuffer = new(std::nothrow) BYTE[dwBufferSize];

		if (pDllImageBuffer && pDllMemoryBuffer)
		{
			ZeroMemory(pDllMemoryBuffer, dwBufferSize);
			//��DLL�Ķ������ļ������ڴ�
			if (!ReadFile(hFile, pDllImageBuffer, dwBufferSize, &dwNumberOfBytesRead, NULL))
			{
				break;
			}

			//��������DLL���ļ������PE�ṹ
			if (!AnalyzePEInfo(pDllImageBuffer, &PEImageInfo))
			{
				break;
			}

			//DLL����ģ��DLL�ڴ�չ����ĸ�ʽ
			//�����н��������ݱ���
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

	//todo�������������ָ���Ƿ�Ჶ���쳣
	try
	{
		//todo��Wow64�������
		//todo��Wow64��������Ӱ�졪����Ӱ�죬32λ���̺�64λ���̵�ַ�ռ䲻ͬ
		//����Ҫ�жϵ��Ǳ��򿪵Ľ�����32λ����64λ�����򿪵Ľ�����64λ���Ǿ�Ҫģ��64λ�ռ�
		if (m_bIsWow64)
		{

		}
		else
		{
			//��������������64λ��DLL
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
					//�������ڴ���չ����Ҫ�õ�Align
					pPeInfo->dwFileAlign = pOptionalHeader64->FileAlignment;
					pPeInfo->dwSectionAlign = pOptionalHeader64->SectionAlignment;

					//�����ȡ������ַҪ�õ�
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
	//todo��Wow64��������Ӱ�졪����Ӱ�죬32λ���̺�64λ���̵�ַ�ռ䲻ͬ
	//����Ҫ�жϵ��Ǳ��򿪵Ľ�����32λ����64λ�����򿪵Ľ�����64λ���Ǿ�Ҫģ��64λ�ռ�
	if (0)
	{

	}
	else
	{
		//ģ��64λ���̣�������64λ���ݽ��м����ַ�ռ�
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
		pNextRelocOffset = (PUSHORT)((UINT64)pBaseRelocBlock + sizeof(IMAGE_BASE_RELOCATION));//ָ��һ���ض�λ���е�ƫ�����ݴ�
		if (NULL == pBaseRelocBlock || 0 == dwBaseRelocTotalSize)
		{
			return FALSE;
		}

		//�����ض�λ��
		while (dwBaseRelocTotalSize)
		{
			DWORD dwBaseRelocBlockSize = 0;
			DWORD dwBaseRelocCount = 0;
			
			//���µ�����
			dwBaseRelocTotalSize -= pBaseRelocBlock->SizeOfBlock;

			//���α�����Ҫ�ض�λ������
			dwBaseRelocBlockSize = pBaseRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
			dwBaseRelocCount = dwBaseRelocBlockSize / sizeof(USHORT);//��Ҫ�ض�λ�������ж��ٸ�

			lpRelocVA = (LPVOID)((UINT64)pMemoryBuffer + (UINT64)pBaseRelocBlock->VirtualAddress);//ָ����һ��4K��ҳ����Ҫ�ض�λ������
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
					//�������type
				}
				pNextRelocOffset++;

			}
			pBaseRelocBlock = (PIMAGE_BASE_RELOCATION)((UINT64)pBaseRelocBlock + pBaseRelocBlock->SizeOfBlock);
			pNextRelocOffset = (PUSHORT)((UINT64)pBaseRelocBlock + sizeof(IMAGE_BASE_RELOCATION));//ָ��һ���ض�λ���е�ƫ�����ݴ�
		}
	}

	return TRUE;
}

BOOL CR3APIHookScanner::BuildImportTable(LPVOID pDllMemoryBuffer, PPE_INFO pPeInfo, LPVOID lpDLLBase)
{
	//1��ȥ�����Լ�������DLL�������õ�ÿ��������DLL�еĺ�����
	//2��ȥ�ڴ�������Щ�����DLL�ĵ�����Ȼ���õ���ַ
	//3��Ȼ����䵼���
	//4����������һ�����⣬�������������Hook����ô�죿������ר�ŵ�EATHook���
	CHECK_POINTER_NULL(pDllMemoryBuffer, FALSE);
	CHECK_POINTER_NULL(pPeInfo, FALSE);
	CHECK_POINTER_NULL(lpDLLBase, FALSE);

	DWORD dwErrCode = 0;
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
		//�õ��ڴ�����ʵ��DLL����Ϣ
		//AnalyzePEInfo(pModuleInfo->pDllBaseAddr, &OriginDLLInfo); //IMAGE_IMPORT_DESCRIPTOR

		if (m_OriginDLLInfo.dwImportDirRVA && m_OriginDLLInfo.dwImportDirSize > 0)
		{
			dwOriginImportTableSize = m_OriginDLLInfo.dwImportDirSize;
			pSimulateOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer +
				m_OriginDLLInfo.dwImportDirRVA);
			pOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer +
				m_OriginDLLInfo.dwImportDirRVA);
			dwImportTableCount = m_OriginDLLInfo.dwImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);//�൱�ڻ�ȡDLL�ĸ���

			//����Ҫ�޸���DLL��������DLL
			for (int i = 0; i < dwImportTableCount && pSimulateOriginImportTableVA->Name; i++)
			{
				//�ҵ�������DLL
				HMODULE lpImportDLLAddr = NULL;
				std::wstring wsRedirectedDLLName;
				pDLLName = (char*)pDllMemoryBuffer + pSimulateOriginImportTableVA->Name;
				printf("Import DLL:%s\n", pDLLName);
				PE_INFO ImportDLLInfo = { 0 };
				wcsDLLName = ConvertCharToWchar(pDLLName);
				dwErrCode = GetLastError();
				wsRedirectedDLLName = RedirectDLLPath(wcsDLLName, NULL);//�����ǵ�һ�ε���RedirectDLLPath
				if (0 != wsRedirectedDLLName.size())
				{
					lpImportDLLAddr = GetModuleHandle(wsRedirectedDLLName.c_str());
				}
				else
				{
					lpImportDLLAddr = GetModuleHandle(wcsDLLName);//GetModuleHandle�õ����ǵ������DLL���Ǹ�DLL�Ļ���ַ
				}
				//��ȡ"�Ѿ�ӳ�䵽���ý�����"��ģ��ľ��

				dwErrCode = GetLastError();
				if (!lpImportDLLAddr)
				{
					FreeConvertedWchar(wcsDLLName);
					return FALSE;
				}
				AnalyzePEInfo(lpImportDLLAddr, &ImportDLLInfo);

				pSimulateFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pDllMemoryBuffer +
					pSimulateOriginImportTableVA->FirstThunk);
				pSimulateOriginFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pDllMemoryBuffer +
					pSimulateOriginImportTableVA->OriginalFirstThunk);

				while (pSimulateFirstThunk->u1.Function)
				{
					LPVOID ExportAddr = NULL;

					if (pSimulateFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)//�����������������Ordinal
					{
						dwOrdinal = pSimulateFirstThunk->u1.Ordinal & 0xFFFF;
						ExportAddr = GetExportFuncAddrByOrdinal(lpImportDLLAddr, &ImportDLLInfo, wcsDLLName, dwOrdinal);
					}
					else
					{
						//�õ����뺯���������ݵ��뺯������ȥ���Ӧ��DLL�ĵ���������ַ
						wchar_t* wcsFuncName = NULL;
						pName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDllMemoryBuffer + pSimulateOriginFirstThunk->u1.AddressOfData);
						wcsFuncName = ConvertCharToWchar(pName->Name);
						if (wcscmp(wcsFuncName, L"__C_specific_handler") == 0)
						{
							printf("");
						}
						ExportAddr = GetExportFuncAddrByName(lpImportDLLAddr, &ImportDLLInfo, wcsDLLName, wcsFuncName, wsRedirectedDLLName.c_str());
						FreeConvertedWchar(wcsFuncName);
					}

					//3����������ĺ�����䵽�������
					pSimulateFirstThunk->u1.AddressOfData = (ULONGLONG)ExportAddr;
					//2�������䵼����
					pSimulateOriginFirstThunk++;
					pSimulateFirstThunk++;
				}

				FreeConvertedWchar(wcsDLLName);
				pOriginImportTableVA++;
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

//todo��PE�ļ��Լ��ĵ������ܱ�Hook
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

		//�õ��ڴ�����ʵ��DLL����Ϣ
		//AnalyzePEInfo(pModuleInfo->pDllBaseAddr, &OriginDLLInfo); //IMAGE_IMPORT_DESCRIPTOR

		if (m_OriginDLLInfo.dwImportDirRVA && m_OriginDLLInfo.dwImportDirSize > 0)
		{
			dwOriginImportTableSize = m_OriginDLLInfo.dwImportDirSize;
			pOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)(pModuleInfo->pDllBaseAddr + 
				m_OriginDLLInfo.dwImportDirRVA);
			pSimulateOriginImportTableVA = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDllMemoryBuffer + 
				m_OriginDLLInfo.dwImportDirRVA);
			dwImportTableCount = m_OriginDLLInfo.dwImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);//�൱�ڻ�ȡDLL�ĸ���

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
					if (pOriginFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)//�����������������Ordinal
					{
						dwOrdinal = pOriginFirstThunk->u1.Ordinal & 0xFFFF;
					}
					else
					{
						pName = (PIMAGE_IMPORT_BY_NAME)(pModuleInfo->pDllBaseAddr + pOriginFirstThunk->u1.AddressOfData);
						pSimulateName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDllMemoryBuffer + pOriginFirstThunk->u1.AddressOfData);
						//IsBadReadPtr()
						
						printf("%d.%s		", j, pName->Name);
						printf("%d. 0x%016I64X\n", j, pFirstThunk->u1.Function);
						printf("%d.%s		", j, pSimulateName->Name);
						printf("%d. 0x%016I64X\n", j++, pSimulateFirstThunk->u1.Function);
					}

					if (pFirstThunk->u1.Function != pSimulateFirstThunk->u1.Function)
					{
						printf("IAT Hook found!\n");
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

LPVOID CR3APIHookScanner::GetExportFuncAddrByName(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, const wchar_t* pDLLName, const wchar_t* pFuncName, const wchar_t* pPreHostDLL)
{
	//���pOriginDLLBase��������ѯ�������DLL��������Ҫ�޸���DLL
	CHECK_POINTER_NULL(pDLLName, NULL);
	CHECK_POINTER_NULL(pFuncName, NULL);
	CHECK_POINTER_NULL(pExportDLLBase, NULL);
	CHECK_POINTER_NULL(pExportDLLInfo, NULL);

	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	DWORD dwExportSize = 0;
	LPVOID lpExportFuncAddr = NULL;

	if (0)
	{

	}
	else
	{
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

		if (((UINT64)lpExportFuncAddr > (UINT64)pExportTable) && ((UINT64)lpExportFuncAddr < (UINT64)pExportTable + dwExportSize))
		{
			//todo��redirection
			printf("");
			lpExportFuncAddr = RedirectionExportFuncAddr((char*)lpExportFuncAddr, pPreHostDLL);
		}
	}

	return lpExportFuncAddr;
}

LPVOID CR3APIHookScanner::GetExportFuncAddrByOrdinal(LPVOID pExportDLLBase, PPE_INFO pExportDLLInfo, const wchar_t* pDLLName, WORD wOrdinal)
{
	CHECK_POINTER_NULL(pExportDLLBase, NULL);
	CHECK_POINTER_NULL(pDLLName, NULL);
	CHECK_POINTER_NULL(pExportDLLInfo, NULL);

	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	DWORD dwExportSize = 0;

	if (0)
	{

	}
	else
	{
		if (pExportDLLInfo->dwExportDirSize > 0 && pExportDLLInfo->dwExportDirRVA > 0)
		{
			pExportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pExportDLLBase + pExportDLLInfo->dwExportDirRVA);
			dwExportSize = pExportDLLInfo->dwExportDirSize;
			DWORD* pFuncAddresses = (DWORD*)((BYTE*)pExportDLLBase + pExportTable->AddressOfFunctions);
			WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)pExportDLLBase + pExportTable->AddressOfNameOrdinals);
			DWORD* pFuncNames = (DWORD*)((BYTE*)pExportDLLBase + pExportTable->AddressOfNames);

			return (LPVOID)((UINT64)pExportDLLBase + (UINT64)pFuncAddresses[wOrdinal - pExportTable->Base]);
		}
	}

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

std::wstring CR3APIHookScanner::RedirectDLLPath(const wchar_t* path, const wchar_t* pPreHostDLL)
{
	CHECK_POINTER_NULL(path, L"");
	std::wstring filename = path;
	std::wstring wsPreHostDLL;
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

	//todo���б��������ֹ��һ������ô��
	if (iter != m_mapApiSchema.end())
	{
		// Select appropriate api host
		return iter->second.front() != wsPreHostDLL ? iter->second.front() : iter->second.back();
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

LPVOID CR3APIHookScanner::RedirectionExportFuncAddr(const char* lpExportFuncAddr, const wchar_t* pPreHostDLL)
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

	wsRedirectedDLLName = RedirectDLLPath(wpDLLName, pPreHostDLL);
	if (0 != wsRedirectedDLLName.size())
	{
		pExportDLLAddr = GetModuleHandle(wsRedirectedDLLName.c_str());
	}
	else
	{
		pExportDLLAddr = GetModuleHandle(wpDLLName);//GetModuleHandle�õ����ǵ������DLL���Ǹ�DLL�Ļ���ַ
	}

	//todo���Ƿ���԰��õ��Ķ���������
	AnalyzePEInfo(pExportDLLAddr, &ExportDLLINfo);
	lpRedirectedExportFuncAddr = GetExportFuncAddrByName(pExportDLLAddr, &ExportDLLINfo, wpDLLName, wpFuncName, wsRedirectedDLLName.c_str());
	FreeConvertedWchar(wpDLLName);
	FreeConvertedWchar(wpFuncName);

	return lpRedirectedExportFuncAddr;
}