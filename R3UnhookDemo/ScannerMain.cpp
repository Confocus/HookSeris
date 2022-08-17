#include "stdafx.h"
#include "CHookScanner.h"

//int WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
//{
//	//todo：解析cmdline
//
//}
//
//typedef struct _HOOK_RESULT
//{
//	//每个扫描结果保存一个Id
//	DWORD dwHookId;
//
//	//对应的进程的ID
//	DWORD dwProcessId;
//
//	//被Hook的地址
//	LPVOID lpHookedAddr;
//
//	//应该恢复的地址，外部不需要知道
//	LPVOID lpRecoverAddr;
//
//	//预留，暂不使用
//	LPVOID lpReserved;
//
//	//Hook的三种类型之一
//	HOOK_TYPE type;
//
//	//被Hook的进程
//	wchar_t szProcess[MAX_PROCESS_NAME_LEN];
//
//	//被Hook的模块
//	wchar_t szModule[MAX_MODULE_PATH_LEN];
//
//	//被Hook的函数
//	wchar_t szFuncName[MAX_FUNCTION_LEN];
//
//	//从哪个DLL恢复。InlineHook恢复专用
//	wchar_t szRecoverDLL[MAX_MODULE_PATH_LEN];
//}HOOK_RESULT, * PHOOK_RESULT;

void main()
{
	//Sleep(10*1000);
	int uSize = sizeof(ULONG);
	CHookScanner R3APIHookScanner;

	R3APIHookScanner.ScanProcessById(48860);
	std::vector<HOOK_RESULT> vecHookRes;
	R3APIHookScanner.GetHookResult(vecHookRes);
	for (auto i : vecHookRes)
	{
		wchar_t szType[0x10] = { 0 };
		switch (i.type)
		{
		case HOOK_TYPE::EATHook:
			wmemcpy_s(szType, 0x10, L"IAT", wcslen(L"IAT") + 1);
			break;
		case HOOK_TYPE::IATHook:
			wmemcpy_s(szType, 0x10, L"EAT", wcslen(L"EAT") + 1);
			break;
		case HOOK_TYPE::InlineHook:
			wmemcpy_s(szType, 0x10, L"inline", wcslen(L"inline") + 1);
			break;
		default:
			break;
		}

		printf("\n{\n");
		printf("Hooked Module:%ls\nIn Module:%ls\nHooked Function:%ls\nHooked Address:0x%016I64x\nRecovered Address:0x%016I64x\n", i.szHookedModule, i.szRecoverDLL, i.szFuncName, i.lpHookedAddr, i.lpRecoverAddr);
		printf("}");
	}

	/*HMODULE hMod = LoadLibrary(L"user32.dll");
	LPVOID lp = (LPVOID)GetProcAddress(hMod, "DefDlgProcA");*/
	//R3APIHookScanner.ScanAllProcesses();
	/*R3APIHookScanner.UnHook(230);*/
	//printf("xxx");

	
	printf("\nfinish..\n");
	getchar();
	return;
}