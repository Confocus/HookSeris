#include "stdafx.h"
#include "CHookScanner.h"
#include <sstream>
using namespace std;

//int WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
//{
//	//todo：解析cmdline
//
//}


void PrintUsage()
{
	printf("Parameters Usage:\n");
	printf("-s: Start Scan\n");//pid all
	/*合法的参数示例 C:\MountTest5\ \\ ? \Volume{2f7e923a - 08dc - 11ed - b01c - 000c2936494c}\  */
	printf("-u: Unhook .\n");//hook id all
}

//todo：内存占用较高，看看如何优化
void wmain(int argc, wchar_t* argv[])
{
	UINT32 uPid = -1;
	PrintUsage();

	//todo：后面重新封装命令行解析
	if (argc > 1)
	{
		//Scan.exe -s 111
		if (wcscmp(argv[1], L"-s") == 0)
		{
			if (argc < 3)
			{
				PrintUsage();
				return;
			}
			wstringstream ss;
			ss << argv[2];
			ss >> uPid;
		}
		else if (wcscmp(argv[1], L"-u") == 0)
		{
			
		}
	}
	else
	{
		return;
	}

	//HOOK_SCAN:
	int uSize = sizeof(ULONG);
	CHookScanner R3APIHookScanner;

	R3APIHookScanner.ScanProcessById(uPid);
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
		printf("Type:%ls\nHooked Module:%ls\nIn Module:%ls\nHooked Function:%ls\nHooked Address:0x%016I64x\nRecovered Address:0x%016I64x\n", szType, i.szHookedModule, i.szRecoverDLL, i.szFuncName, i.lpHookedAddr, i.lpRecoverAddr);
		printf("}");
	}


	//测试摘钩子
	R3APIHookScanner.UnHook();


	/*HMODULE hMod = LoadLibrary(L"user32.dll");
	LPVOID lp = (LPVOID)GetProcAddress(hMod, "DefDlgProcA");*/
	//R3APIHookScanner.ScanAllProcesses();
	/*R3APIHookScanner.UnHook(230);*/
	//printf("xxx");

	
	printf("\nfinish..\n");
	getchar();
	return;
}