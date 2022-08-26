#include "stdafx.h"
#include "CHookScanner.h"
#include <sstream>
using namespace std;



void PrintUsage()
{
	printf("Parameters Usage:\n");
	printf("-s: Start Scan\n");//pid all
	/*合法的参数示例 C:\MountTest5\ \\ ? \Volume{2f7e923a - 08dc - 11ed - b01c - 000c2936494c}\  */
	printf("-u: Unhook .\n");//hook id all
}
//todo：增加gTest
//todo：内存占用较高，看看如何优化:
// 先保存所有的需要修改的点：
//1、根本不需要载入DLL全部镜像
//2、只需要保存导入函数的入口点12个字节即可，修复完12字节即可释放多余的内存。
//3、对于IATHook和EATHook，也只需要保存入口函数地址即可
//4、之前之所以全部保存，是因为考虑有可能不是从函数入口点Hook的，可能在函数任意地方Hook。
//对于待扫描的进程的所有的模块，读入一个扫描一个即可，不必像CbCollectx64ModuleInfo一次性全部读入


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


	while (1)
	{

	}
	//测试摘钩子
	//R3APIHookScanner.UnHook();


	/*HMODULE hMod = LoadLibrary(L"user32.dll");
	LPVOID lp = (LPVOID)GetProcAddress(hMod, "DefDlgProcA");*/
	//R3APIHookScanner.ScanAllProcesses();
	/*R3APIHookScanner.UnHook(230);*/
	//printf("xxx");

	
	printf("\nfinish..\n");
	getchar();
	return;
}