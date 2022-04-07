#include "stdafx.h"
#include "CHookScanner.h"

void main()
{
	Sleep(10*1000);
	//HMODULE hMod = LoadLibrary(L"shell32.dll");
	CHookScanner R3APIHookScanner;
	//R3APIHookScanner.ScanAllProcesses();
	R3APIHookScanner.ScanProcessById(16380);
	R3APIHookScanner.UnHook(1);
	//printf("xxx");
	//getchar();
	return;
}