#include <stdio.h>
#include <Windows.h>
#include "IHookScanner.h"

#define HOOK_SCAN_DLL	L"R3HookScanDLL.dll"

typedef IHookScanner* (__stdcall* PCREATE_OBJECT)();
typedef void(__stdcall* PRELEASE_OBJECT)(IHookScanner**);

void main()
{
	HMODULE hMod = LoadLibrary(HOOK_SCAN_DLL);
	if (NULL == hMod)
	{
		return;
	}

	PCREATE_OBJECT funCreateObject = (PCREATE_OBJECT)GetProcAddress(hMod, "CreateObject");
	if (!funCreateObject)
	{
		return;
	}
	IHookScanner* pHookScanner = funCreateObject();
	PRELEASE_OBJECT funReleaseObject = (PRELEASE_OBJECT)GetProcAddress(hMod, "ReleaseObject");
	if (!funReleaseObject)
	{
		return;
	}

	funReleaseObject(&pHookScanner);

	return;
}