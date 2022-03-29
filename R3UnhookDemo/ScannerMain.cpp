#include "stdafx.h"
#include "CHookScanner.h"

void main()
{
	int n = sizeof(ULONG);
	CHookScanner R3APIHookScanner;
	//R3APIHookScanner.ScanAllProcesses();
	R3APIHookScanner.ScanProcessById(6604);
	R3APIHookScanner.UnHook(1);
	getchar();
	return;
}