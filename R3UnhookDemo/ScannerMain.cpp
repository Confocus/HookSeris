#include "stdafx.h"
#include "CHookScanner.h"

void main()
{
	CHookScanner R3APIHookScanner;
	//R3APIHookScanner.ScanAllProcesses();
	R3APIHookScanner.ScanProcessById(25380);
	R3APIHookScanner.UnHook(1);
	getchar();
	return;
}