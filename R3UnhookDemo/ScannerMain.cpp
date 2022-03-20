#include "stdafx.h"
#include "CR3APIHookScanner.h"

void main()
{
	CR3APIHookScanner R3APIHookScanner;
	//R3APIHookScanner.ScanAllProcesses();
	R3APIHookScanner.ScanProcessById(19964);
	getchar();
	return;
}