#include "stdafx.h"
#include "CHookScanner.h"

void main()
{
	CHookScanner R3APIHookScanner;
	//R3APIHookScanner.ScanAllProcesses();
	R3APIHookScanner.ScanProcessById(10096);
	getchar();
	return;
}