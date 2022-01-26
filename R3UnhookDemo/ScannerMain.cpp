#include "stdafx.h"
#include "CR3APIHookScanner.h"

void main()
{
	CR3APIHookScanner R3APIHookScanner;
	R3APIHookScanner.ScanAllProcesses();
	getchar();
	return;
}