#include "stdafx.h"
#include "inject.h"
#include <stdio.h>

int main()
{
	OutputDebugStringA("[HookSeris]main start.\n");
	BOOL bSuccess = FALSE;
	EnableDebugPriv("SeDebugPrivilege");
	//bSuccess = InjectTargetProcess(2616);
	bSuccess = InjectCode(13524);
	return 1;
}