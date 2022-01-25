// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

void InlineHookThread()
{
	OutputDebugStringA("[HookSeris]CreateThread InlineHookThread.\n");

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	OutputDebugStringA("[HookSeris]Enter DllMain..\n");

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("[HookSeris]Process attached\n");
        HANDLE hInlineHookThread = NULL;
        DWORD dwThreadId = 0;
        hInlineHookThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InlineHookThread, NULL, 0, &dwThreadId);
        break;
    case DLL_THREAD_ATTACH:
		OutputDebugStringA("[HookSeris]Thread attached\n");
        break;
    case DLL_THREAD_DETACH:
		OutputDebugStringA("[HookSeris]Thread detached\n");
        break;
    case DLL_PROCESS_DETACH:
		OutputDebugStringA("[HookSeris]Process detached\n");
        break;
    }
    return TRUE;
}

