// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "IHookScanner.h"
#include "CHookScanner.h"


extern "C" IHookScanner * __stdcall CreateObject()
{
    return new CHookScanner();
}

extern "C" void __stdcall ReleaseObject(IHookScanner** ppObject) 
{
    if (*ppObject)
    {
        delete* ppObject;
        *ppObject = NULL;
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

