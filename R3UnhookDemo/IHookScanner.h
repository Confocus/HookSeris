#pragma once
#include <Windows.h>
#include <vector>

#define MAX_PROCESS_NAME_LEN			0x50
#define MAX_MODULE_PATH_LEN		0x400
#define MAX_FUNCTION_LEN		0x50

enum  class HOOK_TYPE
{
	IATHook = 1,
	EATHook,
	InlineHook,
};

typedef struct _HOOK_RESULT
{
	//每个扫描结果保存一个Id
	DWORD dwHookId;

	//对应的进程的ID
	DWORD dwProcessId;

	//被Hook的地址
	LPVOID lpHookedAddr;

	//应该恢复的地址，外部不需要知道
	LPVOID lpRecoverAddr;

	//预留，暂不使用
	LPVOID lpReserved;

	//Hook的三种类型之一
	HOOK_TYPE type;

	//被Hook的进程
	wchar_t szProcess[MAX_PROCESS_NAME_LEN];

	//被Hook的模块
	wchar_t szHookedModule[MAX_MODULE_PATH_LEN];

	//被Hook的函数。这里保存的是偏移
	wchar_t szFuncName[MAX_FUNCTION_LEN];

	//从哪个DLL恢复。InlineHook恢复专用
	wchar_t szRecoverDLL[MAX_MODULE_PATH_LEN];

	//用来保存跳转到哪个DLL
	wchar_t szTargetDLL[MAX_MODULE_PATH_LEN];
}HOOK_RESULT, * PHOOK_RESULT;

//未支持多线程
//extern "C" IHookScanner* CreateObject()
//extern "C" void ReleaseObject(IHookScanner**)

__interface IHookScanner
{
	//************************************
	// Method:    Init
	// Function:  预留暂时没用
	// Access:    public 
	// Returns:   bool 用来判断函数执行过程中是否出现异常
	// Qualifier:
	//************************************
	virtual BOOL Init() = 0;

	//************************************
	// Method:    Clear
	// Function:  预留暂时没用
	// Access:    public 
	// Returns:   bool 用来判断函数执行过程中是否出现异常
	// Qualifier:
	//************************************
	virtual BOOL Clear() = 0;

	//************************************
	// Method:    ScanAllProcesses
	// Function:  扫描所有进程的钩子
	// Access:    public 
	// Returns:   bool 用来判断函数执行过程中是否出现异常
	// Qualifier:
	//************************************
	virtual BOOL ScanAllProcesses() = 0;


	//************************************
	// Method:    ScanProcessById
	// Function:  扫描指定进程的钩子
	// Access:    public 
	// Returns:   bool 用来判断函数执行过程中是否出现异常
	// Qualifier:
	// Parameter: DWORD dwProcessId：传入指定进程的进程ID
	//************************************
	virtual BOOL ScanProcessById(DWORD dwProcessId) = 0;


	//************************************
	// Method:    GetHookResult
	// Function:  获取扫描钩子的结果
	// Access:    public 
	// Returns:   bool 用来判断函数执行过程中是否出现异常
	// Qualifier:
	// Parameter: std::vector<HOOK_RESULT>& vecHookRes：存储扫描结果的vector
	//************************************
	virtual BOOL GetHookResult(std::vector<HOOK_RESULT>& vecHookRes) = 0;


	//************************************
	// Method:    UnHook
	// Function:  摘掉指定的钩子
	// Access:    public 
	// Returns:   bool 用来判断函数执行过程中是否出现异常
	// Qualifier:
	// Parameter: DWORD dwHookId：每个扫描结果中对应的结果Id
	//************************************
	virtual BOOL UnHook(DWORD dwHookId) = 0;
};