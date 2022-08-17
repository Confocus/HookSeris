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
	//ÿ��ɨ��������һ��Id
	DWORD dwHookId;

	//��Ӧ�Ľ��̵�ID
	DWORD dwProcessId;

	//��Hook�ĵ�ַ
	LPVOID lpHookedAddr;

	//Ӧ�ûָ��ĵ�ַ���ⲿ����Ҫ֪��
	LPVOID lpRecoverAddr;

	//Ԥ�����ݲ�ʹ��
	LPVOID lpReserved;

	//Hook����������֮һ
	HOOK_TYPE type;

	//��Hook�Ľ���
	wchar_t szProcess[MAX_PROCESS_NAME_LEN];

	//��Hook��ģ��
	wchar_t szHookedModule[MAX_MODULE_PATH_LEN];

	//��Hook�ĺ��������ﱣ�����ƫ��
	wchar_t szFuncName[MAX_FUNCTION_LEN];

	//���ĸ�DLL�ָ���InlineHook�ָ�ר��
	wchar_t szRecoverDLL[MAX_MODULE_PATH_LEN];

	//����������ת���ĸ�DLL
	wchar_t szTargetDLL[MAX_MODULE_PATH_LEN];
}HOOK_RESULT, * PHOOK_RESULT;

//δ֧�ֶ��߳�
//extern "C" IHookScanner* CreateObject()
//extern "C" void ReleaseObject(IHookScanner**)

__interface IHookScanner
{
	//************************************
	// Method:    Init
	// Function:  Ԥ����ʱû��
	// Access:    public 
	// Returns:   bool �����жϺ���ִ�й������Ƿ�����쳣
	// Qualifier:
	//************************************
	virtual BOOL Init() = 0;

	//************************************
	// Method:    Clear
	// Function:  Ԥ����ʱû��
	// Access:    public 
	// Returns:   bool �����жϺ���ִ�й������Ƿ�����쳣
	// Qualifier:
	//************************************
	virtual BOOL Clear() = 0;

	//************************************
	// Method:    ScanAllProcesses
	// Function:  ɨ�����н��̵Ĺ���
	// Access:    public 
	// Returns:   bool �����жϺ���ִ�й������Ƿ�����쳣
	// Qualifier:
	//************************************
	virtual BOOL ScanAllProcesses() = 0;


	//************************************
	// Method:    ScanProcessById
	// Function:  ɨ��ָ�����̵Ĺ���
	// Access:    public 
	// Returns:   bool �����жϺ���ִ�й������Ƿ�����쳣
	// Qualifier:
	// Parameter: DWORD dwProcessId������ָ�����̵Ľ���ID
	//************************************
	virtual BOOL ScanProcessById(DWORD dwProcessId) = 0;


	//************************************
	// Method:    GetHookResult
	// Function:  ��ȡɨ�蹳�ӵĽ��
	// Access:    public 
	// Returns:   bool �����жϺ���ִ�й������Ƿ�����쳣
	// Qualifier:
	// Parameter: std::vector<HOOK_RESULT>& vecHookRes���洢ɨ������vector
	//************************************
	virtual BOOL GetHookResult(std::vector<HOOK_RESULT>& vecHookRes) = 0;


	//************************************
	// Method:    UnHook
	// Function:  ժ��ָ���Ĺ���
	// Access:    public 
	// Returns:   bool �����жϺ���ִ�й������Ƿ�����쳣
	// Qualifier:
	// Parameter: DWORD dwHookId��ÿ��ɨ�����ж�Ӧ�Ľ��Id
	//************************************
	virtual BOOL UnHook(DWORD dwHookId) = 0;
};