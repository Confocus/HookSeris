#pragma once
#include "stdafx.h"
#include "nativestructure.h"

enum eBuildThreshold
{
	Build_RS0 = 10586,
	Build_RS1 = 14393,
	Build_RS2 = 15063,
	Build_RS3 = 16299,
	Build_RS4 = 17134,
	Build_RS5 = 17763,
	Build_19H1 = 18362,
	Build_19H2 = 18363,
	Build_20H1 = 19041,
	Build_RS_MAX = 99999,
};

enum eVerShort
{
	WinUnsupported, // Unsupported OS 
	WinXP,          // Windows XP
	Win7,           // Windows 7
	Win8,           // Windows 8
	Win8Point1,     // Windows 8.1
	Win10,          // Windows 10
	Win10_RS1,      // Windows 10 Anniversary update
	Win10_RS2,      // Windows 10 Creators update
	Win10_RS3,      // Windows 10 Fall Creators update
	Win10_RS4,      // Windows 10 Spring Creators update
	Win10_RS5,      // Windows 10 October 2018 update
	Win10_19H1,     // Windows 10 May 2019 update
	Win10_19H2,     // Windows 10 November 2019 update
	Win10_20H1,     // Windows 10 April 2020 update
};

class COSVersionHelper
{
public:
	COSVersionHelper();
	~COSVersionHelper();

	BOOL IsWindowsXPOrGreater();

	BOOL IsWindowsXPSP1OrGreater();

	BOOL IsWindowsXPSP2OrGreater();

	BOOL IsWindowsXPSP3OrGreater();

	BOOL IsWindowsVistaOrGreater();

	BOOL IsWindowsVistaSP1OrGreater();

	BOOL IsWindowsVistaSP2OrGreater();

	BOOL IsWindows7OrGreater();

	BOOL IsWindows7SP1OrGreater();

	BOOL IsWindows8OrGreater();

	BOOL IsWindows8Point1OrGreater();

	BOOL IsWindows10OrGreater();

	BOOL IsWindows10RS1OrGreater();

	BOOL IsWindows10RS2OrGreater();

	BOOL IsWindows10RS3OrGreater();

	BOOL IsWindows10RS4OrGreater();

	BOOL IsWindows10RS5OrGreater();

	BOOL IsWindows1019H1OrGreater();

	BOOL IsWindows1019H2OrGreater();

	BOOL IsWindows1020H1OrGreater();


private:
	BOOL InitVersion();

	BOOL IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor, DWORD dwBuild);

private:
	RTL_OSVERSIONINFOEXW m_OSVer = { 0 };
	eVerShort m_eVer;
};

