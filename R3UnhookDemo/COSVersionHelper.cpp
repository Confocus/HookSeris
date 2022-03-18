#include "COSVersionHelper.h"

COSVersionHelper::COSVersionHelper()
{
	InitVersion();
}

COSVersionHelper::~COSVersionHelper()
{

}

BOOL COSVersionHelper::IsWindowsXPOrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 0, 0);
}

BOOL COSVersionHelper::IsWindowsXPSP1OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 1, 0);
}

BOOL COSVersionHelper::IsWindowsXPSP2OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 2, 0);
}

BOOL COSVersionHelper::IsWindowsXPSP3OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3, 0);
}

BOOL COSVersionHelper::IsWindowsVistaOrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 0, 0);
}

BOOL COSVersionHelper::IsWindowsVistaSP1OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 1, 0);
}

BOOL COSVersionHelper::IsWindowsVistaSP2OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 2, 0);
}

BOOL COSVersionHelper::IsWindows7OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN7), LOBYTE(_WIN32_WINNT_WIN7), 0, 0);
}

BOOL COSVersionHelper::IsWindows7SP1OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN7), LOBYTE(_WIN32_WINNT_WIN7), 1, 0);
}

BOOL COSVersionHelper::IsWindows8OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN8), LOBYTE(_WIN32_WINNT_WIN8), 0, 0);
}

BOOL COSVersionHelper::IsWindows8Point1OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINBLUE), LOBYTE(_WIN32_WINNT_WINBLUE), 0, 0);
}

BOOL COSVersionHelper::IsWindows10OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, 0);
}

BOOL COSVersionHelper::IsWindows10RS1OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS1);
}

BOOL COSVersionHelper::IsWindows10RS2OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS2);
}

BOOL COSVersionHelper::IsWindows10RS3OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS3);
}

BOOL COSVersionHelper::IsWindows10RS4OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS4);
}

BOOL COSVersionHelper::IsWindows10RS5OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_RS5);
}

BOOL COSVersionHelper::IsWindows1019H1OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_19H1);
}

BOOL COSVersionHelper::IsWindows1019H2OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_19H2);
}

BOOL COSVersionHelper::IsWindows1020H1OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0, Build_20H1);
}

BOOL COSVersionHelper::IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor, DWORD dwBuild)
{
	if (m_OSVer.dwMajorVersion == 0)
	{
		return FALSE;
	}

	if (m_OSVer.dwMajorVersion > wMajorVersion)
		return TRUE;
	else if (m_OSVer.dwMajorVersion < wMajorVersion)
		return FALSE;

	if (m_OSVer.dwMinorVersion > wMinorVersion)
		return TRUE;
	else if (m_OSVer.dwMinorVersion < wMinorVersion)
		return FALSE;

	if (m_OSVer.wServicePackMajor > wServicePackMajor)
		return TRUE;
	else if (m_OSVer.wServicePackMajor < wServicePackMajor)
		return FALSE;

	if (m_OSVer.dwBuildNumber >= dwBuild)
		return TRUE;
	
	return FALSE;
}

BOOL COSVersionHelper::InitVersion()
{
	BOOL bRet = FALSE;
	HMODULE hMod = NULL;
	PFUNC_RTLGETVERSION pfRtlGetVersion = NULL;

	hMod = LoadLibrary(L"ntdll.dll");
	if (NULL == hMod)
	{
		return FALSE;
	}

	do 
	{
		pfRtlGetVersion = (PFUNC_RTLGETVERSION)GetProcAddress(hMod, "RtlGetVersion");
		if (!pfRtlGetVersion)
		{
			break;
		}

		pfRtlGetVersion(&m_OSVer);

		if (0 == m_OSVer.dwMajorVersion)
		{
			break;
		}

		switch ((m_OSVer.dwMajorVersion << 8) | m_OSVer.dwMinorVersion)
		{
		case _WIN32_WINNT_WIN10:
			if (m_OSVer.dwBuildNumber >= Build_20H1)
				m_eVer = Win10_20H1;
			else if (m_OSVer.dwBuildNumber >= Build_19H2)
				m_eVer = Win10_19H2;
			else if (m_OSVer.dwBuildNumber >= Build_19H1)
				m_eVer = Win10_19H1;
			else if (m_OSVer.dwBuildNumber >= Build_RS5)
				m_eVer = Win10_RS5;
			else if (m_OSVer.dwBuildNumber >= Build_RS4)
				m_eVer = Win10_RS4;
			else if (m_OSVer.dwBuildNumber >= Build_RS3)
				m_eVer = Win10_RS3;
			else if (m_OSVer.dwBuildNumber >= Build_RS2)
				m_eVer = Win10_RS2;
			else if (m_OSVer.dwBuildNumber >= Build_RS1)
				m_eVer = Win10_RS1;
			else if (m_OSVer.dwBuildNumber >= Build_RS0)
				m_eVer = Win10;
			break;

		case _WIN32_WINNT_WINBLUE:
			m_eVer = Win8Point1;
			break;

		case _WIN32_WINNT_WIN8:
			m_eVer = Win8;
			break;

		case _WIN32_WINNT_WIN7:
			m_eVer = Win7;
			break;

		case _WIN32_WINNT_WINXP:
			m_eVer = WinXP;
			break;

		default:
			m_eVer = WinUnsupported;
		}

	} while (FALSE);

	FreeLibrary(hMod);
	return bRet;
}