#if defined(WIN32) || defined(WIN64)

#include <Windows.h>
#include <stdio.h>

void win_get_machine_guid(LPBYTE buf, LPDWORD len)
{
	HKEY hKey = 0;
	DWORD dwType = REG_SZ;
	const wchar_t* subkey = L"Software\\Microsoft\\Cryptography";

	if (RegOpenKey(HKEY_LOCAL_MACHINE, subkey, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hKey, L"MachineGuid", 0, &dwType, buf, len) == ERROR_SUCCESS)
		{
			printf("MachineGuid: %s\n", buf);
		}
		else 
		{
			printf("Can not query for key value\n");
		}
		RegCloseKey(hKey);
	}
	else 
	{
		printf("Can not open key\n");
	}
}

#endif