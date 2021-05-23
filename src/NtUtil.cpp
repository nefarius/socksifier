#include "socksifier.h"

LPWSTR GetObjectName(HANDLE hObject)
{
	LPWSTR lpwsReturn = nullptr;
	const auto pNTQO = reinterpret_cast<tNtQueryObject>(GetProcAddress(
		GetModuleHandle("NTDLL.DLL"),
		"NtQueryObject"
	));

	if (pNTQO != nullptr)
	{
		DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
		POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION)new BYTE[dwSize];
		NTSTATUS ntReturn = pNTQO(hObject, ObjectNameInformation, pObjectInfo, dwSize, &dwSize);

		if (ntReturn == STATUS_BUFFER_OVERFLOW)
		{
			delete pObjectInfo;
			pObjectInfo = (POBJECT_NAME_INFORMATION)new BYTE[dwSize];
			ntReturn = pNTQO(hObject, ObjectNameInformation, pObjectInfo, dwSize, &dwSize);
		}

		if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != nullptr))
		{
			lpwsReturn = (LPWSTR)new BYTE[pObjectInfo->Length + sizeof(WCHAR)];
			ZeroMemory(lpwsReturn, pObjectInfo->Length + sizeof(WCHAR));
			CopyMemory(lpwsReturn, pObjectInfo->Buffer, pObjectInfo->Length);
		}

		delete pObjectInfo;
	}

	return lpwsReturn;
}

LPWSTR GetObjectTypeName(HANDLE hObject)
{
	LPWSTR lpwsReturn = nullptr;
	const auto pNTQO = reinterpret_cast<tNtQueryObject>(GetProcAddress(
		GetModuleHandle("NTDLL.DLL"),
		"NtQueryObject"
	));

	if (pNTQO != nullptr)
	{
		DWORD dwSize = sizeof(PUBLIC_OBJECT_TYPE_INFORMATION);
		PPUBLIC_OBJECT_TYPE_INFORMATION pObjectInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)new BYTE[dwSize];
		NTSTATUS ntReturn = pNTQO(hObject, ObjectTypeInformation, pObjectInfo, dwSize, &dwSize);

		if (ntReturn == STATUS_BUFFER_OVERFLOW || ntReturn == STATUS_INFO_LENGTH_MISMATCH)
		{
			delete pObjectInfo;
			pObjectInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)new BYTE[dwSize];
			ntReturn = pNTQO(hObject, ObjectTypeInformation, pObjectInfo, dwSize, &dwSize);
		}

		if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->TypeName.Buffer != nullptr))
		{
			lpwsReturn = (LPWSTR)new BYTE[pObjectInfo->TypeName.Length + sizeof(WCHAR)];
			ZeroMemory(lpwsReturn, pObjectInfo->TypeName.Length + sizeof(WCHAR));
			CopyMemory(lpwsReturn, pObjectInfo->TypeName.Buffer, pObjectInfo->TypeName.Length);
		}

		delete pObjectInfo;
	}

	return lpwsReturn;
}
