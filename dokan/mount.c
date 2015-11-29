/*
  Dokan : user-mode file system library for Windows

  Copyright (C) 2008 Hiroki Asakawa info@dokan-dev.net

  http://dokan-dev.net/en

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <stdio.h>
#include "dokani.h"

typedef struct _REPARSE_DATA_BUFFER {
	ULONG ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR DataBuffer[1];
		} GenericReparseBuffer;
	} DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_SIZE                                        \
  FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)

BOOL CreateMountPoint(LPCWSTR MountPoint, LPCWSTR DeviceName) {
	HANDLE handle;
	PREPARSE_DATA_BUFFER reparseData;
	USHORT bufferLength;
	USHORT targetLength;
	BOOL result;
	ULONG resultLength;
	WCHAR targetDeviceName[MAX_PATH] = L"\\??";

	wcscat_s(targetDeviceName, MAX_PATH, DeviceName);
	wcscat_s(targetDeviceName, MAX_PATH, L"\\");

	handle = CreateFile(MountPoint, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
		NULL);

	if (handle == INVALID_HANDLE_VALUE) {
		DbgPrintW(L"CreateFile failed: %s (%d)\n", MountPoint, GetLastError());
		return FALSE;
	}

	targetLength = (USHORT)wcslen(targetDeviceName) * sizeof(WCHAR);
	bufferLength =
		FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) +
		targetLength + sizeof(WCHAR) + sizeof(WCHAR);

	reparseData = (PREPARSE_DATA_BUFFER)malloc(bufferLength);
	if (reparseData == NULL) {
		CloseHandle(handle);
		return FALSE;
	}

	ZeroMemory(reparseData, bufferLength);

	reparseData->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	reparseData->ReparseDataLength =
		bufferLength - REPARSE_DATA_BUFFER_HEADER_SIZE;

	reparseData->MountPointReparseBuffer.SubstituteNameOffset = 0;
	reparseData->MountPointReparseBuffer.SubstituteNameLength = targetLength;
	reparseData->MountPointReparseBuffer.PrintNameOffset =
		targetLength + sizeof(WCHAR);
	reparseData->MountPointReparseBuffer.PrintNameLength = 0;

	RtlCopyMemory(reparseData->MountPointReparseBuffer.PathBuffer,
		targetDeviceName, targetLength);

	result = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, reparseData,
		bufferLength, NULL, 0, &resultLength, NULL);

	CloseHandle(handle);
	free(reparseData);

	if (result) {
		DbgPrintW(L"CreateMountPoint %s -> %s success\n", MountPoint,
			targetDeviceName);
	}
	else {
		DbgPrintW(L"CreateMountPoint %s -> %s failed: %d\n", MountPoint,
			targetDeviceName, GetLastError());
	}
	return result;
}

static BOOL DokanServiceCheck(LPCWSTR ServiceName) {
  SC_HANDLE controlHandle;
  SC_HANDLE serviceHandle;

  controlHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

  if (controlHandle == NULL) {
    DbgPrint("DokanServiceCheck: Failed to open Service Control Manager. error "
             "= %d\n",
             GetLastError());
    return FALSE;
  }

  serviceHandle =
      OpenService(controlHandle, ServiceName,
                  SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);

  if (serviceHandle == NULL) {
    DokanDbgPrintW(
        L"DokanServiceCheck: Failed to open Service (%s). error = %d\n",
        ServiceName, GetLastError());
    CloseServiceHandle(controlHandle);
    return FALSE;
  }

  CloseServiceHandle(serviceHandle);
  CloseServiceHandle(controlHandle);

  return TRUE;
}

static BOOL DokanServiceControl(LPCWSTR ServiceName, ULONG Type) {
	SC_HANDLE controlHandle;
	SC_HANDLE serviceHandle;
	SERVICE_STATUS ss;
	BOOL result = TRUE;

	controlHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

	if (controlHandle == NULL) {
		DokanDbgPrint("DokanServiceControl: Failed to open Service Control "
			"Manager. error = %d\n",
			GetLastError());
		return FALSE;
	}

	serviceHandle =
		OpenService(controlHandle, ServiceName,
			SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);

	if (serviceHandle == NULL) {
		DokanDbgPrintW(
			L"DokanServiceControl: Failed to open Service (%s). error = %d\n",
			ServiceName, GetLastError());
		CloseServiceHandle(controlHandle);
		return FALSE;
	}

	QueryServiceStatus(serviceHandle, &ss);

	if (Type == DOKAN_SERVICE_DELETE) {
		if (DeleteService(serviceHandle)) {
			DokanDbgPrintW(L"DokanServiceControl: Service (%s) deleted\n",
				ServiceName);
			result = TRUE;
		}
		else {
			DokanDbgPrintW(
				L"DokanServiceControl: Failed to delete service (%s). error = %d\n",
				ServiceName, GetLastError());
			result = FALSE;
		}

	}
	else if (ss.dwCurrentState == SERVICE_STOPPED &&
		Type == DOKAN_SERVICE_START) {
		if (StartService(serviceHandle, 0, NULL)) {
			DokanDbgPrintW(L"DokanServiceControl: Service (%s) started\n",
				ServiceName);
			result = TRUE;
		}
		else {
			DokanDbgPrintW(
				L"DokanServiceControl: Failed to start service (%s). error = %d\n",
				ServiceName, GetLastError());
			result = FALSE;
		}

	}
	else if (ss.dwCurrentState == SERVICE_RUNNING &&
		Type == DOKAN_SERVICE_STOP) {

		if (ControlService(serviceHandle, SERVICE_CONTROL_STOP, &ss)) {
			DokanDbgPrintW(L"DokanServiceControl: Service (%s) stopped\n",
				ServiceName);
			result = TRUE;
		}
		else {
			DokanDbgPrintW(
				L"DokanServiceControl: Failed to stop service (%s). error = %d\n",
				ServiceName, GetLastError());
			result = FALSE;
		}
	}

	CloseServiceHandle(serviceHandle);
	CloseServiceHandle(controlHandle);

	Sleep(100);
	return result;
}

BOOL DOKANAPI DokanServiceInstall(LPCWSTR ServiceName, DWORD ServiceType,
                                  LPCWSTR ServiceFullPath) {
  SC_HANDLE controlHandle;
  SC_HANDLE serviceHandle;

  controlHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (controlHandle == NULL) {
    DokanDbgPrint("DokanServiceInstall: Failed to open Service Control "
                  "Manager. error = %d\n",
                  GetLastError());
    return FALSE;
  }

  serviceHandle =
      CreateService(controlHandle, ServiceName, ServiceName, 0, ServiceType,
                    SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, ServiceFullPath,
                    NULL, NULL, NULL, NULL, NULL);

  if (serviceHandle == NULL) {
    BOOL error = GetLastError();
    if (error == ERROR_SERVICE_EXISTS) {
      DokanDbgPrintW(
          L"DokanServiceInstall: Service (%s) is already installed\n",
          ServiceName);
    } else {
      DokanDbgPrintW(
          L"DokanServiceInstall: Failed to install service (%s). error = %d\n",
          ServiceName, error);
    }
    CloseServiceHandle(controlHandle);
    return FALSE;
  }

  CloseServiceHandle(serviceHandle);
  CloseServiceHandle(controlHandle);

  DokanDbgPrintW(L"DokanServiceInstall: Service (%s) installed\n", ServiceName);

  if (DokanServiceControl(ServiceName, DOKAN_SERVICE_START)) {
    DokanDbgPrintW(L"DokanServiceInstall: Service (%s) started\n", ServiceName);
    return TRUE;
  } else {
    DokanDbgPrintW(L"DokanServiceInstall: Service (%s) start failed\n",
                   ServiceName);
    return FALSE;
  }
}

BOOL DOKANAPI DokanServiceDelete(LPCWSTR ServiceName) {
  if (DokanServiceCheck(ServiceName)) {
    DokanServiceControl(ServiceName, DOKAN_SERVICE_STOP);
    if (DokanServiceControl(ServiceName, DOKAN_SERVICE_DELETE)) {
      return TRUE;
    } else {
      return FALSE;
    }
  }
  return TRUE;
}

BOOL DOKANAPI DokanUnmount(WCHAR DriveLetter) {
  WCHAR mountPoint[] = L"M:";
  mountPoint[0] = DriveLetter;
  return DokanRemoveMountPoint(mountPoint);
}

#define DOKAN_NP_SERVICE_KEY L"System\\CurrentControlSet\\Services\\Dokan"
#define DOKAN_NP_DEVICE_NAME L"\\Device\\DokanRedirector"
#define DOKAN_NP_NAME L"DokanNP"
#define DOKAN_NP_PATH L"System32\\dokannp.dll"
#define DOKAN_NP_ORDER_KEY                                                     \
  L"System\\CurrentControlSet\\Control\\NetworkProvider\\Order"

BOOL DOKANAPI DokanNetworkProviderInstall() {
  HKEY key;
  DWORD position;
  DWORD type;
  WCHAR buffer[1024];
  DWORD buffer_size = sizeof(buffer);
  ZeroMemory(&buffer, sizeof(buffer));

  RegCreateKeyEx(HKEY_LOCAL_MACHINE, DOKAN_NP_SERVICE_KEY L"\\NetworkProvider",
                 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key,
                 &position);

  RegSetValueEx(key, L"DeviceName", 0, REG_SZ, (BYTE *)DOKAN_NP_DEVICE_NAME,
                (DWORD)(wcslen(DOKAN_NP_DEVICE_NAME) + 1) * sizeof(WCHAR));

  RegSetValueEx(key, L"Name", 0, REG_SZ, (BYTE *)DOKAN_NP_NAME,
                (DWORD)(wcslen(DOKAN_NP_NAME) + 1) * sizeof(WCHAR));

  RegSetValueEx(key, L"ProviderPath", 0, REG_SZ, (BYTE *)DOKAN_NP_PATH,
                (DWORD)(wcslen(DOKAN_NP_PATH) + 1) * sizeof(WCHAR));

  RegCloseKey(key);

  RegOpenKeyEx(HKEY_LOCAL_MACHINE, DOKAN_NP_ORDER_KEY, 0, KEY_ALL_ACCESS, &key);

  RegQueryValueEx(key, L"ProviderOrder", 0, &type, (BYTE *)&buffer,
                  &buffer_size);

  if (wcsstr(buffer, L",Dokan") == NULL) {
    wcscat_s(buffer, sizeof(buffer) / sizeof(WCHAR), L",Dokan");
    RegSetValueEx(key, L"ProviderOrder", 0, REG_SZ, (BYTE *)&buffer,
                  (DWORD)(wcslen(buffer) + 1) * sizeof(WCHAR));
  }

  RegCloseKey(key);
  return TRUE;
}

BOOL DOKANAPI DokanNetworkProviderUninstall() {
  HKEY key;
  DWORD type;
  WCHAR buffer[1024];
  WCHAR buffer2[1024];

  DWORD buffer_size = sizeof(buffer);
  ZeroMemory(&buffer, sizeof(buffer));
  ZeroMemory(&buffer2, sizeof(buffer));

  RegOpenKeyEx(HKEY_LOCAL_MACHINE, DOKAN_NP_SERVICE_KEY, 0, KEY_ALL_ACCESS,
               &key);
  RegDeleteKey(key, L"NetworkProvider");

  RegCloseKey(key);

  RegOpenKeyEx(HKEY_LOCAL_MACHINE, DOKAN_NP_ORDER_KEY, 0, KEY_ALL_ACCESS, &key);

  RegQueryValueEx(key, L"ProviderOrder", 0, &type, (BYTE *)&buffer,
                  &buffer_size);

  if (wcsstr(buffer, L",Dokan") != NULL) {
    WCHAR *dokan_pos = wcsstr(buffer, L",Dokan");
    wcsncpy_s(buffer2, sizeof(buffer2) / sizeof(WCHAR), buffer,
              dokan_pos - buffer);
    wcscat_s(buffer2, sizeof(buffer2) / sizeof(WCHAR),
             dokan_pos + wcslen(L",Dokan"));
    RegSetValueEx(key, L"ProviderOrder", 0, REG_SZ, (BYTE *)&buffer2,
                  (DWORD)(wcslen(buffer2) + 1) * sizeof(WCHAR));
  }

  RegCloseKey(key);

  return TRUE;
}



VOID NormalizeMountPoint(WCHAR *mountPoint, size_t mountPointMaxLength) {
	size_t mountPointLength = wcslen(mountPoint);

	if (mountPointMaxLength >= 4) {

		if (mountPointLength == 1) {
			mountPoint[0] = towupper(mountPoint[0]);
			mountPoint[1] = L':';
			mountPoint[2] = L'\\';
			mountPoint[3] = 0;
		}
		else if (mountPointLength == 2 && mountPoint[1] == L':') {
			mountPoint[0] = towupper(mountPoint[0]);
			mountPoint[2] = L'\\';
			mountPoint[3] = 0;
		}
		else if (mountPointLength == 3 && mountPoint[1] == L':' &&
			mountPoint[2] == L'\\') {

			mountPoint[0] = towupper(mountPoint[0]);
		}
	}
	else {
		DbgPrintW(L"Failed to normalize mount point because the input buffer has a "
			L"max length < 4!\n");
	}
}

BOOL IsMountPointDriveLetter(WCHAR *mountPoint) {
	size_t mountPointLength;

	if (!mountPoint || *mountPoint == 0) {
		return FALSE;
	}

	mountPointLength = wcslen(mountPoint);

	if (mountPointLength == 1 ||
		(mountPointLength == 2 && mountPoint[1] == L':') ||
		(mountPointLength == 3 && mountPoint[1] == L':' &&
			mountPoint[2] == L'\\')) {

		return TRUE;
	}

	return FALSE;
}

BOOL CheckDriveLetterAvailability(WCHAR DriveLetter) {
	DWORD result = 0;
	WCHAR buffer[MAX_PATH];
	WCHAR driveName[] = L"C:";
	WCHAR driveLetter = towupper(DriveLetter);
	driveName[0] = driveLetter;

	if (driveLetter > 'Z' || driveLetter < 'A')
		return FALSE;

	ZeroMemory(buffer, MAX_PATH * sizeof(WCHAR));
	result = QueryDosDevice(driveName, buffer, MAX_PATH);
	if (result > 0) {
		DbgPrintW(L"QueryDosDevice detected drive \"%c\"\n", DriveLetter);
		return FALSE;
	}

	DWORD drives = GetLogicalDrives();
	result = (drives >> (driveLetter - L'A') & 0x00000001);
	if (result > 0) {
		DbgPrintW(L"GetLogicalDrives detected drive \"%c\"\n", DriveLetter);
		return FALSE;
	}

	return TRUE;
}

BOOL CreateDriveLetter(WCHAR DriveLetter, LPCWSTR DeviceName) {
	WCHAR   dosDevice[] = L"\\\\.\\C:";
	WCHAR   driveName[] = L"C:\\";
	WCHAR	rawVolumeName[MAX_PATH] = L"\\?\\Volume{x}";
	WCHAR	rawDeviceName[MAX_PATH] = L"\\??";
	HANDLE device;

	dosDevice[4] = DriveLetter;
	driveName[0] = DriveLetter;
	driveName[2] = L'\0';
	wcscat_s(rawDeviceName, MAX_PATH, DeviceName);

	DbgPrintW(L"DriveLetter: %c, DeviceName %s\n", DriveLetter, rawDeviceName);

	device = CreateFile(dosDevice, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING, NULL);

	if (device != INVALID_HANDLE_VALUE) {
		DbgPrintW(L"DokanControl Mount failed: %c: is alredy used\n", DriveLetter);
		CloseHandle(device);
		return FALSE;
	}

	if (!CheckDriveLetterAvailability(DriveLetter)) {
		return FALSE;
	}

	if (!DefineDosDevice(DDD_RAW_TARGET_PATH, driveName, rawDeviceName)) {
		DbgPrintW(L"DokanControl DefineDosDevice failed: %d\n", GetLastError());
		return FALSE;
	}

	// This to notify Mount Manager about the mount point
	// Kind of a hack because mount point should normally be allocated by Mount Manager directly
	// through IOCTL_MOUNTMGR_CREATE_POINT for instance
	driveName[2] = L'\\';
	if (!GetVolumeNameForVolumeMountPoint(driveName, rawVolumeName, MAX_PATH)) {
		DbgPrint("Error: GetVolumeNameForVolumeMountPoint failed : %d\n", GetLastError());
	}
	else {
		DbgPrint("UniqueVolumeName %ws\n", rawVolumeName);
		DefineDosDevice(DDD_REMOVE_DEFINITION, &dosDevice[4], NULL);

		if (!SetVolumeMountPoint(driveName, rawVolumeName)) {
			DbgPrint("Error: SetVolumeMountPoint failed : %d\n", GetLastError());
			return FALSE;
		}
	}

	device = CreateFile(
		dosDevice,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
		);

	if (device == INVALID_HANDLE_VALUE) {
		DbgPrintW(L"Mount %c failed:%d\n", DriveLetter,
			GetLastError());
		DefineDosDevice(DDD_REMOVE_DEFINITION, dosDevice, NULL);
		return FALSE;
	}

	CloseHandle(device);
	return TRUE;
}

BOOL DOKANAPI DokanMount(LPCWSTR MountPoint, LPCWSTR DeviceName) {
	size_t length = wcslen(MountPoint);

	if (length == 1 || (length == 2 && MountPoint[1] == L':') ||
		(length == 3 && MountPoint[1] == L':' && MountPoint[2] == L'\\')) {
		return CreateDriveLetter(MountPoint[0], DeviceName);
	}
	else if (length > 3) {
		return CreateMountPoint(MountPoint, DeviceName);
	}
	return FALSE;
}

BOOL DeleteMountPoint(LPCWSTR MountPoint) {
	HANDLE handle;
	BOOL result;
	ULONG resultLength;
	REPARSE_GUID_DATA_BUFFER reparseData = { 0 };

	handle = CreateFile(MountPoint, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
		NULL);

	if (handle == INVALID_HANDLE_VALUE) {
		DbgPrintW(L"CreateFile failed: %s (%d)\n", MountPoint, GetLastError());
		return FALSE;
	}

	reparseData.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;

	result = DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, &reparseData,
		REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, 0,
		&resultLength, NULL);

	CloseHandle(handle);

	if (result) {
		DbgPrintW(L"DeleteMountPoint %s success\n", MountPoint);
	}
	else {
		DbgPrintW(L"DeleteMountPoint %s failed: %d\n", MountPoint, GetLastError());
	}
	return result;
}

BOOL DOKANAPI DokanRemoveMountPoint(LPCWSTR MountPoint) {

	size_t length = wcslen(MountPoint);

	if (length == 1 || (length == 2 && MountPoint[1] == L':') ||
		(length == 3 && MountPoint[1] == L':' && MountPoint[2] == L'\\')) {

		WCHAR   drive[] = L"C:\\";
		drive[0] = MountPoint[0];

		if (!DeleteVolumeMountPoint(drive)) {
			DbgPrintW(L"DokanControl DeleteVolumeMountPoint failed\n");
		}
		drive[2] = L'\0';

		if (!DefineDosDevice(DDD_REMOVE_DEFINITION, drive, NULL)) {
			DbgPrintW(L"DriveLetter %c\n", MountPoint[0]);
			DbgPrintW(L"DokanControl DefineDosDevice failed\n");
			return FALSE;
		}
		else {
			DbgPrintW(L"DokanControl DD_REMOVE_DEFINITION success\n");
			return TRUE;
		}

	}
	else if (length > 3) {
		return DeleteMountPoint(MountPoint);
	}

	return FALSE;
}
