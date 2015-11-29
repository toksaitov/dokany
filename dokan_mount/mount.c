/*

Copyright (c) 2007, 2008 Hiroki Asakawa asakaw@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include "mount.h"

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
  } else {
    DbgPrintW(L"CreateMountPoint %s -> %s failed: %d\n", MountPoint,
              targetDeviceName, GetLastError());
  }
  return result;
}

BOOL DeleteMountPoint(LPCWSTR MountPoint) {
  HANDLE handle;
  BOOL result;
  ULONG resultLength;
  REPARSE_GUID_DATA_BUFFER reparseData = {0};

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
  } else {
    DbgPrintW(L"DeleteMountPoint %s failed: %d\n", MountPoint, GetLastError());
  }
  return result;
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
	} else {
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
    DbgPrintW(L"DokanControl Mount %c failed:%d\n", DriveLetter,
              GetLastError());
    DefineDosDevice(DDD_REMOVE_DEFINITION, dosDevice, NULL);
    return FALSE;
  }

  CloseHandle(device);
  return TRUE;
}

BOOL DokanControlMount(LPCWSTR MountPoint, LPCWSTR DeviceName) {
  size_t length = wcslen(MountPoint);

  if (length == 1 || (length == 2 && MountPoint[1] == L':') ||
      (length == 3 && MountPoint[1] == L':' && MountPoint[2] == L'\\')) {
    return CreateDriveLetter(MountPoint[0], DeviceName);
  } else if (length > 3) {
    return CreateMountPoint(MountPoint, DeviceName);
  }
  return FALSE;
}

BOOL DokanControlUnmount(LPCWSTR MountPoint) {

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
    } else {
      DbgPrintW(L"DokanControl DD_REMOVE_DEFINITION success\n");
      return TRUE;
    }

  } else if (length > 3) {
    return DeleteMountPoint(MountPoint);
  }

  return FALSE;
}

VOID NormalizeMountPoint(WCHAR *mountPoint, size_t mountPointMaxLength) {
  size_t mountPointLength = wcslen(mountPoint);

  if (mountPointMaxLength >= 4) {

    if (mountPointLength == 1) {
      mountPoint[0] = towupper(mountPoint[0]);
      mountPoint[1] = L':';
      mountPoint[2] = L'\\';
      mountPoint[3] = 0;
    } else if (mountPointLength == 2 && mountPoint[1] == L':') {
      mountPoint[0] = towupper(mountPoint[0]);
      mountPoint[2] = L'\\';
      mountPoint[3] = 0;
    } else if (mountPointLength == 3 && mountPoint[1] == L':' &&
               mountPoint[2] == L'\\') {

      mountPoint[0] = towupper(mountPoint[0]);
    }
  } else {
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
