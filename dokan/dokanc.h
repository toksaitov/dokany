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

#ifndef _DOKANC_H_
#define _DOKANC_H_

#include "dokan.h"
#include <malloc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DOKAN_GLOBAL_DEVICE_NAME L"\\\\.\\Dokan"

#define DOKAN_DRIVER_SERVICE L"Dokan"

#define DOKAN_CONTROL_MOUNT 1
#define DOKAN_CONTROL_UNMOUNT 2
#define DOKAN_CONTROL_CHECK 3
#define DOKAN_CONTROL_FIND 4
#define DOKAN_CONTROL_LIST 5

#define DOKAN_CONTROL_OPTION_FORCE_UNMOUNT 1

#define DOKAN_CONTROL_SUCCESS 1
#define DOKAN_CONTROL_FAIL 0

#define DOKAN_SERVICE_START 1
#define DOKAN_SERVICE_STOP 2
#define DOKAN_SERVICE_DELETE 3

#define DOKAN_KEEPALIVE_TIME 3000 // in miliseconds

#define DOKAN_MAX_THREAD 15

// DokanOptions->DebugMode is ON?
extern BOOL g_DebugMode;

// DokanOptions->UseStdErr is ON?
extern BOOL g_UseStdErr;

typedef struct _DOKAN_CONTROL {
  ULONG Type;
  WCHAR MountPoint[MAX_PATH];
  WCHAR DeviceName[64];
  ULONG Option;
  ULONG Status;

} DOKAN_CONTROL, *PDOKAN_CONTROL;

static VOID DokanDbgPrint(LPCSTR format, ...) {
  const char *outputString;
  char *buffer;
  size_t length;
  va_list argp;

  va_start(argp, format);
  length = _vscprintf(format, argp) + 1;
  buffer = (char *)_malloca(length * sizeof(char));
  if (buffer) {
    vsprintf_s(buffer, length, format, argp);
    outputString = buffer;
  } else {
    outputString = format;
  }
  if (g_UseStdErr)
    fputs(outputString, stderr);
  else
    OutputDebugStringA(outputString);
  if (buffer)
    _freea(buffer);
  va_end(argp);
}

static VOID DokanDbgPrintW(LPCWSTR format, ...) {
  const WCHAR *outputString;
  WCHAR *buffer;
  size_t length;
  va_list argp;

  va_start(argp, format);
  length = _vscwprintf(format, argp) + 1;
  buffer = (WCHAR *)_malloca(length * sizeof(WCHAR));
  if (buffer) {
    vswprintf_s(buffer, length, format, argp);
    outputString = buffer;
  } else {
    outputString = format;
  }
  if (g_UseStdErr)
    fputws(outputString, stderr);
  else
    OutputDebugStringW(outputString);
  if (buffer)
    _freea(buffer);
  va_end(argp);
}

#define DbgPrint(format, ...)                                                  \
  do {                                                                         \
    if (g_DebugMode) {                                                         \
      DokanDbgPrint(format, __VA_ARGS__);                                      \
    }                                                                          \
  }                                                                            \
  __pragma(warning(push)) __pragma(warning(disable : 4127)) while (0)          \
      __pragma(warning(pop))

#define DbgPrintW(format, ...)                                                 \
  do {                                                                         \
    if (g_DebugMode) {                                                         \
      DokanDbgPrintW(format, __VA_ARGS__);                                     \
    }                                                                          \
  }                                                                            \
  __pragma(warning(push)) __pragma(warning(disable : 4127)) while (0)          \
      __pragma(warning(pop))

VOID DOKANAPI DokanUseStdErr(BOOL Status);

VOID DOKANAPI DokanDebugMode(BOOL Status);

BOOL DOKANAPI DokanServiceInstall(LPCWSTR ServiceName, DWORD ServiceType,
                                  LPCWSTR ServiceFullPath);

BOOL DOKANAPI DokanServiceDelete(LPCWSTR ServiceName);

BOOL DOKANAPI DokanNetworkProviderInstall();

BOOL DOKANAPI DokanNetworkProviderUninstall();

BOOL DOKANAPI DokanSetDebugMode(ULONG Mode);

#ifdef __cplusplus
}
#endif

#endif