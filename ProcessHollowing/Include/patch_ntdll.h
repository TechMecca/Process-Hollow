#pragma once

#include <windows.h>
#include <cstdio>
#include <cstdint>


using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);

enum class Win11Release : uint32_t
{
	Win11_22H2_Or_23H2 = 22621, // 22H2 baseline; 23H2 is an enablement on 22621
	Win11_24H2 = 26100
};


class Patch
{
public:
		static bool ApplyNtManageHotPatch(bool is32BitProcess, HANDLE processHandle);
private:
		static bool NtManageHotPatch32(HANDLE hProcess);
		static bool NtManageHotPatch64(HANDLE hProcess);
		static bool ZwQueryVirtualMemory(HANDLE hProcess, LPVOID module_ptr);
		static bool GetWindowsBuildNumber(DWORD& outBuild);
		static bool IsWindows11OrNewerBuild(Win11Release minBuild);
};