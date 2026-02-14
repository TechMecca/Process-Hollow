#pragma once
#include <Windows.h>
#include <cstdio>
#include <winternl.h>
#include <wininet.h>
#include <vector>
#include <string>
#include <iostream>
#include <wincrypt.h>
#include <patch_ntdll.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")

LPSTR lpSourceImage;

// Structure to store the address process infromation.
struct ProcessAddressInformation
{
	LPVOID lpProcessPEBAddress;
	LPVOID lpProcessImageBaseAddress;
};

//Structure relocation entry based on : https://docs.microsoft.com/fr-fr/windows/win32/debug/pe-format#the-reloc-section-image-only
typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;


class Process
{
public:
	BOOL Hollow(const LPSTR lpSourceImage, const LPSTR lpTargetProcess);
	BOOL Hollow(const std::vector<uint8_t> Bytes, const LPSTR lpTargetProcess);


private:
	HANDLE GetFileContent(const LPSTR lpFilePath);
	BOOL IsValidPE(const LPVOID lpImage);
	BOOL IsPE32(const LPVOID lpImage);
	ProcessAddressInformation GetProcessAddressInformation32(const PPROCESS_INFORMATION lpPI);
	ProcessAddressInformation GetProcessAddressInformation64(const PPROCESS_INFORMATION lpPI);
	DWORD GetSubsytem32(const LPVOID lpImage);
	DWORD GetSubsytem64(const LPVOID lpImage);
	DWORD GetSubsystemEx32(const HANDLE hProcess, const LPVOID lpImageBaseAddress);
	DWORD GetSubsystemEx64(const HANDLE hProcess, const LPVOID lpImageBaseAddress);
	void CleanAndExitProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent);
	void CleanProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent);
	BOOL HasRelocation32(const LPVOID lpImage);
	BOOL HasRelocation64(const LPVOID lpImage);
	IMAGE_DATA_DIRECTORY GetRelocAddress32(const LPVOID lpImage);
	IMAGE_DATA_DIRECTORY GetRelocAddress64(const LPVOID lpImage);
	BOOL RunPE32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);
	BOOL RunPE64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);
	BOOL RunPEReloc32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);
	BOOL RunPEReloc64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);
	LPVOID GetFileContentFromBytes(const std::vector<std::uint8_t>& data);
};