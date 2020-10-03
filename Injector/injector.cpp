#include "injector.h"

#include <stdio.h>
#include <string>
#include <iostream>

#pragma warning(disable : 6385)

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);

bool ManualMap(HANDLE process_handle, const char* binary_path)
{
	/* Check dll file attributes */
	if (GetFileAttributes(binary_path) == INVALID_FILE_ATTRIBUTES)
	{
		std::cout << ERROR << "OOPS! We ran into some problems... " << std::endl;
		std::cout << ERROR << "Failed to find '" << BINARY_PATH << "'" << std::endl;
		return false;
	}

	/* Open file */
	std::ifstream binary_file(binary_path, std::ios::binary | std::ios::ate);
	if (binary_file.fail())
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #488" << std::endl;
		binary_file.close();
		return false;
	}

	/* Get file size */
	std::streampos file_size = binary_file.tellg();
	if (file_size < 0x1000)
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #489" << std::endl;
		binary_file.close();
		return false;
	}

	std::cout << INFO << "File size 0x" << std::hex << file_size << std::endl;

	/* Allocate buffer */
	PBYTE buffer = reinterpret_cast<PBYTE>(malloc(file_size));
	if (!buffer)
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #490" << std::endl;
		binary_file.close();
		return false;
	}

	std::cout << SUCCESS << "Allocated buffer at 0x" << std::hex << (uintptr_t)buffer << std::endl;

	/* Read file */
	binary_file.seekg(0, std::ios::beg);
	binary_file.read(reinterpret_cast<char*>(buffer), file_size);
	binary_file.close();

	/* Check file signature */
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(buffer)->e_magic != 0x5A4D)
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #491" << std::endl;
		free(buffer);
		return false;
	}

	/* Retrieve headers */
	PIMAGE_NT_HEADERS pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer + reinterpret_cast<IMAGE_DOS_HEADER*>(buffer)->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOldOptHeader = &pOldNtHeader->OptionalHeader;
	PIMAGE_FILE_HEADER pOldFileHeader = &pOldNtHeader->FileHeader;

	/* Check platform */
	if (pOldFileHeader->Machine != CURRENT_ARCH)
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #492" << std::endl;
		free(buffer);
		return false;
	}

	/* Allocate buffer in target process */
	PBYTE pTargetBase = reinterpret_cast<PBYTE>(VirtualAllocEx(process_handle, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase)
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #493 (" << GetLastError() << ")" << std::endl;
		free(buffer);
		return false;
	}

	std::cout << SUCCESS << "Allocated 0x" << std::hex << pOldOptHeader->SizeOfImage << " bytes in target process at 0x" << std::hex << (uintptr_t)pTargetBase << std::endl;

	MANUAL_MAPPING_DATA data = { 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
	data.pbase = pTargetBase;

	/* Write first 0x1000 bytes (header) */
	if (!WriteProcessMemory(process_handle, pTargetBase, buffer, 0x1000, nullptr))
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #494 (" << GetLastError() << ")" << std::endl;
		return false;
	}

	std::cout << SUCCESS << "Mapped header" << std::endl;

	/* Iterate sections */
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) 
	{
		if (!pSectionHeader->SizeOfRawData)
			continue;

		/* Map section */
		if (WriteProcessMemory(process_handle, pTargetBase + pSectionHeader->VirtualAddress, buffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
		{
			std::cout << SUCCESS << "Mapped [" << pSectionHeader->Name << "]" << std::endl;
			continue;
		}
		
		/* Failed to map section */
		std::cout << ERROR << "OOPS! We ran into some problems... #495 (" << GetLastError() << ")" << std::endl;
		
		free(buffer);

		VirtualFreeEx(process_handle, pTargetBase, 0, MEM_RELEASE);
	}

	/* Allocate space for our functions */
	PBYTE mmap_data_buffer = reinterpret_cast<PBYTE>(VirtualAllocEx(process_handle, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!mmap_data_buffer)
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #496 (" << GetLastError() << ")" << std::endl;
		free(buffer);
		return false;
	}

	std::cout << SUCCESS << "Allocated 0x" << std::hex << sizeof(MANUAL_MAPPING_DATA) << " bytes at " << std::hex << (uintptr_t)mmap_data_buffer << " for mmap data" << std::endl;

	/* Write our functions */
	if (!WriteProcessMemory(process_handle, mmap_data_buffer, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #497 (" << GetLastError() << ")" << std::endl;
		free(buffer);
		return false;
	}

	std::cout << SUCCESS << "Mapped mmap data" << std::endl;

	/* Allocate space for our shellcode */
	void* pShellcode = VirtualAllocEx(process_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) 
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #498 (" << GetLastError() << ")" << std::endl;
		VirtualFreeEx(process_handle, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(process_handle, mmap_data_buffer, 0, MEM_RELEASE);
		free(buffer);
		return false;
	}

	std::cout << SUCCESS << "Allocated shellcode (0x1000 bytes at 0x" << std::hex << (uintptr_t)pShellcode << ")" << std::endl;

	/* Write our shellcode */
	if (!WriteProcessMemory(process_handle, pShellcode, Shellcode, 0x1000, nullptr))
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #499 (" << GetLastError() << ")" << std::endl;
		free(buffer);
		return false;
	}

	std::cout << SUCCESS << "Mapped shellcode" << std::endl;

	/* Create thread */
	HANDLE hThread = CreateRemoteThread(process_handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), mmap_data_buffer, 0, nullptr);
	if (!hThread) 
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #500 (" << GetLastError() << ")" << std::endl;

		VirtualFreeEx(process_handle, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(process_handle, mmap_data_buffer, 0, MEM_RELEASE);
		VirtualFreeEx(process_handle, pShellcode, 0, MEM_RELEASE);

		free(buffer);
		return false;
	}

	std::cout << SUCCESS << "Created thread at 0x" << std::hex << (uintptr_t)pShellcode << " (handle: 0x" << std::hex << hThread << ")" << std::endl;

	CloseHandle(hThread);

	std::cout << SUCCESS << "Waiting for entry point to return..." << std::endl;

	/* Wait for shellcode to be ran */
	HINSTANCE hCheck = NULL;
	while (!hCheck) 
	{
		DWORD exitcode = 0;
		GetExitCodeProcess(process_handle, &exitcode);

		if (exitcode != STILL_ACTIVE) 
		{
			std::cout << ERROR << "OOPS! We ran into some problems... #501 (" << exitcode << ")" << std::endl;
			free(buffer);
			return false;
		}

		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(process_handle, mmap_data_buffer, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x404040) 
		{
			std::cout << ERROR << "OOPS! We ran into some problems... #502" << std::endl;
			free(buffer);
			return false;
		}
		else if (hCheck == (HINSTANCE)0x606060) 
		{
			std::cout << ERROR << "OOPS! We ran into some problems... #503" << std::endl;
			free(buffer);
			return false;
		}

		Sleep(10);
	}

	std::cout << SUCCESS << "Entry point returned!" << std::endl;

	/* Zero first 0x1000 bytes (header) */
	BYTE emptyBuffer[0x1000] = { 0 };
	memset(emptyBuffer, 0, 0x1000);

	/* Write empty buffer */
	if (!WriteProcessMemory(process_handle, pTargetBase, emptyBuffer, 0x1000, nullptr))
	{
		std::cout << WARNING << "If you see this message please reboot your system and try again" << std::endl;
	}

	/* Allocate new empty buffer */
	PBYTE emptyBuffer2 = reinterpret_cast<PBYTE>(malloc(1024 * 1024));
	if (!emptyBuffer2) 
	{
		std::cout << ERROR << "OOPS! We ran into some problems... #504" << std::endl;
		free(buffer);
		return false;
	}

	/* Zero buffer */
	memset(emptyBuffer2, 0, 1024 * 1024);

	/* Zero sections */
	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) 
	{
		if (!pSectionHeader->SizeOfRawData)
			continue;
		
		if (strcmp((char*)pSectionHeader->Name, ".pdata") == 0 || strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 || strcmp((char*)pSectionHeader->Name, ".reloc") == 0) 
		{
			if (!WriteProcessMemory(process_handle, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer2, pSectionHeader->SizeOfRawData, nullptr))
			{
				//...
			}
		}
	}

	/* Free shit */
	if (buffer)
	{
		free(buffer);
	}

	if (!VirtualFreeEx(process_handle, pShellcode, 0, MEM_RELEASE))
	{
		std::cout << ERROR << "Failed to free shellcode" << std::endl;
	}

	if (!VirtualFreeEx(process_handle, mmap_data_buffer, 0, MEM_RELEASE))
	{
		std::cout << ERROR << "Failed to free mmap data" << std::endl;
	}

	//Sleep(500);
	return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData) 
	{
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	PBYTE pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + reinterpret_cast<PIMAGE_DOS_HEADER>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	PBYTE LocationDelta = (pBase - pOpt->ImageBase);
	if (LocationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) 
		{
			pData->hMod = (HINSTANCE)0x606060;
			return;
		}

		PIMAGE_BASE_RELOCATION pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD pRelativeInfo = reinterpret_cast<PWORD>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}

			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImportDescr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		
		while (pImportDescr->Name)
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}

			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		
		for (; pCallback && *pCallback; ++pCallback)
		{
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
