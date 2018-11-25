#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>

PROCESSENTRY32 __procAF;

//Prototypes
DWORD FindProcess(const char *__ProcessName, PROCESSENTRY32 *pEntry);
bool bInjectLib(DWORD procID, LPCSTR dllName);
LPCSTR dllName = "PATH_TO_DLL";

int main(int argc, char** argv) {
	if (argc < 2) {
		exit(EXIT_FAILURE);
	}
	DWORD dwTargetProcID = FindProcess(argv[1], &__procAF);
	while (dwTargetProcID <= 0) {
		std::cout << "[-]\tProgram was not found\n[*]\tRetrying. . .\n";
		dwTargetProcID = FindProcess(argv[1], &__procAF);
		Sleep(5*1000);
	}
	std::cout << "[*]\tProc ID of "<< argv[1] << " is: " << dwTargetProcID << std::endl;
	exit(EXIT_SUCCESS);
	std::cout << "[*]\tInjecting dll. . .\n";
	if (bInjectLib(dwTargetProcID, dllName)) {
		std::cout << "[+]\tInjection Successful\n";
	}
	else {
		std::cout << "[-]\tInjection failed\n";
	}
	system("Pause");
	return EXIT_SUCCESS;
}


bool bInjectLib(DWORD procID, LPCSTR dllName) {
	if (procID != 0 && dllName != NULL) {
		std::cout << "[*]\tCreating Objects\n";
		HANDLE ProcessHandle;
		PVOID Alloc;
		SIZE_T DLLLength = strlen(dllName);
		HINSTANCE Kernel32Base;
		PVOID LoadLibraryAddress;

		Kernel32Base = GetModuleHandleA("Kernel32.dll");
		if (Kernel32Base == NULL) {
			exit(EXIT_FAILURE);
		}
		std::cout << "[+]\tAddress of Kernel32: " << Kernel32Base << std::endl;

		LoadLibraryAddress = GetProcAddress(Kernel32Base, "LoadLibraryA");
		std::cout << "[+]\tAddress of LoadLibraryA: " << LoadLibraryAddress << std::endl;

		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
		if (ProcessHandle == NULL) {
			exit(EXIT_FAILURE);
		}
		std::cout << "[+]\tOpened process with all access\n";
		Alloc = VirtualAllocEx(ProcessHandle, NULL, DLLLength + 1, MEM_COMMIT, PAGE_READWRITE);
		if (Alloc == NULL) {
			exit(EXIT_FAILURE);
		}
		std::cout << "[+]\tAllocated memory\n";
		if (!WriteProcessMemory(ProcessHandle, Alloc, dllName, DLLLength + 1, NULL)) {
			exit(EXIT_FAILURE);
		}
		std::cout << "[+]\tWritten DLL path to remote process\n";
		HANDLE hRemoteThread = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, Alloc, 0, NULL);
		if (hRemoteThread == NULL) {
			std::cout << "[-]\tError creating thread\n";
			return false;
		}
		std::cout << "[+]\tCreated remote thread\n";
		return true;
	}
	return false;
}

//Get procID from name of process (stolen from hProcess.h)
DWORD FindProcess(const char *__ProcessName, PROCESSENTRY32 *pEntry)
{
	PROCESSENTRY32 __ProcessEntry;
	__ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;        
	if (!Process32First(hSnapshot, &__ProcessEntry)){
		CloseHandle(hSnapshot);
		return 0;
	}
	do {
		if (!_strcmpi(__ProcessEntry.szExeFile, __ProcessName))
		{
			memcpy((void *)pEntry, (void *)&__ProcessEntry, sizeof(PROCESSENTRY32));
			CloseHandle(hSnapshot);
			return __ProcessEntry.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &__ProcessEntry));
	CloseHandle(hSnapshot);
	return 0;
}
