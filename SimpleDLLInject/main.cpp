#include <iostream>
#include "Windows.h"
#include <TlHelp32.h>
#include <string>
using std::string;

HANDLE GetProcessByName(PCSTR name);

int main(int argc, char** argv) {
	char dllPath[MAX_PATH] = { 0 };
	if (argc != 3) {
		std::cout << "Wrong Parameters." << std::endl << "Usage: " << std::endl << "\tdllinject.exe DLL_PATH PROCESS_NAME" << std::endl;
		return 0;
	}
	unsigned int pathLen = GetFullPathNameA(argv[1], MAX_PATH, dllPath, NULL);
	std::cout << dllPath << " " << argv[2] << std::endl;

	PVOID addrLoadLibrary = (PVOID)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA"); // Getting the LoadLibrary Function Address
	
	/* Opening the remote process */
	DWORD pid = GetProcessId(GetProcessByName(argv[2]));
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	
	/* Allocate enough memory in the remote process to contain our DLL path */
	PVOID memAddr = (PVOID)VirtualAllocEx(proc, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NULL == memAddr) {
		DWORD err = GetLastError();
		std::cout << "Virutal Alloc Error: " << err << std::endl;
		return 0;
	}

	/* Write the DLL path in the memory allocated in the remote process */
	BOOL check = WriteProcessMemory(proc, memAddr, dllPath, pathLen, NULL);
	if (0 == check) {
		DWORD err = GetLastError();
		std::cout << "Write Process Memory Error: " << err << std::endl;
		return 0;
	}

	/* Creating a remote thread to execute LoadLibrary with the DLL path as the parameter to load our DLL and finish the dll Injection */
	HANDLE hRemote = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)addrLoadLibrary, memAddr, NULL, NULL);
	if (NULL == hRemote) {
		DWORD err = GetLastError();
		std::cout << "Create Remote Thread Error: " << err << std::endl;
		return 0;
	}
	WaitForSingleObject(proc, INFINITE);
	VirtualFreeEx(proc, addrLoadLibrary, MAX_PATH, MEM_COMMIT | MEM_RESERVE);
	CloseHandle(proc);

	return 0;
}

/*
Input: PCSTR name - The process name
Ouput: HANDLE - The requested process's handle.
Returns a Handle to a process with a specific name.
*/
HANDLE GetProcessByName(PCSTR name)
{
	DWORD pid = 0;

	// Create toolhelp snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	// Walkthrough all processes.
	if (Process32First(snapshot, &process))
	{
		do
		{
			// Compare process.szExeFile based on format of name, i.e., trim file path
			// trim .exe if necessary, etc.
			if (string(process.szExeFile) == string(name))
			{
				pid = process.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	if (pid != 0)
	{
		return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	}

	// Not found

	return NULL;
}