
#include <windows.h>

#define STATUS_SUCCESS				((NTSTATUS)0x00000000L) // ntsubauth
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == STATUS_SUCCESS)
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define PS_INHERIT_HANDLES          4
#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001
#define RTL_MAX_DRIVE_LETTERS 32

#ifndef KPRIORITY
typedef LONG KPRIORITY;
#endif
typedef struct _UNICODE_STRING 
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT                  Flags;
	USHORT                  Length;
	ULONG                   TimeStamp;
	UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
    PVOID PackageDependencyData; //8+
    ULONG ProcessGroupId;
   // ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_FREE_BLOCK {
	_PEB_FREE_BLOCK          *Next;
	ULONG                   Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;


typedef void (*PPEBLOCKROUTINE)(
								PVOID PebLock
								);

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PPEBLOCKROUTINE         FastPebLockRoutine;
	PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID*                  KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID*                  ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID*                  *ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
    }

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessQuotaLimits = 1,
	ProcessIoCounters = 2,
	ProcessVmCounters = 3,
	ProcessTimes = 4,
	ProcessBasePriority = 5,
	ProcessRaisePriority = 6,
	ProcessDebugPort = 7,
	ProcessExceptionPort = 8,
	ProcessAccessToken = 9,
	ProcessLdtInformation = 10,
	ProcessLdtSize = 11,
	ProcessDefaultHardErrorMode = 12,
	ProcessIoPortHandlers = 13,
	ProcessPooledUsageAndLimits = 14,
	ProcessWorkingSetWatch = 15,
	ProcessUserModeIOPL = 16,
	ProcessEnableAlignmentFaultFixup = 17,
	ProcessPriorityClass = 18,
	ProcessWx86Information = 19,
	ProcessHandleCount = 20,
	ProcessAffinityMask = 21,
	ProcessPriorityBoost = 22,
	ProcessDeviceMap = 23,
	ProcessSessionInformation = 24,
	ProcessForegroundInformation = 25,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessLUIDDeviceMapsEnabled = 28,
	ProcessBreakOnTermination = 29,
	ProcessDebugObjectHandle = 30,
	ProcessDebugFlags = 31,
	ProcessHandleTracing = 32,
	ProcessIoPriority = 33,
	ProcessExecuteFlags = 34,
	ProcessTlsInformation = 35,
	ProcessCookie = 36,
	ProcessImageInformation = 37,
	ProcessCycleTime = 38,
	ProcessPagePriority = 39,
	ProcessInstrumentationCallback = 40,
	ProcessThreadStackAllocation = 41,
	ProcessWorkingSetWatchEx = 42,
	ProcessImageFileNameWin32 = 43,
	ProcessImageFileMapping = 44,
	ProcessAffinityUpdateMode = 45,
	ProcessMemoryAllocationMode = 46,
	ProcessGroupInformation = 47,
	ProcessTokenVirtualizationEnabled = 48,
	ProcessOwnerInformation = 49,
	ProcessWindowInformation = 50,
	ProcessHandleInformation = 51,
	ProcessMitigationPolicy = 52,
	ProcessDynamicFunctionTableInformation = 53,
	ProcessHandleCheckingMode = 54,
	ProcessKeepAliveCount = 55,
	ProcessRevokeFileHandles = 56,
	ProcessWorkingSetControl = 57,
	ProcessHandleTable = 58,
	ProcessCheckStackExtentsMode = 59,
	ProcessCommandLineInformation = 60,
	ProcessProtectionInformation = 61,
	MaxProcessInfoClass = 62
} PROCESSINFOCLASS;



typedef NTSTATUS NTAPI NTCREATETRANSACTION(
	_Out_     PHANDLE TransactionHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_  LPGUID Uow,
	_In_opt_  HANDLE TmHandle,
	_In_opt_  ULONG CreateOptions,
	_In_opt_  ULONG IsolationLevel,
	_In_opt_  ULONG IsolationFlags,
	_In_opt_  PLARGE_INTEGER Timeout,
	_In_opt_  PUNICODE_STRING Description
	);
typedef NTCREATETRANSACTION FAR * LPNTCREATETRANSACTION;

typedef NTSTATUS NTAPI NTALLOCATEVIRTUALMEMORY(
	_In_        HANDLE ProcessHandle,
	_Inout_     PVOID *BaseAddress,
	_In_        ULONG_PTR ZeroBits,
	_Inout_     PSIZE_T RegionSize,
	_In_        ULONG AllocationType,
	_In_        ULONG Protect
	);
typedef NTALLOCATEVIRTUALMEMORY FAR * LPNTALLOCATEVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTCREATESECTION(
	_Out_		PHANDLE SectionHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_	PLARGE_INTEGER MaximumSize,
	_In_		ULONG SectionPageProtection,
	_In_		ULONG AllocationAttributes,
	_In_opt_	HANDLE FileHandle
	);
typedef NTCREATESECTION FAR * LPNTCREATESECTION;

typedef NTSTATUS NTAPI NTROLLBACKTRANSACTION(
    _In_ HANDLE  TransactionHandle,
    _In_ BOOLEAN Wait);
typedef NTROLLBACKTRANSACTION FAR * LPNTROLLBACKTRANSACTION;

typedef NTSTATUS NTAPI NTCLOSE(
	_In_ HANDLE Handle
	);
typedef NTCLOSE FAR * LPNTCLOSE;

typedef NTSTATUS NTAPI NTCREATEPROCESSEX(
    _Out_    PHANDLE ProcessHandle,
    _In_     ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_     HANDLE ParentProcess,
    _In_     ULONG Flags,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort,
    _In_     BOOLEAN InJob);
typedef NTCREATEPROCESSEX FAR * LPNTCREATEPROCESSEX;

typedef NTSTATUS NTAPI NTQUERYINFORMATIONPROCESS(
	_In_		HANDLE ProcessHandle,
	_In_		PROCESSINFOCLASS ProcessInformationClass,
	_Out_		PVOID ProcessInformation,
	_In_		ULONG ProcessInformationLength,
	_Out_opt_	PULONG ReturnLength
	);
typedef NTQUERYINFORMATIONPROCESS FAR * LPNTQUERYINFORMATIONPROCESS;

typedef NTSTATUS NTAPI NTREADVIRTUALMEMORY(
	_In_		HANDLE ProcessHandle,
	_In_opt_	PVOID BaseAddress,
	_Out_		PVOID Buffer,
	_In_		SIZE_T BufferSize,
	_Out_opt_	PSIZE_T NumberOfBytesRead
	);
typedef NTREADVIRTUALMEMORY FAR * LPNTREADVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTWRITEVIRTUALMEMORY(
	_In_        HANDLE ProcessHandle,
	_In_opt_    PVOID BaseAddress,
	_In_        VOID *Buffer,
	_In_        SIZE_T BufferSize,
	_Out_opt_   PSIZE_T NumberOfBytesWritten
	);
typedef NTWRITEVIRTUALMEMORY FAR * LPNTWRITEVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTCREATETHREADEX(
    _Out_ PHANDLE hThread,
    _In_  ACCESS_MASK DesiredAccess,
    _In_  LPVOID ObjectAttributes,
    _In_  HANDLE ProcessHandle,
    _In_  LPTHREAD_START_ROUTINE lpStartAddress,
    _In_  LPVOID lpParameter,
    _In_  BOOL CreateSuspended,
    _In_  DWORD StackZeroBits,
    _In_  DWORD SizeOfStackCommit,
    _In_  DWORD SizeOfStackReserve,
    _Out_ LPVOID lpBytesBuffer);
typedef NTCREATETHREADEX FAR * LPNTCREATETHREADEX;

typedef NTSTATUS NTAPI NTFREEVIRTUALMEMORY(
	_In_       HANDLE ProcessHandle,
	_Inout_    PVOID *BaseAddress,
	_Inout_    PSIZE_T RegionSize,
	_In_       ULONG FreeType
	);
typedef NTFREEVIRTUALMEMORY FAR * LPNTFREEVIRTUALMEMORY;

LPNTCREATETRANSACTION		NtCreateTransaction;
LPNTALLOCATEVIRTUALMEMORY	NtAllocateVirtualMemory;
LPNTCREATESECTION			NtCreateSection;
LPNTROLLBACKTRANSACTION		NtRollbackTransaction;
LPNTCLOSE					NtClose;
LPNTCREATEPROCESSEX			NtCreateProcessEx;
LPNTQUERYINFORMATIONPROCESS	NtQueryInformationProcess;
LPNTREADVIRTUALMEMORY		NtReadVirtualMemory;
LPNTWRITEVIRTUALMEMORY		NtWriteVirtualMemory;
LPNTCREATETHREADEX			NtCreateThreadEx;
LPNTFREEVIRTUALMEMORY		NtFreeVirtualMemory;


typedef NTSTATUS NTAPI RTLCREATEPROCESSPARAMETERSEX(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags);
typedef RTLCREATEPROCESSPARAMETERSEX FAR * LPRTLCREATEPROCESSPARAMETERSEX;

typedef NTSTATUS NTAPI RTLDESTROYPROCESSPARAMETERS(
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );
typedef RTLDESTROYPROCESSPARAMETERS FAR * LPRTLDESTROYPROCESSPARAMETERS;

LPRTLCREATEPROCESSPARAMETERSEX		RtlCreateProcessParametersEx;
LPRTLDESTROYPROCESSPARAMETERS		RtlDestroyProcessParameters;


typedef PIMAGE_NT_HEADERS NTAPI RTLIMAGENTHEADER(
	_In_ PVOID Base
	);
typedef RTLIMAGENTHEADER FAR * LPRTLIMAGENTHEADER;
LPRTLIMAGENTHEADER			RtlImageNtHeader;


typedef PVOID NTAPI RTLINITUNICODESTRING(
	_Inout_	PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString
	);
typedef RTLINITUNICODESTRING FAR * LPRTLINITUNICODESTRING;
LPRTLINITUNICODESTRING			RtlInitUnicodeString;
