#ifndef __COMMONFUNC_H__
#define __COMMONFUNC_H__

#include "struct.h"

#define DEBUGTOOL_NAME1		"cheatengine"
#define DEBUGTOOL_NAME2		"Ollydbg"

#define GAME_NAME			"x2.exe"//"DKonline"//"china_login"//"so3d"//"XYClient"//"xxsj"//"x2.exe"//

#define WORD	USHORT
#define DWORD	ULONG


#define PROCESSID_OFFSET				0xB4
#define PROCESSLIST_OFFSET				0xB8

#ifndef THREADHEADOFPROCESS_OFFSET
#define THREADHEADOFPROCESS_OFFSET		0x02C
#endif

#ifndef THREADLISTOFTHREAD_OFFSET
#define THREADLISTOFTHREAD_OFFSET		0x1E0
#endif

#ifndef SEVICETABLEOFTHREAD_OFFSET
#define SEVICETABLEOFTHREAD_OFFSET		0x0BC
#endif


#define MAKELONG(a, b)      ((LONG)(((WORD)(((DWORD_PTR)(a)) & 0xffff)) \
	| ((DWORD)((WORD)(((DWORD_PTR)(b)) & 0xffff))) << 16))

/*
#define EX_PUSH_LOCK_WAKING          ((ULONG_PTR)0x4)

#define EX_PUSH_LOCK_WAITING         ((ULONG_PTR)0x2)

#define EX_PUSH_LOCK_MULTIPLE_SHARED ((ULONG_PTR)0x8)

#define EX_PUSH_LOCK_SHARE_INC       ((ULONG_PTR)0x10)
#define EX_PUSH_LOCK_PTR_BITS        ((ULONG_PTR)0xf)

#define EX_PUSH_LOCK_LOCK            ((ULONG_PTR)0x1)

#define EX_PUSH_LOCK_FLAGS_EXCLUSIVE  (0x1)
#define EX_PUSH_LOCK_FLAGS_SPINNING_V (0x1)
#define EX_PUSH_LOCK_FLAGS_SPINNING   (0x2)

VOID ExAcquirePushLockShared (
     IN PEX_PUSH_LOCK PushLock
     );

VOID ExfAcquirePushLockShared (
	__inout PEX_PUSH_LOCK_S PushLock
	);

VOID ExpOptimizePushLockList (
	IN PEX_PUSH_LOCK_S PushLock,
	IN EX_PUSH_LOCK_S TopValue
	);

VOID ExfWakePushLock (
	IN PEX_PUSH_LOCK_S PushLock,
	IN EX_PUSH_LOCK_S TopValue
	);

*/

#define __WIN7__

#define try								__try
#define except							__except
#define	MmUserProbeAddress				0x7fff0000

#define SystemModuleInformationClass	11

#ifdef __WIN7__
#	define	CREATE_DBGOBJ_ID		0x3D
#	define	DBG_ACTIVE_PROCESS_ID	0x60
#	define	DBG_CONTINUE_ID			0x61
#	define	REMOVE_PROCESS_DBG_ID	0x121
#	define	WAIT_DBG_EVENT_ID		0x183

#	define	SUSPEND_THREAD_ID		0x16F
#	define	RESUME_THREAD_ID		0x130
#	define	FLUSH_CACHE_ID			0x7D
#	define	CREATE_FILE_ID			0x42
#	define	DUPLICATE_OBJ_ID		0x6F
#	define	MAP_SECTION_ID			0xA8

#define CREATESECTION_SEVICEID		84
#elif __VISTA__
#	define	SUSPEND_THREAD_ID
#elif __2K3__
#	define	SUSPEND_THREAD_ID
#else
#	define	SUSPEND_THREAD_ID
#endif

#define SHLD_DWORD(dest,src,count)	(DWORD)((((DWORD64)dest<<sizeof(DWORD))|src) >> (0x20-count&0x1F))
#define SHRD_DWORD(dest,src,count)	(DWORD)((((DWORD64)src<<sizeof(DWORD))|dest) >> (count&0x1F))

#define ALIGN_VALUE(p,value)		(((ULONG)p+(value-1))&~(value-1))

#define PSP_MAX_LOAD_IMAGE_NOTIFY	0x8

#define ProbeForWriteGenericType(Ptr, Type)                                    \
	do {                                                                       \
	if ((ULONG_PTR)(Ptr) + sizeof(Type) - 1 < (ULONG_PTR)(Ptr) ||          \
	(ULONG_PTR)(Ptr) + sizeof(Type) - 1 >= (ULONG_PTR)MmUserProbeAddress) { \
	ExRaiseAccessViolation();                                          \
		}                                                                      \
		*(volatile Type *)(Ptr) = *(volatile Type *)(Ptr);                     \
	} while (0)

#define ProbeForWriteBoolean(Ptr) ProbeForWriteGenericType(Ptr, BOOLEAN)
#define ProbeForWriteUchar(Ptr) ProbeForWriteGenericType(Ptr, UCHAR)
#define ProbeForWriteChar(Ptr) ProbeForWriteGenericType(Ptr, CHAR)
#define ProbeForWriteUshort(Ptr) ProbeForWriteGenericType(Ptr, USHORT)
#define ProbeForWriteShort(Ptr) ProbeForWriteGenericType(Ptr, SHORT)
#define ProbeForWriteUlong(Ptr) ProbeForWriteGenericType(Ptr, ULONG)
#define ProbeForWriteLong(Ptr) ProbeForWriteGenericType(Ptr, LONG)
#define ProbeForWriteUint(Ptr) ProbeForWriteGenericType(Ptr, UINT)
#define ProbeForWriteInt(Ptr) ProbeForWriteGenericType(Ptr, INT)
#define ProbeForWriteUlonglong(Ptr) ProbeForWriteGenericType(Ptr, ULONGLONG)
#define ProbeForWriteLonglong(Ptr) ProbeForWriteGenericType(Ptr, LONGLONG)
#define ProbeForWritePointer(Ptr) ProbeForWriteGenericType(Ptr, PVOID)
#define ProbeForWriteHandle(Ptr) ProbeForWriteGenericType(Ptr, HANDLE)
#define ProbeForWriteLangid(Ptr) ProbeForWriteGenericType(Ptr, LANGID)
#define ProbeForWriteSize_t(Ptr) ProbeForWriteGenericType(Ptr, SIZE_T)
#define ProbeForWriteLargeInteger(Ptr) ProbeForWriteGenericType(&((PLARGE_INTEGER)Ptr)->QuadPart, LONGLONG)
#define ProbeForWriteUlargeInteger(Ptr) ProbeForWriteGenericType(&((PULARGE_INTEGER)Ptr)->QuadPart, ULONGLONG)
#define ProbeForWriteUnicodeString(Ptr) ProbeForWriteGenericType((PUNICODE_STRING)Ptr, UNICODE_STRING)

#define ProbeForReadGenericType(Ptr, Type, Default)                            \
	(((ULONG_PTR)(Ptr) + sizeof(Type) - 1 < (ULONG_PTR)(Ptr) ||                \
	(ULONG_PTR)(Ptr) + sizeof(Type) - 1 >= (ULONG_PTR)MmUserProbeAddress) ?    \
	ExRaiseAccessViolation(), Default :										   \
	*(const volatile Type *)(Ptr))

#define ProbeForReadBoolean(Ptr) ProbeForReadGenericType(Ptr, BOOLEAN, FALSE)
#define ProbeForReadUchar(Ptr) ProbeForReadGenericType(Ptr, UCHAR, 0)
#define ProbeForReadChar(Ptr) ProbeForReadGenericType(Ptr, CHAR, 0)
#define ProbeForReadUshort(Ptr) ProbeForReadGenericType(Ptr, USHORT, 0)
#define ProbeForReadShort(Ptr) ProbeForReadGenericType(Ptr, SHORT, 0)
#define ProbeForReadUlong(Ptr) ProbeForReadGenericType(Ptr, ULONG, 0)
#define ProbeForReadLong(Ptr) ProbeForReadGenericType(Ptr, LONG, 0)
#define ProbeForReadUint(Ptr) ProbeForReadGenericType(Ptr, UINT, 0)
#define ProbeForReadInt(Ptr) ProbeForReadGenericType(Ptr, INT, 0)
#define ProbeForReadUlonglong(Ptr) ProbeForReadGenericType(Ptr, ULONGLONG, 0)
#define ProbeForReadLonglong(Ptr) ProbeForReadGenericType(Ptr, LONGLONG, 0)
#define ProbeForReadPointer(Ptr) ProbeForReadGenericType(Ptr, PVOID, NULL)
#define ProbeForReadHandle(Ptr) ProbeForReadGenericType(Ptr, HANDLE, NULL)
#define ProbeForReadLangid(Ptr) ProbeForReadGenericType(Ptr, LANGID, 0)
#define ProbeForReadSize_t(Ptr) ProbeForReadGenericType(Ptr, SIZE_T, 0)
#define ProbeForReadLargeInteger(Ptr) ProbeForReadGenericType((const LARGE_INTEGER *)(Ptr), LARGE_INTEGER, __emptyLargeInteger)
#define ProbeForReadUlargeInteger(Ptr) ProbeForReadGenericType((const ULARGE_INTEGER *)(Ptr), ULARGE_INTEGER, __emptyULargeInteger)
#define ProbeForReadUnicodeString(Ptr) ProbeForReadGenericType((const UNICODE_STRING *)(Ptr), UNICODE_STRING, __emptyUnicodeString)
#define ProbeForReadIoStatusBlock(Ptr) ProbeForReadGenericType((const IO_STATUS_BLOCK *)(Ptr), IO_STATUS_BLOCK, __emptyIoStatusBlock)

#define ProbeForReadSmallStructure(Address, Size, Alignment) {               \
    ASSERT(((Alignment) == 1) || ((Alignment) == 2) ||                       \
           ((Alignment) == 4) || ((Alignment) == 8) ||                       \
           ((Alignment) == 16));                                             \
    if ((Size == 0) || (Size > 0x10000)) {                                   \
        ASSERT(0);                                                           \
        ProbeForRead(Address, Size, Alignment);                              \
    } else {                                                                 \
        if (((ULONG_PTR)(Address) & ((Alignment) - 1)) != 0) {               \
            ExRaiseDatatypeMisalignment();                                   \
        }                                                                    \
        if ((ULONG_PTR)(Address) >= (ULONG_PTR)MM_USER_PROBE_ADDRESS) {      \
            *(volatile UCHAR * const)MM_USER_PROBE_ADDRESS = 0;              \
        }                                                                    \
    }                                                                        \
}

#define ProbeAndReadUchar(Address) \
	(((Address) >= (UCHAR * const)MM_USER_PROBE_ADDRESS) ? \
	(*(volatile UCHAR * const)MM_USER_PROBE_ADDRESS) : (*(volatile UCHAR *)(Address)))


#define ProbeAndReadUlong(Address) \
    (((Address) >= (ULONG * const)MM_USER_PROBE_ADDRESS) ? \
        (*(volatile ULONG * const)MM_USER_PROBE_ADDRESS) : (*(volatile ULONG *)(Address)))


#define ProbeAndWriteUlong(Address, Value) {                                 \
	if ((Address) >= (ULONG * const)MM_USER_PROBE_ADDRESS) {                 \
	*(volatile ULONG * const)MM_USER_PROBE_ADDRESS = 0;						 \
	}                                                                        \
																			 \
	*(Address) = (Value);                                                    \
}

#define ProbeAndWriteUlong_ptr(Address, Value) {                             \
    if ((Address) >= (ULONG_PTR * const)MM_USER_PROBE_ADDRESS) {             \
        *(volatile ULONG_PTR * const)MM_USER_PROBE_ADDRESS = 0;              \
    }                                                                        \
                                                                             \
    *(Address) = (Value);                                                    \
}

#define ProbeAndWritePointer(Address, Value) {                               \
    if ((Address) >= (PVOID * const)MM_USER_PROBE_ADDRESS) {                 \
        *(volatile ULONG * const)MM_USER_PROBE_ADDRESS = 0;                  \
    }                                                                        \
                                                                             \
    *(Address) = (Value);                                                    \
}

VOID
ProbeForWriteSmallStructure (
    IN PVOID Address,
    IN SIZE_T Size,
    IN ULONG Alignment
    );

#define PS_SET_BITS(Flags, Flag) \
	RtlInterlockedSetBitsDiscardReturn (Flags, Flag)

#define PS_TEST_SET_BITS(Flags, Flag) \
	RtlInterlockedSetBits (Flags, Flag)

#define MI_VA_TO_PAGE(va) ((ULONG_PTR)(va) >> PAGE_SHIFT)

#define MI_VA_TO_VPN(va)  ((ULONG_PTR)(va) >> PAGE_SHIFT)

#define MI_VPN_TO_VA(vpn)  (PVOID)((vpn) << PAGE_SHIFT)

#define MI_VPN_TO_VA_ENDING(vpn)  (PVOID)(((vpn) << PAGE_SHIFT) | (PAGE_SIZE - 1))

#define MiGetByteOffset(va) ((ULONG_PTR)(va) & (PAGE_SIZE - 1))

#define KiQueryNxThunkEmulationState() \
	((PKTHREAD_S)KeGetCurrentThread())->ApcState.Process->Flags.DisableThunkEmulation

#define LOCK_ADDRESS_SPACE(PROCESS)                                  \
	ExAcquirePushLockShared (&((PROCESS)->AddressCreationLock));

#define UNLOCK_ADDRESS_SPACE(PROCESS)                               \
	ExReleasePushLockShared (&((PROCESS)->AddressCreationLock));

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //仅适用于checked build版本
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

typedef NTSTATUS (*PEX_CALLBACK_FUNCTION ) (
	IN PVOID CallbackContext,
	IN PVOID Argument1,
	IN PVOID Argument2
	);

typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
	EX_RUNDOWN_REF        RundownProtect;
	PEX_CALLBACK_FUNCTION Function;
	PVOID                 Context;
} EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

typedef struct _EX_CALLBACK {
	EX_FAST_REF RoutineBlock;
} EX_CALLBACK, *PEX_CALLBACK;

typedef struct
{
	PVOID section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	char ImageName[MAXIMUM_FILENAME_LENGTH];

}SYSTEM_MODULE,*PSYSTEM_MODULE;

typedef struct
{
	ULONG ModuleCount;
	SYSTEM_MODULE Module[0];    
}SYSTEM_MODULE_INFORMATION,*PSYSTEM_MODULE_INFORMATION;

//global
static PKUSER_SHARED_DATA_S	g_lpUserSharedData = (PKUSER_SHARED_DATA_S)0xFFDF0000; 

PDRIVER_OBJECT	g_LocateDriverObj;
struct _MODULE_ENTRY* g_KernlModule;

ULONG	PspNotifyEnableMask;
EX_CALLBACK *PspLoadImageNotifyRoutine;

ULONG	*PspSystemDlls;

//结构声明
typedef struct _SIGNATURE_INFO{
	UCHAR	cSingature;
	int		Offset;
}SIGNATURE_INFO,*PSIGNATURE_INFO;

//函数指针定义
typedef KPROCESSOR_MODE (*KEGETPREVIOUSMODE)(VOID);
typedef LONG (*EXSYSTEMEXCEPTIONFILTER)(VOID);
typedef NTSTATUS (__stdcall *OBCREATEOBJECT)(
	__in KPROCESSOR_MODE ProbeMode,
	__in POBJECT_TYPE ObjectType,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in KPROCESSOR_MODE OwnershipMode,
	__inout_opt PVOID ParseContext,
	__in ULONG ObjectBodySize,
	__in ULONG PagedPoolCharge,
	__in ULONG NonPagedPoolCharge,
	__out PVOID *Object
	);
typedef NTSTATUS (*NTSUSPENDTHREAD)(
	__in HANDLE ThreadHandle,
	__in PULONG PreviousSuspendCount
	);

typedef NTSTATUS
	(__stdcall *PSSUSPENDTHREAD)(
	IN PETHREAD_S Thread,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);

typedef PIMAGE_NT_HEADERS 
	(*RTLIMAGENTHEADER)(
	PVOID Base
	);
typedef NTSTATUS
	(*NTRESUMETHREAD)(
	__in HANDLE ThreadHandle,
	__out_opt PULONG PreviousSuspendCount
	);

typedef NTSTATUS
	(__stdcall *OBCLOSEHANDLE)(
	__in HANDLE Handle,
	__in KPROCESSOR_MODE PreviousMode
	);
typedef NTSTATUS
	(*NTFLUSHINSTRUCTIONCACHE)(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in SIZE_T Length
	);
typedef NTSTATUS 
	(*NTCREATEFILE) (
	__out PHANDLE FileHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt PLARGE_INTEGER AllocationSize,
	__in ULONG FileAttributes,
	__in ULONG ShareAccess,
	__in ULONG CreateDisposition,
	__in ULONG CreateOptions,
	__in_bcount_opt(EaLength) PVOID EaBuffer,
	__in ULONG EaLength
	);
typedef NTSTATUS
	(*PSREFERENCEPROCESSFILEPOINTER)(
	IN PEPROCESS Process,
	OUT PVOID *OutFileObject
	);
typedef VOID
	(*KICHECKFORKERNELAPCDELIVERY)(
	VOID
	);
typedef VOID
	(*EXFACQUIREPUSHLOCKSHARED)(
	__inout PEX_PUSH_LOCK_S PushLock
	);
typedef VOID
	(*EXFRELEASEPUSHLOCKSHARED)(
	__inout PEX_PUSH_LOCK_S PushLock
	);
typedef VOID
	(*KETHAWALLTHREADS)(
	VOID
	);
typedef VOID
	(*KEFREEZEALLTHREADS)(
	VOID
	);
typedef NTSTATUS
	(*OBDUPLICATEOBJECT)(
	IN PEPROCESS_S SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS_S TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
	);

typedef NTSTATUS 
	(*ZWQUERYSYSTEMINFORMATION)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength OPTIONAL
	);

typedef NTSTATUS
	(*OBREFERENCEOBJECTBYHANDLE)(
	__in HANDLE Handle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__out PVOID *Object,
	__out_opt POBJECT_HANDLE_INFORMATION HandleInformation
	);

typedef LONG_PTR
	(*OBFDEREFERENCEOBJECT)(
	__in PVOID Object
	);
typedef LONG_PTR
	(*OBFREFERENCEOBJECT)(
	__in PVOID Object
	);
typedef NTSTATUS
	(*OBOPENOBJECTBYPOINTER)(
	__in PVOID Object,
	__in ULONG HandleAttributes,
	__in_opt PACCESS_STATE PassedAccessState,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__out PHANDLE Handle
	);
typedef NTSTATUS
	(*OBINSERTOBJECT)(
	__in PVOID Object,
	__inout_opt PACCESS_STATE PassedAccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in ULONG ObjectPointerBias,
	__out_opt PVOID *NewObject,
	__out_opt PHANDLE Handle
	);
typedef VOID
	(*KESTACKATTACHPROCESS)(
	__inout PRKPROCESS PROCESS,
	__out PRKAPC_STATE ApcState
	);

typedef VOID
	(*KEUNSTACKDETACHPROCESS)(
	__in PRKAPC_STATE ApcState
	);

typedef NTSTATUS
	(*PSLOOKUPPROCESSBYPROCESSID)(
	__in HANDLE ProcessId,
	__deref_out PEPROCESS *Process
	);

typedef NTSTATUS
	(*NTPROTECTVIRTUALMEMORY)(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtectWin32,
	__out PULONG OldProtect
	);

KEGETPREVIOUSMODE KeGetPreviousMode;
EXSYSTEMEXCEPTIONFILTER ExSystemExceptionFilter;
OBCREATEOBJECT	ObCreateObject;
NTSUSPENDTHREAD	NtSuspendThread;
PSSUSPENDTHREAD PsSuspendThread;
RTLIMAGENTHEADER	RtlImageNtHeader;
NTRESUMETHREAD		NtResumeThread;
OBCLOSEHANDLE		ObCloseHandle;
NTFLUSHINSTRUCTIONCACHE	NtFlushInstructionCache;
#define ZwFlushInstructionCache	NtFlushInstructionCache
PSREFERENCEPROCESSFILEPOINTER	PsReferenceProcessFilePointer;
KICHECKFORKERNELAPCDELIVERY	KiCheckForKernelApcDelivery;
EXFACQUIREPUSHLOCKSHARED	ExfAcquirePushLockShared;
EXFRELEASEPUSHLOCKSHARED	ExfReleasePushLockShared;
KETHAWALLTHREADS			KeThawAllThreads;
KEFREEZEALLTHREADS			KeFreezeAllThreads;
OBDUPLICATEOBJECT			OrigObDuplicateObject;
OBREFERENCEOBJECTBYHANDLE	ObReferenceObjectByHandle_S;
OBOPENOBJECTBYPOINTER		ObOpenObjectByPointer_S;
OBINSERTOBJECT				ObInsertObject_S;
KESTACKATTACHPROCESS		KeStackAttachProcess_S;
KEUNSTACKDETACHPROCESS		KeUnstackDetachProcess_S;
PSLOOKUPPROCESSBYPROCESSID	PsLookupProcessByProcessId_S;
NTPROTECTVIRTUALMEMORY		NtProtectVirtualMemory;

ULONG		NewObfDereferenceObject;
ULONG		NewObfReferenceObject;
ULONG		NewKeResumeThread;
//global
EX_PUSH_LOCK_S ExpCallBackFlush;
EX_PUSH_LOCK_S MiChangeControlAreaFileLock;

extern POBJECT_TYPE *PsProcessType;
extern POBJECT_TYPE *PsThreadType;

extern ULONG	g_new_kernel_inc;

// 初始化函数指针
BOOLEAN InitCommon();

PETHREAD_S PsGetNextProcessThread (
	IN PEPROCESS_S Process,
	IN PETHREAD_S Thread
	);

NTSTATUS
	MmGetFileNameForSection (
	IN PSEGMENT_OBJECT SectionObject,
	OUT POBJECT_NAME_INFORMATION *FileNameInfo
	);

NTSTATUS
MmGetFileNameForAddress (
    IN PVOID ProcessVa,
    OUT PUNICODE_STRING FileName
    );

ULONG GetAddress(ULONG uAddress,UCHAR *Signature,int flag);

ULONG SearchAddressForSign(
	ULONG uStartBase,
	ULONG uSearchLength,
	SIGNATURE_INFO SignatureInfo[5]
	);

void PageProtectOn();
void PageProtectOff();

PLDR_DATA_TABLE_ENTRY SearchDriver(
	PDRIVER_OBJECT pDriverObject,
	wchar_t *strDriverName);

BOOLEAN	Jmp_HookFunction(
	IN ULONG Destination,
	IN ULONG Source,
	IN UCHAR *Ori_Code
	);

VOID Res_HookFunction(
	IN ULONG	Destination,
	IN UCHAR	*Ori_Code,
	IN ULONG	Length
	);

VOID PsCallImageNotifyRoutines(
	IN PUNICODE_STRING ImageName,
	IN HANDLE ProcessId,
	IN PVOID FileObject,
	OUT PIMAGE_INFO_EX ImageInfoEx);

LOGICAL
	ExFastRefDereference (
	__inout PEX_FAST_REF FastRef,
	__in PVOID Object
	);

EX_FAST_REF
	ExFastReference (
	__inout PEX_FAST_REF FastRef
	);

PEX_CALLBACK_ROUTINE_BLOCK
	ExReferenceCallBackBlock(
	OUT PEX_CALLBACK CallBack);

VOID ExDereferenceCallBackBlock (
	IN OUT PEX_CALLBACK CallBack,
	IN PEX_CALLBACK_ROUTINE_BLOCK CallBackBlock
	);

VOID ExAcquirePushLockShared (
	IN PEX_PUSH_LOCK_S PushLock
	);

VOID ExReleasePushLockShared (
	IN PEX_PUSH_LOCK_S PushLock
	);

VOID
	KeEnterCriticalRegionThread (
	PKTHREAD_S Thread
	);

VOID
	KeLeaveCriticalRegionThread (
	IN PKTHREAD_S Thread
	);

LOGICAL
	ExFastRefAddAdditionalReferenceCounts (
	__inout PEX_FAST_REF FastRef,
	__in PVOID Object,
	__in ULONG RefsToAdd
	);

TABLE_SEARCH_RESULT
MiFindNodeOrParent (
    IN PMM_AVL_TABLE Table,
    IN ULONG_PTR StartingVpn,
    OUT PMMADDRESS_NODE *NodeOrParent
    );

PFILE_OBJECT
	MiReferenceControlAreaFile(
	PCONTROL_AREA CtrlArea);

PMMVAD
FASTCALL
MiLocateAddress (
    IN PVOID VirtualAddress
    );

BOOLEAN
MmCheckForSafeExecution (
    IN PVOID InstructionPointer,
    IN PVOID StackPointer,
    IN PVOID BranchTarget,
    IN BOOLEAN PermitStackExecution
    );

LOGICAL
KiEmulateAtlThunk (
    IN OUT ULONG *InstructionPointer,
    IN OUT ULONG *StackPointer,
    IN OUT ULONG *Eax,
    IN OUT ULONG *Ecx,
    IN OUT ULONG *Edx
    );

BOOLEAN KiCheckForAtlThunk(
	PEXCEPTION_RECORD ExceptionRecord,		//edx
	PCONTEXT	Context						//eax
	);

PFILE_OBJECT
	MmGetFileObjectForSection (
	IN PSEGMENT_OBJECT Section
	);

PVOID
	ObFastReferenceObject (
	IN PEX_FAST_REF FastRef
	);

PVOID
	ObFastReferenceObjectLocked (
	IN PEX_FAST_REF FastRef
	);

ULONG GetDriverDataEntry(
	PDRIVER_OBJECT pDriverObj,
	wchar_t *szFileName
	);

NTSTATUS __stdcall
	ObDuplicateObject(
	IN PEPROCESS_S SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS_S TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
	);
PVOID PsCaptureExceptionPort(
	IN PEPROCESS_S Process);

NTSTATUS GetModuleByName(
	char *szModuleName,PSYSTEM_MODULE ImageInfo);

LONG_PTR __stdcall ObfDereferenceObject_S(
	__in PVOID Object);

LONG_PTR __stdcall ObfReferenceObject_S(
	__in PVOID Object);
NTSTATUS __stdcall KeResumeThread(
	__inout PETHREAD_S Thread);

char* PsGetProcessImageFileName(PEPROCESS Process);
POBJECT_TYPE ObGetObjectType(PVOID Object);

void TrapRecord(PKTRAP_FRAME_S kTrapFrame);

ULONG SearchProcessById(ULONG ProcessId);

ULONG SearchProcess(char *szProcessName);

#endif