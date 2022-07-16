#ifndef __KDBGSYS_H__
#define __KDBGSYS_H__

#include "struct.h"

//调试相关标记
#define DEBUG_OBJECT_DELETE_PENDING			(0x1) // Debug object is delete pending.
#define DEBUG_OBJECT_KILL_ON_CLOSE			(0x2) // Kill all debugged processes on close

#define DEBUG_KILL_ON_CLOSE					(0x01)

#define DEBUG_EVENT_READ					(0x01)  // Event had been seen by win32 app
#define DEBUG_EVENT_NOWAIT					(0x02)  // No waiter one this. Just free the pool
#define DEBUG_EVENT_INACTIVE				(0x04)  // The message is in inactive. It may be activated or deleted later
#define DEBUG_EVENT_RELEASE					(0x08)  // Release rundown protection on this thread
#define DEBUG_EVENT_PROTECT_FAILED			(0x10)  // Rundown protection failed to be acquired on this thread
#define DEBUG_EVENT_SUSPEND					(0x20)  // Resume thread on continue

//
// Define debug object access types. No security is present on this object.
//
#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
	DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)

//一些内核其他定义声明

//
// Used to signify that the delete APC has been queued or the
// thread has called PspExitThread itself.
//
#define PS_CROSS_THREAD_FLAGS_TERMINATED           0x00000001UL
//
// Thread create failed
//
#define PS_CROSS_THREAD_FLAGS_DEADTHREAD           0x00000002UL
//
// Debugger isn't shown this thread
//
#define PS_CROSS_THREAD_FLAGS_HIDEFROMDBG          0x00000004UL
//
// Thread is impersonating
//
#define PS_CROSS_THREAD_FLAGS_IMPERSONATING        0x00000008UL
//
// This is a system thread
//
#define PS_CROSS_THREAD_FLAGS_SYSTEM               0x00000010UL
//
// Hard errors are disabled for this thread
//
#define PS_CROSS_THREAD_FLAGS_HARD_ERRORS_DISABLED 0x00000020UL
//
// We should break in when this thread is terminated
//
#define PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION 0x00000040UL
//
// This thread should skip sending its create thread message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG    0x00000080UL
//
// This thread should skip sending its final thread termination message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG 0x00000100UL

#define IS_SYSTEM_THREAD(Thread)  (((Thread)->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SYSTEM) != 0)


#define PS_PROCESS_FLAGS_CREATE_REPORTED        0x00000001UL // Create process debug call has occurred
#define PS_PROCESS_FLAGS_NO_DEBUG_INHERIT       0x00000002UL // Don't inherit debug port
#define PS_PROCESS_FLAGS_PROCESS_EXITING        0x00000004UL // PspExitProcess entered
#define PS_PROCESS_FLAGS_PROCESS_DELETE         0x00000008UL // Delete process has been issued
#define PS_PROCESS_FLAGS_WOW64_SPLIT_PAGES      0x00000010UL // Wow64 split pages
#define PS_PROCESS_FLAGS_VM_DELETED             0x00000020UL // VM is deleted
#define PS_PROCESS_FLAGS_OUTSWAP_ENABLED        0x00000040UL // Outswap enabled
#define PS_PROCESS_FLAGS_OUTSWAPPED             0x00000080UL // Outswapped
#define PS_PROCESS_FLAGS_FORK_FAILED            0x00000100UL // Fork status
#define PS_PROCESS_FLAGS_WOW64_4GB_VA_SPACE     0x00000200UL // Wow64 process with 4gb virtual address space
#define PS_PROCESS_FLAGS_ADDRESS_SPACE1         0x00000400UL // Addr space state1
#define PS_PROCESS_FLAGS_ADDRESS_SPACE2         0x00000800UL // Addr space state2
#define PS_PROCESS_FLAGS_SET_TIMER_RESOLUTION   0x00001000UL // SetTimerResolution has been called
#define PS_PROCESS_FLAGS_BREAK_ON_TERMINATION   0x00002000UL // Break on process termination
#define PS_PROCESS_FLAGS_CREATING_SESSION       0x00004000UL // Process is creating a session
#define PS_PROCESS_FLAGS_USING_WRITE_WATCH      0x00008000UL // Process is using the write watch APIs
#define PS_PROCESS_FLAGS_IN_SESSION             0x00010000UL // Process is in a session
#define PS_PROCESS_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00020000UL // Process must use native address space (Win64 only)
#define PS_PROCESS_FLAGS_HAS_ADDRESS_SPACE      0x00040000UL // This process has an address space
#define PS_PROCESS_FLAGS_LAUNCH_PREFETCHED      0x00080000UL // Process launch was prefetched
#define PS_PROCESS_INJECT_INPAGE_ERRORS         0x00100000UL // Process should be given inpage errors - hardcoded in trap.asm too
#define PS_PROCESS_FLAGS_VM_TOP_DOWN            0x00200000UL // Process memory allocations default to top-down
#define PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE      0x00400000UL // We have sent a message for this image
#define PS_PROCESS_FLAGS_PDE_UPDATE_NEEDED      0x00800000UL // The system PDEs need updating for this process (NT32 only)
#define PS_PROCESS_FLAGS_VDM_ALLOWED            0x01000000UL // Process allowed to invoke NTVDM support
#define PS_PROCESS_FLAGS_SMAP_ALLOWED           0x02000000UL // Process allowed to invoke SMAP support
#define PS_PROCESS_FLAGS_CREATE_FAILED          0x04000000UL // Process create failed

#define PS_PROCESS_FLAGS_DEFAULT_IO_PRIORITY    0x38000000UL // The default I/O priority for created threads. (3 bits)

#define PS_PROCESS_FLAGS_PRIORITY_SHIFT         27

#define PS_PROCESS_FLAGS_EXECUTE_SPARE1         0x40000000UL //
#define PS_PROCESS_FLAGS_EXECUTE_SPARE2         0x80000000UL //


#define THREAD_TERMINATE						(0x0001)  
#define THREAD_SUSPEND_RESUME					(0x0002)  
#define THREAD_GET_CONTEXT						(0x0008)  
#define THREAD_SET_CONTEXT						(0x0010)  
#define THREAD_QUERY_INFORMATION				(0x0040)  
#define THREAD_SET_INFORMATION					(0x0020)  
#define THREAD_SET_THREAD_TOKEN					(0x0080)
#define THREAD_IMPERSONATE						(0x0100)
#define THREAD_DIRECT_IMPERSONATION				(0x0200)

#define PROCESS_TERMINATE						(0x0001)  
#define PROCESS_CREATE_THREAD					(0x0002)  
#define PROCESS_SET_SESSIONID					(0x0004)  
#define PROCESS_VM_OPERATION					(0x0008)  
#define PROCESS_VM_READ							(0x0010)  
#define PROCESS_VM_WRITE						(0x0020)  
#define PROCESS_DUP_HANDLE						(0x0040)  
#define PROCESS_CREATE_PROCESS					(0x0080)  
#define PROCESS_SET_QUOTA						(0x0100)  
#define PROCESS_SET_INFORMATION					(0x0200)  
#define PROCESS_QUERY_INFORMATION				(0x0400)  
#define PROCESS_SUSPEND_RESUME					(0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION		(0x1000)  


#define LPC_REQUEST								1
#define LPC_REPLY								2
#define LPC_DATAGRAM							3
#define LPC_LOST_REPLY							4
#define LPC_PORT_CLOSED							5
#define LPC_CLIENT_DIED							6
#define LPC_EXCEPTION							7
#define LPC_DEBUG_EVENT							8
#define LPC_ERROR_EVENT							9
#define LPC_CONNECTION_REQUEST					10

#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs,field) \
	((hdrs)->OptionalHeader.##field)

#define DBGKM_MSG_OVERHEAD \
	(FIELD_OFFSET(DBGKM_APIMSG, u.Exception) - sizeof(PORT_MESSAGE))

#define DBGKM_API_MSG_LENGTH(TypeSize) \
	((sizeof(DBGKM_APIMSG) << 16) | (DBGKM_MSG_OVERHEAD + (TypeSize)))

#define DBGKM_FORMAT_API_MSG(m,Number,TypeSize)             \
	(m).h.u1.Length = DBGKM_API_MSG_LENGTH((TypeSize));     \
	(m).h.u2.ZeroInit = LPC_DEBUG_EVENT;                    \
	(m).ApiNumber = (Number)

//结构相关定义

//枚举类型，指定是哪种事件
typedef enum _DBGKM_APINUMBER { 
	DbgKmExceptionApi, 
	DbgKmCreateThreadApi, 
	DbgKmCreateProcessApi, 
	DbgKmExitThreadApi, 
	DbgKmExitProcessApi, 
	DbgKmLoadDllApi, 
	DbgKmUnloadDllApi, 
	DbgKmMaxApiNumber 
} DBGKM_APINUMBER; 

//异常消息
typedef struct _DBGKM_EXCEPTION { 
	EXCEPTION_RECORD ExceptionRecord; 
	ULONG FirstChance; 
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION; 

//创建线程消息
typedef struct _DBGKM_CREATE_THREAD { 
	ULONG SubSystemKey; 
	PVOID StartAddress; 
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD; 

//创建进程消息
typedef struct _DBGKM_CREATE_PROCESS { 
	ULONG SubSystemKey; 
	HANDLE FileHandle; 
	PVOID BaseOfImage; 
	ULONG DebugInfoFileOffset; 
	ULONG DebugInfoSize; 
	DBGKM_CREATE_THREAD InitialThread; 
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS; 

//退出线程消息
typedef struct _DBGKM_EXIT_THREAD { 
	NTSTATUS ExitStatus; 
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD; 

//退出进程消息
typedef struct _DBGKM_EXIT_PROCESS { 
	NTSTATUS ExitStatus; 
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS; 

//加载模块消息
typedef struct _DBGKM_LOAD_DLL { 
	HANDLE FileHandle; 
	PVOID BaseOfDll; 
	ULONG DebugInfoFileOffset; 
	ULONG DebugInfoSize;
	PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL; 

//卸载模块消息
typedef struct _DBGKM_UNLOAD_DLL { 
	PVOID BaseAddress; 
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL; 

//PORT_MESSAGE结构
typedef struct _PORT_MESSAGE
{
	union {
		struct {
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union {
		struct {
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		float DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		ULONG ClientViewSize;
		ULONG CallbackId;
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

//消息结构
typedef struct _DBGKM_APIMSG { 
	PORT_MESSAGE h;								//+0x0
	DBGKM_APINUMBER ApiNumber;					//+0x18
	NTSTATUS ReturnedStatus;					//+0x1c
	union { 
		DBGKM_EXCEPTION Exception; 
		DBGKM_CREATE_THREAD CreateThread; 
		DBGKM_CREATE_PROCESS CreateProcessInfo; 
		DBGKM_EXIT_THREAD ExitThread; 
		DBGKM_EXIT_PROCESS ExitProcess; 
		DBGKM_LOAD_DLL LoadDll; 
		DBGKM_UNLOAD_DLL UnloadDll; 
	} u;										//0x20

	//以上这个部分占了0x74个大小，而windows7此结构的大小是A8，下面应该是输入异常相关的信息，为此，我们要凑够0xA8个大小，不然处理异常的时候会蓝屏掉
	UCHAR	ExceptPart[0x34];
} DBGKM_APIMSG, *PDBGKM_APIMSG;

//调试对象
typedef struct _DEBUG_OBJECT
{
	KEVENT EventsPresent;
	FAST_MUTEX Mutex;
	LIST_ENTRY EventList;
	union
	{
		ULONG Flags;
		struct
		{
			UCHAR DebuggerInactive:1;
			UCHAR KillProcessOnExit:1;
		};
	};
} DEBUG_OBJECT, *PDEBUG_OBJECT;


typedef struct _DEBUG_EVENT
{
	LIST_ENTRY EventList;				//+0x0
	KEVENT ContinueEvent;				//+0x8
	CLIENT_ID ClientId;					//+0x18
	PEPROCESS_S Process;				//+0x20
	PETHREAD_S Thread;					//+0x24
	NTSTATUS Status;					//+0x28
	ULONG Flags;						//+0x2C
	PETHREAD_S BackoutThread;			//+0x30
	ULONG Unkown1;						//+0x34                //这个不晓得做什么的，反正就是多出来了.....
	DBGKM_APIMSG ApiMsg;				//+0x38
} DEBUG_EVENT, *PDEBUG_EVENT;


typedef struct _DBGUI_CREATE_THREAD {
	HANDLE HandleToThread;
	DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, *PDBGUI_CREATE_THREAD;

typedef struct _DBGUI_CREATE_PROCESS {
	HANDLE HandleToProcess;
	HANDLE HandleToThread;
	DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, *PDBGUI_CREATE_PROCESS;

typedef enum _DBG_STATE {
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

typedef struct _DBGUI_WAIT_STATE_CHANGE {
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union {
		DBGKM_EXCEPTION Exception;
		DBGUI_CREATE_THREAD CreateThread;
		DBGUI_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

typedef NTSTATUS
	(__stdcall *DBGKPSENDERRORMESSAGE)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PDBGKM_APIMSG	DbgApiMsg
	);

//函数声明
NTSTATUS __stdcall NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	);

NTSTATUS __stdcall NtDebugActiveProcess(
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle
	);
NTSTATUS DbgkpPostFakeProcessCreateMessages (
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD_S *pLastThread
	);

NTSTATUS DbgkpPostFakeThreadMessages(
	PETHREAD_S	StartThread,
	PEPROCESS_S	Process,
	PDEBUG_OBJECT	DebugObject,
	PETHREAD_S	*pFirstThread,
	PETHREAD_S	*pLastThread
	);
VOID DbgkSendSystemDllMessages(
	PETHREAD_S		Thread,
	PDEBUG_OBJECT	DebugObject,
	PDBGKM_APIMSG	ApiMsg
	);
NTSTATUS DbgkpSendApiMessage(
	PDBGKM_APIMSG ApiMsg,
	ULONG	Flag					//eax传参
	);
BOOLEAN
	DbgkpSuspendProcess (
	VOID
	);
PVOID PsQuerySystemDllInfo(
	ULONG index);
NTSTATUS
	DbgkpQueueMessage (
	IN PEPROCESS_S Process,
	IN PETHREAD_S Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
	);
NTSTATUS
	DbgkpPostModuleMessages (
	IN PEPROCESS_S Process,
	IN PETHREAD_S Thread,
	IN PDEBUG_OBJECT DebugObject
	);

VOID DbgkpWakeTarget (
	IN PDEBUG_EVENT DebugEvent
	);

VOID DbgkpMarkProcessPeb (
	PEPROCESS_S Process
	);

VOID DbgkpFreeDebugEvent (
	IN PDEBUG_EVENT DebugEvent
	);

NTSTATUS __stdcall
	NtDebugContinue (
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus
	);

NTSTATUS __stdcall
	NtWaitForDebugEvent (
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
	);

VOID DbgkpConvertKernelToUserStateChange (
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	PDEBUG_EVENT DebugEvent);

VOID DbgkpOpenHandles (
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	PEPROCESS_S Process,
	PETHREAD_S Thread
	);

NTSTATUS
	DbgkpSetProcessDebugObject (
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD_S LastThread
	);

HANDLE
	DbgkpSectionToFileHandle(
	IN PVOID SectionObject
	);

NTSTATUS __stdcall
	NtRemoveProcessDebug (
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle
	);

NTSTATUS
	DbgkClearProcessDebugObject (
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT SourceDebugObject
	);

VOID __stdcall
	DbgkCreateThread(
	PETHREAD_S Thread
	);

VOID __stdcall
	DbgkExitThread(
	NTSTATUS ExitStatus
	);

VOID __stdcall
	DbgkExitProcess(
	NTSTATUS ExitStatus
	);

VOID __stdcall
	DbgkMapViewOfSection(
	IN PVOID SectionObject,
	IN PVOID BaseAddress,			//edx
	IN PEPROCESS_S	Process			//ecx
	);

VOID DbgkMapViewOfSection_S();

VOID __stdcall
	DbgkUnMapViewOfSection(
	IN PEPROCESS_S	Process,			//eax
	IN PVOID	BaseAddress
	);

VOID DbgkUnMapViewOfSection_S();

BOOLEAN __stdcall
DbgkForwardException(
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN BOOLEAN DebugException,
    IN BOOLEAN SecondChance
    );

NTSTATUS __stdcall
	DbgkpSendApiMessageLpc(
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN PVOID Port,
	IN BOOLEAN SuspendProcess
	);

NTSTATUS __stdcall DbgkCopyProcessDebugPort(
	IN PEPROCESS_S TargetProcess,
	IN PEPROCESS_S SourceProcess,
	IN PDEBUG_OBJECT DebugObject,			//EAX
	OUT PBOOLEAN bFlag
	);

VOID DbgkCopyProcessDebugPort_S();

// 初始化调试函数指针
BOOLEAN InitDbgSys();

//global
BOOLEAN		g_bInitDebugSys;

FAST_MUTEX	DbgkpProcessDebugPortMutex;
POBJECT_TYPE *DbgkDebugObjectType;

ULONG	g_OrigDbgkpSendApiMessageLpc;
DBGKPSENDERRORMESSAGE DbgkpSendErrorMessage;

//////////////////////////////////////////////////////////////////////////
//hook
ULONG	g_OrigKDbgCreateThread;
BOOLEAN	g_bHookDbgCreateThread;
UCHAR	g_DbgCreateThreadCode[0x5];

ULONG	g_OrigKDbgExitProcess;
BOOLEAN	g_bHookDbgExitProcess;
UCHAR	g_DbgExitProcessCode[0x5];

ULONG	g_OrigKDbgExitThread;
BOOLEAN	g_bHookDbgExitThread;
UCHAR	g_DbgExitThreadCode[0x5];

ULONG	g_OrigKDbgMapViewOfSection;
BOOLEAN	g_bHookDbgMapViewOfSection;
UCHAR	g_DbgMapViewOfSectionCode[0x5];

ULONG	g_OrigKDbgUnMapViewOfSection;
BOOLEAN	g_bHookDbgUnMapViewOfSection;
UCHAR	g_DbgUnMapViewOfSectionCode[0x5];

ULONG	g_OrigKDbgForwardException;
BOOLEAN	g_bHookDbgForwardException;
UCHAR	g_DbgForwardExceptionCode[0x5];

ULONG	g_OrigKDbgCopyProcessDebugPort;
BOOLEAN	g_bHookDbgCopyProcessDebugPort;
UCHAR	g_DbgCopyProcessDebugPortCode[0x5];

ULONG	g_OrigKDbgClearProcessDebugPort;
BOOLEAN	g_bHookDbgClearProcessDebugPort;
UCHAR	g_DbgClearProcessDebugPortCode[0x5];
//////////////////////////////////////////////////////////////////////////

#endif