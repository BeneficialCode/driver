#include "kDbgSys.h"
#include "CommonFunc.h"
#include "Ntstrsafe.h"
#pragma comment(lib,"ntoskrnl.lib")

NTSTATUS __stdcall NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	)
{
	NTSTATUS status;
	HANDLE Handle;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE	PreviousMode;

	__asm{	int	3	}

	PreviousMode = KeGetPreviousMode();

	//判断用户层句柄地址是否合法
	try {
		if (PreviousMode != KernelMode) {
			ProbeForWriteHandle (DebugObjectHandle);
		}
		*DebugObjectHandle = NULL;

	} except (ExSystemExceptionFilter ()) {
		return GetExceptionCode ();
	}

	if (Flags & ~DEBUG_KILL_ON_CLOSE) {
		return STATUS_INVALID_PARAMETER;
	}

	//创建调试对象
	status = ObCreateObject(
		PreviousMode,
		*DbgkDebugObjectType,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)&DebugObject);

	if (!NT_SUCCESS(status)) {
		return status;
	}
	//初始化调试对象
	ExInitializeFastMutex (&DebugObject->Mutex);
	InitializeListHead (&DebugObject->EventList);
	KeInitializeEvent (&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & DEBUG_KILL_ON_CLOSE) {
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	} else {
		DebugObject->Flags = 0;
	}

	//调试对象插入句柄表
	status = ObInsertObject(
		DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	try {
		*DebugObjectHandle = Handle;
	} except (ExSystemExceptionFilter ()) {
		status = GetExceptionCode ();
	}

	return status;
}

NTSTATUS __stdcall NtDebugActiveProcess(
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle
	)
{
	NTSTATUS status;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject;
	PEPROCESS_S Process,CurrentProcess;
	PETHREAD_S LastThread;

	PreviousMode = KeGetPreviousMode();
	//得到被调试进程的eprocess
	status = ObReferenceObjectByHandle (
		ProcessHandle,
		0x800,
		*PsProcessType,
		PreviousMode,
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS (status)) {
		return status;
	}

	//判断被调试进程是否自己或者被调试进程是否PsInitialSystemProcess进程，是的话退出
	if (Process == (PEPROCESS_S)PsGetCurrentProcess () || Process == (PEPROCESS_S)PsInitialSystemProcess) {
		ObDereferenceObject (Process);
		return STATUS_ACCESS_DENIED;
	}

	CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();

	//判断下模式、当前进程的ProtectedProcess和被调试进程的ProtectedProcess
	if(PreviousMode==UserMode &&
		CurrentProcess->ProtectedProcess==0 &&
		Process->ProtectedProcess)
	{
		//这里很奇怪，如果当前进程被保护的那么就到不了这里了。
		//那说明当前进程是受保护的就可以忽视目标进程是否受保护了。
		ObfDereferenceObject(Process);
		return STATUS_PROCESS_IS_PROTECTED;
	}

	//得到调试句柄关联的调试对象(DebugObject)
	status = ObReferenceObjectByHandle (
		DebugObjectHandle,
		0x2,
		*DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);

	if (NT_SUCCESS (status)) {
		//进程退出可不好办了，所以在这里还是先调用ExAcquireRundownProtection吧，安全一点儿
		if(ExAcquireRundownProtection(&Process->RundownProtect))
		{
			//发送一个虚拟的进程创建消息....从字面理解是这样的，实际它要达到的效果也是如此
			status = DbgkpPostFakeProcessCreateMessages(Process,DebugObject,&LastThread);

			//注意，DbgkpSetProcessDebugObject函数有个参数是寄存器传参，不分析还很难看出来，
			//其中一个参数是DbgkpPostFakeProcessCreateMessages函数的返回值，而此参数是通过
			//eax传递进去的，为了保持和windows的代码一致，我也写成wrk一样的吧。
			//设置调试对象给被调试的进程
			status = DbgkpSetProcessDebugObject(Process,DebugObject,status,LastThread);

			ExReleaseRundownProtection(&Process->RundownProtect);
		}else{
			status = STATUS_PROCESS_IS_TERMINATING;
		}

		ObDereferenceObject(DebugObject);
	}
	ObDereferenceObject (Process);

	return status;
}

NTSTATUS DbgkpPostFakeProcessCreateMessages (
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD_S *pLastThread
	)
{
	NTSTATUS	status;
	KAPC_STATE	ApcState;
	PETHREAD_S	StartThread,Thread;
	PETHREAD_S	LastThread;

	//收集所有线程创建的消息
	StartThread = 0;
	status = DbgkpPostFakeThreadMessages(
		StartThread,
		Process,
		DebugObject,
		&Thread,
		&LastThread);

	if(NT_SUCCESS(status))
	{
		KeStackAttachProcess((PEPROCESS)Process,&ApcState);

		//收集模块创建的消息
		DbgkpPostModuleMessages(Process,Thread,DebugObject);

		KeUnstackDetachProcess(&ApcState);

		ObfDereferenceObject(Thread);
	}else{
		LastThread = 0;
	}

	*pLastThread = LastThread;
	return	status;
}

NTSTATUS DbgkpPostFakeThreadMessages(
	PETHREAD_S	StartThread,
	PEPROCESS_S	Process,
	PDEBUG_OBJECT	DebugObject,
	PETHREAD_S	*pFirstThread,
	PETHREAD_S	*pLastThread
	)
{
	NTSTATUS status;
	PETHREAD_S Thread, FirstThread, LastThread, CurrentThread;
	DBGKM_APIMSG ApiMsg;	//上面分析的一个未知的结构体，应该就是DBGKM_APIMSG类型的结构
	BOOLEAN First = TRUE;
	BOOLEAN IsFirstThread;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG Flags;
	KAPC_STATE ApcState;

	status = STATUS_UNSUCCESSFUL;

	LastThread = FirstThread = NULL;

	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	if(StartThread==0)
	{
		StartThread = PsGetNextProcessThread(Process,0);
		First = TRUE;
	}else{
		First = FALSE;
		FirstThread = StartThread;
		ObfReferenceObject(StartThread);
	}

	for(Thread = StartThread;
		Thread != NULL;
		Thread = PsGetNextProcessThread (Process, Thread))
	{

		Flags = DEBUG_EVENT_NOWAIT;

		if(LastThread!=0)
		{
			ObfDereferenceObject(LastThread);
		}

		LastThread = Thread;
		ObfReferenceObject(LastThread);

		if(IS_SYSTEM_THREAD(Thread))
		{	continue;	}

		if(Thread->ThreadInserted==0)
		{
			//这个涉及的内容也比较多，而且一般也不会进入这里，所以为了简单注释掉好了
			//PsSynchronizeWithThreadInsertion(Thread,CurrentThread);
			if(Thread->ThreadInserted==0)
			{	continue;	}
		}

		if(ExAcquireRundownProtection (&Thread->RundownProtect))
		{
			Flags |= DEBUG_EVENT_RELEASE;
			status = PsSuspendThread(Thread,0);
			if(NT_SUCCESS(status))
			{
				Flags |= DEBUG_EVENT_SUSPEND;
			}
		}else{
			Flags |= DEBUG_EVENT_PROTECT_FAILED;
		}

		//每次构造一个DBGKM_APIMSG结构
		memset(&ApiMsg,0,sizeof(DBGKM_APIMSG));

		if(First && (Flags&DEBUG_EVENT_PROTECT_FAILED)==0)
		{
			//进程的第一个线程才会到这里
			IsFirstThread = TRUE;
			ApiMsg.ApiNumber = DbgKmCreateProcessApi;
			if(Process->SectionObject)
			{
				//DbgkpSectionToFileHandle函数是返回一个模块的句柄
				ApiMsg.u.CreateProcessInfo.FileHandle = DbgkpSectionToFileHandle(Process->SectionObject);
			}else{
				ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
			}
			ApiMsg.u.CreateProcessInfo.BaseOfImage = Process->SectionBaseAddress;

			KeStackAttachProcess((PEPROCESS)Process,&ApcState);

			__try{
				NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);
				if(NtHeaders)
				{
					ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL; 
					ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.CreateProcessInfo.DebugInfoSize       = NtHeaders->FileHeader.NumberOfSymbols;
				}
			}except(EXCEPTION_EXECUTE_HANDLER){
				ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
				ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = 0;
				ApiMsg.u.CreateProcessInfo.DebugInfoSize = 0;
			}

			KeUnstackDetachProcess(&ApcState);
		}else{
			IsFirstThread = FALSE;
			ApiMsg.ApiNumber = DbgKmCreateThreadApi;
			ApiMsg.u.CreateThread.StartAddress = Thread->StartAddress;
		}

		status = DbgkpQueueMessage (
			Process,
			Thread,
			&ApiMsg,
			Flags,
			DebugObject);

		if(!NT_SUCCESS(status))
		{
			if(Flags & DEBUG_EVENT_SUSPEND)
			{
				KeResumeThread(Thread);
			}

			if(Flags & DEBUG_EVENT_RELEASE)
			{
				ExReleaseRundownProtection(&Thread->RundownProtect);
			}

			if(ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL)
			{
				ObCloseHandle (ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
			}

			ObfDereferenceObject(Thread);
			break;

		}else if(IsFirstThread){
			First = FALSE;
			ObReferenceObject (Thread);
			FirstThread = Thread;

			DbgkSendSystemDllMessages(Thread,DebugObject,&ApiMsg);
		}
	}

	if (!NT_SUCCESS (status)) {
		if (FirstThread) 
		{
			ObDereferenceObject (FirstThread);
		}
		if (LastThread != NULL) 
		{
			ObDereferenceObject (LastThread);
		}
	} else {
		if (FirstThread) {
			*pFirstThread = FirstThread;
			*pLastThread = LastThread;
		} else {

			if (LastThread != NULL) 
			{
				ObDereferenceObject (LastThread);
			}
			status = STATUS_UNSUCCESSFUL;
		}
	}
	return status;
}

typedef struct _MODULE_INFO
{
	ULONG			UnKown1;
	UNICODE_STRING	FileName;		//+0x4
	PVOID			BaseOfDll;		//+0xC
	wchar_t*		Buffer;			//+0x10
	//...
}MODULE_INFO,*PMODULE_INFO;

typedef struct _SYSTEM_DLL
{
	EX_FAST_REF		FastRef;
	EX_PUSH_LOCK_S	Lock;
	MODULE_INFO		ModuleInfo;
}SYSTEM_DLL,*PSYSTEM_DLL;

VOID DbgkSendSystemDllMessages(
	PETHREAD_S		Thread,
	PDEBUG_OBJECT	DebugObject,
	PDBGKM_APIMSG	ApiMsg
	)
{
	NTSTATUS	status;

	HANDLE		FileHandle;

	ULONG		index;
	PTEB		Teb;
	PEPROCESS_S	Process;
	PETHREAD_S	CurrentThread;
	PMODULE_INFO	DllInfo;
	BOOLEAN		bSource;
	KAPC_STATE ApcState;
	PIMAGE_NT_HEADERS NtHeaders;

	IO_STATUS_BLOCK	IoStackBlock;
	OBJECT_ATTRIBUTES	ObjectAttr;

	if (Thread)
	{
		Process = (PEPROCESS_S)Thread->Tcb.Process;
	}else{
		Process = (PEPROCESS_S)PsGetCurrentProcess();
	}
	
	CurrentThread = (PETHREAD_S)PsGetCurrentThread();
	index = 0;
	do 
	{
		if (index >= 2)
		{
			break;
		}
		DllInfo = (PMODULE_INFO)PsQuerySystemDllInfo(index);
		if (DllInfo != NULL)
		{
			ApiMsg->u.LoadDll.DebugInfoFileOffset = 0;
			ApiMsg->u.LoadDll.DebugInfoSize = 0;
			ApiMsg->u.LoadDll.FileHandle = NULL;
			
			Teb = NULL;

			ApiMsg->u.LoadDll.BaseOfDll = DllInfo->BaseOfDll;

			if (Thread && index!=0)
			{
				bSource = TRUE;
				KeStackAttachProcess((PEPROCESS)Process,&ApcState);
			}else{
				bSource = FALSE;
			}

			NtHeaders = RtlImageNtHeader(DllInfo->BaseOfDll);
			if (NtHeaders != NULL)
			{
				ApiMsg->u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				ApiMsg->u.LoadDll.DebugInfoSize       = NtHeaders->FileHeader.NumberOfSymbols;
			}

			if (Thread == 0)
			{
				if (!IS_SYSTEM_THREAD(CurrentThread) &&
					CurrentThread->Tcb.ApcStateIndex != 1)
				{
					Teb = (PTEB)CurrentThread->Tcb.Teb;
				}

				if (Teb)
				{
					RtlStringCbCopyW(Teb->StaticUnicodeBuffer,261*sizeof(wchar_t),DllInfo->Buffer);
					Teb->NtTib.ArbitraryUserPointer = Teb->StaticUnicodeBuffer;
					ApiMsg->u.LoadDll.NamePointer = (PVOID)&Teb->NtTib.ArbitraryUserPointer;
				}
			}

			if (bSource == TRUE)
			{
				KeUnstackDetachProcess(&ApcState);
			}

			InitializeObjectAttributes(
				&ObjectAttr,
				&DllInfo->FileName,
				OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);

			status = ZwOpenFile(
				&FileHandle,
				GENERIC_READ | SYNCHRONIZE,
				&ObjectAttr,
				&IoStackBlock,
				FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_SYNCHRONOUS_IO_NONALERT);
			if (!NT_SUCCESS(status))
			{
				FileHandle = NULL;
			}

			DBGKM_FORMAT_API_MSG (*ApiMsg,DbgKmLoadDllApi,sizeof(DBGKM_LOAD_DLL));

			if (Thread == NULL)
			{
				DbgkpSendApiMessage(ApiMsg,0x3);
				if (FileHandle != NULL)
				{
					ObCloseHandle(FileHandle,KernelMode);
				}
				if (Teb != NULL)
				{
					Teb->NtTib.ArbitraryUserPointer = NULL;

				}
			}else{
				status = DbgkpQueueMessage(
					Process,
					Thread,
					ApiMsg,
					DEBUG_EVENT_NOWAIT,
					DebugObject);
				if (!NT_SUCCESS(status))
				{
					if (FileHandle != NULL)
					{
						ObCloseHandle(FileHandle,KernelMode);
					}
				}
			}
		}
		index++;
	} while (TRUE);
}

NTSTATUS DbgkpSendApiMessage(
	PDBGKM_APIMSG ApiMsg,
	ULONG	Flag					//eax传参
	)
{
	NTSTATUS status;
	BOOLEAN	bIsSuspend;
	PEPROCESS_S	Process;
	PETHREAD_S	Thread;

	bIsSuspend = FALSE;

	if (Flag & 0x1)
	{
		bIsSuspend = DbgkpSuspendProcess();
	}

	Thread = (PETHREAD_S)PsGetCurrentThread();
	Process = (PEPROCESS_S)PsGetCurrentProcess();

	ApiMsg->ReturnedStatus = STATUS_PENDING;
	status = DbgkpQueueMessage(
		Process,
		Thread,
		ApiMsg,
		((Flag&0x2)<<0x5),
		NULL);

	ZwFlushInstructionCache(NtCurrentProcess(),0,0);
	if (bIsSuspend)
	{
		KeThawAllThreads();
	}

	return status;
}

BOOLEAN
DbgkpSuspendProcess (
    VOID
    )
{
    if ((((PEPROCESS_S)PsGetCurrentProcess())->Flags &
		PS_PROCESS_FLAGS_PROCESS_DELETE) == 0) {
        KeFreezeAllThreads();
        return TRUE;
    }
    return FALSE;
}

PVOID PsQuerySystemDllInfo(
	ULONG index)			//这里的index不会大于1
{
	PVOID	DllInfo;

	DllInfo = (PVOID)PspSystemDlls[index];	//[DllInfo+0x14]是模块的基地址
	if (DllInfo != NULL && 
		*(PVOID*)((char*)DllInfo+0x14) != 0)
	{
		return (PVOID)((ULONG)DllInfo+0x8);
	}

	return NULL;
}

NTSTATUS
	DbgkpQueueMessage (
	IN PEPROCESS_S Process,
	IN PETHREAD_S Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
	)
{
	PDEBUG_EVENT DebugEvent;
	DEBUG_EVENT StaticDebugEvent;
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;

	//这里的参数Flags在此函数中就三种含义，是否等待此消息完成和不等待此消息完成，还有种含义可能是跳过loadDll消息
	//不等待此消息完成那么就申请内存来存放此消息，等待此消息完成的话那么就定义临时变量来存放消息，并且等待完成。
	if (Flags&DEBUG_EVENT_NOWAIT) {
		DebugEvent = ExAllocatePoolWithQuotaTag (
			NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE,
			sizeof (*DebugEvent),
			'EgbD');
		if (DebugEvent == NULL) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		DebugEvent->Flags = Flags|DEBUG_EVENT_INACTIVE;
		ObReferenceObject (Process);
		ObReferenceObject (Thread);
		DebugEvent->BackoutThread = (PETHREAD_S)PsGetCurrentThread ();
		DebugObject = TargetDebugObject;
	} else {
		DebugEvent = &StaticDebugEvent;
		DebugEvent->Flags = Flags;
		//同步消息的
		ExAcquireFastMutex (&DbgkpProcessDebugPortMutex);

		DebugObject = Process->DebugPort;

		//是否跳过线程或进程创建的消息
		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi ||
			ApiMsg->ApiNumber == DbgKmCreateProcessApi) {
				if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG) {
					DebugObject = NULL;
				}
		}

		//这里Flags&0x40为真可能是表示跳过LoadDll的消息
		if(ApiMsg->ApiNumber == DbgKmLoadDllApi &&
			Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG &&
			Flags&0x40){
				DebugObject = NULL;
		}

		//跳过线程或者进程退出的消息
		if (ApiMsg->ApiNumber == DbgKmExitThreadApi ||
			ApiMsg->ApiNumber == DbgKmExitProcessApi) {
				if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG) {
					DebugObject = NULL;
				}
		}

		//初始化DebugEvent->ContinueEvent
		KeInitializeEvent (&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);
	}

	//填充DebugEvent的各种信息
	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	DebugEvent->ClientId = Thread->Cid;

	if (DebugObject == NULL) {
		Status = STATUS_PORT_NOT_SET;
	} else {

		//防止DebugObject对象写入冲突
		ExAcquireFastMutex (&DebugObject->Mutex);

		//如果调试对象准备删除的话，那么就不要插入调试事件了
		//否则，把我们的调试事件插入进调试对象，并且看是否等待完成，等待该消息完成的话我们就激活此消息
		if ((DebugObject->Flags&DEBUG_KILL_ON_CLOSE) == 0) {
			InsertTailList (&DebugObject->EventList, &DebugEvent->EventList);

			if ((Flags&DEBUG_EVENT_NOWAIT) == 0) {
				KeSetEvent (&DebugObject->EventsPresent, 0, FALSE);
			}
			Status = STATUS_SUCCESS;
		} else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex (&DebugObject->Mutex);
	}

	//如果等待此消息完成，那我们就要在这里执行等待操作
	if ((Flags&DEBUG_EVENT_NOWAIT) == 0) {
		//这时候释放消息同步，因为这个等待需要耗时，所以我们要在KeWaitForSingleObject函数前调用它
		//而且消息已经顺利的插入调试对象了，所以不存在不安全的因素了
		ExReleaseFastMutex (&DbgkpProcessDebugPortMutex);

		if (NT_SUCCESS (Status)) {
			KeWaitForSingleObject (
				&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			//消息完成的话，这里放入了消息完成的状态值，并且作为返回值使用
			Status = DebugEvent->Status;
			//ApiMsg是输出参数
			*ApiMsg = DebugEvent->ApiMsg;
		}
	} else {
		if (!NT_SUCCESS (Status)) {
			ObDereferenceObject (Process);
			ObDereferenceObject (Thread);
			ExFreePool (DebugEvent);
		}
	}

	return Status;
}


NTSTATUS
DbgkpPostModuleMessages (
    IN PEPROCESS_S Process,
    IN PETHREAD_S Thread,
    IN PDEBUG_OBJECT DebugObject)
{
	PPEB Peb = Process->Peb;
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY LdrHead, LdrNext;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	DBGKM_APIMSG ApiMsg;
	ULONG i;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING Name;
	PIMAGE_NT_HEADERS NtHeaders;
	NTSTATUS Status;
	IO_STATUS_BLOCK iosb;

	if (Peb == NULL) {
		return STATUS_SUCCESS;
	}

	try {
		Ldr = Peb->Ldr;

		LdrHead = &Ldr->InLoadOrderModuleList;
		ProbeForReadSmallStructure (LdrHead, sizeof (LIST_ENTRY), sizeof (UCHAR));
		for (LdrNext = LdrHead->Flink, i = 0;
			LdrNext != LdrHead && i < 500;
			LdrNext = LdrNext->Flink, i++) {

			//因为在DbgkSendSystemDllMessages函数中已经对前两个模块处理了，所以这里要大于1
			if (i > 1) {
				//准备好消息DBGKM_APIMSG消息数据包
				RtlZeroMemory (&ApiMsg, sizeof (ApiMsg));

				//实际没有下面一句也行，因为LdrNext也是LdrEntry
				LdrEntry = CONTAINING_RECORD (LdrNext, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				ProbeForReadSmallStructure (LdrEntry, sizeof (LDR_DATA_TABLE_ENTRY), sizeof (UCHAR));

				//说明是加载模块的消息
				ApiMsg.ApiNumber = DbgKmLoadDllApi;
				ApiMsg.u.LoadDll.BaseOfDll = LdrEntry->DllBase;

				ProbeForReadSmallStructure (ApiMsg.u.LoadDll.BaseOfDll, sizeof (IMAGE_DOS_HEADER), sizeof (UCHAR));

				//得到模块的nt头
				NtHeaders = RtlImageNtHeader (ApiMsg.u.LoadDll.BaseOfDll);
				if (NtHeaders) {
					//设置模块的符号链接
					ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
				//MmGetFileNameForAddress函数是通过一个地址获取一个模块的名字。
				Status = MmGetFileNameForAddress (NtHeaders, &Name);
				if (NT_SUCCESS (Status)) {
					//成功得到模块名字的话，那么就获取此模块的句柄
					InitializeObjectAttributes (
						&oa,
						&Name,
						OBJ_FORCE_ACCESS_CHECK|OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
						NULL,
						NULL);

					Status = ZwOpenFile (
						&ApiMsg.u.LoadDll.FileHandle,
						GENERIC_READ|SYNCHRONIZE,
						&oa,
						&iosb,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						FILE_SYNCHRONOUS_IO_NONALERT);
						if (!NT_SUCCESS (Status)) {
							ApiMsg.u.LoadDll.FileHandle = NULL;
						}
						//因为MmGetFileNameForAddress函数内部会为存放名字的缓冲区申请内存，所以在这里要释放掉，不然会造成内存泄露
						ExFreePool (Name.Buffer);
				}

				//这里来判断是否有调试对象存在
				if(DebugObject)
				{
					//存在的话就直接调用DbgkpQueueMessage把调试消息插入调试对象的队列，并且该消息是不阻塞的(就是说不等到完成后才返回)
					Status = DbgkpQueueMessage (
						Process,
						Thread,
						&ApiMsg,
						DEBUG_EVENT_NOWAIT,
						DebugObject);
				}else{
					//这个函数也可以发送调试消息。原型我分析了下可能如下：
					/*
					NTSTATUS DbgkpSendApiMessage(
						IN ULONG Flags,                                //一个标记
						IN DBGKM_APIMSG *ApiMsg                //消息包
					);
					*/
					//从这个函数的内部实现上看，它所发送的消息是阻塞的
					DbgkpSendApiMessage(&ApiMsg,0x3);
					//在这里设置下错误码，为了后面关闭模块句柄
					Status = STATUS_UNSUCCESSFUL;
				}

                                
				if (!NT_SUCCESS (Status) && ApiMsg.u.LoadDll.FileHandle != NULL) {
					//这里关闭句柄可能是在阻塞模式下要手动关闭句柄.....这个只是猜测，要等到后面看接收调试消息的函数时才晓得是怎么回事儿
					ObCloseHandle (ApiMsg.u.LoadDll.FileHandle, KernelMode);
				}

			}
			ProbeForReadSmallStructure (LdrNext, sizeof (LIST_ENTRY), sizeof (UCHAR));
		}
    } except (EXCEPTION_EXECUTE_HANDLER) {
    }

    return STATUS_SUCCESS;
}


NTSTATUS
	DbgkpSetProcessDebugObject (
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD_S LastThread
	)
{
	NTSTATUS Status;
	PETHREAD_S ThisThread;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;
	PDEBUG_EVENT DebugEvent;
	BOOLEAN First;
	PETHREAD_S Thread;
	BOOLEAN GlobalHeld;
	PETHREAD_S FirstThread;

	PAGED_CODE ();

	ThisThread = (PETHREAD_S)PsGetCurrentThread ();

	//初始化链表，这个之后储存消息
	InitializeListHead (&TempList);

	First = TRUE;
	GlobalHeld = FALSE;

	if (!NT_SUCCESS (MsgStatus)) {
		LastThread = NULL;
		Status = MsgStatus;
	} else {
		Status = STATUS_SUCCESS;
	}


	if (NT_SUCCESS (Status)) {

		while (1) {

			GlobalHeld = TRUE;

			ExAcquireFastMutex (&DbgkpProcessDebugPortMutex);

			//如果被调试进程的debugport已经设置，那么跳出循环
			if (Process->DebugPort != NULL) {
				Status = STATUS_PORT_ALREADY_SET;
				break;
			}

			//没有设置debugport，在这里设置
			Process->DebugPort = DebugObject;

			//增加被调试进程最后一个线程的引用
			ObReferenceObject (LastThread);

			//这里如果返回有值，说明在这之间还有线程被创建了，这里也要加入调试消息链表
			Thread = PsGetNextProcessThread (Process, LastThread);
			if (Thread != NULL) {

				Process->DebugPort = NULL;

				ExReleaseFastMutex (&DbgkpProcessDebugPortMutex);

				GlobalHeld = FALSE;

				ObDereferenceObject (LastThread);
				//通知线程创建消息
				Status = DbgkpPostFakeThreadMessages (
					Thread,
					Process,
					DebugObject,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS (Status)) {
					LastThread = NULL;
					break;
				}
				ObDereferenceObject (FirstThread);
			} else {
				break;
			}
		}
	}

	ExAcquireFastMutex (&DebugObject->Mutex);

	if (NT_SUCCESS (Status)) {
		//看看调试对象是否要求删除
		if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {
			PS_SET_BITS (&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT|PS_PROCESS_FLAGS_CREATE_REPORTED);
			ObReferenceObject (DebugObject);
		} else {
			Process->DebugPort = NULL;
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	//通过上面的操作，调试对象的消息链表装满了线程创建的消息(同时也包含模块加载的消息)
	//
	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		) {
			//取出调试事件
			DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);
			Entry = Entry->Flink;

			//看看调试事件是否急于处理，如果不是急于处理的，说明在DbgkpQueueMessage函数里面没有得到处理，
			//那么我们就在这里想办法处理吧(急于处理的已经在DbgkpQueueMessage函数中处理过了，所以这里无需担心)。
			//并且看看是否是本线程负责通知完成此消息
			if ((DebugEvent->Flags&DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == ThisThread) {
				Thread = DebugEvent->Thread;

				if (NT_SUCCESS (Status)) {
					//这里判断之前对线程申请的停止保护是否失败
					if ((DebugEvent->Flags&DEBUG_EVENT_PROTECT_FAILED) != 0) {
						PS_SET_BITS (&Thread->CrossThreadFlags,
							PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
						RemoveEntryList (&DebugEvent->EventList);
						InsertTailList (&TempList, &DebugEvent->EventList);
					} else {
						//这里极有可能是判断是否主线程的创建消息，是主线程的话完成消息
						if (First) {
							DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
							KeSetEvent (&DebugObject->EventsPresent, 0, FALSE);
							First = FALSE;
						}
						//到这里设置跳过线程创建消息
						DebugEvent->BackoutThread = NULL;
						PS_SET_BITS (&Thread->CrossThreadFlags,
							PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);

					}
				} else {
					//很移除消息，并且加入临时链表中
					RemoveEntryList (&DebugEvent->EventList);
					InsertTailList (&TempList, &DebugEvent->EventList);
				}
				//这里看看是够请求过线程停止保护，是的话释放请求
				if (DebugEvent->Flags&DEBUG_EVENT_RELEASE) {
					DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
					ExReleaseRundownProtection (&Thread->RundownProtect);
				}

			}
	}

	ExReleaseFastMutex (&DebugObject->Mutex);

	if (GlobalHeld) {
		ExReleaseFastMutex (&DbgkpProcessDebugPortMutex);
	}

	if (LastThread != NULL) {
		ObDereferenceObject (LastThread);
	}

	//这里读取临时链表，并且处理里面的每个消息
	while (!IsListEmpty (&TempList)) {
		Entry = RemoveHeadList (&TempList);
		DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);
		DbgkpWakeTarget (DebugEvent);
	}

	if (NT_SUCCESS (Status)) {
		DbgkpMarkProcessPeb (Process);
	}

	return Status;
}


VOID DbgkpWakeTarget (
	IN PDEBUG_EVENT DebugEvent
	)
{
	PETHREAD_S Thread;

	Thread = DebugEvent->Thread;

	if ((DebugEvent->Flags&DEBUG_EVENT_SUSPEND) != 0) {
		NtResumeThread (DebugEvent->Thread, NULL);			//bug
	}

	if (DebugEvent->Flags&DEBUG_EVENT_RELEASE) {
		ExReleaseRundownProtection (&Thread->RundownProtect);
	}

	if ((DebugEvent->Flags&DEBUG_EVENT_NOWAIT) == 0) {
		KeSetEvent (&DebugEvent->ContinueEvent, 0, FALSE);
	} else {
		DbgkpFreeDebugEvent(DebugEvent);
	}
}

VOID DbgkpMarkProcessPeb (
	PEPROCESS_S Process
	)
{
	KAPC_STATE ApcState;

	if (ExAcquireRundownProtection (&Process->RundownProtect)) {

		if (Process->Peb != NULL) {
			KeStackAttachProcess((PRKPROCESS)&Process->Pcb, &ApcState);


			ExAcquireFastMutex (&DbgkpProcessDebugPortMutex);

			try {
				Process->Peb->BeingDebugged = (BOOLEAN)(Process->DebugPort != NULL ? TRUE : FALSE);
			} except (EXCEPTION_EXECUTE_HANDLER) {
			}
			ExReleaseFastMutex (&DbgkpProcessDebugPortMutex);

			KeUnstackDetachProcess(&ApcState);
		}

		ExReleaseRundownProtection (&Process->RundownProtect);
	}
}

VOID DbgkpFreeDebugEvent (
	IN PDEBUG_EVENT DebugEvent
	)
{
	NTSTATUS Status;

	switch (DebugEvent->ApiMsg.ApiNumber) {
	case DbgKmCreateProcessApi :
		if (DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle != NULL) {
			Status = ObCloseHandle (DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
		}
		break;

	case DbgKmLoadDllApi :
		if (DebugEvent->ApiMsg.u.LoadDll.FileHandle != NULL) {
			Status = ObCloseHandle (DebugEvent->ApiMsg.u.LoadDll.FileHandle, KernelMode);
		}
		break;

	}
	ObDereferenceObject (DebugEvent->Process);
	ObDereferenceObject (DebugEvent->Thread);
	ExFreePoolWithTag (DebugEvent,0);
}


NTSTATUS __stdcall
	NtDebugContinue (
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus
	)
{
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent, FoundDebugEvent;
	KPROCESSOR_MODE PreviousMode;
	CLIENT_ID Clid;
	PLIST_ENTRY Entry;
	BOOLEAN GotEvent;

	PreviousMode = KeGetPreviousMode();

	try {
		if (PreviousMode != KernelMode) {
			ProbeForReadSmallStructure (ClientId, sizeof (*ClientId), sizeof (UCHAR));
		}
		Clid = *ClientId;

	} except (ExSystemExceptionFilter ()) {
		return GetExceptionCode ();
	}

	//判断继续操作的类型，此函数就这里和wrk中的不同而已
	switch (ContinueStatus) {
	case DBG_EXCEPTION_NOT_HANDLED :
	case DBG_CONTINUE :
	case DBG_TERMINATE_PROCESS :
		break;
	default :
		return STATUS_INVALID_PARAMETER;
	}

	//得到调试对象
	Status = ObReferenceObjectByHandle (
		DebugObjectHandle,
		DEBUG_READ_EVENT,
		*DbgkDebugObjectType,
		PreviousMode,
		&DebugObject,
		NULL);

	if (!NT_SUCCESS (Status)) {
		return Status;
	}

	//如果获得指定的调试消息就设置为ture，初始化时为false
	GotEvent = FALSE;
	//保存寻找到调试消息的变量
	FoundDebugEvent = NULL;

	//这个锁很重要，前面我还没发现它的重要性但是这里遇到一些莫名其妙的代码，如果这里有这个锁的话，就说得通了。
	ExAcquireFastMutex (&DebugObject->Mutex);

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		Entry = Entry->Flink) {

			DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);

			//这里几个判断就是为了找到指定消息
			if (DebugEvent->ClientId.UniqueProcess == Clid.UniqueProcess) {
				//如果还没有寻找到，进入if
				if (!GotEvent) {
					//这里的DEBUG_EVENT_READ是表示这个消息有没有没读取过，也就是说有没有被处理过。
					//如果被处理过，而且确实是我们要找的消息，那么就从消息链中移除，并保存，然后
					//设置标记说找到了。这里DEBUG_EVENT_READ的意义十分重要，解读它我是逆向了
					//NtWaitForDebugEvent函数才知晓了这个意义
					if (DebugEvent->ClientId.UniqueThread == Clid.UniqueThread &&
						(DebugEvent->Flags&DEBUG_EVENT_READ) != 0) {
							RemoveEntryList (Entry);
							FoundDebugEvent = DebugEvent;
							GotEvent = TRUE;
					}
				} else {
					//会进入这里说明我们已经找到了指定的消息，并且此调试事件链表还不是空的，
					//那么这里就设置完成获取的这个事件；注意，这里这样写是非常有意义的，至于
					//为何要等到分析NtWaitForDebugEvent的时候再揭晓
					DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
					KeSetEvent (&DebugObject->EventsPresent, 0, FALSE);
					break;
				}
			}
	}

	ExReleaseFastMutex (&DebugObject->Mutex);

	ObDereferenceObject (DebugObject);

	if (GotEvent) {
		//找到的话，这个消息也就算彻底完成任务了。注意这里的DbgkpWakeTarget函数里，一般非阻塞消息
		//是直接释放所占内存的
		FoundDebugEvent->ApiMsg.ReturnedStatus = ContinueStatus;
		FoundDebugEvent->Status = STATUS_SUCCESS;
		DbgkpWakeTarget (FoundDebugEvent);
	} else {
		Status = STATUS_INVALID_PARAMETER;
	}

	return Status;
}

NTSTATUS __stdcall
	NtWaitForDebugEvent (
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
	)
{
	NTSTATUS Status;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject;
	LARGE_INTEGER Tmo = {0};
	LARGE_INTEGER StartTime = {0};
	DBGUI_WAIT_STATE_CHANGE tWaitStateChange = {0};
	PEPROCESS_S Process;
	PETHREAD_S Thread;
	PLIST_ENTRY Entry, Entry2;
	PDEBUG_EVENT DebugEvent, DebugEvent2;
	BOOLEAN GotEvent;

	PreviousMode = KeGetPreviousMode();

	try {
		if (ARGUMENT_PRESENT (Timeout)) {
			if (PreviousMode != KernelMode) {
				ProbeForReadSmallStructure (Timeout, sizeof (*Timeout), sizeof (UCHAR));
			}
			Tmo = *Timeout;
			Timeout = &Tmo;
			KeQuerySystemTime (&StartTime);
		}
		if (PreviousMode != KernelMode) {
			ProbeForWriteSmallStructure (WaitStateChange, sizeof (*WaitStateChange), sizeof (UCHAR));
		}

	} except (ExSystemExceptionFilter ()) {
		return GetExceptionCode ();
	}

	//首先通过句柄获取调试对象
	Status = ObReferenceObjectByHandle (DebugObjectHandle,
		DEBUG_READ_EVENT,
		*DbgkDebugObjectType,
		PreviousMode,
		&DebugObject,
		NULL);

	if (!NT_SUCCESS (Status)) {
		return Status;
	}

	Process = NULL;
	Thread = NULL;

	while (1) {
		//在调试对象有事件产生
		Status = KeWaitForSingleObject (&DebugObject->EventsPresent,
			Executive,
			PreviousMode,
			Alertable,
			Timeout);
		if (!NT_SUCCESS (Status) || Status == STATUS_TIMEOUT || Status == STATUS_ALERTED || Status == STATUS_USER_APC) {
			break;
		}

		GotEvent = FALSE;

		DebugEvent = NULL;

		ExAcquireFastMutex (&DebugObject->Mutex);

		//等到有信号后判断是否此调试对象无效了，没有无效那么就进一步处理
		if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {

			//在这里遍历调试事件链表
			for (Entry = DebugObject->EventList.Flink;
				Entry != &DebugObject->EventList;
				Entry = Entry->Flink) {

					DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);
					//判断消息是否已经读取过或者是否还不需要处理，否则处理
					if ((DebugEvent->Flags&(DEBUG_EVENT_READ|DEBUG_EVENT_INACTIVE)) == 0) {
						GotEvent = TRUE;

						//这里进行第二次遍历事件链表
						for (Entry2 = DebugObject->EventList.Flink;
							Entry2 != Entry;
							Entry2 = Entry2->Flink) {

								DebugEvent2 = CONTAINING_RECORD (Entry2, DEBUG_EVENT, EventList);
								//能进入这个遍历的说明有找到比DebugEvent还早的未处理事件，那么就重新设置下
								//DebugEvent事件标记为待处理状态。实际一般情况是进入不到这个循环里的，因为
								//目前我还能看到处理一个调试事件时，还有比这个调试事件更早的没被处理。或许
								//后面的研究会发现这个问题，那时咱们再详谈。通过这里也可以看出，调试事件是
								//严格按照队列形式来处理的，也就是先来的先处理。
								//
								if (DebugEvent->ClientId.UniqueProcess == DebugEvent2->ClientId.UniqueProcess) {

									DebugEvent->Flags |= DEBUG_EVENT_INACTIVE;
									DebugEvent->BackoutThread = NULL;
									GotEvent = FALSE;
									break;
								}
						}
						//找到一个满足条件的事件的话，就退出循环了
						if (GotEvent) {
							break;
						}
					}
			}

			//找到的话，把事件相关的信息转换成用户层可识别的信息，然后设置此事件已读
			if (GotEvent) {
				Process = DebugEvent->Process;
				Thread = DebugEvent->Thread;
				ObReferenceObject (Thread);
				ObReferenceObject (Process);
				DbgkpConvertKernelToUserStateChange (&tWaitStateChange, DebugEvent);
				DebugEvent->Flags |= DEBUG_EVENT_READ;
			} else {
				//没找到的话设置调试对象没有信号了.....
				KeClearEvent (&DebugObject->EventsPresent);
			}
			Status = STATUS_SUCCESS;

		} else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex (&DebugObject->Mutex);

		if (NT_SUCCESS (Status)) {
			if (GotEvent == FALSE) {

				if (Tmo.QuadPart < 0) {
					LARGE_INTEGER NewTime;
					KeQuerySystemTime (&NewTime);
					Tmo.QuadPart = Tmo.QuadPart + (NewTime.QuadPart - StartTime.QuadPart);
					StartTime = NewTime;
					if (Tmo.QuadPart >= 0) {
						Status = STATUS_TIMEOUT;
						break;
					}
				}
			} else {

				DbgkpOpenHandles (&tWaitStateChange, Process, Thread);
				ObDereferenceObject (Thread);
				ObDereferenceObject (Process);
				break;
			}
		} else {
			break;
		}
	}

	ObDereferenceObject (DebugObject);

	try {
		*WaitStateChange = tWaitStateChange;
	} except (ExSystemExceptionFilter ()) {
		Status = GetExceptionCode ();
	}
	return Status;
}

VOID
DbgkpConvertKernelToUserStateChange (
     PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
     PDEBUG_EVENT DebugEvent)
{
    WaitStateChange->AppClientId = DebugEvent->ClientId;
    switch (DebugEvent->ApiMsg.ApiNumber) {
        case DbgKmExceptionApi :
            switch (DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode) {
                case STATUS_BREAKPOINT :
                    WaitStateChange->NewState = DbgBreakpointStateChange;
                    break;

                case STATUS_SINGLE_STEP :
                    WaitStateChange->NewState = DbgSingleStepStateChange;
                    break;

                default :
                    WaitStateChange->NewState = DbgExceptionStateChange;
                    break;
            }
            WaitStateChange->StateInfo.Exception = DebugEvent->ApiMsg.u.Exception;
            break;

        case DbgKmCreateThreadApi :
            WaitStateChange->NewState = DbgCreateThreadStateChange;
            WaitStateChange->StateInfo.CreateThread.NewThread = DebugEvent->ApiMsg.u.CreateThread;
            break;

        case DbgKmCreateProcessApi :
            WaitStateChange->NewState = DbgCreateProcessStateChange;
            WaitStateChange->StateInfo.CreateProcessInfo.NewProcess = DebugEvent->ApiMsg.u.CreateProcessInfo;
            DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
            break;

        case DbgKmExitThreadApi :
            WaitStateChange->NewState = DbgExitThreadStateChange;
            WaitStateChange->StateInfo.ExitThread = DebugEvent->ApiMsg.u.ExitThread;
            break;

        case DbgKmExitProcessApi :
            WaitStateChange->NewState = DbgExitProcessStateChange;
            WaitStateChange->StateInfo.ExitProcess = DebugEvent->ApiMsg.u.ExitProcess;
            break;

        case DbgKmLoadDllApi :
            WaitStateChange->NewState = DbgLoadDllStateChange;
            WaitStateChange->StateInfo.LoadDll = DebugEvent->ApiMsg.u.LoadDll;
            DebugEvent->ApiMsg.u.LoadDll.FileHandle = NULL;
            break;

        case DbgKmUnloadDllApi :
            WaitStateChange->NewState = DbgUnloadDllStateChange;
            WaitStateChange->StateInfo.UnloadDll = DebugEvent->ApiMsg.u.UnloadDll;
            break;

        default :
            ASSERT (FALSE);
    }
}

VOID DbgkpOpenHandles (
    PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
    PEPROCESS_S Process,
    PETHREAD_S Thread
    )
{
    NTSTATUS Status;
    PEPROCESS_S CurrentProcess;
    HANDLE OldHandle;

    switch (WaitStateChange->NewState) {
        case DbgCreateThreadStateChange :
            Status = ObOpenObjectByPointer (Thread,
                                            0,
                                            NULL,
                                            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | \
                                               THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION | THREAD_TERMINATE |
                                               READ_CONTROL | SYNCHRONIZE,
                                            *PsThreadType,
                                            KernelMode,
                                            &WaitStateChange->StateInfo.CreateThread.HandleToThread);
            if (!NT_SUCCESS (Status)) {
                WaitStateChange->StateInfo.CreateThread.HandleToThread = NULL;
            }
            break;

        case DbgCreateProcessStateChange :

            Status = ObOpenObjectByPointer (Thread,
                                            0,
                                            NULL,
                                            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | \
                                               THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION | THREAD_TERMINATE |
                                               READ_CONTROL | SYNCHRONIZE,
                                            *PsThreadType,
                                            KernelMode,
                                            &WaitStateChange->StateInfo.CreateProcessInfo.HandleToThread);
            if (!NT_SUCCESS (Status)) {
                WaitStateChange->StateInfo.CreateProcessInfo.HandleToThread = NULL;
            }
            Status = ObOpenObjectByPointer (Process,
                                            0,
                                            NULL,
                                            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                               PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION |
                                               PROCESS_CREATE_THREAD | PROCESS_TERMINATE |
                                               READ_CONTROL | SYNCHRONIZE,
                                            *PsProcessType,
                                            KernelMode,
                                            &WaitStateChange->StateInfo.CreateProcessInfo.HandleToProcess);
            if (!NT_SUCCESS (Status)) {
                WaitStateChange->StateInfo.CreateProcessInfo.HandleToProcess = NULL;
            }

            OldHandle = WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle;
            if (OldHandle != NULL) {
                CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess ();
                Status = ObDuplicateObject (CurrentProcess,
                                            OldHandle,
                                            CurrentProcess,
                                            &WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle,
                                            0,
                                            0,
                                            DUPLICATE_SAME_ACCESS,
                                            KernelMode);
                if (!NT_SUCCESS (Status)) {
                    WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle = NULL;
                }
                ObCloseHandle (OldHandle, KernelMode);
            }
            break;

        case DbgLoadDllStateChange :

            OldHandle = WaitStateChange->StateInfo.LoadDll.FileHandle;
            if (OldHandle != NULL) {
                CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess ();
                Status = ObDuplicateObject (CurrentProcess,
                                            OldHandle,
                                            CurrentProcess,
                                            &WaitStateChange->StateInfo.LoadDll.FileHandle,
                                            0,
                                            0,
                                            DUPLICATE_SAME_ACCESS,
                                            KernelMode);
                if (!NT_SUCCESS (Status)) {
                    WaitStateChange->StateInfo.LoadDll.FileHandle = NULL;
                }
                ObCloseHandle (OldHandle, KernelMode);
            }

            break;

        default :
            break;
    }
}

HANDLE
	DbgkpSectionToFileHandle(
	IN PVOID SectionObject
	)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE Handle;
	POBJECT_NAME_INFORMATION FileNameInfo;

	Status = MmGetFileNameForSection((PSEGMENT_OBJECT)SectionObject, &FileNameInfo);
	if ( !NT_SUCCESS(Status) ) {
		return NULL;
	}

	InitializeObjectAttributes(
		&Obja,
		&FileNameInfo->Name,
		OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
		);

	Status = ZwOpenFile(
		&Handle,
		(ACCESS_MASK)(GENERIC_READ | SYNCHRONIZE),
		&Obja,
		&IoStatusBlock,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SYNCHRONOUS_IO_NONALERT
		);
	ExFreePool(FileNameInfo);
	if ( !NT_SUCCESS(Status) ) {
		return NULL;
	} else {
		return Handle;
	}
}

NTSTATUS __stdcall
	NtRemoveProcessDebug (
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle
	)
{
	NTSTATUS	status;
	PEPROCESS_S	Process,CurrentProcess;
	KPROCESSOR_MODE	PreviousMode;
	PDEBUG_OBJECT	DebugObject;

	PreviousMode = KeGetPreviousMode();

	status = ObReferenceObjectByHandle(
		ProcessHandle,
		0x800,
		*PsProcessType,
		PreviousMode,
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (PreviousMode == UserMode)
	{
		CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();
		if (CurrentProcess->ProtectedProcess == FALSE &&
			Process->ProtectedProcess == TRUE)
		{
			ObfDereferenceObject(Process);
			return STATUS_PROCESS_IS_PROTECTED;
		}
	}

	status = ObReferenceObjectByHandle(
		DebugObjectHandle,
		0x2,
		*DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);
	if (!NT_SUCCESS(status))
	{
		ObfDereferenceObject(Process);
		return status;
	}

	status = DbgkClearProcessDebugObject(
		Process,
		DebugObject);

	ObfDereferenceObject(DebugObject);
	ObfDereferenceObject(Process);
	return status;
}

NTSTATUS __stdcall
	DbgkClearProcessDebugObject (
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT SourceDebugObject
	)
{
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;

	ExAcquireFastMutex (&DbgkpProcessDebugPortMutex);

	DebugObject = (PDEBUG_OBJECT)Process->DebugPort;
	if (DebugObject == NULL || (DebugObject != SourceDebugObject && SourceDebugObject != NULL)) {
		DebugObject = NULL;
		Status = STATUS_PORT_NOT_SET;
	} else {
		Process->DebugPort = NULL;
		Status = STATUS_SUCCESS;
	}
	ExReleaseFastMutex (&DbgkpProcessDebugPortMutex);

	if (NT_SUCCESS (Status)) {
		DbgkpMarkProcessPeb (Process);
	}

	if (DebugObject) {
		InitializeListHead (&TempList);

		ExAcquireFastMutex (&DebugObject->Mutex);
		for (Entry = DebugObject->EventList.Flink;
			Entry != &DebugObject->EventList;
			) {

				DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);
				Entry = Entry->Flink;
				if (DebugEvent->Process == Process) {
					RemoveEntryList (&DebugEvent->EventList);
					InsertTailList (&TempList, &DebugEvent->EventList);
				}
		}
		ExReleaseFastMutex (&DebugObject->Mutex);

		ObDereferenceObject (DebugObject);

		while (!IsListEmpty (&TempList)) {
			Entry = RemoveHeadList (&TempList);
			DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);
			DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
			DbgkpWakeTarget (DebugEvent);
		}
	}

	return Status;
}

VOID __stdcall
DbgkCreateThread(
    PETHREAD_S Thread
    )
{
    DBGKM_APIMSG m;
    PDBGKM_CREATE_THREAD CreateThreadArgs;
    PDBGKM_CREATE_PROCESS CreateProcessArgs;
    PEPROCESS_S Process;
    PDBGKM_LOAD_DLL LoadDllArgs;
    NTSTATUS status;
    PIMAGE_NT_HEADERS NtHeaders;
    ULONG OldFlags;

	ULONG	index;
	PMODULE_INFO ModuleInfo;
	PDEBUG_OBJECT DebugObject;
	PSYSTEM_DLL	SystemDll;
	PVOID	Object;
	PFILE_OBJECT FileObject;
	PKTHREAD_S	CurrentThread;

    Process = (PEPROCESS_S)Thread->Tcb.Process;

    OldFlags = PS_TEST_SET_BITS (&Process->Flags, PS_PROCESS_FLAGS_CREATE_REPORTED|PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE);

    if ((OldFlags&PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE) == 0 && 
		(PspNotifyEnableMask & 0x1)) 
	{
        
		IMAGE_INFO_EX ImageInfoEx;
        PUNICODE_STRING ImageName;
        POBJECT_NAME_INFORMATION FileNameInfo;
        //
        // notification of main .exe
        //

        ImageInfoEx.ImageInfo.Properties = 0;
        ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
        ImageInfoEx.ImageInfo.ImageBase = Process->SectionBaseAddress;
        ImageInfoEx.ImageInfo.ImageSize = 0;

        try {
            NtHeaders = RtlImageNtHeader (Process->SectionBaseAddress);
    
            if (NtHeaders) {
				ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER (NtHeaders, SizeOfImage);
            }
        } except (EXCEPTION_EXECUTE_HANDLER) {
            ImageInfoEx.ImageInfo.ImageSize = 0;
        }
        ImageInfoEx.ImageInfo.ImageSelector = 0;
        ImageInfoEx.ImageInfo.ImageSectionNumber = 0;

		PsReferenceProcessFilePointer((PEPROCESS)Process,&FileObject);
		status = SeLocateProcessImageName((PEPROCESS)Process,&ImageName);
		if (!NT_SUCCESS(status))
		{
			ImageName = NULL;
		}
		
		PsCallImageNotifyRoutines(
			ImageName,
			Process->UniqueProcessId,
			FileObject,
			&ImageInfoEx);

		if (ImageName)
		{
			//因为在SeLocateProcessImageName中为ImageName申请了内存，所以要在此处释放掉
			ExFreePoolWithTag(ImageName,0);
		}

		//PsReferenceProcessFilePointer增加了引用计数
		ObfDereferenceObject(FileObject);

        index = 0;
		while (index < 2)
		{
			ModuleInfo = (PMODULE_INFO)PsQuerySystemDllInfo(index);
			if (ModuleInfo != NULL)
			{
				ImageInfoEx.ImageInfo.Properties = 0;
				ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
				ImageInfoEx.ImageInfo.ImageBase = ModuleInfo->BaseOfDll;
				ImageInfoEx.ImageInfo.ImageSize = 0;

				try{
					NtHeaders = RtlImageNtHeader(ModuleInfo->BaseOfDll);
					if (NtHeaders)
					{
						ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER (NtHeaders, SizeOfImage);
					}
				}except(EXCEPTION_EXECUTE_HANDLER) {
					ImageInfoEx.ImageInfo.ImageSize = 0;
				}

				ImageInfoEx.ImageInfo.ImageSelector = 0;
				ImageInfoEx.ImageInfo.ImageSectionNumber = 0;

				//实际就是PspSystemDlls
				SystemDll = (PSYSTEM_DLL)((ULONG)ModuleInfo-0x8);
				Object = ObFastReferenceObject(&SystemDll->FastRef);
				if (Object == NULL)
				{
					CurrentThread = (PKTHREAD_S)PsGetCurrentThread();
					KeEnterCriticalRegionThread(CurrentThread);
					
					ExAcquirePushLockShared(&SystemDll->Lock);

					//由于系统模块不可能得不到，所以逆向发现win7没做判断
					Object = ObFastReferenceObjectLocked(&SystemDll->FastRef);

					ExfReleasePushLockShared(&SystemDll->Lock);

					KeLeaveCriticalRegionThread(CurrentThread);
					
				}

				FileObject = MmGetFileObjectForSection(Object);
				
				if (Object != NULL)
				{
					ObFastDereferenceObject(
						&SystemDll->FastRef,
						Object);
				}

				PsCallImageNotifyRoutines(
					&SystemDll->ModuleInfo.FileName,
					Process->UniqueProcessId,
					FileObject,
					&ImageInfoEx);

				ObfDereferenceObject(FileObject);
			}

			index++;
		}
    }

    DebugObject = (PDEBUG_OBJECT)Process->DebugPort;

    if (DebugObject == NULL) {
        return;
    }

    if ((OldFlags&PS_PROCESS_FLAGS_CREATE_REPORTED) == 0) 
	{

        CreateThreadArgs = &m.u.CreateProcessInfo.InitialThread;
        CreateThreadArgs->SubSystemKey = 0;

        CreateProcessArgs = &m.u.CreateProcessInfo;
        CreateProcessArgs->SubSystemKey = 0;
        CreateProcessArgs->FileHandle = DbgkpSectionToFileHandle(
                                            Process->SectionObject
                                            );
        CreateProcessArgs->BaseOfImage = Process->SectionBaseAddress;
        CreateThreadArgs->StartAddress = NULL;
        CreateProcessArgs->DebugInfoFileOffset = 0;
        CreateProcessArgs->DebugInfoSize = 0;

        try {
                        
            NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);

            if ( NtHeaders ) {

                    CreateThreadArgs->StartAddress = (PVOID) (DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER (NtHeaders, ImageBase) +
                        DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER (NtHeaders, AddressOfEntryPoint));
                
                CreateProcessArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
                CreateProcessArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
            }
        } except (EXCEPTION_EXECUTE_HANDLER) {
            CreateThreadArgs->StartAddress = NULL;
            CreateProcessArgs->DebugInfoFileOffset = 0;
            CreateProcessArgs->DebugInfoSize = 0;
        }

        DBGKM_FORMAT_API_MSG(m,DbgKmCreateProcessApi,sizeof(*CreateProcessArgs));

        DbgkpSendApiMessage(&m,FALSE);

        if (CreateProcessArgs->FileHandle != NULL) {
            ObCloseHandle(CreateProcessArgs->FileHandle, KernelMode);
        }

		DbgkSendSystemDllMessages(
			NULL,
			NULL,
			&m);
    }else{

        CreateThreadArgs = &m.u.CreateThread;
        CreateThreadArgs->SubSystemKey = 0;
        CreateThreadArgs->StartAddress = Thread->Win32StartAddress;

        DBGKM_FORMAT_API_MSG (m,DbgKmCreateThreadApi,sizeof(*CreateThreadArgs));

        DbgkpSendApiMessage (&m,TRUE);
    }

	if (Thread->ClonedThread == TRUE)
	{
		DbgkpPostModuleMessages(
			Process,
			Thread,
			NULL);
	}
}

VOID __stdcall
	DbgkExitThread(
	NTSTATUS ExitStatus
	)
{
	DBGKM_APIMSG ApiMsg;
	PEPROCESS_S	Process;
	PETHREAD_S	CurrentThread;

	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	Process = (PEPROCESS_S)PsGetCurrentProcess();
	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	if (!(CurrentThread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) &&
		Process->DebugPort != NULL && CurrentThread->ThreadInserted == TRUE)
	{
		ApiMsg.u.ExitThread.ExitStatus = ExitStatus;
		DBGKM_FORMAT_API_MSG(ApiMsg,DbgKmExitThreadApi,sizeof(DBGKM_EXIT_THREAD));

		DbgkpSendApiMessage(&ApiMsg,0x1);
	}
}

VOID __stdcall
	DbgkExitProcess(
	NTSTATUS ExitStatus
	)
{
	DBGKM_APIMSG ApiMsg;
	PEPROCESS_S	Process;
	PETHREAD_S	CurrentThread;

	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	Process = (PEPROCESS_S)PsGetCurrentProcess();
	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	if (!(CurrentThread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) &&
		Process->DebugPort != NULL && CurrentThread->ThreadInserted == TRUE)
	{
		KeQuerySystemTime(&Process->ExitTime);

		ApiMsg.u.ExitProcess.ExitStatus = ExitStatus;
		DBGKM_FORMAT_API_MSG(ApiMsg,DbgKmExitProcessApi,sizeof(DBGKM_EXIT_PROCESS));

		DbgkpSendApiMessage(&ApiMsg,FALSE);
	}
}

BOOLEAN DbgkpSuppressDbgMsg(
	IN PTEB Teb)
{
	BOOLEAN bSuppress;
	try{
		bSuppress = Teb->SuppressDebugMsg;
	}except(EXCEPTION_EXECUTE_HANDLER){
		bSuppress = FALSE;
	}
	return bSuppress;
}

VOID __stdcall
	DbgkMapViewOfSection(
	IN PVOID SectionObject,
	IN PVOID BaseAddress,			//edx
	IN PEPROCESS_S	Process			//ecx
	)
{
	PTEB	Teb;
	HANDLE	hFile;
	DBGKM_APIMSG ApiMsg;
	PEPROCESS_S	CurrentProcess;
	PETHREAD_S	CurrentThread;
	PIMAGE_NT_HEADERS	pImageHeader;

	hFile = NULL;

	CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();
	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	if (KeGetPreviousMode() == KernelMode ||
		(CurrentThread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) ||
		Process->DebugPort == NULL)
	{
		return;
	}

	if (CurrentThread->SystemThread != TRUE &&
		CurrentThread->Tcb.ApcStateIndex != 0x1)
	{
		Teb = (PTEB)CurrentThread->Tcb.Teb;
	}else{
		Teb = NULL;
	}

	if (Teb != NULL && Process == CurrentProcess)
	{
		if (!DbgkpSuppressDbgMsg(Teb))
		{
			ApiMsg.u.LoadDll.NamePointer = Teb->NtTib.ArbitraryUserPointer;
		}else{
			//暂停调试消息的话就退出
			return;
		}
	}else{
		ApiMsg.u.LoadDll.NamePointer = NULL;
	}

	hFile = DbgkpSectionToFileHandle(SectionObject);
	ApiMsg.u.LoadDll.FileHandle = hFile;
	ApiMsg.u.LoadDll.BaseOfDll = BaseAddress;
	ApiMsg.u.LoadDll.DebugInfoFileOffset = 0;
	ApiMsg.u.LoadDll.DebugInfoSize = 0;

	try{
		pImageHeader = RtlImageNtHeader(BaseAddress);
		if (pImageHeader != NULL)
		{
			ApiMsg.u.LoadDll.DebugInfoFileOffset = pImageHeader->FileHeader.PointerToSymbolTable;
			ApiMsg.u.LoadDll.DebugInfoSize = pImageHeader->FileHeader.NumberOfSymbols;
		}
	}except(EXCEPTION_EXECUTE_HANDLER){
		ApiMsg.u.LoadDll.DebugInfoFileOffset = 0;
		ApiMsg.u.LoadDll.DebugInfoSize = 0;
		ApiMsg.u.LoadDll.NamePointer = NULL;
	}

	DBGKM_FORMAT_API_MSG(ApiMsg,DbgKmLoadDllApi,sizeof(DBGKM_LOAD_DLL));

	DbgkpSendApiMessage(&ApiMsg,0x1);

	if (ApiMsg.u.LoadDll.FileHandle != NULL)
	{
		ObCloseHandle(ApiMsg.u.LoadDll.FileHandle,KernelMode);
	}
}

_declspec(naked) VOID DbgkMapViewOfSection_S()
{
	__asm{
		mov		edi,edi
		push	ebp
		mov		ebp,esp

		push	ecx
		push	edx
		push	[ebp+0x8]
		call	DbgkMapViewOfSection

		pop		ebp
		retn	0x4
	}
}

VOID __stdcall
	DbgkUnMapViewOfSection(
	IN PEPROCESS_S	Process,			//eax
	IN PVOID	BaseAddress
	)
{
	PTEB	Teb;
	DBGKM_APIMSG ApiMsg;
	PEPROCESS_S	CurrentProcess;
	PETHREAD_S	CurrentThread;

	CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();
	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	if (KeGetPreviousMode() == KernelMode ||
		(CurrentThread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) ||
		Process->DebugPort == NULL)
	{
		return;
	}

	if (CurrentThread->SystemThread != TRUE &&
		CurrentThread->Tcb.ApcStateIndex != 0x1)
	{
		Teb = (PTEB)CurrentThread->Tcb.Teb;
	}else{
		Teb = NULL;
	}

	if (Teb != NULL && Process == CurrentProcess)
	{
		if (!DbgkpSuppressDbgMsg(Teb))
		{
			//
		}else{
			//暂停调试消息的话就退出
			return;
		}
	}

	ApiMsg.u.UnloadDll.BaseAddress = BaseAddress;

	DBGKM_FORMAT_API_MSG(ApiMsg,DbgKmUnloadDllApi,sizeof(DBGKM_UNLOAD_DLL));
	DbgkpSendApiMessage(&ApiMsg,0x1);
}

_declspec(naked) VOID DbgkUnMapViewOfSection_S()
{
	__asm{
		mov		edi,edi
		push	ebp
		mov		ebp,esp

		push	[ebp+0x8]
		push	eax
		call	DbgkUnMapViewOfSection

		pop		ebp
		retn	0x4
	}
}

BOOLEAN __stdcall
DbgkForwardException(
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN BOOLEAN DebugException,
    IN BOOLEAN SecondChance
    )
{
	NTSTATUS		st;

    PEPROCESS_S		Process;
	PVOID			ExceptionPort;
	PDEBUG_OBJECT	DebugObject;
	BOOLEAN			bLpcPort;

	DBGKM_APIMSG m;
	PDBGKM_EXCEPTION args;

	DebugObject = NULL;
	ExceptionPort = NULL;
	bLpcPort = FALSE;

	args = &m.u.Exception;
	DBGKM_FORMAT_API_MSG(m,DbgKmExceptionApi,sizeof(*args));

	Process = (PEPROCESS_S)PsGetCurrentProcess();

	if (DebugException == TRUE)
	{
		if (((PETHREAD_S)PsGetCurrentThread())->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_HIDEFROMDBG)
		{
			DebugObject = NULL;
		}else{
			DebugObject = (PDEBUG_OBJECT)Process->DebugPort;
		}
	}else{
		ExceptionPort = PsCaptureExceptionPort(Process);
		m.h.u2.ZeroInit = LPC_EXCEPTION;
		bLpcPort = TRUE;
	}

	if ((ExceptionPort == NULL && DebugObject == NULL) &&
		DebugException == TRUE)
	{
		return FALSE;
	}

	args->ExceptionRecord = *ExceptionRecord;
	args->FirstChance = !SecondChance;

	if (bLpcPort == FALSE)
	{
		st = DbgkpSendApiMessage(&m,DebugException);
	}else if(ExceptionPort){
		
		st = DbgkpSendApiMessageLpc(&m,ExceptionPort,DebugException);
		ObfDereferenceObject(ExceptionPort);
	}else{
		m.ReturnedStatus = DBG_EXCEPTION_NOT_HANDLED;
		st = STATUS_SUCCESS;
	}

	if (NT_SUCCESS(st))
	{
		//根据汇编感觉这样写才恰当....
		st = m.ReturnedStatus;

		if (m.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED)
		{
			if (DebugException == TRUE)
			{
				return FALSE;
			}

			st = DbgkpSendErrorMessage(ExceptionRecord,&m);
		}


	}

	return NT_SUCCESS(st);
}

NTSTATUS __stdcall
	DbgkpSendApiMessageLpc(
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN PVOID Port,
	IN BOOLEAN SuspendProcess
	)
{
	NTSTATUS status;
	__asm{
		xor		eax,eax
		mov		al,SuspendProcess
		push	eax
		push	Port
		mov		eax,ApiMsg
		call	g_OrigDbgkpSendApiMessageLpc
		mov		status,eax
	}

	return status;
}

NTSTATUS __stdcall DbgkCopyProcessDebugPort(
	IN PEPROCESS_S TargetProcess,
	IN PEPROCESS_S SourceProcess,
	IN PDEBUG_OBJECT DebugObject,			//EAX
	OUT PBOOLEAN bFlag
	)
{
	TargetProcess->DebugPort = 0;
	if (DebugObject == NULL)
	{
		if (SourceProcess->DebugPort == NULL)
		{
			*bFlag = FALSE;
			return STATUS_SUCCESS;
		}else{
			ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
			DebugObject = (PDEBUG_OBJECT)SourceProcess->DebugPort;
			if (DebugObject)
			{
				if (SourceProcess->Flags&PS_PROCESS_FLAGS_NO_DEBUG_INHERIT)
				{
					DebugObject = NULL;
				}else{
					ObfReferenceObject(DebugObject);
				}
			}
			ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
		}

	}else{
		ObfReferenceObject(DebugObject);
	}

	if (DebugObject == NULL)
	{
		*bFlag = FALSE;
		return STATUS_SUCCESS;
	}

	if (KeGetPreviousMode() == UserMode &&
		SourceProcess->ProtectedProcess == FALSE &&
		TargetProcess->ProtectedProcess == TRUE)
	{
		ObfDereferenceObject(DebugObject);
		return STATUS_PROCESS_IS_PROTECTED;
	}

	ExAcquireFastMutex(&DebugObject->Mutex);
	if (DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING)	//?
	{
		SourceProcess->Pcb.Header.DebugActive = TRUE;
	}else{
		TargetProcess->DebugPort = DebugObject;
	}
	ExReleaseFastMutex(&DebugObject->Mutex);

	if (SourceProcess->Pcb.Header.DebugActive == TRUE)
	{
		ObfDereferenceObject(DebugObject);
		DebugObject = NULL;
	}

	if (DebugObject == NULL)
	{
		*bFlag = FALSE;
	}else{
		DbgkpMarkProcessPeb(TargetProcess);
		*bFlag = TRUE;
	}

	return STATUS_SUCCESS;
}

_declspec(naked) VOID DbgkCopyProcessDebugPort_S()
{
	__asm{
		mov		edi,edi
		push	ebp
		mov		ebp,esp

		push	[ebp+0x10]
		push	eax
		push	[ebp+0xC]
		push	[ebp+0x8]
		call	DbgkCopyProcessDebugPort

		pop		ebp
		retn	0xC
	}
}

//////////////////////////////////////////////////////////////////////////
VOID InitCreateNewFastMutex()
{
	PMODULE_ENTRY pKernelModule;

	/*
	83e67ac1 83bf9000000000  cmp     dword ptr [edi+90h],0
	83e67ac8 0f848c010000    je      nt!DbgkCopyProcessDebugPort+0x1ba (83e67c5a)
	83e67ace b101            mov     cl,1
	83e67ad0 ff155c61c183    call    dword ptr [nt!_imp_KfRaiseIrql (83c1615c)]
	83e67ad6 bea0c9d783      mov     esi,offset nt!DbgkpProcessDebugPortMutex (83d7c9a0)
	*/

	PFAST_MUTEX	gkv_DbgkpProcessDebugPortMutex;

	SIGNATURE_INFO Signature[5] = {{0xBF,20},{0x0F,14},{0xB1, 8},{0xFF, 6},{0xBE, 0}};

	gkv_DbgkpProcessDebugPortMutex = (PFAST_MUTEX)SearchAddressForSign(\
		(ULONG)g_KernlModule->base,g_KernlModule->sectionsize,Signature);
	if (gkv_DbgkpProcessDebugPortMutex)
	{
		gkv_DbgkpProcessDebugPortMutex = *(PFAST_MUTEX*)((ULONG)gkv_DbgkpProcessDebugPortMutex+1);
	}
	
	DbgkpProcessDebugPortMutex = *gkv_DbgkpProcessDebugPortMutex;
}
//////////////////////////////////////////////////////////////////////////

BOOLEAN InitDbgSys()
{
	/************************************************************************
	nt!NtCreateDebugObject+0x58:
	840c4075 ff75e4          push    dword ptr [ebp-1Ch]
	840c4078 ff7510          push    dword ptr [ebp+10h]
	840c407b ff3534dbf483    push    dword ptr [nt!DbgkDebugObjectType (83f4db34)]
	************************************************************************/
	UCHAR	DbgTypeSign[] = {0xFF,0x75,0x10,0xFF,0x35};
	UCHAR	MapSectionSign[] = {0xE0,0x8B,0x4D,0xD8,0xE8};

	SIGNATURE_INFO	SendErrorMsgSign[] = {{0x80,14},{0x01,11},{0x74,10},{0x50, 4},{0x08, 1}};
	SIGNATURE_INFO	SendLpcMsgSign[] = {{0x3C,16},{0x01,15},{0xDB,11},{0x0C, 6},{0x53, 1}};
	SIGNATURE_INFO	CreateThreadSign[] = {{0x57,17},{0x57,16},{0x04, 4},{0x57, 1},{0xE8, 0}};
	SIGNATURE_INFO	ExitProcessSign[] = {{0x3C,19},{0x20,17},{0x0D, 7},{0x74, 4},{0xE8, 0}};
	SIGNATURE_INFO	UnMapSectionSign[] = {{0x19,17},{0x14,10},{0x14, 3},{0xC3, 1},{0xE8, 0}};
	SIGNATURE_INFO	ForwardExcptSign[] = {{0x14, 6},{0x56, 4},{0x01, 2},{0x53, 1},{0xE8, 0}};
	SIGNATURE_INFO	CopyDbgPortSign[] = {{0x13, 9},{0x50, 8},{0x20, 4},{0x57, 1},{0xE8, 0}};
	SIGNATURE_INFO	ClearDbgPortSign[] = {{0xF0,15},{0x04, 9},{0x00, 2},{0x57, 1},{0xE8, 0}};

	g_bInitDebugSys = FALSE;

	//初始化调试同步锁
	ExInitializeFastMutex(&DbgkpProcessDebugPortMutex);

	//搜索DbgkDebugObjectType
	DbgkDebugObjectType = (POBJECT_TYPE*)GetAddress(KeServiceDescriptorTable.ServiceTableBase[CREATE_DBGOBJ_ID],DbgTypeSign,1);
	if (DbgkDebugObjectType == NULL){	return FALSE;	}

	InitCreateNewFastMutex();

	DbgkpSendErrorMessage = (DBGKPSENDERRORMESSAGE)SearchAddressForSign(
		g_KernlModule->base,g_KernlModule->sectionsize,SendErrorMsgSign);
	if(DbgkpSendErrorMessage == NULL){	return FALSE;	}
	DbgkpSendErrorMessage = (DBGKPSENDERRORMESSAGE)((ULONG)DbgkpSendErrorMessage + *(ULONG*)((ULONG)DbgkpSendErrorMessage + 1) + 0x5);
	if (DbgkpSendErrorMessage == NULL){	return FALSE;	}

	g_OrigDbgkpSendApiMessageLpc = SearchAddressForSign(
		g_KernlModule->base,g_KernlModule->sectionsize,SendLpcMsgSign);
	if (g_OrigDbgkpSendApiMessageLpc == 0){	return FALSE;	}
	g_OrigDbgkpSendApiMessageLpc = g_OrigDbgkpSendApiMessageLpc + *(ULONG*)(g_OrigDbgkpSendApiMessageLpc + 1) + 0x5;
	if (g_OrigDbgkpSendApiMessageLpc == 0){	return FALSE;	}

	g_OrigKDbgCreateThread = SearchAddressForSign(
		g_KernlModule->base,g_KernlModule->sectionsize,CreateThreadSign);
	if(g_OrigKDbgCreateThread == 0){	return FALSE;	}
	g_OrigKDbgCreateThread = g_OrigKDbgCreateThread + *(ULONG*)(g_OrigKDbgCreateThread+0x1) +0x5;
	if(g_OrigKDbgCreateThread == 0){	return FALSE;	}

	//g_OrigKDbgExitThread和g_OrigKDbgExitProcess一起写，因为两个相隔就一点点儿而已....
	g_OrigKDbgExitProcess = SearchAddressForSign(
		g_KernlModule->base,g_KernlModule->sectionsize,ExitProcessSign);
	if(g_OrigKDbgExitProcess == 0){	return FALSE;	}
	g_OrigKDbgExitThread = g_OrigKDbgExitProcess+0x8;
	g_OrigKDbgExitProcess = g_OrigKDbgExitProcess + *(ULONG*)(g_OrigKDbgExitProcess+0x1) +0x5;
	if(g_OrigKDbgExitProcess == 0){	return FALSE;	}
	g_OrigKDbgExitThread = g_OrigKDbgExitThread + *(ULONG*)(g_OrigKDbgExitThread+0x1) +0x5;
	if(g_OrigKDbgExitThread == 0){	return FALSE;	}

	g_OrigKDbgMapViewOfSection = GetAddress(KeServiceDescriptorTable.ServiceTableBase[MAP_SECTION_ID],MapSectionSign,0);
	if(g_OrigKDbgMapViewOfSection == 0){		return FALSE;	}

	g_OrigKDbgUnMapViewOfSection = SearchAddressForSign(
		g_KernlModule->base,g_KernlModule->sectionsize,UnMapSectionSign);
	if(g_OrigKDbgUnMapViewOfSection == 0){	return FALSE;	}
	g_OrigKDbgUnMapViewOfSection = g_OrigKDbgUnMapViewOfSection + *(ULONG*)(g_OrigKDbgUnMapViewOfSection+0x1) +0x5;
	if(g_OrigKDbgUnMapViewOfSection == 0){	return FALSE;	}

	g_OrigKDbgForwardException = SearchAddressForSign(
		g_KernlModule->base,g_KernlModule->sectionsize,ForwardExcptSign);
	if(g_OrigKDbgForwardException == 0){	return FALSE;	}
	g_OrigKDbgForwardException = g_OrigKDbgForwardException + *(ULONG*)(g_OrigKDbgForwardException+0x1) +0x5;
	if(g_OrigKDbgForwardException == 0){	return FALSE;	}

	g_OrigKDbgCopyProcessDebugPort = SearchAddressForSign(
		g_KernlModule->base,g_KernlModule->sectionsize,CopyDbgPortSign);
	if(g_OrigKDbgCopyProcessDebugPort == 0){	return FALSE;	}
	g_OrigKDbgCopyProcessDebugPort = g_OrigKDbgCopyProcessDebugPort + *(ULONG*)(g_OrigKDbgCopyProcessDebugPort+0x1) +0x5;
	if(g_OrigKDbgCopyProcessDebugPort == 0){	return FALSE;	}

	g_OrigKDbgClearProcessDebugPort = SearchAddressForSign(
		g_KernlModule->base,g_KernlModule->sectionsize,ClearDbgPortSign);
	if(g_OrigKDbgClearProcessDebugPort == 0){	return FALSE;	}
	g_OrigKDbgClearProcessDebugPort = g_OrigKDbgClearProcessDebugPort + *(ULONG*)(g_OrigKDbgClearProcessDebugPort+0x1) +0x5;
	if(g_OrigKDbgClearProcessDebugPort == 0){	return FALSE;	}

	g_bInitDebugSys = TRUE;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
/*
Up   p PspTerminateAllThreads(x,x,x,x)+1CF call    _DbgkClearProcessDebugObject@8; DbgkClearProcessDebugObject(x,x)
//nt!PspProcessDelete+0xbe:
nt!ObpCloseHandleTableEntry+0x183:		//内核调试中才会用到debugport
nt!ObpCloseHandle+0xd3:					//内核调试中才会用到debugport
nt!DbgkOpenProcessDebugPort+0x18:
nt!DbgkOpenProcessDebugPort+0x56:

*/
//////////////////////////////////////////////////////////////////////////

