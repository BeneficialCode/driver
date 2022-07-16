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

	//�ж��û�������ַ�Ƿ�Ϸ�
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

	//�������Զ���
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
	//��ʼ�����Զ���
	ExInitializeFastMutex (&DebugObject->Mutex);
	InitializeListHead (&DebugObject->EventList);
	KeInitializeEvent (&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & DEBUG_KILL_ON_CLOSE) {
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	} else {
		DebugObject->Flags = 0;
	}

	//���Զ����������
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
	//�õ������Խ��̵�eprocess
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

	//�жϱ����Խ����Ƿ��Լ����߱����Խ����Ƿ�PsInitialSystemProcess���̣��ǵĻ��˳�
	if (Process == (PEPROCESS_S)PsGetCurrentProcess () || Process == (PEPROCESS_S)PsInitialSystemProcess) {
		ObDereferenceObject (Process);
		return STATUS_ACCESS_DENIED;
	}

	CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();

	//�ж���ģʽ����ǰ���̵�ProtectedProcess�ͱ����Խ��̵�ProtectedProcess
	if(PreviousMode==UserMode &&
		CurrentProcess->ProtectedProcess==0 &&
		Process->ProtectedProcess)
	{
		//�������֣������ǰ���̱���������ô�͵����������ˡ�
		//��˵����ǰ�������ܱ����ľͿ��Ժ���Ŀ������Ƿ��ܱ����ˡ�
		ObfDereferenceObject(Process);
		return STATUS_PROCESS_IS_PROTECTED;
	}

	//�õ����Ծ�������ĵ��Զ���(DebugObject)
	status = ObReferenceObjectByHandle (
		DebugObjectHandle,
		0x2,
		*DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);

	if (NT_SUCCESS (status)) {
		//�����˳��ɲ��ð��ˣ����������ﻹ���ȵ���ExAcquireRundownProtection�ɣ���ȫһ���
		if(ExAcquireRundownProtection(&Process->RundownProtect))
		{
			//����һ������Ľ��̴�����Ϣ....����������������ģ�ʵ����Ҫ�ﵽ��Ч��Ҳ�����
			status = DbgkpPostFakeProcessCreateMessages(Process,DebugObject,&LastThread);

			//ע�⣬DbgkpSetProcessDebugObject�����и������ǼĴ������Σ������������ѿ�������
			//����һ��������DbgkpPostFakeProcessCreateMessages�����ķ���ֵ�����˲�����ͨ��
			//eax���ݽ�ȥ�ģ�Ϊ�˱��ֺ�windows�Ĵ���һ�£���Ҳд��wrkһ���İɡ�
			//���õ��Զ���������ԵĽ���
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

	//�ռ������̴߳�������Ϣ
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

		//�ռ�ģ�鴴������Ϣ
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
	DBGKM_APIMSG ApiMsg;	//���������һ��δ֪�Ľṹ�壬Ӧ�þ���DBGKM_APIMSG���͵Ľṹ
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
			//����漰������Ҳ�Ƚ϶࣬����һ��Ҳ��������������Ϊ�˼�ע�͵�����
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

		//ÿ�ι���һ��DBGKM_APIMSG�ṹ
		memset(&ApiMsg,0,sizeof(DBGKM_APIMSG));

		if(First && (Flags&DEBUG_EVENT_PROTECT_FAILED)==0)
		{
			//���̵ĵ�һ���̲߳Żᵽ����
			IsFirstThread = TRUE;
			ApiMsg.ApiNumber = DbgKmCreateProcessApi;
			if(Process->SectionObject)
			{
				//DbgkpSectionToFileHandle�����Ƿ���һ��ģ��ľ��
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
	ULONG	Flag					//eax����
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
	ULONG index)			//�����index�������1
{
	PVOID	DllInfo;

	DllInfo = (PVOID)PspSystemDlls[index];	//[DllInfo+0x14]��ģ��Ļ���ַ
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

	//����Ĳ���Flags�ڴ˺����о����ֺ��壬�Ƿ�ȴ�����Ϣ��ɺͲ��ȴ�����Ϣ��ɣ������ֺ������������loadDll��Ϣ
	//���ȴ�����Ϣ�����ô�������ڴ�����Ŵ���Ϣ���ȴ�����Ϣ��ɵĻ���ô�Ͷ�����ʱ�����������Ϣ�����ҵȴ���ɡ�
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
		//ͬ����Ϣ��
		ExAcquireFastMutex (&DbgkpProcessDebugPortMutex);

		DebugObject = Process->DebugPort;

		//�Ƿ������̻߳���̴�������Ϣ
		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi ||
			ApiMsg->ApiNumber == DbgKmCreateProcessApi) {
				if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG) {
					DebugObject = NULL;
				}
		}

		//����Flags&0x40Ϊ������Ǳ�ʾ����LoadDll����Ϣ
		if(ApiMsg->ApiNumber == DbgKmLoadDllApi &&
			Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG &&
			Flags&0x40){
				DebugObject = NULL;
		}

		//�����̻߳��߽����˳�����Ϣ
		if (ApiMsg->ApiNumber == DbgKmExitThreadApi ||
			ApiMsg->ApiNumber == DbgKmExitProcessApi) {
				if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG) {
					DebugObject = NULL;
				}
		}

		//��ʼ��DebugEvent->ContinueEvent
		KeInitializeEvent (&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);
	}

	//���DebugEvent�ĸ�����Ϣ
	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	DebugEvent->ClientId = Thread->Cid;

	if (DebugObject == NULL) {
		Status = STATUS_PORT_NOT_SET;
	} else {

		//��ֹDebugObject����д���ͻ
		ExAcquireFastMutex (&DebugObject->Mutex);

		//������Զ���׼��ɾ���Ļ�����ô�Ͳ�Ҫ��������¼���
		//���򣬰����ǵĵ����¼���������Զ��󣬲��ҿ��Ƿ�ȴ���ɣ��ȴ�����Ϣ��ɵĻ����Ǿͼ������Ϣ
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

	//����ȴ�����Ϣ��ɣ������Ǿ�Ҫ������ִ�еȴ�����
	if ((Flags&DEBUG_EVENT_NOWAIT) == 0) {
		//��ʱ���ͷ���Ϣͬ������Ϊ����ȴ���Ҫ��ʱ����������Ҫ��KeWaitForSingleObject����ǰ������
		//������Ϣ�Ѿ�˳���Ĳ�����Զ����ˣ����Բ����ڲ���ȫ��������
		ExReleaseFastMutex (&DbgkpProcessDebugPortMutex);

		if (NT_SUCCESS (Status)) {
			KeWaitForSingleObject (
				&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			//��Ϣ��ɵĻ��������������Ϣ��ɵ�״ֵ̬��������Ϊ����ֵʹ��
			Status = DebugEvent->Status;
			//ApiMsg���������
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

			//��Ϊ��DbgkSendSystemDllMessages�������Ѿ���ǰ����ģ�鴦���ˣ���������Ҫ����1
			if (i > 1) {
				//׼������ϢDBGKM_APIMSG��Ϣ���ݰ�
				RtlZeroMemory (&ApiMsg, sizeof (ApiMsg));

				//ʵ��û������һ��Ҳ�У���ΪLdrNextҲ��LdrEntry
				LdrEntry = CONTAINING_RECORD (LdrNext, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				ProbeForReadSmallStructure (LdrEntry, sizeof (LDR_DATA_TABLE_ENTRY), sizeof (UCHAR));

				//˵���Ǽ���ģ�����Ϣ
				ApiMsg.ApiNumber = DbgKmLoadDllApi;
				ApiMsg.u.LoadDll.BaseOfDll = LdrEntry->DllBase;

				ProbeForReadSmallStructure (ApiMsg.u.LoadDll.BaseOfDll, sizeof (IMAGE_DOS_HEADER), sizeof (UCHAR));

				//�õ�ģ���ntͷ
				NtHeaders = RtlImageNtHeader (ApiMsg.u.LoadDll.BaseOfDll);
				if (NtHeaders) {
					//����ģ��ķ�������
					ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
				//MmGetFileNameForAddress������ͨ��һ����ַ��ȡһ��ģ������֡�
				Status = MmGetFileNameForAddress (NtHeaders, &Name);
				if (NT_SUCCESS (Status)) {
					//�ɹ��õ�ģ�����ֵĻ�����ô�ͻ�ȡ��ģ��ľ��
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
						//��ΪMmGetFileNameForAddress�����ڲ���Ϊ������ֵĻ����������ڴ棬����������Ҫ�ͷŵ�����Ȼ������ڴ�й¶
						ExFreePool (Name.Buffer);
				}

				//�������ж��Ƿ��е��Զ������
				if(DebugObject)
				{
					//���ڵĻ���ֱ�ӵ���DbgkpQueueMessage�ѵ�����Ϣ������Զ���Ķ��У����Ҹ���Ϣ�ǲ�������(����˵���ȵ���ɺ�ŷ���)
					Status = DbgkpQueueMessage (
						Process,
						Thread,
						&ApiMsg,
						DEBUG_EVENT_NOWAIT,
						DebugObject);
				}else{
					//�������Ҳ���Է��͵�����Ϣ��ԭ���ҷ������¿������£�
					/*
					NTSTATUS DbgkpSendApiMessage(
						IN ULONG Flags,                                //һ�����
						IN DBGKM_APIMSG *ApiMsg                //��Ϣ��
					);
					*/
					//������������ڲ�ʵ���Ͽ����������͵���Ϣ��������
					DbgkpSendApiMessage(&ApiMsg,0x3);
					//�����������´����룬Ϊ�˺���ر�ģ����
					Status = STATUS_UNSUCCESSFUL;
				}

                                
				if (!NT_SUCCESS (Status) && ApiMsg.u.LoadDll.FileHandle != NULL) {
					//����رվ��������������ģʽ��Ҫ�ֶ��رվ��.....���ֻ�ǲ²⣬Ҫ�ȵ����濴���յ�����Ϣ�ĺ���ʱ����������ô���¶�
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

	//��ʼ���������֮�󴢴���Ϣ
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

			//��������Խ��̵�debugport�Ѿ����ã���ô����ѭ��
			if (Process->DebugPort != NULL) {
				Status = STATUS_PORT_ALREADY_SET;
				break;
			}

			//û������debugport������������
			Process->DebugPort = DebugObject;

			//���ӱ����Խ������һ���̵߳�����
			ObReferenceObject (LastThread);

			//�������������ֵ��˵������֮�仹���̱߳������ˣ�����ҲҪ���������Ϣ����
			Thread = PsGetNextProcessThread (Process, LastThread);
			if (Thread != NULL) {

				Process->DebugPort = NULL;

				ExReleaseFastMutex (&DbgkpProcessDebugPortMutex);

				GlobalHeld = FALSE;

				ObDereferenceObject (LastThread);
				//֪ͨ�̴߳�����Ϣ
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
		//�������Զ����Ƿ�Ҫ��ɾ��
		if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {
			PS_SET_BITS (&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT|PS_PROCESS_FLAGS_CREATE_REPORTED);
			ObReferenceObject (DebugObject);
		} else {
			Process->DebugPort = NULL;
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	//ͨ������Ĳ��������Զ������Ϣ����װ�����̴߳�������Ϣ(ͬʱҲ����ģ����ص���Ϣ)
	//
	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		) {
			//ȡ�������¼�
			DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);
			Entry = Entry->Flink;

			//���������¼��Ƿ��ڴ���������Ǽ��ڴ���ģ�˵����DbgkpQueueMessage��������û�еõ�����
			//��ô���Ǿ���������취�����(���ڴ�����Ѿ���DbgkpQueueMessage�����д�����ˣ������������赣��)��
			//���ҿ����Ƿ��Ǳ��̸߳���֪ͨ��ɴ���Ϣ
			if ((DebugEvent->Flags&DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == ThisThread) {
				Thread = DebugEvent->Thread;

				if (NT_SUCCESS (Status)) {
					//�����ж�֮ǰ���߳������ֹͣ�����Ƿ�ʧ��
					if ((DebugEvent->Flags&DEBUG_EVENT_PROTECT_FAILED) != 0) {
						PS_SET_BITS (&Thread->CrossThreadFlags,
							PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
						RemoveEntryList (&DebugEvent->EventList);
						InsertTailList (&TempList, &DebugEvent->EventList);
					} else {
						//���Ｋ�п������ж��Ƿ����̵߳Ĵ�����Ϣ�������̵߳Ļ������Ϣ
						if (First) {
							DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
							KeSetEvent (&DebugObject->EventsPresent, 0, FALSE);
							First = FALSE;
						}
						//���������������̴߳�����Ϣ
						DebugEvent->BackoutThread = NULL;
						PS_SET_BITS (&Thread->CrossThreadFlags,
							PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);

					}
				} else {
					//���Ƴ���Ϣ�����Ҽ�����ʱ������
					RemoveEntryList (&DebugEvent->EventList);
					InsertTailList (&TempList, &DebugEvent->EventList);
				}
				//���￴���ǹ�������߳�ֹͣ�������ǵĻ��ͷ�����
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

	//�����ȡ��ʱ�������Ҵ��������ÿ����Ϣ
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

	//�жϼ������������ͣ��˺����������wrk�еĲ�ͬ����
	switch (ContinueStatus) {
	case DBG_EXCEPTION_NOT_HANDLED :
	case DBG_CONTINUE :
	case DBG_TERMINATE_PROCESS :
		break;
	default :
		return STATUS_INVALID_PARAMETER;
	}

	//�õ����Զ���
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

	//������ָ���ĵ�����Ϣ������Ϊture����ʼ��ʱΪfalse
	GotEvent = FALSE;
	//����Ѱ�ҵ�������Ϣ�ı���
	FoundDebugEvent = NULL;

	//���������Ҫ��ǰ���һ�û����������Ҫ�Ե�����������һЩĪ������Ĵ��룬���������������Ļ�����˵��ͨ�ˡ�
	ExAcquireFastMutex (&DebugObject->Mutex);

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		Entry = Entry->Flink) {

			DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);

			//���Ｘ���жϾ���Ϊ���ҵ�ָ����Ϣ
			if (DebugEvent->ClientId.UniqueProcess == Clid.UniqueProcess) {
				//�����û��Ѱ�ҵ�������if
				if (!GotEvent) {
					//�����DEBUG_EVENT_READ�Ǳ�ʾ�����Ϣ��û��û��ȡ����Ҳ����˵��û�б��������
					//����������������ȷʵ������Ҫ�ҵ���Ϣ����ô�ʹ���Ϣ�����Ƴ��������棬Ȼ��
					//���ñ��˵�ҵ��ˡ�����DEBUG_EVENT_READ������ʮ����Ҫ�����������������
					//NtWaitForDebugEvent������֪�����������
					if (DebugEvent->ClientId.UniqueThread == Clid.UniqueThread &&
						(DebugEvent->Flags&DEBUG_EVENT_READ) != 0) {
							RemoveEntryList (Entry);
							FoundDebugEvent = DebugEvent;
							GotEvent = TRUE;
					}
				} else {
					//���������˵�������Ѿ��ҵ���ָ������Ϣ�����Ҵ˵����¼��������ǿյģ�
					//��ô�����������ɻ�ȡ������¼���ע�⣬��������д�Ƿǳ�������ģ�����
					//Ϊ��Ҫ�ȵ�����NtWaitForDebugEvent��ʱ���ٽ���
					DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
					KeSetEvent (&DebugObject->EventsPresent, 0, FALSE);
					break;
				}
			}
	}

	ExReleaseFastMutex (&DebugObject->Mutex);

	ObDereferenceObject (DebugObject);

	if (GotEvent) {
		//�ҵ��Ļ��������ϢҲ���㳹����������ˡ�ע�������DbgkpWakeTarget�����һ���������Ϣ
		//��ֱ���ͷ���ռ�ڴ��
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

	//����ͨ�������ȡ���Զ���
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
		//�ڵ��Զ������¼�����
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

		//�ȵ����źź��ж��Ƿ�˵��Զ�����Ч�ˣ�û����Ч��ô�ͽ�һ������
		if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {

			//��������������¼�����
			for (Entry = DebugObject->EventList.Flink;
				Entry != &DebugObject->EventList;
				Entry = Entry->Flink) {

					DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);
					//�ж���Ϣ�Ƿ��Ѿ���ȡ�������Ƿ񻹲���Ҫ����������
					if ((DebugEvent->Flags&(DEBUG_EVENT_READ|DEBUG_EVENT_INACTIVE)) == 0) {
						GotEvent = TRUE;

						//������еڶ��α����¼�����
						for (Entry2 = DebugObject->EventList.Flink;
							Entry2 != Entry;
							Entry2 = Entry2->Flink) {

								DebugEvent2 = CONTAINING_RECORD (Entry2, DEBUG_EVENT, EventList);
								//�ܽ������������˵�����ҵ���DebugEvent�����δ�����¼�����ô������������
								//DebugEvent�¼����Ϊ������״̬��ʵ��һ������ǽ��벻�����ѭ����ģ���Ϊ
								//Ŀǰ�һ��ܿ�������һ�������¼�ʱ�����б���������¼������û����������
								//������о��ᷢ��������⣬��ʱ��������̸��ͨ������Ҳ���Կ����������¼���
								//�ϸ��ն�����ʽ������ģ�Ҳ�����������ȴ���
								//
								if (DebugEvent->ClientId.UniqueProcess == DebugEvent2->ClientId.UniqueProcess) {

									DebugEvent->Flags |= DEBUG_EVENT_INACTIVE;
									DebugEvent->BackoutThread = NULL;
									GotEvent = FALSE;
									break;
								}
						}
						//�ҵ�һ�������������¼��Ļ������˳�ѭ����
						if (GotEvent) {
							break;
						}
					}
			}

			//�ҵ��Ļ������¼���ص���Ϣת�����û����ʶ�����Ϣ��Ȼ�����ô��¼��Ѷ�
			if (GotEvent) {
				Process = DebugEvent->Process;
				Thread = DebugEvent->Thread;
				ObReferenceObject (Thread);
				ObReferenceObject (Process);
				DbgkpConvertKernelToUserStateChange (&tWaitStateChange, DebugEvent);
				DebugEvent->Flags |= DEBUG_EVENT_READ;
			} else {
				//û�ҵ��Ļ����õ��Զ���û���ź���.....
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
			//��Ϊ��SeLocateProcessImageName��ΪImageName�������ڴ棬����Ҫ�ڴ˴��ͷŵ�
			ExFreePoolWithTag(ImageName,0);
		}

		//PsReferenceProcessFilePointer���������ü���
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

				//ʵ�ʾ���PspSystemDlls
				SystemDll = (PSYSTEM_DLL)((ULONG)ModuleInfo-0x8);
				Object = ObFastReferenceObject(&SystemDll->FastRef);
				if (Object == NULL)
				{
					CurrentThread = (PKTHREAD_S)PsGetCurrentThread();
					KeEnterCriticalRegionThread(CurrentThread);
					
					ExAcquirePushLockShared(&SystemDll->Lock);

					//����ϵͳģ�鲻���ܵò���������������win7û���ж�
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
			//��ͣ������Ϣ�Ļ����˳�
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
			//��ͣ������Ϣ�Ļ����˳�
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
		//���ݻ��о�����д��ǡ��....
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

	//��ʼ������ͬ����
	ExInitializeFastMutex(&DbgkpProcessDebugPortMutex);

	//����DbgkDebugObjectType
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

	//g_OrigKDbgExitThread��g_OrigKDbgExitProcessһ��д����Ϊ���������һ��������....
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
nt!ObpCloseHandleTableEntry+0x183:		//�ں˵����вŻ��õ�debugport
nt!ObpCloseHandle+0xd3:					//�ں˵����вŻ��õ�debugport
nt!DbgkOpenProcessDebugPort+0x18:
nt!DbgkOpenProcessDebugPort+0x56:

*/
//////////////////////////////////////////////////////////////////////////

