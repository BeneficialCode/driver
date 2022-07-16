#include "CommonFunc.h"
#include "stdio.h"

/*
VOID ExAcquirePushLockShared (
	IN PEX_PUSH_LOCK_S PushLock
	)
{
	EX_PUSH_LOCK_S OldValue, NewValue;

	OldValue.Value = 0;
	NewValue.Value = EX_PUSH_LOCK_SHARE_INC|EX_PUSH_LOCK_LOCK;

	if (InterlockedCompareExchangePointer (&PushLock->Ptr,
		NewValue.Ptr,
		OldValue.Ptr) != OldValue.Ptr) {
			ExfAcquirePushLockShared (PushLock);
	}
}

VOID ExfAcquirePushLockShared (
     __inout PEX_PUSH_LOCK_S PushLock
     )
{
    EX_PUSH_LOCK_S OldValue, NewValue, TopValue;
    EX_PUSH_LOCK_WAIT_BLOCK WaitBlock;
    BOOLEAN Optimize;

    OldValue = ReadForWriteAccess (PushLock);

    while (1) {
        //
        // If the lock is already held we need to wait if its not held shared
        //
        if (!OldValue.Locked || (!OldValue.Waiting && OldValue.Shared > 0)) {

            if (OldValue.Waiting) {
                NewValue.Value = OldValue.Value + EX_PUSH_LOCK_LOCK;
            } else {
                NewValue.Value = (OldValue.Value + EX_PUSH_LOCK_SHARE_INC) | EX_PUSH_LOCK_LOCK;
            }
            ASSERT (NewValue.Locked);
            NewValue.Ptr = InterlockedCompareExchangePointer (&PushLock->Ptr,
                                                              NewValue.Ptr,
                                                              OldValue.Ptr);
            if (NewValue.Ptr == OldValue.Ptr) {
                break;
            }

        } else {
            WaitBlock.Flags = EX_PUSH_LOCK_FLAGS_SPINNING;
            WaitBlock.ShareCount = 0;
            Optimize = FALSE;
            WaitBlock.Previous = NULL;
 
            if (OldValue.Waiting) {
                WaitBlock.Last = NULL;
                WaitBlock.Next = (PEX_PUSH_LOCK_WAIT_BLOCK)
                                     (OldValue.Value & ~EX_PUSH_LOCK_PTR_BITS);
                NewValue.Ptr = (PVOID)(((ULONG_PTR) &WaitBlock) |
                                    (OldValue.Value & (EX_PUSH_LOCK_LOCK | EX_PUSH_LOCK_MULTIPLE_SHARED)) |
                                    EX_PUSH_LOCK_WAITING | EX_PUSH_LOCK_WAKING);
                if (!OldValue.Waking) {
                    Optimize = TRUE;
                }
            } else {
                WaitBlock.Last = &WaitBlock;
                NewValue.Ptr = (PVOID)(((ULONG_PTR) &WaitBlock) |
                                    (OldValue.Value & EX_PUSH_LOCK_PTR_BITS) |
                                    EX_PUSH_LOCK_WAITING);
            }
             
            ASSERT (NewValue.Waiting);

            TopValue = NewValue;
            NewValue.Ptr = InterlockedCompareExchangePointer (&PushLock->Ptr,
                                                              NewValue.Ptr,
                                                              OldValue.Ptr);

            if (NewValue.Ptr == OldValue.Ptr) {
                ULONG i;

                if (Optimize) {
                    ExpOptimizePushLockList (PushLock, TopValue);
                }

                //
                // It is safe to initialize the gate here, as the interlocked operation below forces 
                // a gate signal to always follow gate initialization.
                //
                KeInitializeGate (&WaitBlock.WakeGate);

                for (i = ExPushLockSpinCount; i > 0; i--) {
                    if (((*(volatile LONG *)&WaitBlock.Flags)&EX_PUSH_LOCK_FLAGS_SPINNING) == 0) {
                        break;
                    }
                    KeYieldProcessor ();
                }

                if (InterlockedBitTestAndReset ((LONG*)&WaitBlock.Flags, EX_PUSH_LOCK_FLAGS_SPINNING_V)) {

                    KeWaitForGate (&WaitBlock.WakeGate, WrPushLock, KernelMode);

                }

            } else {

				//////////////////////////////////////////////////////////////////////////
            }

        }
        OldValue = NewValue;
    }

}

VOID ExpOptimizePushLockList (
    IN PEX_PUSH_LOCK_S PushLock,
    IN EX_PUSH_LOCK_S TopValue
    )
{
    EX_PUSH_LOCK OldValue, NewValue;
    PEX_PUSH_LOCK_WAIT_BLOCK WaitBlock, PreviousWaitBlock, FirstWaitBlock, NextWaitBlock;

    OldValue = TopValue;
    while (1) {
        if (!OldValue.Locked) {
            ExfWakePushLock (PushLock, OldValue);
            break;
        }

        WaitBlock = (PEX_PUSH_LOCK_WAIT_BLOCK)(OldValue.Value & ~(EX_PUSH_LOCK_PTR_BITS));

        FirstWaitBlock = WaitBlock;

        while (1) {

            NextWaitBlock = WaitBlock->Last;
            if (NextWaitBlock != NULL) {
                FirstWaitBlock->Last = NextWaitBlock;
                break;
            }

            PreviousWaitBlock = WaitBlock;
            WaitBlock = WaitBlock->Next;
            WaitBlock->Previous = PreviousWaitBlock;
        }

        NewValue.Value = OldValue.Value - EX_PUSH_LOCK_WAKING;
        ASSERT (NewValue.Locked);
        ASSERT (!NewValue.Waking);
        if ((NewValue.Ptr = InterlockedCompareExchangePointer (&PushLock->Ptr,
                                                               NewValue.Ptr,
                                                               OldValue.Ptr)) == OldValue.Ptr) {
            break;
        }
        OldValue = NewValue;
    }
}

VOID ExfWakePushLock (
    IN PEX_PUSH_LOCK_S PushLock,
    IN EX_PUSH_LOCK_S TopValue
    )
{
    EX_PUSH_LOCK_S OldValue, NewValue;
    PEX_PUSH_LOCK_WAIT_BLOCK WaitBlock, NextWaitBlock, FirstWaitBlock, PreviousWaitBlock;
    KIRQL OldIrql;

    OldValue = TopValue;

    while (1) {

        //
        // Nobody should be walking the list while we manipulate it.
        //

        ASSERT (!OldValue.MultipleShared);

        //
        // No point waking somebody to find a locked lock. Just clear the waking bit
        //

        while (OldValue.Locked) {
            NewValue.Value = OldValue.Value - EX_PUSH_LOCK_WAKING;
            ASSERT (!NewValue.Waking);
            ASSERT (NewValue.Locked);
            ASSERT (NewValue.Waiting);
            if ((NewValue.Ptr = InterlockedCompareExchangePointer (&PushLock->Ptr,
                                                                   NewValue.Ptr,
                                                                   OldValue.Ptr)) == OldValue.Ptr) {
                return;
            }
            OldValue = NewValue;
        }

        WaitBlock = (PEX_PUSH_LOCK_WAIT_BLOCK)
           (OldValue.Value & ~(ULONG_PTR)EX_PUSH_LOCK_PTR_BITS);

        FirstWaitBlock = WaitBlock;

        while (1) {

            NextWaitBlock = WaitBlock->Last;
            if (NextWaitBlock != NULL) {
                WaitBlock = NextWaitBlock;
                break;
            }

            PreviousWaitBlock = WaitBlock;
            WaitBlock = WaitBlock->Next;
            WaitBlock->Previous = PreviousWaitBlock;
        }

        if (WaitBlock->Flags&EX_PUSH_LOCK_FLAGS_EXCLUSIVE &&
            (PreviousWaitBlock = WaitBlock->Previous) != NULL) {

            FirstWaitBlock->Last = PreviousWaitBlock;

            WaitBlock->Previous = NULL;

            ASSERT (FirstWaitBlock != WaitBlock);

            ASSERT (PushLock->Waiting);

#if defined (_WIN64)
            InterlockedAnd64 ((LONG64 *)&PushLock->Value, ~EX_PUSH_LOCK_WAKING);
#else
            InterlockedAnd ((LONG *)&PushLock->Value, ~EX_PUSH_LOCK_WAKING);
#endif

            break;
        } else {
            NewValue.Value = 0;
            ASSERT (!NewValue.Waking);
            if ((NewValue.Ptr = InterlockedCompareExchangePointer (&PushLock->Ptr,
                                                                   NewValue.Ptr,
                                                                   OldValue.Ptr)) == OldValue.Ptr) {
                break;
            }
            OldValue = NewValue;
        }
    }

    //
    // If we are waking more than one thread then raise to DPC level to prevent us
    // getting rescheduled part way through the operation
    //

    OldIrql = DISPATCH_LEVEL;
    if (WaitBlock->Previous != NULL) {
        KeRaiseIrql (DISPATCH_LEVEL, &OldIrql);
    }

    while (1) {

        NextWaitBlock = WaitBlock->Previous;

        if (!InterlockedBitTestAndReset (&WaitBlock->Flags, EX_PUSH_LOCK_FLAGS_SPINNING_V)) {
            KeSignalGateBoostPriority (&WaitBlock->WakeGate);
        }

        WaitBlock = NextWaitBlock;
        if (WaitBlock == NULL) {
            break;
        }
    }

    if (OldIrql != DISPATCH_LEVEL) {
        KeLowerIrql (OldIrql);
    }
}

*/

BOOLEAN InitCommon()
{
	UNICODE_STRING	usFuncName;

	UCHAR	NotifyMaskSign[] = {0xF0,0x0F,0xC1,0x08,0xA1};
	UCHAR	ImageNotifySign[] = {0x3B,0xDF,0x74,0x25,0xBE};
	UCHAR	FreezeTreadSign[] = {0x90,0x90,0x90,0x90,0x8B};
	UCHAR	DuplicateObjSign[] = {0x0C,0x8B,0x4D,0xD8,0xE8};
	UCHAR	SuspendThreadSign[] = {0x50,0xFF,0x75,0xE4,0xE8};
	UCHAR	ResumeThreadSign[] = {0x5E,0x8B,0x45,0xE4,0xE8};

	//这个特征码不行
	SIGNATURE_INFO SystemDllSign[] = 
	{{0xC7,18},{0x1,15},{0xEB, 6},{0xF8, 2},{0xBF, 1}};
	SIGNATURE_INFO ThawThreadSign[] = 
	{{0x8B,12},{0x6A,14},{0x75,2},{0x05, 1},{0xE8, 0}};

	ExInitializePushLock ((PULONG_PTR)&ExpCallBackFlush);
	ExInitializePushLock((PULONG_PTR)&MiChangeControlAreaFileLock);

	g_KernlModule = (PMODULE_ENTRY)GetDriverDataEntry(g_LocateDriverObj,L"ntoskrnl.exe");
	if (g_KernlModule == NULL)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&usFuncName,L"KeGetPreviousMode");
	KeGetPreviousMode = MmGetSystemRoutineAddress(&usFuncName);
	RtlInitUnicodeString(&usFuncName,L"ExSystemExceptionFilter");
	ExSystemExceptionFilter = MmGetSystemRoutineAddress(&usFuncName);
	RtlInitUnicodeString(&usFuncName,L"ObCreateObject");
	ObCreateObject = MmGetSystemRoutineAddress(&usFuncName);
	NtSuspendThread = (NTSUSPENDTHREAD)KeServiceDescriptorTable.ServiceTableBase[SUSPEND_THREAD_ID];
	RtlInitUnicodeString(&usFuncName,L"RtlImageNtHeader");
	RtlImageNtHeader = MmGetSystemRoutineAddress(&usFuncName);
	NtResumeThread = (NTRESUMETHREAD)KeServiceDescriptorTable.ServiceTableBase[RESUME_THREAD_ID];
	RtlInitUnicodeString(&usFuncName,L"ObCloseHandle");
	ObCloseHandle = MmGetSystemRoutineAddress(&usFuncName);
	NtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)KeServiceDescriptorTable.ServiceTableBase[FLUSH_CACHE_ID];
	RtlInitUnicodeString(&usFuncName,L"PsReferenceProcessFilePointer");
	PsReferenceProcessFilePointer = MmGetSystemRoutineAddress(&usFuncName);
	RtlInitUnicodeString(&usFuncName,L"KiCheckForKernelApcDelivery");
	KiCheckForKernelApcDelivery = MmGetSystemRoutineAddress(&usFuncName);
	RtlInitUnicodeString(&usFuncName,L"ExfAcquirePushLockShared");
	ExfAcquirePushLockShared = MmGetSystemRoutineAddress(&usFuncName);
	RtlInitUnicodeString(&usFuncName,L"ExfReleasePushLockShared");
	ExfReleasePushLockShared = MmGetSystemRoutineAddress(&usFuncName);
	if (KeGetPreviousMode == NULL ||
		ExSystemExceptionFilter == NULL ||
		ObCreateObject == NULL ||
		NtSuspendThread == NULL ||
		RtlImageNtHeader == NULL ||
		NtResumeThread == NULL ||
		ObCloseHandle == NULL ||
		NtFlushInstructionCache == NULL ||
		PsReferenceProcessFilePointer == NULL ||
		KiCheckForKernelApcDelivery == NULL ||
		ExfAcquirePushLockShared == NULL ||
		ExfReleasePushLockShared == NULL)
	{
		KdPrint(("failed in 335 line from commonfunc.c"));
		return FALSE;
	}

	//初始化PspNotifyEnableMask的值
	PspNotifyEnableMask = GetAddress((ULONG)PsSetLoadImageNotifyRoutine,NotifyMaskSign,1);
	if (PspNotifyEnableMask == 0)
	{
		return FALSE;
	}
	PspLoadImageNotifyRoutine = (EX_CALLBACK*)GetAddress((ULONG)PsSetLoadImageNotifyRoutine,ImageNotifySign,1);
	if (PspLoadImageNotifyRoutine == 0)
	{
		return FALSE;
	}

	PspSystemDlls = (ULONG*)SearchAddressForSign(g_KernlModule->base,g_KernlModule->sectionsize,SystemDllSign);
	if (PspSystemDlls == NULL){	return FALSE;	}
	PspSystemDlls = *(ULONG**)PspSystemDlls;
	if (PspSystemDlls == NULL){	return FALSE;	}

	KeThawAllThreads = (KETHAWALLTHREADS)SearchAddressForSign(g_KernlModule->base,g_KernlModule->sectionsize,ThawThreadSign);
	if(KeThawAllThreads == NULL){	return FALSE;	}
	KeThawAllThreads = (KETHAWALLTHREADS)((ULONG)KeThawAllThreads + *(ULONG*)((ULONG)KeThawAllThreads+0x1) + 0x5);
	if(KeThawAllThreads == NULL){	return FALSE;	}

	//KeFreezeAllThreads是在KeQueryRuntimeThread的上面
	KeFreezeAllThreads = (KEFREEZEALLTHREADS)GetAddress((ULONG)KeQueryRuntimeThread-0x200,FreezeTreadSign,2);
	if(KeFreezeAllThreads == NULL){		return FALSE;	}

	OrigObDuplicateObject = (OBDUPLICATEOBJECT)GetAddress(KeServiceDescriptorTable.ServiceTableBase[DUPLICATE_OBJ_ID],DuplicateObjSign,0);
	if (OrigObDuplicateObject == NULL){		return FALSE;	}

	PsSuspendThread = (PSSUSPENDTHREAD)GetAddress((ULONG)NtSuspendThread,SuspendThreadSign,0);
	if(PsSuspendThread == NULL){	return FALSE;	}

	NewKeResumeThread = GetAddress((ULONG)NtResumeThread,ResumeThreadSign,0);
	if (NewKeResumeThread == 0){	return FALSE;	}

	ObCreateObject = (OBCREATEOBJECT)((ULONG)ObCreateObject + g_new_kernel_inc);
	ObCloseHandle = (OBCLOSEHANDLE)((ULONG)ObCloseHandle + g_new_kernel_inc);
	PsSuspendThread = (PSSUSPENDTHREAD)((ULONG)PsSuspendThread + g_new_kernel_inc);
	NewKeResumeThread = (ULONG)NewKeResumeThread + g_new_kernel_inc;
	OrigObDuplicateObject = (OBDUPLICATEOBJECT)((ULONG)OrigObDuplicateObject + g_new_kernel_inc);
	ObReferenceObjectByHandle_S = (OBREFERENCEOBJECTBYHANDLE)((ULONG)ObReferenceObjectByHandle + g_new_kernel_inc);
	NewObfDereferenceObject = (ULONG)ObfDereferenceObject + g_new_kernel_inc;
	NewObfReferenceObject = (ULONG)ObfReferenceObject + g_new_kernel_inc;
	ObOpenObjectByPointer_S = (OBOPENOBJECTBYPOINTER)((ULONG)ObOpenObjectByPointer + g_new_kernel_inc);
	ObInsertObject_S = (OBINSERTOBJECT)((ULONG)ObInsertObject + g_new_kernel_inc);
	KeStackAttachProcess_S = (KESTACKATTACHPROCESS)((ULONG)KeStackAttachProcess + g_new_kernel_inc);
	KeUnstackDetachProcess_S = (KEUNSTACKDETACHPROCESS)((ULONG)KeUnstackDetachProcess + g_new_kernel_inc);
	PsLookupProcessByProcessId_S = (PSLOOKUPPROCESSBYPROCESSID)((ULONG)PsLookupProcessByProcessId+g_new_kernel_inc);
	NtProtectVirtualMemory = (NTPROTECTVIRTUALMEMORY)(KeServiceDescriptorTable.ServiceTableBase[215] + g_new_kernel_inc);
	return TRUE;
}

PETHREAD_S PsGetNextProcessThread (
    IN PEPROCESS_S Process,
    IN PETHREAD_S Thread
    )
{
	PETHREAD_S	NewThread;
	PKTHREAD_S	CurrentThread;
	PLIST_ENTRY ListEntry;

	BOOLEAN		bIsGet = FALSE;

//     PLIST_ENTRY ListEntry;
//     PETHREAD_S NewThread, CurrentThread;
// 
//     PAGED_CODE ();
//  
//     CurrentThread = (PETHREAD_S)PsGetCurrentThread ();
// 
// 	//这里我们把此函数简化一下，否则PspLockProcessShared函数涉及的内容实在有点儿多
//     //PspLockProcessShared (Process, CurrentThread);
// 
//     for (ListEntry = (Thread == NULL) ? Process->ThreadListHead.Flink : Thread->ThreadListEntry.Flink;
//          ;
//          ListEntry = ListEntry->Flink) {
//         if (ListEntry != &Process->ThreadListHead) {
//             NewThread = CONTAINING_RECORD (ListEntry, ETHREAD_S, ThreadListEntry);
//             //
//             // Don't reference a thread thats in its delete routine
//             //
//             if (ObReferenceObject (NewThread)) {
//                 break;
//             }
//         } else {
//             NewThread = NULL;
//             break;
//         }
//     }
//     
// 	//PspUnlockProcessShared (Process, CurrentThread);
// 
//     if (Thread != NULL) {
//         ObDereferenceObject (Thread);
//     }
//     return NewThread;

	CurrentThread = (PKTHREAD_S)PsGetCurrentThread();
	KeEnterCriticalRegionThread(CurrentThread);
	ExAcquirePushLockShared(&Process->ProcessLock);

	for (ListEntry = (Thread == NULL) ? Process->ThreadListHead.Flink : Thread->ThreadListEntry.Flink;
		;
		ListEntry = ListEntry->Flink)
	{
		if (ListEntry != &Process->ThreadListHead)
		{
			NewThread = CONTAINING_RECORD (ListEntry, ETHREAD_S, ThreadListEntry);
			if (ObfReferenceObject_S(NewThread))
			{
				bIsGet = TRUE;
				break;
			}
		}else{
			NewThread = NULL;
			break;
		}
	}

	ExReleasePushLockShared(&Process->ProcessLock);
	KeLeaveCriticalRegionThread(CurrentThread);

	if (Thread != NULL)
	{
		ObfDereferenceObject_S(Thread);
	}

	if (!bIsGet)
	{
		NewThread = NULL;
	}

	return NewThread;
}

//这个函数如何逆向win7的有些头痛，因为里面会用到一些不常使用的锁操作，那些操作比较复杂，所以就偷懒直接用wrk的改改了
NTSTATUS
MmGetFileNameForSection (
    IN PSEGMENT_OBJECT SectionObject,
    OUT POBJECT_NAME_INFORMATION *FileNameInfo
    )
{
    ULONG NumberOfBytes;
    ULONG AdditionalLengthNeeded;
    NTSTATUS Status;
    PFILE_OBJECT FileObject;

    NumberOfBytes = 1024;

    *FileNameInfo = NULL;

    if (SectionObject->MmSectionFlags.Image == 0) {
        return STATUS_SECTION_NOT_IMAGE;
    }

    *FileNameInfo = ExAllocatePoolWithTag (PagedPool, NumberOfBytes, '  mM');

    if (*FileNameInfo == NULL) {
        return STATUS_NO_MEMORY;
    }

    FileObject = (PFILE_OBJECT)(SectionObject->ImageCommitment->ControlArea->FilePointer.Value & ~MAX_FAST_REFS);

    Status = ObQueryNameString (FileObject,
                                *FileNameInfo,
                                NumberOfBytes,
                                &AdditionalLengthNeeded);

    if (!NT_SUCCESS (Status)) {

        if (Status == STATUS_INFO_LENGTH_MISMATCH) {

            //
            // Our buffer was not large enough, retry just once with a larger
            // one (as specified by ObQuery).  Don't try more than once to
            // prevent broken parse procedures which give back wrong
            // AdditionalLengthNeeded values from causing problems.
            //

            ExFreePool (*FileNameInfo);

            NumberOfBytes += AdditionalLengthNeeded;

            *FileNameInfo = ExAllocatePoolWithTag (PagedPool,
                                                   NumberOfBytes,
                                                   '  mM');

            if (*FileNameInfo == NULL) {
                return STATUS_NO_MEMORY;
            }

            Status = ObQueryNameString (FileObject,
                                        *FileNameInfo,
                                        NumberOfBytes,
                                        &AdditionalLengthNeeded);

            if (NT_SUCCESS (Status)) {
                return STATUS_SUCCESS;
            }
        }

        ExFreePool (*FileNameInfo);
        *FileNameInfo = NULL;
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
MmGetFileNameForAddress (
    IN PVOID ProcessVa,
    OUT PUNICODE_STRING FileName
    )
{
    PMMVAD Vad;
    PFILE_OBJECT FileObject;
    PCONTROL_AREA ControlArea;
    NTSTATUS Status;
    ULONG RetLen;
    ULONG BufLen;
    PEPROCESS_S Process;
    POBJECT_NAME_INFORMATION FileNameInfo;

    PAGED_CODE ();

    Process = (PEPROCESS_S)PsGetCurrentProcess();

    LOCK_ADDRESS_SPACE (Process);

    Vad = MiLocateAddress (ProcessVa);

    if (Vad == NULL) {

        //
        // No virtual address is allocated at the specified base address,
        // return an error.
        //

        Status = STATUS_INVALID_ADDRESS;
        goto ErrorReturn;
    }

    //
    // Reject private memory.
    //

    if (Vad->u.VadFlags.PrivateMemory == 1) {
        Status = STATUS_SECTION_NOT_IMAGE;
        goto ErrorReturn;
    }

    ControlArea = Vad->Subsection->ControlArea;

    if (ControlArea == NULL) {
        Status = STATUS_SECTION_NOT_IMAGE;
        goto ErrorReturn;
    }

    //
    // Reject non-image sections.
    //

    if (ControlArea->u.Flags == 0) {
        Status = STATUS_SECTION_NOT_IMAGE;
        goto ErrorReturn;
    }

    FileObject = (PFILE_OBJECT)(ControlArea->FilePointer.Value & ~MAX_FAST_REFS);

    ASSERT (FileObject != NULL);

    ObfReferenceObject_S (FileObject);

    UNLOCK_ADDRESS_SPACE (Process);

    //
    // Pick an initial size big enough for most reasonable files.
    //

    BufLen = sizeof (*FileNameInfo) + 1024;

    do {

        FileNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag (PagedPool, BufLen, '  mM');

        if (FileNameInfo == NULL) {
            Status = STATUS_NO_MEMORY;
            break;
        }

        RetLen = 0;

        Status = ObQueryNameString (FileObject, FileNameInfo, BufLen, &RetLen);

        if (NT_SUCCESS (Status)) {
            FileName->Length = FileName->MaximumLength = FileNameInfo->Name.Length;
            FileName->Buffer = (PWCHAR) FileNameInfo;
            RtlMoveMemory (FileName->Buffer, FileNameInfo->Name.Buffer, FileName->Length);
        }
        else {
            ExFreePool (FileNameInfo);
            if (RetLen > BufLen) {
                BufLen = RetLen;
                continue;
            }
        }
        break;

    } while (TRUE);

    ObfDereferenceObject_S (FileObject);
    return Status;

ErrorReturn:

    UNLOCK_ADDRESS_SPACE (Process);
    return Status;
}

ULONG GetAddress(ULONG uAddress,UCHAR *Signature,int flag)
{
	ULONG	index;
	UCHAR	*p;
	ULONG	uRetAddress;

	if(uAddress==0){	return 0;	}

	p = (UCHAR*)uAddress;
	for (index=0;index<0x3000;index++)
	{
		if (*p==Signature[0]&&
			*(p+1)==Signature[1]&&
			*(p+2)==Signature[2]&&
			*(p+3)==Signature[3]&&
			*(p+4)==Signature[4])
		{
			if (flag==0)
			{
				uRetAddress = (ULONG)(p+4) + *(ULONG*)(p+5) + 5;
				return uRetAddress;
			}else if (flag==1)
			{
				uRetAddress = *(ULONG*)(p+5);
				return uRetAddress;
			}else if(flag==2){
				uRetAddress = (ULONG)(p+4);
				return uRetAddress;
			}else if(flag==3){
				uRetAddress = (ULONG)(p+5);
				return uRetAddress;
			}else if(flag==4)
			{
				return (ULONG)p;
			}else{
				return 0;
			}
		}
		p++;
	}
	return 0;
}

ULONG SearchAddressForSign(ULONG uStartBase,ULONG uSearchLength,SIGNATURE_INFO SignatureInfo[5])
{
	UCHAR *p;
	ULONG u_index1,u_index2;

	//ULONG uIndex;
	PIMAGE_DOS_HEADER pimage_dos_header;
	PIMAGE_NT_HEADERS pimage_nt_header;
	PIMAGE_SECTION_HEADER pimage_section_header;

	if(!MmIsAddressValid((PVOID)uStartBase))
	{	return 0;	}

	pimage_dos_header = (PIMAGE_DOS_HEADER)uStartBase;
	pimage_nt_header = (PIMAGE_NT_HEADERS)((ULONG)uStartBase+pimage_dos_header->e_lfanew);
	pimage_section_header = (PIMAGE_SECTION_HEADER)((ULONG)pimage_nt_header+sizeof(IMAGE_NT_HEADERS));

	for (u_index1 = 0;u_index1<pimage_nt_header->FileHeader.NumberOfSections;u_index1++)
	{
		if (pimage_section_header[u_index1].Characteristics&0x60000000)
		{
			//可读可写的段
			//DbgPrint("SectionName:%s----0x%X----0x%X",pSecHeader[uIndex1].Name,\
			//	pSecHeader[uIndex1].Misc.VirtualSize,uStartBase+pSecHeader[uIndex1].VirtualAddress);
			p = (UCHAR*)uStartBase + pimage_section_header[u_index1].VirtualAddress;
			for (u_index2 = 0;u_index2<pimage_section_header[u_index1].Misc.VirtualSize;u_index2++)
			{
				if (!MmIsAddressValid((p-SignatureInfo[0].Offset))||
					!MmIsAddressValid((p-SignatureInfo[4].Offset)))
				{
					p++;
					continue;
				}
				__try{
					if (*(p-SignatureInfo[0].Offset)==SignatureInfo[0].cSingature&&
						*(p-SignatureInfo[1].Offset)==SignatureInfo[1].cSingature&&
						*(p-SignatureInfo[2].Offset)==SignatureInfo[2].cSingature&&
						*(p-SignatureInfo[3].Offset)==SignatureInfo[3].cSingature&&
						*(p-SignatureInfo[4].Offset)==SignatureInfo[4].cSingature)
					{
						return (ULONG)p;
					}

				}__except(EXCEPTION_EXECUTE_HANDLER){
					DbgPrint("Search error!");
				}
				p++;
			}
		}
	}

	return 0;
}

void PageProtectOn()
{
	__asm{//恢复内存保护  
		mov  eax,cr0
		or   eax,10000h
		mov  cr0,eax
		sti
	}
}

void PageProtectOff()
{
	__asm{//去掉内存保护
		cli
		mov  eax,cr0
		and  eax,not 10000h
		mov  cr0,eax
	}
}

PLDR_DATA_TABLE_ENTRY SearchDriver(PDRIVER_OBJECT pDriverObject,wchar_t *strDriverName)
{
	LDR_DATA_TABLE_ENTRY	*pdata_table_entry,*ptemp_data_table_entry;
	PLIST_ENTRY				plist;
	UNICODE_STRING			str_module_name;

	RtlInitUnicodeString(&str_module_name,strDriverName);

	pdata_table_entry = (LDR_DATA_TABLE_ENTRY*)pDriverObject->DriverSection;
	if (!pdata_table_entry)
	{
		return 0;
	}

	plist = pdata_table_entry->InLoadOrderLinks.Flink;

	while(plist!= &pdata_table_entry->InLoadOrderLinks)
	{
		ptemp_data_table_entry = (LDR_DATA_TABLE_ENTRY *)plist;

		//KdPrint(("%wZ",&pTempDataTableEntry->BaseDllName));
		if (0==RtlCompareUnicodeString(&ptemp_data_table_entry->BaseDllName,&str_module_name,FALSE))
		{
			return ptemp_data_table_entry;
		}

		plist = plist->Flink;
	}

	return 0;
}

BOOLEAN	Jmp_HookFunction(
	IN ULONG Destination,
	IN ULONG Source,
	IN UCHAR *Ori_Code
	)
{
	ULONG	jmp_offset;
	UCHAR	jmp_code[5] = {0xE9};

	KSPIN_LOCK lock;
	KIRQL irql;

	if (Destination==0||Source==0)
	{
		DbgPrint("Params error!");
		return FALSE;
	}
	RtlCopyMemory(Ori_Code,(PVOID)Destination,5);
	jmp_offset = Source - Destination-5;
	*(ULONG*)&jmp_code[1] = jmp_offset;

	KeInitializeSpinLock (&lock );
	KeAcquireSpinLock(&lock,&irql);

	PageProtectOff();
	RtlCopyMemory((PVOID)Destination,jmp_code,5);
	PageProtectOn();

	KeReleaseSpinLock (&lock,irql);

	return TRUE;
}

VOID Res_HookFunction(
	IN ULONG	Destination,
	IN UCHAR	*Ori_Code,
	IN ULONG	Length
	)
{
	KSPIN_LOCK lock;
	KIRQL irql;

	if (Destination==0||Ori_Code==0){	return;	}

	/*KeInitializeSpinLock (&lock );
	KeAcquireSpinLock(&lock,&irql);*/

	PageProtectOff();
	RtlCopyMemory((PVOID)Destination,Ori_Code,Length);
	PageProtectOn();

	/*KeReleaseSpinLock (&lock,irql);*/
}

VOID PsCallImageNotifyRoutines(
	IN PUNICODE_STRING ImageName,
	IN HANDLE ProcessId,
	IN PVOID FileObject,
	OUT PIMAGE_INFO_EX ImageInfoEx)
{
	PKTHREAD_S	Thread;
	ULONG	i;
	PLOAD_IMAGE_NOTIFY_ROUTINE Rtn;

	PEX_CALLBACK_ROUTINE_BLOCK	CallBack;

	Thread = (PKTHREAD_S)PsGetCurrentThread();
	KeEnterCriticalRegionThread(Thread);

	/*
	PspNotifyEnableMask是一个系统通知回调是否产生的一个标记
	0位——标记是否产生模块回调。
	3位——标记是否产生线程回调。
	其他位有待分析......
	*/
	if (PspNotifyEnableMask & 0x1)
	{
		ImageInfoEx->Size = sizeof(IMAGE_INFO_EX);
		ImageInfoEx->ImageInfo.ExtendedInfoPresent = TRUE;
		ImageInfoEx->FileObject = (FILE_OBJECT*)FileObject;

		for (i = 0;i<PSP_MAX_LOAD_IMAGE_NOTIFY;i++)
		{
			CallBack = ExReferenceCallBackBlock(&PspLoadImageNotifyRoutine[i]);
			if (CallBack != NULL)
			{
				Rtn = (PLOAD_IMAGE_NOTIFY_ROUTINE)CallBack->Function;
				Rtn(ImageName,
					ProcessId,
					&ImageInfoEx->ImageInfo);
				ExDereferenceCallBackBlock (&PspLoadImageNotifyRoutine[i], CallBack);
			}
		}
	}
	KeLeaveCriticalRegionThread(Thread);

}

PEX_CALLBACK_ROUTINE_BLOCK
	ExReferenceCallBackBlock(
	OUT PEX_CALLBACK CallBack)
{
	PKTHREAD_S CurrentThread;
	EX_FAST_REF OldRef;
	PEX_CALLBACK_ROUTINE_BLOCK CallBackBlock;

	CurrentThread = (PKTHREAD_S)PsGetCurrentThread();

	if (CallBack->RoutineBlock.RefCnt & MAX_FAST_REFS)
	{
		OldRef = ExFastReference(&CallBack->RoutineBlock);
		if (OldRef.Value == 0)
		{
			return NULL;
		}
	}

	if (OldRef.RefCnt == 0)
	{
		return NULL;
	}

	if(!(OldRef.RefCnt & MAX_FAST_REFS))
	{
		KeEnterCriticalRegionThread (CurrentThread);

		ExAcquirePushLockShared(&ExpCallBackFlush);

		CallBackBlock = (PEX_CALLBACK_ROUTINE_BLOCK)(CallBack->RoutineBlock.Value & ~MAX_FAST_REFS);
		if (CallBackBlock && !ExAcquireRundownProtection(&CallBackBlock->RundownProtect))
		{
			CallBackBlock = NULL;
		}

		ExReleasePushLockShared(&ExpCallBackFlush);

		KeLeaveCriticalRegionThread (CurrentThread);

		if (CallBackBlock == NULL) {
			return NULL;
		}
	}else{
		CallBackBlock = (PEX_CALLBACK_ROUTINE_BLOCK)(OldRef.Value & ~MAX_FAST_REFS);

		if (OldRef.RefCnt == 1 &&
			ExAcquireRundownProtectionEx(&CallBackBlock->RundownProtect,MAX_FAST_REFS))
		{
			if (!ExFastRefAddAdditionalReferenceCounts (&CallBack->RoutineBlock,
				CallBackBlock,
				MAX_FAST_REFS)) {
					ExReleaseRundownProtectionEx (&CallBackBlock->RundownProtect,
						MAX_FAST_REFS);
			}
		}
	}

	return CallBackBlock;
}

VOID ExDereferenceCallBackBlock (
	IN OUT PEX_CALLBACK CallBack,
	IN PEX_CALLBACK_ROUTINE_BLOCK CallBackBlock
	)
{
	if (!ExFastRefDereference (&CallBack->RoutineBlock, CallBackBlock)) {
		ExReleaseRundownProtection (&CallBackBlock->RundownProtect);
	}
}

LOGICAL
ExFastRefDereference (
    __inout PEX_FAST_REF FastRef,
    __in PVOID Object
    )
{
    EX_FAST_REF OldRef, NewRef;

    while (1) {

        OldRef = ReadForWriteAccess(FastRef);

        if ((OldRef.Value^(ULONG_PTR)Object) >= MAX_FAST_REFS) {
            return FALSE;
        }

        NewRef.Value = OldRef.Value + 1;
        NewRef.Object = InterlockedCompareExchangePointerRelease (&FastRef->Object,
                                                                  NewRef.Object,
                                                                  OldRef.Object);
        if (NewRef.Object != OldRef.Object) {
            continue;
        }
        break;
    }
    return TRUE;
}

EX_FAST_REF
ExFastReference (
    __inout PEX_FAST_REF FastRef
    )
{
	EX_FAST_REF OldRef, NewRef;

	while (1) {
        
		OldRef = ReadForWriteAccess(FastRef);
        
		if (OldRef.RefCnt != 0) {
			NewRef.Value = OldRef.Value - 1;
			NewRef.Object = InterlockedCompareExchangePointerAcquire (
				&FastRef->Object,
				NewRef.Object,
				OldRef.Object);
			if (NewRef.Object != OldRef.Object) {
				continue;
			}
		}
		break;
	}

	return OldRef;
}

VOID __stdcall
	ExfAcquirePushLockShared_S (
	IN PEX_PUSH_LOCK_S PushLock
	)
{
	__asm{
		push	ecx
		mov		ecx,PushLock
		call	ExfAcquirePushLockShared
		pop		ecx
	}
}

VOID
ExAcquirePushLockShared (
     IN PEX_PUSH_LOCK_S PushLock
     )
{
	if (InterlockedCompareExchangePointer (&PushLock->Ptr,
		(PVOID)(EX_PUSH_LOCK_SHARE_INC|EX_PUSH_LOCK_LOCK),
		NULL) != NULL) {
			ExfAcquirePushLockShared_S (PushLock);
	}
}

VOID
	ExfReleasePushLockShared_S (
	IN PEX_PUSH_LOCK_S PushLock
	)
{
	__asm{
		push	ecx
		mov		ecx,PushLock
		call	ExfReleasePushLockShared
		pop		ecx
	}
}

VOID
ExReleasePushLockShared (
     IN PEX_PUSH_LOCK_S PushLock
     )
{
    EX_PUSH_LOCK_S OldValue, NewValue;

    OldValue.Value = EX_PUSH_LOCK_SHARE_INC|EX_PUSH_LOCK_LOCK;
    NewValue.Value = 0;

    if (InterlockedCompareExchangePointer (&PushLock->Ptr,
                                           NewValue.Ptr,
                                           OldValue.Ptr) != OldValue.Ptr) {
        ExfReleasePushLockShared_S (PushLock);
    }
}

VOID
KeEnterCriticalRegionThread (
    PKTHREAD_S Thread
    )
{
    Thread->KernelApcDisable -= 1;
    return;
}

VOID
KeLeaveCriticalRegionThread (
    IN PKTHREAD_S Thread
    )
{
    if ((Thread->KernelApcDisable += 1) == 0) {
        if (Thread->ApcState.ApcListHead[KernelMode].Flink !=         
                                &Thread->ApcState.ApcListHead[KernelMode]) {

            if (Thread->SpecialApcDisable == 0) {
                KiCheckForKernelApcDelivery();
            }
        }                                                               
    }
    return;
}


LOGICAL
ExFastRefAddAdditionalReferenceCounts (
    __inout PEX_FAST_REF FastRef,
    __in PVOID Object,
    __in ULONG RefsToAdd
    )
{
    EX_FAST_REF OldRef, NewRef;

    while (1) {
        OldRef = ReadForWriteAccess(FastRef);

        if (OldRef.RefCnt + RefsToAdd > MAX_FAST_REFS ||
            (ULONG_PTR) Object != (OldRef.Value & ~MAX_FAST_REFS)) {
            return FALSE;
        }

        NewRef.Value = OldRef.Value + RefsToAdd;
        NewRef.Object = InterlockedCompareExchangePointerAcquire (&FastRef->Object,
                                                                  NewRef.Object,
                                                                  OldRef.Object);
        if (NewRef.Object != OldRef.Object) {
            continue;
        }
        break;
    }
    return TRUE;
}

PVOID
ObFastReferenceObject (
    IN PEX_FAST_REF FastRef
    )
{
    EX_FAST_REF OldRef;
    PVOID Object;
    ULONG RefsToAdd, Unused;

    OldRef = ExFastReference (FastRef);

    Object = (PVOID)(OldRef.Value & (~MAX_FAST_REFS));

    Unused = OldRef.RefCnt;

    if (Unused <= 1) {
        if (Unused == 0) {
            return NULL;
        }

        RefsToAdd = MAX_FAST_REFS;
        ObfReferenceObject_S (Object);

        if (!ExFastRefAddAdditionalReferenceCounts (FastRef, Object, RefsToAdd)) {
            ObfDereferenceObject_S (Object);
        }
    }
    return Object;
}

VOID
ObFastDereferenceObject (
    IN PEX_FAST_REF FastRef,
    IN PVOID Object
    )
{
    if (!ExFastRefDereference (FastRef, Object)) {
        ObfDereferenceObject_S (Object);
    }
}

PVOID
ObFastReferenceObjectLocked (
    IN PEX_FAST_REF FastRef
    )
{
    PVOID Object;
    EX_FAST_REF OldRef;

    OldRef = *FastRef;
    Object = (PVOID)(OldRef.Value & ~MAX_FAST_REFS);
    if (Object != NULL) {
        ObfReferenceObject_S (Object);
    }
    return Object;
}

PFILE_OBJECT
	MmGetFileObjectForSection (
	IN PSEGMENT_OBJECT Section
	)
{
	PFILE_OBJECT FileObject;
	FileObject = (PFILE_OBJECT)ObFastReferenceObject(\
		&Section->ImageCommitment->ControlArea->FilePointer);

	if (FileObject == NULL)
	{
		FileObject = MiReferenceControlAreaFile(Section->ImageCommitment->ControlArea);
	}
	return FileObject;
}

PFILE_OBJECT
	MiReferenceControlAreaFile(
	PCONTROL_AREA CtrlArea)
{
	PKTHREAD_S	CurrentThread;
	PFILE_OBJECT FileObject;

	CurrentThread = (PKTHREAD_S)PsGetCurrentThread();
	KeEnterCriticalRegionThread(CurrentThread);

	ExAcquirePushLockShared(&MiChangeControlAreaFileLock);

	((PETHREAD_S)CurrentThread)->OwnsChangeControlAreaShared = TRUE;
	FileObject = (PFILE_OBJECT)ObFastReferenceObjectLocked(&CtrlArea->FilePointer);
	((PETHREAD_S)CurrentThread)->OwnsChangeControlAreaShared = FALSE;

	ExReleasePushLockShared(&MiChangeControlAreaFileLock);

	KeLeaveCriticalRegionThread(CurrentThread);

	return FileObject;
}

TABLE_SEARCH_RESULT
MiFindNodeOrParent (
    IN PMM_AVL_TABLE Table,
    IN ULONG_PTR StartingVpn,
    OUT PMMADDRESS_NODE *NodeOrParent
    )
{
#if DBG
    ULONG NumberCompares = 0;
#endif
    PMMADDRESS_NODE Child;
    PMMADDRESS_NODE NodeToExamine;

    if (Table->NumberGenericTableElements == 0) {
        return TableEmptyTree;
    }

    NodeToExamine = (PMMADDRESS_NODE) Table->BalancedRoot.RightChild;

    do {

        //
        // Make sure the depth of tree is correct.
        //

        ASSERT(++NumberCompares <= Table->DepthOfTree);

        //
        // Compare the buffer with the key in the tree element.
        //

        if (StartingVpn < NodeToExamine->StartingVpn) {

            Child = NodeToExamine->LeftChild;

            if (Child != NULL) {
                NodeToExamine = Child;
            }
            else {

                //
                // Node is not in the tree.  Set the output
                // parameter to point to what would be its
                // parent and return which child it would be.
                //

                *NodeOrParent = NodeToExamine;
                return TableInsertAsLeft;
            }
        }
        else if (StartingVpn <= NodeToExamine->EndingVpn) {

            //
            // This is the node.
            //

            *NodeOrParent = NodeToExamine;
            return TableFoundNode;
        }
        else {

            Child = NodeToExamine->RightChild;

            if (Child != NULL) {
                NodeToExamine = Child;
            }
            else {

                //
                // Node is not in the tree.  Set the output
                // parameter to point to what would be its
                // parent and return which child it would be.
                //

                *NodeOrParent = NodeToExamine;
                return TableInsertAsRight;
            }
        }

    } while (TRUE);
}

PMMVAD
FASTCALL
MiLocateAddress (
    IN PVOID VirtualAddress
    )

/*++

Routine Description:

    The function locates the virtual address descriptor which describes
    a given address.

Arguments:

    VirtualAddress - Supplies the virtual address to locate a descriptor for.

    Table - Supplies the table describing the tree.

Return Value:

    Returns a pointer to the virtual address descriptor which contains
    the supplied virtual address or NULL if none was located.

--*/

{
    PMMVAD FoundVad;
    ULONG_PTR Vpn;
    PMM_AVL_TABLE Table;
    TABLE_SEARCH_RESULT SearchResult;

    Table = &((PEPROCESS_S)PsGetCurrentProcess ())->VadRoot;

    //
    // Note the NodeHint *MUST* be captured locally - see the synchronization
    // comment below for details.
    //

    FoundVad = (PMMVAD) Table->NodeHint;

    if (FoundVad == NULL) {
        return NULL;
    }

    Vpn = MI_VA_TO_VPN (VirtualAddress);

    if ((Vpn >= FoundVad->StartingVpn) && (Vpn <= FoundVad->EndingVpn)) {
        return FoundVad;
    }

    //
    // Lookup the element and save the result.
    //

    SearchResult = MiFindNodeOrParent (Table,
                                       Vpn,
                                       (PMMADDRESS_NODE *) &FoundVad);

    if (SearchResult != TableFoundNode) {
        return NULL;
    }

    ASSERT (FoundVad != NULL);

    ASSERT ((Vpn >= FoundVad->StartingVpn) && (Vpn <= FoundVad->EndingVpn));

    //
    // Note the NodeHint field update is not synchronized in all cases, ie:
    // some callers hold the address space mutex and others hold the working
    // set pushlock.  It is ok that the update is not synchronized - as long
    // as care is taken above that it is read into a local variable and then
    // referenced.  Because no VAD can be removed from the tree without holding
    // both the address space & working set.
    //

    Table->NodeHint = (PVOID) FoundVad;

    //
    // Return the VAD.
    //

    return FoundVad;
}

BOOLEAN
MmCheckForSafeExecution (
    IN PVOID InstructionPointer,
    IN PVOID StackPointer,
    IN PVOID BranchTarget,
    IN BOOLEAN PermitStackExecution
    )

/*++

Routine Description:

    This routine compares two virtual addresses (Va1 and Va2) to determine whether they
    fall within the same VAD in the current process or the target address (Va3) falls
    inside an image file.

Arguments:

    InstructionPointer - Supplies the address of the "thunk" to execute

    StackPointer - Supplies the stack pointer at the time of thunk execution.
    
    BranchTarget - Supplies the calculated target address of the thunk.

    PermitStackExecution - Indicates whether the thunk may reside on the
        stack.

Return Value:

    Returns TRUE if execution of the thunk is permitted, FALSE otherwise.

Environment:

    PASSIVE_LEVEL, arbitrary thread context.  Address space lock not taken.

--*/

{
    PEPROCESS_S CurrentProcess;
    BOOLEAN RetValue;
    PMMVAD InstructionVad;
    PMMVAD StackVad;
    PMMVAD TargetVad;

    UNREFERENCED_PARAMETER (InstructionPointer);
    UNREFERENCED_PARAMETER (StackPointer);

    CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess ();
    RetValue = TRUE;

    ExAcquirePushLockShared (&CurrentProcess->AddressCreationLock);

    if (PermitStackExecution == FALSE) {

        //
        // Ensure that the instruction pointer does not refer to the
        // same VAD as the stack pointer.
        //
        // And that the instruction pointer does not reside in an
        // image section.
        //

        InstructionVad = MiLocateAddress (InstructionPointer);
        StackVad = MiLocateAddress (StackPointer);

        if ((InstructionVad == NULL) ||
            (StackVad == NULL) ||
            (InstructionVad == StackVad) ||
            (InstructionVad->u.VadFlags.VadType == VadImageMap)) {

            RetValue = FALSE;
        }
    }

    if (RetValue != FALSE) {

        //
        // Ensure that the branch target is backed by an image section.
        //
            
        TargetVad = MiLocateAddress (BranchTarget);
        if (TargetVad == NULL ||
            TargetVad->u.VadFlags.VadType != VadImageMap) {

            RetValue = FALSE;
        }
    }

    ExReleasePushLockShared(&CurrentProcess->AddressCreationLock);

    return RetValue;
}

LOGICAL
KiEmulateAtlThunk (
    IN OUT ULONG *InstructionPointer,
    IN OUT ULONG *StackPointer,
    IN OUT ULONG *Eax,
    IN OUT ULONG *Ecx,
    IN OUT ULONG *Edx
    )

/*++

Routine Description:

    This routine is called to determine whether the 32-bit X86 IStream
    contains a recognized ATL thunk sequence and if so, performs
    the emulation.

Arguments:

    InstructionPointer - Supplies a pointer to the value of the 32-bit
        instruction pointer at the time of the fault.

    StackPointer - Supplies a pointer to the value of the 32-bit stack
        pointer at the time of the fault.

    Ecx - Supplies a pointer to the value of ecx at the time of the fault.

    Edx - Supplies a pointer to the value of edx at the time of the fault.

Return Value:

    Returns TRUE if an ATL thunk was recognized and emulated, FALSE if not.


    It is up to the caller to first ensure:

    - The fault occured while executing 32-bit code
    - The fault occured as a result of attempting to execute NX code

--*/

{
    LONG branchTarget;
    LONG imm32;
    PVOID rip;
    PUCHAR rsp;
    BOOLEAN safeThunkCall;
    BOOLEAN *safeThunkCallPtr;
    LOGICAL validThunk;

    //
    // Three types of ATL thunks of interest
    //

    #pragma pack(1)

    struct {
        LONG Mov;           // 0x042444C7   mov [esp+4], imm32
        LONG MovImmediate;
        UCHAR Jmp;          // 0xe9         jmp imm32
        LONG JmpImmediate;
    } *thunk1;

    struct {
        UCHAR Mov;          // 0xb9         mov ecx, imm32
        LONG EcxImmediate;
        UCHAR Jmp;          // 0xe9         jmp imm32
        LONG JmpImmediate;
    } *thunk2;

    struct {
        UCHAR MovEdx;       // 0xba         mov edx, imm32
        LONG EdxImmediate;
        UCHAR MovEcx;       // 0xb9         mov ecx, imm32
        LONG EcxImmediate;
        USHORT JmpEcx;      // 0xe1ff       jmp ecx
    } *thunk3;

    struct {
        UCHAR MovEcx;       // 0xb9         mov ecx, imm32
        LONG EcxImmediate;
        UCHAR MovEax;       // 0xb8         mov eax, imm32
        LONG EaxImmediate;
        USHORT JmpEax;      // 0xe0ff       jmp eax
    } *thunk4;

    struct {
        UCHAR PopEcx;       // 0x59
        UCHAR PopEax;       // 0x58
        UCHAR PushEcx;      // 0x51
        UCHAR Jmp[3];       // 0xFF 0x60 0x04   jmp [eax+4]
    } *thunk7;

    #pragma pack()

    rip = UlongToPtr(*InstructionPointer);
    rsp = UlongToPtr(*StackPointer);

    thunk1 = rip;
    thunk2 = rip;
    thunk3 = rip;
    thunk4 = rip;
    thunk7 = rip;

    validThunk = FALSE;

    //
    // If thunk emulation is disabled, then do not attempt to emulate any
    // thunks.
    //

    if (KiQueryNxThunkEmulationState() != 0) {
        return FALSE;
    }

    //
    // Carefully examine the instruction stream.  If it matches a known
    // ATL thunk template, then emulate it.
    //

    try {
        ProbeAndReadUchar((PUCHAR)rip);

        safeThunkCall = *safeThunkCallPtr;
        if (safeThunkCall != FALSE) {
            *safeThunkCallPtr = FALSE;
        }

        if ((thunk1->Mov == 0x042444C7) && (thunk1->Jmp == 0xe9)) {

            //
            // Type 1 thunk.
            //

            //
            // emulate: jmp imm32
            //

            imm32 = thunk1->JmpImmediate +
                    PtrToUlong(rip) +
                    sizeof(*thunk1);

            //
            // Determine if it is safe to emulate this code stream.
            //

            if ((MmCheckForSafeExecution (rip,
                                          rsp,
                                          UlongToPtr (imm32),
                                          TRUE) == FALSE) ||
                (safeThunkCall == FALSE)) {
                goto Done;
            }
            
            //
            // emulate: mov [esp+4], imm32
            // 

            ProbeAndWriteUlong((PULONG)(rsp+4), thunk1->MovImmediate);
            *InstructionPointer = imm32;
            validThunk = TRUE;

        } else if ((thunk2->Mov == 0xb9) && (thunk2->Jmp == 0xe9)) {

            //
            // Type 2 thunk.
            //

            //
            // emulate: jmp imm32
            //

            imm32 = thunk2->JmpImmediate +
                    PtrToUlong(rip) +
                    sizeof(*thunk2);

            //
            // Determine if it is safe to emulate this code stream.
            //

            if ((MmCheckForSafeExecution (rip,
                                          rsp,
                                          UlongToPtr (imm32),
                                          TRUE) == FALSE) ||
                (safeThunkCall == FALSE)) {
                goto Done;
            }

            //
            // emulate: mov ecx, imm32
            //

            *Ecx = thunk2->EcxImmediate;


            *InstructionPointer = imm32;
            validThunk = TRUE;

        } else if ((thunk3->MovEdx == 0xba) &&
                   (thunk3->MovEcx == 0xb9) &&
                   (thunk3->JmpEcx == 0xe1ff)) {

            //
            // Type 3 thunk.
            //

            //
            // emulate: mov ecx, imm32
            //

            imm32 = thunk3->EcxImmediate;

            //
            // Determine if it is safe to emulate this code stream.
            //

            if (MmCheckForSafeExecution (rip,
                                         rsp,
                                         UlongToPtr (imm32),
                                         FALSE) == FALSE) {
                goto Done;
            }

            //
            // emulate: mov edx, imm32
            //

            *Edx = thunk3->EdxImmediate;

            *Ecx = imm32;

            //
            // emulate: jmp ecx
            //

            *InstructionPointer = imm32;
            validThunk = TRUE;

        } else if ((thunk4->MovEcx == 0xb9) &&
                   (thunk4->MovEax == 0xb8) &&
                   (thunk4->JmpEax == 0xe0ff)) {

            //
            // Type 4 thunk
            //
            
            //
            // emulate: mov eax, imm32
            //

            imm32 = thunk4->EaxImmediate;

            //
            // Determine if it is safe to emulate this code stream.
            //

            if ((MmCheckForSafeExecution (rip,
                                          rsp,
                                          UlongToPtr (imm32),
                                          TRUE) == FALSE) ||
                (safeThunkCall == FALSE)) {
                goto Done;
            }

            //
            // emulate: mov ecx, imm32
            //

            *Ecx = thunk4->EcxImmediate;

            *Eax = imm32;

            //
            // emulate: jmp eax
            //

            *InstructionPointer = imm32;
            validThunk = TRUE;

        } else if (thunk7->PopEcx == 0x59 &&
                   thunk7->PopEax == 0x58 &&
                   thunk7->PushEcx == 0x51 &&
                   thunk7->Jmp[0] == 0xFF &&
                   thunk7->Jmp[1] == 0x60 &&
                   thunk7->Jmp[2] == 0x04) {

            //
            // Type 7 thunk
            //
            // This is used by VB6
            //

            //
            // First determine and validate the branch target
            //

            imm32 = ProbeAndReadUlong((PULONG)(rsp+4));
            branchTarget = ProbeAndReadUlong((PULONG)(UlongToPtr(imm32+4)));

            //
            // Determine if it is safe to emulate this code stream.
            //

            if (MmCheckForSafeExecution(rip,
                                        rsp,
                                        UlongToPtr(branchTarget),
                                        FALSE) == FALSE) {
                goto Done;
            }

            //
            // Emulate: pop ecx
            //

            *Ecx = *(PULONG)rsp;
            rsp += 4;

            //
            // Emulate: pop eax
            //          push ecx
            //

            *Eax = *(PULONG)rsp;
            *(PULONG)rsp = *Ecx;

            //
            // Emulate: jmp [eax+4]
            //

            *InstructionPointer = branchTarget;
            *StackPointer = PtrToUlong(rsp);
            validThunk = TRUE;
        }

    } except (EXCEPTION_EXECUTE_HANDLER) {
        NOTHING;
    }

Done:
    return validThunk;
}

BOOLEAN KiCheckForAtlThunk(
	PEXCEPTION_RECORD ExceptionRecord,		//edx
	PCONTEXT	Context						//eax
	)
{
	ULONG faultIndicator;

	//
	// Interested only in an instruction fetch fault.
	// 

	faultIndicator = ExceptionRecord->ExceptionInformation[0];
	if ((faultIndicator & 0x8) == 0) {
		return FALSE;
	}

	//
	// Where the fault address is the instruction
	// 

	if (ExceptionRecord->ExceptionInformation[1] != Context->Eip) {
		return FALSE;
	}

	if (KiEmulateAtlThunk(&Context->Eip,
		&Context->Esp,
		&Context->Eax,
		&Context->Ecx,
		&Context->Edx)) {

			return TRUE;
	} else {
		return FALSE;
	}
}

ULONG GetDriverDataEntry(
	PDRIVER_OBJECT pDriverObj,
	wchar_t *szFileName
	)
{
	UNICODE_STRING	usFileName;
	PMODULE_ENTRY pStart_Entry,pCurrent_Entry;
	if (!MmIsAddressValid(pDriverObj)||
		!MmIsAddressValid(szFileName))
	{
		DbgPrint("Error:param is null.");
		return 0;
	}
	RtlInitUnicodeString(&usFileName,szFileName);
	pStart_Entry = pCurrent_Entry = (PMODULE_ENTRY)pDriverObj->DriverSection;
	while((PMODULE_ENTRY)pCurrent_Entry->le_mod.Flink!=pStart_Entry)
	{
		if(0==RtlCompareUnicodeString(&usFileName,&pCurrent_Entry->driver_Name,FALSE))
		{
			return (ULONG)pCurrent_Entry;
		}
		//DbgPrint("%wZ",&pCurrent_Entry->driver_Name);
		pCurrent_Entry = (PMODULE_ENTRY)pCurrent_Entry->le_mod.Flink;
	}
	return 0;
}

VOID
ProbeForWriteSmallStructure (
    IN PVOID Address,
    IN SIZE_T Size,
    IN ULONG Alignment
    )
{

    ASSERT((Alignment == 1) || (Alignment == 2) ||
           (Alignment == 4) || (Alignment == 8) ||
           (Alignment == 16));

    if ((Size == 0) || (Size >= 0x1000)) {

        ASSERT(0);

        ProbeForWrite(Address, Size, Alignment);

    } else {
        if (((ULONG_PTR)(Address) & (Alignment - 1)) != 0) {
            ExRaiseDatatypeMisalignment();
        }

#if defined(_AMD64_)

        if ((ULONG_PTR)(Address) >= (ULONG_PTR)MM_USER_PROBE_ADDRESS) {
             Address = (UCHAR * const)MM_USER_PROBE_ADDRESS;
        }
    
        ((volatile UCHAR *)(Address))[0] = ((volatile UCHAR *)(Address))[0];
        ((volatile UCHAR *)(Address))[Size - 1] = ((volatile UCHAR *)(Address))[Size - 1];

#else

        if ((ULONG_PTR)(Address) >= (ULONG_PTR)MM_USER_PROBE_ADDRESS) {
             *((volatile UCHAR * const)MM_USER_PROBE_ADDRESS) = 0;
        }
    
        *(volatile UCHAR *)(Address) = *(volatile UCHAR *)(Address);
        if (Size > Alignment) {
            ((volatile UCHAR *)(Address))[(Size - 1) & ~(SIZE_T)(Alignment - 1)] =
                ((volatile UCHAR *)(Address))[(Size - 1) & ~(SIZE_T)(Alignment - 1)];
        }

#endif

    }
}

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
	)
{
	NTSTATUS	status;
	__asm{
		push		ecx
		
		xor			eax,eax
		mov			al,PreviousMode
		push		eax
		push		Options
		push		HandleAttributes
		push		DesiredAccess
		push		TargetHandle
		push		TargetProcess
		push		SourceHandle
		mov			ecx,SourceProcess
		call		OrigObDuplicateObject
		pop			ecx
		mov			status,eax
	}

	return status;
}

PVOID PsCaptureExceptionPort(
	IN PEPROCESS_S Process)
{
	PKTHREAD_S	Thread;
	PVOID		ExceptionPort;

	Thread = (PKTHREAD_S)PsGetCurrentThread();
	ExceptionPort = Process->ExceptionPortData;
	if (ExceptionPort != NULL)
	{
		KeEnterCriticalRegionThread(Thread);
		ExAcquirePushLockShared(&Process->ProcessLock);
		ExceptionPort = (PVOID)((ULONG)ExceptionPort & ~0x7);
		ObfReferenceObject_S(ExceptionPort);
		ExReleasePushLockShared(&Process->ProcessLock);

		KeLeaveCriticalRegionThread(Thread);
	}

	return ExceptionPort;
}

NTSTATUS GetModuleByName(char *szModuleName,PSYSTEM_MODULE ImageInfo)
{	
	NTSTATUS	status;
	UNICODE_STRING	usQueryFunc;

	ULONG count;
	ULONG BufferSize=0;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation=NULL;
	PSYSTEM_MODULE pSystemModule=NULL;

	ZWQUERYSYSTEMINFORMATION	ZwQuerySystemInformation = NULL;

	status = STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&usQueryFunc,L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&usQueryFunc);
	if (ZwQuerySystemInformation == NULL)
	{
		return status;
	}

	status = ZwQuerySystemInformation(SystemModuleInformationClass,NULL,0,&BufferSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return status;
	}

	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool,BufferSize);
	if (pSystemModuleInformation == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformationClass,pSystemModuleInformation,BufferSize,&BufferSize);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pSystemModuleInformation);
		return status;
	}

	status = STATUS_UNSUCCESSFUL;
	pSystemModule=pSystemModuleInformation->Module;
	for(count=0;count<pSystemModuleInformation->ModuleCount;count++)
	{
		if (strstr(_strupr(pSystemModule[count].ImageName),_strupr(szModuleName)) != 0)
		{
			try{
				*ImageInfo = pSystemModule[count];
			}except(EXCEPTION_EXECUTE_HANDLER){
				break;
			}

			status = STATUS_SUCCESS;
			break;
		}
	}

	ExFreePool(pSystemModuleInformation);
	return status;
}

LONG_PTR __stdcall ObfDereferenceObject_S(
    __in PVOID Object)
{
	LONG_PTR	RetV;

	__asm{
		pushad

		mov		ecx,Object
		call	NewObfDereferenceObject
		mov		RetV,eax
		popad
	}

	return RetV;
}

LONG_PTR __stdcall ObfReferenceObject_S(
    __in PVOID Object
    )
{
	LONG_PTR	RetV;

	__asm{
		pushad

		mov		ecx,Object
		call	NewObfReferenceObject
		mov		RetV,eax
		popad
	}

	return RetV;
}

NTSTATUS __stdcall KeResumeThread(
	__inout PETHREAD_S Thread)
{
	NTSTATUS status;

	__asm{
		pushad

		mov		eax,Thread
		call	NewKeResumeThread
		mov		status,eax

		popad
	}

	return status;
}

ULONG SearchProcessById(ULONG ProcessId)
{
	ULONG pEprocess,LastProcess;
	ULONG Current_Pid;
	ULONG Start_Pid;
	int	  index;
	PLIST_ENTRY pList_Active_Process;

	if (ProcessId == 0)
		return 0;

	index = 0;

	pEprocess = (ULONG)PsGetCurrentProcess();
	Start_Pid = *(ULONG*)(pEprocess+PROCESSID_OFFSET);
	Current_Pid = Start_Pid;

	while(TRUE)
	{
		LastProcess = pEprocess;
		pList_Active_Process = (PLIST_ENTRY)(pEprocess+PROCESSLIST_OFFSET);
		pEprocess = (ULONG)pList_Active_Process->Flink;
		pEprocess = pEprocess - PROCESSLIST_OFFSET;
		Current_Pid = *(ULONG*)(pEprocess+PROCESSID_OFFSET);

		if ((Current_Pid==Start_Pid)&&index>0)
		{
			return 0;
		}else if (ProcessId == Current_Pid)
		{
			return pEprocess;
		}
		index++;
	}
	return 0;
}

ULONG SearchProcess(char *szProcessName)
{
	ULONG pEprocess,LastProcess;
	ULONG Current_Pid;
	ULONG Start_Pid;
	int	  index;
	PLIST_ENTRY pList_Active_Process;

	if (!MmIsAddressValid(szProcessName))
		return 0;

	index = 0;

	pEprocess = (ULONG)PsGetCurrentProcess();
	Start_Pid = *(ULONG*)(pEprocess+PROCESSID_OFFSET);
	Current_Pid = Start_Pid;

	while(TRUE)
	{
		LastProcess = pEprocess;
		pList_Active_Process = (PLIST_ENTRY)(pEprocess+PROCESSLIST_OFFSET);
		pEprocess = (ULONG)pList_Active_Process->Flink;
		pEprocess = pEprocess - PROCESSLIST_OFFSET;
		Current_Pid = *(ULONG*)(pEprocess+PROCESSID_OFFSET);

		if ((Current_Pid==Start_Pid)&&index>0)
		{
			return 0;
		}else if (strstr((char*)LastProcess+0x16c,szProcessName)!=0)
		{
			return pEprocess;
		}
		index++;
	}
	return 0;
}

//////////////////////////////////////////////////////////////////////////

VOID log_filter(char *sz_log)
{
	NTSTATUS				status;
	UNICODE_STRING			us_file_name;

	HANDLE					hfile;
	OBJECT_ATTRIBUTES		object_attr;
	IO_STATUS_BLOCK			io_stack_block;

	FILE_STANDARD_INFORMATION	file_standard_info;

	static FAST_MUTEX		write_fast_mutex;
	static BOOLEAN			is_init_lock = FALSE;
	if (is_init_lock==FALSE)
	{
		is_init_lock = TRUE;
		ExInitializeFastMutex(&write_fast_mutex);
	}

	ExAcquireFastMutex(&write_fast_mutex);

	do 
	{
		//在这里为了方便，我直接把日志写入这个文件
		RtlInitUnicodeString(&us_file_name,L"\\??\\c:\\filter.log");

		memset(&object_attr,0,sizeof(OBJECT_ATTRIBUTES));
		InitializeObjectAttributes(&object_attr,&us_file_name,OBJ_CASE_INSENSITIVE,NULL,NULL);


		status = ZwCreateFile(
			&hfile,
			GENERIC_ALL,
			&object_attr,
			&io_stack_block,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN_IF,
			FILE_NON_DIRECTORY_FILE,
			NULL,
			0);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = ZwQueryInformationFile(hfile,&io_stack_block,&file_standard_info,sizeof(FILE_STANDARD_INFORMATION),FileStandardInformation);
		if (!NT_SUCCESS(status))
		{
			ZwClose(hfile);
			break;
		}

		KdPrint(("strlen(sz_log):%s",sz_log));

		ZwWriteFile(hfile,NULL,NULL,NULL,&io_stack_block,sz_log,strlen(sz_log),&file_standard_info.EndOfFile,NULL);

		ZwClose(hfile);

	} while (0);

	ExReleaseFastMutex(&write_fast_mutex);
}

void TrapRecord(PKTRAP_FRAME_S kTrapFrame)
{
	char	szBuffer[500];
	strcpy(szBuffer,"111111111111111111111111111111111111111111111111111111111111111111");
	sprintf(szBuffer,
		"DbgEbp					:%X\n\
		 DbgEip					:%X\n\
		 DbgArgMark				:%X\n\
		 DbgArgPointer			:%X\n\
		 TempSegCs				:%X\n\
		 Logging				:%X\n\
		 Reserved				:%X\n\
		 TempEsp				:%X\n\
		 Dr0					:%X\n\
		 Dr1					:%X\n\
		 Dr2					:%X\n\
		 Dr3					:%X\n\
		 Dr6					:%X\n\
		 Dr7					:%X\n\
		 SegGs					:%X\n\
		 SegEs					:%X\n\
		 SegDs					:%X\n\
		 Edx					:%X\n\
		 Ecx					:%X\n\
		 Eax					:%X\n\
		 PreviousPreviousMode	:%X\n\
		 SegFs					:%X\n\
		 Edi					:%X\n\
		 Esi					:%X\n\
		 Ebx					:%X\n\
		 Ebp					:%X\n\
		 ErrCode				:%X\n\
		 Eip					:%X\n\
		 SegCs					:%X\n\
		 EFlags					:%X\n",
		 kTrapFrame->DbgEbp,kTrapFrame->DbgEip,kTrapFrame->DbgArgMark,
		 kTrapFrame->DbgArgPointer,kTrapFrame->TempSegCs,kTrapFrame->Logging,
		 kTrapFrame->Reserved,kTrapFrame->TempEsp,kTrapFrame->Dr0,
		 kTrapFrame->Dr1,kTrapFrame->Dr2,kTrapFrame->Dr3,kTrapFrame->Dr6,
		 kTrapFrame->Dr7,kTrapFrame->SegGs,kTrapFrame->SegEs,
		 kTrapFrame->SegDs,kTrapFrame->Edx,kTrapFrame->Ecx,kTrapFrame->Eax,
		 kTrapFrame->PreviousPreviousMode,kTrapFrame->SegFs,
		 kTrapFrame->Edi,kTrapFrame->Esi,kTrapFrame->Ebx,
		 kTrapFrame->Ebp,kTrapFrame->ErrCode,kTrapFrame->Eip,
		 kTrapFrame->SegCs,kTrapFrame->EFlags);

	log_filter(szBuffer);
}