#include "kExceptSys.h"
#include "intsafe.h"
/*
NTSTATUS RtlpValidateContextFlags(
	IN ULONG Flag,
	OUT PULONG Validate)
{
	int	index;

	if (!(Flag & 0x10000) || (Flag & 0xFFFEFF80))
	{
		if (!(Flag & 0x100000) || (Flag & 0x27EFFFA0))
		{
			if (!(Flag & 0x80000) || (Flag & 0x27F7FFC0))
			{
				return STATUS_INVALID_PARAMETER;
			}
		}
	}

	index = 0x1;

	if ((Flag & 0x10040) == 0x10040 ||
		(Flag & 0x100040) == 0x100040)
	{
		if (((g_lpUserSharedData->XState.EnabledFeatures.LowPart&(~0x3)) | 
			g_lpUserSharedData->XState.EnabledFeatures.HighPart) == 0)
		{
			return STATUS_NOT_SUPPORTED;
		}else{
			index = 0x3;
		}
	}

	if (Validate != NULL)
	{
		*Validate = index;
	}

	return STATUS_SUCCESS;
}

//获取扩展Context结构的长度
VOID RtlGetExtendedContextLength(
	IN ULONG	Flag,
	OUT PULONG	Length
	)
{
	ULONG Validate;
	NTSTATUS status;
	int		Align;
	ULONG	ContextLength;

	//验证一些特征
	status = RtlpValidateContextFlags(Flag,&Validate);
	if (!NT_SUCCESS(status))
	{
		return;
	}

	Align = 0;
	if (Flag&0x10000)
	{
		ContextLength = 0x2CC;		//应该是sizeof(CONTEXT)
		Align = 0x4;
	}else{
		Align = 0x10;
		if (Flag&0x100000){
			ContextLength = 0x4D0;
		}else if(Flag&0x80000){
			ContextLength = 0xA70;
		}else{
			Align = 0;
		}
	}

	ContextLength += 0x18;
	if (Validate&0x2)
	{
		int temp;

		//向下取整
		temp = (ContextLength+Align-1) & ~(Align - 1) - Align;
		ContextLength = temp + g_lpUserSharedData->XState.Size - 0x1C0;
	}

	*Length = ContextLength + Align - 1;
}

//在不知道扩展的CONTEXT结构时，分析尤为不易....
NTSTATUS RtlInitializeExtendedContext(
	OUT PCONTEXT Context,		//这里的Context是个扩展的CONTEXT结构，由于无法知晓其具体内容，特写成如此
	IN  ULONG Flag,
	OUT PEXTEND_CONTEXT_AREA* ContextExArea)
{
	ULONG Validate;
	NTSTATUS status;

	PEXTEND_CONTEXT_AREA	ExtendedArea;

	status = RtlpValidateContextFlags(Flag,&Validate);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (Flag&0x10000)
	{
		Context = (PCONTEXT)ALIGN_VALUE(Context,0x4);	//按0x4的倍数对齐
		ExtendedArea = (PEXTEND_CONTEXT_AREA)((ULONG)Context + 0x2CC);
		goto __Loop1;
	}else if(Flag&0x100000){
		Context = (PCONTEXT)ALIGN_VALUE(Context,0x10);	//按0x10的倍数对齐
		Context->FloatSave.DataOffset = Flag;			//为了写方便才如此，实际这个偏移位置远非如此含义
		ExtendedArea = (PEXTEND_CONTEXT_AREA)((ULONG)Context + 0x4D0);
		goto __Loop2;
	}else if(!(Flag&0x80000)){
		goto __Loop3;
	}else{
		Context = (PCONTEXT)ALIGN_VALUE(Context,0x10);	//按0x10的倍数对齐
		ExtendedArea = (PEXTEND_CONTEXT_AREA)((ULONG)Context + 0xA70);
	}
__Loop1:
	Context->ContextFlags = Flag;
__Loop2:
	ExtendedArea->ContextOffest = (ULONG)ExtendedArea - (ULONG)Context;
__Loop3:
	ExtendedArea->Unkwon3 = -ExtendedArea->ContextOffest;
	ExtendedArea->Unkwon1 = -ExtendedArea->ContextOffest;
	ExtendedArea->Unkwon2 = ExtendedArea->ContextOffest+0x18;

	if (Flag&0x10000 && (Flag&0x10020)!=0x10020)
	{
		ExtendedArea->ContextOffest = 0xCC;
	}

	if (Flag&0x2)
	{
		VOID*	AlignUnkwon = (VOID*)ALIGN_VALUE(&ExtendedArea->Unkwon7,0x40);
		memset(AlignUnkwon,0,0x40);
		ExtendedArea->Unkwon4 = (ULONG)AlignUnkwon - (ULONG)ExtendedArea;
		ExtendedArea->Unkwon5 = g_lpUserSharedData->XState.Size - 0x200;

		ExtendedArea->Unkwon2 = ExtendedArea->Unkwon5 - ExtendedArea->Unkwon1 + ExtendedArea->Unkwon4;
	}else{
		ExtendedArea->Unkwon5 = 0;
		ExtendedArea->Unkwon4 = 0x19;
	}

	*ContextExArea = ExtendedArea;

	return STATUS_SUCCESS;
}

ULONG inline KiSegSsFromTrapFrame(
    IN PKTRAP_FRAME_S TrapFrame
    )
{
    if (TrapFrame->EFlags & EFLAGS_V86_MASK){
        return TrapFrame->HardwareSegSs;
    } else if ((TrapFrame->SegCs & MODE_MASK) != KernelMode) {

        //
        // It's user mode.  The HardwareSegSs contains R3 data selector.
        //

        return TrapFrame->HardwareSegSs | RPL_MASK;
    } else {
        return KGDT_R0_DATA;
    }
}

ULONG
KiEspFromTrapFrame(
    IN PKTRAP_FRAME_S TrapFrame
    )

{
    if (((TrapFrame->SegCs & MODE_MASK) != KernelMode) ||
         (TrapFrame->EFlags & EFLAGS_V86_MASK)) {

        //  User mode frame, real value of Esp is always in HardwareEsp.

        return TrapFrame->HardwareEsp;

    } else {

        if ((TrapFrame->SegCs & FRAME_EDITED) == 0) {

            //  Kernel mode frame which has had esp edited,
            //  value of Esp is in TempEsp.

            return TrapFrame->TempEsp;

        } else {

            //  Kernel mode frame has has not had esp edited, compute esp.

            return (ULONG)&TrapFrame->HardwareEsp;
        }
    }
}

VOID _declspec(naked) KiFlushNPXState()
{
	__asm{
		push	esi
		push	edi
		push	ebx
		pushfd
		cli
		mov		edi,fs:[0x1C]			;kpcr
		mov		esi,[edi+0x124]			;CurrentThread
		movsx	eax,byte ptr[esi+0x69]	;CurrentThread->NpxState
		test	eax,eax
		jz		__Exit					;CurrentThread->NpxState == 0 ? exit
		
		mov		edx,cr0
		mov		ebx,edx
		test	dl,0xE
		jz		fnpx01
		and		dl,0xF1
		mov		cr0,edx
fnpx01:
		mov		ecx,[esi+0x28]			;CurrentThread->InitialStack
		lea		ecx,[ecx-0x210]			;CurrentThread->InitialStack - sizeof(KSTACK_AREA)
		test	KeEnabledXStateFeatures,0x1
		jz		fnpx03
		test	KeFeatureBits,0x400000
		jnz		fnpx02
		fxsave  dword ptr[ecx]
		jmp		fnpx04
fnpx02:
		cdq
		xsave	byte ptr[ecx]
		jmp		fnpx04
fnpx03:
		fnsave	byte ptr[ecx]
		wait
fnpx04:
		test	al,0x7
		jz		fnpx05
		and		bl,0xF1
		xor		eax,eax
		or		ebx,0xA
		mov		[edi+0x5C0],eax
		or		ebx,[ecx+0x1FC]
		and		byte ptr[esi+0x69],0xF8
fnpx05:
		mov		cr0,ebx
__Exit:
		popfd
		pop		ebx
		pop		edi
		pop		esi
		retn
	}
}

VOID
KiCopyXStateArea(
	IN OUT PXSAVE_AREA XSaveArea,
	IN ULONG LowMask,
	IN ULONG HighMask,
	IN PKSTACK_AREA KStackArea)
{	
	int		index;
	ULONG	Mask1,Mask2;

	LARGE_INTEGER *LargeValue;
	PXSTATE_FEATURE xStateFeature;

	Mask1 = (g_lpUserSharedData->XState.EnabledFeatures.LowPart&KStackArea->Padding[0])&LowMask;
	Mask2 = (g_lpUserSharedData->XState.EnabledFeatures.HighPart&KStackArea->Padding[1])&HighMask;

	LargeValue = (LARGE_INTEGER*)(&XSaveArea->Header.Mask);
	LargeValue->LowPart = (LargeValue->LowPart & ~LowMask) | Mask1;
	LargeValue->HighPart = (LargeValue->HighPart & ~HighMask) | Mask2;

	if (Mask1&0x2 != 0)
	{
		XSaveArea->LegacyState.MxCsr = KStackArea->NpxFrame.MXCsr;
	}

	xStateFeature = g_lpUserSharedData->XState.Features;
	for (index = 0;index < 64;index ++)
	{
		//这里的循环有点意思，要表达的意思是：
		//mask1和mask2合并起来刚好64位，这64位代表了xStateFeature这个数组的各个元素，
		//循环遍历这64位，当某位不为零的时候就要复制数据了

		if (Mask1&0x1 != 0)
		{
			memcpy((PVOID)((ULONG)XSaveArea+KStackArea+xStateFeature[index].Offset),
				(PVOID)((ULONG)KStackArea+xStateFeature[index].Offset),xStateFeature[index].Size);
		}

		Mask1 = SHRD_DWORD(Mask1,Mask2,0x1);
		Mask2 >>= 0x1;
		if (Mask1|Mask2 == 0)
		{
			break;
		}
	}
}

ULONG
RtlFxToFnFrame(
	IN PFXSAVE_FORMAT fxSaveFormat,
	OUT PFNSAVE_FORMAT fnSaveFormat)
{
	ULONG	Mask;
	WORD	TagWord;
	WORD	index,count;

	UCHAR	*fxRegisterArea,*fnRegisterArea;


	PXSTATE_CONFIGURATION_S xStateConfig;

	Mask = 0;

	fnSaveFormat->ControlWord = fxSaveFormat->ControlWord;
	fnSaveFormat->StatusWord = fxSaveFormat->StatusWord;
	fnSaveFormat->ErrorOffset = fxSaveFormat->ErrorOffset;
	fnSaveFormat->ErrorSelector = (fxSaveFormat->ErrorOpcode<<0x10) | fxSaveFormat->ErrorSelector;
	fnSaveFormat->DataOffset = fxSaveFormat->DataOffset;
	fnSaveFormat->DataSelector = fxSaveFormat->DataSelector;

	index = fxSaveFormat->StatusWord;
	index = 0x7 - ((index >> 0xB)&0x7);

	TagWord = fxSaveFormat->TagWord;

	fxRegisterArea = fxSaveFormat->RegisterArea;
	fnRegisterArea = fnSaveFormat->RegisterArea;

	count = 8;
	while (count)
	{
		Mask = Mask << 0x2;
		if (TagWord&0x80)
		{
			Mask |= 0x2;

			//以下计算的结果得到的结构体可能是XSTATE_CONFIGURATION
			xStateConfig = (PXSTATE_CONFIGURATION_S)(((index+0x2)<<0x4) + (ULONG)fxSaveFormat);
			if (xStateConfig->Size&0x7FFF)
			{
				if ((xStateConfig->Size != 0x7FFF) &&
					(xStateConfig->EnabledFeatures.HighPart <= 0) &&
					((xStateConfig->EnabledFeatures.HighPart < 0) ||
					(xStateConfig->EnabledFeatures.LowPart < 0)))
				{
					Mask = Mask&0xFFFC;
				}
			}else 
			if((xStateConfig->EnabledFeatures.LowPart | 
				xStateConfig->EnabledFeatures.HighPart) == 0){

				Mask = Mask&0xFFFD;
				Mask = Mask | 0x1;
			}
		}else{
			Mask |= 0x3;
		}

		TagWord = TagWord << 0x1;
		fxRegisterArea += 0x10;
		fnSaveFormat += 0xA;

		index--;
		index = index&0x7;

		count--;
	}

	fnSaveFormat->TagWord = Mask;
	return Mask;
}

VOID
KiContextFromNpxFrame(
	IN OUT PCONTEXT ContextFrame,
	IN ULONG ContextFlags,
	IN int	Flag1,			//KeEnabledXStateFeatures相关
	IN int Flag2,			//KeEnabledXStateFeatures+4的值
	IN PKSTACK_AREA KStackArea
	)
{
	PXSAVE_FORMAT	xSaveFormat;
	PXSAVE_AREA		xSaveArea;
	KSTACK_AREA		TempKStackArea;

	//基本不会进入这里
	if ((ContextFlags&CONTEXT_XSTATE)==CONTEXT_XSTATE)
	{
		//猜测CONTEXT的扩展部分可能是XSAVE_FORMAT结构.....只是可能.....
		xSaveFormat = (PXSAVE_FORMAT)((ULONG)ContextFrame + sizeof(CONTEXT));
		//貌似是这样 .......
		xSaveArea = (PXSAVE_AREA)((ULONG)ContextFrame + xSaveFormat->DataOffset + sizeof(CONTEXT)-0x200);

		if ((((xSaveArea->Header.Mask&0xFFFFFFFF)&(Flag1)) | 
			((xSaveArea->Header.Mask>>32)&Flag2)) != 0)
		{
			KiCopyXStateArea(
				xSaveArea,
				(xSaveArea->Header.Mask&0xFFFFFFFF)&Flag1,
				(xSaveArea->Header.Mask>>32)&Flag2,
				KStackArea);
		}
	}

	if ((ContextFlags&CONTEXT_EXTENDED_REGISTERS)==CONTEXT_EXTENDED_REGISTERS)
	{
		memcpy(ContextFrame->ExtendedRegisters,KStackArea,0x78*sizeof(DWORD));
	}

	if ((ContextFlags&CONTEXT_FLOATING_POINT)==CONTEXT_FLOATING_POINT)
	{
		if (KeI386FxsrPresent == 0x1)
		{
			//KSTACK_AREA结构开头是个联合，进入这里说明此联合中的NpxFrame成员有效
			RtlFxToFnFrame(&KStackArea->NpxFrame,&TempKStackArea.FnArea);
		}else{
			TempKStackArea = *KStackArea;
		}

		ContextFrame->FloatSave.ControlWord = TempKStackArea.FnArea.ControlWord;
		ContextFrame->FloatSave.StatusWord = TempKStackArea.FnArea.StatusWord;
		ContextFrame->FloatSave.TagWord = TempKStackArea.FnArea.TagWord;
		ContextFrame->FloatSave.ErrorOffset = TempKStackArea.FnArea.ErrorOffset;
		ContextFrame->FloatSave.ErrorSelector = TempKStackArea.FnArea.ErrorSelector;
		ContextFrame->FloatSave.DataOffset = TempKStackArea.FnArea.DataOffset;
		ContextFrame->FloatSave.DataSelector = TempKStackArea.FnArea.DataSelector;

		memcpy(ContextFrame->FloatSave.RegisterArea,TempKStackArea.FnArea.RegisterArea,0x50);
	}
}

_declspec(naked) VOID RtlXSave()
{
	__asm{
		mov		dl,6
		mov		eax,[esp+0x4]		;flag1
		and		dl,al
		cmp		dl,0x4
		mov		edx,[esp+0x8]		;flag2
		jz		__Leep
		xsave	byte ptr[ecx]
		retn	0x8
__Leep:
		push    [ecx+18h]
		push    [ecx+1Ch]
		xsave   byte ptr [ecx]
		pop     [ecx+1Ch]
		pop     [ecx+18h]
		retn    8
	}
}

VOID __stdcall
RtlXSaveNotLazy(
	PXSAVE_AREA xSaveArea,
	ULONG flag1,
	ULONG flag2)
{
	__asm{
		pushfd
		cli
		mov		eax,cr0
		push	ecx
		push	eax
		mov		ecx,[ebp+0x8]
		test	al,0xE
		jz		__Leep1
		and		al,0xF1
		mov		cr0,eax
__Leep1:
		push	[ebp+0x10]
		push	[ebp+0xC]
		call	RtlXSave
		pop		eax
		pop		ecx
		test	al,0xE
		jz		__Leep2
		mov		cr0,eax
__Leep2:
		popfd
	}
}

ULONG
FASTCALL
KiUpdateDr7 (
    IN ULONG Dr7
    )
{
    UCHAR DebugMask;

    DebugMask = (UCHAR) ((PKTHREAD_S)KeGetCurrentThread())->Header.DebugActive; 
    
    if ((DebugMask & DR_MASK (DR7_OVERRIDE_V)) != 0) {
        ASSERT ((DebugMask & DR_REG_MASK) != 0);
        ASSERT ((Dr7 & ~DR7_RESERVED_MASK) == DR7_OVERRIDE_MASK);
        return 0;
    }

    return Dr7;
}

VOID
KeContextFromKframes (
    __in PKTRAP_FRAME_S TrapFrame,
    __in PKEXCEPTION_FRAME ExceptionFrame,
    __inout PCONTEXT ContextFrame
    )
{

    PFX_SAVE_AREA NpxFrame;
    BOOLEAN StateSaved;
    ULONG i;
    struct _FPSaveBuffer {
        UCHAR               Buffer[15];
        FLOATING_SAVE_AREA  SaveArea;
    } FloatSaveBuffer;
    PFLOATING_SAVE_AREA PSaveArea;
    KIRQL OldIrql;

	ULONG flag1,flag2;
	PXSTATE_SAVE	xStateSave;
	PXSAVE_AREA		xSaveArea;
	PKSTACK_AREA	kStackArea;

    UNREFERENCED_PARAMETER( ExceptionFrame );

    //
    // This routine is called at both PASSIVE_LEVEL by exception dispatch
    // and at APC_LEVEL by NtSetContextThread. We raise to APC_LEVEL to
    // make the trap frame capture atomic.
    //
    OldIrql = KeGetCurrentIrql ();
    if (OldIrql < APC_LEVEL) {
        KeRaiseIrql (APC_LEVEL, &OldIrql);
    }

    //
    // Set control information if specified.
    //

    if ((ContextFrame->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {

        //
        // Set registers ebp, eip, cs, eflag, esp and ss.
        //

        ContextFrame->Ebp = TrapFrame->Ebp;
        ContextFrame->Eip = TrapFrame->Eip;

        if (((TrapFrame->SegCs & FRAME_EDITED) == 0) &&
            ((TrapFrame->EFlags & EFLAGS_V86_MASK) == 0)) {
            ContextFrame->SegCs = TrapFrame->TempSegCs & SEGMENT_MASK;
        } else {
            ContextFrame->SegCs = TrapFrame->SegCs & SEGMENT_MASK;
        }
        ContextFrame->EFlags = TrapFrame->EFlags;
        ContextFrame->SegSs = KiSegSsFromTrapFrame(TrapFrame);
        ContextFrame->Esp = KiEspFromTrapFrame(TrapFrame);
    }

    //
    // Set segment register contents if specified.
    //

    if ((ContextFrame->ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {

        //
        // Set segment registers gs, fs, es, ds.
        //
        // These values are junk most of the time, but useful
        // for debugging under certain conditions.  Therefore,
        // we report whatever was in the frame.
        //
        if (TrapFrame->EFlags & EFLAGS_V86_MASK) {
            ContextFrame->SegGs = TrapFrame->V86Gs & SEGMENT_MASK;
            ContextFrame->SegFs = TrapFrame->V86Fs & SEGMENT_MASK;
            ContextFrame->SegEs = TrapFrame->V86Es & SEGMENT_MASK;
            ContextFrame->SegDs = TrapFrame->V86Ds & SEGMENT_MASK;
        }
        else {
            if (TrapFrame->SegCs == KGDT_R0_CODE) {
                //
                // Trap frames created from R0_CODE traps do not save
                // the following selectors.  Set them in the frame now.
                //

                TrapFrame->SegGs = 0;
                TrapFrame->SegFs = KGDT_R0_PCR;
                TrapFrame->SegEs = KGDT_R3_DATA | RPL_MASK;
                TrapFrame->SegDs = KGDT_R3_DATA | RPL_MASK;
            }

            ContextFrame->SegGs = TrapFrame->SegGs & SEGMENT_MASK;
            ContextFrame->SegFs = TrapFrame->SegFs & SEGMENT_MASK;
            ContextFrame->SegEs = TrapFrame->SegEs & SEGMENT_MASK;
            ContextFrame->SegDs = TrapFrame->SegDs & SEGMENT_MASK;
        }

    }

    //
    // Set integer register contents if specified.
    //

    if ((ContextFrame->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {

        //
        // Set integer registers edi, esi, ebx, edx, ecx, eax
        //

        ContextFrame->Edi = TrapFrame->Edi;
        ContextFrame->Esi = TrapFrame->Esi;
        ContextFrame->Ebx = TrapFrame->Ebx;
        ContextFrame->Ecx = TrapFrame->Ecx;
        ContextFrame->Edx = TrapFrame->Edx;
        ContextFrame->Eax = TrapFrame->Eax;
    }

	//////////////////////////////////////////////////////////////////////////

	if (((TrapFrame->SegCs & MODE_MASK) == UserMode) &&
		((ContextFrame->ContextFlags & CONTEXT_EXTENDED_REGISTERS)==CONTEXT_EXTENDED_REGISTERS) ||
		((ContextFrame->ContextFlags & CONTEXT_FLOATING_POINT)==CONTEXT_FLOATING_POINT) ||
		((ContextFrame->ContextFlags & CONTEXT_XSTATE)==CONTEXT_XSTATE))
	{
		if (OldIrql < DISPATCH_LEVEL)
		{
			KeEnterCriticalRegionThread((PKTHREAD_S)KeGetCurrentThread());
		}

		xStateSave = ((PKTHREAD_S)KeGetCurrentThread())->XStateSave;

		flag1 = *(ULONG*)KeEnabledXStateFeatures;
		flag2 = 0;

		if (xStateSave != NULL)
		{
			do 
			{
				xStateSave = xStateSave->Prev;
			} while (xStateSave->Prev);

			//这里应该是如此.....
			xSaveArea = xStateSave->Reserved3;
		}else{
			xSaveArea = 0;
		}

		//通过这里的分析发现_XSAVE_AREA结构和_KSTACK_AREA结构实际是一样的，
		//_XSAVE_AREA结构比_KSTACK_AREA描述的详细点而已，所以这里能直接转换
		kStackArea = (PKSTACK_AREA)xSaveArea;

		if (xSaveArea == NULL)
		{
			//InitialStack是记录内核栈初始化的位置
			kStackArea = (PKSTACK_AREA)((ULONG)((PKTHREAD_S)KeGetCurrentThread())->InitialStack - sizeof(KSTACK_AREA));
			KiFlushNPXState();
		}else{
			
			//KeEnabledXStateFeatures+0x4

			//mov     eax, KeEnabledXStateFeatures+0x4
			//and     ecx, 0FFFFFFFCh
			//mov     [esp+28h+var_4], eax
			//mov     ebx, ecx
			//

			flag1 &= 0xFFFFFFFC;
			flag2 = *(ULONG*)(KeEnabledXStateFeatures+0x4);
		}

		KiContextFromNpxFrame(
			ContextFrame,
			ContextFrame->ContextFlags,
			flag1,
			flag2,
			kStackArea);

		 if ((ContextFrame->ContextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE)
		 {
			 PXSAVE_FORMAT	xSFormat;
			 PXSAVE_AREA	xSArea;

			 //猜测CONTEXT的扩展部分可能是XSAVE_FORMAT结构.....只是可能.....
			 xSFormat = (PXSAVE_FORMAT)((ULONG)ContextFrame + sizeof(CONTEXT));
			 //貌似是这样 .......
			 xSArea = (PXSAVE_AREA)((ULONG)ContextFrame + xSFormat->DataOffset + sizeof(CONTEXT)-0x200);

			 flag1 = (xSArea->Header.Mask&(~flag1))&(*(ULONG*)KeEnabledXStateFeatures)&0xFFFFFFFC;
			 flag2 = ((xSArea->Header.Mask>>32)&(~flag2))&(*(ULONG*)(KeEnabledXStateFeatures+0x4));
			 if (flag1 | flag2)
			 {
				 RtlXSaveNotLazy(xSArea,flag1,flag2);
			 }
		 }

		 if (OldIrql < DISPATCH_LEVEL)
		 {
			 KeLeaveCriticalRegionThread((PKTHREAD_S)KeGetCurrentThread());
		 }
	}

    if ((ContextFrame->ContextFlags & CONTEXT_DEBUG_REGISTERS) ==
        CONTEXT_DEBUG_REGISTERS) {
         
        //
        // Care is now taken to ensure that the DebugActive/Dr7 value is set on
        // any valid set of a legal DR value, ensuring the values on the kernel
        // stack cannot become trash.
        //

        if ((TrapFrame->Dr7 & ~DR7_RESERVED_MASK) != 0) {
            ContextFrame->Dr0 = TrapFrame->Dr0;
            ContextFrame->Dr1 = TrapFrame->Dr1;
            ContextFrame->Dr2 = TrapFrame->Dr2;
            ContextFrame->Dr3 = TrapFrame->Dr3;
            ContextFrame->Dr6 = TrapFrame->Dr6;
            ContextFrame->Dr7 = KiUpdateDr7 (TrapFrame->Dr7);
        } else {
            ContextFrame->Dr0 = 0;
            ContextFrame->Dr1 = 0;
            ContextFrame->Dr2 = 0;
            ContextFrame->Dr3 = 0;
            ContextFrame->Dr6 = 0;
            ContextFrame->Dr7 = 0;
        }
    }

    //
    // Lower IRQL if we had to raise it
    //
    if (OldIrql < APC_LEVEL) {
        KeLowerIrql (OldIrql);
    }

	//////////////////////////////////////////////////////////////////////////
}

VOID
	KiDispatchException (
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME_S TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance
	)
{
	NTSTATUS status;
	PKPRCB	kPrcb;
	ULONG	Flag;

	ULONG	ExContextLength;

	ULONG UserStack1;
	ULONG UserStack2;

	PCONTEXT	ExtenContext;
	PEXTEND_CONTEXT_AREA ExtenContextArea;
	
	EXCEPTION_RECORD ExceptionRecord1, ExceptionRecord2;

	kPrcb = KeGetCurrentPrcb();
	kPrcb->KeExceptionDispatchCount++;

	Flag = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	if (PreviousMode == UserMode || *KdDebuggerEnabled == TRUE)
	{
		Flag |= CONTEXT_FLOATING_POINT;
		if (KeI386XMMIPresent != 0)
		{
			Flag |= CONTEXT_EXTENDED_REGISTERS;
		}

		if (KeFeatureBits&0x400000)
		{
			//这里涉及了几句处理器特性相关的处理语句，以后再根据情况添加
		}
	}

	RtlGetExtendedContextLength(Flag,&ExContextLength);

	ExtenContext = (PCONTEXT)ExAllocatePool(NonPagedPool,ExContextLength);

	status = RtlInitializeExtendedContext((PCONTEXT)ExtenContext,Flag,&ExtenContextArea);

	if ((Flag&0x10040) == 0x10040)
	{
		//这里涉及了几句处理器特性相关的处理语句，以后再根据情况添加
	}

	KeContextFromKframes(TrapFrame,ExceptionFrame,ExtenContext);

	switch (ExceptionRecord->ExceptionCode)
	{
	case STATUS_BREAKPOINT:
		ExtenContext->Eip--;
		break;
	case KI_EXCEPTION_ACCESS_VIOLATION:
		ExceptionRecord->ExceptionCode = STATUS_ACCESS_VIOLATION;
		if (PreviousMode == UserMode)
		{
			if (KiCheckForAtlThunk(ExceptionRecord,ExtenContext) != FALSE)
			{
				goto __Leep1;
			}

			if ((g_lpUserSharedData->ProcessorFeatures[PF_NX_ENABLED] == TRUE) &&
				(ExceptionRecord->ExceptionInformation [0] == EXCEPTION_EXECUTE_FAULT)) {
                    
				if (((KeFeatureBits & KF_GLOBAL_32BIT_EXECUTE) != 0) ||
					(((PEPROCESS_S)PsGetCurrentProcess())->Pcb.Flags.ExecuteEnable != 0) ||
					(((KeFeatureBits & KF_GLOBAL_32BIT_NOEXECUTE) == 0) &&
					(((PEPROCESS_S)PsGetCurrentProcess())->Pcb.Flags.ExecuteDisable == 0))) {
						
					ExceptionRecord->ExceptionInformation [0] = 0;
				}
			}
		}
		break;
	}

	if (PreviousMode == KernelMode)
	{
		//是第一次到来
		if (FirstChance == TRUE)
		{
			if(KiDebugRoutine(
				TrapFrame,
				ExceptionFrame,
				ExceptionRecord,
				ExtenContext,
				PreviousMode,
				FALSE) != FALSE)
			{
				goto __Leep1;
			}

			if (RtlDispatchException(ExceptionRecord,ExtenContext) == TRUE) {
				goto __Leep1;
			}
		}

		//
		// This is the second chance to handle the exception.
		//

		if (KiDebugRoutine(
			TrapFrame,
			ExceptionFrame,
			ExceptionRecord,
			ExtenContext,
			PreviousMode,
			TRUE) != FALSE) {
				goto __Leep1;
		}

		KeBugCheckEx(
            KERNEL_MODE_EXCEPTION_NOT_HANDLED,
            ExceptionRecord->ExceptionCode,
            (ULONG)ExceptionRecord->ExceptionAddress,
            (ULONG)TrapFrame,
            0);
	}else{
		
		memset(&ExceptionRecord->ExceptionInformation[ExceptionRecord->NumberParameters],
			0,(ULONG)&ExceptionRecord - (ULONG)&ExceptionRecord->ExceptionInformation[ExceptionRecord->NumberParameters] + sizeof(EXCEPTION_RECORD));

		if (FirstChance == TRUE)
		{
			//用户模式第一次来到这里
			if (((PEPROCESS_S)PsGetCurrentProcess())->DebugPort != NULL ||
				KdIgnoreUmExceptions != 0)
			{
				if (ExceptionRecord->ExceptionCode != STATUS_BREAKPOINT ||
					ExceptionRecord->NumberParameters <= 0 ||
					ExceptionRecord->ExceptionInformation[0] == 0)
				{
					goto __Leep2;
				}
			}

			if (KiDebugRoutine(
				TrapFrame,
				ExceptionFrame,
				ExceptionRecord,
				ExtenContext,
				PreviousMode,
				NULL) != FALSE)
			{
				goto __Leep1;
			}

__Leep2:
			if (DbgkForwardException(ExceptionRecord, TRUE, FALSE)) {
				return;
			}

			ExceptionRecord1.ExceptionCode = 0;

		repeat:
			try{
				if (TrapFrame->HardwareSegSs != (KGDT_R3_DATA | RPL_MASK) ||
					TrapFrame->EFlags&EFLAGS_V86_MASK)
				{
					ExceptionRecord->ExceptionCode = STATUS_ACCESS_VIOLATION;
					ExceptionRecord->ExceptionFlags = 0;
					ExceptionRecord->NumberParameters = 0;
					RtlRaiseException(&ExceptionRecord);
				}

				//
				// Compute length of context record and new aligned user stack
				// pointer.
				//

				UserStack1 = (ExtenContext->Esp & ~CONTEXT_ROUND);
				if ((Flag&0x10040)!=0x10040)
				{
					UserStack1 -= ExtenContextArea->Unkwon5;
					UserStack1 = UserStack1&(~0xF);
				}


			}except(){
				//
			}

		}

		//用户模式第二次来到这里
		if (DbgkForwardException(ExceptionRecord, TRUE, TRUE)) {
			return;
		}else if (DbgkForwardException(ExceptionRecord, FALSE, TRUE)){
			return;
		}else{
			ZwTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);
			KeBugCheckEx(
				KERNEL_MODE_EXCEPTION_NOT_HANDLED,
				ExceptionRecord->ExceptionCode,
				(ULONG)ExceptionRecord->ExceptionAddress,
				(ULONG)TrapFrame,
				0);
		}


	}

__Leep1:
	KeContextToKframes(TrapFrame, ExceptionFrame,ExtenContext,
		ExtenContext->ContextFlags, PreviousMode);
}
*/