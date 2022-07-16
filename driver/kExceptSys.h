#ifndef __KEXCEPTSYS_H__
#define __KEXCEPTSYS_H__

#include "CommonFunc.h"
#include "struct.h"

#define KeI386XMMIPresent		0x1
#define KeFeatureBits			0x0
#define KeEnabledXStateFeatures	0x0
#define KeI386FxsrPresent		0x1

//
//  Bits forced to 0 in SegCs if Esp has been edited.
//

#define FRAME_EDITED        0xfff8

//
// Defined processor features
//

#define PF_FLOATING_POINT_PRECISION_ERRATA  0   // winnt
#define PF_FLOATING_POINT_EMULATED          1   // winnt
#define PF_COMPARE_EXCHANGE_DOUBLE          2   // winnt
#define PF_MMX_INSTRUCTIONS_AVAILABLE       3   // winnt
#define PF_PPC_MOVEMEM_64BIT_OK             4   // winnt
#define PF_ALPHA_BYTE_INSTRUCTIONS          5   // winnt
#define PF_XMMI_INSTRUCTIONS_AVAILABLE      6   // winnt
#define PF_3DNOW_INSTRUCTIONS_AVAILABLE     7   // winnt
#define PF_RDTSC_INSTRUCTION_AVAILABLE      8   // winnt
#define PF_PAE_ENABLED                      9   // winnt
#define PF_XMMI64_INSTRUCTIONS_AVAILABLE   10   // winnt
#define PF_SSE_DAZ_MODE_AVAILABLE          11   // winnt
#define PF_NX_ENABLED                      12   // winnt


//
// i386 Feature bit definitions
//
// N.B. The no execute feature flags must be identical on all platforms.

#define KF_V86_VIS          0x00000001
#define KF_RDTSC            0x00000002
#define KF_CR4              0x00000004
#define KF_CMOV             0x00000008
#define KF_GLOBAL_PAGE      0x00000010
#define KF_LARGE_PAGE       0x00000020
#define KF_MTRR             0x00000040
#define KF_CMPXCHG8B        0x00000080
#define KF_MMX              0x00000100
#define KF_WORKING_PTE      0x00000200
#define KF_PAT              0x00000400
#define KF_FXSR             0x00000800
#define KF_FAST_SYSCALL     0x00001000
#define KF_XMMI             0x00002000
#define KF_3DNOW            0x00004000
#define KF_AMDK6MTRR        0x00008000
#define KF_XMMI64           0x00010000
#define KF_DTS              0x00020000
#define KF_NOEXECUTE        0x20000000
#define KF_GLOBAL_32BIT_EXECUTE 0x40000000
#define KF_GLOBAL_32BIT_NOEXECUTE 0x80000000

// begin_wx86
//
//  GDT selectors - These defines are R0 selector numbers, which means
//                  they happen to match the byte offset relative to
//                  the base of the GDT.
//

#define KGDT_NULL       0
#define KGDT_R0_CODE    8
#define KGDT_R0_DATA    16
#define KGDT_R3_CODE    24
#define KGDT_R3_DATA    32
#define KGDT_TSS        40
#define KGDT_R0_PCR     48
#define KGDT_R3_TEB     56
#define KGDT_VDM_TILE   64
#define KGDT_LDT        72
#define KGDT_DF_TSS     80
#define KGDT_NMI_TSS    88


// begin_nthal
//
// Define constants used in selector tests.
//
//  RPL_MASK is the real value for extracting RPL values.  IT IS THE WRONG
//  CONSTANT TO USE FOR MODE TESTING.
//
//  MODE_MASK is the value for deciding the current mode.
//  WARNING:    MODE_MASK assumes that all code runs at either ring-0
//              or ring-3.  Ring-1 or Ring-2 support will require changing
//              this value and all of the code that refers to it.

#define MODE_MASK    1      // ntosp
#define RPL_MASK     3
//
// SEGMENT_MASK is used to throw away trash part of segment.  Part always
// pushes or pops 32 bits to/from stack, but if it's a segment value,
// high order 16 bits are trash.
//

#define SEGMENT_MASK    0xffff

//
// bits defined in Eflags
//

#define EFLAGS_CF_MASK        0x00000001L
#define EFLAGS_PF_MASK        0x00000004L
#define EFLAGS_AF_MASK        0x00000010L
#define EFLAGS_ZF_MASK        0x00000040L
#define EFLAGS_SF_MASK        0x00000080L
#define EFLAGS_TF             0x00000100L
#define EFLAGS_INTERRUPT_MASK 0x00000200L
#define EFLAGS_DF_MASK        0x00000400L
#define EFLAGS_OF_MASK        0x00000800L
#define EFLAGS_IOPL_MASK      0x00003000L
#define EFLAGS_NT             0x00004000L
#define EFLAGS_RF             0x00010000L
#define EFLAGS_V86_MASK       0x00020000L
#define EFLAGS_ALIGN_CHECK    0x00040000L
#define EFLAGS_VIF            0x00080000L
#define EFLAGS_VIP            0x00100000L
#define EFLAGS_ID_MASK        0x00200000L

#define EFLAGS_USER_SANITIZE  0x003f4dd7L

//
// The following values specify the type of failing access when the status is 
// STATUS_ACCESS_VIOLATION and the first parameter in the execpetion record.
//

#define EXCEPTION_READ_FAULT          0 // Access violation was caused by a read
#define EXCEPTION_WRITE_FAULT         1 // Access violation was caused by a write
#define EXCEPTION_EXECUTE_FAULT       8 // Access violation was caused by an instruction fetch

#define KI_EXCEPTION_INTERNAL               0x10000000
#define KI_EXCEPTION_GP_FAULT               (KI_EXCEPTION_INTERNAL | 0x1)
#define KI_EXCEPTION_INVALID_OP             (KI_EXCEPTION_INTERNAL | 0x2)
#define KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO (KI_EXCEPTION_INTERNAL | 0x3)
#define KI_EXCEPTION_ACCESS_VIOLATION       (KI_EXCEPTION_INTERNAL | 0x4)


#define DR7_OVERRIDE_V 0x04

#define DR_MASK(Bit) (((UCHAR)(1UL << (Bit))))


#define DR_REG_MASK (DR_MASK(0) | DR_MASK(1) | DR_MASK(2) | DR_MASK(3) | DR_MASK(6))
#define DR_VALID_MASK (DR_REG_MASK | DR_MASK (7) | DR_MASK (DR7_OVERRIDE_V))

#define DR7_MASK_SHIFT 16   // Shift to translate the valid mask to a spare region in Dr7
// The region occupied is the LEN & R/W region for Dr0

#define DR7_OVERRIDE_MASK ((0x0FUL) << DR7_MASK_SHIFT)  // This corresponds to a break on R/W of 4
#define DR7_RESERVED_MASK 0x0000DC00    // Bits 10-12, 14-15 are reserved
#define DR7_ACTIVE  0x00000055  // If any of these bits are set, a Dr is active

// #define CONTEXT_i386    0x00010000    // this assumes that i386 and
// #define CONTEXT_i486    0x00010000    // i486 have identical context records

// #define CONTEXT_CONTROL         (CONTEXT_i386 | 0x00000001L) // SS:SP, CS:IP, FLAGS, BP
// #define CONTEXT_INTEGER         (CONTEXT_i386 | 0x00000002L) // AX, BX, CX, DX, SI, DI
// #define CONTEXT_SEGMENTS        (CONTEXT_i386 | 0x00000004L) // DS, ES, FS, GS
// #define CONTEXT_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L) // 387 state
// #define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L) // DB 0-3,6,7
// #define CONTEXT_EXTENDED_REGISTERS  (CONTEXT_i386 | 0x00000020L) // cpu specific extensions
// 
// #define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER |\
// 	CONTEXT_SEGMENTS)

#define CONTEXT_LENGTH  (sizeof(CONTEXT))
#define CONTEXT_ALIGN   (sizeof(ULONG))
#define CONTEXT_ROUND   (CONTEXT_ALIGN - 1)
//
// Context size (as written to user stacks)
//
#define CONTEXT_ALIGNED_SIZE ((sizeof(CONTEXT) + CONTEXT_ROUND) & ~CONTEXT_ROUND)

typedef struct _EXTEND_CONTEXT_AREA
{
	ULONG	Unkwon1;			//+0x0
	ULONG	Unkwon2;			//+0x4
	ULONG	Unkwon3;			//+0x8
	ULONG	ContextOffest;		//+0xC
	ULONG	Unkwon4;			//+0x10
	ULONG	Unkwon5;			//0x14
	char	Unkwon6[0x46];
	ULONG	Unkwon7;
}EXTEND_CONTEXT_AREA,*PEXTEND_CONTEXT_AREA;

NTSTATUS RtlpValidateContextFlags(
	IN ULONG Flag);

PKPRCB KeGetCurrentPrcb()
{
	__asm{
		mov		eax,fs:[0x20]
	}
}

#endif