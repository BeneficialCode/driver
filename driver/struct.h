#ifndef __STRUCT_H__
#define __STRUCT_H__

#include "ntifs.h"
#include "ntimage.h"

/************************************************************************/
//windows 7


#define MAX_FAST_REFS	7
typedef struct _EX_FAST_REF      // 3 elements, 0x4 bytes (sizeof) 
{                                                                  
	union                        // 3 elements, 0x4 bytes (sizeof) 
	{                                                              
		/*0x000*/         VOID*        Object;
		/*0x000*/         ULONG32      RefCnt : 3; // 0 BitPosition                  
		/*0x000*/         ULONG32      Value;                                        
	};                                                             
}EX_FAST_REF, *PEX_FAST_REF;

typedef struct _CONTROL_AREA                                      // 16 elements, 0x50 bytes (sizeof) 
{                                                                                                     
	/*0x000*/     void* Segment;                                                                         
	/*0x004*/     struct _LIST_ENTRY DereferenceList;                           // 2 elements, 0x8 bytes (sizeof)   
	/*0x00C*/     ULONG32      NumberOfSectionReferences;                                                           
	/*0x010*/     ULONG32      NumberOfPfnReferences;                                                               
	/*0x014*/     ULONG32      NumberOfMappedViews;                                                                 
	/*0x018*/     ULONG32      NumberOfUserReferences;                                                              
	union                                                         // 2 elements, 0x4 bytes (sizeof)   
	{                                                                                                 
		/*0x01C*/         ULONG32      LongFlags;                                                                       
		/*0x01C*/         ULONG32	   Flags;                            // 27 elements, 0x4 bytes (sizeof)  
	}u;                                                                                               
	/*0x020*/     ULONG32      FlushInProgressCount;                                                                
	/*0x024*/     struct _EX_FAST_REF FilePointer;                              // 3 elements, 0x4 bytes (sizeof)   
	/*0x028*/     LONG32       ControlAreaLock;                                                                     
	union                                                         // 2 elements, 0x4 bytes (sizeof)   
	{                                                                                                 
		/*0x02C*/         ULONG32      ModifiedWriteCount;                                                              
		/*0x02C*/         ULONG32      StartingFrame;                                                                   
	};                                                                                                
	/*0x030*/     void* WaitingForDeletion;                                             
	union                                                         // 1 elements, 0xC bytes (sizeof)   
	{                                                                                                 
		struct                                                    // 9 elements, 0xC bytes (sizeof)   
		{                                                                                             
			union                                                 // 2 elements, 0x4 bytes (sizeof)   
			{                                                                                         
				/*0x034*/                 ULONG32      NumberOfSystemCacheViews;                                                
				/*0x034*/                 ULONG32      ImageRelocationStartBit;                                                 
			};                                                                                        
			union                                                 // 2 elements, 0x4 bytes (sizeof)   
			{                                                                                         
				/*0x038*/                 LONG32       WritableUserReferences;                                                  
				struct                                            // 4 elements, 0x4 bytes (sizeof)   
				{                                                                                     
					/*0x038*/                     ULONG32      ImageRelocationSizeIn64k : 16;   // 0 BitPosition                    
					/*0x038*/                     ULONG32      Unused : 14;                     // 16 BitPosition                   
					/*0x038*/                     ULONG32      BitMap64 : 1;                    // 30 BitPosition                   
					/*0x038*/                     ULONG32      ImageActive : 1;                 // 31 BitPosition                   
				};                                                                                    
			};                                                                                        
			union                                                 // 2 elements, 0x4 bytes (sizeof)   
			{                                                                                         
				/*0x03C*/                 void* SubsectionRoot;                                      
				/*0x03C*/                 void* SeImageStub;                                     
			};                                                                                        
		}e2;                                                                                          
	}u2;                                                                                              
	/*0x040*/     INT64        LockedPages;                                                                         
	/*0x048*/     struct _LIST_ENTRY ViewList;                                  // 2 elements, 0x8 bytes (sizeof)   
}CONTROL_AREA, *PCONTROL_AREA;

typedef struct _MMSECTION_FLAGS               // 27 elements, 0x4 bytes (sizeof) 
{                                                                                
	/*0x000*/     UINT32       BeingDeleted : 1;            // 0 BitPosition                   
	/*0x000*/     UINT32       BeingCreated : 1;            // 1 BitPosition                   
	/*0x000*/     UINT32       BeingPurged : 1;             // 2 BitPosition                   
	/*0x000*/     UINT32       NoModifiedWriting : 1;       // 3 BitPosition                   
	/*0x000*/     UINT32       FailAllIo : 1;               // 4 BitPosition                   
	/*0x000*/     UINT32       Image : 1;                   // 5 BitPosition                   
	/*0x000*/     UINT32       Based : 1;                   // 6 BitPosition                   
	/*0x000*/     UINT32       File : 1;                    // 7 BitPosition                   
	/*0x000*/     UINT32       Networked : 1;               // 8 BitPosition                   
	/*0x000*/     UINT32       Rom : 1;                     // 9 BitPosition                   
	/*0x000*/     UINT32       PhysicalMemory : 1;          // 10 BitPosition                  
	/*0x000*/     UINT32       CopyOnWrite : 1;             // 11 BitPosition                  
	/*0x000*/     UINT32       Reserve : 1;                 // 12 BitPosition                  
	/*0x000*/     UINT32       Commit : 1;                  // 13 BitPosition                  
	/*0x000*/     UINT32       Accessed : 1;                // 14 BitPosition                  
	/*0x000*/     UINT32       WasPurged : 1;               // 15 BitPosition                  
	/*0x000*/     UINT32       UserReference : 1;           // 16 BitPosition                  
	/*0x000*/     UINT32       GlobalMemory : 1;            // 17 BitPosition                  
	/*0x000*/     UINT32       DeleteOnClose : 1;           // 18 BitPosition                  
	/*0x000*/     UINT32       FilePointerNull : 1;         // 19 BitPosition                  
	/*0x000*/     UINT32       GlobalOnlyPerSession : 1;    // 20 BitPosition                  
	/*0x000*/     UINT32       SetMappedFileIoComplete : 1; // 21 BitPosition                  
	/*0x000*/     UINT32       CollidedFlush : 1;           // 22 BitPosition                  
	/*0x000*/     UINT32       NoChange : 1;                // 23 BitPosition                  
	/*0x000*/     UINT32       Spare : 1;                   // 24 BitPosition                  
	/*0x000*/     UINT32       UserWritable : 1;            // 25 BitPosition                  
	/*0x000*/     UINT32       PreferredNode : 6;           // 26 BitPosition                  
}MMSECTION_FLAGS, *PMMSECTION_FLAGS;

typedef struct _IMAGE_COMMITMENT 
{
	struct _CONTROL_AREA* ControlArea;
	//..........
}IMAGE_COMMITMENT,*PIMAGE_COMMITMENT;


//win7进程对象的SectionObject成员实际就是_SEGMENT_OBJECT结构，而不是_SECTION_OBJECT
typedef struct _SEGMENT_OBJECT                     // 9 elements, 0x28 bytes (sizeof) 
{                                                                                     
	/*0x000*/     VOID*        BaseAddress;                                                         
	/*0x004*/     ULONG32      TotalNumberOfPtes;                                                   
	/*0x008*/     union _LARGE_INTEGER SizeOfSegment;            // 4 elements, 0x8 bytes (sizeof)  
	/*0x010*/     ULONG32      NonExtendedPtes;                                                     
	/*0x014*/     struct _IMAGE_COMMITMENT*	ImageCommitment;		//这个成员经过分析我们重新定义一下                                                   
	/*0x018*/     struct _CONTROL_AREA* ControlArea;                                                
	/*0x01C*/     void* Subsection;                                                   
	/*0x020*/     struct _MMSECTION_FLAGS	MmSectionFlags;                                          
	/*0x024*/     void* MmSubSectionFlags;                                    
}SEGMENT_OBJECT, *PSEGMENT_OBJECT;

typedef struct _SECTION_OBJECT       // 6 elements, 0x18 bytes (sizeof) 
{                                                                       
	/*0x000*/     VOID*        StartingVa;                                            
	/*0x004*/     VOID*        EndingVa;                                              
	/*0x008*/     VOID*        Parent;                                                
	/*0x00C*/     VOID*        LeftChild;                                             
	/*0x010*/     VOID*        RightChild;                                            
	/*0x014*/     struct _SEGMENT_OBJECT* Segment;                                    
}SECTION_OBJECT, *PSECTION_OBJECT;

typedef struct _EX_PUSH_LOCK_WAIT_BLOCK        // 6 elements, 0x30 bytes (sizeof) 
{                                                                                 
	/*0x000*/     struct _KEVENT WakeEvent;                  // 1 elements, 0x10 bytes (sizeof) 
	/*0x010*/     struct _EX_PUSH_LOCK_WAIT_BLOCK* Next;                                        
	/*0x014*/     struct _EX_PUSH_LOCK_WAIT_BLOCK* Last;                                        
	/*0x018*/     struct _EX_PUSH_LOCK_WAIT_BLOCK* Previous;                                    
	/*0x01C*/     LONG32       ShareCount;                                                      
	/*0x020*/     LONG32       Flags;                                                           
	/*0x024*/     UINT8        _PADDING0_[0xC];                                                 
}EX_PUSH_LOCK_WAIT_BLOCK, *PEX_PUSH_LOCK_WAIT_BLOCK;

typedef struct _EX_PUSH_LOCK_S                 // 7 elements, 0x4 bytes (sizeof) 
{
#define EX_PUSH_LOCK_LOCK_V          ((ULONG_PTR)0x0)
#define EX_PUSH_LOCK_LOCK            ((ULONG_PTR)0x1)

	//
	// Waiting bit designates that the pointer has chained waiters
	//

#define EX_PUSH_LOCK_WAITING         ((ULONG_PTR)0x2)

	//
	// Waking bit designates that we are either traversing the list
	// to wake threads or optimizing the list
	//

#define EX_PUSH_LOCK_WAKING          ((ULONG_PTR)0x4)

	//
	// Set if the lock is held shared by multiple owners and there are waiters
	//

#define EX_PUSH_LOCK_MULTIPLE_SHARED ((ULONG_PTR)0x8)

	//
	// Total shared Acquires are incremented using this
	//
#define EX_PUSH_LOCK_SHARE_INC       ((ULONG_PTR)0x10)
#define EX_PUSH_LOCK_PTR_BITS        ((ULONG_PTR)0xf)
	union                                    // 3 elements, 0x4 bytes (sizeof) 
	{                                                                          
		struct                               // 5 elements, 0x4 bytes (sizeof) 
		{                                                                      
			/*0x000*/             ULONG32      Locked : 1;         // 0 BitPosition                  
			/*0x000*/             ULONG32      Waiting : 1;        // 1 BitPosition                  
			/*0x000*/             ULONG32      Waking : 1;         // 2 BitPosition                  
			/*0x000*/             ULONG32      MultipleShared : 1; // 3 BitPosition                  
			/*0x000*/             ULONG32      Shared : 28;        // 4 BitPosition                  
		};                                                                     
		/*0x000*/         ULONG32      Value;                                                    
		/*0x000*/         VOID*        Ptr;                                                      
	};                                                                         
}EX_PUSH_LOCK_S, *PEX_PUSH_LOCK_S;

typedef struct _MMADDRESS_NODE          // 5 elements, 0x14 bytes (sizeof) 
{                                                                          
	union                               // 2 elements, 0x4 bytes (sizeof)  
	{                                                                      
		/*0x000*/         LONG32       Balance : 2;       // 0 BitPosition                   
		/*0x000*/         struct _MMADDRESS_NODE* Parent;                                    
	}u1;                                                                   
	/*0x004*/     struct _MMADDRESS_NODE* LeftChild;                                     
	/*0x008*/     struct _MMADDRESS_NODE* RightChild;                                    
	/*0x00C*/     ULONG32      StartingVpn;                                              
	/*0x010*/     ULONG32      EndingVpn;                                                
}MMADDRESS_NODE, *PMMADDRESS_NODE;    

typedef struct _MM_AVL_TABLE                          // 6 elements, 0x20 bytes (sizeof) 
{                                                                                        
	/*0x000*/     struct _MMADDRESS_NODE BalancedRoot;              // 5 elements, 0x14 bytes (sizeof) 
	struct                                            // 3 elements, 0x4 bytes (sizeof)  
	{                                                                                    
		/*0x014*/         ULONG32      DepthOfTree : 5;                 // 0 BitPosition                   
		/*0x014*/         ULONG32      Unused : 3;                      // 5 BitPosition                   
		/*0x014*/         ULONG32      NumberGenericTableElements : 24; // 8 BitPosition                   
	};                                                                                   
	/*0x018*/     VOID*        NodeHint;                                                               
	/*0x01C*/     VOID*        NodeFreeHint;                                                           
}MM_AVL_TABLE, *PMM_AVL_TABLE;

typedef struct _MMSUPPORT_FLAGS                 // 15 elements, 0x4 bytes (sizeof) 
{                                                                                  
	struct                                      // 6 elements, 0x1 bytes (sizeof)  
	{                                                                              
		/*0x000*/         UINT8        WorkingSetType : 3;        // 0 BitPosition                   
		/*0x000*/         UINT8        ModwriterAttached : 1;     // 3 BitPosition                   
		/*0x000*/         UINT8        TrimHard : 1;              // 4 BitPosition                   
		/*0x000*/         UINT8        MaximumWorkingSetHard : 1; // 5 BitPosition                   
		/*0x000*/         UINT8        ForceTrim : 1;             // 6 BitPosition                   
		/*0x000*/         UINT8        MinimumWorkingSetHard : 1; // 7 BitPosition                   
	};                                                                             
	struct                                      // 4 elements, 0x1 bytes (sizeof)  
	{                                                                              
		/*0x001*/         UINT8        SessionMaster : 1;         // 0 BitPosition                   
		/*0x001*/         UINT8        TrimmerState : 2;          // 1 BitPosition                   
		/*0x001*/         UINT8        Reserved : 1;              // 3 BitPosition                   
		/*0x001*/         UINT8        PageStealers : 4;          // 4 BitPosition                   
	};                                                                             
	/*0x002*/     UINT8        MemoryPriority : 8;            // 0 BitPosition                   
	struct                                      // 4 elements, 0x1 bytes (sizeof)  
	{                                                                              
		/*0x003*/         UINT8        WsleDeleted : 1;           // 0 BitPosition                   
		/*0x003*/         UINT8        VmExiting : 1;             // 1 BitPosition                   
		/*0x003*/         UINT8        ExpansionFailed : 1;       // 2 BitPosition                   
		/*0x003*/         UINT8        Available : 5;             // 3 BitPosition                   
	};                                                                             
}MMSUPPORT_FLAGS, *PMMSUPPORT_FLAGS;                                               

typedef struct _MMSUPPORT                        // 21 elements, 0x6C bytes (sizeof) 
{                                                                                    
	/*0x000*/     EX_PUSH_LOCK WorkingSetMutex;        // 7 elements, 0x4 bytes (sizeof)   
	/*0x004*/     struct _KGATE* ExitGate;                                                         
	/*0x008*/     VOID*        AccessLog;                                                          
	/*0x00C*/     struct _LIST_ENTRY WorkingSetExpansionLinks; // 2 elements, 0x8 bytes (sizeof)   
	/*0x014*/     ULONG32      AgeDistribution[7];                                                 
	/*0x030*/     ULONG32      MinimumWorkingSetSize;                                              
	/*0x034*/     ULONG32      WorkingSetSize;                                                     
	/*0x038*/     ULONG32      WorkingSetPrivateSize;                                              
	/*0x03C*/     ULONG32      MaximumWorkingSetSize;                                              
	/*0x040*/     ULONG32      ChargedWslePages;                                                   
	/*0x044*/     ULONG32      ActualWslePages;                                                    
	/*0x048*/     ULONG32      WorkingSetSizeOverhead;                                             
	/*0x04C*/     ULONG32      PeakWorkingSetSize;                                                 
	/*0x050*/     ULONG32      HardFaultCount;                                                     
	/*0x054*/     struct _MMWSL* VmWorkingSetList;                                                 
	/*0x058*/     UINT16       NextPageColor;                                                      
	/*0x05A*/     UINT16       LastTrimStamp;                                                      
	/*0x05C*/     ULONG32      PageFaultCount;                                                     
	/*0x060*/     ULONG32      RepurposeCount;                                                     
	/*0x064*/     ULONG32      Spare[1];                                                           
	/*0x068*/     struct _MMSUPPORT_FLAGS Flags;               // 15 elements, 0x4 bytes (sizeof)  
}MMSUPPORT, *PMMSUPPORT;

typedef struct _KGDTENTRY                 // 3 elements, 0x8 bytes (sizeof)  
{                                                                            
	/*0x000*/     UINT16       LimitLow;                                                   
	/*0x002*/     UINT16       BaseLow;                                                    
	union                                 // 2 elements, 0x4 bytes (sizeof)  
	{                                                                        
		struct                            // 4 elements, 0x4 bytes (sizeof)  
		{                                                                    
			/*0x004*/             UINT8        BaseMid;                                            
			/*0x005*/             UINT8        Flags1;                                             
			/*0x006*/             UINT8        Flags2;                                             
			/*0x007*/             UINT8        BaseHi;                                             
		}Bytes;                                                              
		struct                            // 10 elements, 0x4 bytes (sizeof) 
		{                                                                    
			/*0x004*/             ULONG32      BaseMid : 8;     // 0 BitPosition                   
			/*0x004*/             ULONG32      Type : 5;        // 8 BitPosition                   
			/*0x004*/             ULONG32      Dpl : 2;         // 13 BitPosition                  
			/*0x004*/             ULONG32      Pres : 1;        // 15 BitPosition                  
			/*0x004*/             ULONG32      LimitHi : 4;     // 16 BitPosition                  
			/*0x004*/             ULONG32      Sys : 1;         // 20 BitPosition                  
			/*0x004*/             ULONG32      Reserved_0 : 1;  // 21 BitPosition                  
			/*0x004*/             ULONG32      Default_Big : 1; // 22 BitPosition                  
			/*0x004*/             ULONG32      Granularity : 1; // 23 BitPosition                  
			/*0x004*/             ULONG32      BaseHi : 8;      // 24 BitPosition                  
		}Bits;                                                               
	}HighWord;                                                               
}KGDTENTRY, *PKGDTENTRY;

typedef struct _KIDTENTRY        // 4 elements, 0x8 bytes (sizeof) 
{                                                                  
	/*0x000*/     UINT16       Offset;                                           
	/*0x002*/     UINT16       Selector;                                         
	/*0x004*/     UINT16       Access;                                           
	/*0x006*/     UINT16       ExtendedOffset;                                   
}KIDTENTRY, *PKIDTENTRY;

typedef struct _KAFFINITY_EX // 4 elements, 0xC bytes (sizeof) 
{                                                              
	/*0x000*/     UINT16       Count;                                        
	/*0x002*/     UINT16       Size;                                         
	/*0x004*/     ULONG32      Reserved;                                     
	/*0x008*/     ULONG32      Bitmap[1];                                    
}KAFFINITY_EX, *PKAFFINITY_EX;

typedef union _KEXECUTE_OPTIONS                           // 9 elements, 0x1 bytes (sizeof) 
{                                                                                           
	struct                                                // 8 elements, 0x1 bytes (sizeof) 
	{                                                                                       
		/*0x000*/         UINT8        ExecuteDisable : 1;                  // 0 BitPosition                  
		/*0x000*/         UINT8        ExecuteEnable : 1;                   // 1 BitPosition                  
		/*0x000*/         UINT8        DisableThunkEmulation : 1;           // 2 BitPosition                  
		/*0x000*/         UINT8        Permanent : 1;                       // 3 BitPosition                  
		/*0x000*/         UINT8        ExecuteDispatchEnable : 1;           // 4 BitPosition                  
		/*0x000*/         UINT8        ImageDispatchEnable : 1;             // 5 BitPosition                  
		/*0x000*/         UINT8        DisableExceptionChainValidation : 1; // 6 BitPosition                  
		/*0x000*/         UINT8        Spare : 1;                           // 7 BitPosition                  
	};                                                                                      
	/*0x000*/     UINT8        ExecuteOptions;                                                            
}KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS;

typedef union _KSTACK_COUNT           // 3 elements, 0x4 bytes (sizeof) 
{                                                                       
	/*0x000*/     LONG32       Value;                                                 
	struct                            // 2 elements, 0x4 bytes (sizeof) 
	{                                                                   
		/*0x000*/         ULONG32      State : 3;       // 0 BitPosition                  
		/*0x000*/         ULONG32      StackCount : 29; // 3 BitPosition                  
	};                                                                  
}KSTACK_COUNT, *PKSTACK_COUNT;

typedef struct _ALPC_PROCESS_CONTEXT  // 3 elements, 0x10 bytes (sizeof) 
{                                                                        
	/*0x000*/     EX_PUSH_LOCK Lock;        // 7 elements, 0x4 bytes (sizeof)  
	/*0x004*/     struct _LIST_ENTRY ViewListHead;  // 2 elements, 0x8 bytes (sizeof)  
	/*0x00C*/     ULONG32      PagedPoolQuotaCache;                                    
}ALPC_PROCESS_CONTEXT, *PALPC_PROCESS_CONTEXT;

typedef struct _PEB                                                                               // 91 elements, 0x248 bytes (sizeof) 
{                                                                                                                                      
	/*0x000*/     UINT8        InheritedAddressSpace;                                                                                                
	/*0x001*/     UINT8        ReadImageFileExecOptions;                                                                                             
	/*0x002*/     UINT8        BeingDebugged;                                                                                                        
	union                                                                                         // 2 elements, 0x1 bytes (sizeof)    
	{                                                                                                                                  
		/*0x003*/         UINT8        BitField;                                                                                                         
		struct                                                                                    // 6 elements, 0x1 bytes (sizeof)    
		{                                                                                                                              
			/*0x003*/             UINT8        ImageUsesLargePages : 1;                                                 // 0 BitPosition                     
			/*0x003*/             UINT8        IsProtectedProcess : 1;                                                  // 1 BitPosition                     
			/*0x003*/             UINT8        IsLegacyProcess : 1;                                                     // 2 BitPosition                     
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;                                         // 3 BitPosition                     
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1;                                        // 4 BitPosition                     
			/*0x003*/             UINT8        SpareBits : 3;                                                           // 5 BitPosition                     
		};                                                                                                                             
	};                                                                                                                                 
	/*0x004*/     VOID*        Mutant;                                                                                                               
	/*0x008*/     VOID*        ImageBaseAddress;                                                                                                     
	/*0x00C*/     struct _PEB_LDR_DATA* Ldr;                                                                                                         
	/*0x010*/     VOID*	ProcessParameters;                                                                            
	/*0x014*/     VOID*        SubSystemData;                                                                                                        
	/*0x018*/     VOID*        ProcessHeap;                                                                                                          
	/*0x01C*/     struct _RTL_CRITICAL_SECTION* FastPebLock;                                                                                         
	/*0x020*/     VOID*        AtlThunkSListPtr;                                                                                                     
	/*0x024*/     VOID*        IFEOKey;                                                                                                              
	union                                                                                         // 2 elements, 0x4 bytes (sizeof)    
	{                                                                                                                                  
		/*0x028*/         ULONG32      CrossProcessFlags;                                                                                                
		struct                                                                                    // 6 elements, 0x4 bytes (sizeof)    
		{                                                                                                                              
			/*0x028*/             ULONG32      ProcessInJob : 1;                                                        // 0 BitPosition                     
			/*0x028*/             ULONG32      ProcessInitializing : 1;                                                 // 1 BitPosition                     
			/*0x028*/             ULONG32      ProcessUsingVEH : 1;                                                     // 2 BitPosition                     
			/*0x028*/             ULONG32      ProcessUsingVCH : 1;                                                     // 3 BitPosition                     
			/*0x028*/             ULONG32      ProcessUsingFTH : 1;                                                     // 4 BitPosition                     
			/*0x028*/             ULONG32      ReservedBits0 : 27;                                                      // 5 BitPosition                     
		};                                                                                                                             
	};                                                                                                                                 
	union                                                                                         // 2 elements, 0x4 bytes (sizeof)    
	{                                                                                                                                  
		/*0x02C*/         VOID*        KernelCallbackTable;                                                                                              
		/*0x02C*/         VOID*        UserSharedInfoPtr;                                                                                                
	};                                                                                                                                 
	/*0x030*/     ULONG32      SystemReserved[1];                                                                                                    
	/*0x034*/     ULONG32      AtlThunkSListPtr32;                                                                                                   
	/*0x038*/     VOID*        ApiSetMap;                                                                                                            
	/*0x03C*/     ULONG32      TlsExpansionCounter;                                                                                                  
	/*0x040*/     VOID*        TlsBitmap;                                                                                                            
	/*0x044*/     ULONG32      TlsBitmapBits[2];                                                                                                     
	/*0x04C*/     VOID*        ReadOnlySharedMemoryBase;                                                                                             
	/*0x050*/     VOID*        HotpatchInformation;                                                                                                  
	/*0x054*/     VOID**       ReadOnlyStaticServerData;                                                                                             
	/*0x058*/     VOID*        AnsiCodePageData;                                                                                                     
	/*0x05C*/     VOID*        OemCodePageData;                                                                                                      
	/*0x060*/     VOID*        UnicodeCaseTableData;                                                                                                 
	/*0x064*/     ULONG32      NumberOfProcessors;                                                                                                   
	/*0x068*/     ULONG32      NtGlobalFlag;                                                                                                         
	/*0x06C*/     UINT8        _PADDING0_[0x4];                                                                                                      
	/*0x070*/     union _LARGE_INTEGER CriticalSectionTimeout;                                                  // 4 elements, 0x8 bytes (sizeof)    
	/*0x078*/     ULONG32      HeapSegmentReserve;                                                                                                   
	/*0x07C*/     ULONG32      HeapSegmentCommit;                                                                                                    
	/*0x080*/     ULONG32      HeapDeCommitTotalFreeThreshold;                                                                                       
	/*0x084*/     ULONG32      HeapDeCommitFreeBlockThreshold;                                                                                       
	/*0x088*/     ULONG32      NumberOfHeaps;                                                                                                        
	/*0x08C*/     ULONG32      MaximumNumberOfHeaps;                                                                                                 
	/*0x090*/     VOID**       ProcessHeaps;                                                                                                         
	/*0x094*/     VOID*        GdiSharedHandleTable;                                                                                                 
	/*0x098*/     VOID*        ProcessStarterHelper;                                                                                                 
	/*0x09C*/     ULONG32      GdiDCAttributeList;                                                                                                   
	/*0x0A0*/     struct _RTL_CRITICAL_SECTION* LoaderLock;                                                                                          
	/*0x0A4*/     ULONG32      OSMajorVersion;                                                                                                       
	/*0x0A8*/     ULONG32      OSMinorVersion;                                                                                                       
	/*0x0AC*/     UINT16       OSBuildNumber;                                                                                                        
	/*0x0AE*/     UINT16       OSCSDVersion;                                                                                                         
	/*0x0B0*/     ULONG32      OSPlatformId;                                                                                                         
	/*0x0B4*/     ULONG32      ImageSubsystem;                                                                                                       
	/*0x0B8*/     ULONG32      ImageSubsystemMajorVersion;                                                                                           
	/*0x0BC*/     ULONG32      ImageSubsystemMinorVersion;                                                                                           
	/*0x0C0*/     ULONG32      ActiveProcessAffinityMask;                                                                                            
	/*0x0C4*/     ULONG32      GdiHandleBuffer[34];                                                                                                  
	/*0x14C*/     VOID* PostProcessInitRoutine;                                      
	/*0x150*/     VOID*        TlsExpansionBitmap;                                                                                                   
	/*0x154*/     ULONG32      TlsExpansionBitmapBits[32];                                                                                           
	/*0x1D4*/     ULONG32      SessionId;                                                                                                            
	/*0x1D8*/     union _ULARGE_INTEGER AppCompatFlags;                                                         // 4 elements, 0x8 bytes (sizeof)    
	/*0x1E0*/     union _ULARGE_INTEGER AppCompatFlagsUser;                                                     // 4 elements, 0x8 bytes (sizeof)    
	/*0x1E8*/     VOID*        pShimData;                                                                                                            
	/*0x1EC*/     VOID*        AppCompatInfo;                                                                                                        
	/*0x1F0*/     struct _UNICODE_STRING CSDVersion;                                                            // 3 elements, 0x8 bytes (sizeof)    
	/*0x1F8*/     VOID* ActivationContextData;                                                                            
	/*0x1FC*/     VOID* ProcessAssemblyStorageMap;                                                                           
	/*0x200*/     VOID* SystemDefaultActivationContextData;                                                               
	/*0x204*/     VOID* SystemAssemblyStorageMap;                                                                            
	/*0x208*/     ULONG32      MinimumStackCommit;                                                                                                   
	/*0x20C*/     VOID* FlsCallback;                                                                                            
	/*0x210*/     struct _LIST_ENTRY FlsListHead;                                                               // 2 elements, 0x8 bytes (sizeof)    
	/*0x218*/     VOID*        FlsBitmap;                                                                                                            
	/*0x21C*/     ULONG32      FlsBitmapBits[4];                                                                                                     
	/*0x22C*/     ULONG32      FlsHighIndex;                                                                                                         
	/*0x230*/     VOID*        WerRegistrationData;                                                                                                  
	/*0x234*/     VOID*        WerShipAssertPtr;                                                                                                     
	/*0x238*/     VOID*        pContextData;                                                                                                         
	/*0x23C*/     VOID*        pImageHeaderHash;                                                                                                     
	union                                                                                         // 2 elements, 0x4 bytes (sizeof)    
	{                                                                                                                                  
		/*0x240*/         ULONG32      TracingFlags;                                                                                                     
		struct                                                                                    // 3 elements, 0x4 bytes (sizeof)    
		{                                                                                                                              
			/*0x240*/             ULONG32      HeapTracingEnabled : 1;                                                  // 0 BitPosition                     
			/*0x240*/             ULONG32      CritSecTracingEnabled : 1;                                               // 1 BitPosition                     
			/*0x240*/             ULONG32      SpareTracingBits : 30;                                                   // 2 BitPosition                     
		};                                                                                                                             
	};                                                                                                                                 
}PEB, *PPEB;

typedef struct _KPROCESS_S                       // 34 elements, 0x98 bytes (sizeof) 
{                                                                                  
	/*0x000*/     struct _DISPATCHER_HEADER Header;          // 30 elements, 0x10 bytes (sizeof) 
	/*0x010*/     struct _LIST_ENTRY ProfileListHead;        // 2 elements, 0x8 bytes (sizeof)   
	/*0x018*/     ULONG32      DirectoryTableBase;                                               
	/*0x01C*/     struct _KGDTENTRY LdtDescriptor;           // 3 elements, 0x8 bytes (sizeof)   
	/*0x024*/     struct _KIDTENTRY Int21Descriptor;         // 4 elements, 0x8 bytes (sizeof)   
	/*0x02C*/     struct _LIST_ENTRY ThreadListHead;         // 2 elements, 0x8 bytes (sizeof)   
	/*0x034*/     ULONG32      ProcessLock;                                                      
	/*0x038*/     struct _KAFFINITY_EX Affinity;             // 4 elements, 0xC bytes (sizeof)   
	/*0x044*/     struct _LIST_ENTRY ReadyListHead;          // 2 elements, 0x8 bytes (sizeof)   
	/*0x04C*/     struct _SINGLE_LIST_ENTRY SwapListEntry;   // 1 elements, 0x4 bytes (sizeof)   
	/*0x050*/     struct _KAFFINITY_EX ActiveProcessors;     // 4 elements, 0xC bytes (sizeof)   
	union                                      // 2 elements, 0x4 bytes (sizeof)   
	{                                                                              
		struct                                 // 5 elements, 0x4 bytes (sizeof)   
		{                                                                          
			/*0x05C*/             LONG32       AutoAlignment : 1;    // 0 BitPosition                    
			/*0x05C*/             LONG32       DisableBoost : 1;     // 1 BitPosition                    
			/*0x05C*/             LONG32       DisableQuantum : 1;   // 2 BitPosition                    
			/*0x05C*/             ULONG32      ActiveGroupsMask : 1; // 3 BitPosition                    
			/*0x05C*/             LONG32       ReservedFlags : 28;   // 4 BitPosition                    
		};                                                                         
		/*0x05C*/         LONG32       ProcessFlags;                                                 
	};                                                                             
	/*0x060*/     CHAR         BasePriority;                                                     
	/*0x061*/     CHAR         QuantumReset;                                                     
	/*0x062*/     UINT8        Visited;                                                          
	/*0x063*/     UINT8        Unused3;                                                          
	/*0x064*/     ULONG32      ThreadSeed[1];                                                    
	/*0x068*/     UINT16       IdealNode[1];                                                     
	/*0x06A*/     UINT16       IdealGlobalNode;                                                  
	/*0x06C*/     union _KEXECUTE_OPTIONS Flags;             // 9 elements, 0x1 bytes (sizeof)   
	/*0x06D*/     UINT8        Unused1;                                                          
	/*0x06E*/     UINT16       IopmOffset;                                                       
	/*0x070*/     ULONG32      Unused4;                                                          
	/*0x074*/     union _KSTACK_COUNT StackCount;            // 3 elements, 0x4 bytes (sizeof)   
	/*0x078*/     struct _LIST_ENTRY ProcessListEntry;       // 2 elements, 0x8 bytes (sizeof)   
	/*0x080*/     UINT64       CycleTime;                                                        
	/*0x088*/     ULONG32      KernelTime;                                                       
	/*0x08C*/     ULONG32      UserTime;                                                         
	/*0x090*/     VOID*        VdmTrapcHandler;                                                  
	/*0x094*/     UINT8        _PADDING0_[0x4];                                                  
}KPROCESS_S, *PKPROCESS_S;

typedef struct _EPROCESS_S												// 134 elements, 0x2C0 bytes (sizeof) 
{                                                                                                            
	/*0x000*/     KPROCESS_S Pcb;									// 34 elements, 0x98 bytes (sizeof)   
	/*0x098*/     EX_PUSH_LOCK_S ProcessLock;						// 7 elements, 0x4 bytes (sizeof)     
	/*0x09C*/     UINT8        _PADDING0_[0x4];                                                                            
	/*0x0A0*/     union _LARGE_INTEGER CreateTime;						// 4 elements, 0x8 bytes (sizeof)     
	/*0x0A8*/     union _LARGE_INTEGER ExitTime;						// 4 elements, 0x8 bytes (sizeof)     
	/*0x0B0*/     struct _EX_RUNDOWN_REF RundownProtect;				// 2 elements, 0x4 bytes (sizeof)     
	/*0x0B4*/     VOID*        UniqueProcessId;                                                                            
	/*0x0B8*/     struct _LIST_ENTRY ActiveProcessLinks;				// 2 elements, 0x8 bytes (sizeof)     
	/*0x0C0*/     ULONG32      ProcessQuotaUsage[2];                                                                       
	/*0x0C8*/     ULONG32      ProcessQuotaPeak[2];                                                                        
	/*0x0D0*/     ULONG32      CommitCharge;                                                                               
	/*0x0D4*/     struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                                                                
	/*0x0D8*/     struct _PS_CPU_QUOTA_BLOCK* CpuQuotaBlock;                                                               
	/*0x0DC*/     ULONG32      PeakVirtualSize;                                                                            
	/*0x0E0*/     ULONG32      VirtualSize;                                                                                
	/*0x0E4*/     struct _LIST_ENTRY SessionProcessLinks;				// 2 elements, 0x8 bytes (sizeof)     
	/*0x0EC*/     VOID*        DebugPort;                                                                                  
	union																// 3 elements, 0x4 bytes (sizeof)     
	{                                                                                                        
		/*0x0F0*/         VOID*        ExceptionPortData;                                                                      
		/*0x0F0*/         ULONG32      ExceptionPortValue;                                                                     
		/*0x0F0*/         ULONG32      ExceptionPortState : 3;			// 0 BitPosition                      
	};                                                                                                       
	/*0x0F4*/     struct _HANDLE_TABLE* ObjectTable;                                                                       
	/*0x0F8*/     struct _EX_FAST_REF Token;							// 3 elements, 0x4 bytes (sizeof)     
	/*0x0FC*/     ULONG32      WorkingSetPage;                                                                             
	/*0x100*/     EX_PUSH_LOCK_S AddressCreationLock;					// 7 elements, 0x4 bytes (sizeof)     
	/*0x104*/     struct _ETHREAD* RotateInProgress;                                                                       
	/*0x108*/     struct _ETHREAD* ForkInProgress;                                                                         
	/*0x10C*/     ULONG32      HardwareTrigger;                                                                            
	/*0x110*/     PVOID		   PhysicalVadRoot;                                                                   
	/*0x114*/     VOID*        CloneRoot;                                                                                  
	/*0x118*/     ULONG32      NumberOfPrivatePages;                                                                       
	/*0x11C*/     ULONG32      NumberOfLockedPages;                                                                        
	/*0x120*/     VOID*        Win32Process;                                                                               
	/*0x124*/     PVOID		   Job;                                                                                       
	/*0x128*/     VOID*        SectionObject;                                                                              
	/*0x12C*/     VOID*        SectionBaseAddress;                                                                         
	/*0x130*/     ULONG32      Cookie;                                                                                     
	/*0x134*/     ULONG32      Spare8;                                                                                     
	/*0x138*/     PVOID		   WorkingSetWatch;                                                              
	/*0x13C*/     VOID*        Win32WindowStation;                                                                         
	/*0x140*/     VOID*        InheritedFromUniqueProcessId;                                                               
	/*0x144*/     VOID*        LdtInformation;                                                                             
	/*0x148*/     VOID*        VdmObjects;                                                                                 
	/*0x14C*/     ULONG32      ConsoleHostProcess;                                                                         
	/*0x150*/     VOID*        DeviceMap;                                                                                  
	/*0x154*/     VOID*        EtwDataSource;                                                                              
	/*0x158*/     VOID*        FreeTebHint;                                                                                
	/*0x15C*/     UINT8        _PADDING1_[0x4];                                                                            
	union                                                              // 2 elements, 0x8 bytes (sizeof)     
	{                                                                                                        
		/*0x160*/         UINT64	   PageDirectoryPte;                         // 16 elements, 0x8 bytes (sizeof)    
		/*0x160*/         UINT64       Filler;                                                                                 
	};                                                                                                       
	/*0x168*/     VOID*        Session;                                                                                    
	/*0x16C*/     UINT8        ImageFileName[15];                                                                          
	/*0x17B*/     UINT8        PriorityClass;                                                                              
	/*0x17C*/     struct _LIST_ENTRY JobLinks;                                       // 2 elements, 0x8 bytes (sizeof)     
	/*0x184*/     VOID*        LockedPagesList;                                                                            
	/*0x188*/     struct _LIST_ENTRY ThreadListHead;                                 // 2 elements, 0x8 bytes (sizeof)     
	/*0x190*/     VOID*        SecurityPort;                                                                               
	/*0x194*/     VOID*        PaeTop;                                                                                     
	/*0x198*/     ULONG32      ActiveThreads;                                                                              
	/*0x19C*/     ULONG32      ImagePathHash;                                                                              
	/*0x1A0*/     ULONG32      DefaultHardErrorProcessing;                                                                 
	/*0x1A4*/     LONG32       LastThreadExitStatus;                                                                       
	/*0x1A8*/     struct _PEB* Peb;                                                                                        
	/*0x1AC*/     struct _EX_FAST_REF PrefetchTrace;                                 // 3 elements, 0x4 bytes (sizeof)     
	/*0x1B0*/     union _LARGE_INTEGER ReadOperationCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x1B8*/     union _LARGE_INTEGER WriteOperationCount;                          // 4 elements, 0x8 bytes (sizeof)     
	/*0x1C0*/     union _LARGE_INTEGER OtherOperationCount;                          // 4 elements, 0x8 bytes (sizeof)     
	/*0x1C8*/     union _LARGE_INTEGER ReadTransferCount;                            // 4 elements, 0x8 bytes (sizeof)     
	/*0x1D0*/     union _LARGE_INTEGER WriteTransferCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x1D8*/     union _LARGE_INTEGER OtherTransferCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x1E0*/     ULONG32      CommitChargeLimit;                                                                          
	/*0x1E4*/     ULONG32      CommitChargePeak;                                                                           
	/*0x1E8*/     VOID*        AweInfo;                                                                                    
	/*0x1EC*/     VOID*		   SeAuditProcessCreationInfo; // 1 elements, 0x4 bytes (sizeof)     
	/*0x1F0*/     struct _MMSUPPORT Vm;                                              // 21 elements, 0x6C bytes (sizeof)   
	/*0x25C*/     struct _LIST_ENTRY MmProcessLinks;                                 // 2 elements, 0x8 bytes (sizeof)     
	/*0x264*/     VOID*        HighestUserAddress;                                                                         
	/*0x268*/     ULONG32      ModifiedPageCount;                                                                          
	union                                                              // 2 elements, 0x4 bytes (sizeof)     
	{                                                                                                        
		/*0x26C*/         ULONG32      Flags2;                                                                                 
		struct                                                         // 20 elements, 0x4 bytes (sizeof)    
		{                                                                                                    
			/*0x26C*/             ULONG32      JobNotReallyActive : 1;                       // 0 BitPosition                      
			/*0x26C*/             ULONG32      AccountingFolded : 1;                         // 1 BitPosition                      
			/*0x26C*/             ULONG32      NewProcessReported : 1;                       // 2 BitPosition                      
			/*0x26C*/             ULONG32      ExitProcessReported : 1;                      // 3 BitPosition                      
			/*0x26C*/             ULONG32      ReportCommitChanges : 1;                      // 4 BitPosition                      
			/*0x26C*/             ULONG32      LastReportMemory : 1;                         // 5 BitPosition                      
			/*0x26C*/             ULONG32      ReportPhysicalPageChanges : 1;                // 6 BitPosition                      
			/*0x26C*/             ULONG32      HandleTableRundown : 1;                       // 7 BitPosition                      
			/*0x26C*/             ULONG32      NeedsHandleRundown : 1;                       // 8 BitPosition                      
			/*0x26C*/             ULONG32      RefTraceEnabled : 1;                          // 9 BitPosition                      
			/*0x26C*/             ULONG32      NumaAware : 1;                                // 10 BitPosition                     
			/*0x26C*/             ULONG32      ProtectedProcess : 1;                         // 11 BitPosition                     
			/*0x26C*/             ULONG32      DefaultPagePriority : 3;                      // 12 BitPosition                     
			/*0x26C*/             ULONG32      PrimaryTokenFrozen : 1;                       // 15 BitPosition                     
			/*0x26C*/             ULONG32      ProcessVerifierTarget : 1;                    // 16 BitPosition                     
			/*0x26C*/             ULONG32      StackRandomizationDisabled : 1;               // 17 BitPosition                     
			/*0x26C*/             ULONG32      AffinityPermanent : 1;                        // 18 BitPosition                     
			/*0x26C*/             ULONG32      AffinityUpdateEnable : 1;                     // 19 BitPosition                     
			/*0x26C*/             ULONG32      PropagateNode : 1;                            // 20 BitPosition                     
			/*0x26C*/             ULONG32      ExplicitAffinity : 1;                         // 21 BitPosition                     
		};                                                                                                   
	};                                                                                                       
	union                                                              // 2 elements, 0x4 bytes (sizeof)     
	{                                                                                                        
		/*0x270*/         ULONG32      Flags;                                                                                  
		struct                                                         // 29 elements, 0x4 bytes (sizeof)    
		{                                                                                                    
			/*0x270*/             ULONG32      CreateReported : 1;                           // 0 BitPosition                      
			/*0x270*/             ULONG32      NoDebugInherit : 1;                           // 1 BitPosition                      
			/*0x270*/             ULONG32      ProcessExiting : 1;                           // 2 BitPosition                      
			/*0x270*/             ULONG32      ProcessDelete : 1;                            // 3 BitPosition                      
			/*0x270*/             ULONG32      Wow64SplitPages : 1;                          // 4 BitPosition                      
			/*0x270*/             ULONG32      VmDeleted : 1;                                // 5 BitPosition                      
			/*0x270*/             ULONG32      OutswapEnabled : 1;                           // 6 BitPosition                      
			/*0x270*/             ULONG32      Outswapped : 1;                               // 7 BitPosition                      
			/*0x270*/             ULONG32      ForkFailed : 1;                               // 8 BitPosition                      
			/*0x270*/             ULONG32      Wow64VaSpace4Gb : 1;                          // 9 BitPosition                      
			/*0x270*/             ULONG32      AddressSpaceInitialized : 2;                  // 10 BitPosition                     
			/*0x270*/             ULONG32      SetTimerResolution : 1;                       // 12 BitPosition                     
			/*0x270*/             ULONG32      BreakOnTermination : 1;                       // 13 BitPosition                     
			/*0x270*/             ULONG32      DeprioritizeViews : 1;                        // 14 BitPosition                     
			/*0x270*/             ULONG32      WriteWatch : 1;                               // 15 BitPosition                     
			/*0x270*/             ULONG32      ProcessInSession : 1;                         // 16 BitPosition                     
			/*0x270*/             ULONG32      OverrideAddressSpace : 1;                     // 17 BitPosition                     
			/*0x270*/             ULONG32      HasAddressSpace : 1;                          // 18 BitPosition                     
			/*0x270*/             ULONG32      LaunchPrefetched : 1;                         // 19 BitPosition                     
			/*0x270*/             ULONG32      InjectInpageErrors : 1;                       // 20 BitPosition                     
			/*0x270*/             ULONG32      VmTopDown : 1;                                // 21 BitPosition                     
			/*0x270*/             ULONG32      ImageNotifyDone : 1;                          // 22 BitPosition                     
			/*0x270*/             ULONG32      PdeUpdateNeeded : 1;                          // 23 BitPosition                     
			/*0x270*/             ULONG32      VdmAllowed : 1;                               // 24 BitPosition                     
			/*0x270*/             ULONG32      CrossSessionCreate : 1;                       // 25 BitPosition                     
			/*0x270*/             ULONG32      ProcessInserted : 1;                          // 26 BitPosition                     
			/*0x270*/             ULONG32      DefaultIoPriority : 3;                        // 27 BitPosition                     
			/*0x270*/             ULONG32      ProcessSelfDelete : 1;                        // 30 BitPosition                     
			/*0x270*/             ULONG32      SetTimerResolutionLink : 1;                   // 31 BitPosition                     
		};                                                                                                   
	};                                                                                                       
	/*0x274*/     LONG32       ExitStatus;                                                                                 
	/*0x278*/     struct _MM_AVL_TABLE VadRoot;                                      // 6 elements, 0x20 bytes (sizeof)    
	/*0x298*/     struct _ALPC_PROCESS_CONTEXT AlpcContext;                          // 3 elements, 0x10 bytes (sizeof)    
	/*0x2A8*/     struct _LIST_ENTRY TimerResolutionLink;                            // 2 elements, 0x8 bytes (sizeof)     
	/*0x2B0*/     ULONG32      RequestedTimerResolution;                                                                   
	/*0x2B4*/     ULONG32      ActiveThreadsHighWatermark;                                                                 
	/*0x2B8*/     ULONG32      SmallestTimerResolution;                                                                    
	/*0x2BC*/     struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;                                                
}EPROCESS_S, *PEPROCESS_S;

typedef union _PS_CLIENT_SECURITY_CONTEXT    // 4 elements, 0x4 bytes (sizeof) 
{                                                                              
	/*0x000*/     ULONG32      ImpersonationData;                                            
	/*0x000*/     VOID*        ImpersonationToken;                                           
	struct                                   // 2 elements, 0x4 bytes (sizeof) 
	{                                                                          
		/*0x000*/         ULONG32      ImpersonationLevel : 2; // 0 BitPosition                  
		/*0x000*/         ULONG32      EffectiveOnly : 1;      // 2 BitPosition                  
	};                                                                         
}PS_CLIENT_SECURITY_CONTEXT, *PPS_CLIENT_SECURITY_CONTEXT;

typedef union _KWAIT_STATUS_REGISTER // 8 elements, 0x1 bytes (sizeof) 
{                                                                      
	/*0x000*/     UINT8        Flags;                                                
	struct                           // 7 elements, 0x1 bytes (sizeof) 
	{                                                                  
		/*0x000*/         UINT8        State : 2;      // 0 BitPosition                  
		/*0x000*/         UINT8        Affinity : 1;   // 2 BitPosition                  
		/*0x000*/         UINT8        Priority : 1;   // 3 BitPosition                  
		/*0x000*/         UINT8        Apc : 1;        // 4 BitPosition                  
		/*0x000*/         UINT8        UserApc : 1;    // 5 BitPosition                  
		/*0x000*/         UINT8        Alert : 1;      // 6 BitPosition                  
		/*0x000*/         UINT8        Unused : 1;     // 7 BitPosition                  
	};                                                                 
}KWAIT_STATUS_REGISTER, *PKWAIT_STATUS_REGISTER;

typedef struct _KAPC_STATE_S             // 5 elements, 0x18 bytes (sizeof) 
{                                                                         
	/*0x000*/     struct _LIST_ENTRY ApcListHead[2];                                    
	/*0x010*/     struct _KPROCESS_S* Process;                                            
	/*0x014*/     UINT8        KernelApcInProgress;                                     
	/*0x015*/     UINT8        KernelApcPending;                                        
	/*0x016*/     UINT8        UserApcPending;                                          
	/*0x017*/     UINT8        _PADDING0_[0x1];                                         
}KAPC_STATE_S, *PKAPC_STATE_S;

typedef struct _KTHREAD_S                                 // 115 elements, 0x200 bytes (sizeof) 
{                                                                                             
	/*0x000*/     struct _DISPATCHER_HEADER Header;                   // 30 elements, 0x10 bytes (sizeof)   
	/*0x010*/     UINT64       CycleTime;                                                                   
	/*0x018*/     ULONG32      HighCycleTime;                                                               
	/*0x01C*/     UINT8        _PADDING0_[0x4];                                                             
	/*0x020*/     UINT64       QuantumTarget;                                                               
	/*0x028*/     VOID*        InitialStack;                                                                
	/*0x02C*/     VOID*        StackLimit;                                                                  
	/*0x030*/     VOID*        KernelStack;                                                                 
	/*0x034*/     ULONG32      ThreadLock;                                                                  
	/*0x038*/     union _KWAIT_STATUS_REGISTER WaitRegister;          // 8 elements, 0x1 bytes (sizeof)     
	/*0x039*/     UINT8        Running;                                                                     
	/*0x03A*/     UINT8        Alerted[2];                                                                  
	union                                               // 2 elements, 0x4 bytes (sizeof)     
	{                                                                                         
		struct                                          // 14 elements, 0x4 bytes (sizeof)    
		{                                                                                     
			/*0x03C*/             ULONG32      KernelStackResident : 1;       // 0 BitPosition                      
			/*0x03C*/             ULONG32      ReadyTransition : 1;           // 1 BitPosition                      
			/*0x03C*/             ULONG32      ProcessReadyQueue : 1;         // 2 BitPosition                      
			/*0x03C*/             ULONG32      WaitNext : 1;                  // 3 BitPosition                      
			/*0x03C*/             ULONG32      SystemAffinityActive : 1;      // 4 BitPosition                      
			/*0x03C*/             ULONG32      Alertable : 1;                 // 5 BitPosition                      
			/*0x03C*/             ULONG32      GdiFlushActive : 1;            // 6 BitPosition                      
			/*0x03C*/             ULONG32      UserStackWalkActive : 1;       // 7 BitPosition                      
			/*0x03C*/             ULONG32      ApcInterruptRequest : 1;       // 8 BitPosition                      
			/*0x03C*/             ULONG32      ForceDeferSchedule : 1;        // 9 BitPosition                      
			/*0x03C*/             ULONG32      QuantumEndMigrate : 1;         // 10 BitPosition                     
			/*0x03C*/             ULONG32      UmsDirectedSwitchEnable : 1;   // 11 BitPosition                     
			/*0x03C*/             ULONG32      TimerActive : 1;               // 12 BitPosition                     
			/*0x03C*/             ULONG32      Reserved : 19;                 // 13 BitPosition                     
		};                                                                                    
		/*0x03C*/         LONG32       MiscFlags;                                                               
	};                                                                                        
	union                                               // 2 elements, 0x18 bytes (sizeof)    
	{                                                                                         
		/*0x040*/         struct _KAPC_STATE_S ApcState;                    // 5 elements, 0x18 bytes (sizeof)    
		struct                                          // 2 elements, 0x18 bytes (sizeof)    
		{                                                                                     
			/*0x040*/             UINT8        ApcStateFill[23];                                                    
			/*0x057*/             CHAR         Priority;                                                            
		};                                                                                    
	};                                                                                        
	/*0x058*/     ULONG32      NextProcessor;                                                               
	/*0x05C*/     ULONG32      DeferredProcessor;                                                           
	/*0x060*/     ULONG32      ApcQueueLock;                                                                
	/*0x064*/     ULONG32      ContextSwitches;                                                             
	/*0x068*/     UINT8        State;                                                                       
	/*0x069*/     CHAR         NpxState;                                                                    
	/*0x06A*/     UINT8        WaitIrql;                                                                    
	/*0x06B*/     CHAR         WaitMode;                                                                    
	/*0x06C*/     LONG32       WaitStatus;                                                                  
	/*0x070*/     struct _KWAIT_BLOCK* WaitBlockList;                                                       
	union                                               // 2 elements, 0x8 bytes (sizeof)     
	{                                                                                         
		/*0x074*/         struct _LIST_ENTRY WaitListEntry;               // 2 elements, 0x8 bytes (sizeof)     
		/*0x074*/         struct _SINGLE_LIST_ENTRY SwapListEntry;        // 1 elements, 0x4 bytes (sizeof)     
	};                                                                                        
	/*0x07C*/     struct _KQUEUE* Queue;                                                                    
	/*0x080*/     ULONG32      WaitTime;                                                                    
	union                                               // 2 elements, 0x4 bytes (sizeof)     
	{                                                                                         
		struct                                          // 2 elements, 0x4 bytes (sizeof)     
		{                                                                                     
			/*0x084*/             INT16        KernelApcDisable;                                                    
			/*0x086*/             INT16        SpecialApcDisable;                                                   
		};                                                                                    
		/*0x084*/         ULONG32      CombinedApcDisable;                                                      
	};                                                                                        
	/*0x088*/     VOID*        Teb;                                                                         
	/*0x08C*/     UINT8        _PADDING1_[0x4];                                                             
	/*0x090*/     struct _KTIMER Timer;                               // 5 elements, 0x28 bytes (sizeof)    
	union                                               // 2 elements, 0x4 bytes (sizeof)     
	{                                                                                         
		struct                                          // 11 elements, 0x4 bytes (sizeof)    
		{                                                                                     
			/*0x0B8*/             ULONG32      AutoAlignment : 1;             // 0 BitPosition                      
			/*0x0B8*/             ULONG32      DisableBoost : 1;              // 1 BitPosition                      
			/*0x0B8*/             ULONG32      EtwStackTraceApc1Inserted : 1; // 2 BitPosition                      
			/*0x0B8*/             ULONG32      EtwStackTraceApc2Inserted : 1; // 3 BitPosition                      
			/*0x0B8*/             ULONG32      CalloutActive : 1;             // 4 BitPosition                      
			/*0x0B8*/             ULONG32      ApcQueueable : 1;              // 5 BitPosition                      
			/*0x0B8*/             ULONG32      EnableStackSwap : 1;           // 6 BitPosition                      
			/*0x0B8*/             ULONG32      GuiThread : 1;                 // 7 BitPosition                      
			/*0x0B8*/             ULONG32      UmsPerformingSyscall : 1;      // 8 BitPosition                      
			/*0x0B8*/             ULONG32      VdmSafe : 1;                   // 9 BitPosition                      
			/*0x0B8*/             ULONG32      ReservedFlags : 22;            // 10 BitPosition                     
		};                                                                                    
		/*0x0B8*/         LONG32       ThreadFlags;                                                             
	};                                                                                        
	/*0x0BC*/     VOID*        ServiceTable;                                                                
	/*0x0C0*/     struct _KWAIT_BLOCK WaitBlock[4];                                                         
	/*0x120*/     struct _LIST_ENTRY QueueListEntry;                  // 2 elements, 0x8 bytes (sizeof)     
	/*0x128*/     struct _KTRAP_FRAME* TrapFrame;                                                           
	/*0x12C*/     VOID*        FirstArgument;                                                               
	union                                               // 2 elements, 0x4 bytes (sizeof)     
	{                                                                                         
		/*0x130*/         VOID*        CallbackStack;                                                           
		/*0x130*/         ULONG32      CallbackDepth;                                                           
	};                                                                                        
	/*0x134*/     UINT8        ApcStateIndex;                                                               
	/*0x135*/     CHAR         BasePriority;                                                                
	union                                               // 2 elements, 0x1 bytes (sizeof)     
	{                                                                                         
		/*0x136*/         CHAR         PriorityDecrement;                                                       
		struct                                          // 2 elements, 0x1 bytes (sizeof)     
		{                                                                                     
			/*0x136*/             UINT8        ForegroundBoost : 4;           // 0 BitPosition                      
			/*0x136*/             UINT8        UnusualBoost : 4;              // 4 BitPosition                      
		};                                                                                    
	};                                                                                        
	/*0x137*/     UINT8        Preempted;                                                                   
	/*0x138*/     UINT8        AdjustReason;                                                                
	/*0x139*/     CHAR         AdjustIncrement;                                                             
	/*0x13A*/     CHAR         PreviousMode;                                                                
	/*0x13B*/     CHAR         Saturation;                                                                  
	/*0x13C*/     ULONG32      SystemCallNumber;                                                            
	/*0x140*/     ULONG32      FreezeCount;                                                                 
	/*0x144*/     struct _GROUP_AFFINITY UserAffinity;                // 3 elements, 0xC bytes (sizeof)     
	/*0x150*/     PKPROCESS_S Process;                                                                
	/*0x154*/     struct _GROUP_AFFINITY Affinity;                    // 3 elements, 0xC bytes (sizeof)     
	/*0x160*/     ULONG32      IdealProcessor;                                                              
	/*0x164*/     ULONG32      UserIdealProcessor;                                                          
	/*0x168*/     struct _KAPC_STATE* ApcStatePointer[2];                                                   
	union                                               // 2 elements, 0x18 bytes (sizeof)    
	{                                                                                         
		/*0x170*/         struct _KAPC_STATE SavedApcState;               // 5 elements, 0x18 bytes (sizeof)    
		struct                                          // 2 elements, 0x18 bytes (sizeof)    
		{                                                                                     
			/*0x170*/             UINT8        SavedApcStateFill[23];                                               
			/*0x187*/             UINT8        WaitReason;                                                          
		};                                                                                    
	};                                                                                        
	/*0x188*/     CHAR         SuspendCount;                                                                
	/*0x189*/     CHAR         Spare1;                                                                      
	/*0x18A*/     UINT8        OtherPlatformFill;                                                           
	/*0x18B*/     UINT8        _PADDING2_[0x1];                                                             
	/*0x18C*/     VOID*        Win32Thread;                                                                 
	/*0x190*/     VOID*        StackBase;                                                                   
	union                                               // 7 elements, 0x30 bytes (sizeof)    
	{                                                                                         
		/*0x194*/         struct _KAPC SuspendApc;                        // 16 elements, 0x30 bytes (sizeof)   
		struct                                          // 2 elements, 0x30 bytes (sizeof)    
		{                                                                                     
			/*0x194*/             UINT8        SuspendApcFill0[1];                                                  
			/*0x195*/             UINT8        ResourceIndex;                                                       
			/*0x196*/             UINT8        _PADDING3_[0x2E];                                                    
		};                                                                                    
		struct                                          // 2 elements, 0x30 bytes (sizeof)    
		{                                                                                     
			/*0x194*/             UINT8        SuspendApcFill1[3];                                                  
			/*0x197*/             UINT8        QuantumReset;                                                        
			/*0x198*/             UINT8        _PADDING4_[0x2C];                                                    
		};                                                                                    
		struct                                          // 2 elements, 0x30 bytes (sizeof)    
		{                                                                                     
			/*0x194*/             UINT8        SuspendApcFill2[4];                                                  
			/*0x198*/             ULONG32      KernelTime;                                                          
			/*0x19C*/             UINT8        _PADDING5_[0x28];                                                    
		};                                                                                    
		struct                                          // 2 elements, 0x30 bytes (sizeof)    
		{                                                                                     
			/*0x194*/             UINT8        SuspendApcFill3[36];                                                 
			/*0x1B8*/             struct _KPRCB* WaitPrcb;                                                          
			/*0x1BC*/             UINT8        _PADDING6_[0x8];                                                     
		};                                                                                    
		struct                                          // 2 elements, 0x30 bytes (sizeof)    
		{                                                                                     
			/*0x194*/             UINT8        SuspendApcFill4[40];                                                 
			/*0x1BC*/             VOID*        LegoData;                                                            
			/*0x1C0*/             UINT8        _PADDING7_[0x4];                                                     
		};                                                                                    
		struct                                          // 2 elements, 0x30 bytes (sizeof)    
		{                                                                                     
			/*0x194*/             UINT8        SuspendApcFill5[47];                                                 
			/*0x1C3*/             UINT8        LargeStack;                                                          
		};                                                                                    
	};                                                                                        
	/*0x1C4*/     ULONG32      UserTime;                                                                    
	union                                               // 2 elements, 0x14 bytes (sizeof)    
	{                                                                                         
		/*0x1C8*/         struct _KSEMAPHORE SuspendSemaphore;            // 2 elements, 0x14 bytes (sizeof)    
		/*0x1C8*/         UINT8        SuspendSemaphorefill[20];                                                
	};                                                                                        
	/*0x1DC*/     ULONG32      SListFaultCount;                                                             
	/*0x1E0*/     struct _LIST_ENTRY ThreadListEntry;                 // 2 elements, 0x8 bytes (sizeof)     
	/*0x1E8*/     struct _LIST_ENTRY MutantListHead;                  // 2 elements, 0x8 bytes (sizeof)     
	/*0x1F0*/     VOID*        SListFaultAddress;                                                           
	/*0x1F4*/     struct _KTHREAD_COUNTERS* ThreadCounters;                                                 
	/*0x1F8*/     struct _XSTATE_SAVE* XStateSave;                                                          
	/*0x1FC*/     UINT8        _PADDING8_[0x4];                                                             
}KTHREAD_S, *PKTHREAD_S;

typedef struct _ETHREAD_S                                              // 88 elements, 0x2B8 bytes (sizeof)  
{                                                                                                          
	/*0x000*/     struct _KTHREAD_S Tcb;                                             // 115 elements, 0x200 bytes (sizeof) 
	/*0x200*/     union _LARGE_INTEGER CreateTime;                                 // 4 elements, 0x8 bytes (sizeof)     
	union                                                            // 2 elements, 0x8 bytes (sizeof)     
	{                                                                                                      
		/*0x208*/         union _LARGE_INTEGER ExitTime;                               // 4 elements, 0x8 bytes (sizeof)     
		/*0x208*/         struct _LIST_ENTRY KeyedWaitChain;                           // 2 elements, 0x8 bytes (sizeof)     
	};                                                                                                     
	/*0x210*/     LONG32       ExitStatus;                                                                               
	union                                                            // 2 elements, 0x8 bytes (sizeof)     
	{                                                                                                      
		/*0x214*/         struct _LIST_ENTRY PostBlockList;                            // 2 elements, 0x8 bytes (sizeof)     
		struct                                                       // 2 elements, 0x8 bytes (sizeof)     
		{                                                                                                  
			/*0x214*/             VOID*        ForwardLinkShadow;                                                                
			/*0x218*/             VOID*        StartAddress;                                                                     
		};                                                                                                 
	};                                                                                                     
	union                                                            // 3 elements, 0x4 bytes (sizeof)     
	{                                                                                                      
		/*0x21C*/         struct _TERMINATION_PORT* TerminationPort;                                                         
		/*0x21C*/         struct _ETHREAD* ReaperLink;                                                                       
		/*0x21C*/         VOID*        KeyedWaitValue;                                                                       
	};                                                                                                     
	/*0x220*/     ULONG32      ActiveTimerListLock;                                                                      
	/*0x224*/     struct _LIST_ENTRY ActiveTimerListHead;                          // 2 elements, 0x8 bytes (sizeof)     
	/*0x22C*/     struct _CLIENT_ID Cid;                                           // 2 elements, 0x8 bytes (sizeof)     
	union                                                            // 2 elements, 0x14 bytes (sizeof)    
	{                                                                                                      
		/*0x234*/         struct _KSEMAPHORE KeyedWaitSemaphore;                       // 2 elements, 0x14 bytes (sizeof)    
		/*0x234*/         struct _KSEMAPHORE AlpcWaitSemaphore;                        // 2 elements, 0x14 bytes (sizeof)    
	};                                                                                                     
	/*0x248*/     union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                // 4 elements, 0x4 bytes (sizeof)     
	/*0x24C*/     struct _LIST_ENTRY IrpList;                                      // 2 elements, 0x8 bytes (sizeof)     
	/*0x254*/     ULONG32      TopLevelIrp;                                                                              
	/*0x258*/     struct _DEVICE_OBJECT* DeviceToVerify;                                                                 
	/*0x25C*/     union _PSP_CPU_QUOTA_APC* CpuQuotaApc;                                                                 
	/*0x260*/     VOID*        Win32StartAddress;                                                                        
	/*0x264*/     VOID*        LegacyPowerObject;                                                                        
	/*0x268*/     struct _LIST_ENTRY ThreadListEntry;                              // 2 elements, 0x8 bytes (sizeof)     
	/*0x270*/     struct _EX_RUNDOWN_REF RundownProtect;                           // 2 elements, 0x4 bytes (sizeof)     
	/*0x274*/     EX_PUSH_LOCK ThreadLock;                                 // 7 elements, 0x4 bytes (sizeof)     
	/*0x278*/     ULONG32      ReadClusterSize;                                                                          
	/*0x27C*/     LONG32       MmLockOrdering;                                                                           
	union                                                            // 2 elements, 0x4 bytes (sizeof)     
	{                                                                                                      
		/*0x280*/         ULONG32      CrossThreadFlags;                                                                     
		struct                                                       // 14 elements, 0x4 bytes (sizeof)    
		{                                                                                                  
			/*0x280*/             ULONG32      Terminated : 1;                             // 0 BitPosition                      
			/*0x280*/             ULONG32      ThreadInserted : 1;                         // 1 BitPosition                      
			/*0x280*/             ULONG32      HideFromDebugger : 1;                       // 2 BitPosition                      
			/*0x280*/             ULONG32      ActiveImpersonationInfo : 1;                // 3 BitPosition                      
			/*0x280*/             ULONG32      SystemThread : 1;                           // 4 BitPosition                      
			/*0x280*/             ULONG32      HardErrorsAreDisabled : 1;                  // 5 BitPosition                      
			/*0x280*/             ULONG32      BreakOnTermination : 1;                     // 6 BitPosition                      
			/*0x280*/             ULONG32      SkipCreationMsg : 1;                        // 7 BitPosition                      
			/*0x280*/             ULONG32      SkipTerminationMsg : 1;                     // 8 BitPosition                      
			/*0x280*/             ULONG32      CopyTokenOnOpen : 1;                        // 9 BitPosition                      
			/*0x280*/             ULONG32      ThreadIoPriority : 3;                       // 10 BitPosition                     
			/*0x280*/             ULONG32      ThreadPagePriority : 3;                     // 13 BitPosition                     
			/*0x280*/             ULONG32      RundownFail : 1;                            // 16 BitPosition                     
			/*0x280*/             ULONG32      NeedsWorkingSetAging : 1;                   // 17 BitPosition                     
		};                                                                                                 
	};                                                                                                     
	union                                                            // 2 elements, 0x4 bytes (sizeof)     
	{                                                                                                      
		/*0x284*/         ULONG32      SameThreadPassiveFlags;                                                               
		struct                                                       // 7 elements, 0x4 bytes (sizeof)     
		{                                                                                                  
			/*0x284*/             ULONG32      ActiveExWorker : 1;                         // 0 BitPosition                      
			/*0x284*/             ULONG32      ExWorkerCanWaitUser : 1;                    // 1 BitPosition                      
			/*0x284*/             ULONG32      MemoryMaker : 1;                            // 2 BitPosition                      
			/*0x284*/             ULONG32      ClonedThread : 1;                           // 3 BitPosition                      
			/*0x284*/             ULONG32      KeyedEventInUse : 1;                        // 4 BitPosition                      
			/*0x284*/             ULONG32      RateApcState : 2;                           // 5 BitPosition                      
			/*0x284*/             ULONG32      SelfTerminate : 1;                          // 7 BitPosition                      
		};                                                                                                 
	};                                                                                                     
	union                                                            // 2 elements, 0x4 bytes (sizeof)     
	{                                                                                                      
		/*0x288*/         ULONG32      SameThreadApcFlags;                                                                   
		struct                                                       // 4 elements, 0x4 bytes (sizeof)     
		{                                                                                                  
			struct                                                   // 8 elements, 0x1 bytes (sizeof)     
			{                                                                                              
				/*0x288*/                 UINT8        Spare : 1;                              // 0 BitPosition                      
				/*0x288*/                 UINT8        StartAddressInvalid : 1;                // 1 BitPosition                      
				/*0x288*/                 UINT8        EtwPageFaultCalloutActive : 1;          // 2 BitPosition                      
				/*0x288*/                 UINT8        OwnsProcessWorkingSetExclusive : 1;     // 3 BitPosition                      
				/*0x288*/                 UINT8        OwnsProcessWorkingSetShared : 1;        // 4 BitPosition                      
				/*0x288*/                 UINT8        OwnsSystemCacheWorkingSetExclusive : 1; // 5 BitPosition                      
				/*0x288*/                 UINT8        OwnsSystemCacheWorkingSetShared : 1;    // 6 BitPosition                      
				/*0x288*/                 UINT8        OwnsSessionWorkingSetExclusive : 1;     // 7 BitPosition                      
			};                                                                                             
			struct                                                   // 8 elements, 0x1 bytes (sizeof)     
			{                                                                                              
				/*0x289*/                 UINT8        OwnsSessionWorkingSetShared : 1;        // 0 BitPosition                      
				/*0x289*/                 UINT8        OwnsProcessAddressSpaceExclusive : 1;   // 1 BitPosition                      
				/*0x289*/                 UINT8        OwnsProcessAddressSpaceShared : 1;      // 2 BitPosition                      
				/*0x289*/                 UINT8        SuppressSymbolLoad : 1;                 // 3 BitPosition                      
				/*0x289*/                 UINT8        Prefetching : 1;                        // 4 BitPosition                      
				/*0x289*/                 UINT8        OwnsDynamicMemoryShared : 1;            // 5 BitPosition                      
				/*0x289*/                 UINT8        OwnsChangeControlAreaExclusive : 1;     // 6 BitPosition                      
				/*0x289*/                 UINT8        OwnsChangeControlAreaShared : 1;        // 7 BitPosition                      
			};                                                                                             
			struct                                                   // 6 elements, 0x1 bytes (sizeof)     
			{                                                                                              
				/*0x28A*/                 UINT8        OwnsPagedPoolWorkingSetExclusive : 1;   // 0 BitPosition                      
				/*0x28A*/                 UINT8        OwnsPagedPoolWorkingSetShared : 1;      // 1 BitPosition                      
				/*0x28A*/                 UINT8        OwnsSystemPtesWorkingSetExclusive : 1;  // 2 BitPosition                      
				/*0x28A*/                 UINT8        OwnsSystemPtesWorkingSetShared : 1;     // 3 BitPosition                      
				/*0x28A*/                 UINT8        TrimTrigger : 2;                        // 4 BitPosition                      
				/*0x28A*/                 UINT8        Spare1 : 2;                             // 6 BitPosition                      
			};                                                                                             
			/*0x28B*/             UINT8        PriorityRegionActive;                                                             
		};                                                                                                 
	};                                                                                                     
	/*0x28C*/     UINT8        CacheManagerActive;                                                                       
	/*0x28D*/     UINT8        DisablePageFaultClustering;                                                               
	/*0x28E*/     UINT8        ActiveFaultCount;                                                                         
	/*0x28F*/     UINT8        LockOrderState;                                                                           
	/*0x290*/     ULONG32      AlpcMessageId;                                                                            
	union                                                            // 2 elements, 0x4 bytes (sizeof)     
	{                                                                                                      
		/*0x294*/         VOID*        AlpcMessage;                                                                          
		/*0x294*/         ULONG32      AlpcReceiveAttributeSet;                                                              
	};                                                                                                     
	/*0x298*/     struct _LIST_ENTRY AlpcWaitListEntry;                            // 2 elements, 0x8 bytes (sizeof)     
	/*0x2A0*/     ULONG32      CacheManagerCount;                                                                        
	/*0x2A4*/     ULONG32      IoBoostCount;                                                                             
	/*0x2A8*/     ULONG32      IrpListLock;                                                                              
	/*0x2AC*/     VOID*        ReservedForSynchTracking;                                                                 
	/*0x2B0*/     struct _SINGLE_LIST_ENTRY CmCallbackListHead;                    // 1 elements, 0x4 bytes (sizeof)     
	/*0x2B4*/     UINT8        _PADDING0_[0x4];                                                                          
}ETHREAD_S, *PETHREAD_S;

typedef struct _GDI_TEB_BATCH // 3 elements, 0x4E0 bytes (sizeof) 
{                                                                 
	/*0x000*/     ULONG32      Offset;                                          
	/*0x004*/     ULONG32      HDC;                                             
	/*0x008*/     ULONG32      Buffer[310];                                     
}GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB                                                  // 99 elements, 0xFE4 bytes (sizeof) 
{                                                                                                         
	/*0x000*/     struct _NT_TIB NtTib;                                            // 8 elements, 0x1C bytes (sizeof)   
	/*0x01C*/     VOID*        EnvironmentPointer;                                                                      
	/*0x020*/     struct _CLIENT_ID ClientId;                                      // 2 elements, 0x8 bytes (sizeof)    
	/*0x028*/     VOID*        ActiveRpcHandle;                                                                         
	/*0x02C*/     VOID*        ThreadLocalStoragePointer;                                                               
	/*0x030*/     VOID*		   ProcessEnvironmentBlock;                                                                 
	/*0x034*/     ULONG32      LastErrorValue;                                                                          
	/*0x038*/     ULONG32      CountOfOwnedCriticalSections;                                                            
	/*0x03C*/     VOID*        CsrClientThread;                                                                         
	/*0x040*/     VOID*        Win32ThreadInfo;                                                                         
	/*0x044*/     ULONG32      User32Reserved[26];                                                                      
	/*0x0AC*/     ULONG32      UserReserved[5];                                                                         
	/*0x0C0*/     VOID*        WOW32Reserved;                                                                           
	/*0x0C4*/     ULONG32      CurrentLocale;                                                                           
	/*0x0C8*/     ULONG32      FpSoftwareStatusRegister;                                                                
	/*0x0CC*/     VOID*        SystemReserved1[54];                                                                     
	/*0x1A4*/     LONG32       ExceptionCode;                                                                           
	/*0x1A8*/     VOID*		   ActivationContextStackPointer;                                      
	/*0x1AC*/     UINT8        SpareBytes[36];                                                                          
	/*0x1D0*/     ULONG32      TxFsContext;                                                                             
	/*0x1D4*/     struct _GDI_TEB_BATCH GdiTebBatch;                               // 3 elements, 0x4E0 bytes (sizeof)  
	/*0x6B4*/     struct _CLIENT_ID RealClientId;                                  // 2 elements, 0x8 bytes (sizeof)    
	/*0x6BC*/     VOID*        GdiCachedProcessHandle;                                                                  
	/*0x6C0*/     ULONG32      GdiClientPID;                                                                            
	/*0x6C4*/     ULONG32      GdiClientTID;                                                                            
	/*0x6C8*/     VOID*        GdiThreadLocalInfo;                                                                      
	/*0x6CC*/     ULONG32      Win32ClientInfo[62];                                                                     
	/*0x7C4*/     VOID*        glDispatchTable[233];                                                                    
	/*0xB68*/     ULONG32      glReserved1[29];                                                                         
	/*0xBDC*/     VOID*        glReserved2;                                                                             
	/*0xBE0*/     VOID*        glSectionInfo;                                                                           
	/*0xBE4*/     VOID*        glSection;                                                                               
	/*0xBE8*/     VOID*        glTable;                                                                                 
	/*0xBEC*/     VOID*        glCurrentRC;                                                                             
	/*0xBF0*/     VOID*        glContext;                                                                               
	/*0xBF4*/     ULONG32      LastStatusValue;                                                                         
	/*0xBF8*/     struct _UNICODE_STRING StaticUnicodeString;                      // 3 elements, 0x8 bytes (sizeof)    
	/*0xC00*/     WCHAR        StaticUnicodeBuffer[261];                                                                
	/*0xE0A*/     UINT8        _PADDING0_[0x2];                                                                         
	/*0xE0C*/     VOID*        DeallocationStack;                                                                       
	/*0xE10*/     VOID*        TlsSlots[64];                                                                            
	/*0xF10*/     struct _LIST_ENTRY TlsLinks;                                     // 2 elements, 0x8 bytes (sizeof)    
	/*0xF18*/     VOID*        Vdm;                                                                                     
	/*0xF1C*/     VOID*        ReservedForNtRpc;                                                                        
	/*0xF20*/     VOID*        DbgSsReserved[2];                                                                        
	/*0xF28*/     ULONG32      HardErrorMode;                                                                           
	/*0xF2C*/     VOID*        Instrumentation[9];                                                                      
	/*0xF50*/     struct _GUID ActivityId;                                         // 4 elements, 0x10 bytes (sizeof)   
	/*0xF60*/     VOID*        SubProcessTag;                                                                           
	/*0xF64*/     VOID*        EtwLocalData;                                                                            
	/*0xF68*/     VOID*        EtwTraceData;                                                                            
	/*0xF6C*/     VOID*        WinSockData;                                                                             
	/*0xF70*/     ULONG32      GdiBatchCount;                                                                           
	union                                                            // 3 elements, 0x4 bytes (sizeof)    
	{                                                                                                     
		/*0xF74*/         struct _PROCESSOR_NUMBER CurrentIdealProcessor;              // 3 elements, 0x4 bytes (sizeof)    
		/*0xF74*/         ULONG32      IdealProcessorValue;                                                                 
		struct                                                       // 4 elements, 0x4 bytes (sizeof)    
		{                                                                                                 
			/*0xF74*/             UINT8        ReservedPad0;                                                                    
			/*0xF75*/             UINT8        ReservedPad1;                                                                    
			/*0xF76*/             UINT8        ReservedPad2;                                                                    
			/*0xF77*/             UINT8        IdealProcessor;                                                                  
		};                                                                                                
	};                                                                                                    
	/*0xF78*/     ULONG32      GuaranteedStackBytes;                                                                    
	/*0xF7C*/     VOID*        ReservedForPerf;                                                                         
	/*0xF80*/     VOID*        ReservedForOle;                                                                          
	/*0xF84*/     ULONG32      WaitingOnLoaderLock;                                                                     
	/*0xF88*/     VOID*        SavedPriorityState;                                                                      
	/*0xF8C*/     ULONG32      SoftPatchPtr1;                                                                           
	/*0xF90*/     VOID*        ThreadPoolData;                                                                          
	/*0xF94*/     VOID**       TlsExpansionSlots;                                                                       
	/*0xF98*/     ULONG32      MuiGeneration;                                                                           
	/*0xF9C*/     ULONG32      IsImpersonating;                                                                         
	/*0xFA0*/     VOID*        NlsCache;                                                                                
	/*0xFA4*/     VOID*        pShimData;                                                                               
	/*0xFA8*/     ULONG32      HeapVirtualAffinity;                                                                     
	/*0xFAC*/     VOID*        CurrentTransactionHandle;                                                                
	/*0xFB0*/     VOID*		   ActiveFrame;                                                                
	/*0xFB4*/     VOID*        FlsData;                                                                                 
	/*0xFB8*/     VOID*        PreferredLanguages;                                                                      
	/*0xFBC*/     VOID*        UserPrefLanguages;                                                                       
	/*0xFC0*/     VOID*        MergedPrefLanguages;                                                                     
	/*0xFC4*/     ULONG32      MuiImpersonation;                                                                        
	union                                                            // 2 elements, 0x2 bytes (sizeof)    
	{                                                                                                     
		/*0xFC8*/         UINT16       CrossTebFlags;                                                                       
		/*0xFC8*/         UINT16       SpareCrossTebBits : 16;                         // 0 BitPosition                     
	};                                                                                                    
	union                                                            // 2 elements, 0x2 bytes (sizeof)    
	{                                                                                                     
		/*0xFCA*/         UINT16       SameTebFlags;                                                                        
		struct                                                       // 12 elements, 0x2 bytes (sizeof)   
		{                                                                                                 
			/*0xFCA*/             UINT16       SafeThunkCall : 1;                          // 0 BitPosition                     
			/*0xFCA*/             UINT16       InDebugPrint : 1;                           // 1 BitPosition                     
			/*0xFCA*/             UINT16       HasFiberData : 1;                           // 2 BitPosition                     
			/*0xFCA*/             UINT16       SkipThreadAttach : 1;                       // 3 BitPosition                     
			/*0xFCA*/             UINT16       WerInShipAssertCode : 1;                    // 4 BitPosition                     
			/*0xFCA*/             UINT16       RanProcessInit : 1;                         // 5 BitPosition                     
			/*0xFCA*/             UINT16       ClonedThread : 1;                           // 6 BitPosition                     
			/*0xFCA*/             UINT16       SuppressDebugMsg : 1;                       // 7 BitPosition                     
			/*0xFCA*/             UINT16       DisableUserStackWalk : 1;                   // 8 BitPosition                     
			/*0xFCA*/             UINT16       RtlExceptionAttached : 1;                   // 9 BitPosition                     
			/*0xFCA*/             UINT16       InitialThread : 1;                          // 10 BitPosition                    
			/*0xFCA*/             UINT16       SpareSameTebBits : 5;                       // 11 BitPosition                    
		};                                                                                                
	};                                                                                                    
	/*0xFCC*/     VOID*        TxnScopeEnterCallback;                                                                   
	/*0xFD0*/     VOID*        TxnScopeExitCallback;                                                                    
	/*0xFD4*/     VOID*        TxnScopeContext;                                                                         
	/*0xFD8*/     ULONG32      LockCount;                                                                               
	/*0xFDC*/     ULONG32      SpareUlong0;                                                                             
	/*0xFE0*/     VOID*        ResourceRetValue;                                                                        
}TEB, *PTEB;

typedef struct _PEB_LDR_DATA                            // 9 elements, 0x30 bytes (sizeof) 
{                                                                                          
	/*0x000*/     ULONG32      Length;                                                                   
	/*0x004*/     UINT8        Initialized;                                                              
	/*0x005*/     UINT8        _PADDING0_[0x3];                                                          
	/*0x008*/     VOID*        SsHandle;                                                                 
	/*0x00C*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x8 bytes (sizeof)  
	/*0x014*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x8 bytes (sizeof)  
	/*0x01C*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x8 bytes (sizeof)  
	/*0x024*/     VOID*        EntryInProgress;                                                          
	/*0x028*/     UINT8        ShutdownInProgress;                                                       
	/*0x029*/     UINT8        _PADDING1_[0x3];                                                          
	/*0x02C*/     VOID*        ShutdownThreadId;                                                         
}PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY                         // 24 elements, 0x78 bytes (sizeof) 
{                                                                                                
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x8 bytes (sizeof)   
	/*0x008*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x8 bytes (sizeof)   
	/*0x010*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x8 bytes (sizeof)   
	/*0x018*/     VOID*        DllBase;                                                                        
	/*0x01C*/     VOID*        EntryPoint;                                                                     
	/*0x020*/     ULONG32      SizeOfImage;                                                                    
	/*0x024*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x8 bytes (sizeof)   
	/*0x02C*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x8 bytes (sizeof)   
	/*0x034*/     ULONG32      Flags;                                                                          
	/*0x038*/     UINT16       LoadCount;                                                                      
	/*0x03A*/     UINT16       TlsIndex;                                                                       
	union                                                    // 2 elements, 0x8 bytes (sizeof)   
	{                                                                                            
		/*0x03C*/         struct _LIST_ENTRY HashLinks;                        // 2 elements, 0x8 bytes (sizeof)   
		struct                                               // 2 elements, 0x8 bytes (sizeof)   
		{                                                                                        
			/*0x03C*/             VOID*        SectionPointer;                                                         
			/*0x040*/             ULONG32      CheckSum;                                                               
		};                                                                                       
	};                                                                                           
	union                                                    // 2 elements, 0x4 bytes (sizeof)   
	{                                                                                            
		/*0x044*/         ULONG32      TimeDateStamp;                                                              
		/*0x044*/         VOID*        LoadedImports;                                                              
	};                                                                                           
	/*0x048*/     VOID* EntryPointActivationContext;                                     
	/*0x04C*/     VOID*        PatchInformation;                                                               
	/*0x050*/     struct _LIST_ENTRY ForwarderLinks;                       // 2 elements, 0x8 bytes (sizeof)   
	/*0x058*/     struct _LIST_ENTRY ServiceTagLinks;                      // 2 elements, 0x8 bytes (sizeof)   
	/*0x060*/     struct _LIST_ENTRY StaticLinks;                          // 2 elements, 0x8 bytes (sizeof)   
	/*0x068*/     VOID*        ContextInformation;                                                             
	/*0x06C*/     ULONG32      OriginalBase;                                                                   
	/*0x070*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)   
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _XSTATE_CONFIGURATION_S {
	// Mask of enabled features
	struct{
		ULONG LowPart;
		LONG HighPart;
	}EnabledFeatures;

	// Total size of the save area
	ULONG Size;

	ULONG OptimizedSave : 1;

	// List of features (
	XSTATE_FEATURE Features[MAXIMUM_XSTATE_FEATURES];

} XSTATE_CONFIGURATION_S, *PXSTATE_CONFIGURATION_S;

typedef struct _KUSER_SHARED_DATA_S                                // 75 elements, 0x5F0 bytes (sizeof) 
{                                                                                                     
	/*0x000*/     ULONG32      TickCountLowDeprecated;                                                              
	/*0x004*/     ULONG32      TickCountMultiplier;                                                                 
	/*0x008*/     struct _KSYSTEM_TIME InterruptTime;                          // 3 elements, 0xC bytes (sizeof)    
	/*0x014*/     struct _KSYSTEM_TIME SystemTime;                             // 3 elements, 0xC bytes (sizeof)    
	/*0x020*/     struct _KSYSTEM_TIME TimeZoneBias;                           // 3 elements, 0xC bytes (sizeof)    
	/*0x02C*/     UINT16       ImageNumberLow;                                                                      
	/*0x02E*/     UINT16       ImageNumberHigh;                                                                     
	/*0x030*/     WCHAR        NtSystemRoot[260];                                                                   
	/*0x238*/     ULONG32      MaxStackTraceDepth;                                                                  
	/*0x23C*/     ULONG32      CryptoExponent;                                                                      
	/*0x240*/     ULONG32      TimeZoneId;                                                                          
	/*0x244*/     ULONG32      LargePageMinimum;                                                                    
	/*0x248*/     ULONG32      Reserved2[7];                                                                        
	/*0x264*/     enum _NT_PRODUCT_TYPE NtProductType;                                                              
	/*0x268*/     UINT8        ProductTypeIsValid;                                                                  
	/*0x269*/     UINT8        _PADDING0_[0x3];                                                                     
	/*0x26C*/     ULONG32      NtMajorVersion;                                                                      
	/*0x270*/     ULONG32      NtMinorVersion;                                                                      
	/*0x274*/     UINT8        ProcessorFeatures[64];                                                               
	/*0x2B4*/     ULONG32      Reserved1;                                                                           
	/*0x2B8*/     ULONG32      Reserved3;                                                                           
	/*0x2BC*/     ULONG32      TimeSlip;                                                                            
	/*0x2C0*/     enum _ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;                                      
	/*0x2C4*/     ULONG32      AltArchitecturePad[1];                                                               
	/*0x2C8*/     union _LARGE_INTEGER SystemExpirationDate;                   // 4 elements, 0x8 bytes (sizeof)    
	/*0x2D0*/     ULONG32      SuiteMask;                                                                           
	/*0x2D4*/     UINT8        KdDebuggerEnabled;                                                                   
	/*0x2D5*/     UINT8        NXSupportPolicy;                                                                     
	/*0x2D6*/     UINT8        _PADDING1_[0x2];                                                                     
	/*0x2D8*/     ULONG32      ActiveConsoleId;                                                                     
	/*0x2DC*/     ULONG32      DismountCount;                                                                       
	/*0x2E0*/     ULONG32      ComPlusPackage;                                                                      
	/*0x2E4*/     ULONG32      LastSystemRITEventTickCount;                                                         
	/*0x2E8*/     ULONG32      NumberOfPhysicalPages;                                                               
	/*0x2EC*/     UINT8        SafeBootMode;                                                                        
	union                                                        // 2 elements, 0x1 bytes (sizeof)    
	{                                                                                                 
		/*0x2ED*/         UINT8        TscQpcData;                                                                      
		struct                                                   // 3 elements, 0x1 bytes (sizeof)    
		{                                                                                             
			/*0x2ED*/             UINT8        TscQpcEnabled : 1;                      // 0 BitPosition                     
			/*0x2ED*/             UINT8        TscQpcSpareFlag : 1;                    // 1 BitPosition                     
			/*0x2ED*/             UINT8        TscQpcShift : 6;                        // 2 BitPosition                     
		};                                                                                            
	};                                                                                                
	/*0x2EE*/     UINT8        TscQpcPad[2];                                                                        
	union                                                        // 2 elements, 0x4 bytes (sizeof)    
	{                                                                                                 
		/*0x2F0*/         ULONG32      SharedDataFlags;                                                                 
		struct                                                   // 8 elements, 0x4 bytes (sizeof)    
		{                                                                                             
			/*0x2F0*/             ULONG32      DbgErrorPortPresent : 1;                // 0 BitPosition                     
			/*0x2F0*/             ULONG32      DbgElevationEnabled : 1;                // 1 BitPosition                     
			/*0x2F0*/             ULONG32      DbgVirtEnabled : 1;                     // 2 BitPosition                     
			/*0x2F0*/             ULONG32      DbgInstallerDetectEnabled : 1;          // 3 BitPosition                     
			/*0x2F0*/             ULONG32      DbgSystemDllRelocated : 1;              // 4 BitPosition                     
			/*0x2F0*/             ULONG32      DbgDynProcessorEnabled : 1;             // 5 BitPosition                     
			/*0x2F0*/             ULONG32      DbgSEHValidationEnabled : 1;            // 6 BitPosition                     
			/*0x2F0*/             ULONG32      SpareBits : 25;                         // 7 BitPosition                     
		};                                                                                            
	};                                                                                                
	/*0x2F4*/     ULONG32      DataFlagsPad[1];                                                                     
	/*0x2F8*/     UINT64       TestRetInstruction;                                                                  
	/*0x300*/     ULONG32      SystemCall;                                                                          
	/*0x304*/     ULONG32      SystemCallReturn;                                                                    
	/*0x308*/     UINT64       SystemCallPad[3];                                                                    
	union                                                        // 3 elements, 0xC bytes (sizeof)    
	{                                                                                                 
		/*0x320*/         struct _KSYSTEM_TIME TickCount;                          // 3 elements, 0xC bytes (sizeof)    
		/*0x320*/         UINT64       TickCountQuad;                                                                   
		/*0x320*/         ULONG32      ReservedTickCountOverlay[3];                                                     
	};                                                                                                
	/*0x32C*/     ULONG32      TickCountPad[1];                                                                     
	/*0x330*/     ULONG32      Cookie;                                                                              
	/*0x334*/     ULONG32      CookiePad[1];                                                                        
	/*0x338*/     INT64        ConsoleSessionForegroundProcessId;                                                   
	/*0x340*/     ULONG32      Wow64SharedInformation[16];                                                          
	/*0x380*/     UINT16       UserModeGlobalLogger[16];                                                            
	/*0x3A0*/     ULONG32      ImageFileExecutionOptions;                                                           
	/*0x3A4*/     ULONG32      LangGenerationCount;                                                                 
	/*0x3A8*/     UINT64       Reserved5;                                                                           
	/*0x3B0*/     UINT64       InterruptTimeBias;                                                                   
	/*0x3B8*/     UINT64       TscQpcBias;                                                                          
	/*0x3C0*/     ULONG32      ActiveProcessorCount;                                                                
	/*0x3C4*/     UINT16       ActiveGroupCount;                                                                    
	/*0x3C6*/     UINT16       Reserved4;                                                                           
	/*0x3C8*/     ULONG32      AitSamplingValue;                                                                    
	/*0x3CC*/     ULONG32      AppCompatFlag;                                                                       
	/*0x3D0*/     UINT64       SystemDllNativeRelocation;                                                           
	/*0x3D8*/     ULONG32      SystemDllWowRelocation;                                                              
	/*0x3DC*/     ULONG32      XStatePad[1];                                                                        
	/*0x3E0*/     XSTATE_CONFIGURATION_S XState;                         // 4 elements, 0x210 bytes (sizeof)  
}KUSER_SHARED_DATA_S, *PKUSER_SHARED_DATA_S;


typedef struct _KTRAP_FRAME_S                               // 37 elements, 0x8C bytes (sizeof) 
{                                                                                             
	/*0x000*/     ULONG32      DbgEbp;                                                                      
	/*0x004*/     ULONG32      DbgEip;                                                                      
	/*0x008*/     ULONG32      DbgArgMark;                                                                  
	/*0x00C*/     ULONG32      DbgArgPointer;                                                               
	/*0x010*/     UINT16       TempSegCs;                                                                   
	/*0x012*/     UINT8        Logging;                                                                     
	/*0x013*/     UINT8        Reserved;                                                                    
	/*0x014*/     ULONG32      TempEsp;                                                                     
	/*0x018*/     ULONG32      Dr0;                                                                         
	/*0x01C*/     ULONG32      Dr1;                                                                         
	/*0x020*/     ULONG32      Dr2;                                                                         
	/*0x024*/     ULONG32      Dr3;                                                                         
	/*0x028*/     ULONG32      Dr6;                                                                         
	/*0x02C*/     ULONG32      Dr7;                                                                         
	/*0x030*/     ULONG32      SegGs;                                                                       
	/*0x034*/     ULONG32      SegEs;                                                                       
	/*0x038*/     ULONG32      SegDs;                                                                       
	/*0x03C*/     ULONG32      Edx;                                                                         
	/*0x040*/     ULONG32      Ecx;                                                                         
	/*0x044*/     ULONG32      Eax;                                                                         
	/*0x048*/     ULONG32      PreviousPreviousMode;                                                        
	/*0x04C*/     struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;                                     
	/*0x050*/     ULONG32      SegFs;                                                                       
	/*0x054*/     ULONG32      Edi;                                                                         
	/*0x058*/     ULONG32      Esi;                                                                         
	/*0x05C*/     ULONG32      Ebx;                                                                         
	/*0x060*/     ULONG32      Ebp;                                                                         
	/*0x064*/     ULONG32      ErrCode;                                                                     
	/*0x068*/     ULONG32      Eip;                                                                         
	/*0x06C*/     ULONG32      SegCs;                                                                       
	/*0x070*/     ULONG32      EFlags;                                                                      
	/*0x074*/     ULONG32      HardwareEsp;                                                                 
	/*0x078*/     ULONG32      HardwareSegSs;                                                               
	/*0x07C*/     ULONG32      V86Es;                                                                       
	/*0x080*/     ULONG32      V86Ds;                                                                       
	/*0x084*/     ULONG32      V86Fs;                                                                       
	/*0x088*/     ULONG32      V86Gs;                                                                       
}KTRAP_FRAME_S, *PKTRAP_FRAME_S;

typedef struct _PPM_FFH_THROTTLE_STATE_INFO // 5 elements, 0x20 bytes (sizeof) 
{                                                                              
	/*0x000*/     UINT8        EnableLogging;                                                
	/*0x001*/     UINT8        _PADDING0_[0x3];                                              
	/*0x004*/     ULONG32      MismatchCount;                                                
	/*0x008*/     UINT8        Initialized;                                                  
	/*0x009*/     UINT8        _PADDING1_[0x7];                                              
	/*0x010*/     UINT64       LastValue;                                                    
	/*0x018*/     union _LARGE_INTEGER LastLogTickCount;  // 4 elements, 0x8 bytes (sizeof)  
}PPM_FFH_THROTTLE_STATE_INFO, *PPPM_FFH_THROTTLE_STATE_INFO;

typedef struct _PROC_IDLE_SNAP // 2 elements, 0x10 bytes (sizeof) 
{                                                                 
	/*0x000*/     UINT64       Time;                                            
	/*0x008*/     UINT64       Idle;                                            
}PROC_IDLE_SNAP, *PPROC_IDLE_SNAP;

typedef struct _PROCESSOR_POWER_STATE                         // 27 elements, 0xC8 bytes (sizeof) 
{                                                                                                 
	/*0x000*/     void* IdleStates;                                                          
	/*0x004*/     UINT8        _PADDING0_[0x4];                                                                 
	/*0x008*/     UINT64       IdleTimeLast;                                                                    
	/*0x010*/     UINT64       IdleTimeTotal;                                                                   
	/*0x018*/     UINT64       IdleTimeEntry;                                                                   
	/*0x020*/     void* IdleAccounting;                                                 
	/*0x024*/     /*enum*/ int Hypervisor;                                                       
	/*0x028*/     ULONG32      PerfHistoryTotal;                                                                
	/*0x02C*/     UINT8        ThermalConstraint;                                                               
	/*0x02D*/     UINT8        PerfHistoryCount;                                                                
	/*0x02E*/     UINT8        PerfHistorySlot;                                                                 
	/*0x02F*/     UINT8        Reserved;                                                                        
	/*0x030*/     ULONG32      LastSysTime;                                                                     
	/*0x034*/     ULONG32      WmiDispatchPtr;                                                                  
	/*0x038*/     LONG32       WmiInterfaceEnabled;                                                             
	/*0x03C*/     UINT8        _PADDING1_[0x4];                                                                 
	/*0x040*/     struct _PPM_FFH_THROTTLE_STATE_INFO FFHThrottleStateInfo; // 5 elements, 0x20 bytes (sizeof)  
	/*0x060*/     struct _KDPC PerfActionDpc;                               // 9 elements, 0x20 bytes (sizeof)  
	/*0x080*/     LONG32       PerfActionMask;                                                                  
	/*0x084*/     UINT8        _PADDING2_[0x4];                                                                 
	/*0x088*/     struct _PROC_IDLE_SNAP IdleCheck;                         // 2 elements, 0x10 bytes (sizeof)  
	/*0x098*/     struct _PROC_IDLE_SNAP PerfCheck;                         // 2 elements, 0x10 bytes (sizeof)  
	/*0x0A8*/     void* Domain;                                                             
	/*0x0AC*/     void* PerfConstraint;                                                 
	/*0x0B0*/     void* Load;                                                                 
	/*0x0B4*/     void* PerfHistory;                                                      
	/*0x0B8*/     ULONG32      Utility;                                                                         
	/*0x0BC*/     ULONG32      OverUtilizedHistory;                                                             
	/*0x0C0*/     ULONG32      AffinityCount;                                                                   
	/*0x0C4*/     ULONG32      AffinityHistory;                                                                 
}PROCESSOR_POWER_STATE, *PPROCESSOR_POWER_STATE;

typedef struct _DESCRIPTOR // 3 elements, 0x8 bytes (sizeof) 
{                                                            
	/*0x000*/     UINT16       Pad;                                        
	/*0x002*/     UINT16       Limit;                                      
	/*0x004*/     ULONG32      Base;                                       
}DESCRIPTOR, *PDESCRIPTOR;

typedef struct _KSPECIAL_REGISTERS // 15 elements, 0x54 bytes (sizeof) 
{                                                                      
	/*0x000*/     ULONG32      Cr0;                                                  
	/*0x004*/     ULONG32      Cr2;                                                  
	/*0x008*/     ULONG32      Cr3;                                                  
	/*0x00C*/     ULONG32      Cr4;                                                  
	/*0x010*/     ULONG32      KernelDr0;                                            
	/*0x014*/     ULONG32      KernelDr1;                                            
	/*0x018*/     ULONG32      KernelDr2;                                            
	/*0x01C*/     ULONG32      KernelDr3;                                            
	/*0x020*/     ULONG32      KernelDr6;                                            
	/*0x024*/     ULONG32      KernelDr7;                                            
	/*0x028*/     struct _DESCRIPTOR Gdtr;       // 3 elements, 0x8 bytes (sizeof)   
	/*0x030*/     struct _DESCRIPTOR Idtr;       // 3 elements, 0x8 bytes (sizeof)   
	/*0x038*/     UINT16       Tr;                                                   
	/*0x03A*/     UINT16       Ldtr;                                                 
	/*0x03C*/     ULONG32      Reserved[6];                                          
}KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

typedef struct _KPROCESSOR_STATE                 // 2 elements, 0x320 bytes (sizeof)  
{                                                                                     
	/*0x000*/     struct _CONTEXT ContextFrame;                // 25 elements, 0x2CC bytes (sizeof) 
	/*0x2CC*/     struct _KSPECIAL_REGISTERS SpecialRegisters; // 15 elements, 0x54 bytes (sizeof)  
}KPROCESSOR_STATE, *PKPROCESSOR_STATE;

typedef struct _PP_LOOKASIDE_LIST // 2 elements, 0x8 bytes (sizeof) 
{                                                                   
	/*0x000*/     struct _GENERAL_LOOKASIDE* P;                                   
	/*0x004*/     struct _GENERAL_LOOKASIDE* L;                                   
}PP_LOOKASIDE_LIST, *PPP_LOOKASIDE_LIST;

typedef struct _KDPC_DATA           // 4 elements, 0x14 bytes (sizeof) 
{                                                                      
	/*0x000*/     struct _LIST_ENTRY DpcListHead; // 2 elements, 0x8 bytes (sizeof)  
	/*0x008*/     ULONG32      DpcLock;                                              
	/*0x00C*/     LONG32       DpcQueueDepth;                                        
	/*0x010*/     ULONG32      DpcCount;                                             
}KDPC_DATA, *PKDPC_DATA;

typedef struct _KTIMER_TABLE_ENTRY // 3 elements, 0x18 bytes (sizeof) 
{                                                                     
	/*0x000*/     ULONG32      Lock;                                                
	/*0x004*/     struct _LIST_ENTRY Entry;      // 2 elements, 0x8 bytes (sizeof)  
	/*0x00C*/     UINT8        _PADDING0_[0x4];                                     
	/*0x010*/     union _ULARGE_INTEGER Time;    // 4 elements, 0x8 bytes (sizeof)  
}KTIMER_TABLE_ENTRY, *PKTIMER_TABLE_ENTRY;                                   

typedef struct _KTIMER_TABLE                      // 2 elements, 0x1840 bytes (sizeof) 
{                                                                                      
	/*0x000*/     struct _KTIMER* TimerExpiry[16];                                                   
	/*0x040*/     struct _KTIMER_TABLE_ENTRY TimerEntries[256];                                      
}KTIMER_TABLE, *PKTIMER_TABLE;

typedef struct _KPRCB                                                   // 245 elements, 0x3628 bytes (sizeof) 
{                                                                                                              
	/*0x000*/      UINT16       MinorVersion;                                                                                 
	/*0x002*/      UINT16       MajorVersion;                                                                                 
	/*0x004*/      struct _KTHREAD_S* CurrentThread;                                                                            
	/*0x008*/      struct _KTHREAD_S* NextThread;                                                                               
	/*0x00C*/      struct _KTHREAD_S* IdleThread;                                                                               
	/*0x010*/      UINT8        LegacyNumber;                                                                                 
	/*0x011*/      UINT8        NestingLevel;                                                                                 
	/*0x012*/      UINT16       BuildType;                                                                                    
	/*0x014*/      CHAR         CpuType;                                                                                      
	/*0x015*/      CHAR         CpuID;                                                                                        
	union                                                               // 2 elements, 0x2 bytes (sizeof)      
	{                                                                                                          
		/*0x016*/          UINT16       CpuStep;                                                                                  
		struct                                                          // 2 elements, 0x2 bytes (sizeof)      
		{                                                                                                      
			/*0x016*/              UINT8        CpuStepping;                                                                          
			/*0x017*/              UINT8        CpuModel;                                                                             
		};                                                                                                     
	};                                                                                                         
	/*0x018*/      struct _KPROCESSOR_STATE ProcessorState;                            // 2 elements, 0x320 bytes (sizeof)    
	/*0x338*/      ULONG32      KernelReserved[16];                                                                           
	/*0x378*/      ULONG32      HalReserved[16];                                                                              
	/*0x3B8*/      ULONG32      CFlushSize;                                                                                   
	/*0x3BC*/      UINT8        CoresPerPhysicalProcessor;                                                                    
	/*0x3BD*/      UINT8        LogicalProcessorsPerCore;                                                                     
	/*0x3BE*/      UINT8        PrcbPad0[2];                                                                                  
	/*0x3C0*/      ULONG32      MHz;                                                                                          
	/*0x3C4*/      UINT8        CpuVendor;                                                                                    
	/*0x3C5*/      UINT8        GroupIndex;                                                                                   
	/*0x3C6*/      UINT16       Group;                                                                                        
	/*0x3C8*/      ULONG32      GroupSetMember;                                                                               
	/*0x3CC*/      ULONG32      Number;                                                                                       
	/*0x3D0*/      UINT8        PrcbPad1[72];                                                                                 
	/*0x418*/      struct _KSPIN_LOCK_QUEUE LockQueue[17];                                                                    
	/*0x4A0*/      struct _KTHREAD_S* NpxThread;                                                                                
	/*0x4A4*/      ULONG32      InterruptCount;                                                                               
	/*0x4A8*/      ULONG32      KernelTime;                                                                                   
	/*0x4AC*/      ULONG32      UserTime;                                                                                     
	/*0x4B0*/      ULONG32      DpcTime;                                                                                      
	/*0x4B4*/      ULONG32      DpcTimeCount;                                                                                 
	/*0x4B8*/      ULONG32      InterruptTime;                                                                                
	/*0x4BC*/      ULONG32      AdjustDpcThreshold;                                                                           
	/*0x4C0*/      ULONG32      PageColor;                                                                                    
	/*0x4C4*/      UINT8        DebuggerSavedIRQL;                                                                            
	/*0x4C5*/      UINT8        NodeColor;                                                                                    
	/*0x4C6*/      UINT8        PrcbPad20[2];                                                                                 
	/*0x4C8*/      ULONG32      NodeShiftedColor;                                                                             
	/*0x4CC*/      void*		ParentNode;                                                                                 
	/*0x4D0*/      ULONG32      SecondaryColorMask;                                                                           
	/*0x4D4*/      ULONG32      DpcTimeLimit;                                                                                 
	/*0x4D8*/      ULONG32      PrcbPad21[2];                                                                                 
	/*0x4E0*/      ULONG32      CcFastReadNoWait;                                                                             
	/*0x4E4*/      ULONG32      CcFastReadWait;                                                                               
	/*0x4E8*/      ULONG32      CcFastReadNotPossible;                                                                        
	/*0x4EC*/      ULONG32      CcCopyReadNoWait;                                                                             
	/*0x4F0*/      ULONG32      CcCopyReadWait;                                                                               
	/*0x4F4*/      ULONG32      CcCopyReadNoWaitMiss;                                                                         
	/*0x4F8*/      LONG32       MmSpinLockOrdering;                                                                           
	/*0x4FC*/      LONG32       IoReadOperationCount;                                                                         
	/*0x500*/      LONG32       IoWriteOperationCount;                                                                        
	/*0x504*/      LONG32       IoOtherOperationCount;                                                                        
	/*0x508*/      union _LARGE_INTEGER IoReadTransferCount;                           // 4 elements, 0x8 bytes (sizeof)      
	/*0x510*/      union _LARGE_INTEGER IoWriteTransferCount;                          // 4 elements, 0x8 bytes (sizeof)      
	/*0x518*/      union _LARGE_INTEGER IoOtherTransferCount;                          // 4 elements, 0x8 bytes (sizeof)      
	/*0x520*/      ULONG32      CcFastMdlReadNoWait;                                                                          
	/*0x524*/      ULONG32      CcFastMdlReadWait;                                                                            
	/*0x528*/      ULONG32      CcFastMdlReadNotPossible;                                                                     
	/*0x52C*/      ULONG32      CcMapDataNoWait;                                                                              
	/*0x530*/      ULONG32      CcMapDataWait;                                                                                
	/*0x534*/      ULONG32      CcPinMappedDataCount;                                                                         
	/*0x538*/      ULONG32      CcPinReadNoWait;                                                                              
	/*0x53C*/      ULONG32      CcPinReadWait;                                                                                
	/*0x540*/      ULONG32      CcMdlReadNoWait;                                                                              
	/*0x544*/      ULONG32      CcMdlReadWait;                                                                                
	/*0x548*/      ULONG32      CcLazyWriteHotSpots;                                                                          
	/*0x54C*/      ULONG32      CcLazyWriteIos;                                                                               
	/*0x550*/      ULONG32      CcLazyWritePages;                                                                             
	/*0x554*/      ULONG32      CcDataFlushes;                                                                                
	/*0x558*/      ULONG32      CcDataPages;                                                                                  
	/*0x55C*/      ULONG32      CcLostDelayedWrites;                                                                          
	/*0x560*/      ULONG32      CcFastReadResourceMiss;                                                                       
	/*0x564*/      ULONG32      CcCopyReadWaitMiss;                                                                           
	/*0x568*/      ULONG32      CcFastMdlReadResourceMiss;                                                                    
	/*0x56C*/      ULONG32      CcMapDataNoWaitMiss;                                                                          
	/*0x570*/      ULONG32      CcMapDataWaitMiss;                                                                            
	/*0x574*/      ULONG32      CcPinReadNoWaitMiss;                                                                          
	/*0x578*/      ULONG32      CcPinReadWaitMiss;                                                                            
	/*0x57C*/      ULONG32      CcMdlReadNoWaitMiss;                                                                          
	/*0x580*/      ULONG32      CcMdlReadWaitMiss;                                                                            
	/*0x584*/      ULONG32      CcReadAheadIos;                                                                               
	/*0x588*/      ULONG32      KeAlignmentFixupCount;                                                                        
	/*0x58C*/      ULONG32      KeExceptionDispatchCount;                                                                     
	/*0x590*/      ULONG32      KeSystemCalls;                                                                                
	/*0x594*/      ULONG32      AvailableTime;                                                                                
	/*0x598*/      ULONG32      PrcbPad22[2];                                                                                 
	/*0x5A0*/      struct _PP_LOOKASIDE_LIST PPLookasideList[16];                                                             
	/*0x620*/      struct _GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];                                                  
	/*0xF20*/      struct _GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];                                                   
	/*0x1820*/     ULONG32      PacketBarrier;                                                                                
	/*0x1824*/     LONG32       ReverseStall;                                                                                 
	/*0x1828*/     VOID*        IpiFrame;                                                                                     
	/*0x182C*/     UINT8        PrcbPad3[52];                                                                                 
	/*0x1860*/     VOID*        CurrentPacket[3];                                                                             
	/*0x186C*/     ULONG32      TargetSet;                                                                                    
	/*0x1870*/     void*		WorkerRoutine;                                                              
	/*0x1874*/     ULONG32      IpiFrozen;                                                                                    
	/*0x1878*/     UINT8        PrcbPad4[40];                                                                                 
	/*0x18A0*/     ULONG32      RequestSummary;                                                                               
	/*0x18A4*/     struct _KPRCB* SignalDone;                                                                                 
	/*0x18A8*/     UINT8        PrcbPad50[56];                                                                                
	/*0x18E0*/     struct _KDPC_DATA DpcData[2];                                                                              
	/*0x1908*/     VOID*        DpcStack;                                                                                     
	/*0x190C*/     LONG32       MaximumDpcQueueDepth;                                                                         
	/*0x1910*/     ULONG32      DpcRequestRate;                                                                               
	/*0x1914*/     ULONG32      MinimumDpcRate;                                                                               
	/*0x1918*/     ULONG32      DpcLastCount;                                                                                 
	/*0x191C*/     ULONG32      PrcbLock;                                                                                     
	/*0x1920*/     struct _KGATE DpcGate;                                              // 1 elements, 0x10 bytes (sizeof)     
	/*0x1930*/     UINT8        ThreadDpcEnable;                                                                              
	/*0x1931*/     UINT8        QuantumEnd;                                                                                   
	/*0x1932*/     UINT8        DpcRoutineActive;                                                                             
	/*0x1933*/     UINT8        IdleSchedule;                                                                                 
	union                                                               // 3 elements, 0x4 bytes (sizeof)      
	{                                                                                                          
		/*0x1934*/         LONG32       DpcRequestSummary;                                                                        
		/*0x1934*/         INT16        DpcRequestSlot[2];                                                                        
		struct                                                          // 2 elements, 0x4 bytes (sizeof)      
		{                                                                                                      
			/*0x1934*/             INT16        NormalDpcState;                                                                       
			union                                                       // 2 elements, 0x2 bytes (sizeof)      
			{                                                                                                  
				/*0x1936*/                 UINT16       DpcThreadActive : 1;                       // 0 BitPosition                       
				/*0x1936*/                 INT16        ThreadDpcState;                                                                   
			};                                                                                                 
		};                                                                                                     
	};                                                                                                         
	/*0x1938*/     ULONG32      TimerHand;                                                                                    
	/*0x193C*/     ULONG32      LastTick;                                                                                     
	/*0x1940*/     LONG32       MasterOffset;                                                                                 
	/*0x1944*/     ULONG32      PrcbPad41[2];                                                                                 
	/*0x194C*/     ULONG32      PeriodicCount;                                                                                
	/*0x1950*/     ULONG32      PeriodicBias;                                                                                 
	/*0x1954*/     UINT8        _PADDING0_[0x4];                                                                              
	/*0x1958*/     UINT64       TickOffset;                                                                                   
	/*0x1960*/     struct _KTIMER_TABLE TimerTable;                                    // 2 elements, 0x1840 bytes (sizeof)   
	/*0x31A0*/     struct _KDPC CallDpc;                                               // 9 elements, 0x20 bytes (sizeof)     
	/*0x31C0*/     LONG32       ClockKeepAlive;                                                                               
	/*0x31C4*/     UINT8        ClockCheckSlot;                                                                               
	/*0x31C5*/     UINT8        ClockPollCycle;                                                                               
	/*0x31C6*/     UINT8        PrcbPad6[2];                                                                                  
	/*0x31C8*/     LONG32       DpcWatchdogPeriod;                                                                            
	/*0x31CC*/     LONG32       DpcWatchdogCount;                                                                             
	/*0x31D0*/     LONG32       ThreadWatchdogPeriod;                                                                         
	/*0x31D4*/     LONG32       ThreadWatchdogCount;                                                                          
	/*0x31D8*/     LONG32       KeSpinLockOrdering;                                                                           
	/*0x31DC*/     ULONG32      PrcbPad70[1];                                                                                 
	/*0x31E0*/     struct _LIST_ENTRY WaitListHead;                                    // 2 elements, 0x8 bytes (sizeof)      
	/*0x31E8*/     ULONG32      WaitLock;                                                                                     
	/*0x31EC*/     ULONG32      ReadySummary;                                                                                 
	/*0x31F0*/     ULONG32      QueueIndex;                                                                                   
	/*0x31F4*/     struct _SINGLE_LIST_ENTRY DeferredReadyListHead;                    // 1 elements, 0x4 bytes (sizeof)      
	/*0x31F8*/     UINT64       StartCycles;                                                                                  
	/*0x3200*/     UINT64       CycleTime;                                                                                    
	/*0x3208*/     ULONG32      HighCycleTime;                                                                                
	/*0x320C*/     ULONG32      PrcbPad71;                                                                                    
	/*0x3210*/     UINT64       PrcbPad72[2];                                                                                 
	/*0x3220*/     struct _LIST_ENTRY DispatcherReadyListHead[32];                                                            
	/*0x3320*/     VOID*        ChainedInterruptList;                                                                         
	/*0x3324*/     LONG32       LookasideIrpFloat;                                                                            
	/*0x3328*/     LONG32       MmPageFaultCount;                                                                             
	/*0x332C*/     LONG32       MmCopyOnWriteCount;                                                                           
	/*0x3330*/     LONG32       MmTransitionCount;                                                                            
	/*0x3334*/     LONG32       MmCacheTransitionCount;                                                                       
	/*0x3338*/     LONG32       MmDemandZeroCount;                                                                            
	/*0x333C*/     LONG32       MmPageReadCount;                                                                              
	/*0x3340*/     LONG32       MmPageReadIoCount;                                                                            
	/*0x3344*/     LONG32       MmCacheReadCount;                                                                             
	/*0x3348*/     LONG32       MmCacheIoCount;                                                                               
	/*0x334C*/     LONG32       MmDirtyPagesWriteCount;                                                                       
	/*0x3350*/     LONG32       MmDirtyWriteIoCount;                                                                          
	/*0x3354*/     LONG32       MmMappedPagesWriteCount;                                                                      
	/*0x3358*/     LONG32       MmMappedWriteIoCount;                                                                         
	/*0x335C*/     ULONG32      CachedCommit;                                                                                 
	/*0x3360*/     ULONG32      CachedResidentAvailable;                                                                      
	/*0x3364*/     VOID*        HyperPte;                                                                                     
	/*0x3368*/     UINT8        PrcbPad8[4];                                                                                  
	/*0x336C*/     UINT8        VendorString[13];                                                                             
	/*0x3379*/     UINT8        InitialApicId;                                                                                
	/*0x337A*/     UINT8        LogicalProcessorsPerPhysicalProcessor;                                                        
	/*0x337B*/     UINT8        PrcbPad9[5];                                                                                  
	/*0x3380*/     ULONG32      FeatureBits;                                                                                  
	/*0x3384*/     UINT8        _PADDING1_[0x4];                                                                              
	/*0x3388*/     union _LARGE_INTEGER UpdateSignature;                               // 4 elements, 0x8 bytes (sizeof)      
	/*0x3390*/     UINT64       IsrTime;                                                                                      
	/*0x3398*/     UINT64       RuntimeAccumulation;                                                                          
	/*0x33A0*/     struct _PROCESSOR_POWER_STATE PowerState;                           // 27 elements, 0xC8 bytes (sizeof)    
	/*0x3468*/     struct _KDPC DpcWatchdogDpc;                                        // 9 elements, 0x20 bytes (sizeof)     
	/*0x3488*/     struct _KTIMER DpcWatchdogTimer;                                    // 5 elements, 0x28 bytes (sizeof)     
	/*0x34B0*/     VOID*        WheaInfo;                                                                                     
	/*0x34B4*/     VOID*        EtwSupport;                                                                                   
	/*0x34B8*/     union _SLIST_HEADER InterruptObjectPool;                            // 4 elements, 0x8 bytes (sizeof)      
	/*0x34C0*/     union _SLIST_HEADER HypercallPageList;                              // 4 elements, 0x8 bytes (sizeof)      
	/*0x34C8*/     VOID*        HypercallPageVirtual;                                                                         
	/*0x34CC*/     VOID*        VirtualApicAssist;                                                                            
	/*0x34D0*/     UINT64*      StatisticsPage;                                                                               
	/*0x34D4*/     VOID*        RateControl;                                                                                  
	/*0x34D8*/     struct _CACHE_DESCRIPTOR Cache[5];                                                                         
	/*0x3514*/     ULONG32      CacheCount;                                                                                   
	/*0x3518*/     ULONG32      CacheProcessorMask[5];                                                                        
	/*0x352C*/     struct _KAFFINITY_EX PackageProcessorSet;                           // 4 elements, 0xC bytes (sizeof)      
	/*0x3538*/     ULONG32      PrcbPad91[1];                                                                                 
	/*0x353C*/     ULONG32      CoreProcessorSet;                                                                             
	/*0x3540*/     struct _KDPC TimerExpirationDpc;                                    // 9 elements, 0x20 bytes (sizeof)     
	/*0x3560*/     ULONG32      SpinLockAcquireCount;                                                                         
	/*0x3564*/     ULONG32      SpinLockContentionCount;                                                                      
	/*0x3568*/     ULONG32      SpinLockSpinCount;                                                                            
	/*0x356C*/     ULONG32      IpiSendRequestBroadcastCount;                                                                 
	/*0x3570*/     ULONG32      IpiSendRequestRoutineCount;                                                                   
	/*0x3574*/     ULONG32      IpiSendSoftwareInterruptCount;                                                                
	/*0x3578*/     ULONG32      ExInitializeResourceCount;                                                                    
	/*0x357C*/     ULONG32      ExReInitializeResourceCount;                                                                  
	/*0x3580*/     ULONG32      ExDeleteResourceCount;                                                                        
	/*0x3584*/     ULONG32      ExecutiveResourceAcquiresCount;                                                               
	/*0x3588*/     ULONG32      ExecutiveResourceContentionsCount;                                                            
	/*0x358C*/     ULONG32      ExecutiveResourceReleaseExclusiveCount;                                                       
	/*0x3590*/     ULONG32      ExecutiveResourceReleaseSharedCount;                                                          
	/*0x3594*/     ULONG32      ExecutiveResourceConvertsCount;                                                               
	/*0x3598*/     ULONG32      ExAcqResExclusiveAttempts;                                                                    
	/*0x359C*/     ULONG32      ExAcqResExclusiveAcquiresExclusive;                                                           
	/*0x35A0*/     ULONG32      ExAcqResExclusiveAcquiresExclusiveRecursive;                                                  
	/*0x35A4*/     ULONG32      ExAcqResExclusiveWaits;                                                                       
	/*0x35A8*/     ULONG32      ExAcqResExclusiveNotAcquires;                                                                 
	/*0x35AC*/     ULONG32      ExAcqResSharedAttempts;                                                                       
	/*0x35B0*/     ULONG32      ExAcqResSharedAcquiresExclusive;                                                              
	/*0x35B4*/     ULONG32      ExAcqResSharedAcquiresShared;                                                                 
	/*0x35B8*/     ULONG32      ExAcqResSharedAcquiresSharedRecursive;                                                        
	/*0x35BC*/     ULONG32      ExAcqResSharedWaits;                                                                          
	/*0x35C0*/     ULONG32      ExAcqResSharedNotAcquires;                                                                    
	/*0x35C4*/     ULONG32      ExAcqResSharedStarveExclusiveAttempts;                                                        
	/*0x35C8*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresExclusive;                                               
	/*0x35CC*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresShared;                                                  
	/*0x35D0*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresSharedRecursive;                                         
	/*0x35D4*/     ULONG32      ExAcqResSharedStarveExclusiveWaits;                                                           
	/*0x35D8*/     ULONG32      ExAcqResSharedStarveExclusiveNotAcquires;                                                     
	/*0x35DC*/     ULONG32      ExAcqResSharedWaitForExclusiveAttempts;                                                       
	/*0x35E0*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresExclusive;                                              
	/*0x35E4*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresShared;                                                 
	/*0x35E8*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresSharedRecursive;                                        
	/*0x35EC*/     ULONG32      ExAcqResSharedWaitForExclusiveWaits;                                                          
	/*0x35F0*/     ULONG32      ExAcqResSharedWaitForExclusiveNotAcquires;                                                    
	/*0x35F4*/     ULONG32      ExSetResOwnerPointerExclusive;                                                                
	/*0x35F8*/     ULONG32      ExSetResOwnerPointerSharedNew;                                                                
	/*0x35FC*/     ULONG32      ExSetResOwnerPointerSharedOld;                                                                
	/*0x3600*/     ULONG32      ExTryToAcqExclusiveAttempts;                                                                  
	/*0x3604*/     ULONG32      ExTryToAcqExclusiveAcquires;                                                                  
	/*0x3608*/     ULONG32      ExBoostExclusiveOwner;                                                                        
	/*0x360C*/     ULONG32      ExBoostSharedOwners;                                                                          
	/*0x3610*/     ULONG32      ExEtwSynchTrackingNotificationsCount;                                                         
	/*0x3614*/     ULONG32      ExEtwSynchTrackingNotificationsAccountedCount;                                                
	/*0x3618*/     struct _CONTEXT* Context;                                                                                  
	/*0x361C*/     ULONG32      ContextFlags;                                                                                 
	/*0x3620*/     struct _XSAVE_AREA* ExtendedState;                                                                         
	/*0x3624*/     UINT8        _PADDING2_[0x4];                                                                              
}KPRCB, *PKPRCB;

typedef enum _MI_VAD_TYPE {
	VadNone,
	VadDevicePhysicalMemory,
	VadImageMap,
	VadAwe,
	VadWriteWatch,
	VadLargePages,
	VadRotatePhysical,
	VadLargePageSection
} MI_VAD_TYPE, *PMI_VAD_TYPE;

typedef struct _MMVAD_FLAGS         // 7 elements, 0x4 bytes (sizeof) 
{                                                                     
	/*0x000*/     ULONG32      CommitCharge : 19; // 0 BitPosition                  
	/*0x000*/     ULONG32      NoChange : 1;      // 19 BitPosition                 
	/*0x000*/     ULONG32      VadType : 3;       // 20 BitPosition                 
	/*0x000*/     ULONG32      MemCommit : 1;     // 23 BitPosition                 
	/*0x000*/     ULONG32      Protection : 5;    // 24 BitPosition                 
	/*0x000*/     ULONG32      Spare : 2;         // 29 BitPosition                 
	/*0x000*/     ULONG32      PrivateMemory : 1; // 31 BitPosition                 
}MMVAD_FLAGS, *PMMVAD_FLAGS;                                          

typedef struct _MMVAD_FLAGS3              // 6 elements, 0x4 bytes (sizeof) 
{                                                                           
	/*0x000*/     ULONG32      PreferredNode : 6;       // 0 BitPosition                  
	/*0x000*/     ULONG32      Teb : 1;                 // 6 BitPosition                  
	/*0x000*/     ULONG32      Spare : 1;               // 7 BitPosition                  
	/*0x000*/     ULONG32      SequentialAccess : 1;    // 8 BitPosition                  
	/*0x000*/     ULONG32      LastSequentialTrim : 15; // 9 BitPosition                  
	/*0x000*/     ULONG32      Spare2 : 8;              // 24 BitPosition                 
}MMVAD_FLAGS3, *PMMVAD_FLAGS3;                                              

typedef struct _MMVAD_FLAGS2          // 9 elements, 0x4 bytes (sizeof) 
{                                                                       
	/*0x000*/     UINT32       FileOffset : 24;     // 0 BitPosition                  
	/*0x000*/     UINT32       SecNoChange : 1;     // 24 BitPosition                 
	/*0x000*/     UINT32       OneSecured : 1;      // 25 BitPosition                 
	/*0x000*/     UINT32       MultipleSecured : 1; // 26 BitPosition                 
	/*0x000*/     UINT32       Spare : 1;           // 27 BitPosition                 
	/*0x000*/     UINT32       LongVad : 1;         // 28 BitPosition                 
	/*0x000*/     UINT32       ExtendableFile : 1;  // 29 BitPosition                 
	/*0x000*/     UINT32       Inherit : 1;         // 30 BitPosition                 
	/*0x000*/     UINT32       CopyOnWrite : 1;     // 31 BitPosition                 
}MMVAD_FLAGS2, *PMMVAD_FLAGS2;

typedef struct _MMSUBSECTION_FLAGS            // 8 elements, 0x4 bytes (sizeof) 
{                                                                               
	struct                                    // 3 elements, 0x2 bytes (sizeof) 
	{                                                                           
		/*0x000*/         UINT16       SubsectionAccessed : 1;  // 0 BitPosition                  
		/*0x000*/         UINT16       Protection : 5;          // 1 BitPosition                  
		/*0x000*/         UINT16       StartingSector4132 : 10; // 6 BitPosition                  
	};                                                                          
	struct                                    // 5 elements, 0x2 bytes (sizeof) 
	{                                                                           
		/*0x002*/         UINT16       SubsectionStatic : 1;    // 0 BitPosition                  
		/*0x002*/         UINT16       GlobalMemory : 1;        // 1 BitPosition                  
		/*0x002*/         UINT16       DirtyPages : 1;          // 2 BitPosition                  
		/*0x002*/         UINT16       Spare : 1;               // 3 BitPosition                  
		/*0x002*/         UINT16       SectorEndOffset : 12;    // 4 BitPosition                  
	};                                                                          
}MMSUBSECTION_FLAGS, *PMMSUBSECTION_FLAGS;

typedef struct _MMPTE_HIGHLOW // 2 elements, 0x8 bytes (sizeof) 
{                                                               
	/*0x000*/     ULONG32      LowPart;                                       
	/*0x004*/     ULONG32      HighPart;                                      
}MMPTE_HIGHLOW, *PMMPTE_HIGHLOW;

typedef struct _MMPTE_HARDWARE         // 14 elements, 0x8 bytes (sizeof) 
{                                                                         
	/*0x000*/     UINT64       Valid : 1;            // 0 BitPosition                   
	/*0x000*/     UINT64       Dirty1 : 1;           // 1 BitPosition                   
	/*0x000*/     UINT64       Owner : 1;            // 2 BitPosition                   
	/*0x000*/     UINT64       WriteThrough : 1;     // 3 BitPosition                   
	/*0x000*/     UINT64       CacheDisable : 1;     // 4 BitPosition                   
	/*0x000*/     UINT64       Accessed : 1;         // 5 BitPosition                   
	/*0x000*/     UINT64       Dirty : 1;            // 6 BitPosition                   
	/*0x000*/     UINT64       LargePage : 1;        // 7 BitPosition                   
	/*0x000*/     UINT64       Global : 1;           // 8 BitPosition                   
	/*0x000*/     UINT64       CopyOnWrite : 1;      // 9 BitPosition                   
	/*0x000*/     UINT64       Unused : 1;           // 10 BitPosition                  
	/*0x000*/     UINT64       Write : 1;            // 11 BitPosition                  
	/*0x000*/     UINT64       PageFrameNumber : 26; // 12 BitPosition                  
	/*0x000*/     UINT64       reserved1 : 26;       // 38 BitPosition                  
}MMPTE_HARDWARE, *PMMPTE_HARDWARE;                                        

typedef struct _MMPTE_PROTOTYPE     // 8 elements, 0x8 bytes (sizeof) 
{                                                                     
	/*0x000*/     UINT64       Valid : 1;         // 0 BitPosition                  
	/*0x000*/     UINT64       Unused0 : 7;       // 1 BitPosition                  
	/*0x000*/     UINT64       ReadOnly : 1;      // 8 BitPosition                  
	/*0x000*/     UINT64       Unused1 : 1;       // 9 BitPosition                  
	/*0x000*/     UINT64       Prototype : 1;     // 10 BitPosition                 
	/*0x000*/     UINT64       Protection : 5;    // 11 BitPosition                 
	/*0x000*/     UINT64       Unused : 16;       // 16 BitPosition                 
	/*0x000*/     UINT64       ProtoAddress : 32; // 32 BitPosition                 
}MMPTE_PROTOTYPE, *PMMPTE_PROTOTYPE;                                  

typedef struct _MMPTE_SOFTWARE      // 8 elements, 0x8 bytes (sizeof) 
{                                                                     
	/*0x000*/     UINT64       Valid : 1;         // 0 BitPosition                  
	/*0x000*/     UINT64       PageFileLow : 4;   // 1 BitPosition                  
	/*0x000*/     UINT64       Protection : 5;    // 5 BitPosition                  
	/*0x000*/     UINT64       Prototype : 1;     // 10 BitPosition                 
	/*0x000*/     UINT64       Transition : 1;    // 11 BitPosition                 
	/*0x000*/     UINT64       InStore : 1;       // 12 BitPosition                 
	/*0x000*/     UINT64       Unused1 : 19;      // 13 BitPosition                 
	/*0x000*/     UINT64       PageFileHigh : 32; // 32 BitPosition                 
}MMPTE_SOFTWARE, *PMMPTE_SOFTWARE;                                    

typedef struct _MMPTE_TIMESTAMP        // 7 elements, 0x8 bytes (sizeof) 
{                                                                        
	/*0x000*/     UINT64       MustBeZero : 1;       // 0 BitPosition                  
	/*0x000*/     UINT64       PageFileLow : 4;      // 1 BitPosition                  
	/*0x000*/     UINT64       Protection : 5;       // 5 BitPosition                  
	/*0x000*/     UINT64       Prototype : 1;        // 10 BitPosition                 
	/*0x000*/     UINT64       Transition : 1;       // 11 BitPosition                 
	/*0x000*/     UINT64       Unused : 20;          // 12 BitPosition                 
	/*0x000*/     UINT64       GlobalTimeStamp : 32; // 32 BitPosition                 
}MMPTE_TIMESTAMP, *PMMPTE_TIMESTAMP;                                     

typedef struct _MMPTE_TRANSITION       // 10 elements, 0x8 bytes (sizeof) 
{                                                                         
	/*0x000*/     UINT64       Valid : 1;            // 0 BitPosition                   
	/*0x000*/     UINT64       Write : 1;            // 1 BitPosition                   
	/*0x000*/     UINT64       Owner : 1;            // 2 BitPosition                   
	/*0x000*/     UINT64       WriteThrough : 1;     // 3 BitPosition                   
	/*0x000*/     UINT64       CacheDisable : 1;     // 4 BitPosition                   
	/*0x000*/     UINT64       Protection : 5;       // 5 BitPosition                   
	/*0x000*/     UINT64       Prototype : 1;        // 10 BitPosition                  
	/*0x000*/     UINT64       Transition : 1;       // 11 BitPosition                  
	/*0x000*/     UINT64       PageFrameNumber : 26; // 12 BitPosition                  
	/*0x000*/     UINT64       Unused : 26;          // 38 BitPosition                  
}MMPTE_TRANSITION, *PMMPTE_TRANSITION;                                    

typedef struct _MMPTE_SUBSECTION         // 6 elements, 0x8 bytes (sizeof) 
{                                                                          
	/*0x000*/     UINT64       Valid : 1;              // 0 BitPosition                  
	/*0x000*/     UINT64       Unused0 : 4;            // 1 BitPosition                  
	/*0x000*/     UINT64       Protection : 5;         // 5 BitPosition                  
	/*0x000*/     UINT64       Prototype : 1;          // 10 BitPosition                 
	/*0x000*/     UINT64       Unused1 : 21;           // 11 BitPosition                 
	/*0x000*/     UINT64       SubsectionAddress : 32; // 32 BitPosition                 
}MMPTE_SUBSECTION, *PMMPTE_SUBSECTION;                                     

typedef struct _MMPTE_LIST       // 6 elements, 0x8 bytes (sizeof) 
{                                                                  
	/*0x000*/     UINT64       Valid : 1;      // 0 BitPosition                  
	/*0x000*/     UINT64       OneEntry : 1;   // 1 BitPosition                  
	/*0x000*/     UINT64       filler0 : 8;    // 2 BitPosition                  
	/*0x000*/     UINT64       Prototype : 1;  // 10 BitPosition                 
	/*0x000*/     UINT64       filler1 : 21;   // 11 BitPosition                 
	/*0x000*/     UINT64       NextEntry : 32; // 32 BitPosition                 
}MMPTE_LIST, *PMMPTE_LIST;

typedef struct _HARDWARE_PTE                   // 16 elements, 0x8 bytes (sizeof) 
{                                                                                 
	union                                      // 2 elements, 0x8 bytes (sizeof)  
	{                                                                             
		struct                                 // 14 elements, 0x8 bytes (sizeof) 
		{                                                                         
			/*0x000*/             UINT64       Valid : 1;            // 0 BitPosition                   
			/*0x000*/             UINT64       Write : 1;            // 1 BitPosition                   
			/*0x000*/             UINT64       Owner : 1;            // 2 BitPosition                   
			/*0x000*/             UINT64       WriteThrough : 1;     // 3 BitPosition                   
			/*0x000*/             UINT64       CacheDisable : 1;     // 4 BitPosition                   
			/*0x000*/             UINT64       Accessed : 1;         // 5 BitPosition                   
			/*0x000*/             UINT64       Dirty : 1;            // 6 BitPosition                   
			/*0x000*/             UINT64       LargePage : 1;        // 7 BitPosition                   
			/*0x000*/             UINT64       Global : 1;           // 8 BitPosition                   
			/*0x000*/             UINT64       CopyOnWrite : 1;      // 9 BitPosition                   
			/*0x000*/             UINT64       Prototype : 1;        // 10 BitPosition                  
			/*0x000*/             UINT64       reserved0 : 1;        // 11 BitPosition                  
			/*0x000*/             UINT64       PageFrameNumber : 26; // 12 BitPosition                  
			/*0x000*/             UINT64       reserved1 : 26;       // 38 BitPosition                  
		};                                                                        
		struct                                 // 2 elements, 0x8 bytes (sizeof)  
		{                                                                         
			/*0x000*/             ULONG32      LowPart;                                                 
			/*0x004*/             ULONG32      HighPart;                                                
		};                                                                        
	};                                                                            
}HARDWARE_PTE, *PHARDWARE_PTE;

typedef struct _MMPTE                      // 1 elements, 0x8 bytes (sizeof)  
{                                                                             
	union                                  // 11 elements, 0x8 bytes (sizeof) 
	{                                                                         
		/*0x000*/         UINT64       Long;                                                    
		/*0x000*/         UINT64       VolatileLong;                                            
		/*0x000*/         struct _MMPTE_HIGHLOW HighLow;     // 2 elements, 0x8 bytes (sizeof)  
		/*0x000*/         struct _HARDWARE_PTE Flush;        // 16 elements, 0x8 bytes (sizeof) 
		/*0x000*/         struct _MMPTE_HARDWARE Hard;       // 14 elements, 0x8 bytes (sizeof) 
		/*0x000*/         struct _MMPTE_PROTOTYPE Proto;     // 8 elements, 0x8 bytes (sizeof)  
		/*0x000*/         struct _MMPTE_SOFTWARE Soft;       // 8 elements, 0x8 bytes (sizeof)  
		/*0x000*/         struct _MMPTE_TIMESTAMP TimeStamp; // 7 elements, 0x8 bytes (sizeof)  
		/*0x000*/         struct _MMPTE_TRANSITION Trans;    // 10 elements, 0x8 bytes (sizeof) 
		/*0x000*/         struct _MMPTE_SUBSECTION Subsect;  // 6 elements, 0x8 bytes (sizeof)  
		/*0x000*/         struct _MMPTE_LIST List;           // 6 elements, 0x8 bytes (sizeof)  
	}u;                                                                       
}MMPTE, *PMMPTE;

typedef struct _SUBSECTION                          // 9 elements, 0x20 bytes (sizeof) 
          {                                                                                      
/*0x000*/     struct _CONTROL_AREA* ControlArea;                                                 
/*0x004*/     struct _MMPTE* SubsectionBase;                                                     
/*0x008*/     struct _SUBSECTION* NextSubsection;                                                
/*0x00C*/     ULONG32      PtesInSubsection;                                                     
              union                                           // 2 elements, 0x4 bytes (sizeof)  
              {                                                                                  
/*0x010*/         ULONG32      UnusedPtes;                                                       
/*0x010*/         struct _MM_AVL_TABLE* GlobalPerSessionHead;                                    
              };                                                                                 
              union                                           // 2 elements, 0x4 bytes (sizeof)  
              {                                                                                  
/*0x014*/         ULONG32      LongFlags;                                                        
/*0x014*/         struct _MMSUBSECTION_FLAGS SubsectionFlags; // 8 elements, 0x4 bytes (sizeof)  
              }u;                                                                                
/*0x018*/     ULONG32      StartingSector;                                                       
/*0x01C*/     ULONG32      NumberOfFullSectors;                                                  
          }SUBSECTION, *PSUBSECTION;

typedef struct _MMSUBSECTION_NODE                   // 6 elements, 0x18 bytes (sizeof) 
          {                                                                                      
              union                                           // 2 elements, 0x4 bytes (sizeof)  
              {                                                                                  
/*0x000*/         ULONG32      LongFlags;                                                        
/*0x000*/         struct _MMSUBSECTION_FLAGS SubsectionFlags; // 8 elements, 0x4 bytes (sizeof)  
              }u;                                                                                
/*0x004*/     ULONG32      StartingSector;                                                       
/*0x008*/     ULONG32      NumberOfFullSectors;                                                  
              union                                           // 2 elements, 0x4 bytes (sizeof)  
              {                                                                                  
/*0x00C*/         LONG32       Balance : 2;                   // 0 BitPosition                   
/*0x00C*/         struct _MMSUBSECTION_NODE* Parent;                                             
              }u1;                                                                               
/*0x010*/     struct _MMSUBSECTION_NODE* LeftChild;                                              
/*0x014*/     struct _MMSUBSECTION_NODE* RightChild;                                             
          }MMSUBSECTION_NODE, *PMMSUBSECTION_NODE;

typedef struct _MSUBSECTION                         // 15 elements, 0x38 bytes (sizeof) 
          {                                                                                       
/*0x000*/     struct _CONTROL_AREA* ControlArea;                                                  
/*0x004*/     struct _MMPTE* SubsectionBase;                                                      
              union                                           // 2 elements, 0x4 bytes (sizeof)   
              {                                                                                   
/*0x008*/         struct _SUBSECTION* NextSubsection;                                             
/*0x008*/         struct _MSUBSECTION* NextMappedSubsection;                                      
              };                                                                                  
/*0x00C*/     ULONG32      PtesInSubsection;                                                      
              union                                           // 2 elements, 0x4 bytes (sizeof)   
              {                                                                                   
/*0x010*/         ULONG32      UnusedPtes;                                                        
/*0x010*/         struct _MM_AVL_TABLE* GlobalPerSessionHead;                                     
              };                                                                                  
              union                                           // 2 elements, 0x4 bytes (sizeof)   
              {                                                                                   
/*0x014*/         ULONG32      LongFlags;                                                         
/*0x014*/         struct _MMSUBSECTION_FLAGS SubsectionFlags; // 8 elements, 0x4 bytes (sizeof)   
              }u;                                                                                 
/*0x018*/     ULONG32      StartingSector;                                                        
/*0x01C*/     ULONG32      NumberOfFullSectors;                                                   
              union                                           // 2 elements, 0x4 bytes (sizeof)   
              {                                                                                   
/*0x020*/         LONG32       Balance : 2;                   // 0 BitPosition                    
/*0x020*/         struct _MMSUBSECTION_NODE* Parent;                                              
              }u1;                                                                                
/*0x024*/     struct _MMSUBSECTION_NODE* LeftChild;                                               
/*0x028*/     struct _MMSUBSECTION_NODE* RightChild;                                              
/*0x02C*/     struct _LIST_ENTRY DereferenceList;             // 2 elements, 0x8 bytes (sizeof)   
/*0x034*/     ULONG32      NumberOfMappedViews;                                                   
          }MSUBSECTION, *PMSUBSECTION;

typedef struct _MMVAD                          // 15 elements, 0x3C bytes (sizeof) 
          {                                                                                  
              union                                      // 2 elements, 0x4 bytes (sizeof)   
              {                                                                              
/*0x000*/         LONG32       Balance : 2;              // 0 BitPosition                    
/*0x000*/         struct _MMVAD* Parent;                                                     
              }u1;                                                                           
/*0x004*/     struct _MMVAD* LeftChild;                                                      
/*0x008*/     struct _MMVAD* RightChild;                                                     
/*0x00C*/     ULONG32      StartingVpn;                                                      
/*0x010*/     ULONG32      EndingVpn;                                                        
              union                                      // 2 elements, 0x4 bytes (sizeof)   
              {                                                                              
/*0x014*/         ULONG32      LongFlags;                                                    
/*0x014*/         struct _MMVAD_FLAGS VadFlags;          // 7 elements, 0x4 bytes (sizeof)   
              }u;                                                                            
/*0x018*/     struct _EX_PUSH_LOCK_S PushLock;             // 7 elements, 0x4 bytes (sizeof)   
              union                                      // 2 elements, 0x4 bytes (sizeof)   
              {                                                                              
/*0x01C*/         ULONG32      LongFlags3;                                                   
/*0x01C*/         struct _MMVAD_FLAGS3 VadFlags3;        // 6 elements, 0x4 bytes (sizeof)   
              }u5;                                                                           
              union                                      // 2 elements, 0x4 bytes (sizeof)   
              {                                                                              
/*0x020*/         ULONG32      LongFlags2;                                                   
/*0x020*/         struct _MMVAD_FLAGS2 VadFlags2;        // 9 elements, 0x4 bytes (sizeof)   
              }u2;                                                                           
              union                                      // 2 elements, 0x4 bytes (sizeof)   
              {                                                                              
/*0x024*/         struct _SUBSECTION* Subsection;                                            
/*0x024*/         struct _MSUBSECTION* MappedSubsection;                                     
              };                                                                             
/*0x028*/     struct _MMPTE* FirstPrototypePte;                                              
/*0x02C*/     struct _MMPTE* LastContiguousPte;                                              
/*0x030*/     struct _LIST_ENTRY ViewLinks;              // 2 elements, 0x8 bytes (sizeof)   
/*0x038*/     struct _EPROCESS_S* VadsProcess;                                                 
          }MMVAD, *PMMVAD;


typedef struct _FNSAVE_FORMAT      // 8 elements, 0x6C bytes (sizeof) 
{                                                                     
	/*0x000*/     ULONG32      ControlWord;                                         
	/*0x004*/     ULONG32      StatusWord;                                          
	/*0x008*/     ULONG32      TagWord;                                             
	/*0x00C*/     ULONG32      ErrorOffset;                                         
	/*0x010*/     ULONG32      ErrorSelector;                                       
	/*0x014*/     ULONG32      DataOffset;                                          
	/*0x018*/     ULONG32      DataSelector;                                        
	/*0x01C*/     UINT8        RegisterArea[80];                                    
}FNSAVE_FORMAT, *PFNSAVE_FORMAT;

typedef struct _FXSAVE_FORMAT       // 13 elements, 0x1E0 bytes (sizeof) 
{                                                                        
	/*0x000*/     UINT16       ControlWord;                                            
	/*0x002*/     UINT16       StatusWord;                                             
	/*0x004*/     UINT16       TagWord;                                                
	/*0x006*/     UINT16       ErrorOpcode;                                            
	/*0x008*/     ULONG32      ErrorOffset;                                            
	/*0x00C*/     ULONG32      ErrorSelector;                                          
	/*0x010*/     ULONG32      DataOffset;                                             
	/*0x014*/     ULONG32      DataSelector;                                           
	/*0x018*/     ULONG32      MXCsr;                                                  
	/*0x01C*/     ULONG32      MXCsrMask;                                              
	/*0x020*/     UINT8        RegisterArea[128];                                      
	/*0x0A0*/     UINT8        Reserved3[128];                                         
	/*0x120*/     UINT8        Reserved4[192];                                         
}FXSAVE_FORMAT, *PFXSAVE_FORMAT;

typedef struct _KERNEL_STACK_SEGMENT // 5 elements, 0x14 bytes (sizeof) 
{                                                                       
	/*0x000*/     ULONG32      StackBase;                                             
	/*0x004*/     ULONG32      StackLimit;                                            
	/*0x008*/     ULONG32      KernelStack;                                           
	/*0x00C*/     ULONG32      InitialStack;                                          
	/*0x010*/     ULONG32      ActualLimit;                                           
}KERNEL_STACK_SEGMENT, *PKERNEL_STACK_SEGMENT;

typedef struct _KERNEL_STACK_CONTROL                  // 7 elements, 0x1C bytes (sizeof) 
{                                                                                        
	union                                             // 2 elements, 0x4 bytes (sizeof)  
	{                                                                                    
		/*0x000*/         struct _KTRAP_FRAME* PreviousTrapFrame;                                          
		/*0x000*/         VOID*        PreviousExceptionList;                                              
	};                                                                                   
	union                                             // 2 elements, 0x4 bytes (sizeof)  
	{                                                                                    
		/*0x004*/         ULONG32      StackControlFlags;                                                  
		struct                                        // 3 elements, 0x4 bytes (sizeof)  
		{                                                                                
			/*0x004*/             ULONG32      PreviousLargeStack : 1;      // 0 BitPosition                   
			/*0x004*/             ULONG32      PreviousSegmentsPresent : 1; // 1 BitPosition                   
			/*0x004*/             ULONG32      ExpandCalloutStack : 1;      // 2 BitPosition                   
		};                                                                               
	};                                                                                   
	/*0x008*/     struct _KERNEL_STACK_SEGMENT Previous;            // 5 elements, 0x14 bytes (sizeof) 
}KERNEL_STACK_CONTROL, *PKERNEL_STACK_CONTROL;

typedef struct _KSTACK_AREA                    // 5 elements, 0x210 bytes (sizeof)  
{                                                                                   
	union                                      // 2 elements, 0x1E0 bytes (sizeof)  
	{                                                                               
		/*0x000*/         struct _FNSAVE_FORMAT FnArea;          // 8 elements, 0x6C bytes (sizeof)   
		/*0x000*/         struct _FXSAVE_FORMAT NpxFrame;        // 13 elements, 0x1E0 bytes (sizeof) 
	};                                                                              
	/*0x1E0*/     struct _KERNEL_STACK_CONTROL StackControl; // 7 elements, 0x1C bytes (sizeof)   
	/*0x1FC*/     ULONG32      Cr0NpxState;                                                       
	/*0x200*/     ULONG32      Padding[4];                                                        
}KSTACK_AREA, *PKSTACK_AREA;

typedef struct _MODULE_ENTRY { 
	LIST_ENTRY le_mod; 
	ULONG unknown[4]; 
	ULONG base; 
	ULONG driver_start; 
	ULONG sectionsize; 
	UNICODE_STRING driver_Path; 
	UNICODE_STRING driver_Name; 
} MODULE_ENTRY, *PMODULE_ENTRY; 

/************************************************************************/

#endif