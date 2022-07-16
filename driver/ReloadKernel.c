#include "CommonFunc.h"
#include "LinkDbg.h"
#include "stdio.h"

#define DEBUGTOOL_NAME1		"cheatengine"
#define DEBUGTOOL_NAME2		"Ollydbg"
#define	DEBUGTOOL_NAME3		"Cheat Engine"

#define	__Max(a,b)	a>b?a:b

//global
PVOID	g_lp_virtual_pointer;
ULONG	g_ntcreatefile;
ULONG	g_fastcall_hookpointer;
ULONG	g_goto_origfunc;
ULONG	g_new_kernel_inc;
ServiceDescriptorTableEntry_t	*g_pnew_service_table;

//搜索kifastcallentry hook的地方
ULONG SearchHookPointer(ULONG StartAddress)
{
	ULONG	u_index;

	UCHAR	*p = (UCHAR*)StartAddress;

	for (u_index = 0;u_index < 200;u_index++)
	{
		if (*p==0x2B&&
			*(p+1)==0xE1&&
			*(p+2)==0xC1&&
			*(p+3)==0xE9&&
			*(p+4)==0x02)
		{
			return (ULONG)p;
		}

		p--;
	}

	return 0;
}

//过滤kifastcallentry
ULONG FilterKiFastCallEntry(ULONG ServiceTableBase,ULONG FuncIndex,ULONG OrigFuncAddress)
{
	ULONG	ProcessObj;

	ProcessObj = *(ULONG*)((ULONG)PsGetCurrentThread()+0x150);

	if (ServiceTableBase==(ULONG)KeServiceDescriptorTable.ServiceTableBase)
	{
		if (strstr((char*)ProcessObj+0x16C,DEBUGTOOL_NAME1)!=0
			||strstr((char*)ProcessObj+0x16C,DEBUGTOOL_NAME2)!=0
			||strstr((char*)ProcessObj+0x16C,DEBUGTOOL_NAME3)!=0)
		{
			return g_pnew_service_table->ServiceTableBase[FuncIndex];
		}
	}

	return OrigFuncAddress;
}

__declspec(naked)
	void NewKiFastCallEntry()
{
	__asm{
		pushad
		pushfd

		push	edx
		push	eax
		push	edi
		call	FilterKiFastCallEntry
		mov		[esp+0x18],eax

		popfd
		popad

		sub     esp,ecx
		shr     ecx,2
		jmp		g_goto_origfunc
	}
}

NTSTATUS NewNtCreateFile (
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
	)
{
	ULONG	u_call_retaddr;

	__asm{
		pushad
		mov		eax,[ebp+0x4]
		mov		u_call_retaddr,eax
		popad
	}

	g_fastcall_hookpointer = SearchHookPointer(u_call_retaddr);
	if (g_fastcall_hookpointer==0)
	{
		KdPrint(("search failed."));
	}else{
		KdPrint(("search success."));
	}

	PageProtectOff();
	KeServiceDescriptorTable.ServiceTableBase[CREATE_FILE_ID] = (unsigned int)g_ntcreatefile;
	PageProtectOn();

	return ((NTCREATEFILE)g_ntcreatefile)(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);
}

//搜索kifastcallentry
void SearchKiFastCallEntry()
{
	HANDLE				hfile;
	NTSTATUS			status;
	OBJECT_ATTRIBUTES	obj_attributes;
	UNICODE_STRING		str_file_name;
	IO_STATUS_BLOCK		io_status_block;

	RtlInitUnicodeString(&str_file_name,L"\\??\\C:\\Windows\\System32\\ntkrnlpa.exe");
	InitializeObjectAttributes(
		&obj_attributes,
		&str_file_name,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	g_ntcreatefile = KeServiceDescriptorTable.ServiceTableBase[CREATE_FILE_ID];
	PageProtectOff();
	KeServiceDescriptorTable.ServiceTableBase[CREATE_FILE_ID] = (unsigned int)NewNtCreateFile;
	PageProtectOn();

	status = ZwCreateFile(
		&hfile,
		FILE_ALL_ACCESS,
		&obj_attributes,
		&io_status_block,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
		NULL,
		0);
	if (NT_SUCCESS(status))
	{
		ZwClose(hfile);
	}
}

void UnHookKiFastCallEntry()
{
	UCHAR	str_origfuncode[5] = {0x2B,0xE1,0xC1,0xE9,0x02};

	if (g_fastcall_hookpointer==0)
	{	return;	}

	PageProtectOff();
	RtlCopyMemory((PVOID)g_fastcall_hookpointer,str_origfuncode,5);
	PageProtectOn();

	if (g_lp_virtual_pointer)
	{
		ExFreePool(g_lp_virtual_pointer);
	}
}

NTSTATUS ReadFileToMemory(wchar_t *strFileName,PVOID *lpVirtualAddress,PVOID pOrigImage);

void HookKiFastCallEntry(PDRIVER_OBJECT pDriverObject)
{
	ULONG	u_temp;
	UCHAR	str_jmp_code[5];

	ANSI_STRING		asMapImagePath;
	UNICODE_STRING	usMapImagePath;

	SYSTEM_MODULE			ImageInfo;
	LDR_DATA_TABLE_ENTRY	*pldr_data_table_entry;

	if (!NT_SUCCESS(GetModuleByName("ntoskrnl.exe",&ImageInfo)) &&
		!NT_SUCCESS(GetModuleByName("ntkrnlpa.exe",&ImageInfo))	)
	{
		return;
	}

	RtlInitAnsiString(&asMapImagePath,ImageInfo.ImageName);
	RtlAnsiStringToUnicodeString(&usMapImagePath,&asMapImagePath,TRUE);

	ReadFileToMemory(
		usMapImagePath.Buffer,		//ntoskrnl  ntkrnlpa
		&g_lp_virtual_pointer,
		ImageInfo.ImageBase);

	RtlFreeUnicodeString(&usMapImagePath);

	g_new_kernel_inc = (ULONG)g_lp_virtual_pointer - (ULONG)ImageInfo.ImageBase;

	SearchKiFastCallEntry();
	if (!g_fastcall_hookpointer){	return;	}
	g_goto_origfunc = g_fastcall_hookpointer + 5;

	str_jmp_code[0] = 0xE9;

	u_temp = (ULONG)NewKiFastCallEntry - g_fastcall_hookpointer - 5;
	*(ULONG*)&str_jmp_code[1] = u_temp;

	PageProtectOff();

	RtlCopyMemory((PVOID)g_fastcall_hookpointer,str_jmp_code,5);

	PageProtectOn();
}

VOID SetNewSSDT(PVOID pNewImage,\
				PVOID pOrigImage,\
				ServiceDescriptorTableEntry_t **pNewSeviceTable)
{
	ULONG							u_index;
	ULONG							u_offset;
	ServiceDescriptorTableEntry_t	*pnew_ssdt;


	g_new_kernel_inc = (ULONG)pNewImage - (ULONG)pOrigImage;
	pnew_ssdt = (ServiceDescriptorTableEntry_t *)((ULONG)&KeServiceDescriptorTable + g_new_kernel_inc);

	if (!MmIsAddressValid(pnew_ssdt))
	{
		KdPrint(("pNewSSDT"));
		return;
	}

	pnew_ssdt->NumberOfServices = KeServiceDescriptorTable.NumberOfServices;

	u_offset = (ULONG)KeServiceDescriptorTable.ServiceTableBase - (ULONG)pOrigImage;
	pnew_ssdt->ServiceTableBase = (unsigned int*)((ULONG)pNewImage + u_offset);
	if (!MmIsAddressValid(pnew_ssdt->ServiceTableBase))
	{
		KdPrint(("pNewSSDT->ServiceTableBase:%X",pnew_ssdt->ServiceTableBase));
		return;
	}

	for (u_index = 0;u_index<pnew_ssdt->NumberOfServices;u_index++)
	{
		pnew_ssdt->ServiceTableBase[u_index] += g_new_kernel_inc;
	}

	u_offset = (ULONG)KeServiceDescriptorTable.ParamTableBase - (ULONG)pOrigImage;
	pnew_ssdt->ParamTableBase = (unsigned char*)((ULONG)pNewImage + u_offset);
	if (!MmIsAddressValid(pnew_ssdt->ParamTableBase))
	{
		KdPrint(("pNewSSDT->ParamTableBase"));
		return;
	}
	RtlCopyMemory(pnew_ssdt->ParamTableBase,KeServiceDescriptorTable.ParamTableBase,pnew_ssdt->NumberOfServices*sizeof(char));

	*pNewSeviceTable = pnew_ssdt;
	KdPrint(("set new ssdt success."));
}

void RelocModule(PVOID pNewImage,PVOID pOrigImage)
{
	ULONG					u_index;
	ULONG					u_reloctable_size;
	USHORT					type_value;
	USHORT					*poffset_array;
	ULONG					u_offset_array_size;

	ULONG					u_reloc_offset;

	ULONG					u_reloc_address;

	PIMAGE_DOS_HEADER		pimage_dos_header;
	PIMAGE_NT_HEADERS		pimage_nt_header;
	IMAGE_DATA_DIRECTORY	image_data_directory;
	IMAGE_BASE_RELOCATION	*pimage_base_relocation;

	pimage_dos_header = (PIMAGE_DOS_HEADER)pNewImage;
	pimage_nt_header = (PIMAGE_NT_HEADERS)((ULONG)pNewImage + pimage_dos_header->e_lfanew);

	u_reloc_offset = (ULONG)pOrigImage - pimage_nt_header->OptionalHeader.ImageBase;

	image_data_directory = pimage_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	pimage_base_relocation = (PIMAGE_BASE_RELOCATION)(image_data_directory.VirtualAddress + (ULONG)pNewImage);
	u_reloctable_size = image_data_directory.Size;

	while(u_reloctable_size)
	{
		u_offset_array_size = (pimage_base_relocation->SizeOfBlock - sizeof(ULONG)*2) / sizeof(USHORT);

		poffset_array = pimage_base_relocation->TypeOffset;
		for (u_index = 0;u_index<u_offset_array_size;u_index++)
		{
			type_value = poffset_array[u_index];
			if (type_value>>12==IMAGE_REL_BASED_HIGHLOW)
			{
				u_reloc_address = (type_value&0xfff)+pimage_base_relocation->VirtualAddress + (ULONG)pNewImage;
				if (!MmIsAddressValid((PVOID)u_reloc_address))
				{
					continue;
				}

				*(ULONG*)u_reloc_address += u_reloc_offset;
			}
		}

		u_reloctable_size -= pimage_base_relocation->SizeOfBlock;
		pimage_base_relocation = (IMAGE_BASE_RELOCATION *)(\
			(ULONG)pimage_base_relocation + pimage_base_relocation->SizeOfBlock);
	}
}

NTSTATUS ReadFileToMemory(wchar_t *strFileName,PVOID *lpVirtualAddress,PVOID pOrigImage)
{
	NTSTATUS				status;
	HANDLE					hfile;
	LARGE_INTEGER			file_offset;
	UNICODE_STRING			str_file_name;
	OBJECT_ATTRIBUTES		obj_attributes;
	IO_STATUS_BLOCK			io_status_block;

	IMAGE_DOS_HEADER		image_dos_header;
	IMAGE_NT_HEADERS		image_nt_header;
	IMAGE_SECTION_HEADER	*pimage_section_header;

	ULONG					u_index;
	PVOID					lp_virtual_pointer;
	ULONG					u_section_address,u_size_of_section;
	ULONG					u_pointer_to_rawdata;

	if (!MmIsAddressValid(strFileName))
	{
		return STATUS_UNSUCCESSFUL;
	}

	RtlInitUnicodeString(&str_file_name,strFileName);

	InitializeObjectAttributes(
		&obj_attributes,
		&str_file_name,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	status = ZwCreateFile(
		&hfile,
		FILE_ALL_ACCESS,
		&obj_attributes,
		&io_status_block,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
		NULL,
		0);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwCreateFile failed:%X",status));
		return status;
	}

	file_offset.QuadPart = 0;
	status = ZwReadFile(
		hfile,
		NULL,
		NULL,
		NULL,
		&io_status_block,
		&image_dos_header,
		sizeof(IMAGE_DOS_HEADER),
		&file_offset,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("read iamge_dos_header failed:%X",status));
		ZwClose(hfile);
		return status;
	}

	file_offset.QuadPart = image_dos_header.e_lfanew;
	status = ZwReadFile(
		hfile,
		NULL,
		NULL,
		NULL,
		&io_status_block,
		&image_nt_header,
		sizeof(IMAGE_NT_HEADERS),
		&file_offset,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("read IMAGE_NT_HEADERS failed:%X",status));
		ZwClose(hfile);
		return status;
	}

	pimage_section_header = ExAllocatePool(
		NonPagedPool,
		sizeof(IMAGE_SECTION_HEADER)*image_nt_header.FileHeader.NumberOfSections);
	if (pimage_section_header==0)
	{
		KdPrint(("pImageSectionHeader is null."));
		ZwClose(hfile);
		return STATUS_UNSUCCESSFUL;
	}

	file_offset.QuadPart += sizeof(IMAGE_NT_HEADERS);
	status = ZwReadFile(
		hfile,
		NULL,
		NULL,
		NULL,
		&io_status_block,
		pimage_section_header,
		sizeof(IMAGE_SECTION_HEADER)*image_nt_header.FileHeader.NumberOfSections,
		&file_offset,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("read IMAGE_SECTION_HEADER failed:%X",status));
		ExFreePool(pimage_section_header);
		ZwClose(hfile);
		return status;
	}

	lp_virtual_pointer = ExAllocatePool(NonPagedPool,image_nt_header.OptionalHeader.SizeOfImage);
	if (lp_virtual_pointer==0)
	{
		KdPrint(("lpVirtualPointer is null"));
		ExFreePool(pimage_section_header);
		ZwClose(hfile);
		return STATUS_UNSUCCESSFUL;
	}

	memset(lp_virtual_pointer,0,image_nt_header.OptionalHeader.SizeOfImage);
	RtlCopyMemory(
		lp_virtual_pointer,
		&image_dos_header,
		sizeof(IMAGE_DOS_HEADER));
	RtlCopyMemory(
		(PVOID)((ULONG)lp_virtual_pointer+image_dos_header.e_lfanew),
		&image_nt_header,
		sizeof(IMAGE_NT_HEADERS));
	RtlCopyMemory(
		(PVOID)((ULONG)lp_virtual_pointer+image_dos_header.e_lfanew+sizeof(IMAGE_NT_HEADERS)),
		pimage_section_header,
		sizeof(IMAGE_SECTION_HEADER)*image_nt_header.FileHeader.NumberOfSections);

	for (u_index = 0;u_index<image_nt_header.FileHeader.NumberOfSections;u_index++)
	{
		u_section_address = pimage_section_header[u_index].VirtualAddress;
		u_size_of_section = __Max(pimage_section_header[u_index].SizeOfRawData,
			pimage_section_header[u_index].Misc.VirtualSize);

		u_pointer_to_rawdata = pimage_section_header[u_index].PointerToRawData;

		file_offset.QuadPart = u_pointer_to_rawdata;
		status = ZwReadFile(
			hfile,
			NULL,
			NULL,
			NULL,
			&io_status_block,
			(PVOID)((ULONG)lp_virtual_pointer+u_section_address),
			u_size_of_section,
			&file_offset,
			NULL);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("read failed is pImageSectionHeader[%d]",u_index));
			ExFreePool(pimage_section_header);
			ExFreePool(lp_virtual_pointer);
			ZwClose(hfile);
			return status;
		}
	}

	RelocModule(lp_virtual_pointer,pOrigImage);
	SetNewSSDT(lp_virtual_pointer,pOrigImage,&g_pnew_service_table);

	KdPrint(("ok!"));

	ExFreePool(pimage_section_header);
	*lpVirtualAddress = lp_virtual_pointer;
	ZwClose(hfile);
	return STATUS_SUCCESS;
}