#include "LinkDbg.h"
#include "kDbgSys.h"
#include "CommonFunc.h"

VOID ReplaceDbgSys(
	IN PDRIVER_OBJECT pDriverObject)
{
	if (pDriverObject == NULL || g_bInitDebugSys == FALSE)
	{	return;	}

	HookKiFastCallEntry(pDriverObject);

	if (!MmIsAddressValid(g_pnew_service_table))
	{	return;	}

	g_pnew_service_table->ServiceTableBase[CREATE_DBGOBJ_ID] = (ULONG)NtCreateDebugObject;
	g_pnew_service_table->ServiceTableBase[DBG_ACTIVE_PROCESS_ID] = (ULONG)NtDebugActiveProcess;
	g_pnew_service_table->ServiceTableBase[DBG_CONTINUE_ID] = (ULONG)NtDebugContinue;
	g_pnew_service_table->ServiceTableBase[REMOVE_PROCESS_DBG_ID] = (ULONG)NtRemoveProcessDebug;
	g_pnew_service_table->ServiceTableBase[WAIT_DBG_EVENT_ID] = (ULONG)NtWaitForDebugEvent;

	g_bHookDbgCreateThread = Jmp_HookFunction(
		g_OrigKDbgCreateThread,(ULONG)DbgkCreateThread,g_DbgCreateThreadCode);
	Jmp_HookFunction(g_OrigKDbgCreateThread+g_new_kernel_inc,(ULONG)DbgkCreateThread,g_DbgCreateThreadCode);
	g_bHookDbgExitProcess = Jmp_HookFunction(
		g_OrigKDbgExitProcess,(ULONG)DbgkExitProcess,g_DbgExitProcessCode);
	Jmp_HookFunction(g_OrigKDbgExitProcess+g_new_kernel_inc,(ULONG)DbgkExitProcess,g_DbgExitProcessCode);
	g_bHookDbgExitThread = Jmp_HookFunction(
		g_OrigKDbgExitThread,(ULONG)DbgkExitThread,g_DbgExitThreadCode);
	Jmp_HookFunction(g_OrigKDbgExitThread+g_new_kernel_inc,(ULONG)DbgkExitThread,g_DbgExitThreadCode);
	g_bHookDbgMapViewOfSection = Jmp_HookFunction(
		g_OrigKDbgMapViewOfSection,(ULONG)DbgkMapViewOfSection_S,g_DbgMapViewOfSectionCode);
	Jmp_HookFunction(g_OrigKDbgMapViewOfSection+g_new_kernel_inc,(ULONG)DbgkMapViewOfSection_S,g_DbgMapViewOfSectionCode);
	g_bHookDbgUnMapViewOfSection = Jmp_HookFunction(
		g_OrigKDbgUnMapViewOfSection,(ULONG)DbgkUnMapViewOfSection_S,g_DbgUnMapViewOfSectionCode);
	Jmp_HookFunction(g_OrigKDbgUnMapViewOfSection+g_new_kernel_inc,(ULONG)DbgkUnMapViewOfSection_S,g_DbgUnMapViewOfSectionCode);
	g_bHookDbgForwardException = Jmp_HookFunction(
		g_OrigKDbgForwardException,(ULONG)DbgkForwardException,g_DbgForwardExceptionCode);
	Jmp_HookFunction(g_OrigKDbgForwardException+g_new_kernel_inc,(ULONG)DbgkForwardException,g_DbgForwardExceptionCode);
	g_bHookDbgCopyProcessDebugPort = Jmp_HookFunction(
		g_OrigKDbgCopyProcessDebugPort,(ULONG)DbgkCopyProcessDebugPort_S,g_DbgCopyProcessDebugPortCode);
	Jmp_HookFunction(g_OrigKDbgCopyProcessDebugPort+g_new_kernel_inc,(ULONG)DbgkCopyProcessDebugPort_S,g_DbgCopyProcessDebugPortCode);
	g_bHookDbgClearProcessDebugPort = Jmp_HookFunction(
		g_OrigKDbgClearProcessDebugPort,(ULONG)DbgkClearProcessDebugObject,g_DbgClearProcessDebugPortCode);
	Jmp_HookFunction(g_OrigKDbgClearProcessDebugPort+g_new_kernel_inc,(ULONG)DbgkClearProcessDebugObject,g_DbgClearProcessDebugPortCode);
}

VOID RevertDbgSys()
{
	if (g_bInitDebugSys == FALSE){	return;	}
	if (g_bHookDbgCreateThread)
	{
		Res_HookFunction(g_OrigKDbgCreateThread,g_DbgCreateThreadCode,0x5);
	}
	if (g_bHookDbgExitProcess)
	{
		Res_HookFunction(g_OrigKDbgExitProcess,g_DbgExitProcessCode,0x5);
	}
	if (g_bHookDbgExitThread)
	{
		Res_HookFunction(g_OrigKDbgExitThread,g_DbgExitThreadCode,0x5);
	}
	if (g_bHookDbgMapViewOfSection)
	{
		Res_HookFunction(g_OrigKDbgMapViewOfSection,g_DbgMapViewOfSectionCode,0x5);
	}
	if (g_bHookDbgUnMapViewOfSection)
	{
		Res_HookFunction(g_OrigKDbgUnMapViewOfSection,g_DbgUnMapViewOfSectionCode,0x5);
	}
	if (g_bHookDbgForwardException)
	{
		Res_HookFunction(g_OrigKDbgForwardException,g_DbgForwardExceptionCode,0x5);
	}
	if (g_bHookDbgCopyProcessDebugPort)
	{
		Res_HookFunction(g_OrigKDbgCopyProcessDebugPort,g_DbgCopyProcessDebugPortCode,0x5);
	}
	if (g_bHookDbgClearProcessDebugPort)
	{
		Res_HookFunction(g_OrigKDbgClearProcessDebugPort,g_DbgClearProcessDebugPortCode,0x5);
	}
	UnHookKiFastCallEntry();
}