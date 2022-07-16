#ifndef __LINK_DBG_H__
#define __LINK_DBG_H__

#include "CommonFunc.h"

extern ULONG	g_new_kernel_inc;
extern ServiceDescriptorTableEntry_t	*g_pnew_service_table;

// 重载ssdt，对KiFastCallEntry进行hook
void HookKiFastCallEntry(PDRIVER_OBJECT pDriverObject);
void UnHookKiFastCallEntry();

VOID ReplaceDbgSys(IN PDRIVER_OBJECT pDriverObject);
VOID RevertDbgSys();

#endif // !__LINK_DBG_H__
