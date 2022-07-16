#include "ntifs.h"
#include "CommonFunc.h"
#include "kDbgSys.h"
#include "LinkDbg.h"

void DriverUnLoad(PDRIVER_OBJECT DriverObject)
{
	RevertDbgSys();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING usRegistPath)
{
	g_LocateDriverObj = DriverObject;

	if (InitCommon() != TRUE || InitDbgSys() != TRUE)
	{
		DbgPrint("initialize is failed!");
	}

	ReplaceDbgSys(DriverObject);

	DriverObject->DriverUnload = DriverUnLoad;
	return STATUS_SUCCESS;
}