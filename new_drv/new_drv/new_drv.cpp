#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

void drv_unload(PDRIVER_OBJECT i)
{
	UNREFERENCED_PARAMETER(i);
	DbgPrintEx(77, 0, "卸载了傻逼。\r\n");
};

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT i, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrintEx(77, 0, "加载了傻逼。\r\n");
	i->DriverUnload = drv_unload;
	return STATUS_SUCCESS;
};