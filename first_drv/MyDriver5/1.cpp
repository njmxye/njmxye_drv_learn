#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

void drv_unload(PDRIVER_OBJECT DriverObject)
{
    DbgPrintEx(77, 0, "Ð¶ÔØÁËÉµ±Æ¡£\r\n");
};

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DbgPrintEx(77, 0, "¼ÓÔØÁËÉµ±Æ¡£\r\n");
    DriverObject->DriverUnload = drv_unload;
    return STATUS_SUCCESS;
};