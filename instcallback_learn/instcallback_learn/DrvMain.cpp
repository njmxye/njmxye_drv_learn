#include "CommIO.h"


void DriverUnload(PDRIVER_OBJECT DriverObject) {
	if (DriverObject->DeviceObject) {
		IoDeleteDevice(DriverObject->DeviceObject);
		UNICODE_STRING symbolLinkName = RTL_CONSTANT_STRING(SYBOLNAME);
		NTSTATUS status = IoDeleteSymbolicLink(&symbolLinkName);
		if (!NT_SUCCESS(status)) {
			DbgPrint("符号删除成功！\n");
		}
	}
	DbgPrint("驱动卸载成功！\n");
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath) {
	RegisterPath;
	DriverObject->DriverUnload = DriverUnload;

	PDEVICE_OBJECT pDeviceObj;
	NTSTATUS status;
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICENAME);
	UNICODE_STRING symbolLinkName = RTL_CONSTANT_STRING(SYBOLNAME);

	//创建设备对象
	status = IoCreateDevice(DriverObject, NULL, &deviceName, FILE_DEVICE_UNKNOWN, NULL, FALSE, &pDeviceObj);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	//pDeviceObj->Flags = 0; 


	status = IoCreateSymbolicLink(&symbolLinkName, &deviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(pDeviceObj);
		return status;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateDriver;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseDriver;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIrpCtl;

	DbgPrint("驱动加载成功！\n");
	return status;
}


