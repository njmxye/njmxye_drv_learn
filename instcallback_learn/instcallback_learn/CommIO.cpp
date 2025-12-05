#include"CommIo.h"


NTSTATUS CreateDriver(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
NTSTATUS CloseDriver(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverIrpCtl(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevice);
	ULONG Buffer = 0;

	NTSTATUS status = 0;
	auto stack = IoGetCurrentIrpStackLocation(pIrp);

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case CALLBACKINJECT: {

		PINIT_DATA Info = (PINIT_DATA)pIrp->AssociatedIrp.SystemBuffer;
		g_fnGetProcAddress = Info->fnGetProc;
		g_fnLoadLibrary = Info->fnLoadLibrary;
		g_fnAddFuntionTable = Info->fnAddFunc;


		if (g_fnAddFuntionTable == 0 || g_fnLoadLibrary == 0 || g_fnAddFuntionTable == 0) {
			DbgPrint("g_fnGetProcAddress %p,g_fnLoadLibrary:%p,g_fnAddFuntionTable:%p", g_fnGetProcAddress, g_fnLoadLibrary, g_fnAddFuntionTable);
			return STATUS_UNSUCCESSFUL;
		}
		//__debugbreak();
		wchar_t DllR0Name[MAX_PATH] = { 0 };

		wcscpy(DllR0Name, L"\\??\\");
		wcscat(DllR0Name, Info->szDllName); //Æ´½Ó×Ö·û´®

		UNICODE_STRING r0_dll_path{ 0 };
		RtlInitUnicodeString(&r0_dll_path, DllR0Name);

		status = inst_callback_inject((HANDLE)Info->dwPid, &r0_dll_path);
		Buffer = sizeof(INIT_DATA);
		break;
	}
	default:
		return status;
	}

	pIrp->IoStatus.Information = Buffer;
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;

}




