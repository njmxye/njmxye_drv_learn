#pragma once
#include "ShellCode.h"
#include "InstCallBack.h"

#define CALLBACKINJECT CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define APCINJECT CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)


#define  DEVICENAME L"\\Device\\DemoInject"
#define  SYBOLNAME L"\\??\\DemoInject"



EXTERN_C NTSTATUS DriverIrpCtl(PDEVICE_OBJECT pDevice, PIRP pIrp);

EXTERN_C NTSTATUS CreateDriver(PDEVICE_OBJECT pDevice, PIRP pIrp);

EXTERN_C NTSTATUS CloseDriver(PDEVICE_OBJECT pDevice, PIRP pIrp);

typedef struct _INIT_DATA {

	DWORD32 dwPid;
	UINT64 fnLoadLibrary;
	UINT64 fnGetProc;
	UINT64 fnAddFunc;
	wchar_t* szDllName;
}INIT_DATA, * PINIT_DATA;


typedef struct _APC_INJECT {

	ULONG64 dwPid;

	const wchar_t* szDllName;


	UINT64 gpa;
	UINT64 raf;
	UINT64 llb;

}APC_INJECT, * PAPC_INJECT;