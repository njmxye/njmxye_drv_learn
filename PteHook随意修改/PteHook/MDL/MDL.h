#pragma once
#include<ntifs.h>
#include<ntddk.h>

typedef struct _REPROTECT_CONTEXT {
	PMDL Mdl;
	PUCHAR Lockedva;

}REPROTECT_CONTEXT,*PREPROTECT_CONTEXT;

NTSTATUS MmLockVaForWrite(
	PVOID Va,
	ULONG Length,
	__out PREPROTECT_CONTEXT ReprotectContext
);


NTSTATUS MmUnlockVaForWrite(
	__out PREPROTECT_CONTEXT ReprotectContext
);