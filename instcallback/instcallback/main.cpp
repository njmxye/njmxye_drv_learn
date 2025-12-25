#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
ZwSetInfomationProcess(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__in_bcount(ProcessInfomationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
	);

#pragma waring(disable:4839)
#pragma waring(disable:4309)
char g_InstCallBackShellCode[] =
{
	0x51,//push rcx
	0x52,//push rdx
	0x53,//push rbx
	0x55,
	0x56,
	0x57,
	0x41, 0x50,
	0x41, 0x51,
	0x41, 0x52,
	0x41, 0x53,
	0x41, 0x54,
	0x41, 0x55,
	0x41, 0x56,
	0x41, 0x57,
	//上面都是保存寄存器
	// sub rsp,0x20
	0x48,0x83,0xec,0x28,

	//中间写入一些东西shell code
	0x49,0xB9,0x44,0xD6,0xB4,0xFE,0xFA,0x7F,00,00,0x4D,0x3B,0xCA,0x75,0x05,0xB8,0x10,00,00,0xC0,

	//add rsp,0x20
	0x48,0x83,0xc4,0x28,

	//pop 寄存器
	0x41, 0x5F,
	0x41, 0x5E,
	0x41, 0x5D,
	0x41, 0x5C,
	0x41, 0x5B,
	0x41, 0x5A,
	0x41, 0x59,
	0x41, 0x58,
	0x5F,
	0x5E,
	0x5D,
	0x5B,
	0x5A,
	0x59,
	0x41, 0xFF, 0xE2,//jmp r10 返回


};



NTSTATUS set_instcallback(HANDLE process_id) {
	PEPROCESS process{ 0 };
	KAPC_STATE apc{ 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	status = PsLookupProcessByProcessId(process_id, &process);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(77, 0, "[+]没几把成功获取eprocess\r\n");
		return status;


	}
	while (1)
	{
		KeStackAttachProcess(process, &apc);
		void* alloc_addr = 0;
		SIZE_T size = PAGE_SIZE;
		status= ZwAllocateVirtualMemory(NtCurrentProcess(), &alloc_addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!NT_SUCCESS(status)) {
			DbgPrintEx(77, 0, "[+]申请内存几把失败了\r\n");
			break;
		}
		DbgPrintEx(77, 0, "[+]申请的内存是：%llx\r\n",alloc_addr);

		memcpy(alloc_addr, g_InstCallBackShellCode, sizeof(g_InstCallBackShellCode));

		//set instcall
		status = ZwSetInfomationProcess(NtCurrentProcess(), ProcessInstrumentationCallback, &alloc_addr, sizeof(&alloc_addr));
		if (!NT_SUCCESS(status)) DbgPrintEx(77, 0, "[+]设置instcall back出错了草你妈的。\r\n");
		break;
	}

	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(process);
	return status;


}


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
{
	return set_instcallback((HANDLE)9596);
};