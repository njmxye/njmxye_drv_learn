#include<ntifs.h>
#include<ntddk.h>
#include"HookManager.h"

typedef NTSTATUS(NTAPI* pfnNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* pfnNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

pfnNtOpenProcess g_oriNtOpenProcess;
pfnNtCreateFile g_oriNtCreateFile;
HANDLE g_pid = (HANDLE) 1808;

NTSTATUS NTAPI FakeNtOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId) {
    DbgPrintEx(102,0, "Fake NtOpenProcess \n");   // 没有 \n  在windbg 的log 中看不到
    
    return g_oriNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
};

NTSTATUS NTAPI FakeNtCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength) {
    
    DbgPrint("Fake Ntfakeopenfile"); 

    return g_oriNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

};



void DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    HookManager::GetInstance()->RemoveInlinehook(g_pid, (void*)FakeNtOpenProcess);
    HookManager::GetInstance()->RemoveInlinehook(g_pid, (void*)FakeNtCreateFile);

}
 
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath){
    UNREFERENCED_PARAMETER(RegisterPath);
    DriverObject->DriverUnload = DriverUnload;
    g_oriNtOpenProcess = NtOpenProcess;
    g_oriNtCreateFile = NtCreateFile;
    //DbgPrintEx(102, 0, "success main");
    DbgPrintEx(102, 0, "1 \n");
    if (HookManager::GetInstance()->InstallInlinehook(g_pid, (void**)&g_oriNtOpenProcess, (void*)FakeNtOpenProcess)) {
        DbgPrintEx(102, 0, "success main \n");
    };
    //if (HookManager::GetInstance()->InstallInlinehook((void**)&g_oriNtCreateFile, (void*)FakeNtCreateFile)) {
    //    DbgPrintEx(102, 0, "success main");
    //};
	return STATUS_SUCCESS; 
}