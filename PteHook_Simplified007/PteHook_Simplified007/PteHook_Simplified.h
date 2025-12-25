/*
 * PteHook Simplified - 教学版内联钩子驱动头文件
 * PteHook_Simplified.h
 */

#ifndef _PTEHOOK_SIMPLIFIED_H_
#define _PTEHOOK_SIMPLIFIED_H_

#include <ntifs.h>
#include <ntddk.h>
#include"./ia32/ia32.hpp" 

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_HOOK_COUNT 10
#define PAGE_SIZE_4KB 0x1000
#define JMP_INSTRUCTION_SIZE 12

typedef struct _HOOK_INFO {
    HANDLE  pid;                    // 被hook的目标进程ID
    void*   targetAddr;            // 要hook的目标函数地址
    void*   hookAddr;              // 自定义的hook函数地址
    void*   trampolineAddr;        // trampoline代码地址（用于调用原函数）
    UINT32  originalBytesCount;    // 原始字节数
    UCHAR   originalBytes[14];     // 保存的原始指令字节
} HOOK_INFO, *PHOOK_INFO;

typedef struct _REPROTECT_CONTEXT {
    PMDL    mdl;        // MDL结构 - 内存描述符列表
    PUCHAR  lockedVa;   // 锁定的虚拟地址 - 可写的内存映射
} REPROTECT_CONTEXT, *PREPROTECT_CONTEXT;

typedef struct _PAGE_TABLE_OFFSET {
    pte_64*  pte;       // 页表项 (Page Table Entry)
    pde_64*  pde;       // 页目录项 (Page Directory Entry)
    pdpte_64* pdpte;    // 页目录指针项 (Page Directory Pointer Table Entry)
    pml4e_64* pml4e;    // PML4项 (Page Map Level 4 Entry)
} PAGE_TABLE_OFFSET, *PPAGE_TABLE_OFFSET;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
void DriverUnload(PDRIVER_OBJECT DriverObject);

BOOLEAN InstallInlineHook(
    HANDLE  pid,            // 目标进程ID
    void**  originalFunc,   // 指向原函数地址的指针（会被修改为trampoline地址）
    void*   hookFunc        // 自定义的hook函数地址
);

BOOLEAN RemoveInlineHook(PVOID hookFunc);

NTSTATUS MmLockMemoryForWrite(PVOID va, ULONG length, PREPROTECT_CONTEXT ctx);
NTSTATUS MmUnlockMemoryForWrite(PREPROTECT_CONTEXT ctx);

ULONG64 VaToPa(PVOID va);
PVOID PaToVa(ULONG64 pa);

void GetPageTableOffsets(PVOID va, PPAGE_TABLE_OFFSET offsets);

BOOLEAN DisasmInstruction(PVOID code, PUINT8 length);

#ifdef __cplusplus
}
#endif

#endif // _PTEHOOK_SIMPLIFIED_H_
