#include "MDL.h"

/*
    MDL  内存描述页表； 用 MDL 来描述物理内存， for DMA 设备（更快 ）
*/


NTSTATUS MmLockVaForWrite(PVOID Va, ULONG Length, __out PREPROTECT_CONTEXT ReprotectContext)
{   //自己写一个内存函数，作为IoAllocateMdl，MmProbeAndLockPages，GetExceptionCode，MmMapLockedPagesSpecifyCache，IoFreeMdl，MmProtectMdlSystemAddress，NT_SUCCESS，MmUnmapLockedPages，MmUnlockPages的上层封装
    NTSTATUS status;
    status = STATUS_SUCCESS;//加载驱动成功

    ReprotectContext->Mdl = 0;//创了一个mdl结构并清空
    ReprotectContext->Lockedva = 0;
    /*
    IoAllocateMdl：
        功能：用于分配一个描述内存页信息的 MDL（Memory Descriptor List）结构。
        参数：通常需要传递要描述的内存区域的虚拟地址（Va）和长度（Length），以及其他参数如是否分配辅助表、是否从非分页池中分配等。
        使用场景：主要用于创建描述内存页信息的 MDL 结构，但并不进行内存页的映射操作。
    */
    ReprotectContext->Mdl = IoAllocateMdl(Va, Length, FALSE, FALSE, NULL); //分配缓冲区申请了一块内存出来

    if (!ReprotectContext->Mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;//如果申请失败
    };

    __try{//把容易异常的代码放到try中
        MmProbeAndLockPages(ReprotectContext->Mdl, KernelMode, IoWriteAccess); // access or  write 可能会蓝
    
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();//捕获异常并返回异常处理接管seh防止蓝屏
    }
    /*
        MmMapLockedPagesSpecifyCache：
            功能：用于将已经描述的内存页映射到系统地址空间中，并返回映射后的虚拟地址。
            参数：需要传递已经分配好的 MDL 结构（ReprotectContext->Mdl）、映射的访问模式（KernelMode）、缓存类型（MmCached）、映射的虚拟地址和是否是正常优先级等。
            使用场景：主要用于将已经描述的内存页映射到系统地址空间中，以便进行读写操作等。常见的使用场景包括将用户空间的缓冲区映射到内核空间，或者将内核空间的缓冲区映射到用户空间。
    */
    ReprotectContext->Lockedva = (PUCHAR)MmMapLockedPagesSpecifyCache(ReprotectContext->Mdl, 
                                        KernelMode, MmCached, NULL, FALSE, NormalPagePriority);  //真正实现映射 分配虚拟地址
    if (!ReprotectContext->Lockedva) {
        IoFreeMdl(ReprotectContext->Mdl);
        ReprotectContext->Mdl = 0;
        return STATUS_UNSUCCESSFUL;
    }

    status = MmProtectMdlSystemAddress(ReprotectContext->Mdl, PAGE_EXECUTE_READWRITE);
    
    if (!NT_SUCCESS(status)) {
        MmUnmapLockedPages(ReprotectContext->Lockedva, ReprotectContext->Mdl); 
        MmUnlockPages(ReprotectContext->Mdl);
        IoFreeMdl(ReprotectContext->Mdl);
        ReprotectContext->Lockedva = 0;
        ReprotectContext->Mdl = 0;
    }

    return status;
}

NTSTATUS MmUnlockVaForWrite(__out  PREPROTECT_CONTEXT ReprotectContext)
{
    NTSTATUS status;
    status = STATUS_SUCCESS;

    MmUnmapLockedPages(ReprotectContext->Lockedva, ReprotectContext->Mdl);
    MmUnlockPages(ReprotectContext->Mdl);
    IoFreeMdl(ReprotectContext->Mdl);
    ReprotectContext->Lockedva = 0;
    ReprotectContext->Mdl = 0;

    return status;
}
