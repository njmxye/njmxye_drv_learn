#include "MDL.h"

/**
 * @file MDL.cpp
 * @brief 内存描述符列表（MDL）操作实现文件
 * 
 * 本文件实现了对Windows内核MDL（Memory Descriptor List）机制的高级封装，
 * 用于在内核模式下安全地修改受保护的内存区域。
 * 
 * @section mdl_overview MDL概述
 * 
 * MDL（Memory Descriptor List，内存描述符列表）是Windows内核用于描述物理内存的
 * 一种数据结构。最早设计用于DMA（直接内存访问）设备驱动程序，以便快速访问大量
 * 物理内存。在内核安全研究领域，MDL被广泛用于：
 * 
 * - 锁定内存页（防止被换出到页面文件）
 * - 修改只读/执行保护的内核代码
 * - 在进程间安全地传递内存地址
 * - 访问其他进程的虚拟地址空间
 * 
 * @section why_use_mdl 为什么需要MDL进行内核补丁操作
 * 
 * 在进行Inline Hook等内核补丁操作时，我们通常需要修改目标函数的机器码。
 * 然而，以下情况会导致直接写操作失败：
 * 
 * 1. 代码页通常是只读的（PAGE_EXECUTE_READ）
 * 2. 某些内核代码页受到Write-XOR-Execute保护
 * 3. 内存管理器可能将页面换出到页面文件
 * 4. 在进程上下文中修改内存需要特殊权限
 * 
 * MDL机制通过以下步骤解决这些问题：
 * 1. 描述目标虚拟地址对应的物理内存页
 * 2. 锁定物理页到内存中（防止换出）
 * 3. 映射到内核地址空间（获得可访问的虚拟地址）
 * 4. 修改页保护属性为可写
 */

/**
 * @brief 锁定虚拟地址区间以进行写访问
 * 
 * 此函数是内核补丁操作的核心前置步骤。它执行以下关键操作：
 * 
 * 1. 分配MDL结构：创建一个MDL来描述目标虚拟地址范围对应的物理内存页。
 *    MDL本质上一个链表结构，每个节点描述一个物理内存页的信息。
 * 
 * 2. 锁定内存页：调用MmProbeAndLockPages将描述的物理页锁定在RAM中。
 *    锁定后的页面不会被换出到页面文件，确保后续操作期间页面始终可用。
 *    同时，此函数会检查页面是否支持请求的访问模式（写访问）。
 * 
 * 3. 映射到内核空间：调用MmMapLockedPagesSpecifyCache将锁定的物理页
 *    映射到系统地址空间，返回一个可在当前驱动上下文中访问的虚拟地址。
 * 
 * 4. 修改保护属性：调用MmProtectMdlSystemAddress将映射区域的保护属性
 *    设置为PAGE_EXECUTE_READWRITE，允许执行写操作。
 * 
 * @param Va 要锁定的虚拟地址起始位置。这个地址必须是有效的用户或内核
 *        虚拟地址，且对齐到页面边界（虽然函数内部会处理不对齐的情况）。
 * @param Length 要锁定的内存区域长度（字节）。如果跨越多个页面，将锁定
 *        所有涉及的页面。
 * @param ReprotectContext 输出参数，用于接收重保护上下文信息。调用者
 *        必须提供一个REPROTECT_CONTEXT结构体，函数将填充MDL指针和
 *        映射后的虚拟地址。
 * 
 * @return NTSTATUS 返回操作结果。成功返回STATUS_SUCCESS，失败返回错误码。
 *         主要的错误场景包括：
 *         - STATUS_INSUFFICIENT_RESOURCES：系统资源不足，无法分配MDL
 *         - 访问违例异常：如果Va无效或页面不支持写访问
 *         - STATUS_UNSUCCESSFUL：内存映射失败
 *         - 其他：MmProtectMdlSystemAddress可能返回的错误码
 * 
 * @note 此函数不修改任何页面内容，仅准备可写的内存环境。
 *       实际的写操作需要由调用者使用返回的Lockedva地址进行。
 * 
 * @warning 必须在__try/__except块中调用此函数，以处理可能的页面访问异常。
 *          即使函数成功返回，后续的内存访问仍可能触发异常。
 * 
 * @warning 调用此函数后，必须在使用完毕后调用MmUnlockVaForWrite释放资源。
 *          遗漏释放会导致内存泄漏和系统不稳定。
 * 
 * @par 使用示例：
 * @code
 * REPROTECT_CONTEXT ctx = {0};
 * NTSTATUS status = MmLockVaForWrite(TargetFunc, 64, &ctx);
 * if (NT_SUCCESS(status)) {
 *     // 现在可以安全地修改TargetFunc指向的内存
 *     memcpy(ctx.Lockedva, HookCode, HookCodeLength);
 *     // ... 执行其他操作
 *     MmUnlockVaForWrite(&ctx);
 * }
 * @endcode
 * 
 * @see MmUnlockVaForWrite 用于释放本函数分配的资源
 */
NTSTATUS MmLockVaForWrite(PVOID Va, ULONG Length, __out PREPROTECT_CONTEXT ReprotectContext)
{   
    NTSTATUS status;
    status = STATUS_SUCCESS;

    ReprotectContext->Mdl = 0;
    ReprotectContext->Lockedva = 0;

    /**
     * IoAllocateMdl函数详解：
     * 
     * 功能：为指定的虚拟地址范围分配并初始化一个MDL结构。
     * 
     * 参数说明：
     * - Va：描述的起始虚拟地址
     * - Length：描述的内存长度（字节）
     * - FALSE：SecondaryBuffer参数，表示这不是辅助MDL（用于描述散/聚内存）
     * - FALSE：ChargeQuota参数，表示不进行配额计费（驱动通常不需要）
     * - NULL：指向父MDL的指针，用于创建MDL链
     * 
     * MDL结构的关键字段：
     * - MdlFlags：标志位，指示MDL的状态（已分配、已锁定、已映射等）
     * - StartVa：起始虚拟地址（页面对齐）
     * - ByteCount：总字节数
     * - ByteOffset：起始地址在第一个页面内的偏移
     * - Next：指向下一个MDL的指针（用于MDL链）
     * 
     * 返回值：
     * - 成功：返回分配的MDL指针
     * - 失败：返回NULL
     * 
     * @warning 即使分配成功，MDL也不会自动锁定或映射页面。
     *          必须后续调用MmProbeAndLockPages和MmMapLockedPagesSpecifyCache。
     */
    ReprotectContext->Mdl = IoAllocateMdl(Va, Length, FALSE, FALSE, NULL);

    if (!ReprotectContext->Mdl) {
        /**
         * STATUS_INSUFFICIENT_RESOURCES表示系统无法分配所需的内存。
         * 这通常发生在系统内存严重不足的情况下。
         */
        return STATUS_INSUFFICIENT_RESOURCES;
    };

    /**
     * __try/__except异常处理机制：
     * 
     * Windows内核使用结构化异常处理（SEH）来处理各种异常情况。
     * __try块包含可能抛出异常的代码，__except块指定处理异常的代码。
     * 
     * 在此处的用途：
     * MmProbeAndLockPages可能会访问无效的虚拟地址，或者页面不支持
     * 请求的访问模式。这些情况会触发页面错误异常（PAGE_FAULT）。
     * 
     * EXCEPTION_EXECUTE_HANDLER表示无论捕获到什么异常，都执行
     * __except块中的代码（获取并返回异常码）。
     * 
     * @note 虽然函数内部有异常处理，但调用者也应该在更上层
     *       设置异常处理，以防备其他潜在的异常情况。
     */
    __try{
        /**
         * MmProbeAndLockPages函数详解：
         * 
         * 功能：探测指定MDL描述的页面是否支持请求的访问模式，
         *       并将页面锁定在物理内存中。
         * 
         * 参数说明：
         * - Mdl：指向要处理的MDL结构
         * - KernelMode：调用者模式。KernelMode表示调用者运行在内核模式，
         *               意味着异常处理会更宽松（某些访问违例外壳处理）
         * - IoWriteAccess：请求的访问模式，表示需要写访问权限
         * 
         * 其他可能的访问模式：
         * - IoReadAccess：只读访问
         * - IoModifyAccess：修改访问（与IoWriteAccess相同）
         * 
         * 函数执行过程：
         * 1. 遍历MDL中描述的所有页面
         * 2. 检查每个页面的当前保护属性
         * 3. 验证页面是否支持请求的访问模式
         * 4. 将页面锁定在物理内存中（设置PTE的锁定位）
         * 5. 更新MDL的标志位（MDL_PAGES_LOCKED）
         * 
         * @note 锁定页面会：
         *       - 防止页面被换出到页面文件
         *       - 确保后续映射操作能找到物理页框
         *       - 可能增加系统的内存压力
         * 
         * @note 如果页面原本是只读的，此函数会验证但不会修改保护属性。
         *       保护属性的修改需要后续调用MmProtectMdlSystemAddress。
         * 
         * @warning 如果Va参数无效（指向不存在的内存），或者页面不支持
         *          写访问，此函数会抛出异常。
         * 
         * @warning 此函数必须在进程上下文中调用，或者目标地址必须是
         *          可访问的内核地址。
         * 
         * @see MmUnlockPages 用于解除页面的锁定
         */
        MmProbeAndLockPages(ReprotectContext->Mdl, KernelMode, IoWriteAccess);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        /**
         * GetExceptionCode返回异常代码，常见的页面相关异常包括：
         * - STATUS_ACCESS_VIOLATION (0xC0000005)：访问违例，通常是无效地址
         * - STATUS_INVALID_PAGE_PROTECTION (0xC0000047)：不支持的保护属性
         * - STATUS_PAGEFILE_QUOTA_EXCEEDED (0xC0000007)：页面文件配额超限
         */
        return GetExceptionCode();
    }

    /**
     * MmMapLockedPagesSpecifyCache函数详解：
     * 
     * 功能：将已锁定的内存页映射到指定的系统地址空间。
     * 
     * 参数说明：
     * - Mdl：指向已锁定页面的MDL结构
     * - KernelMode：映射模式。KernelMode返回的地址可在任何线程上下文中访问
     * - MmCached：缓存类型
     *         - MmCached：缓存内存（普通内存）
     *         - MmUncached：非缓存内存（直接访问物理内存）
     *         - MmWriteCombined：写合并缓存（适合显卡内存等）
     * - NULL：要求的起始地址，NULL表示由系统选择
     * - FALSE：NonBounded，如果MDL描述的内存是连续的则为FALSE
     * - NormalPagePriority：映射优先级，影响内存分配策略
     * 
     * 其他优先级选项：
     * - HighPagePriority：高优先级，可能使用更稳定的内存
     * - LowPagePriority：低优先级，适用于非关键操作
     * - VeryLowPagePriority：非常低的优先级
     * 
     * 返回值：
     * - 成功：返回映射后的虚拟地址，可用于访问锁定的页面
     * - 失败：返回NULL
     * 
     * 映射地址的特点：
     * - 映射地址与原始Va不同（除非原始地址已在系统空间中）
     * - 映射地址是临时的，Unmap后失效
     * - 映射地址指向同一组物理页面
     * 
     * @note 对于内核补丁来说，我们通常使用映射后的地址（Lockedva）
     *       进行写操作，而不是原始地址（Va）。
     * 
     * @warning 映射是临时的，必须在解锁前完成所有写操作。
     * 
     * @see MmUnmapLockedPages 用于解除映射
     */
    ReprotectContext->Lockedva = (PUCHAR)MmMapLockedPagesSpecifyCache(
                                        ReprotectContext->Mdl, 
                                        KernelMode, 
                                        MmCached, 
                                        NULL, 
                                        FALSE, 
                                        NormalPagePriority);

    if (!ReprotectContext->Lockedva) {
        /**
         * 如果映射失败，需要清理已分配的资源：
         * 1. 释放MDL结构（IoFreeMdl）
         * 2. 清除Mdl指针
         * 3. 返回错误状态
         * 
         * 注意：此时页面已被锁定，但映射失败意味着无法访问它们。
         *       需要先解锁页面才能释放MDL。
         */
        MmUnlockPages(ReprotectContext->Mdl);
        IoFreeMdl(ReprotectContext->Mdl);
        ReprotectContext->Mdl = 0;
        return STATUS_UNSUCCESSFUL;
    }

    /**
     * MmProtectMdlSystemAddress函数详解：
     * 
     * 功能：修改MDL描述的内存区域的保护属性。
     * 
     * 参数说明：
     * - Mdl：指向目标MDL结构
     * - PAGE_EXECUTE_READWRITE：新的保护属性
     * 
     * 常用的保护属性值：
     * - PAGE_NOACCESS：不可访问
     * - PAGE_READONLY：只读
     * - PAGE_READWRITE：读写
     * - PAGE_EXECUTE：可执行
     * - PAGE_EXECUTE_READ：执行+读
     * - PAGE_EXECUTE_READWRITE：执行+读+写
     * - PAGE_EXECUTE_WRITECOPY：执行+写时复制
     * - PAGE_WRITECOPY：写时复制
     * 
     * @note 此函数修改的是系统地址空间中的保护属性，
     *       即映射后的地址（Lockedva）的保护属性。
     * 
     * @note 原始地址（Va）的保护属性可能仍保持不变，
     *       但由于我们使用映射后的地址进行操作，
     *       因此只需要修改映射地址的保护属性。
     * 
     * @warning 如果修改失败，必须清理所有已分配的资源。
     *          这是函数中错误处理最复杂的部分。
     */
    status = MmProtectMdlSystemAddress(ReprotectContext->Mdl, PAGE_EXECUTE_READWRITE);
    
    if (!NT_SUCCESS(status)) {
        /**
         * 如果保护属性修改失败，需要清理：
         * 1. 解除映射（MmUnmapLockedPages）
         * 2. 解锁页面（MmUnlockPages）
         * 3. 释放MDL（IoFreeMdl）
         * 4. 清空上下文
         */
        MmUnmapLockedPages(ReprotectContext->Lockedva, ReprotectContext->Mdl); 
        MmUnlockPages(ReprotectContext->Mdl);
        IoFreeMdl(ReprotectContext->Mdl);
        ReprotectContext->Lockedva = 0;
        ReprotectContext->Mdl = 0;
    }

    return status;
}

/**
 * @brief 解锁并释放通过MmLockVaForWrite锁定的内存
 * 
 * 此函数执行MmLockVaForWrite的反向操作：
 * 1. 解除内核地址空间的映射
 * 2. 解锁物理内存页（允许换出到页面文件）
 * 3. 释放MDL结构
 * 
 * 这是资源清理的关键步骤，必须在完成内存修改后调用。
 * 
 * @param ReprotectContext 指向由MmLockVaForWrite填充的重保护上下文结构。
 *                         函数执行完毕后，所有指针将被清零。
 * 
 * @return NTSTATUS 始终返回STATUS_SUCCESS。
 *         即使某些步骤失败（如解锁失败），函数也不会返回错误码，
 *         因为这些失败通常表示系统状态异常，调用者无法恢复。
 * 
 * @note 函数按以下顺序执行清理操作：
 *       1. MmUnmapLockedPages：解除地址映射
 *       2. MmUnlockPages：解锁物理页面
 *       3. IoFreeMdl：释放MDL结构
 *       4. 清空上下文结构中的指针
 * 
 * @warning 在调用此函数前，确保所有对映射内存的写操作已完成。
 *          解除映射后，对Lockedva的访问会导致系统崩溃。
 * 
 * @warning 确保此函数只被调用一次，多次调用可能导致系统崩溃。
 * 
 * @see MmLockVaForWrite 用于准备可写的内存环境
 */
NTSTATUS MmUnlockVaForWrite(__out  PREPROTECT_CONTEXT ReprotectContext)
{
    NTSTATUS status;
    status = STATUS_SUCCESS;

    /**
     * MmUnmapLockedPages函数详解：
     * 
     * 功能：解除之前通过MmMapLockedPagesSpecifyCache建立的映射。
     * 
     * 参数说明：
     * - Lockedva：由MmMapLockedPagesSpecifyCache返回的映射地址
     * - Mdl：关联的MDL结构
     * 
     * @note 此函数仅解除映射，不影响锁定的页面。
     *       页面仍然被锁定，需要调用MmUnlockPages来解锁。
     * 
     * @note 映射是临时的，解除映射后Lockedva地址变为无效。
     */
    MmUnmapLockedPages(ReprotectContext->Lockedva, ReprotectContext->Mdl);

    /**
     * MmUnlockPages函数详解：
     * 
     * 功能：解锁之前通过MmProbeAndLockPages锁定的页面。
     * 
     * 参数说明：
     * - Mdl：关联的MDL结构
     * 
     * @note 解锁后，页面可以被内存管理器换出到页面文件。
     *       如果页面内容被修改，这些修改会保留（如果页面是脏的）。
     * 
     * @note 如果页面是用户模式页面，解锁可能触发写回操作
     *       （如果页面被标记为脏页）。
     * 
     * @see MmProbeAndLockPages 用于锁定页面
     */
    MmUnlockPages(ReprotectContext->Mdl);

    /**
     * IoFreeMdl函数详解：
     * 
     * 功能：释放之前通过IoAllocateMdl分配的MDL结构。
     * 
     * @note MDL结构本身是从非分页池中分配的，
     *       因此释放操作不会失败。
     * 
     * @see IoAllocateMdl 用于分配MDL结构
     */
    IoFreeMdl(ReprotectContext->Mdl);

    /**
     * 清空上下文结构：
     * 
     * 这是良好的编程实践，可以防止：
     * 1. 使用已释放的指针（悬空指针）
     * 2. 重复释放资源
     * 3. 调试时混淆资源状态
     */
    ReprotectContext->Lockedva = 0;
    ReprotectContext->Mdl = 0;

    return status;
}
