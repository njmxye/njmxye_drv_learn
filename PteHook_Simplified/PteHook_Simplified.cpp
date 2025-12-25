/*******************************************************************************
 * 
 *  PteHook Simplified - 教学版内联钩子驱动
 *  ==============================================================
 *  
 *  【项目背景】
 *  这是一个用于学习Windows内核Hook技术的简化驱动。
 *  原始项目PteHook实现了完整的页表隔离技术，本简化版保留了核心逻辑，
 *  移除了复杂的页表操作，更适合初学者理解。
 *  
 *  【核心功能】
 *  1. Inline Hook（内联钩子）：在目标函数入口处写入跳转指令
 *  2. Trampoline（蹦床）：保存原始代码，使hook后仍能调用原函数
 *  3. MDL内存操作：绕过写保护修改代码页
 *  
 *  【应用场景】
 *  - 拦截系统调用：监控 NtOpenProcess、NtCreateFile 等
 *  - 函数监控：在函数入口/出口添加监控代码
 *  - 软件调试：动态分析程序行为
 *  
 *  【前置知识要求】
 *  - C语言基础：指针、结构体、位操作
 *  - x86/x64汇编基础：了解常见指令
 *  - Windows内核基础：了解驱动、进程、内存管理概念
 *  
 ******************************************************************************/

/* ============================================================================
 *                           头文件包含
 * ============================================================================ */

/* 
 * ntifs.h - Windows内核文件系统驱动头文件
 * 包含NT内核的大部分函数声明、数据类型定义
 * 是编写内核驱动必需的头文件
 * 
 * 与 ntddk.h 的区别：
 * - ntifs.h: 主要用于文件系统驱动，包含更多文件系统相关的声明
 * - ntddk.h: 通用驱动开发头文件
 * 在现代Windows版本中，两者在功能上差异不大
 */
#include <ntifs.h>

/* 
 * ntddk.h - Windows内核驱动开发头文件
 * 包含内核调试函数（如DbgPrintEx）、内存管理函数等
 * DDK = Driver Development Kit
 */
#include <ntddk.h>


/* ============================================================================
 *                           宏定义与常量
 * ============================================================================ */

/* 
 * MAX_HOOK_COUNT - 最大钩子数量
 * 限制同时hook的函数数量，防止内存溢出
 * 实际项目中可以根据需要调整
 */
#define MAX_HOOK_COUNT 10

/* 
 * PAGE_SIZE_4KB - 4KB页面大小
 * Windows和大多数操作系统使用4KB作为基本内存页大小
 * x86架构也可以使用2MB或4MB的大页，但本简化版只处理4KB页
 * 0x1000 = 4096 = 4 * 1024
 */
#define PAGE_SIZE_4KB 0x1000

/* 
 * JMP_INSTRUCTION_SIZE - 跳转指令大小（字节）
 * 
 * 在x64架构下，从任意地址跳转到任意地址需要12字节：
 *   mov rax, <64位地址>   ; 机器码：48 B8 [8字节地址]  共10字节
 *   jmp rax              ; 机器码：FF E0              共2字节
 *   总计：12字节
 * 
 * 对比x86架构：
 *   jmp <32位地址>       ; 机器码：E9 [4字节偏移]     共5字节
 */
#define JMP_INSTRUCTION_SIZE 12


/* ============================================================================
 *                           数据结构定义
 * ============================================================================ */

/**
 * _HOOK_INFO - 钩子信息结构体
 * 
 * 用于保存每个hook的详细信息，方便后续卸载和调试
 * 这个结构体相当于钩子的"身份证"，记录了钩子的所有信息
 */
typedef struct _HOOK_INFO {
    /* 
     * pid - 目标进程ID
     * 记录这个钩子作用在哪个进程上
     * Windows中每个进程都有一个唯一的进程ID（PID）
     * 注意：内核使用HANDLE类型来存储PID
     */
    HANDLE  pid;
    
    /* 
     * targetAddr - 原始函数地址
     * 要hook的目标函数的入口地址
     * 例如：hook NtOpenProcess，这里就保存NtOpenProcess的地址
     */
    void*   targetAddr;
    
    /* 
     * hookAddr - 自定义Hook函数地址
     * 我们编写的hook函数的地址
     * 当原函数被调用时，会跳转到这个地址执行
     */
    void*   hookAddr;
    
    /* 
     * trampolineAddr - Trampoline代码地址
     * 
     * 什么是Trampoline（蹦床）？
     * 当我们hook一个函数后，需要一种方式在hook函数中调用原函数
     * trampoline就是解决这个问题：它保存了原函数开头的指令，
     * 让我们可以在执行完自定义逻辑后继续执行原函数
     * 
     * trampoline的典型结构：
     *   [原始指令备份] + [跳回原函数的代码]
     */
    void*   trampolineAddr;
    
    /* 
     * originalBytesCount - 原始字节数
     * 保存的原函数入口处的字节数量
     * 这个值用于：
     *   1. 复制原始指令到trampoline
     *   2. 卸载hook时恢复原始代码
     */
    UINT32  originalBytesCount;
    
    /* 
     * originalBytes - 原始字节数组
     * 保存原函数入口处的机器码（最多14字节）
     * 14字节 > 12字节的跳转指令，确保有足够的空间写入跳转
     * 
     * 为什么是14字节？
     * 因为x64指令长度可变，我们可能需要保存超过12字节的指令
     * 这些字节在卸载hook时会被恢复到原函数入口
     */
    UCHAR   originalBytes[14];
} HOOK_INFO, *PHOOK_INFO;

/**
 * _REPROTECT_CONTEXT - 内存重保护上下文
 * 
 * 用于保存MDL操作的上下文信息
 * MDL = Memory Descriptor List（内存描述符列表）
 * 
 * 为什么需要这个结构体？
 * 修改代码页需要绕过写保护（代码页默认是只读+可执行）
 * MDL提供了一种方式来锁定内存页并修改其保护属性
 * 
 * 使用流程：
 *   1. 创建MDL描述要修改的内存区域
 *   2. 锁定页面（防止被换出到磁盘）
 *   3. 映射到内核地址空间（获得可写指针）
 *   4. 修改保护属性为可写
 *   5. 执行写操作
 *   6. 清理（逆序释放资源）
 */
typedef struct _REPROTECT_CONTEXT {
    /* 
     * mdl - MDL句柄
     * IoAllocateMdl创建的MDL结构
     * 用于后续的解锁和释放操作
     */
    PMDL    mdl;
    
    /* 
     * lockedVa - 锁定的虚拟地址
     * MmMapLockedPagesSpecifyCache返回的可写虚拟地址
     * 通过这个指针可以安全地写入代码页
     */
    PUCHAR  lockedVa;
} REPROTECT_CONTEXT, *PREPROTECT_CONTEXT;

/**
 * _PAGE_TABLE_OFFSET - 页表项偏移结构体
 * 
 * 用于保存虚拟地址对应的各级页表项指针
 * 
 * x64架构的虚拟地址空间组织（4级页表）：
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  63  │  47..39 │  38..30 │  29..21 │  20..12 │   11..0   │
 * │ 符号 │  PML4   │  PDPT   │   PDE   │   PTE   │  页内偏移  │
 * │扩展  │  索引   │  索引   │  索引   │  索引   │           │
 * └─────────────────────────────────────────────────────────────────┘
 * 
 * 每一级索引9位，可以寻址512个条目
 * 
 * 访问一个虚拟地址需要：
 *   1. 用PML4索引从PML4表中找到PDPT的物理页
 *   2. 用PDPT索引从PDPT表中找到PDE的物理页
 *   3. 用PDE索引从PDE表中找到PTE的物理页
 *   4. 用PTE索引从PTE表中找到实际物理页
 *   5. 加上页内偏移得到最终物理地址
 * 
 * Windows使用"自映射"技术，使得PTE_BASE（PTE表的起始虚拟地址）
 * 固定在一个已知地址（0xFFFFF68000000000）
 */
typedef struct _PAGE_TABLE_OFFSET {
    /* 
     * pte - 页表项指针
     * 指向虚拟地址对应的PTE（Page Table Entry）
     * PTE包含物理页帧号和页面属性（读/写/执行等）
     */
    pte_64*  pte;
    
    /* 
     * pde - 页目录项指针
     * 指向虚拟地址对应的PDE（Page Directory Entry）
     * 当PDE的large_page位为1时，表示2MB大页
     */
    pde_64*  pde;
    
    /* 
     * pdpte - 页目录指针项指针
     * 指向虚拟地址对应的PDPT Entry
     * 当PDPT的large_page位为1时，表示1GB大页
     */
    pdpte_64* pdpte;
    
    /* 
     * pml4e - PML4项指针
     * 指向虚拟地址对应的PML4 Entry
     * PML4是4级页表的最高级
     */
    pml4e_64* pml4e;
} PAGE_TABLE_OFFSET, *PPAGE_TABLE_OFFSET;


/* ============================================================================
 *                           函数声明
 * ============================================================================ */

/* 
 * 驱动入口和卸载函数声明
 * Windows驱动模型要求必须有这两个导出函数
 */

/**
 * DriverEntry - 驱动入口函数
 * 
 * Windows加载驱动时首先调用的函数
 * 相当于普通程序的main函数
 * 
 * 参数：
 *   DriverObject - 驱动对象，Windows内核创建，描述驱动的各种信息
 *   RegistryPath - 驱动在注册表中的路径
 * 
 * 返回值：
 *   STATUS_SUCCESS (0) 表示驱动加载成功
 *   其他值表示失败，驱动会被卸载
 * 
 * 注意：
 *   函数名必须是DriverEntry，导出名为"DriverEntry"
 *   实际上是由NT内核直接调用的，不是通过函数指针
 */
DRIVER_INITIALIZE DriverEntry;

/**
 * DriverUnload - 驱动卸载函数
 * 
 * 当驱动被卸载时Windows调用此函数
 * 用于清理驱动分配的资源
 * 
 * 参数：
 *   DriverObject - 驱动对象指针
 * 
 * 注意：
 *   不是所有驱动都需要实现卸载功能
 *   如果需要支持卸载，必须在DriverEntry中设置此函数指针
 */
DRIVER_UNLOAD     DriverUnload;


/* ============================================================================
 *                           内存操作函数声明
 * ============================================================================ */

/**
 * MmLockMemoryForWrite - 锁定内存页以进行写入
 * 
 * Windows内核中，代码页默认是只读的（PAGE_EXECUTE_READ）
 * 要修改代码页，需要先锁定它并修改保护属性
 * 
 * 这个函数封装了MDL操作的完整流程：
 *   1. 创建MDL
 *   2. 锁定页面
 *   3. 映射到内核空间
 *   4. 修改保护属性
 * 
 * 参数：
 *   va      - 要修改的虚拟地址
 *   length  - 要修改的内存长度（通常是一页大小）
 *   ctx     - 输出参数，保存操作的上下文信息
 * 
 * 返回值：
 *   STATUS_SUCCESS 表示成功
 *   其他值表示失败，可能的原因：
 *     - 内存地址无效
 *     - 页面锁定失败
 *     - 内存映射失败
 *     - 保护属性修改失败
 */
NTSTATUS MmLockMemoryForWrite(
    PVOID va,                    // 虚拟地址
    ULONG length,                // 长度
    PREPROTECT_CONTEXT ctx       // 输出：操作上下文
);

/**
 * MmUnlockMemoryForWrite - 解除内存页的锁定
 * 
 * MmLockMemoryForWrite的逆操作
 * 释放MDL、解锁页面、解除映射
 * 
 * 注意：
 *   必须在MmLockMemoryForWrite成功后调用
 *   如果MmLockMemoryForWrite失败，不能调用此函数
 * 
 * 参数：
 *   ctx - MmLockMemoryForWrite创建的上下文
 * 
 * 返回值：
 *   STATUS_SUCCESS 表示成功
 */
NTSTATUS MmUnlockMemoryForWrite(
    PREPROTECT_CONTEXT ctx       // 操作上下文
);


/* ============================================================================
 *                           地址转换函数声明
 * ============================================================================ */

/**
 * VaToPa - 虚拟地址转物理地址
 * 
 * Windows内核函数，用于获取虚拟地址对应的物理地址
 * 
 * 参数：
 *   va - 虚拟地址
 * 
 * 返回值：
 *   物理地址（64位值）
 * 
 * 注意：
 *   只能用于内核空间地址或已锁定的用户空间地址
 *   对于分页内存，物理地址可能随时变化
 */
ULONG64 VaToPa(
    PVOID va                     // 虚拟地址
);

/**
 * PaToVa - 物理地址转虚拟地址
 * 
 * 通过物理地址获取对应的内核虚拟地址
 * 
 * 参数：
 *   pa - 物理地址
 * 
 * 返回值：
 *   虚拟地址指针
 * 
 * 注意：
 *   物理地址必须是连续的（由MmAllocateContiguousMemory分配）
 *   普通页面的物理地址可能不连续，无法使用此函数
 */
PVOID PaToVa(
    ULONG64 pa                   // 物理地址
);


/* ============================================================================
 *                           页表操作函数声明
 * ============================================================================ */

/**
 * GetPageTableOffsets - 获取虚拟地址对应的页表项
 * 
 * 计算虚拟地址在各级页表中的索引
 * 并返回对应的页表项指针
 * 
 * 参数：
 *   va      - 虚拟地址
 *   offsets - 输出参数，保存各级页表项指针
 * 
 * 注意：
 *   本简化版不进行实际的页表修改
 *   仅提供页表结构的演示
 */
void GetPageTableOffsets(
    PVOID va,                    // 虚拟地址
    PPAGE_TABLE_OFFSET offsets   // 输出：页表项指针
);


/* ============================================================================
 *                           反汇编函数声明
 * ============================================================================ */

/**
 * DisasmInstruction - 解析指令长度
 * 
 * 由于x64指令长度可变，我们需要知道原函数入口处
 * 有多少字节的指令，才能正确复制到trampoline
 * 
 * 这是一个简化版的指令解析器，只能解析常见的指令
 * 实际项目中应该使用专业的反汇编引擎（如HDE64）
 * 
 * 参数：
 *   code   - 要解析的指令地址
 *   length - 输出参数，实际指令长度
 * 
 * 返回值：
 *   TRUE  表示解析成功
 *   FALSE 表示解析失败
 */
BOOLEAN DisasmInstruction(
    PVOID code,                  // 指令地址
    PUINT8 length                // 输出：指令长度
);


/* ============================================================================
 *                           核心Hook函数声明
 * ============================================================================ */

/**
 * InstallInlineHook - 安装内联钩子
 * 
 * 这是整个项目的核心函数，实现Inline Hook的安装
 * 
 * Hook原理：
 *   1. 在目标函数入口处写入12字节的跳转指令
 *   2. 跳转到我们的hook函数
 *   3. 创建trampoline保存原始代码，用于调用原函数
 * 
 * 执行流程：
 *   1. 检查参数和状态
 *   2. 附加到目标进程
 *   3. 解析原函数指令长度
 *   4. 创建trampoline代码
 *   5. 锁定并修改原函数入口
 *   6. 保存hook信息
 *   7. 分离目标进程
 * 
 * 参数：
 *   pid         - 目标进程ID，要hook的进程
 *   originalFunc - 指向原函数地址的指针
 *                 安装后会被修改为trampoline地址
 *                 调用原函数时实际执行trampoline
 *   hookFunc    - 自定义的hook函数地址
 * 
 * 返回值：
 *   TRUE  表示安装成功
 *   FALSE 表示安装失败，可能原因：
 *     - 参数无效
 *     - 进程不存在
 *     - 内存操作失败
 *     - 已达到最大hook数量
 */
BOOLEAN InstallInlineHook(
    HANDLE pid,                  // 目标进程ID
    void** originalFunc,         // 原函数地址（输入/输出）
    void* hookFunc               // Hook函数地址
);

/**
 * RemoveInlineHook - 移除内联钩子
 * 
 * 卸载已安装的hook，恢复原函数
 * 
 * 执行流程：
 *   1. 查找对应的hook信息
 *   2. 附加到目标进程
 *   3. 恢复原函数入口的原始字节
 *   4. 清理trampoline
 *   5. 分离目标进程
 * 
 * 参数：
 *   hookFunc - 要移除的hook函数地址
 *             这个地址是InstallInlineHook中传入的hookFunc
 * 
 * 返回值：
 *   TRUE  表示移除成功
 *   FALSE 表示未找到对应的hook
 */
BOOLEAN RemoveInlineHook(
    PVOID hookFunc               // Hook函数地址
);


/* ============================================================================
 *                           全局变量
 * ============================================================================ */

/**
 * g_hooks - 全局钩子信息数组
 * 
 * 保存所有已安装的hook信息
 * 是一个固定大小的数组，由MAX_HOOK_COUNT限制数量
 * 
 * 为什么用数组而不用链表？
 *   - 数组访问速度快，O(1)时间复杂度
 *   - 内存连续，缓存友好
 *   - 固定大小，避免动态分配
 *   - 简化实现，入门教程不需要太复杂
 * 
 * 初始化为0（全局变量默认初始化）
 */
HOOK_INFO g_hooks[MAX_HOOK_COUNT] = {0};

/**
 * g_hookCount - 当前hook数量
 * 
 * 记录已安装的hook数量
 * 作为g_hooks数组的写入索引
 * 
 * 线程安全考虑：
 *   本简化版不处理多线程并发
 *   实际项目中需要添加自旋锁或互斥体
 */
UINT32 g_hookCount = 0;

/**
 * g_trampolinePool - Trampoline缓冲池
 * 
 * 预先分配的内存池，用于存放trampoline代码
 * 
 * 为什么使用缓冲池？
 *   - 避免频繁分配内存（驱动中分配内存有开销）
 *   - 简化内存管理
 *   - 4KB * 4 = 16KB，足够存放10个trampoline
 * 
 * 分配方式：
 *   NonPagedPool - 非分页内存，不会被换出到磁盘
 *   驱动代码必须在非分页内存中执行
 */
void* g_trampolinePool = NULL;


/* ============================================================================
 *                           驱动入口函数
 * ============================================================================ */

/**
 * DriverEntry - 驱动入口
 * 
 * Windows加载驱动时调用的第一个函数
 * 相当于C程序的main函数
 * 
 * 函数原型由DRIVER_INITIALIZE宏定义：
 *   typedef NTSTATUS (*PDRIVER_INITIALIZE)(
 *       PDRIVER_OBJECT DriverObject,
 *       PUNICODE_STRING RegistryPath
 *   );
 * 
 * 调用时机：
 *   驱动被CreateService/StartService加载时
 *   或通过NtLoadDriver加载时
 */
NTSTATUS DriverEntry(
    /* 
     * DriverObject - 驱动对象
     * Windows内核为每个驱动创建的对象
     * 包含驱动的各种信息：
     *   - DriverUnload: 卸载函数指针
     *   - DriverInit: 初始化函数指针
     *   - MajorFunction: 派遣函数数组（IRP处理）
     *   - DeviceObject: 设备对象链表
     */
    PDRIVER_OBJECT DriverObject,
    
    /* 
     * RegistryPath - 注册表路径
     * 驱动在注册表中的配置路径
     * 格式：\Registry\Machine\System\CurrentControlSet\Services\<驱动名>
     * 
     * 本简化版不使用此参数，所以用UNREFERENCED_PARAMETER忽略
     */
    PUNICODE_STRING RegistryPath
) {
    /* 
     * UNREFERENCED_PARAMETER - 消除未使用参数警告
     * 告诉编译器："我知道这个参数没用，不要警告我"
     * 等价于：(void)RegistryPath;
     */
    UNREFERENCED_PARAMETER(RegistryPath);
    
    /* 
     * 设置驱动卸载函数
     * Windows驱动模型要求：
     * 如果驱动需要支持卸载，必须设置此回调
     * 当驱动被卸载时，Windows会调用此函数
     * 
     * 设置方法：
     *   DriverObject->DriverUnload = 函数指针;
     * 
     * 如果不设置，驱动加载后无法卸载（只能重启系统）
     */
    DriverObject->DriverUnload = DriverUnload;
    
    /* 
     * DbgPrintEx - 内核调试打印函数
     * 相当于用户态的printf，但在内核中使用
     * 
     * 参数：
     *   DPFLTR_ACPI_ID - 调试组件ID，类似日志级别/分类
     *                    ACPI是高级配置和电源接口
     *                    这里只是借用一个常量值
     *   0               - 调试级别，0表示最低级别
     *   format string   - 格式字符串
     * 
     * 使用DbgPrintEx而不是DbgPrint：
     *   DbgPrintEx支持调试级别和组件过滤
     *   可以通过注册表或调试器设置只显示特定级别的输出
     * 
     * 输出查看方式：
     *   - 使用WinDbg: dbgview或内核调试
     *   - 使用DebugView工具
     */
    DbgPrintEx(DPFLTR_ACPI_ID, 0, "[PteHook] Driver loaded successfully\n");
    
    /* 
     * 返回成功状态
     * Windows驱动必须返回NTSTATUS类型的值
     * STATUS_SUCCESS = 0 表示成功
     * 
     * 常见的错误码：
     *   STATUS_UNSUCCESSFUL        - 操作失败
     *   STATUS_INSUFFICIENT_RESOURCES - 资源不足
     *   STATUS_ACCESS_VIOLATION    - 访问违规
     *   STATUS_OBJECT_NAME_NOT_FOUND - 对象不存在
     */
    return STATUS_SUCCESS;
}


/* ============================================================================
 *                           驱动卸载函数
 * ============================================================================ */

/**
 * DriverUnload - 驱动卸载函数
 * 
 * 当驱动被卸载时调用
 * 负责释放驱动分配的所有资源
 * 
 * 资源清理原则：
 *   1. 按照分配的反序释放
 *   2. 检查指针有效性后再释放
 *   3. 释放后立即置为NULL，防止double free
 *   4. 即使某个步骤失败，也要继续清理其他资源
 */
void DriverUnload(
    PDRIVER_OBJECT DriverObject   // 驱动对象（未使用）
) {
    UNREFERENCED_PARAMETER(DriverObject);
    
    /* 
     * 遍历所有hook并逐一移除
     * 卸载驱动时，必须先卸载所有hook
     * 否则目标进程会跳转到不存在的代码
     */
    for (UINT32 i = 0; i < g_hookCount; i++) {
        /* 
         * 检查hook是否存在
         * pid为NULL表示该槽位为空（已被移除）
         */
        if (g_hooks[i].pid != NULL) {
            /* 
             * RemoveInlineHook会：
             *   1. 附加到目标进程
             *   2. 恢复原函数入口
             *   3. 分离进程
             */
            RemoveInlineHook(g_hooks[i].hookAddr);
        }
    }
    
    /* 
     * 释放trampoline缓冲池
     * ExFreePool是内核内存释放函数
     * 
     * 注意：
     *   - 必须检查指针是否有效（非NULL）
     *   - 释放后立即置为NULL
     *   - 只能释放自己分配的内存
     */
    if (g_trampolinePool) {
        /* 
         * ExFreePool - 释放非分页池内存
         * 参数：要释放的内存指针
         * 
         * 对应的分配函数：
         *   ExAllocatePool(NonPagedPool, size)
         *   或 ExAllocatePoolWithTag(NonPagedPool, size, tag)
         */
        ExFreePool(g_trampolinePool);
        g_trampolinePool = NULL;
    }
    
    /* 
     * 记录卸载日志
     * 好的驱动应该在关键步骤记录日志
     * 便于调试和问题排查
     */
    DbgPrintEx(DPFLTR_ACPI_ID, 0, "[PteHook] Driver unloaded\n");
}


/* ============================================================================
 *                           核心Hook安装函数
 * ============================================================================ */

/**
 * InstallInlineHook - 安装内联钩子
 * 
 * 核心功能：在目标函数入口处写入跳转指令
 * 
 * 执行原理图示：
 * 
 *   安装前：                    安装后：
 *   ┌─────────────┐            ┌─────────────┐
 *   │ 原函数入口   │            │ mov rax, hook│  ← 12字节跳转指令
 *   │ [原始指令]   │            │ jmp rax      │
 *   │ ...         │            ├─────────────┤
 *                              │ 原函数继续   │  ← 由trampoline执行
 *                              │ ...         │
 *                              └─────────────┘
 * 
 * Trampoline结构：
 *   ┌─────────────────────────────────────┐
 *   │ [原函数开头的指令备份]  (N字节)      │
 *   │ retn                                │  ← 返回调用者
 *   │ nop nop nop nop nop nop             │  ← 填充对齐
 *   └─────────────────────────────────────┘
 * 
 * 当调用原函数时：
 *   由于originalFunc被修改为trampoline地址
 *   所以会先执行trampoline中的原始指令
 *   然后执行ret返回
 *   这样就"模拟"执行了原函数的前几条指令
 */
BOOLEAN InstallInlineHook(
    HANDLE pid,                  // 目标进程ID
    void** originalFunc,         // 原函数地址指针（输入输出参数）
    void* hookFunc               // 自定义Hook函数地址
) {
    /* 
     * 局部变量定义
     * 
     * PEPROCESS - 进程对象指针类型
     * Windows内核用EPROCESS结构体描述进程
     * PEPROCESS是指向EPROCESS的指针类型
     * 
     * 这个结构体包含进程的所有信息：
     *   - 进程ID、父进程ID
     *   - 页表基址（CR3）
     *   - 虚拟地址空间信息
     *   - 线程链表
     *   - 句柄表等
     */
    PEPROCESS process = NULL;
    
    /* 
     * BOOLEAN - 布尔类型
     * Windows内核中的布尔类型，只有TRUE(1)和FALSE(0)
     * 
     * result用于保存函数执行结果
     * 初始化为FALSE，失败时保持FALSE，成功时设为TRUE
     */
    BOOLEAN result = FALSE;
    
    /* ==================== 参数检查 ==================== */
    
    /* 
     * 检查hook数量是否已达上限
     * 防止数组越界访问
     */
    if (g_hookCount >= MAX_HOOK_COUNT) {
        DbgPrintEx(DPFLTR_ACPI_ID, 0, "[PteHook] Max hook count reached\n");
        return FALSE;
    }
    
    /* 
     * PsLookupProcessByProcessId - 通过进程ID查找进程对象
     * 
     * 参数：
     *   pid     - 进程ID（HANDLE类型）
     *   process - 输出参数，返回EPROCESS指针
     * 
     * 返回值：
     *   STATUS_SUCCESS 表示成功
     *   STATUS_INVALID_PARAMETER - 参数无效
     *   STATUS_INVALID_CID - 进程ID不存在
     * 
     * 注意：
     *   这个函数会增加进程的引用计数
     *   使用完后需要调用ObDereferenceObject减少计数
     * 
     * 为什么需要查找进程？
     *   我们需要获取EPROCESS结构体来：
     *   1. 附加到进程地址空间（KeStackAttachProcess）
     *   2. 获取进程信息
     *   3. 确保进程存在且有效
     */
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) {
        DbgPrintEx(DPFLTR_ACPI_ID, 0, "[PteHook] Failed to find process %p\n", pid);
        return FALSE;
    }
    
    /* 
     * 获取目标地址
     * originalFunc是一个指针的指针（void**）
     * *originalFunc是目标函数的实际地址
     * 
     * 例如：
     *   void* ntOpenProcessAddr = NtOpenProcess;
     *   void** pAddr = &ntOpenProcessAddr;
     *   InstallInlineHook(pid, pAddr, fakeFunc);
     *   此时*pAddr就是NtOpenProcess的地址
     */
    void* targetAddr = *originalFunc;
    
    /* 
     * bytesNeeded - 需要复制的字节数
     * 用于保存原函数开头的指令
     * 初始化为0，稍后由DisasmInstruction填充
     */
    UINT8 bytesNeeded = 0;
    
    /* ==================== 进程附加 ==================== */
    
    /* 
     * KAPC_STATE - 异步过程调用状态结构
     * 
     * 用于KeStackAttachProcess保存当前线程的附加状态
     * 附加完成后，当前线程"进入"目标进程的上下文
     * 之后所有的内存操作都是针对目标进程的
     * 
     * APC = Asynchronous Procedure Call
     * 内核用于在线程上下文中执行代码的机制
     * 
     * 附加目标进程：
     *   KeStackAttachProcess(process, &apcState);
     *   // 现在在目标进程上下文中
     *   // 可以访问目标进程的内存
     *   KeUnstackDetachProcess(&apcState);  // 分离
     */
    KAPC_STATE apcState;
    
    /* 
     * KeStackAttachProcess - 附加到目标进程地址空间
     * 
     * 作用：使当前线程"借用"目标进程的地址空间
     *      之后执行的代码可以访问目标进程的内存
     * 
     * 参数：
     *   process  - 目标进程的EPROCESS指针
     *   apcState - 输出参数，保存附加状态
     * 
     * 注意事项：
     *   - 必须与KeUnstackDetachProcess配对使用
     *   - 附加期间不能进行可能导致上下切换的操作
     *   - 不能睡眠或等待
     * 
     * 为什么需要附加？
     *   Windows的内存保护机制：
     *   - 每个进程有独立的虚拟地址空间
     *   - 用户态地址（如0x400000）在不同进程中映射不同物理内存
     *   - 只有在目标进程上下文中才能正确访问其用户态内存
     */
    KeStackAttachProcess(process, &apcState);
    
    /* ==================== 指令解析 ==================== */
    
    /* 
     * DisasmInstruction - 反汇编函数
     * 
     * 作用：解析目标函数开头的指令，计算总长度
     * 
     * 为什么需要解析指令？
     *   - x64指令长度不固定（1-15字节）
     *   - 我们需要知道前N字节的指令内容
     *   - N必须 >= 12（跳转指令大小）
     *   - 如果原函数开头不足12字节指令，需要更多字节
     * 
     * 返回值通过length参数输出
     * 如果解析失败，返回FALSE
     */
    if (!DisasmInstruction(targetAddr, &bytesNeeded)) {
        DbgPrintEx(DPFLTR_ACPI_ID, 0, "[PteHook] Failed to disassemble target function\n");
        goto CLEANUP;  // 跳转到清理代码
    }
    
    /* 
     * 确保bytesNeeded至少等于跳转指令大小
     * 如果原函数开头只有少量字节指令
     * 我们需要复制更多字节来填满12字节的跳转指令
     * 
     * 例如：
     *   targetAddr开头有：push rbx (2字节)
     *   mov rax, rcx (3字节)
     *   总共5字节 < 12字节
     *   需要复制12字节，覆盖更多后续指令
     */
    if (bytesNeeded < JMP_INSTRUCTION_SIZE) {
        bytesNeeded = JMP_INSTRUCTION_SIZE;
    }
    
    /* ==================== 分配Trampoline缓冲池 ==================== */
    
    /* 
     * 检查trampoline缓冲池是否已分配
     * 第一次调用时需要分配
     */
    if (!g_trampolinePool) {
        /* 
         * ExAllocatePool - 从非分页池分配内存
         * 
         * 参数：
         *   NonPagedPool - 内存池类型
         *                非分页内存：不会被换出到磁盘
         *                驱动代码必须在非分页内存中执行
         *                （因为缺页中断处理可能需要锁）
         * 
         *   PAGE_SIZE_4KB * 4 - 分配大小
         *                    4个页面，16KB
         *                    每个hook最多占用一个页面（4KB）
         *                    最多支持MAX_HOOK_COUNT(10)个hook
         * 
         * 返回值：
         *   NULL表示分配失败
         *   成功返回分配的内存指针
         * 
         * 对应的释放函数：
         *   ExFreePool(pointer)
         * 
         * 替代函数（推荐）：
         *   ExAllocatePool2(NonPagedPool, size, 'tag')
         *   可以指定4字节的tag，便于调试时追踪内存分配来源
         */
        g_trampolinePool = ExAllocatePool(NonPagedPool, PAGE_SIZE_4KB * 4);
        
        /* 
         * 检查分配结果
         * 如果失败，释放之前分配的资源并返回
         */
        if (!g_trampolinePool) {
            DbgPrintEx(DPFLTR_ACPI_ID, 0, "[PteHook] Failed to allocate trampoline pool\n");
            goto CLEANUP;
        }
        
        /* 
         * RtlZeroMemory - 清零内存
         * 
         * 将内存块的所有字节设置为0
         * 等价于memset(ptr, 0, size)
         * 
         * 为什么要清零？
         *   - 防止未初始化的数据导致问题
         *   - 确保trampoline以干净的状态开始
         */
        RtlZeroMemory(g_trampolinePool, PAGE_SIZE_4KB * 4);
    }
    
    /* 
     * 计算当前trampoline的存放位置
     * 
     * 布局：
     *   g_trampolinePool
     *   ├─ Hook 0: 0x0000 - 0x0FFF (4KB)
     *   ├─ Hook 1: 0x1000 - 0x1FFF (4KB)
     *   ├─ Hook 2: 0x2000 - 0x2FFF (4KB)
     *   └─ ...
     * 
     * 每个hook占用4KB空间，足够存放：
     *   - 原始指令备份（最多12字节）
     *   - 返回指令（8字节）
     *   - 填充（剩余空间）
     */
    void* trampolineAddr = (char*)g_trampolinePool + (g_hookCount * PAGE_SIZE_4KB);
    
    /* ==================== 创建Trampoline代码 ==================== */
    
    /* 
     * 复制原始指令到trampoline
     * 
     * RtlCopyMemory - 内核内存复制函数
     * 等价于C标准库的memcpy
     * 
     * 参数：
     *   destination - 目标地址（trampoline）
     *   source      - 源地址（原函数入口）
     *   length      - 复制长度（bytesNeeded字节）
     * 
     * 作用：
     *   保存原函数开头的指令
     *   这样在hook函数中可以调用"原函数"
     *   实际上是执行这些被复制过来的指令
     */
    RtlCopyMemory(trampolineAddr, targetAddr, bytesNeeded);
    
    /* 
     * 添加返回指令
     * 
     * returnCode数组包含：
     *   0xC3 - retn指令，机器码1字节
     *          弹出返回地址，返回到调用者
     * 
     *   0x90 - nop指令，机器码1字节
     *          空操作，用于填充对齐
     * 
     * 这些指令放在复制的原始指令后面
     * trampoline执行流程：
     *   1. 执行复制的原始指令（模拟原函数开头）
     *   2. 执行ret，返回到调用者
     *   3. 这样就"跳过"了原函数的剩余部分
     */
    UCHAR returnCode[] = {
        0xC3,   // retn - 返回调用者
        0x90,   // nop  - 填充
        0x90,
        0x90,
        0x90,
        0x90,
        0x90,
        0x90
    };
    
    /* 
     * 将返回指令复制到trampoline
     * 位置：原始指令之后
     */
    RtlCopyMemory((char*)trampolineAddr + bytesNeeded, returnCode, sizeof(returnCode));
    
    /* ==================== 构造跳转指令 ==================== */
    
    /* 
     * jmpCode - 跳转指令机器码
     * 
     * 在x64架构下，跳转到任意地址需要12字节：
     * 
     *   ┌──────────────────────────────────────────┐
     *   │ 48 B8 │ [8字节地址] │ FF E0            │
     *   │ mov   │ hook函数地址 │ jmp rax         │
     *   │ rax,  │             │                 │
     *   │ imm64 │             │                 │
     *   └──────────────────────────────────────────┘
     *   1字节  8字节          2字节  = 12字节
     * 
     * 字节编码详解：
     *   0x48 - REX前缀，表示使用64位操作数大小
     *   0xB8 - mov rax, imm64 操作码
     *   [2-9字节] - hook函数地址（64位立即数）
     *   0xFF - ModR/M前缀
     *   0xE0 - ModR/M字节，mod=00, reg=100, rm=000
     *           其中reg=100表示jmp r/m64（跳转到rax）
     */
    UCHAR jmpCode[JMP_INSTRUCTION_SIZE] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, imm64
        0xFF, 0xE0                                                   // jmp rax
    };
    
    /* 
     * 填充跳转目标地址
     * 
     * jmpCode + 2 指向8字节立即数的位置
     * 
     * *(PVOID*)(jmpCode + 2) = hookFunc;
     * 
     * 解释：
     *   (jmpCode + 2) - 数组指针运算，得到第3个元素的地址
     *   (PVOID*)      - 将地址转换为void*指针
     *   *(...)        - 解引用，赋值
     * 
     * 写入后：
     *   jmpCode[2-9] = hookFunc的低32位（在小端序中先存储）
     *   jmpCode[10] = hookFunc的第8字节（最高位）
     * 
     * 注意：小端序存储：
     *   地址0x12345678ABCD1000在内存中存储为：
     *   00 10 CD AB 78 56 34 12（低字节在前）
     */
    *(PVOID*)(jmpCode + 2) = hookFunc;
    
    /* ==================== 修改目标函数入口 ==================== */
    
    /* 
     * 初始化重保护上下文
     * 将所有成员设置为0/NULL
     * 避免使用未初始化的数据
     */
    REPROTECT_CONTEXT reprotectCtx = {0};
    
    /* 
     * 锁定内存以进行写入
     * 
     * MmLockMemoryForWrite函数：
     *   1. 创建MDL描述目标内存
     *   2. 锁定页面（防止被换出）
     *   3. 映射到内核空间获得可写指针
     *   4. 修改保护属性为可写+可执行
     * 
     * 参数：
     *   targetAddr - 要修改的虚拟地址（原函数入口）
     *   PAGE_SIZE_4KB - 修改的范围（一页）
     *   &reprotectCtx - 输出上下文信息
     * 
     * 注意：
     *   代码页默认是PAGE_EXECUTE_READ（只读+可执行）
     *   我们需要修改它，所以必须改变保护属性
     */
    if (!NT_SUCCESS(MmLockMemoryForWrite(targetAddr, PAGE_SIZE_4KB, &reprotectCtx))) {
        DbgPrintEx(DPFLTR_ACPI_ID, 0, "[PteHook] Failed to lock memory for write\n");
        goto CLEANUP;
    }
    
    /* 
     * 复制跳转指令到目标地址
     * 
     * reprotectCtx.lockedVa是锁定后的可写虚拟地址
     * 
     * 这一步是实际"安装"hook的操作：
     *   原函数入口的前12字节被替换为跳转指令
     *   当任何代码调用原函数时，会先跳转到hook函数
     * 
     * 注意：
     *   这里修改的是目标进程内存
     *   因为我们之前调用了KeStackAttachProcess
     *   所以当前线程在目标进程上下文中
     */
    RtlCopyMemory(reprotectCtx.lockedVa, jmpCode, JMP_INSTRUCTION_SIZE);
    
    /* 
     * 解除内存锁定
     * 
     * 完成修改后，立即解锁内存
     * 恢复原来的保护属性（只读+可执行）
     * 减少被攻击面
     * 
     * 错误处理：
     *   如果解锁失败，很难处理
     *   实际项目中应该记录日志并考虑系统稳定性
     */
    MmUnlockMemoryForWrite(&reprotectCtx);
    
    /* ==================== 保存Hook信息 ==================== */
    
    /* 
     * 保存hook信息到全局数组
     * 方便后续卸载和调试
     * 
     * 保存的信息：
     *   pid - 目标进程ID
     *   targetAddr - 原函数入口地址
     *   hookAddr - hook函数地址
     *   trampolineAddr - trampoline代码地址
     *   originalBytesCount - 原始字节数
     *   originalBytes - 原始字节内容
     */
    g_hooks[g_hookCount].pid = pid;
    g_hooks[g_hookCount].targetAddr = targetAddr;
    g_hooks[g_hookCount].hookAddr = hookFunc;
    g_hooks[g_hookCount].trampolineAddr = trampolineAddr;
    g_hooks[g_hookCount].originalBytesCount = bytesNeeded;
    RtlCopyMemory(g_hooks[g_hookCount].originalBytes, targetAddr, bytesNeeded);
    
    /* 
     * 修改originalFunc指针
     * 
     * 重要步骤：
     *   将*originalFunc修改为trampolineAddr
     * 
     * 这意味着：
     *   调用者以为调用的是原函数
     *   实际上执行的是trampoline代码
     *   trampoline执行原始指令后返回
     *   就"模拟"执行了原函数
     * 
     * 为什么能调用原函数？
     *   调用者使用保存的originalFunc指针调用
     *   实际调用的是trampoline
     *   trampoline执行原函数开头的指令后返回
     *   所以看起来像是调用了原函数
     */
    *originalFunc = trampolineAddr;
    
    /* 
     * 增加hook计数
     * 为下一个hook准备索引
     */
    g_hookCount++;
    
    /* ==================== 记录成功日志 ==================== */
    
    DbgPrintEx(DPFLTR_ACPI_ID, 0, "[PteHook] Hook installed successfully\n");
    DbgPrintEx(DPFLTR_ACPI_ID, 0, "[PteHook] Target: %p, Hook: %p, Trampoline: %p\n", 
               targetAddr, hookFunc, trampolineAddr);
    
    /* 
     * 设置成功标志
     * 之后跳转到CLEANUP进行清理
     */
    result = TRUE;
    
/* ==================== 清理代码 ==================== */

/*
 * CLEANUP标签
 * 所有错误路径都会跳转到这里
 * 
 * 使用goto进行错误处理的优点：
 *   1. 资源释放集中在一处，避免遗漏
 *   2. 减少嵌套层次，提高代码可读性
 *   3. 清晰展示函数的执行流程
 * 
 * 清理步骤：
 *   1. 分离目标进程
 *   2. 减少进程引用计数
 */
CLEANUP:
    /* 
     * KeUnstackDetachProcess - 分离进程
     * 
     * 与KeStackAttachProcess配对使用
     * 恢复当前线程到原来的进程上下文
     * 
     * 参数：
     *   &apcState - KeStackAttachProcess保存的状态
     * 
     * 注意：
     *   必须在任何返回路径之前调用
     *   否则会导致线程处于错误的进程上下文
     */
    KeUnstackDetachProcess(&apcState);
    
    /* 
     * ObDereferenceObject - 减少对象引用计数
     * 
     * PsLookupProcessByProcessId会增加进程的引用计数
     * 必须调用此函数减少计数，否则会导致进程对象泄漏
     * 
     * 引用计数机制：
     *   - 每次获取对象指针时计数+1
     *   - 使用完毕后计数-1
     *   - 计数为0时对象被销毁
     * 
     * 常见错误：
     *   - 忘记调用此函数 → 内存泄漏
     *   - 调用次数过多 → 提前销毁对象
     */
    ObDereferenceObject(process);
    
    /* 
     * 返回结果
     * 成功返回TRUE，失败返回FALSE
     */
    return result;
}


/* ============================================================================
 *                           Hook卸载函数
 * ============================================================================ */

/**
 * RemoveInlineHook - 卸载内联钩子
 * 
 * 恢复原函数入口，移除hook
 * 
 * 执行流程：
 *   1. 查找对应的hook信息
 *   2. 附加到目标进程
 *   3. 恢复原函数入口的原始字节
 *   4. 清理trampoline
 *   5. 分离目标进程
 * 
 * 参数：
 *   hookFunc - 要卸载的hook函数地址
 *             这个地址是InstallInlineHook中传入的hookFunc
 * 
 * 返回值：
 *   TRUE  - 找到并成功卸载
 *   FALSE - 未找到对应的hook
 */
BOOLEAN RemoveInlineHook(
    PVOID hookFunc               // Hook函数地址
) {
    /* 
     * 遍历hook数组查找目标
     * 线性搜索，时间复杂度O(n)
     * 由于MAX_HOOK_COUNT=10，性能影响可忽略
     */
    for (UINT32 i = 0; i < g_hookCount; i++) {
        /* 
         * 匹配hook函数地址
         * 必须完全匹配才能卸载
         */
        if (g_hooks[i].hookAddr == hookFunc) {
            PEPROCESS process = NULL;
            
            /* 
             * 再次获取进程对象
             * 需要EPROCESS指针来附加进程
             */
            if (NT_SUCCESS(PsLookupProcessByProcessId(g_hooks[i].pid, &process))) {
                /* 附加到目标进程 */
                KAPC_STATE apcState;
                KeStackAttachProcess(process, &apcState);
                
                /* 
                 * 恢复原始字节
                 * 将保存的原函数入口字节复制回去
                 */
                REPROTECT_CONTEXT reprotectCtx = {0};
                if (NT_SUCCESS(MmLockMemoryForWrite(g_hooks[i].targetAddr, PAGE_SIZE_4KB, &reprotectCtx))) {
                    /* 
                     * 恢复原始字节
                     * 使用RtlCopyMemory将保存的字节复制回原位置
                     * 
                     * 这一步至关重要：
                     *   - 移除跳转指令
                     *   - 恢复原始指令
                     *   - 原函数恢复正常执行
                     */
                    RtlCopyMemory(reprotectCtx.lockedVa, 
                                  g_hooks[i].originalBytes, 
                                  g_hooks[i].originalBytesCount);
                    
                    MmUnlockMemoryForWrite(&reprotectCtx);
                }
                
                /* 分离进程 */
                KeUnstackDetachProcess(&apcState);
                
                /* 减少引用计数 */
                ObDereferenceObject(process);
            }
            
            /* 
             * 清除hook信息
             * 设置pid为NULL表示此槽位可用
             * 注意：不清除其他字段，因为不再使用
             */
            g_hooks[i].pid = NULL;
            
            DbgPrintEx(DPFLTR_ACPI_ID, 0, "[PteHook] Hook removed successfully\n");
            
            return TRUE;
        }
    }
    
    return FALSE;
}


/* ============================================================================
 *                           指令解析函数
 * ============================================================================ */

/**
 * DisasmInstruction - 解析指令长度（简化版）
 * 
 * x64指令长度解析：
 *   - 指令长度从1字节到15字节不等
 *   - 由操作码、前缀、ModR/M、SIB、立即数等组成
 *   - 需要逐字节解析才能确定总长度
 * 
 * 简化版实现：
 *   - 只解析最常见的指令前缀
 *   - 不处理所有复杂情况
 *   - 实际项目应使用专业反汇编引擎（如HDE64）
 * 
 * 参数：
 *   code   - 要解析的指令地址
 *   length - 输出参数，指令长度
 * 
 * 返回值：
 *   TRUE - 解析成功
 *   FALSE - 解析失败
 */
BOOLEAN DisasmInstruction(
    PVOID code,                  // 指令地址
    PUINT8 length                // 输出：指令长度
) {
    /* totalLen - 已解析的总字节数 */
    UINT8 totalLen = 0;
    
    /* 
     * 循环解析指令
     * 最多解析5条指令，总长不超过15字节
     */
    for (int i = 0; i < 5 && totalLen < 15; i++) {
        /* 读取当前字节 */
        UCHAR byte = *(UCHAR*)((char*)code + totalLen);
        
        /* 
         * 指令解析
         * 
         * push/pop寄存器指令：
         *   50+r  - push r32 (r32=0-7对应rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi)
         *   58+r  - pop r32
         *   长度：1字节
         */
        if (byte >= 0x50 && byte <= 0x57) {
            totalLen += 1;
        }
        /* 
         * REX前缀：
         *   48     - REX.W (64位操作数大小覆盖)
         *   49     - REX.WB
         *   4C     - REX.XLB
         *   等...
         *   长度：1字节
         */
        else if (byte == 0x48 || byte == 0x4C || byte == 0x49) {
            totalLen += 1;
        }
        /* 
         * mov r32, imm32：
         *   B8+r - mov r32, imm32
         *   长度：5字节（1字节 opcode + 4字节立即数）
         */
        else if (byte == 0xB8 || byte == 0xBA || byte == 0xBB || byte == 0xB9) {
            totalLen += 5;
        }
        /* 
         * 短跳转/近跳转：
         *   E9     - jmp rel32 (近跳转，32位相对偏移)
         *   EB     - jmp rel8  (短跳转，8位相对偏移)
         *   长度：5字节或1字节（包含操作数）
         * 
         * 立即数存储方式：
         *   rel8/rel32 是相对于下一条指令的偏移
         *   例如：E9 0x12345678 表示跳转到 (当前地址+5+0x12345678)
         */
        else if (byte == 0xE9 || byte == 0xEB) {
            totalLen += 5;  // 简化为5字节
        }
        /* 
         * 间接跳转：
         *   FF 25 - jmp qword ptr [rip+disp32] (64位)
         *   长度：6字节（2字节 opcode + 4字节偏移）
         */
        else if (byte == 0xFF && *(UCHAR*)((char*)code + totalLen + 1) == 0x25) {
            totalLen += 6;
        }
        /* 
         * 算术/逻辑指令（imm32）：
         *   80-83  - various arithmetic/logic with imm8/imm32
         *   长度：5字节（1字节 opcode + ModR/M + 4字节立即数）
         */
        else if ((byte & 0xF0) == 0x80) {
            totalLen += 5;
        }
        /* 
         * mov指令（复杂寻址）：
         *   88-8B  - mov r/m32, r32 或 mov r32, r/m32
         *   长度：6字节（1字节 opcode + 1字节 ModR/M + 4字节位移）
         */
        else if ((byte & 0xFE) == 0x88) {
            totalLen += 6;
        }
        /* 
         * 扩展操作码：
         *   0F     - 2字节操作码前缀
         *   长度：6字节（1字节 0F + 1字节 opcode + ModR/M + 4字节操作数）
         */
        else if (byte == 0x0F) {
            totalLen += 6;
        }
        /* 
         * 默认情况：
         *   其他单字节指令
         *   长度：1字节
         */
        else {
            totalLen += 1;
        }
    }
    
    /* 
     * 限制最小长度
     * 确保至少能容纳12字节的跳转指令
     */
    *length = totalLen > 12 ? 12 : totalLen;
    
    return TRUE;
}


/* ============================================================================
 *                           内存锁定函数
 * ============================================================================ */

/**
 * MmLockMemoryForWrite - 锁定内存页以进行写入
 * 
 * 完整的MDL操作流程：
 * 
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │ 步骤1：创建MDL                                             │
 *   │   IoAllocateMdl(va, length, FALSE, FALSE, NULL)            │
 *   │   ↓                                                        │
 *   │ 步骤2：锁定页面                                             │
 *   │   MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess)      │
 *   │   ↓                                                        │
 *   │ 步骤3：映射到内核空间                                       │
 *   │   MmMapLockedPagesSpecifyCache(mdl, KernelMode, ...)       │
 *   │   ↓                                                        │
 *   │ 步骤4：修改保护属性                                         │
 *   │   MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE)   │
 *   │   ↓                                                        │
 *   │ [可以安全写入]                                             │
 *   │   ↓                                                        │
 *   │ 步骤5：清理（调用MmUnlockMemoryForWrite）                   │
 *   └─────────────────────────────────────────────────────────────┘
 * 
 * 参数：
 *   va      - 要修改的虚拟地址
 *   length  - 内存区域长度
 *   ctx     - 输出参数，保存操作上下文
 * 
 * 返回值：
 *   STATUS_SUCCESS - 成功
 *   其他值 - 失败
 */
NTSTATUS MmLockMemoryForWrite(
    PVOID va,                    // 虚拟地址
    ULONG length,                // 长度
    PREPROTECT_CONTEXT ctx       // 输出上下文
) {
    NTSTATUS status;
    
    /* 初始化状态为成功 */
    status = STATUS_SUCCESS;
    
    /* 初始化上下文为0 */
    ctx->mdl = 0;
    ctx->lockedVa = 0;
    
    /* 
     * 步骤1：创建MDL
     * 
     * IoAllocateMdl - 创建MDL结构
     * 
     * 参数：
     *   va        - 要描述的虚拟地址
     *   length    - 内存区域长度
     *   Secondary - FALSE表示这是主MDL，不是辅助MDL
     *   ChargeQuota - FALSE表示不进行配额计费
     *   Irp        - NULL，不关联IRP
     * 
     * 返回值：
     *   NULL表示失败
     *   成功返回PMDL指针
     * 
     * MDL = Memory Descriptor List
     * 用于描述一个内存区域的信息
     * 主要用于：
     *   - 锁定页面（防止被换出）
     *   - DMA传输（描述物理内存布局）
     */
    ctx->mdl = IoAllocateMdl(va, length, FALSE, FALSE, NULL);
    
    /* 检查MDL创建结果 */
    if (!ctx->mdl) {
        /* 
         * STATUS_INSUFFICIENT_RESOURCES
         * 内存不足，无法分配MDL结构
         */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    /* 
     * 步骤2：锁定页面
     * 
     * MmProbeAndLockPages - 探测并锁定页面
     * 
     * 参数：
     *   mdl       - MDL指针
     *   KernelMode - 调用者运行在KernelMode
     *   IoWriteAccess - 请求写入权限
     * 
     * 作用：
     *   - 检查MDL描述的内存区域是否有效
     *   - 将物理页面锁定在内存中（不会被换出到磁盘）
     *   - 设置页面的访问权限标记
     * 
     * 异常处理：
     *   使用__try/__except捕获异常
     *   如果内存访问失败，会触发异常
     */
    __try {
        /* 
         * MmProbeAndLockPages可能失败的场景：
         *   - 用户态地址无效（进程已退出）
         *   - 内存已被释放
         *   - 页面不在内存中（已被换出，但恢复时出错）
         */
        MmProbeAndLockPages(ctx->mdl, KernelMode, IoWriteAccess);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        /* 捕获异常，释放MDL并返回错误码 */
        return GetExceptionCode();
    }
    
    /* 
     * 步骤3：映射到内核空间
     * 
     * MmMapLockedPagesSpecifyCache - 指定缓存方式映射锁定的页面
     * 
     * 参数：
     *   mdl           - 锁定的MDL
     *   KernelMode    - 内核模式访问
     *   MmCached      - 缓存方式（MmCached/MmNonCached/MmWriteCombined）
     *   RequestedAddress - NULL，由系统选择映射地址
     *   BugCheckOnFailure - FALSE，失败时不蓝屏
     *   Priority - NormalPagePriority，映射优先级
     * 
     * 返回值：
     *   NULL表示失败
     *   成功返回映射后的内核虚拟地址
     * 
     * 为什么需要映射？
     *   - 原始虚拟地址可能是用户态地址
     *   - 我们在内核态，无法直接访问用户态地址
     *   - 需要将页面映射到内核地址空间
     */
    ctx->lockedVa = (PUCHAR)MmMapLockedPagesSpecifyCache(
        ctx->mdl, 
        KernelMode, 
        MmCached, 
        NULL, 
        FALSE, 
        NormalPagePriority
    );
    
    /* 检查映射结果 */
    if (!ctx->lockedVa) {
        /* 
         * 映射失败，清理已分配的资源
         * 逆序释放：先解锁页面，再释放MDL
         */
        MmUnlockPages(ctx->mdl);
        IoFreeMdl(ctx->mdl);
        ctx->mdl = 0;
        return STATUS_UNSUCCESSFUL;
    }
    
    /* 
     * 步骤4：修改保护属性
     * 
     * MmProtectMdlSystemAddress - 修改MDL描述区域的保护属性
     * 
     * 参数：
     *   mdl          - MDL指针
     *   ProtectValue - 新的保护属性
     * 
     * PAGE_EXECUTE_READWRITE：
     *   - 可执行（EXECUTE）
     *   - 可读（READ）
     *   - 可写（WRITE）
     * 
     * 原始代码页保护属性通常是：
     *   PAGE_EXECUTE_READ（只读+可执行）
     * 
     * 注意：
     *   修改为可写后，虽然方便我们写入
     *   但也降低了安全性（代码可能被意外修改）
     *   应该在写入后立即恢复原始保护属性
     */
    status = MmProtectMdlSystemAddress(ctx->mdl, PAGE_EXECUTE_READWRITE);
    
    /* 检查保护属性修改结果 */
    if (!NT_SUCCESS(status)) {
        /* 失败，清理资源 */
        MmUnmapLockedPages(ctx->lockedVa, ctx->mdl);
        MmUnlockPages(ctx->mdl);
        IoFreeMdl(ctx->mdl);
        ctx->lockedVa = 0;
        ctx->mdl = 0;
    }
    
    return status;
}


/* ============================================================================
 *                           内存解锁函数
 * ============================================================================ */

/**
 * MmUnlockMemoryForWrite - 解除内存锁定
 * 
 * MmLockMemoryForWrite的逆操作
 * 逆序释放资源
 * 
 * 清理步骤：
 *   1. 解除内核地址映射
 *   2. 解锁页面
 *   3. 释放MDL
 *   4. 清零上下文指针
 * 
 * 参数：
 *   ctx - MmLockMemoryForWrite创建的上下文
 * 
 * 返回值：
 *   STATUS_SUCCESS
 */
NTSTATUS MmUnlockMemoryForWrite(
    PREPROTECT_CONTEXT ctx       // 操作上下文
) {
    NTSTATUS status;
    
    status = STATUS_SUCCESS;
    
    /* 
     * 步骤1：解除映射
     * 
     * MmUnmapLockedPages - 解除页面映射
     * 
     * 参数：
     *   BaseAddress - MmMapLockedPagesSpecifyCache返回的地址
     *   Mdl         - 关联的MDL
     */
    if (ctx->lockedVa) {
        MmUnmapLockedPages(ctx->lockedVa, ctx->mdl);
    }
    
    /* 
     * 步骤2：解锁页面
     * 
     * MmUnlockPages - 解锁页面
     * 
     * 作用：
     *   - 允许页面被换出到磁盘
     *   - 清除锁定标记
     */
    if (ctx->mdl) {
        MmUnlockPages(ctx->mdl);
        
        /* 
         * 步骤3：释放MDL
         * 
         * IoFreeMdl - 释放MDL结构
         */
        IoFreeMdl(ctx->mdl);
    }
    
    /* 
     * 步骤4：清零上下文
     * 
     * 防止释放后的指针被误用
     */
    ctx->lockedVa = NULL;
    ctx->mdl = NULL;
    
    return status;
}


/* ============================================================================
 *                           地址转换函数
 * ============================================================================ */

/**
 * VaToPa - 虚拟地址转物理地址
 * 
 * 封装Windows内核函数
 * 
 * 参数：
 *   va - 虚拟地址
 * 
 * 返回值：
 *   物理地址（64位值）
 * 
 * 注意：
 *   这个函数只能用于内核地址
 *   用户态地址需要先附加到对应进程
 */
ULONG64 VaToPa(
    PVOID va                     // 虚拟地址
) {
    /* 
     * MmGetPhysicalAddress - 获取物理地址
     * 
     * 参数：
     *   VirtualAddress - 虚拟地址
     * 
     * 返回值：
     *   PHYSICAL_ADDRESS结构体
     *   QuadPart字段包含64位物理地址
     * 
     * 物理地址结构：
     *   typedef struct _PHYSICAL_ADDRESS {
     *       ULONGLONG QuadPart;
     *   } PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
     */
    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(va);
    
    /* 返回64位物理地址值 */
    return pa.QuadPart;
}


/**
 * PaToVa - 物理地址转虚拟地址
 * 
 * 封装Windows内核函数
 * 
 * 参数：
 *   pa - 物理地址
 * 
 * 返回值：
 *   虚拟地址指针
 * 
 * 注意：
 *   只能用于连续物理内存
 *   普通页面的物理地址不连续，无法映射
 */
PVOID PaToVa(
    ULONG64 pa                   // 物理地址
) {
    PHYSICAL_ADDRESS physicalAddr = {0};
    
    /* 初始化物理地址结构 */
    physicalAddr.QuadPart = pa;
    
    /* 
     * MmGetVirtualForPhysical - 物理地址转虚拟地址
     * 
     * 参数：
     *   PhysicalAddress - 物理地址
     * 
     * 返回值：
     *   映射后的虚拟地址
     * 
     * 注意：
     *   这个函数用于连续物理内存的映射
     *   由MmAllocateContiguousMemory分配的内存
     */
    return MmGetVirtualForPhysical(physicalAddr);
}


/* ============================================================================
 *                           页表操作函数
 * ============================================================================ */

/**
 * GetPageTableOffsets - 获取虚拟地址对应的页表项
 * 
 * x64虚拟地址结构：
 * 
 *   63      48 47    39 38    30 29    21 20    12 11         0
 *   ┌───────┬───────┬───────┬───────┬───────┬───────────────┐
 *   │ Sign  │ PML4  │ PDPT  │  PDE  │  PTE  │  Page Offset  │
 *   │ Extend│ Index │ Index │ Index │ Index │               │
 *   └───────┴───────┴───────┴───────┴───────┴───────────────┘
 *      16位     9位     9位     9位     9位       12位
 * 
 * 各级页表：
 *   - PML4（Page Map Level 4）：第1级，512个条目
 *   - PDPT（Page Directory Pointer Table）：第2级，512个条目
 *   - PDE（Page Directory Entry）：第3级，512个条目
 *   - PTE（Page Table Entry）：第4级，512个条目
 * 
 * 每个条目8字节（64位）
 * 
 * 参数：
 *   va      - 虚拟地址
 *   offsets - 输出参数，保存各级页表项指针
 * 
 * 注意：
 *   本简化版只计算指针，不进行实际修改
 */
void GetPageTableOffsets(
    PVOID va,                    // 虚拟地址
    PPAGE_TABLE_OFFSET offsets   // 输出：页表项指针
) {
    /* 
     * PTE_BASE - PTE表的内核虚拟地址
     * 
     * Windows内核使用自映射技术：
     *   - PTE表本身存储在物理内存中
     *   - 内核将PTE表映射到一个固定的虚拟地址
     *   - 这个地址是0xFFFFF68000000000
     * 
     * 有了PTE_BASE，就可以计算出其他各级表的位置
     * 
     * 地址计算公式：
     *   PTE = PTE_BASE + (VPN << 3)
     *   其中VPN = VirtualPageNumber = 虚拟地址 >> 12
     * 
     * 各级的VPN：
     *   PTE VPN  = va >> 12
     *   PDE VPN  = va >> 21
     *   PDPT VPN = va >> 30
     *   PML4 VPN = va >> 39
     */
    PVOID pteBase = (PVOID)0xFFFFF68000000000;
    
    /* 将虚拟地址转换为UINT64，避免符号扩展问题 */
    UINT64 virtualAddr = (UINT64)va;
    
    /* 
     * 计算各级索引并获取页表项指针
     * 
     * 步骤：
     *   1. 右移移除页内偏移（取VPN）
     *   2. 与掩码0x1FF提取低9位（索引）
     *   3. 左移3位（乘以8，因为每个条目8字节）
     *   4. 加上pteBase得到页表项地址
     * 
     * 掩码0x1FF（二进制）：
     *   0x1FF = 0b111111111 = 9个1
     */
    
    /* PTE索引：虚拟地址 >> 12，提取bits 12-20 */
    offsets->pte = (pte_64*)((pteBase) + ((virtualAddr >> 12) & 0x1FF));
    
    /* PDE索引：虚拟地址 >> 21，提取bits 21-29 */
    offsets->pde = (pde_64*)((pteBase) + ((virtualAddr >> 21) & 0x1FF));
    
    /* PDPT索引：虚拟地址 >> 30，提取bits 30-38 */
    offsets->pdpte = (pdpte_64*)((pteBase) + ((virtualAddr >> 30) & 0x1FF));
    
    /* PML4索引：虚拟地址 >> 39，提取bits 39-47 */
    offsets->pml4e = (pml4e_64*)((pteBase) + ((virtualAddr >> 39) & 0x1FF));
}
