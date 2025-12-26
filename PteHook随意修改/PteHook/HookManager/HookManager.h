/**
 * @file HookManager.h
 * @brief HookManager类头文件 - Inline Hook核心管理模块
 * 
 * 这个头文件定义了HookManager类，它是整个Inline Hook系统的核心。
 * HookManager负责管理所有Hook的安装、卸载，以及处理底层的技术细节。
 * 
 * 【什么是Inline Hook？】
 * 
 * Inline Hook（内联钩子）是一种运行时修改代码的技术。
 * 它的原理是：修改目标函数开头的几条机器指令，
 * 将程序执行流重定向到我们自定义的函数（钩子函数）。
 * 
 * 【Inline Hook的工作原理】
 * 
 * 1. 原始函数开头可能是：
 *    0x55                push rbp
 *    0x48 0x89 0xE5      mov rbp, rsp
 *    0x48 0xB8 xx xx...  mov rax, xxx (函数实际逻辑)
 * 
 * 2. Hook后变成：
 *    0x48 0xB8 xx xx...  mov rax, hook_function_address  (跳转到钩子函数)
 *    0xFF 0xE0           jmp rax
 *    ...（被覆盖的指令保存到trampoline）
 * 
 * 3. 当有人调用原始函数时，实际上先执行我们的钩子函数
 * 4. 钩子函数执行完后，可以选择调用原始函数（通过trampoline跳转）
 * 
 * 【Inline Hook vs EAT/IAT Hook】
 * 
 * - Inline Hook：直接修改函数代码，通用性强但实现复杂
 * - EAT Hook：修改导出地址表，只能Hook导出的函数
 * - IAT Hook：修改导入地址表，只能Hook动态导入的函数
 * 
 * Inline Hook是最通用但也最复杂的方法。
 * 
 * 【本项目的技术特点】
 * 
 * 本项目使用了一种特殊的Inline Hook技术：
 * - 隔离页表（Page Table Isolation）：让被Hook的页面只对目标进程可见
 * - 大页分割（Large Page Split）：将2MB/1GB大页分割成4KB小页
 * - Trampoline（蹦床）：保存原始指令，用于调用原函数
 */

#pragma once

/**
 * @brief 包含必要的头文件
 * 
 * structer.h：定义了HOOK_INFO结构体
 * MDL.h：提供了内存锁定和MDL操作的功能
 * ia32.hpp：提供了x86/x64指令解码功能
 */
#include"../structer.h"
#include"../MDL/MDL.h"
#include"../ia32/ia32.hpp"

/**
 * @class HookManager
 * @brief Inline Hook管理器类
 * 
 * HookManager类封装了所有Inline Hook相关的操作，
 * 提供了一个简单易用的接口来安装和卸载Hook。
 * 
 * 【单例模式】
 * 
 * HookManager使用单例模式（Singleton Pattern），
 * 这意味着在整个系统中只有一个HookManager实例。
 * 
 * 好处：
 * 1. 确保所有Hook操作都由同一个管理器处理
 * 2. 避免重复分配资源
 * 3. 方便管理全局状态
 * 
 * 实现方式：
 * - 私有构造函数：禁止外部创建实例
 * - 静态成员mInstance：保存唯一实例
 * - 静态方法GetInstance：获取实例
 * 
 * 【线程安全说明】
 * 
 * 在实际生产代码中，GetInstance需要考虑线程安全，
 * 可能需要使用双检查锁定（Double-Checked Locking）模式。
 * 但在本示例中，我们简化了实现。
 */
class HookManager
{
public: 
    /**
     * @fn bool InstallInlinehook(HANDLE pid, __inout void** originAddr, void* hookAddr)
     * @brief 安装Inline Hook
     * 
     * 这个函数是HookManager最核心的函数，负责完成所有Hook安装工作。
     * 
     * 【安装Hook的步骤】
     * 
     * 1. 检查是否超出最大Hook数量限制
     * 2. 获取目标进程对象（PEPROCESS）
     * 3. 隔离目标进程的页表（防止修改影响其他进程）
     * 4. 解析目标函数的开头指令（使用HDE引擎）
     * 5. 分配trampoline内存（保存原始指令）
     * 6. 修改目标函数开头，跳转到钩子函数
     * 7. 保存Hook信息到mHookInfo数组
     * 
     * 【参数详解】
     * 
     * @param pid 目标进程ID
     *     - 指定要Hook哪个进程的函数
     *     - Inline Hook是进程相关的，不同进程有独立的地址空间
     *     - 本项目支持跨进程Hook
     * 
     * @param originAddr 原始函数地址的指针（输入输出参数）
     *     - 输入：指向原始函数地址的指针
     *     - 输出：函数返回后，这个指针指向trampoline（蹦床）
     *     - trampoline是一个小内存块，包含：
     *       a) 原始函数被覆盖的指令
     *       b) 跳回原始函数剩余部分的代码
     *     - 调用者可以使用这个地址来调用原始函数
     * 
     * @param hookAddr 钩子函数地址
     *     - 这是我们自定义的函数地址
     *     - 当目标函数被调用时，会先跳转到这个地址
     * 
     * @return bool 安装成功返回true，失败返回false
     * 
     * 【__inout说明】
     * 
     * __inout是Microsoft特定的SAL（Source Annotation Language）标注。
     * - __in：输入参数
     * - __out：输出参数
     * - __inout：既是输入又是输出
     * 
     * 这些标注帮助编译器进行静态分析，找出潜在的bug。
     */
    bool InstallInlinehook(HANDLE pid, __inout void** originAddr, void* hookAddr );
    
    /**
     * @fn bool RemoveInlinehook(HANDLE pid, void* hookAddr)
     * @brief 卸载Inline Hook
     * 
     * 卸载Hook需要：
     * 1. 找到对应的Hook信息
     * 2. 恢复原始函数的机器码
     * 3. 释放trampoline内存
     * 4. 从Hook列表中移除
     * 
     * @param pid 目标进程ID
     * @param hookAddr 钩子函数地址（用于查找）
     * @return bool 卸载成功返回true，失败返回false
     */
    bool RemoveInlinehook(HANDLE pid, void* hookAddr);
    
    /**
     * @fn static HookManager* GetInstance()
     * @brief 获取HookManager单例实例
     * 
     * 这是获取HookManager实例的唯一方式。
     * 
     * 【实现原理】
     * 
     * static表示这是类方法，不需要创建类的实例就能调用。
     * 第一次调用时，如果mInstance为空，就创建新实例。
     * 后续调用直接返回已创建的实例。
     * 
     * 【使用示例】
     * 
     * // 获取实例
     * HookManager* mgr = HookManager::GetInstance();
     * 
     * // 安装Hook
     * mgr->InstallInlinehook(pid, &funcAddr, hookFunc);
     * 
     * @return HookManager* 指向单例实例的指针
     */
    static HookManager* GetInstance();

private: 
    /**
     * @fn bool IsolationPageTable(PEPROCESS process, void* isolateioAddr)
     * @brief 隔离目标进程的页表
     * 
     * 【为什么需要页表隔离？】
     * 
     * 在Windows系统中，多个进程可能共享物理内存页。
     * 例如：
     * - 系统DLL（如ntdll.dll、kernel32.dll）通常被所有进程共享
     * - 如果我们直接修改共享页，会影响所有进程
     * 
     * 我们的目标是只Hook特定进程（pid指定）中的函数，
     * 而不是影响所有进程。所以需要：
     * 1. 为目标进程创建一个独立的页表副本
     * 2. 修改这个副本，让被Hook的页面只映射到我们的 trampoline
     * 3. 让目标进程使用这个修改后的页表
     * 
     * 【PEPROCESS类型】
     * 
     * PEPROCESS是Windows内核中代表进程对象的数据类型。
     * 它是一个指针，指向系统的EPROCESS结构体。
     * EPROCESS包含了进程的所有信息：
     * - 进程ID（UniqueProcessId）
     * - 页表基址（DirectoryTableBase）
     * - 进程名称（ImageFileName）
     * - 等等...
     * 
     * 我们可以通过PsLookupProcessByProcessId从PID获取PEPROCESS。
     * 
     * @param process 目标进程的PEPROCESS对象
     * @param isolateioAddr 要隔离的虚拟地址
     * @return bool 成功返回true，失败返回false
     */
    bool IsolationPageTable(PEPROCESS process, void* isolateioAddr);
    
    /**
     * @fn bool SplitLargePage(pde_64 InPde, pde_64& OutPde)
     * @brief 将大页分割成小页
     * 
     * 【x64架构的内存页大小】
     * 
     * x64架构支持多种页大小：
     * - 4KB页（最常用）
     * - 2MB页（大页，Large Page）
     * - 1GB页（巨页，Huge Page）
     * 
     * 【为什么需要分割大页？】
     * 
     * 页表隔离需要修改单个页面的映射。
     * 但是，如果目标地址位于一个大页（2MB或1GB）内，
     * 我们无法只修改部分区域——大页是整体映射的。
     * 
     * 解决方案：
     * 1. 检测目标地址是否在大页内
     * 2. 如果是大页，将其分割成多个4KB小页
     * 3. 修改分割后的小页表项
     * 
     * 【pde_64结构体】
     * 
     * pde_64是Page Directory Entry（页目录项）的64位版本。
     * 它包含：
     * - page_frame_number：物理页帧号
     * - large_page：是否为2MB大页
     * - 其他标志位（可读、可写、用户/内核模式等）
     * 
     * 【参数说明】
     * 
     * @param InPde 输入的页目录项（可能指向大页）
     * @param OutPde 输出的页目录项（指向分割后的小页）
     *     使用引用（&）参数，这样函数可以修改实参
     * 
     * @return bool 分割成功返回true，失败返回false
     */
    bool SplitLargePage(pde_64 InPde, pde_64& OutPde ); 
    
    /**
     * @fn bool ReplacePageTable(cr3 cr3, void* replaceAlignAddr, pde_64* pde)
     * @brief 替换页表
     * 
     * 这是页表隔离的最后一步。
     * 创建一个新的页表结构，将被Hook的页面重新映射。
     * 
     * 【cr3寄存器】
     * 
     * cr3是x86/x64架构的控制寄存器之一，存储当前页表的物理地址。
     * cr3结构体包含：
     * - address_of_page_directory：页目录表的物理基址
     * - 以及一些标志位（如PCD、PWT等）
     * 
     * 【页表层级结构（x64）】
     * 
     * x64使用四级页表结构：
     * 
     *         虚拟地址
 *           |
 *           v
 *     +-----------------+
 *     |   PML4 (47-39)  |  ---> PML4E (Page Map Level 4 Entry)
 *     +-----------------+
 *           |
 *           v
 *     +-----------------+
 *     |  PDPT (38-30)   |  ---> PDPTE (Page Directory Pointer Table Entry)
 *     +-----------------+
 *           |
 *           v
 *     +-----------------+
 *     |   PD (29-21)    |  ---> PDE (Page Directory Entry)
 *     +-----------------+
 *           |
 *           v
 *     +-----------------+
 *     |   PT (20-12)    |  ---> PTE (Page Table Entry)
 *     +-----------------+
 *           |
 *           v
 *     +-----------------+
 *     |  物理页 (11-0)  |  ---> 实际物理内存
 *     +-----------------+
     * 
     * 【参数说明】
     * 
     * @param cr3 原始进程的cr3值（页表基址）
     * @param replaceAlignAddr 要替换的页面对齐地址
     * @param pde 指向新的页目录项（已修改的映射）
     * 
     * @return bool 替换成功返回true，失败返回false
     */
    bool ReplacePageTable(cr3 cr3, void* replaceAlignAddr, pde_64* pde);

public:
    /**
     * @fn ULONG64 VaToPa(void* va)
     * @brief 虚拟地址转物理地址
     * 
     * 使用MmGetPhysicalAddress内核函数完成转换。
     * 
     * 【虚拟地址 vs 物理地址】
     * 
     * - 虚拟地址（VA，Virtual Address）：程序使用的地址，每个进程独立
     * - 物理地址（PA，Physical Address）：实际硬件内存的地址
     * 
     * CPU通过MMU（内存管理单元）和页表将虚拟地址转换为物理地址。
     * 
     * @param va 虚拟地址
     * @return ULONG64 对应的物理地址
     */
    ULONG64 VaToPa(void* va);
    
    /**
     * @fn void* PaToVa(ULONG64 pa)
     * @brief 物理地址转虚拟地址
     * 
     * 使用MmGetVirtualForPhysical内核函数完成转换。
     * 注意：这个转换不一定总是成功，
     * 因为物理地址可能没有映射到当前进程的虚拟地址空间。
     * 
     * @param pa 物理地址
     * @return void* 对应的虚拟地址（如果存在），否则可能返回NULL或错误值
     */
    void* PaToVa(ULONG64 pa);
    
    /**
     * @fn void offPGE()
     * @brief 禁用页全局扩展（PGE）
     * 
     * 【PGE是什么？】
     * 
     * PGE（Page Global Enable）是CR4寄存器中的一个位。
     * 当启用时，页表项中的全局位（G bit）可以防止TLB被刷新。
     * 这是一种性能优化手段。
     * 
     * 【为什么需要禁用PGE？】
     * 
     * 当我们修改页表后，需要让CPU的TLB（Translation Lookaside Buffer）
     * 缓存失效，否则CPU可能继续使用旧的映射。
     * 
     * 但是，如果PGE启用，某些页表项不会被TLB刷新。
     * 为了确保我们的页表修改生效，需要：
     * 1. 暂时禁用PGE
     * 2. 刷新TLB
     * 3. 重新启用PGE（可选）
     * 
     * 【实现方式】
     * 
     * 使用KeIpiGenericCall在所有CPU核心上执行禁用PGE的操作。
     * 这是因为多核系统中，每个核心都有独立的TLB。
     */
    void offPGE();

    /**
     * @var mHookCount
     * @brief 当前已安装的Hook数量
     * 
     * UINT32是无符号32位整数（0到4294967295）。
     * 用于跟踪已安装的Hook数量，防止超出MAX_HOOK_COUNT限制。
     */
    UINT32 mHookCount = 0; 
    
    /**
     * @var mHookInfo
     * @brief 保存所有Hook信息的数组
     * 
     * 这是一个固定大小的数组，包含MAX_HOOK_COUNT个元素。
     * 每个元素是一个HOOK_INFO结构体，记录一个Hook的所有信息。
     * 
     * 【初始化】
     * 
     * = { 0 } 将整个数组初始化为0。
     * 在C/C++中，结构体/数组的初始化可以使用大括号语法：
     * - HOOK_INFO arr[10] = {0}; // 所有元素初始化为0
     * - HOOK_INFO arr[10] = {{0}}; // 第一种写法的另一种形式
     */
    HOOK_INFO mHookInfo[MAX_HOOK_COUNT] = { 0 };
    
    /**
     * @var mTrampLinePool
     * @brief Trampoline内存池
     * 
     * Trampoline（蹦床）是一块分配的内存，
     * 用于保存被Hook函数开头的原始指令。
     * 
     * 为什么需要Trampoline？
     * 
     * 假设原始函数开头是（20字节）：
     *     push rbp
     *     mov rbp, rsp
     *     sub rsp, 0x40
     *     mov eax, 1
     * 
     * Hook时我们覆盖了前12字节：
     *     jmp hook_func  (12字节)
     * 
     * 为了让原始函数能继续执行，我们需要：
     * 1. 把被覆盖的12字节保存到trampoline
     * 2. 在trampoline末尾加上跳回原始函数第13字节的指令
     * 
     * 之后调用原始函数时：
     *     调用方 --> trampoline --> 原始函数
     * 
     * 【内存池设计】
     * 
     * 我们使用内存池而不是每次单独分配：
     * - 优点：减少内存碎片，提高分配效率
     * - 缺点：需要预先计算总大小
     * 
     * 这里预分配了4个页面（16KB）作为内存池。
     */
    char* mTrampLinePool = 0;
    
    /**
     * @var mPoolUSED
     * @brief 内存池已使用的大小（字节）
     * 
     * UINT32类型，记录trampoline内存池已使用的字节数。
     * 每次分配trampoline时，这个值会增加。
     */
    UINT32 mPoolUSED = 0;
    
    /**
     * @var mInstance
     * @brief 指向HookManager单例实例的指针
     * 
     * static成员变量，属于类本身而不是类的实例。
     * 所有实例共享这一个指针。
     * 
     * 【初始化时机】
     * 
     * 在C++中，static成员变量需要在类外部单独定义和初始化。
     * 这通常在.cpp文件的全局作用域中完成。
     */
    static HookManager* mInstance;
};

/**
 * @struct PAGE_TABLE
 * @brief 页表结构体，用于封装页表相关的信息
 * 
 * 这个结构体将页表的各个层级组合在一起，
 * 方便在函数调用时传递和访问。
 * 
 * 【为什么要封装？】
 * 
 * 页表操作需要访问多个层级的表项（PML4、PDPT、PD、PTE）。
     * 直接传递四个指针很麻烦，封装成一个结构体更清晰。
 */
struct PAGE_TABLE
{
    /**
     * @struct Entry
     * @brief 包含各级页表项的指针
     */
    struct
    {
        /**
         * @brief 页表项指针（Page Table Entry）
         * 指向4KB页的映射，虚拟地址的第12-20位索引
         */
        pte_64* Pte;
        
        /**
         * @brief 页目录项指针（Page Directory Entry）
         * 指向页表本身，虚拟地址的第21-29位索引
         * 如果large_page标志为1，则直接映射2MB页
         */
        pde_64* Pde;
        
        /**
         * @brief 页目录指针表项指针（Page Directory Pointer Table Entry）
         * 指向页目录，虚拟地址的第30-38位索引
         * 如果large_page标志为1，则直接映射1GB页
         */
        pdpte_64* Pdpte;
        
        /**
         * @brief PML4表项指针（Page Map Level 4 Entry）
         * 指向页目录指针表，虚拟地址的最高位（39-47位）索引
         */
        pml4e_64* Pml4e;
    } Entry;
    
    /**
     * @brief 要查询的虚拟地址
     * 
     * 这个成员记录我们要查询哪个虚拟地址的页表映射。
     * 在GetPageTable函数中会使用这个值来计算各级索引。
     */
    void* VirtualAddress;
};

/**
 * 【HookManager类总结】
 * 
 * HookManager是整个Inline Hook系统的核心，提供了：
 * 1. InstallInlinehook：安装Hook
 * 2. RemoveInlinehook：卸载Hook
 * 3. 内部页表操作函数（IsolationPageTable、SplitLargePage、ReplacePageTable）
 * 4. 地址转换工具（VaToPa、PaToVa）
 * 
 * 【核心流程】
 * 
 * 安装Hook时：
 * 1. 获取目标进程
 * 2. 隔离页表（处理大页）
 * 3. 解析指令（确定覆盖范围）
 * 4. 分配trampoline
 * 5. 修改函数开头
 * 6. 保存Hook信息
 * 
 * 这个设计确保了Hook的正确性和可恢复性。
 */
