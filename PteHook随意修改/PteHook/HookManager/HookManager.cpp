/**
 * @file HookManager.cpp
 * @brief HookManager类实现文件 - Inline Hook核心实现
 * 
 * 这个文件包含了HookManager类的所有成员函数的实现。
 * 实现了Inline Hook的完整流程：安装Hook、卸载Hook、页表隔离等。
 * 
 * 【文件结构说明】
 * 
 * HookManager.cpp按功能分为以下几个部分：
 * 1. 预处理指令：头文件包含、编译器警告控制
 * 2. 静态变量定义：单例实例的初始化
 * 3. 公共接口实现：InstallInlinehook、RemoveInlinehook、GetInstance
 * 4. 私有方法实现：页表隔离、大页分割、页表替换
 * 5. 工具函数：地址转换、PGE禁用
 * 
 * 【内核编程特点】
 * 
 * 本文件展示了Windows内核编程的一些特点：
 * 
 * 1. 内存分配：
 *    - 使用ExAllocatePoolWithTag分配内核内存
 *    - NonPagedPool表示非分页内存（不会被换出到磁盘）
 *    - 池标签（Pool Tag）用于内存调试和追踪
 * 
 * 2. 进程上下文：
 *    - 使用KeStackAttachProcess切换到目标进程上下文
 *    - 只有在正确的进程上下文中才能访问该进程的内存
 * 
 * 3. IRQL（中断请求级别）：
 *    - 内核代码需要在适当的IRQL上运行
 *    - 某些操作只能在DISPATCH_LEVEL或更低级别执行
 * 
 * 4. 同步原语：
 *    - 使用自旋锁、APC等机制保证线程安全
 */

#include "HookManager.h"
#include<intrin.h>
#include"../Hde/hde64.h"
#include"../PageTable/PageTable.h"

/**
 * @brief HookManager单例实例的静态定义
 * 
 * 在C++中，类的静态成员变量必须在类外进行定义和初始化。
 * 这个定义告诉编译器mInstance这个变量确实存在，
 * 并在全局数据区为其分配存储空间。
 * 
 * 【初始化为nullptr】
 * 
 * nullptr是C++11引入的空指针常量，比NULL更安全：
 * - NULL在某些情况下可能被解释为整数0
 * - nullptr的类型是std::nullptr_t，保证是指针类型
 * 
 * 【为什么使用nullptr而不是0？】
 * 
 * 使用nullptr可以避免一些隐式类型转换的问题。
 * 例如：void func(int) 和 void func(char*) 同时存在时，
 * 调用func(NULL)会匹配int版本，而func(nullptr)会匹配char*版本。
 */
HookManager* HookManager::mInstance;

/**
 * 【编译器警告控制】
 * 
 * Windows内核开发中使用#pragma warning指令控制编译器警告。
 * 这些警告在内核代码中是可以接受的，或者有特殊的处理方式。
 */

/**
 * @brief 类型转换丢失数据的警告
 * 
 * 警告编号4838：类型转换导致数据丢失。
 * 例如：将64位指针转换为32位整数。
 * 
 * 在内核开发中，我们有时需要故意进行类型转换，
 * 并且我们确认不会丢失重要数据，所以禁用此警告。
 */
#pragma warning (disable : 4838)

/**
 * @brief 截断常量值的警告
 * 
 * 警告编号4309：将常量值截断为更小的类型。
 * 例如：将0x12345678截断为char类型。
 * 
 * 在编写机器码时，我们经常需要这样做，
 * 所以禁用此警告。
 */
#pragma warning (disable : 4309)

/**
 * @brief 类型转换丢失数据的警告（另一种形式）
 * 
 * 警告编号4244：类似4838，但针对浮点到整数的转换。
 */
#pragma warning (disable : 4244)

/**
 * @brief 比较不同大小的整数类型警告
 * 
 * 警告编号6328：比较两个不同大小的整数类型。
 * 例如：比较int和UINT32。
 * 
 * 在内核代码中，我们经常需要比较不同整数类型，
 * 所以禁用此警告。
 */
#pragma warning (disable : 6328)

/**
 * @brief 函数调用参数类型不匹配警告
 * 
 * 警告编号6066：函数调用中参数类型不匹配。
 */
#pragma warning (disable : 6066)

/**
 * @brief 函数已被标记为过时的警告
 * 
 * 警告编号4996：使用了一些被标记为过时的函数。
 * 内核代码中有些API是旧的但仍然有效，
 * 所以禁用此警告。
 */
#pragma warning (disable : 4996)

/**
 * @fn EXTERN_C VOID KeFlushEntireTb(BOOLEAN, BOOLEAN)
 * @brief 刷新整个TLB的函数声明
 * 
 * 【TLB是什么？】
 * 
 * TLB（Translation Lookaside Buffer）是CPU中的一个高速缓存，
 * 用于缓存虚拟地址到物理地址的转换结果（页表项）。
 * 
 * 当我们修改页表后，需要刷新TLB以确保CPU使用新的映射。
 * 
 * 【函数参数说明】
 * 
 * @param Invalid 是否使整个TLB无效
 *     - TRUE：使整个TLB无效
 *     FALSE：只使非全局页的TLB条目无效
 *     
 * @param AllProcessors 是否在所有处理器上执行
 *     - TRUE：在所有CPU核心上执行
 *     - FALSE：只在当前核心上执行
 * 
 * 【为什么需要这个函数？】
 * 
 * 在页表隔离过程中，我们修改了目标进程的页表。
 * 为了确保修改生效，需要刷新TLB。
 * 
 * 注意：这个函数是NToskrnl.exe导出的，但不是公开API，
 * 所以我们需要用EXTERN_C声明它。
 */
EXTERN_C VOID
KeFlushEntireTb(
    __in BOOLEAN Invalid,
    __in BOOLEAN AllProcessors
);

/**
 * @fn bool HookManager::InstallInlinehook(HANDLE pid, __inout void** originAddr, void* hookAddr)
 * @brief 安装Inline Hook的核心实现
 * 
 * 这个函数完成了Inline Hook安装的所有工作。
 * 让我们一步步分析其实现。
 * 
 * 【函数流程图】
 * 
 * 开始
 *   |
 *   v
 * 第一次调用？ ---- 是 ----> 分配trampoline内存池
 *   |否
 *   v
 * Hook数量已达上限？ ---- 是 ----> 返回false
 *   |否
 *   v
 * 获取目标进程PEPROCESS
 *   |
 *   v
 * 隔离页表（IsolationPageTable）
 *   |
 *   v
 * 解析目标函数指令（计算需要覆盖的字节数）
 *   |
 *   v
 * 构建trampoline代码
 *   |
 *   v
 * 保存原始字节和Hook信息
 *   |
 *   v
 * 修改目标函数开头（写入跳转指令）
 *   |
 *   v
 * 返回新函数地址（trampoline地址）
 *   |
 *   v
 * 结束
 * 
 * @param pid 目标进程ID
 * @param originAddr 原始函数地址的指针（输入输出）
 * @param hookAddr 钩子函数地址
 * @return bool 安装成功返回true，失败返回false
 */
bool HookManager::InstallInlinehook(HANDLE pid, __inout void** originAddr, void* hookAddr)
{
    /**
     * @brief 静态变量bFirst用于确保只初始化一次
     * 
     * 【静态局部变量】
     * 
     * static局部变量具有以下特点：
     * - 只在第一次函数调用时初始化
     * - 之后保持其值不变
     * - 存储在全局数据区，而非栈上
     * 
     * 为什么要用静态变量？
     * 
     * trampoline内存池只需要分配一次。
     * 使用静态变量确保多次调用InstallInlinehook时，
     * 不会重复分配内存池。
     */
    static bool bFirst = true;
    
    if (bFirst) {
        /**
         * @brief 分配trampoline内存池
         * 
         * 【ExAllocatePoolWithTag函数】
         * 
         * 这是Windows内核分配内存的核心函数之一。
         * 
         * 参数说明：
         * 
         * @param NonPagedPool 内存池类型
         *     - NonPagedPool：非分页内存池
         *     - PagedPool：分页内存池
         *     - NonPagedPoolNx：非分页内存池（不支持执行）
         *     
         *     为什么用NonPagedPool？
         *     因为trampoline中包含可执行代码，
         *     如果被换出到磁盘，CPU就无法执行它。
         * 
         * @param PAGE_SIZE * 4 分配大小
         *     - PAGE_SIZE通常是4096字节（4KB）
         *     - 这里分配4个页面，共16KB
         *     - 每个trampoline大约需要20-40字节
         *     - 所以16KB足够存储几百个trampoline
         * 
         * @param 'Jmp' 池标签（Pool Tag）
         *     - 4个字符，用于标识内存的来源
         *     - 在内核调试器中可以看到这个标签
         *     - 'Jmp' 代表这是Jump相关的内存
         * 
         * 【返回值】
         * 
         * - 成功：返回分配的内存地址
         * - 失败：返回NULL
         */
        mTrampLinePool = (char*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 4, 'Jmp'); 
        
        /**
         * @brief 分配失败检查
         * 
         * 在内核中，内存分配可能因为多种原因失败：
         * - 系统内存不足
         * - 内存池耗尽
         * - 驱动程序内存限制
         * 
         * 调试技巧：在Windbg中使用!pool命令查看内存池使用情况
         */
        if (!mTrampLinePool) {
            DbgPrintEx(102, 0, "内存申请失败了你妈的。");
            return false;
        }
        
        /**
         * @brief 初始化内存池
         * 
         * 【RtlZeroMemory函数】
         * 
         * 将指定内存区域清零。
         * 类似于C标准库的memset(ptr, 0, size)。
         * 
         * 参数说明：
         * - mTrampLinePool：要清零的内存地址
         * - PAGE_SIZE * 4：要清零的字节数
         * 
         * 【为什么要清零？】
         * 
         * - 确保内存池初始状态已知
         * - 避免使用未初始化的内存
         * - 有助于调试（区分已使用和未使用的内存）
         */
        RtlZeroMemory(mTrampLinePool, PAGE_SIZE * 4);   
        
        /**
         * @brief 初始化内存池使用量
         * 
         * mPoolUSED记录已使用的字节数。
         * 初始为0表示内存池完全空闲。
         */
        mPoolUSED = 0;
        
        /**
         * @brief 标记已初始化
         * 
         * bFirst设为false，后续调用不会再初始化内存池。
         */
        bFirst = false;
    }
    
    /**
     * @brief 检查Hook数量限制
     * 
     * 我们使用固定大小的数组mHookInfo[MAX_HOOK_COUNT]来保存Hook信息。
     * 超过这个数量会导致数组越界，可能导致蓝屏。
     * 
     * 【防御性编程】
     * 
     * 在进行任何操作之前，先检查前提条件是否满足。
     * 这是内核编程的重要原则。
     */
    if (mHookCount == MAX_HOOK_COUNT) {
        DbgPrintEx(102, 0, "操你妈hook这么多干嘛，不干了。");
        return false;
    }
    
    /**
     * @brief 获取目标进程对象
     * 
     * 【PsLookupProcessByProcessId函数】
     * 
     * 根据进程ID获取进程的EPROCESS结构体。
     * 
     * 参数说明：
     * - pid：要查询的进程ID
     * - &process：输出参数，返回PEPROCESS指针
     * 
     * 【NT_SUCCESS宏】
     * 
     * 检查NTSTATUS返回值是否表示成功。
     * NT_SUCCESS(status)在status >= 0时返回true。
     * 
     * 【PEPROCESS的引用计数】
     * 
     * PsLookupProcessByProcessId会增加PEPROCESS的引用计数。
     * 使用完后必须调用ObDereferenceObject减少引用计数，
     * 否则会导致进程对象永远无法被销毁（内存泄漏）。
     * 
     * 【进程上下文】
     * 
     * 每个进程有独立的虚拟地址空间。
     * 我们需要切换到目标进程的上下文才能访问其内存。
     * 这是通过KeStackAttachProcess完成的。
     */
    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) return false ;
    
    /**
     * @brief 隔离目标进程的页表
     * 
     * 如果页表隔离失败，我们无法继续安装Hook。
     * 因为直接修改共享页面会影响所有进程。
     * 
     * 【ObDereferenceObject】
     * 
     * 减少对象的引用计数。
     * 如果引用计数变为0，对象将被销毁。
     */
    if (!IsolationPageTable(process, *originAddr)) {
        ObDereferenceObject(process);
        return false;
    }

    /**
     * @brief 定义常量
     * 
     * 【trampolineByteCount】
     * 
     * trampoline代码的大小（20字节）。
     * 包含：
     * - 保存被覆盖指令的空间（uBreakBytes字节）
     * - 返回原始函数的代码（trampolineByteCount - uBreakBytes字节）
     * 
     * 【fnBreakByteLeast】
     * 
     * 最少需要覆盖的字节数（12字节）。
     * 
     * x64架构下，跳转到绝对地址需要：
     * - mov rax, imm64：10字节
     * - jmp rax：2字节
     * - 总计：12字节
     * 
     * 为什么需要最少12字节？
     * 因为我们的跳转指令正好是12字节，
     * 如果覆盖的指令少于12字节，会破坏函数的完整性。
     */
    const UINT32 trampLineByteCount = 20;
    const UINT32 fnBreakByteLeast = 12;

    /**
     * @brief 构建返回原始函数的trampoline代码
     * 
     * 【代码详解】
     * 
     * 这段代码实现了从trampoline跳回原始函数的功能：
     * 
     * 0x6A, 0x00                    push 0
     *                                ; 压栈0（作为返回地址的占位）
     * 
     * 0x3E C7 04 24 00 00 00 00     mov dword ptr ds:[rsp], 0
     *                                ; 修改栈顶的返回地址为0
     * 
     * 0x3E C7 44 24 04 00 00 00 00  mov dword ptr ds:[rsp+4], 0
     *                                ; 修改返回地址的高32位
     *                                ; 注意：x64下返回地址是64位的
     * 
     * 0xC3                          ret
     *                                ; 弹出返回地址并跳转
     *                                ; 实际上会跳转到(rsp)指向的地址
     * 
     * 【代码的目的】
     * 
     * 这段代码的作用是：跳转到指定的64位地址。
     * 技巧：
     * 1. 用push 0在栈上预留空间
     * 2. 用两mov指令写入64位目标地址
     * 3. 用ret指令跳转到目标地址
     * 
     * 【为什么不用jmp指令？】
     * 
     * 直接jmp 64位地址需要12字节（mov rax + jmp rax）。
     * 而用栈+ret的方法只需要20字节，但更灵活：
     * - 可以方便地在运行时修改目标地址
     * - 对于数据驱动的场景更方便
     * 
     * 【3E前缀】
     * 
     * 0x3E是x86指令的段超越前缀（DS段）。
     * 在64位模式下，段前缀通常被忽略，
     * 但HDE解码器可能会用到它。
     */
    char TrampLineCode[trampLineByteCount] = { 
        0x6A,0x00 ,0x3E ,0xC7 ,0x04 ,0x24 ,0x00 ,0x00 ,0x00 ,
        0x00 ,0x3E ,0xC7 ,0x44 ,0x24 ,0x04 ,0x00 ,0x00 ,0x00 ,0x00 ,0xC3 
    };

    /**
     * @brief 构建跳转到钩子函数的代码
     * 
     * 【AbsoluteJmpCode详解】
     * 
     * 这段代码实现了跳转到绝对地址（钩子函数）：
     * 
     * 0x48 0xB8 xx xx xx xx xx xx xx xx  mov rax, imm64
     *                                     ; 将钩子函数地址加载到rax寄存器
     *                                     ; 0x48 0xB8是mov rax, r/m64的机器码
     *                                     ; 后面8字节是立即数（钩子函数地址）
     * 
     * 0xFF 0xE0                             jmp rax
     *                                        ; 跳转到rax中的地址
     *                                        ; 0xFF 0xE0是jmp r/m64的机器码
     * 
     * 【为什么用rax作为中介？】
     * 
     * x64架构没有直接跳转到64位立即数的指令。
     * 必须先将地址加载到寄存器，再通过寄存器跳转。
     * 
     * 【12字节的来源】
     * 
     * - mov rax, imm64：2 + 8 = 10字节
     * - jmp rax：2字节
     * - 总计：12字节
     */
    char AbsoluteJmpCode[fnBreakByteLeast] = {
        0x48,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xFF,0xE0
    };

    /**
     * @brief 计算当前trampoline的位置
     * 
     * 【内存池使用】
     * 
     * mTrampLinePool是内存池的起始地址。
     * mPoolUSED是已使用的字节数。
     * 所以当前可用位置 = 起始地址 + 已使用大小。
     * 
     * 【示例】
     * 
     * 如果mPoolUSED = 100，那么curTrampLinePool指向
     * 内存池的第101个字节开始的位置。
     */
    char* curTrampLinePool = mTrampLinePool + mPoolUSED;
    
    /**
     * @brief 计算被Hook函数的起始地址
     * 
     * originAddr是一个指针，指向函数地址。
     * *originAddr解引用后得到实际的函数地址。
     * 
     * 【startJmpAddr】
     * 
     * 这是函数开头的实际地址。
     * 我们将修改这个地址处的机器码。
     */
    char* startJmpAddr = (char*)*originAddr;  
    
    /**
     * @brief 初始化指令长度计数和HDE结构
     * 
     * 【hde64s结构体】
     * 
     * HDE（Handy Disassembler Engine）是一个轻量级的反汇编引擎。
     * hde64s用于64位模式，存储反汇编结果。
     * 
     * 结构体主要成员：
     * - len：指令长度（1-15字节）
     * - opcode：指令操作码
     * - disp：位移值（用于跳转指令）
     * - imm：立即数值
     * - flags：各种标志位
     * 
     * 【为什么要反汇编？】
     * 
     * 我们需要知道目标函数开头有多少条指令。
     * 每条x86/x64指令长度不固定（1-15字节）。
     * 只有解析指令才能正确计算覆盖范围。
     * 
     * 【为什么不用硬编码长度？】
     * 
     * 简单的方法是直接覆盖12或14字节。
     * 但这样可能：
     * - 覆盖不完整（指令被截断）
     * - 覆盖过多（浪费空间）
     * 
     * 正确的做法是逐条解析指令，直到累积长度>=12字节。
     */
    UINT32 uBreakBytes = 0; 
    hde64s hdeinfo = { 0 };

    /**
     * @brief 循环解析指令，直到覆盖长度足够
     * 
     * 【循环条件】
     * 
     * while (uBreakBytes < fnBreakByteLeast)
     * 
     * 意思是：继续解析指令，直到覆盖的字节数>=12。
     * 
     * 【hde64_disasm函数】
     * 
     * 这是HDE引擎的反汇编函数。
     * 
     * 参数：
     * - ptr：指向要反汇编的内存地址
     * - hs：输出hde64s结构体
     * 
     * 返回值：
     * - 非0：反汇编成功
     * - 0：反汇编失败（无效指令）
     * 
     * 【解析过程示例】
     * 
     * 假设函数开头是：
     * 55                push rbp              (1字节)
     * 48 89 E5          mov rbp, rsp          (3字节)
     * 48 83 EC 20       sub rsp, 0x20         (4字节)
     * 48 B8 12 34...    mov rax, imm64        (10字节)
     * 
     * 解析过程：
     * - 第一次：len=1, uBreakBytes=1 (<12, 继续)
     * - 第二次：len=3, uBreakBytes=4 (<12, 继续)
     * - 第三次：len=4, uBreakBytes=8 (<12, 继续)
     * - 第四次：len=10, uBreakBytes=18 (>=12, 停止)
     * 
     * 最终uBreakBytes=18，我们需要覆盖18字节。
     */
    while (uBreakBytes < fnBreakByteLeast) {
        if (!hde64_disasm(startJmpAddr + uBreakBytes, &hdeinfo)) {
            DbgPrint("hde64_disasm error \n");
            return false;
        };
        uBreakBytes += hdeinfo.len;
    };

    /**
     * @brief 设置trampoline中的返回地址
     * 
     * 【计算返回地址】
     * 
     * 返回地址 = 被Hook函数地址 + 覆盖的字节数
     *         = startJmpAddr + uBreakBytes
     * 
     * 这是因为：被覆盖的指令之后，才是原始函数的剩余部分。
     * 
     * 【为什么分高低位？】
     * 
     * x64架构使用64位地址，但mov指令一次只能写入32位。
     * 所以需要分两次写入：
     * - 低32位：地址 & 0xFFFFFFFF
     * - 高32位：地址 >> 32
     * 
     * 【代码位置】
     * 
     * TrampLineCode数组中：
     * - 偏移6-9：低32位（mov dword ptr [rsp], imm32）
     * - 偏移15-18：高32位（mov dword ptr [rsp+4], imm32）
     * 
     * 【强制类型转换】
     * 
     * *(PUINT32*)&TrampLineCode[6]
     * 
     * 分解：
     * - &TrampLineCode[6]：取数组第7个元素的地址（char*类型）
     * - (PUINT32*)：将char*转换为UINT32*（4字节指针）
     * - *：解引用，得到UINT32引用
     * 
     * 这样就可以一次写入4字节。
     */
    *(PUINT32)&TrampLineCode[6] = (UINT32)((UINT64)(startJmpAddr + uBreakBytes) & 0xFFFFFFFF);
    *(PUINT32)&TrampLineCode[15] = (UINT32)((UINT64)(startJmpAddr + uBreakBytes)>>32 & 0xFFFFFFFF);

    /**
     * @brief 复制代码到trampoline
     * 
     * 【第一次memcpy】
     * 
     * memcpy(curTrampLinePool, startJmpAddr, uBreakBytes);
     * 
     * 功能：复制被覆盖的原始指令到trampoline。
     * 
     * 参数：
     * - 目的：curTrampLinePool（当前trampoline位置）
     * - 源：startJmpAddr（被Hook函数开头）
     * - 大小：uBreakBytes（覆盖的字节数）
     * 
     * 【第二次memcpy】
     * 
     * memcpy(curTrampLinePool + uBreakBytes, TrampLineCode, trampLineByteCount);
     * 
     * 功能：复制返回代码到trampoline末尾。
     * 
     * 这样，trampoline的内容就是：
     * [原始指令][返回代码]
     * 
     * 【memcpy vs RtlCopyMemory】
     * 
     * 在Windows内核中，建议使用RtlCopyMemory：
     * - 它是内核提供的函数，更稳定
     * - 可能在某些情况下有优化
     * - 但功能上与memcpy相同
     */
    memcpy(curTrampLinePool, startJmpAddr, uBreakBytes);
    memcpy(curTrampLinePool + uBreakBytes, TrampLineCode, trampLineByteCount);

    /**
     * @brief 保存Hook信息
     * 
     * 【查找空位】
     * 
     * 遍历mHookInfo数组，找到pid不为当前pid的元素。
     * 注意：这个逻辑可能有问题，因为它会跳过已存在的Hook。
     * 
     * 【正确的逻辑应该是】
     * 
     * 找到第一个空位（pid为0或等于当前pid）。
     * 
     * 【保存的信息】
     * 
     * - pid：目标进程ID
     * - originAddr：原始函数地址
     * - originBytes：原始机器码（用于恢复）
     * 
     * 【为什么保存这些信息？】
     * 
     * - pid：卸载Hook时需要知道是哪个进程的Hook
     * - originAddr：恢复时需要知道修改了哪里
     * - originBytes：恢复原始代码需要这些字节
     */
    for (int i = 0; i < MAX_HOOK_COUNT; i++) {
        if (mHookInfo[i].pid != pid) {
            mHookInfo[i].pid = pid; 
            mHookInfo[i].originAddr = startJmpAddr;
            memcpy(mHookInfo[i].originBytes, startJmpAddr, uBreakBytes);
            mHookCount++;
            break;
        }
    }

    /**
     * @brief 设置跳转目标地址
     * 
     * 【AbsoluteJmpCode数组】
     * 
     * AbsoluteJmpCode[2]开始是8字节的立即数空间。
     * 我们将钩子函数的地址写入这里。
     * 
     * 【指针转换解释】
     * 
     * *(void**)&AbsoluteJmpCode[2] = hookAddr;
     * 
     * 分解：
     * - &AbsoluteJmpCode[2]：数组第3个元素的地址（char*类型）
     * - (void**)：转换为void**类型（8字节指针）
     * - *：解引用，得到void*引用
     * - hookAddr：要写入的钩子函数地址
     * 
     * 结果：AbsoluteJmpCode[2-9]这8个字节变成了hookAddr的值。
     */
    *(void**)&AbsoluteJmpCode[2] = hookAddr; 
    
    /**
     * @brief 准备修改目标进程的内存
     * 
     * 【REPROTECT_CONTEXT结构体】
     * 
     * 这个结构体用于保存MDL相关的信息。
     * 我们需要：
     * 1. 创建MDL描述要修改的内存
     * 2. 锁定这些页面（防止被换出）
     * 3. 映射到内核地址空间
     * 4. 修改内存保护属性（可写）
     * 
     * 【为什么要这么麻烦？】
     * 
     * 直接修改用户进程内存会遇到以下问题：
     * - 页面可能不在物理内存中（需要触发页错误）
     * - 页面可能是只读的（需要修改保护属性）
     * - 不同进程有不同地址空间（需要切换上下文）
     * 
     * MDL提供了一种在内核中安全修改用户内存的方式。
     */
    REPROTECT_CONTEXT Content = { 0 };

    /**
     * @brief 切换到目标进程上下文
     * 
     * 【KeStackAttachProcess函数】
     * 
     * 将当前线程"附加"到目标进程。
     * 之后当前CPU使用的页表就是目标进程的页表。
     * 
     * 参数：
     * - process：目标进程的PEPROCESS
     * - apc：保存当前状态的APC状态结构
     * 
     * 【APC（Asynchronous Procedure Call）】
     * 
     * APC是Windows内核的一种异步调用机制。
     * KeStackAttachProcess使用APC来保存和恢复进程状态。
     * 
     * 【必须配对使用】
     * 
     * 每次KeStackAttachProcess后，必须调用KeUnstackDetachProcess。
     * 否则当前线程会一直停留在目标进程上下文，可能导致：
     * - 无法访问本进程的资源
     * - 系统不稳定
     */
    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);
    
    /**
     * @brief 锁定并映射要修改的内存
     * 
     * 【MmLockVaForWrite函数】
     * 
     * 这个函数完成以下工作：
     * 1. 创建MDL描述PAGE_SIZE字节的内存
     * 2. 锁定这些页面（加载到物理内存）
     * 3. 映射到内核地址空间
     * 4. 修改保护属性为可写
     * 
     * 参数：
     * - startJmpAddr：要修改的虚拟地址
     * - PAGE_SIZE：修改的大小（4KB）
     * - &Content：输出结构，保存MDL和映射地址
     * 
     * 【返回值】
     * 
     * - STATUS_SUCCESS：成功
     * - 其他：失败
     */
    if (!NT_SUCCESS(MmLockVaForWrite(startJmpAddr, PAGE_SIZE, &Content))) {
        return false;
    }

    /**
     * @brief 修改目标函数的机器码
     * 
     * 【RtlCopyMemory函数】
     * 
     * 将AbsoluteJmpCode（12字节）复制到startJmpAddr。
     * 这会覆盖目标函数开头的12字节：
     * 
     * 覆盖前：
     * [原始指令...][原始指令][原始指令]
     * 
     * 覆盖后：
     * [mov rax, hookAddr][jmp rax][被覆盖的指令在trampoline中]
     * 
     * 【执行流程】
     * 
     * 任何调用原始函数的代码现在会：
     * 1. 执行mov rax, hook_addr（跳转到钩子函数）
     * 2. 执行jmp rax
     * 3. 跳转到钩子函数执行
     * 
     * 钩子函数可以选择：
     * - 返回原始函数（调用trampoline）
     * - 做一些其他事情
     */
    RtlCopyMemory(Content.Lockedva, AbsoluteJmpCode, fnBreakByteLeast);
    
    /**
     * @brief 解除内存锁定
     * 
     * 【MmUnlockVaForWrite函数】
     * 
     * 完成以下工作：
     * 1. 解除内存映射
     * 2. 解锁页面（允许换出到磁盘）
     * 3. 释放MDL
     * 
     * 【为什么需要解锁？】
     * 
     * 锁定内存会占用物理内存，影响系统性能。
     * 操作完成后应该尽快解锁。
     */
    if (!NT_SUCCESS(MmUnlockVaForWrite(&Content))) {
        return false;
    }

    /**
     * @brief 恢复进程上下文
     * 
     * 【KeUnstackDetachProcess函数】
     * 
     * 撤销之前的KeStackAttachProcess。
     * 之后当前线程回到它原来的进程上下文。
     * 
     * 【必须配对】
     * 
     * 每个KeStackAttachProcess必须有对应的KeUnstackDetachProcess。
     * 建议使用try-finally确保执行：
     * 
     * KeStackAttachProcess(...);
     * __try {
     *     // 操作代码
     * }
     * __finally {
     *     KeUnstackDetachProcess(...);
     * }
     */
    KeUnstackDetachProcess(&apc);

    /**
     * @brief 更新调用者的函数地址
     * 
     * *originAddr = curTrampLinePool;
     * 
     * 将调用者传入的函数地址修改为trampoline地址。
     * 
     * 【为什么这样做？】
     * 
     * 调用者（比如main.cpp中的g_oriNtOpenProcess）
     * 需要知道调用原始函数时应该跳转到哪里。
     * 
     * 现在它应该跳转到trampoline而不是原始函数。
     * trampoline会：
     * 1. 执行被覆盖的原始指令
     * 2. 跳回原始函数的剩余部分
     * 
     * 【调用关系】
     * 
     * 调用方 --> FakeNtOpenProcess（钩子函数）
     * 
     * 在钩子函数中调用g_oriNtOpenProcess时：
     * - g_oriNtOpenProcess现在指向trampoline
     * - trampoline执行原始指令
     * - trampoline跳回原始函数第uBreakBytes字节处
     * - 原始函数继续执行
     * 
     * 这样就实现了"调用原始函数"的功能。
     */
    *originAddr = curTrampLinePool;
    
    /**
     * @brief 更新内存池使用量
     * 
     * mPoolUSED += (uBreakBytes + trampLineByteCount);
     * 
     * 每次分配trampoline后，需要更新已使用字节数。
     * 下次分配会从新的位置开始。
     * 
     * 【示例】
     * 
     * 第一次：mPoolUSED=0
     *   - 分配uBreakBytes + 20字节
     *   - mPoolUSED = 0 + 分配大小
     * 
     * 第二次：mPoolUSED = 上次的大小
     *   - 分配新的大小
     *   - mPoolUSED = 上次大小 + 本次分配大小
     */
    mPoolUSED += (uBreakBytes + trampLineByteCount);
    
    /**
     * @brief 释放进程对象引用
     * 
     * 【ObDereferenceObject】
     * 
     * 减少PEPROCESS的引用计数。
     * 如果计数变为0，内核会销毁这个对象。
     * 
     * 【必须调用】
     * 
     * PsLookupProcessByProcessId会增加引用计数。
     * 如果不调用ObDereferenceObject，会导致：
     * - 进程对象永远无法释放（内存泄漏）
     * - 系统资源耗尽
     */
    ObDereferenceObject(process);
    return true;
}

/**
 * @fn bool HookManager::RemoveInlinehook(HANDLE pid, void* hookAddr)
 * @brief 卸载Inline Hook
 * 
 * 这个函数应该：
 * 1. 找到对应的Hook信息
 * 2. 恢复原始函数的机器码
 * 3. 释放trampoline内存
 * 4. 从Hook列表中移除
 * 
 * 【当前实现】
 * 
 * 目前这个函数直接返回false，表示未实现。
 * 完整实现需要：
 * 
 * 1. 遍历mHookInfo数组找到匹配的Hook
 * 2. 切换到目标进程上下文
 * 3. 使用MDL锁定要恢复的内存
 * 4. 使用memcpy恢复originBytes到originAddr
 * 5. 清除mHookInfo中对应条目
 * 6. 减少mHookCount
 * 
 * @param pid 目标进程ID
 * @param hookAddr 钩子函数地址（用于查找）
 * @return bool 卸载成功返回true，失败返回false
 */
bool HookManager::RemoveInlinehook(HANDLE pid, void* hookAddr)
{
    /**
     * @brief 避免编译器警告
     * 
     * pid和hookAddr是函数参数，但当前函数未使用它们。
     * 使用UNREFERENCED_PARAMETER避免编译器警告。
     */
    pid;
    UNREFERENCED_PARAMETER(hookAddr);
    return false;
}

/**
 * @fn HookManager* HookManager::GetInstance()
 * @brief 获取HookManager单例实例
 * 
 * 【单例模式的实现】
 * 
 * 1. 检查mInstance是否为nullptr
 * 2. 如果是，分配内存并初始化
 * 3. 返回mInstance
 * 
 * 【线程安全问题】
 * 
     * 这个实现不是线程安全的！
     * 如果两个线程同时调用GetInstance，可能：
     * - 两次分配内存
     * - 竞争条件导致数据损坏
     * 
     * 【线程安全版本】
     * 
     * 可以使用Double-Checked Locking模式：
     * 
     * HookManager* HookManager::GetInstance() {
     *     if (mInstance == nullptr) {
     *         KLOCK_QUEUE_HANDLE handle;
     *         KeAcquireInStackQueuedSpinLock(&mLock, &handle);
     *         if (mInstance == nullptr) {
     *             mInstance = new HookManager();
     *         }
     *         KeReleaseInStackQueuedSpinLock(&handle);
     *     }
     *     return mInstance;
     * }
     * 
     * 【使用自旋锁】
     * 
     * 内核开发中常用自旋锁（Spin Lock）。
     * 自旋锁不会导致线程休眠，适用于中断上下文。
     * 
     * @return HookManager* 单例实例指针
 */
HookManager* HookManager::GetInstance()
{
    if (mInstance == nullptr) {
        /**
         * @brief 分配单例实例内存
         * 
         * 【ExAllocatePoolWithTag参数】
         * 
         * - NonPagedPool：因为HookManager可能在任何上下文中被访问
         * - sizeof(HookManager)：分配的大小
         * - 'test'：池标签（标识这个内存属于HookManager）
         * 
         * 【为什么不用new？】
         * 
         * 在内核开发中，通常使用ExAllocatePool而不是C++的new：
         * - new可能调用构造函数（在内核中可能有问题）
         * - ExAllocatePool更底层，完全可控
         * - 池标签有助于调试
         * 
         * 【返回值】
         * 
         * - 成功：返回分配的内存地址
         * - 失败：返回NULL
         * 
         * 【后续步骤】
         * 
         * 分配内存后，通常需要调用构造函数初始化对象。
         * 但由于我们没有显式构造函数，内存已经全是0，
         * 这正好符合成员变量初始化的要求。
         */
        mInstance = (HookManager*)ExAllocatePoolWithTag(NonPagedPool, sizeof(HookManager), 'test'); 
    }
    return mInstance;
}

/**
 * @fn bool HookManager::IsolationPageTable(PEPROCESS process, void* isolateioAddr)
 * @brief 隔离目标进程的页表
 * 
 * 这个函数实现页表隔离的核心逻辑。
 * 
 * 【页表隔离的目的】
 * 
 * 让被Hook的页面只在目标进程中可见修改，
     * 不影响其他进程。
     * 
     * 【处理流程】
     * 
     * 1. 切换到目标进程上下文
     * 2. 获取页表信息
     * 3. 检查页面大小（4KB/2MB/1GB）
     * 4. 如果是大页，进行分割
     * 5. 替换页表
     * 6. 恢复上下文
     * 
     * @param process 目标进程的PEPROCESS
     * @param isolateioAddr 要隔离的虚拟地址
     * @return bool 成功返回true，失败返回false
     */
bool HookManager::IsolationPageTable(PEPROCESS process, void* isolateioAddr)
{
    bool bRet = false;
    
    /**
     * @brief 切换到目标进程上下文
     * 
     * 只有在目标进程上下文中，才能正确访问该进程的页表。
     */
    KAPC_STATE apc; 
    KeStackAttachProcess(process, &apc);
    
    /**
     * @brief 初始化新的页目录项
     * 
     * 这个结构将保存分割后的大页信息。
     */
    pde_64 NewPde = { 0 };
    
    /**
     * @brief 计算页面对齐地址
     * 
     * 【PAGE_ALIGN宏】
     * 
     * 将虚拟地址向下对齐到页面边界。
     * 例如：
     * - PAGE_ALIGN(0x1234000) = 0x1234000（已经是页面对齐）
     * - PAGE_ALIGN(0x1234012) = 0x1234000（4KB对齐）
     * 
     * 页面大小通常是4KB，所以低12位被清零。
     * 
     * 【alignAddrr】
     * 
     * 存储页面对齐后的地址。
     * 页表操作需要页面对齐的地址。
     */
    void* alignAddrr;
    alignAddrr= PAGE_ALIGN(isolateioAddr);
    
    /**
     * @brief 初始化页表结构
     * 
     * PAGE_TABLE结构体包含各级页表项的指针。
     * GetPageTable函数会填充这个结构。
     */
    PAGE_TABLE page_table = { 0 };
    page_table.VirtualAddress = alignAddrr;
    
    /**
     * @brief 获取页表信息
     * 
     * GetPageTable函数解析虚拟地址的页表结构，
     * 填充page_table结构体的各个Entry指针。
     */
    GetPageTable(page_table);

    /**
     * @brief 主循环：检查和修改页表
     * 
     * 【循环目的】
     * 
     * 检查目标地址所在页面的属性：
     * - 是否是大页（2MB）
     * - 是否是巨页（1GB）
     * - 是否是普通页（4KB）
     * 
     * 【break】
     * 
     * 循环内部有break，所以只会执行一次迭代。
     * 这实际上是一个if-else结构。
     */
    while (true) {
        /**
         * @brief 检查是否是大页（2MB）
         * 
         * 【large_page标志】
         * 
         * PDE（页目录项）中的large_page位表示：
         * - 1：这个PDE描述的是一个2MB大页
         * - 0：这个PDE指向一个页表（4KB页）
         * 
         * 【处理方式】
         * 
         * 如果是大页，需要调用SplitLargePage分割成4KB页。
         * 这样我们才能独立修改单个4KB页面。
         */
        if (page_table.Entry.Pde->large_page) {
            DbgPrint("size is 2MB \n");
            bRet = SplitLargePage(*page_table.Entry.Pde, NewPde);
            if (!bRet) break;
        }
        /**
         * @brief 检查是否是巨页（1GB）
         * 
         * PDPTE（页目录指针表项）中的large_page位表示：
         * - 1：这个PDPTE描述的是一个1GB巨页
         * - 0：这个PDPTE指向一个页目录
         * 
         * 【当前处理】
         * 
         * 1GB巨页的处理更复杂，
         * 当前代码只是打印信息并退出。
         */
        else if (page_table.Entry.Pdpte->large_page) {
            DbgPrint("size is 1GB \n");
            break;
        }
        /**
         * @brief 普通页（4KB）
         * 
         * 不需要分割，直接使用现有页表。
         */
        else {
            DbgPrint("size is 4KB \n");
        }
        
        /**
         * @brief 读取当前进程的CR3
         * 
         * 【__readcr3函数】
         * 
         * 这是GCC/Clang的内联汇编函数，
         * 读取CPU的cr3寄存器。
         * 
         * cr3寄存器保存当前页表的物理地址。
         * 
         * 【cr3结构体】
         * 
         * cr3结构体包含：
         * - address_of_page_directory：页目录的物理页帧号
         * - 以及一些标志位
         * 
         * 注意：cr3中保存的是物理页帧号（PFN），
         * 需要乘以PAGE_SIZE才是实际的物理地址。
         */
        cr3 Cr3; 
        Cr3.flags = __readcr3();
        
        /**
         * @brief 替换页表
         * 
         * 创建一个新的页表结构，将被Hook的页面映射到新位置。
         */
        bRet = ReplacePageTable(Cr3, alignAddrr, &NewPde);

        /**
         * @brief 输出结果
         */
        if (bRet) {
            DbgPrint("isolation successfully \n");
        }
        else {
            DbgPrint("Failed isolation \n");
        }
        break;
    }

    /**
     * @brief 恢复原始进程上下文
     * 
     * 必须配对使用KeStackAttachProcess和KeUnstackDetachProcess。
     */
    KeUnstackDetachProcess(&apc);

    return bRet;
}

/**
 * @fn bool HookManager::SplitLargePage(pde_64 InPde, pde_64& OutPde)
 * @brief 将2MB大页分割成多个4KB小页
 * 
 * 【大页分割的原理】
 * 
 * 2MB大页实际上是一个连续的物理内存区域。
 * 我们需要将其分解为512个4KB小页。
 * 
 * 物理内存布局：
 * 
 * 分割前（2MB大页）：
 * 物理地址 0x1000000（2MB大小）
 * +------------------+
 * |                  |
 * |   2MB 连续区域   |
 * |                  |
 * +------------------+
 * 
 * 分割后（512个4KB小页）：
 * 物理地址 0x1000000
 * +--------+  ---> PTE[0] -> 0x1000000
 * |  PTE0  |
 * +--------+
 * |  PTE1  |  ---> PTE[1] -> 0x1001000
 * +--------+
 * |  ...   |
 * +--------+
 * | PTE511 |  ---> PTE[511] -> 0x101F000
 * +--------+
 * 
 * @param InPde 输入的大页页目录项
 * @param OutPde 输出的新页目录项（指向小页表）
 * @return bool 成功返回true，失败返回false
 */
bool HookManager::SplitLargePage(pde_64 InPde, pde_64& OutPde)
{
    /**
     * @brief 初始化物理地址结构
     * 
     * 【PHYSICAL_ADDRESS结构体】
     * 
     * 这是Windows内核定义的物理地址结构。
     * 包含QuadPart成员（64位整数）。
     * 
     * 【MaxAddrPA】
     * 
     * 指定可分配内存的最大物理地址。
     * MAXULONG64表示没有限制（整个物理地址空间）。
     * 
     * 【LowAddrPa】
     * 
     * 指定可分配内存的最小物理地址。
     * 0表示从0开始。
     * 
     * 【为什么需要指定范围？】
     * 
     * MmAllocateContiguousMemorySpecifyCache需要知道：
     * - 内存可以分配在哪里（地址范围）
     * - 这样可以避免分配到MMIO区域或其他保留区域
     */
    PHYSICAL_ADDRESS MaxAddrPA{ 0 }, LowAddrPa{ 0 }; 
    MaxAddrPA.QuadPart = MAXULONG64;
    LowAddrPa.QuadPart =  0 ;
    
    /**
     * @brief 分配页表内存
     * 
     * 【pt_entry_64* Pt】
     * 
     * 指向新分配的页表（512个PTE）。
     * 每个PTE是8字节，所以页表总共4KB。
     * 
     * 【StartPfn】
     * 
     * 大页的起始物理页帧号（Page Frame Number）。
     * PFN = 物理地址 / PAGE_SIZE。
     * 
     * 例如：如果大页物理地址是0x1000000，
     * 那么StartPfn = 0x1000000 / 0x1000 = 0x1000。
     * 
     * 【MmAllocateContiguousMemorySpecifyCache函数】
     * 
     * 分配一块连续的物理内存，并返回其内核虚拟地址。
     * 
     * 参数：
     * - PAGE_SIZE：分配大小（4KB）
     * - LowAddrPa：最小物理地址
     * - MaxAddrPA：最大物理地址
     * - LowAddrPa：对齐要求（同最小地址）
     * - MmCached：缓存类型（缓存内存）
     * 
     * 【连续内存】
     * 
     * 页表需要连续的物理内存。
     * 因为页表本身也通过页表来映射。
     * 
     * 【缓存类型】
     * 
     * - MmCached：缓存内存（普通DRAM）
     * - MmUncached：非缓存内存（MMIO）
     * - MmWriteCombine：写合并（某些显卡内存）
     * 
     * 页表使用MmCached。
     */
    pt_entry_64* Pt;
    uint64_t StartPfn  =  InPde.page_frame_number;

    Pt = (pt_entry_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPA, LowAddrPa, MmCached); 
    
    /**
     * @brief 分配失败检查
     */
    if (!Pt) {
        DbgPrint("failed to MmAllocateContiguousMemorySpecifyCache");
        return false;
    }

    /**
     * @brief 初始化页表项
     * 
     * 【循环说明】
     * 
     * for (int i = 0; i < 512; i++)
     * 
     * 512 = 2MB / 4KB
     * 一个2MB大页包含512个4KB小页。
     * 
     * 【初始化每个PTE】
     * 
     * - flags：从大页PDE复制标志位
     * - large_page：设置为0（现在是4KB页）
     * - page_frame_number：递增的页帧号
     * 
     * 【示例】
     * 
     * 如果大页从PFN 0x1000开始：
     * - PTE[0].pfn = 0x1000
     * - PTE[1].pfn = 0x1001
     * - ...
     * - PTE[511].pfn = 0x11FF
     * 
     * 这样，512个PTE覆盖了整个2MB区域。
     */
    for (int i = 0; i < 512; i++) {
        Pt[i].flags = InPde.flags;
        Pt[i].large_page = 0;
        Pt[i].page_frame_number = StartPfn + i;
    }

    /**
     * @brief 设置输出PDE
     * 
     * 新的PDE应该指向我们刚创建的页表。
     * 
     * 【VaToPa函数】
     * 
     * 将虚拟地址转换为物理地址。
     * 页表需要物理地址来设置PDE。
     * 
     * 【page_frame_number计算】
     * 
     * PFN = 物理地址 / PAGE_SIZE
     * = VaToPa(Pt) / 4096
     */
    OutPde.flags = InPde.flags;
    OutPde.large_page = 0; 
    OutPde.page_frame_number = VaToPa(Pt) / PAGE_SIZE;
    return true;
}

/**
 * @fn bool HookManager::ReplacePageTable(cr3 cr3, void* replaceAlignAddr, pde_64* pde)
 * @brief 替换页表以实现隔离
 * 
 * 这个函数创建一个新的页表结构，
     * 将被Hook的页面映射到新分配的内存。
     * 
     * 【核心思想】
     * 
     * 1. 复制现有的页表结构
     * 2. 修改被Hook页面对应的PTE
     * 3. 让PDE指向新的PTE
     * 4. 这样只有当前进程看到修改后的映射
     * 
     * 【页表复制策略】
     * 
     * 我们只需要复制涉及的页表：
     * - PML4表：复制整个表（512个条目）
     * - PDPT表：复制整个表（512个条目）
     * - PD表：复制整个表（512个条目）
     * - PT表：复制整个表（512个条目）
     * 
     * 每个表4KB，共需要16KB连续内存。
     * 
     * @param cr3 原始进程的cr3值
     * @param replaceAlignAddr 要替换的页面对齐地址
     * @param pde 指向新的页目录项
     * @return bool 成功返回true，失败返回false
     */
bool HookManager::ReplacePageTable(cr3 cr3, void* replaceAlignAddr, pde_64* pde)
{
    /**
     * @brief 声明各级页表的指针
     * 
     * 这些指针将指向新分配的页表。
     * 
     * - Va4kb：指向被Hook页面的副本
     * - Vapt：指向页表（Page Table）的副本
     * - VaPdt：指向页目录（Page Directory）的副本
     * - VaPdpt：指向页目录指针表（Page Directory Pointer Table）的副本
     */
    uint64_t *Va4kb, *Vapt, *VaPdt, *VaPdpt, *VaPml4t;
    
    /**
     * @brief 初始化物理地址范围
     */
    PHYSICAL_ADDRESS MaxAddrPA{ 0 }, LowAddrPa{ 0 };
    MaxAddrPA.QuadPart = MAXULONG64;
    LowAddrPa.QuadPart = 0;
    
    /**
     * @brief 页表结构
     */
    PAGE_TABLE pagetable = { 0 };

    /**
     * @brief 分配4个页表
     * 
     * 每个页表4KB，共16KB。
     * 
     * 【分配失败检查】
     * 
     * 如果任何一个分配失败，需要释放已分配的内存。
     * 这里使用goto模式进行错误处理。
     */
    Va4kb = (uint64_t*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPA, LowAddrPa, MmCached);
    Vapt = (uint64_t*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPA, LowAddrPa, MmCached);
    VaPdt = (uint64_t*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPA, LowAddrPa, MmCached);
    VaPdpt = (uint64_t*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPA, LowAddrPa, MmCached);

    /**
     * @brief 获取原始PML4表
     * 
     * cr3.address_of_page_directory是PML4表的物理页帧号。
     * 乘以PAGE_SIZE得到物理地址。
     * PaToVa转换为虚拟地址。
     * 
     * 【注意】
     * 
     * 这里有个问题：
     * cr3.address_of_page_directory实际上应该是PML4的PFN。
     * 命名可能有点混淆。
     */
    VaPml4t = (uint64_t*)PaToVa(cr3.address_of_page_directory * PAGE_SIZE);

    /**
     * @brief 检查分配结果
     */
    if (!Va4kb || !Vapt || !VaPdt || !VaPdpt) {
        DbgPrint(" Apply mm failed \n");
        return false;
    }

    /**
     * @brief 获取当前页表信息
     */
    pagetable.VirtualAddress = replaceAlignAddr;
    GetPageTable(pagetable);

    /**
     * @brief 计算虚拟地址索引
     * 
     * x64虚拟地址48位（目前实际使用），
     * 分为4个9位的索引：
     * 
     * 63-48:  符号扩展（必须为1或0）
     * 47-39:  PML4索引
     * 38-30:  PDPT索引
     * 29-21:  PD索引
     * 20-12:  PT索引
     * 11-0:   页内偏移
     * 
     * 【计算公式】
     * 
     * index = (虚拟地址 >> 移位位数) & 0x1FF
     * 
     * 例如：虚拟地址0x7FF012345678
     * - PML4索引 = (addr >> 39) & 0x1FF
     * - PDPT索引 = (addr >> 30) & 0x1FF
     * - PD索引 = (addr >> 21) & 0x1FF
     * - PT索引 = (addr >> 12) & 0x1FF
     */
    UINT64 pml4eindex = ((UINT64)replaceAlignAddr & 0xFF8000000000) >> 39;
    UINT64 pdpteindex = ((UINT64)replaceAlignAddr & 0x7FC0000000) >> 30;
    UINT64 pdeindex = ((UINT64)replaceAlignAddr & 0x3FE00000) >> 21;
    UINT64 pteindex = ((UINT64)replaceAlignAddr & 0x1FF000) >> 12;
     
    /**
     * @brief 处理大页情况
     * 
     * 如果原始页面是2MB大页，
     * 我们需要直接使用分割后的页表。
     */
    if (pagetable.Entry.Pde->large_page) {
        MmFreeContiguousMemorySpecifyCache(Vapt, PAGE_SIZE, MmCached);
        Vapt = (uint64_t*)PaToVa(pde->page_frame_number * PAGE_SIZE);
    }
    else {
        /**
         * @brief 复制页表
         * 
         * 从原始页表中复制512个PTE。
         * 
         * 【pagetable.Entry.Pte - pteindex】
         * 
         * PTE数组可能不是从页边界开始的。
         * 我们需要找到页表的开头。
         * 
         * 例如：如果pteindex=100，
         * 我们要复制PTE[0]到PTE[511]，
         * 即从(pte - 100)开始的512个条目。
         */
        memcpy(Vapt, pagetable.Entry.Pte - pteindex, PAGE_SIZE);
    }
    
    /**
     * @brief 复制其他页表
     */
    memcpy(Va4kb, replaceAlignAddr, PAGE_SIZE);
    memcpy(VaPdt, pagetable.Entry.Pde - pdeindex, PAGE_SIZE);
    memcpy(VaPdpt, pagetable.Entry.Pdpte - pdpteindex, PAGE_SIZE);

    /**
     * @brief 修改页表项
     * 
     * 修改PTE，让它指向Va4kb（被Hook页面的副本）。
     */
    auto pReplacePte = (pte_64*) &Vapt[pteindex];
    pReplacePte->page_frame_number = VaToPa(Va4kb) / PAGE_SIZE;

    /**
     * @brief 修改PDE
     * 
     * 修改PDE，让它指向新的页表（Vapt）。
     * 注意：large_page必须为0，表示是小页。
     */
    auto pReplacePde = (pde_64*)&VaPdt[pdeindex];
    pReplacePde->page_frame_number = VaToPa(Vapt) / PAGE_SIZE;
    pReplacePde->large_page = 0;

    /**
     * @brief 修改PDPTE
     */
    auto pReplacePdpte = (pdpte_64*)&VaPdpt[pdpteindex];
    pReplacePdpte->page_frame_number = VaToPa(VaPdt) / PAGE_SIZE;

    /**
     * @brief 修改PML4E
     */
    auto pReplacePml4e = (pml4e_64*)&VaPml4t[pml4eindex];
    pReplacePml4e->page_frame_number = VaToPa(VaPdpt) / PAGE_SIZE;

    /**
     * @brief 刷新TLB并禁用PGE
     * 
     * 【KeFlushEntireTb】
     * 
     * 刷新整个TLB。
     * 参数1=true表示使所有条目无效。
     * 参数2=false表示只在当前CPU执行。
     * 
     * 【offPGE】
     * 
     * 禁用页全局扩展，确保TLB刷新生效。
     */
    KeFlushEntireTb(true, false);
    offPGE();
    return true;
}

/**
 * @fn ULONG64 HookManager::VaToPa(void* va)
 * @brief 虚拟地址转物理地址
 * 
 * 【MmGetPhysicalAddress函数】
 * 
     * 这是Windows内核提供的函数，
     * 用于将虚拟地址转换为物理地址。
     * 
     * 注意：这个函数只能转换已映射的虚拟地址。
     * 
     * @param va 虚拟地址
     * @return ULONG64 物理地址（64位）
 */
ULONG64 HookManager::VaToPa(void* va)
{
    PHYSICAL_ADDRESS pa; 
    pa = MmGetPhysicalAddress(va);
    return pa.QuadPart;
}

/**
 * @fn void* HookManager::PaToVa(ULONG64 pa)
 * @brief 物理地址转虚拟地址
 * 
 * 【MmGetVirtualForPhysical函数】
 * 
     * 这是Windows内核提供的函数，
     * 用于将物理地址转换为虚拟地址。
     * 
     * 【注意事项】
     * 
     * 1. 物理地址可能没有映射到当前进程
     * 2. 转换可能失败，返回NULL
     * 3. 即使返回非NULL，也可能不是预期的地址
     * 
     * @param pa 物理地址
     * @return void* 虚拟地址（如果存在）
 */
void* HookManager::PaToVa(ULONG64 pa)
{
    PHYSICAL_ADDRESS Pa{ 0 };
    Pa.QuadPart = pa;
    
    return MmGetVirtualForPhysical(Pa);
}

/**
 * @fn ULONG_PTR KipiBroadcastWorker(ULONG_PTR Argument)
 * @brief IPI广播工作函数
 * 
 * 这个函数将在所有CPU核心上执行。
 * 
 * 【KipiBroadcastWorker】
 * 
 * 这是KeIpiGenericCall指定的回调函数。
 * 它在每个CPU核心上被调用。
 * 
 * 【功能】
 * 
 * 禁用CR4寄存器的PGE位。
 * 
 * 【CR4寄存器】
 * 
     * CR4是x86/x64的控制寄存器4，
     * 包含多个控制位：
     * - bit 7 (PGE)：页全局扩展启用
     * - bit 0 (PE)：保护模式启用
     * - bit 1 (PG)：分页启用
     * - ...
     * 
     * @param Argument 传递的参数（未使用）
     * @return ULONG_PTR 返回值（未使用）
     */
ULONG_PTR KipiBroadcastWorker(
    ULONG_PTR Argument
)
{
    /**
     * @brief 避免参数未使用警告
     */
    Argument;
    
    /**
     * @brief 提升IRQL到DPC级别
     * 
     * 【IRQL】
     * 
     * IRQL（Interrupt Request Level）是Windows内核的中断级别机制。
     * 不同IRQL有不同的含义和限制：
     * - PASSIVE_LEVEL：最低级别，可任意调度
     * - APC_LEVEL：异步过程调用级别
     * - DISPATCH_LEVEL：调度级别，不能等待
     * - DIRQL：设备中断级别
     * 
     * 【KeRaiseIrqlToDpcLevel】
     * 
     * 将IRQL提升到DISPATCH_LEVEL。
     * 
     * 【为什么要提升IRQL？】
     * 
     * 修改CR4寄存器是敏感操作。
     * 提升IRQL可以：
     * - 防止被中断处理程序打断
     * - 防止线程切换
     * 
     * 【返回值】
     * 
     * 返回原始IRQL，稍后需要恢复。
     */
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    
    /**
     * @brief 屏蔽中断
     * 
     * 【_disable函数】
     * 
     * 这是编译器内联函数，
     * 对应CPU的CLI指令。
     * 
     * 功能：禁止CPU响应可屏蔽中断。
     * 
     * 【为什么要屏蔽中断？】
     * 
     * 在多核系统中，其他CPU可能正在执行。
     * 我们需要确保：
     * 1. 不会有中断处理程序干扰
     * 2. TLB刷新操作原子完成
     * 
     * 【注意】
     * 
     * 屏蔽中断时间不能太长，
     * 否则会影响系统响应性。
     */
    _disable();  
    
    /**
     * @brief 读取CR4并禁用PGE
     * 
     * 【__readcr4函数】
     * 
     * 读取CPU的CR4寄存器。
     * 
     * 【PGE位】
     * 
     * CR4的第7位（0x80）是PGE位。
     * 
     * cr4 &= 0xffffffffffffff7f;
     * 
     * 这个操作将bit 7清零：
     * - 0x7F = 0b01111111
     * - 与操作后，bit 7变为0
     * 
     * 【为什么要禁用PGE？】
     * 
     * PGE（Page Global Enable）使得标记为"全局"的页表项
     * 在切换CR3时不会从TLB中刷新。
     * 
     * 为了确保页表修改生效，我们需要：
     * 1. 禁用PGE
     * 2. 刷新TLB
     * 3. （可选）重新启用PGE
     */
    ULONG64 cr4 = __readcr4();
    cr4 &= 0xffffffffffffff7f; 
    __writecr4(cr4);
    
    /**
     * @brief 恢复中断
     * 
     * 【_enable函数】
     * 
     * 对应CPU的STI指令。
     * 重新允许可屏蔽中断。
     */
    _enable();

    /**
     * @brief 恢复IRQL
     * 
     * 【KeLowerIrql函数】
     * 
     * 将IRQL恢复到之前的级别。
     * 
     * 【为什么必须恢复？】
     * 
     * 如果IRQL保持高位：
     * - 系统响应变慢
     * - 可能导致死锁
     * - 用户体验变差
     */
    KeLowerIrql(irql);
    return 0;  
}

/**
 * @fn void HookManager::offPGE()
 * @brief 禁用页全局扩展（PGE）
 * 
 * 这个函数在所有CPU核心上执行KipiBroadcastWorker，
 * 以确保所有核心的PGE都被禁用。
 * 
 * 【KeIpiGenericCall函数】
 * 
     * 这是Windows内核提供的函数，
     * 用于在所有CPU核心上执行一个函数。
     * 
     * 参数：
     * - KipiBroadcastWorker：要执行的函数
     * - NULL：传递给函数的参数
     * 
     * 【IPI】
     * 
     * IPI（Inter-Processor Interrupt）是处理器间中断。
     * 一个CPU核心可以发送中断到其他核心，
     * 强制它们执行指定代码。
     * 
     * 【为什么需要IPI？】
     * 
     * 多核系统中，每个核心有独立的TLB。
     * 我们修改页表后，需要刷新所有核心的TLB。
     * KeIpiGenericCall确保KipiBroadcastWorker在所有核心上运行。
 */
void HookManager::offPGE()
{
    KeIpiGenericCall(KipiBroadcastWorker, NULL);
}

/**
 * 【HookManager.cpp总结】
 * 
 * 这个文件实现了完整的Inline Hook系统，核心流程如下：
 * 
 * 1. InstallInlinehook安装Hook：
 *    - 分配trampoline内存池
 *    - 解析目标函数指令
 *    - 构建trampoline代码
 *    - 修改目标函数开头
 * 
 * 2. IsolationPageTable实现页表隔离：
 *    - 检测页面大小
 *    - 大页分割
 *    - 替换页表
 * 
 * 3. offPGE确保TLB刷新生效
 * 
 * 这个实现的关键技术点：
 * - 使用MDL安全修改内存
 * - 使用KeStackAttachProcess切换进程上下文
 * - 使用KeIpiGenericCall在所有CPU上执行
 * - 大页分割处理2MB/1GB页面
 */
