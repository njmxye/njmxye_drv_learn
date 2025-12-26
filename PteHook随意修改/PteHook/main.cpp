/**
 * @file main.cpp
 * @brief 驱动程序主入口点文件
 * 
 * 这个文件是Windows内核驱动程序的入口点，展示了如何使用HookManager框架
 * 来hook（拦截）系统内核函数NtOpenProcess和NtCreateFile。
 * 
 * 【驱动开发基础知识】
 * 
 * Windows内核驱动程序不同于普通的用户态应用程序，它运行在系统的内核模式下，
 * 具有更高的权限，可以直接访问硬件和操作系统核心数据结构。
 * 
 * 驱动程序的生命周期：
 * 1. DriverEntry：驱动加载时由系统调用，是驱动的入口点
 * 2. DriverUnload：驱动卸载时由系统调用，用于清理资源
 * 
 * 【内核调试技巧】
 * 
 * DbgPrintEx函数用于在内核中输出调试信息，类似用户态的printf。
 * 参数说明：
 * - 第一个参数102：调试端口类型，102表示DbgPrint
 * - 第二个参数0：调试级别，0表示总是输出
 * - 第三个参数：格式字符串
 * 
 * 注意：使用DbgPrintEx时，字符串末尾需要加\n换行符，否则在Windbg中看不到输出。
 * 
 * 【关于Inline Hook】
 * 
 * Inline Hook是一种运行时 patching 技术，通过修改目标函数开头的机器码，
 * 将程序执行流重定向到我们自定义的函数（钩子函数）。
 * 
 * 本示例中：
 * - FakeNtOpenProcess：伪造的NtOpenProcess函数，会在真函数调用前被触发
 * - g_oriNtOpenProcess：保存原始NtOpenProcess函数的地址，用于后续调用
 */

#include<ntifs.h>
#include<ntddk.h>
#include"./HookManager/HookManager.h"

/**
 * @typedef pfnNtOpenProcess
 * @brief NtOpenProcess函数的函数指针类型定义
 * 
 * NtOpenProcess是Windows内核函数，用于打开一个进程对象并获取其句柄。
 * 这个类型定义使得我们可以用统一的方式声明函数指针。
 * 
 * 【函数指针详解】
 * 
 * 函数指针本质上是一个变量，它存储的是函数的入口地址。
 * 声明语法：返回类型 (*指针名)(参数列表)
 * 
 * 参数说明：
 * - PHANDLE ProcessHandle：输出参数，返回打开的进程句柄
 * - ACCESS_MASK DesiredAccess：请求的访问权限，如PROCESS_ALL_ACCESS
 * - POBJECT_ATTRIBUTES ObjectAttributes：对象属性结构
 * - PCLIENT_ID ClientId：要打开的目标进程ID
 * 
 * ACCESS_MASK是一个32位整数，每一位代表不同的访问权限：
 * - 0x0001：PROCESS_TERMINATE 终止进程
 * - 0x0002：PROCESS_VM_READ 读取进程内存
 * - 0x0008：PROCESS_VM_WRITE 写入进程内存
 * - 0x0020：PROCESS_CREATE_PROCESS 创建进程
 * 等等...
 */
typedef NTSTATUS(NTAPI* pfnNtOpenProcess)(
    PHANDLE,                      // 输出：返回的进程句柄
    ACCESS_MASK,                  // 输入：请求的访问权限掩码
    POBJECT_ATTRIBUTES,           // 输入：对象属性（包含进程名或ID）
    PCLIENT_ID                    // 输入：客户端ID（包含进程PID）
);

/**
 * @typedef pfnNtCreateFile
 * @brief NtCreateFile函数的函数指针类型定义
 * 
 * NtCreateFile是Windows内核函数，用于创建或打开文件、目录、设备等对象。
 * 这是内核中最重要的文件操作函数之一。
 * 
 * 【参数详解】
 * 
 * - PHANDLE FileHandle：输出参数，返回文件句柄
 * - ACCESS_MASK DesiredAccess：访问权限，如FILE_READ_DATA、FILE_WRITE_DATA
 * - POBJECT_ATTRIBUTES ObjectAttributes：包含文件路径的对象属性
 * - PIO_STATUS_BLOCK IoStatusBlock：返回操作状态的结构
 * - PLARGE_INTEGER AllocationSize：文件的初始分配大小
 * - ULONG FileAttributes：文件属性（只读、隐藏、系统等）
 * - ULONG ShareAccess：共享访问模式（读/写/删除共享）
 * - ULONG CreateDisposition：创建方式（新建、打开、覆盖等）
 * - ULONG CreateOptions：创建选项（目录、流等）
 * - PVOID EaBuffer：扩展属性缓冲区
 * - ULONG EaLength：扩展属性长度
 */
typedef NTSTATUS(NTAPI* pfnNtCreateFile)(
    PHANDLE,                      // 输出：返回的文件句柄
    ACCESS_MASK,                  // 输入：请求的访问权限
    POBJECT_ATTRIBUTES,           // 输入：对象属性（包含文件路径）
    PIO_STATUS_BLOCK,             // 输出：IO状态块
    PLARGE_INTEGER,               // 输入（可选）：初始分配大小
    ULONG,                        // 输入：文件属性
    ULONG,                        // 输入：共享访问模式
    ULONG,                        // 输入：创建处置方式
    ULONG,                        // 输入：创建选项
    PVOID,                        // 输入（可选）：扩展属性缓冲区
    ULONG                         // 输入：扩展属性长度
);

/**
 * @var g_oriNtOpenProcess
 * @brief 保存原始NtOpenProcess函数的地址
 * 
 * 【全局变量详解】
 * 
 * 在内核驱动中使用全局变量需要谨慎，因为：
 * 1. 全局变量在所有进程上下文中共享
 * 2. 多核CPU上可能有并发访问问题
 * 3. 驱动卸载时需要清理这些指针
 * 
 * 这里我们保存原始函数的地址，这样在钩子函数中
 * 可以选择性地调用原始函数，实现"继续原操作"的效果。
 */
pfnNtOpenProcess g_oriNtOpenProcess;

/**
 * @var g_oriNtCreateFile
 * @brief 保存原始NtCreateFile函数的地址
 * 
 * 作用同g_oriNtOpenProcess，用于NtCreateFile函数的HOOK场景。
 */
pfnNtCreateFile g_oriNtCreateFile;

/**
 * @var g_pid
 * @brief 要HOOK的目标进程PID
 * 
 * 【进程标识符PID】
 * 
 * PID（Process Identifier）是Windows系统用来唯一标识一个进程的整数。
 * 每个运行中的进程都有一个唯一的PID（在进程生命周期内）。
 * 
 * 注意：
 * - PID可以被重复使用（进程终止后，系统可能将同一个PID分配给新进程）
 * - 使用PID时要注意进程可能已经终止
 * - 建议结合进程名验证，避免HOOK错进程
 * 
 * 这里硬编码为1808，实际项目中应该动态获取或通过通信接口传递。
 */
HANDLE g_pid = (HANDLE)1808;

/**
 * @fn NTSTATUS NTAPI FakeNtOpenProcess(...)
 * @brief 伪造的NtOpenProcess函数（钩子函数）
 * 
 * 这是我们自定义的NtOpenProcess函数，会在原始函数被调用前执行。
 * 这就是Inline Hook的核心：在目标函数开头插入跳转指令，
 * 让程序先执行我们的代码。
 * 
 * 【钩子函数的典型用途】
 * 
 * 1. 安全监控：记录所有打开进程的操作
 * 2. 访问控制：阻止特定进程被其他进程打开
 * 3. 参数修改：修改调用者传入的参数
 * 4. 权限提升：给调用者提升权限
 * 
 * 【NTSTATUS返回值】
 * 
 * Windows内核函数普遍返回NTSTATUS类型，这是一个32位状态码：
 * - STATUS_SUCCESS (0x00000000)：操作成功
 * - STATUS_ACCESS_DENIED (0xC0000022)：访问被拒绝
 * - STATUS_INVALID_PARAMETER (0xC000000D)：无效参数
 * - STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)：对象名未找到
 * 等等...
 * 
 * @param ProcessHandle 输出参数，返回打开的进程句柄
 * @param DesiredAccess 请求的访问权限
 * @param ObjectAttributes 对象属性结构
 * @param ClientId 客户端ID（目标进程ID）
 * @return NTSTATUS 状态码，成功返回STATUS_SUCCESS
 */
NTSTATUS NTAPI FakeNtOpenProcess(
    _Out_ PHANDLE ProcessHandle,              // 输出：返回的进程句柄
    _In_ ACCESS_MASK DesiredAccess,           // 输入：请求的访问权限
    _In_ POBJECT_ATTRIBUTES ObjectAttributes, // 输入：对象属性
    _In_opt_ PCLIENT_ID ClientId              // 输入（可选）：客户端ID
) {
    // 使用DbgPrintEx输出调试信息
    // 第一个参数102表示调试组件ID（用于过滤调试输出）
    // 第二个参数0表示调试级别（0表示总是输出）
    // 注意：一定要加\n，否则在Windbg中看不到输出
    DbgPrintEx(102, 0, "Fake NtOpenProcess \n");
    
    // 调用原始的NtOpenProcess函数
    // 这是钩子函数的典型模式：先执行自己的逻辑，然后调用原始函数
    return g_oriNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
};

/**
 * @fn NTSTATUS NTAPI FakeNtCreateFile(...)
 * @brief 伪造的NtCreateFile函数（钩子函数）
 * 
 * 用于拦截文件创建/打开操作。
 * 
 * 【文件操作hook的用途】
 * 
 * 1. 文件访问审计：记录所有文件读写操作
 * 2. 文件保护：阻止删除或修改特定文件
 * 3. 透明加密：读写文件时自动加解密
 * 4. 虚拟文件系统：拦截文件操作实现虚拟磁盘
 * 
 * @param FileHandle 输出参数，返回的文件句柄
 * @param DesiredAccess 访问权限
 * @param ObjectAttributes 对象属性
 * @param IoStatusBlock IO状态块
 * @param AllocationSize 初始分配大小
 * @param FileAttributes 文件属性
 * @param ShareAccess 共享访问模式
 * @param CreateDisposition 创建处置方式
 * @param CreateOptions 创建选项
 * @param EaBuffer 扩展属性缓冲区
 * @param EaLength 扩展属性长度
 * @return NTSTATUS 状态码
 */
NTSTATUS NTAPI FakeNtCreateFile(
    _Out_ PHANDLE FileHandle,                                    // 输出：返回的文件句柄
    _In_ ACCESS_MASK DesiredAccess,                              // 输入：请求的访问权限
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,                    // 输入：对象属性（包含文件路径）
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,                        // 输出：IO状态块
    _In_opt_ PLARGE_INTEGER AllocationSize,                      // 输入（可选）：初始分配大小
    _In_ ULONG FileAttributes,                                   // 输入：文件属性
    _In_ ULONG ShareAccess,                                      // 输入：共享访问模式
    _In_ ULONG CreateDisposition,                                // 输入：创建处置方式
    _In_ ULONG CreateOptions,                                    // 输入：创建选项
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,              // 输入（可选）：扩展属性缓冲区
    _In_ ULONG EaLength                                          // 输入：扩展属性长度
) {
    // 输出调试信息（注意：这个DbgPrint没有使用DbgPrintEx，更简单但无法过滤）
    DbgPrint("Fake Ntfakeopenfile"); 

    // 调用原始的NtCreateFile函数
    return g_oriNtCreateFile(
        FileHandle, 
        DesiredAccess, 
        ObjectAttributes, 
        IoStatusBlock, 
        AllocationSize, 
        FileAttributes, 
        ShareAccess, 
        CreateDisposition, 
        CreateOptions, 
        EaBuffer, 
        EaLength
    );
};

/**
 * @fn void DriverUnload(PDRIVER_OBJECT DriverObject)
 * @brief 驱动卸载函数
 * 
 * 当系统准备卸载驱动时，会调用这个函数。
 * 我们需要在这个函数中：
 * 1. 移除所有安装的hook
 * 2. 释放分配的内存
 * 3. 清理其他资源
 * 
 * 【驱动对象DRIVER_OBJECT】
 * 
 * DRIVER_OBJECT是Windows内核为每个驱动创建的核心数据结构，
 * 包含驱动的各种信息，如驱动名称、驱动程序例程等。
 * 
 * 重要的DriverObject成员：
 * - DriverUnload：指向驱动卸载函数
 * - DriverInit：指向驱动初始化函数
 * - MajorFunction：IRP主功能函数表
 * - DeviceObject：设备对象链表
 * 
 * 【UNREFERENCED_PARAMETER宏】
 * 
 * 这个宏的作用是"使用"参数以避免编译器警告（未使用的参数）。
 * 在Release版本中它什么都不做，在Debug版本中它可能检查参数是否有效。
 */
void DriverUnload(PDRIVER_OBJECT DriverObject) {
    // 告诉编译器我们"使用"了这个参数，避免警告
    UNREFERENCED_PARAMETER(DriverObject);
    
    // 移除HookManager安装的inline hook
    // 参数说明：
    // - g_pid：要移除hook的目标进程ID
    // - FakeNtOpenProcess：要移除的钩子函数地址
    HookManager::GetInstance()->RemoveInlinehook(g_pid, (void*)FakeNtOpenProcess);
    
    // 同样移除NtCreateFile的hook
    HookManager::GetInstance()->RemoveInlinehook(g_pid, (void*)FakeNtCreateFile);
}

/**
 * @fn NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
 * @brief 驱动入口点函数
 * 
 * 【DriverEntry详解】
 * 
 * DriverEntry是驱动程序的入口点，当驱动被加载时由系统调用。
 * 它类似于C/C++程序中的main函数。
 * 
 * 参数说明：
 * - PDRIVER_OBJECT DriverObject：指向系统创建的驱动对象
 * - PUNICODE_STRING RegisterPath：驱动在注册表中的服务键路径
 * 
 * 返回值：
 * - STATUS_SUCCESS：驱动加载成功
 * - 其他NTSTATUS值：驱动加载失败，系统会卸载驱动
 * 
 * 【驱动加载方式】
 * 
 * 1. 通过Service Control Manager（SCM）启动服务
 * 2. 通过inf文件安装驱动
 * 3. 通过工具如sc.exe或驅動精靈加载
 * 4. 通过内核调试器手动加载
 * 
 * 【驱动初始化步骤】
 * 
 * 典型的DriverEntry应该完成以下步骤：
 * 1. 创建设备对象
 * 2. 创建符号链接（用户态可访问）
 * 3. 注册IRP处理函数
 * 4. 初始化驱动特定的数据
 * 5. 设置DriverUnload函数
 */
EXTERN_C NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,      // 输入：驱动对象
    PUNICODE_STRING RegisterPath      // 输入：注册表路径（未使用）
) {
    // 使用参数避免警告
    UNREFERENCED_PARAMETER(RegisterPath);
    
    // 设置驱动卸载函数
    // 这是必需的，否则系统无法卸载驱动
    DriverObject->DriverUnload = DriverUnload;
    
    // 保存原始函数的地址
    // NtOpenProcess和NtCreateFile是内核函数的真正地址
    // 我们在编译时并不知道这些函数的实际地址，所以需要运行时获取
    g_oriNtOpenProcess = NtOpenProcess;
    g_oriNtCreateFile = NtCreateFile;
    
    // 输出调试信息
    DbgPrintEx(102, 0, "1 \n");
    
    // 安装Inline Hook
    // InstallInlinehook函数会：
    // 1. 修改目标进程（g_pid）中指定函数（g_oriNtOpenProcess）的开头几条指令
    // 2. 将这些指令替换为跳转到我们的钩子函数（FakeNtOpenProcess）
    // 3. 保存原始指令到trampoline（蹦床），以便后续恢复或调用
    // 
    // 参数说明：
    // - g_pid：要hook的目标进程ID
    // - &g_oriNtOpenProcess：原始函数地址的指针（因为函数地址本身是常量，我们传入指针让函数能修改它）
    // - FakeNtOpenProcess：我们的钩子函数地址
    // 
    // 返回值：true表示hook成功，false表示失败
    if (HookManager::GetInstance()->InstallInlinehook(g_pid, (void**)&g_oriNtOpenProcess, (void*)FakeNtOpenProcess)) {
        DbgPrintEx(102, 0, "success main \n");
    }
    
    // 注意：NtCreateFile的hook被注释掉了，可能是调试时暂时禁用
    // if (HookManager::GetInstance()->InstallInlinehook((void**)&g_oriNtCreateFile, (void*)FakeNtCreateFile)) {
    //     DbgPrintEx(102, 0, "success main");
    // }
    
    // 返回STATUS_SUCCESS表示驱动加载成功
    // 任何非STATUS_SUCCESS的值都会导致驱动加载失败
    return STATUS_SUCCESS; 
}
