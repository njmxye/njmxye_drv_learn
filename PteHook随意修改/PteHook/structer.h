/**
 * @file structer.h
 * @brief 定义Hook管理器的核心数据结构
 * 
 * 这个头文件定义了Inline Hook系统所需的基本数据结构和常量。
 * 这些结构体用于保存Hook信息、管理钩子状态。
 * 
 * 【设计模式说明】
 * 
 * 这里使用结构体来组织相关数据，类似于C++中类的简化版本。
 * 结构体在C中是一种将不同类型数据组合在一起的方式。
 * 
 * 【内存布局】
 * 
 * 结构体在内存中是连续存储的，类似于数组。
 * 例如：
 * struct Example {
 *     int a;      // 偏移0-3
 *     char b;     // 偏移4
 *     int c;      // 偏移8-11（因为对齐，可能有空洞）
 * };
 * 
 * 【#pragma once】
 * 
 * 这是一个预处理器指令，确保头文件只被包含一次。
 * 防止头文件被重复include导致的重复定义错误。
 * 等价于：
 * #ifndef STRUCTER_H
 * #define STRUCTER_H
 * ...代码...
 * #endif
 */

#pragma once

/**
 * @brief 包含Windows内核开发所需的基本类型定义
 * 
 * ntifs.h和ntddk.h是Windows内核开发的核心头文件：
 * 
 * - ntddk.h：内核模式驱动开发的基本定义
 *   包含NT内核的基础数据类型、函数原型、结构体定义
 *   适用于传统的WDM（Windows Driver Model）驱动
 * 
 * - ntifs.h：文件系统驱动和高级NT API的定义
 *   包含更多NT内核的内部API和文件系统相关的定义
 *   适用于文件系统过滤驱动、文件系统监控等场景
 * 
 * 这两个头文件都定义了NTDDK（NT Driver Development Kit）中的内容，
 * 包括NTSTATUS、PEPROCESS、HANDLE等核心类型。
 */
#include<ntifs.h>
#include<ntddk.h>

/**
 * @def MAX_HOOK_COUNT
 * @brief 最大Hook数量限制
 * 
 * 【宏定义详解】
 * 
 * #define是C语言的预处理指令，用于定义常量或宏。
 * 它在编译前进行文本替换，没有类型检查。
 * 
 * 这里定义为10，表示系统最多同时管理10个Hook。
 * 限制Hook数量的原因：
 * 
 * 1. 资源管理：每个Hook都需要分配内存来保存原始指令
 * 2. 稳定性考虑：过多的Hook可能影响系统稳定性
 * 3. 性能优化：减少遍历Hook列表的开销
 * 
 * 如果需要Hook更多函数，可以增加这个值，
 * 但要注意内存分配可能失败。
 */
#define MAX_HOOK_COUNT 10

/**
 * @struct _HOOK_INFO
 * @brief 保存单个Hook信息的结构体
 * 
 * 【结构体详解】
 * 
 * 这个结构体用于记录一次完整的Inline Hook操作所需的所有信息。
 * 当我们HOOK一个函数时，需要保存：
 * - 目标进程ID
 * - 原始函数地址
 * - 原始函数开头的机器码（用于恢复）
 * 
 * 【为什么要保存原始机器码？】
 * 
 * Inline Hook的本质是修改目标函数开头的几条指令。
 * 为了能够"卸载Hook"（RemoveInlinehook），
 * 我们必须保存被修改的原始指令。
 * 
 * 示例：
 * 假设原始函数开头是：
 *     mov eax, 0x12345678
 *     jmp 0x9ABCDEF0
 * 
 * 我们HOOK时可能改成：
 *     jmp hook_function
 *     (被覆盖的指令放到trampoline)
 * 
 * 卸载时需要把原始指令恢复回去。
 * 
 * 【为什么是14字节？】
 * 
 * 14字节是一个经验值，足够容纳：
 * - x64架构下的远跳转指令（12字节）
 * - 一些额外的空间用于对齐或保存更多指令
 * 
 * x64远跳转的机器码格式：
 *     mov rax, imm64      // 10字节
 *     jmp rax             // 2字节
 *     总计：12字节
 * 
 * 所以14字节足够保存x64架构的跳转指令。
 */
typedef struct _HOOK_INFO {
    /**
     * @brief 目标进程ID
     * 
     * HANDLE类型本质上是void*或void**，用于表示各种内核对象。
     * 在Windows中，PID（进程ID）通常是一个整数，但用HANDLE表示。
     * 
     * 每个进程都有一个唯一的PID，用于在系统中标识该进程。
     * 我们需要记录是对哪个进程进行了Hook，
     * 因为Inline Hook是进程相关的。
     */
    HANDLE pid;
    
    /**
     * @brief 保存原始函数的机器码
     * 
     * 【字节数组详解】
     * 
     * char originBytes[14]定义了一个14字节的字符数组。
     * char在C中通常用于存储单字节数据，这里用来存储机器码。
     * 
     * 为什么要用数组？
     * 因为我们不知道原始函数开头是什么指令，
     * 但我们需要保存它们（至少12-14字节）以便恢复。
     * 
     * 【机器码是什么？】
     * 
     * 计算机CPU执行的指令是二进制数据，称为机器码或Opcode。
     * 例如：
     * - 0x48 0xB8 可能是"mov rax, imm64"的一部分
     * - 0xFF 0xE0 可能是"jmp rax"
     * 
     * 不同CPU架构（x86、x64、ARM）的机器码完全不同。
     * 我们这里是x64架构，使用x64指令集。
     */
    char originBytes[14];
    
    /**
     * @brief 原始函数的地址
     * 
     * void*是通用指针类型，可以指向任何类型的数据。
     * 这里存储被Hook函数的起始地址。
     * 
     * 【为什么不用具体函数指针类型？】
     * 
     * 因为我们要Hook的函数类型不确定（可能是NtOpenProcess、
     * NtCreateFile，或任何其他函数），所以用void*通用指针。
     * 
     * 有了这个地址，我们可以：
     * 1. 读取原始机器码
     * 2. 修改目标函数
     * 3. 恢复原始函数
     */
    void* originAddr;
    
} HOOK_INFO, *PHOOK_INFO;

/**
 * 【总结：这个文件定义了Inline Hook系统的核心数据结构】
 * 
 * HOOK_INFO结构体是整个Hook系统的基本单元。
 * 每个HOOK_INFO实例记录了一个完整的Hook操作的所有信息。
 * HookManager类会使用HOOK_INFO数组来管理多个Hook。
 * 
 * 【内存布局示例】
 * 
 * 假设我们有2个Hook，内存中可能是这样的：
 * 
 * 地址         内容
 * 0x1000       [Hook1.pid = 1808]
 * 0x1008       [Hook1.originBytes = 0x48 0xB8 ... (14字节)]
 * 0x1012       [Hook1.originAddr = 0x7FF012345678]
 * 
 * 0x101A       [Hook2.pid = 2024]
 * 0x1022       [Hook2.originBytes = 0x55 0x48 0x89 ... (14字节)]
 * 0x1030       [Hook2.originAddr = 0x7FF0ABCDEF01]
 * 
 * 注意：实际内存对齐后，结构体大小可能大于各成员大小之和。
 */
