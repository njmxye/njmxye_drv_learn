#pragma once
#include"../HookManager/HookManager.h"

/**
 * @file PageTable.h
 * @brief 页表操作接口头文件
 * 
 * 本文件定义了页表操作的核心接口，用于获取和操作x86-64架构下的
 * 四级页表结构（PML4、PDPT、PD、PT），实现页表条目的直接访问和修改。
 * 
 * @section paging_overview x86-64分页机制概述
 * 
 * Windows 64位系统采用4级分页结构（IA-32e分页模式）：
 * 
 * 1. PML4（Page Map Level 4）：页映射级别4，也称为PML4E表
 *    - 每个进程有一个PML4表
 *    - 由CR3寄存器指向（PML4物理基地址）
 *    - 512个条目，每个条目指向一个PDPT
 *    - 虚拟地址中用于索引的位：39-47（共9位）
 * 
 * 2. PDPT（Page Directory Pointer Table）：页目录指针表，也称为PDPTE表
 *    - 每个PML4条目指向一个PDPT
 *    - 512个条目，每个条目指向一个页目录
 *    - 虚拟地址中用于索引的位：30-38（共9位）
 * 
 * 3. PD（Page Directory）：页目录，也称为PDE表
 *    - 每个PDPT条目指向一个PD
 *    - 512个条目，每个条目指向一个页表
 *    - 虚拟地址中用于索引的位：21-29（共9位）
 * 
 * 4. PT（Page Table）：页表，也称为PTE表
 *    - 每个PD条目指向一个PT
 *    - 512个条目，每个条目指向一个4KB物理页
 *    - 虚拟地址中用于索引的位：12-20（共9位）
 * 
 * 虚拟地址结构（48位有效）：
 * | 63-48 | 47-39 | 38-30 | 29-21 | 20-12 | 11-0 |
 * |-------|-------|-------|-------|-------|------|
 * |  Sign | PML4  | PDPT  |  PD   |   PT  | Offset|
 * 
 * 页面大小选项：
 * - 4KB页面：使用所有四级表
 * - 2MB页面：PD条目直接指向2MB页面（PDE的PS位为1）
 * - 1GB页面：PDPT条目直接指向1GB页面（PDPTE的PS位为1）
 */


/**
 * @brief 获取页表信息
 * 
 * 此函数根据传入的PAGE_TABLE结构中的VirtualAddress字段，
 * 计算并填充该虚拟地址对应的各级页表条目的指针。
 * 
 * @param table 页表结构引用，调用者需要预先设置VirtualAddress字段
 *             函数返回时将填充Pte、Pde、Pdpte、Pml4e指针
 * 
 * @return bool 成功返回true，失败返回false
 *         失败的主要原因包括：
 *         - 无法获取PTE基地址（GetPteBase返回nullptr）
 *         - 页表计算过程中出现异常
 * 
 * @note 计算过程：
 *       1. 获取PTE基地址（内核中PTE结构的起始虚拟地址）
 *       2. 根据PTE基地址推导PDE、PDPTE、PML4E的基地址
 *       3. 使用虚拟地址的相应位作为索引，计算各级条目的地址
 * 
 * @note 虚拟地址到页表条目的转换公式：
 *       PTE地址 = PTE_BASE + (VA >> 12) * 8
 *       PDE地址 = PDE_BASE + (VA >> 21) * 8
 *       PDPTE地址 = PDPTE_BASE + (VA >> 30) * 8
 *       PML4E地址 = PML4E_BASE + (VA >> 39) * 8
 * 
 * @par 使用示例：
 * @code
 * PAGE_TABLE table = {0};
 * table.VirtualAddress = TargetFunction;
 * 
 * if (GetPageTable(table)) {
 *     // 现在可以访问各级页表条目
 *     DbgPrint("PTE: %p\n", table.Entry.Pte);
 *     DbgPrint("PDE: %p\n", table.Entry.Pde);
 *     DbgPrint("PDPTE: %p\n", table.Entry.Pdpte);
 *     DbgPrint("PML4E: %p\n", table.Entry.Pml4e);
 *     
 *     // 读取PTE的值
 *     pte_64 pte = *table.Entry.Pte;
 *     DbgPrint("PTE value: %llx\n", pte.flags);
 * }
 * @endcode
 * 
 * @see GetPteBase 用于获取PTE基地址
 * @see PAGE_TABLE 结构体定义
 */
bool GetPageTable(PAGE_TABLE& table);

/**
 * @brief 获取内核PTE结构的基地址
 * 
 * 此函数通过读取CR3寄存器并遍历PML4表，
 * 找到内核空间PTE结构（NonPagedPool中的PTE区域）的虚拟基地址。
 * 
 * @return void* 成功返回PTE基地址（内核模式虚拟地址），失败返回nullptr
 * 
 * @note 这个函数的核心原理：
 *       1. 读取当前进程的CR3（页目录基地址）
 *       2. 将CR3转换为虚拟地址（通过MmGetVirtualForPhysical）
 *       3. 遍历PML4表，找到指向自身的条目（Self-referential PML4E）
 *       4. 根据找到的条目位置计算PTE基地址
 * 
 * @note Self-referential PML4E：
 *       在x86-64分页中，每个进程的PML4表都包含一个特殊条目，
 *       该条目指向PML4表自身。这个条目用于实现内核空间的自映射。
 *       对于典型的Windows系统，这个条目位于索引508（0x1F8）。
 * 
 * @note 为什么要获取PTE基地址：
 *       - 内核中的PTE结构位于NonPagedPool，需要知道其基地址
 *       - PTE基地址是计算任意虚拟地址对应的PTE地址的基础
 *       - 用于页表隔离和页面属性修改等操作
 * 
 * @warning 这个函数依赖于特定的Windows内核布局，可能在不同版本间有差异
 * 
 * @par 内部实现原理：
 * @code
 * // 1. 读取CR3
 * CR3.address_of_page_directory = __readcr3();
 * 
 * // 2. 获取CR3的虚拟地址
 * cr3_pa.QuadPart = CR3.address_of_page_directory * PAGE_SIZE;
 * PULONG64 cr3_va = (PULONG64)MmGetVirtualForPhysical(cr3_pa);
 * 
 * // 3. 遍历PML4表查找自引用条目
 * // 自引用条目的物理地址等于CR3的物理地址
 * while ((*cr3_va & 0x000FFFFFFFFFF000) != cr3_pa.QuadPart) {
 *     cr3_va++;
 * }
 * 
 * // 4. 计算PTE基地址
 * // 自引用条目在索引n，则PTE基地址 = (n << 39) | 0xFFFF000000000000
 * return (void*)(0xffff000000000000 | (nCount << 39));
 * @endcode
 * 
 * @see GetPageTable 用于使用PTE基地址计算页表条目
 */
void* GetPteBase();