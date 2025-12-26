#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include "../ia32/ia32.hpp" 
#include "PageTable.h"
#include "../HookManager/HookManager.h"

#pragma warning(disable:4389)

/**
 * @file PageTable.cpp
 * @brief 页表操作实现文件
 * 
 * 本文件实现了对Windows x64内核页表结构的直接访问和操作。
 * 通过获取PTE基地址并直接计算各级页表条目的虚拟地址，
 * 实现对页表条目的读取和修改，从而控制内存映射。
 * 
 * @section page_table_structure 页表结构详解
 * 
 * x86-64架构采用4级页表结构，每个进程拥有独立的页表。
 * CR3寄存器存储当前进程的PML4表物理基地址。
 * 
 * 页表条目的共同结构（64位）：
 * | Bit   | 名称    | 描述                                    |
 * |-------|---------|----------------------------------------|
 * | 0     | P       | Present，存在位，为1表示条目有效         |
 * | 1     | R/W     | Read/Write，读写权限位                  |
 * | 2     | U/S     | User/Supervisor，用户/内核模式位        |
 * | 3     | PWT     | Page Write Through，写直达位            |
 * | 4     | PCD     | Page Cache Disable，缓存禁用位          |
 * | 5     | A       | Accessed，访问位，由CPU自动设置          |
 * | 6     | D       | Dirty，脏位，由CPU自动设置（仅PTE/PDE）  |
 * | 7     | PS      | Page Size，页面大小（仅PDE/PDPTE）       |
 * | 8     | G       | Global，全局位（TLB刷新时保留）          |
 * | 9-11  | Avail   | 可用位，操作系统可自由使用              |
 * | 12-51 | PFN     | Page Frame Number，物理页框号           |
 * | 52-62 | Avail   | 可用位，操作系统可自由使用              |
 * | 63    | NX      | No Execute，禁止执行位                  |
 * 
 * @section pte_base PTE基地址的重要性
 * 
 * 在Windows内核中，PTE（页表条目）本身也存储在内存中。
 * 内核空间有一个特殊的自映射区域，使得可以通过虚拟地址访问PTE结构。
 * 
 * GetPteBase()函数的核心任务是找到这个PTE区域的起始虚拟地址。
 * 找到PTE基地址后，就可以计算任意虚拟地址对应的PTE地址：
 * PTE_VA = PTE_BASE + (VirtualAddress >> 12) * sizeof(PTE)
 * 
 * 同理，可以计算出PDE、PDPTE、PML4E的地址。
 */

/**
 * @brief 获取内核PTE结构的基地址
 * 
 * 此函数是页表操作的核心基础设施函数。它通过读取CR3寄存器，
 * 并利用Windows内核的自映射机制，找到内核PTE结构的虚拟基地址。
 * 
 * @section algorithm 算法原理
 * 
 * 此函数基于Windows内核的一个特殊设计：自引用PML4条目。
 * 
 * 1. 自引用条目的产生：
 *    在系统初始化时，内核会在PML4表中创建一个特殊的条目，
 *    该条目指向PML4表自身。这是通过将PML4表的物理地址
 *    写入PML4表中某个索引位置来实现的。
 * 
 * 2. 自引用的作用：
 *    这个自引用条目使得内核可以访问PTE、PDE、PDPTE、PML4E
 *    结构本身，实现"通过页表访问页表"。
 * 
 * 3. 计算方法：
 *    假设自引用条目位于索引n（通常为508 = 0x1F8），
 *    那么PTE基地址的计算公式为：
 *    PTE_BASE = 0xFFFF000000000000 | (n << 39)
 * 
 *    这是因为：
 *    - 0xFFFF000000000000是Windows 64位内核空间的地址掩码
 *    - 自引用条目索引n对应虚拟地址的位39-47
 *    - 通过将n左移39位，可以得到该条目在虚拟地址空间中的基地址
 * 
 * @section implementation 实现细节
 * 
 * 函数执行步骤：
 * 1. 使用__readcr3()内联函数读取CR3寄存器的值
 *    - CR3存储当前进程的PML4表物理基地址
 *    - 注意：这里读取的是当前进程的CR3，不是目标进程的
 * 
 * 2. 将物理地址转换为虚拟地址
 *    - MmGetVirtualForPhysical()将物理地址转换为虚拟地址
 *    - 由于PML4表通常在内核空间，可以直接映射
 * 
 * 3. 遍历PML4表查找自引用条目
 *    - 自引用条目的物理地址等于CR3指向的物理地址
 *    - 比较每个条目的物理地址部分（掩码0x000FFFFFFFFFF000）
 *    - 如果相等，说明找到了自引用条目
 * 
 * 4. 计算并返回PTE基地址
 *    - 使用找到的索引计算PTE基地址
 *    - 返回的是内核模式虚拟地址
 * 
 * @return void* PTE基地址（内核模式虚拟地址），失败返回nullptr
 *         失败的原因可能包括：
 *         - 系统不支持自引用PML4（某些特殊配置）
 *         - MmGetVirtualForPhysical转换失败
 *         - PML4表损坏或异常
 * 
 * @note 此函数假设当前进程的PML4表与目标进程有相同的自引用结构
 *       如果需要在目标进程上下文中操作，应该先切换到目标进程上下文
 * 
 * @warning 此函数依赖于特定的Windows内核布局
 *         在不同版本的Windows中，自引用条目的索引可能不同
 * 
 * @see GetPageTable 使用PTE基地址计算各级页表条目地址
 */
void* GetPteBase() {
	/**
	 * cr3结构体用于解析CR3寄存器的内容
	 * 
	 * CR3寄存器（64位）的结构：
	 * - address_of_page_directory[51:12]：PML4表物理基地址（40位物理地址）
	 * - reserved1[11:9]：保留，必须为0
	 * - PWT[8]：Page Write Through，控制缓存行为
	 * - PCD[7]：Page Cache Disable，控制缓存行为
	 * - reserved2[6:4]：保留
	 * - address_of_page_directory_nonzero_part[63:52]：地址的高12位（部分架构）
	 * 
	 * @note 在大多数x86-64实现中，CR3的高32位为0
	 *       address_of_page_directory占用低32位中的位12-51
	 */
	cr3 CR3;
	
	/**
	 * PHYSICAL_ADDRESS结构体用于表示物理地址
	 * 
	 * QuadPart是64位整型，可以存储完整的物理地址
	 * 虽然当前物理地址只有40-52位有效，但使用64位可以容纳未来扩展
	 */
	PHYSICAL_ADDRESS cr3_pa = { 0 };
	
	/**
	 * 步骤1：读取CR3寄存器
	 * 
	 * __readcr3()是编译器内联函数（通常使用_rdcr3指令）
	 * 返回当前进程的PML4表物理基地址
	 * 
	 * @note 这里读取的是当前线程所在进程的CR3
	 *       如果需要在其他进程上下文操作，需要先切换进程
	 * 
	 * @see KeStackAttachProcess 用于切换到目标进程上下文
	 */
	CR3.flags = __readcr3();
	
	/**
	 * 步骤2：计算CR3物理地址
	 * 
	 * PML4表在物理内存中的地址 = CR3.address_of_page_directory * PAGE_SIZE
	 * 
	 * 因为：
	 * - CR3存储的是PML4表物理基地址，以4KB（PAGE_SIZE）为单位
	 * - 要得到实际的物理地址，需要乘以PAGE_SIZE
	 * 
	 * @note 为什么除以PAGE_SIZE？因为PML4表必须4KB对齐
	 *       CR3存储的是对齐后的基地址索引
	 */
	cr3_pa.QuadPart = CR3.address_of_page_directory * PAGE_SIZE;
	
	/**
	 * 步骤3：将物理地址转换为虚拟地址
	 * 
	 * MmGetVirtualForPhysical()是一个未文档化的内核函数
	 * 它尝试将物理地址映射到当前进程的虚拟地址空间
	 * 
	 * @note PML4表通常位于内核空间，可以被任何进程访问
	 *       因此使用当前进程的地址空间也可以映射
	 * 
	 * @warning 如果物理地址无法映射（例如是设备内存），返回NULL
	 */
	PULONG64 cr3_va = (PULONG64)MmGetVirtualForPhysical(cr3_pa);
	
	/**
	 * 步骤4：遍历PML4表查找自引用条目
	 * 
	 * 自引用条目的特征：
	 * - 该条目指向的物理地址等于PML4表自身的物理地址
	 * - 即：PML4E[TargetIndex].PFN == CR3.address_of_page_directory
	 * 
	 * 比较操作详解：
	 * - (*cr3_va & 0x000FFFFFFFFFF000)：提取PTE/PDE/PDPTE/PML4E的物理页框号（PFN）
	 *   掩码0x000FFFFFFFFFF000的作用是保留位12-51（PFN字段）
	 * - cr3_pa.QuadPart：CR3指向的PML4表物理基地址
	 * - 如果两者相等，说明当前条目是自引用条目
	 * 
	 * @note PML4表有512个条目（索引0-511）
	 *       自引用条目通常位于索引508（0x1F8）
	 *       这是Windows内核的约定，但不是硬性规定
	 * 
	 * @note 循环计数器nCount记录找到的索引位置
	 *       这个索引将用于计算PTE基地址
	 */
	UINT64 nCount = 0;
	while ((*cr3_va & 0x000FFFFFFFFFF000) != cr3_pa.QuadPart) {
		/**
		 * 遍历检查每个PML4条目
		 * 
		 * @note 这里使用++cr3_va是因为PULONG64指针
		 *       每次递增会移动8字节（一个PML4E的大小）
		 * 
		 * @warning 如果循环超过512次，说明找不到自引用条目
		 *          这是异常情况，可能表示系统配置特殊
		 */
		if (++nCount >= 512) {
			/**
			 * 找不到自引用条目，返回nullptr
			 * 
			 * 这可能发生在：
			 * 1. 系统禁用了自引用PML4（某些安全配置）
			 * 2. PML4表损坏
			 * 3. 物理地址转换失败
			 */
			return nullptr;
		}
		cr3_va++;
	}
	
	/**
	 * 步骤5：计算PTE基地址
	 * 
	 * 计算公式：PTE_BASE = 0xFFFF000000000000 | (nCount << 39)
	 * 
	 * 详细解释：
	 * - 0xFFFF000000000000：Windows 64位内核空间的典型地址掩码
	 *   内核空间的虚拟地址通常使用这个前缀
	 * - nCount << 39：将自引用条目索引移动到正确的位位置
	 *   因为PML4索引对应虚拟地址的位39-47
	 *   左移39位后，索引的每一位对应虚拟地址的相应位
	 * 
	 * 为什么是左移39位？
	 * - PML4索引使用虚拟地址的位39-47
	 * - 每个PML4条目是8字节（64位）
	 * - PTE基地址位于虚拟地址空间的特定区域
	 * - 通过将索引左移39位，可以得到该索引对应的虚拟地址基地址
	 * 
	 * @par 示例计算（假设nCount = 508 = 0x1F8）：
	 * 0x1F8 << 39 = 0x3F000000000
	 * 结果 = 0xFFFF000000000000 | 0x3F000000000 = 0xFFFF3F0000000000
	 * 
	 * @note 返回的地址是内核模式虚拟地址
	 *       可以直接用于后续的页表计算
	 * 
	 * @see GetPageTable 使用PTE基地址计算页表条目
	 */
	return (void*)(0xffff000000000000 | (nCount << 39));
}

/**
 * @brief 获取页表信息
 * 
 * 此函数根据给定的虚拟地址，计算并填充该地址对应的
 * 各级页表条目的指针（PTE、PDE、PDPTE、PML4E）。
 * 
 * @section calculation_method 页表条目地址计算方法
 * 
 * 在Windows内核中，各级页表条目按照以下规则排列：
 * 
 * 1. PTE地址计算：
 *    PTE_VA = PTE_BASE + (VirtualAddress >> 12) * 8
 *    
 *    解释：
 *    - VirtualAddress >> 12：提取虚拟地址的页内偏移，得到页号
 *    - * 8：每个PTE占8字节
 *    - + PTE_BASE：加上PTE区域的基地址
 * 
 * 2. PDE地址计算：
 *    PDE_VA = ((VirtualAddress >> 21) << 3) + PDE_BASE
 *    
 *    其中PDE_BASE的推导：
 *    - PDE_BASE = ((PTE_BASE & 0xFFFFFFFFFFFF) >> 12) * 8 + PTE_BASE
 *    - PTE_BASE的低48位是有效的虚拟地址
 *    - >> 12：提取PTE_BASE的页号
 *    - * 8：转换为PDE区域的偏移
 *    - + PTE_BASE：加上PTE基地址
 * 
 * 3. PDPTE地址计算：
 *    PDPTE_VA = ((VirtualAddress >> 30) << 3) + PDPTE_BASE
 *    
 *    其中PDPTE_BASE的推导：
 *    - PDPTE_BASE = ((PDE_BASE & 0xFFFFFFFFFFFF) >> 12) * 8 + PTE_BASE
 * 
 * 4. PML4E地址计算：
 *    PML4E_VA = ((VirtualAddress >> 39) << 3) + PML4E_BASE
 *    
 *    其中PML4E_BASE的推导：
 *    - PML4E_BASE = ((PDPTE_BASE & 0xFFFFFFFFFFFF) >> 12) * 8 + PTE_BASE
 * 
 * @section page_size_considerations 大页面考虑
 * 
 * 在x86-64分页中，存在不同大小的页面：
 * 
 * 1. 4KB页面（最常用）：
 *    - 需要完整的四级页表（PML4 -> PDPT -> PD -> PT -> Page）
 *    - PTE指向4KB物理页面
 *    - 虚拟地址的低12位是页面内偏移
 * 
 * 2. 2MB页面：
 *    - 使用三级页表（PML4 -> PDPT -> PD -> Page）
 *    - PDE的PS位（Bit 7）为1时，表示大页面
 *    - PDE直接指向2MB物理页面
 *    - 虚拟地址的低21位是页面内偏移
 * 
 * 3. 1GB页面：
 *    - 使用二级页表（PML4 -> PDPT -> Page）
 *    - PDPTE的PS位（Bit 7）为1时，表示超大页面
 *    - PDPTE直接指向1GB物理页面
 *    - 虚拟地址的低30位是页面内偏移
 * 
 * @param table 页表结构引用，必须预先设置VirtualAddress字段
 *             函数将填充以下字段：
 *             - Entry.Pte：指向虚拟地址对应的PTE
 *             - Entry.Pde：指向虚拟地址对应的PDE
 *             - Entry.Pdpte：指向虚拟地址对应的PDPTE
 *             - Entry.Pml4e：指向虚拟地址对应的PML4E
 * 
 * @return bool 成功返回true，失败返回false
 *         失败的主要原因：
 *         - GetPteBase()返回nullptr（无法获取PTE基地址）
 * 
 * @note 计算得到的指针可以直接解引用读取页表条目内容
 *       例如：pte_64 pte = *table.Entry.Pte;
 * 
 * @par 使用示例：
 * @code
 * PAGE_TABLE table;
 * table.VirtualAddress = (void*)0xFFFF800012345678;
 * 
 * if (GetPageTable(table)) {
 *     // 读取各级页表条目
 *     pml4e_64 pml4e = *table.Entry.Pml4e;
 *     pdpte_64 pdpte = *table.Entry.Pdpte;
 *     pde_64 pde = *table.Entry.Pde;
 *     pte_64 pte = *table.Entry.Pte;
 *     
 *     // 检查条目是否有效
 *     if (pml4e.flags.P) {
 *         DbgPrint("PML4E有效，指向PDPT\n");
 *     }
 *     if (pdpte.flags.PS) {
 *         DbgPrint("使用1GB大页面\n");
 *     } else if (pde.flags.PS) {
 *         DbgPrint("使用2MB大页面\n");
 *     } else {
 *         DbgPrint("使用4KB页面\n");
 *     }
 * }
 * @endcode
 * 
 * @see GetPteBase 获取PTE基地址
 * @see PAGE_TABLE 结构体定义
 */
bool GetPageTable(PAGE_TABLE& table) {
	/**
	 * 局部变量声明
	 * 
	 * PteBase：PTE区域的虚拟基地址
	 * pdeBase：PDE区域的虚拟基地址
	 * pdpteBase：PDPTE区域的虚拟基地址
	 * pml4eBase：PML4E区域的虚拟基地址
	 */
	ULONG64 PteBase = 0;
	ULONG64 pdeBase = 0;
	ULONG64 pdpteBase = 0;
	ULONG64 pml4eBase = 0;

	/**
	 * 步骤1：获取PTE基地址
	 * 
	 * 调用GetPteBase()获取内核PTE结构的虚拟基地址
	 * 这是所有后续计算的基础
	 * 
	 * @note 如果返回nullptr，说明无法获取PTE基地址
	 *       可能的原因包括自引用PML4条目不存在
	 */
	PteBase = (ULONG64)GetPteBase();
	DbgPrint("PteBase :%p\n", PteBase);

	/**
	 * 步骤2：验证PTE基地址
	 * 
	 * 如果PTE基地址获取失败，直接返回false
	 */
	if (PteBase == NULL) return false;

	/**
	 * 步骤3：计算各级页表区域的基地址
	 * 
	 * 这些计算基于Windows内核的自映射机制：
	 * 
	 * 计算PDE_BASE：
	 * - PDE区域位于PTE区域的"上方"
	 * - 实际上，PDE_BASE是通过特定的数学关系推导的
	 * - 公式：PDE_BASE = ((PTE_BASE & 0xFFFFFFFFFFFF) >> 12) * 8 + PTE_BASE
	 * 
	 * 计算PDPTE_BASE：
	 * - 类似地，PDPTE_BASE = ((PDE_BASE & 0xFFFFFFFFFFFF) >> 12) * 8 + PTE_BASE
	 * 
	 * 计算PML4E_BASE：
	 * - PML4E_BASE = ((PDPTE_BASE & 0xFFFFFFFFFFFF) >> 12) * 8 + PTE_BASE
	 * 
	 * @note 这些计算依赖于Windows内核的特定布局
	 *       不同版本可能需要调整
	 * 
	 * @note 使用0xFFFFFFFFFFFF掩码确保只处理低48位地址
	 *       因为x86-64只使用48位虚拟地址（扩展到57位但未使用）
	 */
	pdeBase = (((PteBase & 0xffffffffffff) >> 12) << 3) + PteBase;
	pdpteBase = (((pdeBase & 0xffffffffffff) >> 12) << 3) + PteBase;
	pml4eBase = (((pdpteBase & 0xffffffffffff) >> 12) << 3) + PteBase;

	/**
	 * 步骤4：计算目标虚拟地址对应的页表条目地址
	 * 
	 * 虚拟地址到页表条目的映射：
	 * 
	 * 1. PTE地址计算：
	 *    PTE = ((VirtualAddress >> 12) << 3) + PTE_BASE
	 *    - VirtualAddress >> 12：右移12位，得到页号
	 *    - << 3：左移3位（乘以8），得到页表中的偏移
	 *    - + PTE_BASE：加上PTE区域基地址
	 *    - 右移12位是提取[20:12]位作为索引
	 *    - 左移3位是因为每个PTE占8字节（2^3）
	 * 
	 * 2. PDE地址计算：
	 *    PDE = ((VirtualAddress >> 21) << 3) + PDE_BASE
	 *    - VirtualAddress >> 21：右移21位，提取[29:21]位
	 *    - << 3：左移3位得到页表偏移
	 *    - + PDE_BASE：加上PDE区域基地址
	 * 
	 * 3. PDPTE地址计算：
	 *    PDPTE = ((VirtualAddress >> 30) << 3) + PDPTE_BASE
	 *    - VirtualAddress >> 30：右移30位，提取[38:30]位
	 * 
	 * 4. PML4E地址计算：
	 *    PML4E = ((VirtualAddress >> 39) << 3) + PML4E_BASE
	 *    - VirtualAddress >> 39：右移39位，提取[47:39]位
	 * 
	 * @note 这些计算假设虚拟地址是有效的用户或内核地址
	 *       如果地址无效，计算的指针可能指向非法内存
	 * 
	 * @note 使用0xFFFFFFFFFFFF掩码确保地址截断到48位
	 *       符合x86-64的虚拟地址限制
	 */
	table.Entry.Pte = (pte_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 12) << 3) + PteBase);
	table.Entry.Pde = (pde_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 21) << 3) + pdeBase);
	table.Entry.Pdpte = (pdpte_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 30) << 3) + pdpteBase);
	table.Entry.Pml4e = (pml4e_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 39) << 3) + pml4eBase);

	/**
	 * 返回成功
	 * 
	 * @note 即使虚拟地址无效，函数也可能返回true
	 *       调用者需要自行验证页表条目的有效性（检查P位）
	 */
	return true;
}