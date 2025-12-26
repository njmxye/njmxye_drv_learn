#pragma once
#include<ntifs.h>
#include<ntddk.h>

/**
 * @brief 重保护上下文结构体
 * 
 * 用于存储MDL操作过程中分配的资源和状态信息。
 * 在对虚拟地址进行写锁定操作时，系统需要分配MDL结构、映射内存页，
 * 这些资源需要在操作完成后统一释放，该结构体用于跟踪这些资源。
 */
typedef struct _REPROTECT_CONTEXT {
	PMDL Mdl;          ///< 指向分配的MDL（内存描述符列表）的指针，用于描述被锁定的内存页
	PUCHAR Lockedva;   ///< 指向映射后的虚拟地址的指针，该地址可用于对锁定内存进行写操作

}REPROTECT_CONTEXT,*PREPROTECT_CONTEXT;

/**
 * @brief 锁定虚拟地址区间以进行写访问
 * 
 * 此函数将指定的虚拟地址区间锁定在物理内存中，并映射到内核地址空间，
 * 使调用者能够对该内存区域进行写操作。这是进行内核补丁操作的关键前置步骤，
 * 因为通常情况下某些内存页面可能是只读的或者需要特殊权限才能修改。
 * 
 * @param Va 要锁定的虚拟地址起始位置
 * @param Length 要锁定的内存区域长度（字节）
 * @param ReprotectContext 输出参数，用于接收重保护上下文信息，包含MDL和映射后的VA
 * 
 * @return NTSTATUS 成功返回STATUS_SUCCESS，失败返回相应的错误码
 *         可能的错误码包括：
 *         - STATUS_INSUFFICIENT_RESOURCES：MDL分配失败
 *         - 其他：从异常处理中获取的异常码
 * 
 * @note 该函数执行以下操作：
 *       1. 分配MDL结构描述目标内存区域
 *       2. 锁定内存页（防止被换出到页面文件）
 *       3. 映射到内核地址空间
 *       4. 将内存保护属性改为可写
 * 
 * @warning 调用此函数后，必须在适当的时候调用 MmUnlockVaForWrite 释放资源
 * @warning 必须在try-except块中调用，以处理可能的页面访问异常
 */
NTSTATUS MmLockVaForWrite(
	PVOID Va,
	ULONG Length,
	__out PREPROTECT_CONTEXT ReprotectContext
);

/**
 * @brief 解锁并释放通过 MmLockVaForWrite 锁定的内存
 * 
 * 此函数释放之前通过 MmLockVaForWrite 分配和设置的所有资源，
 * 包括解除内存页的锁定、释放MDL结构等。
 * 
 * @param ReprotectContext 指向由 MmLockVaForWrite 填充的重保护上下文结构
 * 
 * @return NTSTATUS 始终返回STATUS_SUCCESS
 * 
 * @note 该函数执行以下操作：
 *       1. 解除内核地址空间的映射
 *       2. 解锁内存页（允许换出到页面文件）
 *       3. 释放MDL结构
 *       4. 清空上下文结构中的指针
 * 
 * @warning 在调用此函数后，ReprotectContext 中的指针将变为无效
 * @warning 确保在调用此函数前，所有对映射内存的写操作已完成
 */
NTSTATUS MmUnlockVaForWrite(
	__out PREPROTECT_CONTEXT ReprotectContext
);