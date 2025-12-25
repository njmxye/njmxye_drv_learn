# PteHook 项目分析与教学版实现

## 一、项目概述

这是一个 **Windows 内核层 Inline Hook 驱动**，名为 PteHook，核心功能是实现对目标进程用户态函数的挂钩（Hook）操作。

### 主要应用场景
- **安全监控**：拦截系统调用，如 `NtOpenProcess`、`NtCreateFile` 等
- **软件保护**：在用户态函数入口处插入钩子实现功能增强
- **调试与逆向**：动态分析目标程序的函数调用行为

## 二、核心技术原理

### 2.1 Inline Hook 基本原理

Inline Hook 的核心思想是在目标函数的入口处写入跳转指令，将程序执行流重定向到自定义的 hook 函数。基本流程如下：

```
┌─────────────────────────────────────────────────────────────────────┐
│                          原函数入口流程                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   调用者 ──►  原函数入口 ──► [原始指令] ──► 继续执行原函数          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                          Hook后的执行流程                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   调用者 ──► 原函数入口 ──► JMP到Hook函数 ──► 自定义逻辑            │
│                                         │                           │
│                                         ▼                           │
│                                   [可选]调用原函数                   │
│                                         │                           │
│                                         ▼                           │
│                                   返回调用者                        │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 跳转指令的实现

在 x64 架构下，跳转到任意地址需要 12 字节的指令序列：

```assembly
mov rax, <hook函数地址>    ; 48 B8 xx xx xx xx xx xx xx xx
jmp rax                    ; FF E0
```

这条指令序列的作用是：
1. 将 hook 函数地址加载到 RAX 寄存器（8 字节地址）
2. 通过 JMP RAX 跳转到该地址执行

### 2.3 Trampoline 技术

为了保持 hook 后仍能调用原函数，需要创建一个 "蹦床"（Trampoline）代码块：

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Trampoline 代码结构                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌────────────────┬─────────────┬────────────────┐                  │
│  │  原始指令备份   │   JMP回原函数 │  返回指令(retn) │                 │
│  │  (复制原函数开头的指令)   │  (跳回原函数继续执行) │                  │
│  └────────────────┴─────────────┴────────────────┘                  │
│                                                                     │
│  作用：                                                              │
│  1. 保存原始函数的前N字节指令                                        │
│  2. 在末尾添加返回指令                                               │
│  3. 将 originalFunc 指针指向这里                                     │
│  4. 调用原函数时实际执行这段代码                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.4 页表隔离机制

这是 PteHook 项目最核心、最复杂的技术，目的是 **只让目标进程看到修改后的代码**。

#### 为什么需要页表隔离？

默认情况下，所有进程共享同一份内核代码。当我们在内核中修改目标函数的入口字节时，**所有进程**都会受到影响。这通常不是我们想要的结果。

#### 页表隔离的实现步骤

**步骤1：附加到目标进程**

```cpp
KAPC_STATE apcState;
KeStackAttachProcess(process, &apcState);
// 现在我们在目标进程的地址空间中执行
```

**步骤2：检查页大小**

```cpp
PAGE_TABLE table = {0};
table.VirtualAddress = PAGE_ALIGN(targetAddr);
GetPageTable(table);

if (table.Entry.Pde->large_page) {
    // 当前是 2MB 大页，需要拆分为 4KB 小页
    SplitLargePage(*table.Entry.Pde, newPde);
}
```

**步骤3：创建新的页表映射**

```
原页表结构：                              新页表结构：
┌─────────────────┐                       ┌─────────────────┐
│  PML4           │                       │  PML4           │
├─────────────────┤                       ├─────────────────┤
│  PDPT ──────────┼────► 1GB页 ──────────►│  PDPT ──────────┼──► 新的PDE
├─────────────────┤                       ├─────────────────┤
│  PDE ──────────┼────► 2MB大页 ─────────►│  PDE ──────────┼──► 拆分为512个小PTE
├─────────────────┤                       ├─────────────────┤
│  PTE ──────────┼────► 4KB页 ──────────►│  PTE ──────────┼──► 指向新分配的物理页
├─────────────────┤                       ├─────────────────┤
│  物理页         │                       │  物理页         │
│  (原代码)       │                       │  (复制后的代码) │
└─────────────────┘                       └─────────────────┘
```

**步骤4：替换页表项**

```cpp
// 分配连续的物理内存
void* newPage = MmAllocateContiguousMemory(PAGE_SIZE, ...);

// 复制原页内容
RtlCopyMemory(newPage, targetAddr, PAGE_SIZE);

// 修改页表项指向新页
pReplacePte->page_frame_number = VaToPa(newPage) / PAGE_SIZE;
```

### 2.5 MDL 内存锁定机制

修改代码页需要绕过写保护，MDL（Memory Descriptor List）提供了这种方法：

```
┌─────────────────────────────────────────────────────────────────────┐
│                         MDL 操作流程                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. 创建MDL：IoAllocateMdl(va, length, ...)                         │
│              ↓                                                      │
│  2. 锁定页面：MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess)   │
│              ↓                                                      │
│  3. 映射到内核：MmMapLockedPagesSpecifyCache(mdl, ...)              │
│              ↓                                                      │
│  4. 修改保护属性：MmProtectMdlSystemAddress(mdl, PAGE_RWX)          │
│              ↓                                                      │
│  5. 执行写操作                                                       │
│              ↓                                                      │
│  6. 清理：MmUnmapLockedPages / MmUnlockPages / IoFreeMdl            │
└─────────────────────────────────────────────────────────────────────┘
```

## 三、代码架构分析

### 3.1 项目文件结构

```
PteHook/
├── main.cpp                 # 驱动入口和使用示例
├── HookManager/
│   ├── HookManager.h        # Hook管理器类定义
│   └── HookManager.cpp      # Hook管理器实现
├── PageTable/
│   ├── PageTable.h          # 页表操作接口
│   └── PageTable.cpp        # 页表获取实现
├── MDL/
│   ├── MDL.h                # MDL操作接口
│   └── MDL.cpp              # MDL实现
├── Hde/
│   ├── hde64.h/.cpp         # 反汇编引擎
│   └── table64.h            # 指令表定义
├── ia32/
│   ├── ia32.hpp             # x86架构定义
│   └── ia32_defines_only.h  # 定义文件
└── structer.h               # 共用数据结构
```

### 3.2 核心类设计

**HookManager 类** 是整个项目的核心：

```cpp
class HookManager {
public:
    // 安装内联钩子
    bool InstallInlinehook(HANDLE pid, void** originAddr, void* hookAddr);
    
    // 移除内联钩子
    bool RemoveInlinehook(HANDLE pid, void* hookAddr);
    
    // 获取单例实例
    static HookManager* GetInstance();
    
    // 地址转换
    ULONG64 VaToPa(void* va);
    void* PaToVa(ULONG64 pa);
    
private:
    // 页表隔离（核心）
    bool IsolationPageTable(PEPROCESS process, void* isolateioAddr);
    
    // 大页拆分
    bool SplitLargePage(pde_64 InPde, pde_64& OutPde);
    
    // 替换页表
    bool ReplacePageTable(cr3 cr3, void* replaceAlignAddr, pde_64* pde);
    
    // 关闭PGE（页全局特性）
    void offPGE();
    
    UINT32 mHookCount = 0;
    HOOK_INFO mHookInfo[MAX_HOOK_COUNT] = {0};
    char* mTrampLinePool = 0;
    UINT32 mPoolUSED = 0;
};
```

## 四、教学版简化实现

我已经为你创建了一个简化版的教学驱动，位于 `PteHook_Simplified/` 目录下：

### 4.1 文件结构

```
PteHook_Simplified/
├── PteHook_Simplified.h     # 头文件（接口定义）
└── PteHook_Simplified.cpp   # 源文件（完整实现）
```

### 4.2 简化版 vs 原版对比

| 功能 | 原版 | 教学版 |
|------|------|--------|
| 页表隔离 | ✅ 完整实现 | ❌ 简化为直接附加进程 |
| 大页拆分 | ✅ 支持 | ❌ 跳过 |
| 多进程支持 | ✅ 完整 | ✅ 支持 |
| 反汇编引擎 | HDE64 | 简化版手动解析 |
| Trampoline | ✅ 完整 | ✅ 简化版 |
| 代码复杂度 | 高 | 中 |

### 4.3 使用示例

```cpp
// 定义原函数指针类型
typedef NTSTATUS(NTAPI* pfnNtOpenProcess)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

// 原始函数地址
pfnNtOpenProcess g_oriNtOpenProcess;

// 自定义Hook函数
NTAPI NTAPI FakeNtOpenProcess(...) {
    DbgPrint("[Hook] NtOpenProcess called\n");
    // 可以在这里添加自定义逻辑
    
    // 调用原始函数（通过trampoline）
    return g_oriNtOpenProcess(...);
}

// 驱动入口
NTSTATUS DriverEntry(...) {
    // 保存原始函数地址
    g_oriNtOpenProcess = NtOpenProcess;
    
    // 安装Hook
    InstallInlineHook(targetPid, (void**)&g_oriNtOpenProcess, FakeNtOpenProcess);
    
    return STATUS_SUCCESS;
}
```

## 五、关键技术要点

### 5.1 虚拟地址到物理地址转换

x64 架构下虚拟地址结构：

```
63    48  47  39  38  30  29  21  20  12  11   0
┌──────┬─────┬─────┬─────┬─────┬─────┬──────────┐
│ Sign │PML4 │ PDPT│ PDE │ PTE │Offset│  Unused  │
└──────┴─────┴─────┴─────┴─────┴─────┴──────────┘
       9位   9位   9位   9位   12位
```

页表遍历：

```cpp
void GetPageTableOffsets(PVOID va, PPAGE_TABLE_OFFSET offsets) {
    PVOID pteBase = (PVOID)0xFFFFF68000000000;
    UINT64 virtualAddr = (UINT64)va;
    
    // 各级的索引计算
    offsets->pml4e = (pml4e_64*)(pteBase + ((virtualAddr >> 39) & 0x1FF));
    offsets->pdpte = (pdpte_64*)(pteBase + ((virtualAddr >> 30) & 0x1FF));
    offsets->pde   = (pde_64*)(pteBase   + ((virtualAddr >> 21) & 0x1FF));
    offsets->pte   = (pte_64*)(pteBase   + ((virtualAddr >> 12) & 0x1FF));
}
```

### 5.2 指令长度解析

为了确保正确写入跳转指令，需要先解析原函数开头的指令长度：

```cpp
BOOLEAN DisasmInstruction(PVOID code, PUINT8 length) {
    UINT8 totalLen = 0;
    
    // 简化版：解析常见指令前缀
    for (int i = 0; i < 5 && totalLen < 15; i++) {
        UCHAR byte = *(UCHAR*)((char*)code + totalLen);
        
        if (byte >= 0x50 && byte <= 0x57) {
            totalLen += 1;  // push/pop reg
        }
        else if (byte == 0x48 || byte == 0x4C || byte == 0x49) {
            totalLen += 1;  // REX前缀
        }
        else if (byte == 0xB8 || byte == 0xBA || byte == 0xBB || byte == 0xB9) {
            totalLen += 5;  // mov reg, imm32
        }
        // ... 更多指令解析
    }
    
    *length = totalLen > 12 ? 12 : totalLen;
    return TRUE;
}
```

### 5.3 进程附加

修改目标进程内存需要先附加到该进程：

```cpp
KAPC_STATE apcState;
KeStackAttachProcess(process, &apcState);

// 现在所有内存操作都在目标进程上下文中执行
// 可以读取/修改目标进程的内存

KeUnstackDetachProcess(&apcState);  // 记得分离
```

## 六、总结

PteHook 项目展示了以下核心技术：

1. **Inline Hook 技术**：在函数入口处写入跳转指令
2. **页表操作**：理解并操作 x64 页表结构
3. **MDL 内存锁定**：绕过写保护修改代码页
4. **进程附加**：在目标进程上下文中执行操作
5. **Trampoline 生成**：保存原始指令以支持原函数调用

简化版教学驱动保留了核心逻辑，移除了复杂的页表隔离和大页拆分功能，更适合学习和理解。