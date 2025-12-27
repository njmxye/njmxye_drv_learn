谢谢你的补充信息！结合你新上传的关于 `ObpReferenceObjectByHandleWithTag`（带 `p` 的内部函数）以及 IDA 的截图，代码的意图更加清晰了。

这套代码的核心逻辑是：通过特征码定位 Windows 内核未导出的私有函数 `ObpReferenceObjectByHandleWithTag`，然后挂钩它。在代理函数中，它强行将 `DesiredAccess`（请求权限）改为 `0`，并将 `AccessMode`（访问模式）改为 `0`（即 `KernelMode`）。**这样做的目的是让系统认为所有的句柄操作都是内核发起的，从而绕过权限检查（因为内核模式下的操作通常不受权限限制），或者获取全权限句柄。**

以下是结合所有图片细节，修正并补全的完整代码。我修复了之前版本中未区分 `Ob`（导出）和 `Obp`（私有）函数的问题，并根据截图修正了函数定义。

```cpp
#include <ntifs.h>
#include <ntddk.h>
// 假设这是你的Hook管理器头文件
#include "PteHookManager.h" 

// -------------------------------------------------------------------------
// 全局变量与定义
// -------------------------------------------------------------------------

const uint32_t MAX_HOOK_PROCESS = 100;
HANDLE g_HkPids[MAX_HOOK_PROCESS];
bool g_IsObp = 0;
CHAR g_szHookProcessName[] = "oxygen"; // 目标进程名
uint32_t g_HookCount = 0;

// 声明未导出的辅助函数
EXTERN_C PCHAR PsGetProcessImageFileName(PEPROCESS Process);

// -------------------------------------------------------------------------
// 函数指针类型定义
// -------------------------------------------------------------------------

// 1. 标准导出的 ObReferenceObjectByHandleWithTag
typedef NTSTATUS(*fnObReferenceObjectByHandleWithTag)(
    HANDLE Handle,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    ULONG Tag,
    PVOID* Object,
    POBJECT_HANDLE_INFORMATION HandleInformation
);

// 2. 内部私有的 ObpReferenceObjectByHandleWithTag
// 根据截图 6ec6... 和 cf9f...，代码中认为它多了一个 PVOID Unk 参数
typedef NTSTATUS(*fnObpReferenceObjectByHandleWithTag)(
    HANDLE Handle,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    ULONG Tag,
    PVOID* Object,
    POBJECT_HANDLE_INFORMATION HandleInformation,
    PVOID Unk 
);

// 全局变量保存函数地址
fnObReferenceObjectByHandleWithTag g_OriObReferenceObjectByHandleWithTag; // 原始导出函数
uint64_t g_ObReferenceObjectByHandleWithTag;

fnObpReferenceObjectByHandleWithTag g_OriObpReferenceObjectByHandleWithTag; // 原始内部函数 (Obp)
uint64_t g_ObpReferenceObjectByHandleWithTag;

// UNICODE 字符串定义
UNICODE_STRING g_usObRef = RTL_CONSTANT_STRING(L"ObReferenceObjectByHandleWithTag");

// -------------------------------------------------------------------------
// 代理函数 (Hook Handlers)
// -------------------------------------------------------------------------

// 针对导出函数的 Hook 代理（代码中定义了但似乎主要用下面那个）
NTSTATUS MyObReferenceObjectByHandleWithTag(
    HANDLE Handle,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    ULONG Tag,
    PVOID* Object,
    POBJECT_HANDLE_INFORMATION HandleInformation
) {
    UNREFERENCED_PARAMETER(AccessMode);
    UNREFERENCED_PARAMETER(DesiredAccess);

    // 强行修改权限为 0，AccessMode 为 0 (KernelMode)
    return g_OriObReferenceObjectByHandleWithTag(
        Handle, 
        0, 
        ObjectType, 
        0, 
        Tag, 
        Object, 
        HandleInformation
    );
}

// 针对内部私有函数 Obp 的 Hook 代理（实际使用的 Hook 目标）
NTSTATUS MyObpReferenceObjectByHandleWithTag(
    HANDLE Handle,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    ULONG Tag,
    PVOID* Object,
    POBJECT_HANDLE_INFORMATION HandleInformation,
    PVOID Unk
) {
    UNREFERENCED_PARAMETER(AccessMode);
    UNREFERENCED_PARAMETER(DesiredAccess);

    // 打印 PID 证明 Hook 触发
    // 注意截图中使用 %llx 打印 Pid
    DbgPrintEx(77, 0, "[+]Pid:%llx\r\n", PsGetCurrentProcessId());

    // 调用原始 Obp 函数，但篡改了 DesiredAccess(0) 和 AccessMode(0)
    // 这里的逻辑就是你提到的：降权/提权绕过检查
    return g_OriObpReferenceObjectByHandleWithTag(
        Handle, 
        0, // DesiredAccess = 0
        ObjectType, 
        0, // AccessMode = KernelMode (0)
        Tag, 
        Object, 
        HandleInformation,
        Unk // 透传未知的第8个参数
    );
}

// -------------------------------------------------------------------------
// 进程回调函数
// -------------------------------------------------------------------------

VOID on_process_notify(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
) {
    UNREFERENCED_PARAMETER(ParentId);
    PEPROCESS Process;

    if (Create) {
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {
            
            PCHAR szImageName = PsGetProcessImageFileName(Process);

            if (szImageName && strstr(szImageName, g_szHookProcessName)) {
                
                bool bSuc = 0;
                static bool bFirst = true;

                // ---------------------------------------------------------
                // 首次运行：寻找 Obp 函数地址并初始化
                // ---------------------------------------------------------
                if (bFirst) {
                    RTL_OSVERSIONINFOEXW version = { 0 };
                    version.dwOSVersionInfoSize = sizeof(version);
                    RtlGetVersion((PRTL_OSVERSIONINFOW)&version);

                    // 1. 获取导出函数地址作为基准
                    g_OriObReferenceObjectByHandleWithTag = (fnObReferenceObjectByHandleWithTag)MmGetSystemRoutineAddress(&g_usObRef);
                    g_ObReferenceObjectByHandleWithTag = (uint64_t)g_OriObReferenceObjectByHandleWithTag;

                    // 2. 版本检查 (Win7 或 某些老版本Win10不支持)
                    if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601 || version.dwBuildNumber < 14393) {
                        DbgPrintEx(77, 0, "[BpObCall]:not support the os version\r\n");
                        ObDereferenceObjectWithTag(Process, 'tlfD');
                        return;
                    } 
                    else {
                        // 3. 特征码搜索：寻找 call 指令 (0xE8) 跳转到的内部函数 Obp...
                        PUCHAR pStart = (PUCHAR)g_ObReferenceObjectByHandleWithTag;
                        
                        // 向下搜索第一个 0xE8 (CALL)
                        while (*pStart != 0xe8) {
                            pStart++;
                        }

                        // 4. 计算跳转目标地址
                        // Target = CurrentAddr + 5 (Instruction Length) + Offset
                        g_OriObpReferenceObjectByHandleWithTag = (fnObpReferenceObjectByHandleWithTag)(pStart + 5 + *(int*)(pStart + 1));
                        
                        // 保存 Obp 地址
                        g_ObpReferenceObjectByHandleWithTag = (uint64_t)g_OriObpReferenceObjectByHandleWithTag;

                        // 5. 执行第一次 Hook
                        // 使用 MyObpReferenceObjectByHandleWithTag 作为回调
                        bSuc = PteHookManager::GetInstance()->fn_pte_inline_hook_bp_pg(
                            ProcessId, 
                            (void**)&g_OriObpReferenceObjectByHandleWithTag, // 传入函数指针的地址
                            (void*)MyObpReferenceObjectByHandleWithTag      // 代理函数
                        );

                        g_IsObp = true; // 标记已定位到 Obp
                    }
                    bFirst = false;
                } 
                // ---------------------------------------------------------
                // 后续运行：直接应用 Hook
                // ---------------------------------------------------------
                else {
                    void* hkaddr;
                    void* callback;

                    if (g_IsObp) {
                        // 使用 Obp 地址和对应的代理函数
                        hkaddr = (void*)g_ObpReferenceObjectByHandleWithTag;
                        callback = (void*)MyObpReferenceObjectByHandleWithTag;
                    } else {
                        // 备用分支 (代码逻辑中看似和上面一样，可能是为了兼容未找到Obp的情况，但在bFirst里直接return了)
                        hkaddr = (void*)g_ObReferenceObjectByHandleWithTag;
                        callback = (void*)MyObReferenceObjectByHandleWithTag;
                    }

                    bSuc = PteHookManager::GetInstance()->fn_pte_inline_hook_bp_pg(ProcessId, &hkaddr, callback);
                }

                if (bSuc) {
                    DbgPrintEx(77, 0, "[BpObCall]:hook successfully\r\n");
                    if (g_HookCount < MAX_HOOK_PROCESS) {
                        g_HkPids[g_HookCount++] = ProcessId;
                    }
                } else {
                    DbgPrintEx(77, 0, "[BpObCall]:hook failed\r\n");
                }
            }
            
            ObDereferenceObjectWithTag(Process, 'tlfD');
        }
    }
}

// -------------------------------------------------------------------------
// 驱动卸载函数
// -------------------------------------------------------------------------

void driver_unload(PDRIVER_OBJECT driver_object) {
    UNREFERENCED_PARAMETER(driver_object);

    // 注销进程回调
    PsSetCreateProcessNotifyRoutine(on_process_notify, 1);
    
    void* RemoveAddr = 0;

    if (g_IsObp) {
        RemoveAddr = (void*)g_ObpReferenceObjectByHandleWithTag;
    } else {
        RemoveAddr = (void*)g_ObReferenceObjectByHandleWithTag;
    }

    // 移除所有 Hook
    for (unsigned int i = 0; i < g_HookCount; i++) {
        PteHookManager::GetInstance()->fn_remove_hook(g_HkPids[i], RemoveAddr);
    }
}

// -------------------------------------------------------------------------
// 驱动入口点
// -------------------------------------------------------------------------

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING us_regpath) {
    // Hook测试
    UNREFERENCED_PARAMETER(us_regpath);
    NTSTATUS status;

    driver_object->DriverUnload = driver_unload;

    // 在进程回调中修改
    status = PsSetCreateProcessNotifyRoutine(on_process_notify, 0);

    return STATUS_SUCCESS;
}

```

### 关键修正说明：

1. **区分 `Ob` 和 `Obp**`：
* 根据代码截图，增加了 `g_OriObpReferenceObjectByHandleWithTag` 和 `fnObpReferenceObjectByHandleWithTag`。
* 在 `bFirst` 初始化逻辑中，代码明确是在计算 `Obp` 的地址，并将 Hook 目标指向了这个内部函数。


2. **修正参数个数 (`Unk`)**：
* 标准的 `ObReferenceObjectByHandleWithTag` 只有 7 个参数。
* 但是在你的截图 `cf9fa64f...` 和 `6ec6d974...` 中，自定义的 `MyObpReferenceObjectByHandleWithTag` 接收 **8个参数**（多了一个 `PVOID Unk`）。这通常是因为在某些 Windows 版本中，内部函数 `Obp` 的调用约定确实多一个参数，或者是编译器的某些优化导致的。我已经按照截图强制加上了这个参数，以保证代码一致性。


3. **权限篡改逻辑**：
* 在 `MyObpReferenceObjectByHandleWithTag` 中，可以看到 `return` 语句将第二个参数（`DesiredAccess`）硬编码为 `0`，第四个参数（`AccessMode`）硬编码为 `0`。
* `AccessMode = 0` 对应 `KernelMode`。当内核模式请求句柄时，Windows 对象管理器会跳过大部分权限检查。这完美解释了“把accessmode改为kernelmode这样也能达到目的”的描述。



这份代码现在应该能够准确复现原图的逻辑。如果你在编译时遇到 `PteHookManager` 相关的问题，请确保你已经有了对应的头文件和 `.cpp` 实现文件，因为那部分不包含在截图中。