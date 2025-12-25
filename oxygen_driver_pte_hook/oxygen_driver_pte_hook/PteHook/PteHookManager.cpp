#include "PteHookManager.h"

#pragma warning(disable: 4838)
#pragma warning(disable: 4309)
//single object
PteHookManager* PteHookManager::m_instance;

bool PteHookManager::fn_pte_inline_hook_bp_pg(HANDLE process_id, void** ori_addr, void* hk_addr)
{
    static bool bFirst = true;

    if (bFirst) {
        m_PteBase = nullptr;
        m_TrampLinePool = (char*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 5, 'JmpP');

        if (!m_TrampLinePool) {
            fn_logger_info("failed to alloc trampline pool", 0, 0);
            return false;
        }
        //清空Hook Info
        memset(&m_HookInfo, 0, sizeof(m_HookInfo));
		m_PoolUsed = 0;
        bFirst = false;
    }

    PEPROCESS Process{ 0 };
    KAPC_STATE Apc{ 0 };
    NTSTATUS status;
    const uint32_t BREAK_BYTES_LEAST = 14; //ff 25 绝对跳转
    const uint32_t TrampLineBreakBytes = 20;
    uint32_t uBreakBytes = 0;
    char* TrampLine = m_TrampLinePool + m_PoolUsed;
    hde64s hde_info{ 0 }; //反汇编引擎
    char* JmpAddresssStart = (char*)*ori_addr;

    //是否Hook满了
    if (m_HookCount == MAX_HOOK_COUNT) {

        fn_logger_info("hooks too many", true, 0);
        return false;
    }

	status = PsLookupProcessByProcessId(process_id, &Process);

    if (!NT_SUCCESS(status)) {
        fn_logger_info("failed to get process by pid", true, status);
        return false;
	}

    //首先隔离页表
    auto ret = fn_isolation_pages(process_id, *ori_addr);
    if (!ret) return false;
    //隔离成功，构建hook
    while (uBreakBytes < BREAK_BYTES_LEAST) {
        hde64_disasm((void*)((uint64_t)JmpAddresssStart + uBreakBytes), &hde_info);
        uBreakBytes += hde_info.len;
	}
