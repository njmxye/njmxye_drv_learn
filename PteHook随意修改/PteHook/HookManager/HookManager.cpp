#include "HookManager.h"
#include<intrin.h>
#include"../Hde/hde64.h"
#include"../PageTable/PageTable.h"

HookManager* HookManager::mInstance;
//防报错
#pragma warning (disable : 4838)//类型转换丢失数据
#pragma warning (disable : 4309)//截断常量值
#pragma warning (disable : 4244)//类型转换丢失数据
#pragma warning (disable : 6328)//比较不同大小的整数类型
#pragma warning (disable : 6066)//函数调用参数类型不匹配
#pragma warning (disable : 4996)//函数已被标记为过时

EXTERN_C VOID
KeFlushEntireTb(
    __in BOOLEAN Invalid,
    __in BOOLEAN AllProcessors
);

bool HookManager::InstallInlinehook(HANDLE pid, __inout void** originAddr, void* hookAddr)
{
    //写了一个状态码，保证正常运行一次后跳出
    static bool bFirst = true;
    if (bFirst) {
        //非分页内存池，4个4KB大小，池标记jmp，返回一个char*类型
        mTrampLinePool = (char*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 4, 'Jmp'); // ExAllocatePool2 蓝屏！！！！！！！
        //如果申请内存池失败，打印日志
        if (!mTrampLinePool) {
            DbgPrintEx(102, 0, "内存申请失败了你妈的。");
            return false;
        };
        //用0填充给定内存地址，大小4KB
        RtlZeroMemory(mTrampLinePool, PAGE_SIZE * 4);   
        //HookManager类里的无符号32位整数
        mPoolUSED = 0;
        //状态机置否
        bFirst = false;
 
    }
    //HookManager类里的无符号32位整数
    //限制 Hook 的最大数量，防止溢出
    if (mHookCount == MAX_HOOK_COUNT) {
        DbgPrintEx(102, 0, "操你妈hook这么多干嘛，不干了。");
        return false;
    }
    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) return false ;
    
    if (!IsolationPageTable(process, *originAddr)) {
        ObDereferenceObject(process);
        return false;
    }


    const UINT32 trampLineByteCount = 20;
    const UINT32 fnBreakByteLeast = 12;

    /*
    push 0
    mov dword ptr ds : [rsp] , 0
    mov dword ptr ds : [rsp + 4] , 0
    */
    char TrampLineCode[trampLineByteCount] = { 
        0x6A,0x00 ,0x3E ,0xC7 ,0x04 ,0x24 ,0x00 ,0x00 ,0x00 ,
        0x00 ,0x3E ,0xC7 ,0x44 ,0x24 ,0x04 ,0x00 ,0x00 ,0x00 ,0x00 ,0xC3 };

    /*
        mov rax, 0 
        Jmp rax
    */
    char AbsoluteJmpCode[fnBreakByteLeast] = {
        0x48,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xFF,0xE0
    };



    char* curTrampLinePool = mTrampLinePool + mPoolUSED;
    char* startJmpAddr = (char*)*originAddr;  // 要HOOK函数的首地址
    UINT32 uBreakBytes = 0; 
    hde64s hdeinfo = { 0 };

    while (uBreakBytes < fnBreakByteLeast) {
        if (!hde64_disasm(startJmpAddr + uBreakBytes, &hdeinfo)) {
            DbgPrint("hde64_disasm error \n");
            return false;
        };
        uBreakBytes += hdeinfo.len;
    };

    *(PUINT32)&TrampLineCode[6] = (UINT32)((UINT64)(startJmpAddr + uBreakBytes) & 0xFFFFFFFF); // 取高位
    *(PUINT32)&TrampLineCode[15] = (UINT32)((UINT64)(startJmpAddr + uBreakBytes)>>32 & 0xFFFFFFFF); //取低位

    memcpy(curTrampLinePool, startJmpAddr, uBreakBytes); //保存原函数的 内容
    memcpy(curTrampLinePool + uBreakBytes, TrampLineCode, trampLineByteCount);  //return 语句


    for (int i = 0; i < MAX_HOOK_COUNT; i++) {
        if (mHookInfo[i].pid != pid) {
            mHookInfo[i].pid = pid; 
            mHookInfo[i].originAddr = startJmpAddr;
            memcpy(mHookInfo[i].originBytes, startJmpAddr, uBreakBytes);
            //Hook数量累加
            mHookCount++;
            break;
        }
    }

    *(void**)&AbsoluteJmpCode[2] = hookAddr; // 数组地址转位一级指针：数组本身就是地址，& 取一次值就变成了耳机指针， 在 * 取一次值
    REPROTECT_CONTEXT Content = { 0 };

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);
    if (!NT_SUCCESS(MmLockVaForWrite(startJmpAddr, PAGE_SIZE, &Content))) {
        return false;
    }

    RtlCopyMemory(Content.Lockedva, AbsoluteJmpCode, fnBreakByteLeast);
    
    if (!NT_SUCCESS(MmUnlockVaForWrite(&Content))) {
        return false;
    }

    KeUnstackDetachProcess(&apc);


    *originAddr = curTrampLinePool;
    mPoolUSED += (uBreakBytes + trampLineByteCount);
    ObDereferenceObject(process);
    return true;
}

bool HookManager::RemoveInlinehook(HANDLE pid, void* hookAddr)
{
    pid;
    UNREFERENCED_PARAMETER(hookAddr);
    return false;
}

HookManager* HookManager::GetInstance()
{//nullptr是空指针常量
//文头创建了一个指向HookManager类的指针，如果此指针为空，则创建一个HookManager实例，返回指针
    if (mInstance == nullptr) {
        //分配大小为HookManager类大小，类型为非分页池的池内存，用在内核驱动防止被换出到磁盘，池标记为test
        mInstance = (HookManager*)ExAllocatePoolWithTag(NonPagedPool, sizeof(HookManager), 'test'); 
    }
    return mInstance;
}

bool HookManager::IsolationPageTable(PEPROCESS process, void* isolateioAddr)
{
    bool bRet = false;
    KAPC_STATE apc; 
    KeStackAttachProcess(process, &apc);
    pde_64 NewPde = { 0 };
    void* alignAddrr; // ?? 

    alignAddrr= PAGE_ALIGN(isolateioAddr); // 0x1000 对齐
    PAGE_TABLE page_table = { 0 };
    page_table.VirtualAddress = alignAddrr;
    GetPageTable(page_table);

    while (true) {
        if (page_table.Entry.Pde->large_page) {
            DbgPrint("size is 2MB \n");
            bRet = SplitLargePage(*page_table.Entry.Pde, NewPde);
            if (!bRet) break;
        }
        else if (page_table.Entry.Pdpte->large_page) {
            DbgPrint("size is 1GB \n");
            break;
        }
        else {
            DbgPrint("size is 4KB \n");
        }
        cr3 Cr3; 
        Cr3.flags = __readcr3();
        bRet = ReplacePageTable(Cr3, alignAddrr, &NewPde);

        if (bRet) {
            DbgPrint("isolation successfully \n");
        }
        else {
            DbgPrint("Failed isolation \n");
        }
        break;
    }

    KeUnstackDetachProcess(&apc);



    return bRet;
}

bool HookManager::SplitLargePage(pde_64 InPde, pde_64& OutPde)
{
    PHYSICAL_ADDRESS MaxAddrPA{ 0 }, LowAddrPa{ 0 }; 
    MaxAddrPA.QuadPart = MAXULONG64;
    LowAddrPa.QuadPart =  0 ;
    pt_entry_64* Pt;
    uint64_t StartPfn  =  InPde.page_frame_number;

    Pt = (pt_entry_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPA, LowAddrPa, MmCached); // 与MmAllocateContiguousMemory ？ 
    if (!Pt) {
        DbgPrint("failed to MmAllocateContiguousMemorySpecifyCache");
        return false;
    }

    for (int i = 0; i < 512; i++) {
        Pt[i].flags = InPde.flags;
        Pt[i].large_page = 0;
        Pt[i].page_frame_number = StartPfn + i;
    }

    OutPde.flags = InPde.flags;
    OutPde.large_page = 0; 
    OutPde.page_frame_number = VaToPa(Pt) / PAGE_SIZE;
    return true;
}

bool HookManager::ReplacePageTable(cr3 cr3, void* replaceAlignAddr, pde_64* pde)
{
    uint64_t *Va4kb, *Vapt, *VaPdt, *VaPdpt, *VaPml4t;
    PHYSICAL_ADDRESS MaxAddrPA{ 0 }, LowAddrPa{ 0 };
    MaxAddrPA.QuadPart = MAXULONG64;
    LowAddrPa.QuadPart = 0;
    PAGE_TABLE pagetable = { 0 };

    Va4kb = (uint64_t*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPA, LowAddrPa, MmCached);
    Vapt = (uint64_t*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPA, LowAddrPa, MmCached);
    VaPdt = (uint64_t*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPA, LowAddrPa, MmCached);
    VaPdpt = (uint64_t*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPA, LowAddrPa, MmCached);

    VaPml4t = (uint64_t*)PaToVa(cr3.address_of_page_directory * PAGE_SIZE);

    if (!Va4kb || !Vapt || !VaPdt || !VaPdpt) {
        DbgPrint(" Apply mm failed \n");
        return false;
    }

    pagetable.VirtualAddress = replaceAlignAddr;
    GetPageTable(pagetable);

    UINT64 pml4eindex = ((UINT64)replaceAlignAddr & 0xFF8000000000) >> 39;
    UINT64 pdpteindex = ((UINT64)replaceAlignAddr & 0x7FC0000000) >> 30;
    UINT64 pdeindex = ((UINT64)replaceAlignAddr & 0x3FE00000) >> 21;
    UINT64 pteindex = ((UINT64)replaceAlignAddr & 0x1FF000) >> 12;
     
    if (pagetable.Entry.Pde->large_page) {
        MmFreeContiguousMemorySpecifyCache(Vapt, PAGE_SIZE, MmCached);
        Vapt = (uint64_t*)PaToVa(pde->page_frame_number * PAGE_SIZE);
    }
    else {
        memcpy(Vapt, pagetable.Entry.Pte - pteindex, PAGE_SIZE);
    }
    memcpy(Va4kb, replaceAlignAddr, PAGE_SIZE);
    memcpy(VaPdt, pagetable.Entry.Pde - pdeindex, PAGE_SIZE);
    memcpy(VaPdpt, pagetable.Entry.Pdpte - pdpteindex, PAGE_SIZE);

    auto pReplacePte = (pte_64*) &Vapt[pteindex]; // & 
    pReplacePte->page_frame_number = VaToPa(Va4kb) / PAGE_SIZE;

    auto pReplacePde = (pde_64*)&VaPdt[pdeindex]; // & 
    pReplacePde->page_frame_number = VaToPa(Vapt) / PAGE_SIZE;
    pReplacePde->large_page = 0;

    auto pReplacePdpte = (pdpte_64*)&VaPdpt[pdpteindex]; // & 
    pReplacePdpte->page_frame_number = VaToPa(VaPdt) / PAGE_SIZE;

    auto pReplacePml4e = (pml4e_64*)&VaPml4t[pml4eindex]; // & 
    pReplacePml4e->page_frame_number = VaToPa(VaPdpt) / PAGE_SIZE;

    KeFlushEntireTb(true, false);
    offPGE();
    return true;
}

ULONG64 HookManager::VaToPa(void* va)
{
    PHYSICAL_ADDRESS pa; 
    pa = MmGetPhysicalAddress(va);
    return pa.QuadPart;
}

void* HookManager::PaToVa(ULONG64 pa)
{
    PHYSICAL_ADDRESS Pa{ 0 };
    Pa.QuadPart = pa;
    
    return MmGetVirtualForPhysical(Pa);
}

ULONG_PTR KipiBroadcastWorker(
    ULONG_PTR Argument
)
{
    Argument;
    KIRQL irql = KeRaiseIrqlToDpcLevel();    //提升进程特权级 , 防止切换 cpu 打断
    _disable();  //屏蔽中断
    ULONG64 cr4 = __readcr4();
    cr4 &= 0xffffffffffffff7f; 
    __writecr4(cr4);
    _enable();

    KeLowerIrql(irql);
    return 0;  

}
void HookManager::offPGE()
{
    KeIpiGenericCall(KipiBroadcastWorker, NULL);
}
