#include<ntifs.h>
#include<ntddk.h>
#include<intrin.h>
#include"ia32/ia32.hpp" 
#include"PageTable.h"
#include"HookManager.h"

#pragma warning(disable:4389)
void* GetPteBase() {
	cr3 CR3;
	PHYSICAL_ADDRESS cr3_pa = { 0 };
	CR3.flags = __readcr3();
	cr3_pa.QuadPart = CR3.address_of_page_directory * PAGE_SIZE;
	PULONG64 cr3_va = (PULONG64)MmGetVirtualForPhysical(cr3_pa);

	UINT64 nCount = 0;
	while ((*cr3_va & 0x000FFFFFFFFFF000) != cr3_pa.QuadPart) {
		if (++nCount >= 512) {
			return nullptr;
		}
		cr3_va++;
	}
	return (void*)(0xffff000000000000 | (nCount << 39));
}

bool GetPageTable(PAGE_TABLE& table) {
	ULONG64 PteBase = 0;
	ULONG64 pdeBase = 0;
	ULONG64 pdpteBase = 0;
	ULONG64 pml4eBase = 0;

	PteBase = (ULONG64)GetPteBase();
	DbgPrint("PteBase :%p\n", PteBase);

	if (PteBase == NULL) return false;
	pdeBase = (((PteBase & 0xffffffffffff) >> 12) << 3) + PteBase;
	pdpteBase = (((pdeBase & 0xffffffffffff) >> 12) << 3) + PteBase;
	pml4eBase = (((pdpteBase & 0xffffffffffff) >> 12) << 3) + PteBase;

	table.Entry.Pte = (pte_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 12) << 3) + PteBase);
	table.Entry.Pde = (pde_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 21) << 3) + pdeBase);
	table.Entry.Pdpte = (pdpte_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 30) << 3) + pdpteBase);
	table.Entry.Pml4e = (pml4e_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 39) << 3) + pml4eBase);

	return true;
}