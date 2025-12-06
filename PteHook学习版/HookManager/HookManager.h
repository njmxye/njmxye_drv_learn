#pragma once
#include"structer.h"
#include"MDL.h"
#include"ia32/ia32.hpp"

class HookManager
{
	// 单例模式
public: 
	bool InstallInlinehook(HANDLE pid, __inout void** originAddr, void* hookAddr );
	bool RemoveInlinehook(HANDLE pid, void* hookAddr);
	static HookManager* GetInstance();

private: 
	bool IsolationPageTable(PEPROCESS process, void* isolateioAddr);
	bool SplitLargePage(pde_64 InPde, pde_64& OutPde ); // 大页分割成小页
	bool ReplacePageTable(cr3 cr3, void* replaceAlignAddr, pde_64* pde);

public:
	ULONG64 VaToPa(void* va);
	void* PaToVa(ULONG64 pa);
	void offPGE();

	UINT32 mHookCount = 0; 

	HOOK_INFO mHookInfo[MAX_HOOK_COUNT] = { 0 };

	char* mTrampLinePool = 0;
	UINT32 mPoolUSED = 0;

	static HookManager* mInstance;
};


struct PAGE_TABLE
{
	struct
	{
		pte_64* Pte;
		pde_64* Pde;
		pdpte_64* Pdpte;
		pml4e_64* Pml4e;
	}Entry;
	void* VirtualAddress;
};


