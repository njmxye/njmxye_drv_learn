#pragma once
#include"../structer.h"
#include"../MDL/MDL.h"
#include"../ia32/ia32.hpp"

class HookManager
{
	// 单例模式，分私有和公有，对外暴露需要被调用的接口和工具，对内隐藏实现细节和危险操作
public: 
	//安装inlinehook函数，需要参数句柄，原函数指针的指针，钩子函数指针
	//后文你会看见这个函数很长，很重要
	bool InstallInlinehook(HANDLE pid, __inout void** originAddr, void* hookAddr );
	//卸载inlinehook函数，需要参数句柄，钩子函数指针
	//这个函数并不长
	bool RemoveInlinehook(HANDLE pid, void* hookAddr);
	//静态函数，返回一个指向HookManager类的指针，后面会实现
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
	//创建一个HOOK_INFO结构体并初始化
	HOOK_INFO mHookInfo[MAX_HOOK_COUNT] = { 0 };
	
	char* mTrampLinePool = 0;
	UINT32 mPoolUSED = 0;
	//静态类型，指向HookManager类的指针
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


