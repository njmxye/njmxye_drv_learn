#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <ntimage.h>

#pragma warning (disable : 4838)
#pragma warning (disable : 4309)

#define MAX_PATH 260

//确定是否需要重定位
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#define RELOC_FLAG RELOC_FLAG64

#define MYLOG(text,is_err,...) DbgPrintEx(77,0,"[drv_inject]:");\
	if(is_err)DbgPrintEx(77,0,"err,func_name:%s,line:%d   ",__FUNCTION__,__LINE__);\
	DbgPrintEx(77,0,text,__VA_ARGS__);\
	DbgPrintEx(77,0,"\r\n");


#define X64 0x8664
#define X86 0x14c

//不这样写就会重定义
extern UINT64 g_fnLoadLibrary;
extern UINT64 g_fnGetProcAddress;
extern UINT64 g_fnAddFuntionTable;

typedef PVOID HINSTANCE, HMODULE;

using f_LoadLibraryA = HINSTANCE(__stdcall*)(const char* lpLibFilename);
using f_GetProcAddress = PVOID(__stdcall*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOLEAN(__stdcall*)(void* hDll, DWORD32 dwReason, void* pReserved);
using f_RtlAddFunctionTable = BOOLEAN(__stdcall*)(_IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable, DWORD32 EntryCount, DWORD64 BaseAddress);

struct Manual_Mapping_data//内存映射dll对象
{
	//用于重定位IAT
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	//x64专有
	f_RtlAddFunctionTable pRtlAddFunctionTable;

	char* pBase;
	DWORD32 dwReadson;
	PVOID reservedParam;
	BOOLEAN bFirst;//只允许第一次系统调用进入
	BOOLEAN bStart;//开始执行shellcode了 可以同步关掉InstCallBack
	BOOLEAN bContinue;//用于继续执行 去掉PE头后执行dllmain
	//BOOLEAN clean;//可以改变属性了 去掉PE头了
	size_t DllSize;
};

void __stdcall InstruShellCode(Manual_Mapping_data* pData);

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationProcess(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__in_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
);

EXTERN_C
NTSTATUS
MmCopyVirtualMemory(PEPROCESS FromProcess, PVOID FromAddress,
	PEPROCESS ToProcess, PVOID ToAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
	PSIZE_T NumberOfBytesCopied);

