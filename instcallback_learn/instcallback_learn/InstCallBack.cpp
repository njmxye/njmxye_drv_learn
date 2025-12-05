#include "InstCallBack.h"
#include "HideMemory.h"

#pragma warning (disable : 4838)
#pragma warning (disable : 4309)
#pragma warning (disable : 5040)



//CallBack Shellcode
UINT64 g_fnLoadLibrary = 0;
UINT64 g_fnGetProcAddress = 0;
UINT64 g_fnAddFuntionTable = 0;

#pragma pack(push)    //保存当前内存对齐状态
#pragma pack(1) //设置内存对齐值为1 相当于没有内存对齐的概念
struct shellcode_t {
private:
	char padding[43];//43
public:
	uintptr_t manual_data;//8 重定位结构体
private:
	char pdding[47];
public:
	uintptr_t rip;
	uintptr_t shellcode;
};

//shell_code
char g_instcall_shellcode[] =
{
	0x50,//push rax
	0x51, //push  rcx   
	0x52, //push  rdx
	0x53, //push  rbx												//
	0x55, 															//
	0x56, 															//
	0x57, 															//
	0x41, 0x50, 													//
	0x41, 0x51, 													//
	0x41, 0x52, 													//
	0x41, 0x53, 													//
	0x41, 0x54, 													//
	0x41, 0x55, 													//
	0x41, 0x56, 													//
	0x41, 0x57, 													//
	//上面都是保存寄存器
	// sub rsp,0x20
	//把rsp保存过去
	0x48,0x89,0x25,0x4c,0x00,0x00,0x00,//将rsp保存
	0x48,0x83,0xec,0x38,
	0x48,0x81,0xe4,0xf0,0xff,0xff,0xff, //强行对齐

	//00000217F568001 | 48:83EC 20 | sub rsp,0x20 |
	//00000217F568001 | 48 : 83C4 20 | add rsp,0x20 |
	//Call ShellCode 进行重定位

	0x48, 0xB9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,  //mov rcx,重定位数据

	0xFF, 0x15, 0x29, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,//call 地址

	//恢复寄存器
	0x48,0x8b,0x25,0x22,0x00,0x00,0x00,//将原来的rsp恢复
	//add rsp,0x20
	//pop 寄存器
	0x41, 0x5F,
	0x41, 0x5E,
	0x41, 0x5D,
	0x41, 0x5C,
	0x41, 0x5B,
	0x41, 0x5A,
	0x41, 0x59,
	0x41, 0x58,
	0x5F,
	0x5E,
	0x5D,
	0x5B,
	0x5A,
	0x59,
	0x58,//pop rax
	0x41, 0xFF, 0xE2,  //jmp r10 返回  不是InstCall注入 RIP要换地方
	//0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,//call 地址
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0 //原来的rsp放在这
};
#pragma pack(pop) //恢复当前内存对齐状态

PUCHAR inst_callback_get_dll_memory(UNICODE_STRING* us_dll_path) {
	HANDLE hFile = 0;
	OBJECT_ATTRIBUTES objattr;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	LARGE_INTEGER		lainter = { 0 };
	NTSTATUS status;
	FILE_STANDARD_INFORMATION	fileinfo = { 0 };
	ULONG FileSize = 0; //dll文件大小
	PUCHAR pDllMemory = 0; //dll文件加载到内存中的地址
	LARGE_INTEGER byteoffset = { 0 };//读取文件的偏移开始
	//设置对象属性
	InitializeObjectAttributes(&objattr, us_dll_path, OBJ_CASE_INSENSITIVE, 0, 0);

	status = ZwCreateFile(&hFile, GENERIC_READ, &objattr, &IoStatusBlock, &lainter, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, FILE_OPEN, 0, 0, 0);
	if (!NT_SUCCESS(status)) {
		Log("failed to create file123", true, status);
		Log("failed to create file", true, status);
		status = STATUS_UNSUCCESSFUL;
		return 0;
	}
	//获取文件大小
	status = ZwQueryInformationFile(hFile, &IoStatusBlock, &fileinfo, sizeof(fileinfo), FileStandardInformation);
	FileSize = (ULONG)fileinfo.AllocationSize.QuadPart;
	if (!NT_SUCCESS(status)) {
		Log("failed to get file size", true, status);
		return 0;
	}
	//内存对齐
	FileSize += 0x1000; //加0x1000在对齐 免得对齐后还变小了
	FileSize = (UINT64)PAGE_ALIGN(FileSize);
	//分配内存空间
	pDllMemory = (PUCHAR)ExAllocatePoolWithTag(PagedPool, FileSize, 'Dllp'); //文件塞进去
	RtlSecureZeroMemory(pDllMemory, FileSize);


	status = ZwReadFile(hFile, 0, 0, 0, &IoStatusBlock, pDllMemory, FileSize, &byteoffset, 0);
	//刷新一下 要不然会卡顿
	ZwFlushBuffersFile(hFile, &IoStatusBlock);
	if (!NT_SUCCESS(status)) {
		ExFreePool(pDllMemory);
		ZwClose(hFile);

		Log("failed to read file content", true, status);
		return 0;
	}

	ZwClose(hFile);
	return pDllMemory;
}

NTSTATUS inst_callback_alloc_memory(HANDLE PID, PUCHAR p_dll_memory, _Out_ PVOID* inst_callbak_addr, _Out_ PVOID* p_manual_data) {
	PEPROCESS Process{ 0 };
	//已经挂靠了避免重复挂靠
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOptHeader = nullptr;
	IMAGE_FILE_HEADER* pFileHeader = nullptr;

	char* pStartMapAddr = nullptr;//R3层地址 通过ZwAllocatevirtual Dll从PE头开始的地址
	size_t AllocSize = 0, RetSize;
	size_t DllSize;
	Manual_Mapping_data ManualMapData{ 0 };
	PVOID pManualMapData = 0, pShellCode = 0;//分配的内存,一个是映射结构地址,一个是ShellCode地址 
	NTSTATUS status = STATUS_SUCCESS;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(p_dll_memory)->e_magic != 0x5A4D) {
		status = STATUS_INVALID_PARAMETER;
		Log("the dll is not an valid file structure", true, status);
		return status;
	}
	//获取NT头 通过NT头获取文件头 和 选项头
	pNtHeader = (IMAGE_NT_HEADERS*)((ULONG_PTR)p_dll_memory + reinterpret_cast<IMAGE_DOS_HEADER*>(p_dll_memory)->e_lfanew);
	pFileHeader = &pNtHeader->FileHeader;
	pOptHeader = &pNtHeader->OptionalHeader;

	//Machine 运行平台，更准确的来说应该是CPU的指令集，用来表明可执行文件运行在哪种类型的CPU上。 
	//IMAGE_FILE_MACHINE_I386，0x14C，也是通过该字段来判断IMAGE_NT_HEADER是使用32位的结构还是64位的结构
	if (pFileHeader->Machine != X64) {
		status = STATUS_NOT_SUPPORTED;
		Log("the dll is x86 structure,not support", true, status);
		return status;
	}
	//SizeOfImage 镜像载入内存中的总大小，该值是内存对齐的倍数，总大小即所有节（包括头）映射进内存的总大小。
	AllocSize = pOptHeader->SizeOfImage;
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pStartMapAddr, 0, &AllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)) {

		Log("failed to alloc memory", true, status);
		return status;
	}
	DllSize = AllocSize;
	//清空
	RtlSecureZeroMemory(pStartMapAddr, AllocSize);

	//初始化ManualMapData 这个结构体会通过shellcode的RCX寄存器传给重定位shellcode
	//并且通过判断这些结构体中的标志位来及时取消instcall回调和隐藏卸载PE结构
	ManualMapData.dwReadson = 0;
	ManualMapData.pGetProcAddress = (f_GetProcAddress)g_fnGetProcAddress;
	ManualMapData.pLoadLibraryA = (f_LoadLibraryA)g_fnLoadLibrary;
	ManualMapData.pRtlAddFunctionTable = (f_RtlAddFunctionTable)g_fnAddFuntionTable;

	ManualMapData.pBase = pStartMapAddr;
	ManualMapData.bContinue = false; //这个标志用来判断是否抹掉了注入DLL的PE标志 抹掉后再调用dllmain
	ManualMapData.bFirst = true; //是否是第一次加载 如果是第一次则运行shellcode  因为只要是系统调用他都会走instrcall 我们只让他走一次instrcall就行了
	ManualMapData.bStart = false;//这个标志用来判断是否开始执行shellcode了 开始运行了instrucall就没用了 及时取消instrcall 并且有的函数有instrcall标志调用会崩溃
	ManualMapData.DllSize = DllSize;

	//开始按照内存对齐拉伸区块（section）
	//这里直接拷贝一个页的大小 PE结构映射到内存中
	//这里拷贝了了 DOS头 NT头 区块表 吧这三个结构视作一个区块
	Process = IoGetCurrentProcess();
	status = MmCopyVirtualMemory(Process, p_dll_memory, Process, pStartMapAddr, PAGE_SIZE, KernelMode, &RetSize);
	if (!NT_SUCCESS(status)) {
		Log("failed to write pe header!", true, status);
		return status;
	}

	//开始拉伸各区块
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader); //取到第一个区块的指针 （这时候还在文件中）
	//遍历每个区块头 拉伸各个区块
	for (int i = 0; i < pFileHeader->NumberOfSections; i++, pSectionHeader++) {
		if (pSectionHeader->SizeOfRawData) {
			//这一步将各节区的数据写入到虚拟地址,且已经对齐 FA->RVA转换
			/*
			VirtualSize 在内存中的大小，内存对齐前的数值**
			VirtualAddress 该节拷贝到内存中的RVA
			SizeOfRawData 该节在文件中的大小，文件对其后的值。
			PointerToRawData 该节在文件中的偏移FA（file address）
			*/
			status = MmCopyVirtualMemory(Process, p_dll_memory + pSectionHeader->PointerToRawData, Process, pStartMapAddr + pSectionHeader->VirtualAddress, pSectionHeader->SizeOfRawData, KernelMode, &RetSize);
			if (!NT_SUCCESS(status)) {
				Log("failed to write sections", true, status);
				return status;
			}
		}
	}
	//开始映射ManualMapData
	AllocSize = PAGE_SIZE;
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pManualMapData, 0, &AllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)) {
		Log("failed to alloc mem for manualdata", true, status);
		return status;
	}
	RtlSecureZeroMemory(pManualMapData, AllocSize);

	status = MmCopyVirtualMemory(Process, &ManualMapData, Process, pManualMapData, sizeof(ManualMapData), KernelMode, &RetSize);
	if (!NT_SUCCESS(status)) {

		Log("failed to write mem for manualdata", true, status);
		return status;
	}
	//开始映射 shellcode
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pShellCode, 0, &AllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)) {

		Log("failed to alloc mem for shellcode", true, status);
		return status;
	}

	RtlSecureZeroMemory(pShellCode, AllocSize);

	//写入shellcode
	status = MmCopyVirtualMemory(Process, InstruShellCode, Process, pShellCode, AllocSize, KernelMode, &RetSize);
	if (!NT_SUCCESS(status)) {

		Log("failed to write mem for shellcode", true, status);
		return status;
	}

	shellcode_t shell_code;
	memset(&shell_code, 0, sizeof shell_code);
	//吧shellcode拷贝到结构体中
	memcpy(&shell_code, &g_instcall_shellcode, sizeof shellcode_t);
	shell_code.manual_data = (UINT64)pManualMapData;//相关数据 要通过RCX传入
	shell_code.rip = (UINT64)pShellCode; //PE加载器

	//分配shellcode inst_callbak_addr传出函数 instrcallback 要指向shellcode
	ZwAllocateVirtualMemory(NtCurrentProcess(), inst_callbak_addr, 0, &AllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)) {
		Log("failed to alloc mem for instcall shellcode", true, status);
		return status;
	}
	RtlSecureZeroMemory(*inst_callbak_addr, AllocSize);

	//写入InstCallBack ShellCode
	MmCopyVirtualMemory(Process, &shell_code, Process, *inst_callbak_addr, sizeof shell_code, KernelMode, &RetSize);
	if (!NT_SUCCESS(status)) {
		Log("failed to write mem for instcall shellcode", true, status);
		return status;
	}


	*p_manual_data = pManualMapData; //吧配置信息结构体传出去

	for (size_t index = 0; index < DllSize; index += PAGE_SIZE)

		hide_mem(PID, (void*)((UINT64)pStartMapAddr + index), MM_NOACCESS);  //进行内存隐藏 注入PUBG

	hide_mem(PID, pManualMapData, MM_NOACCESS);

	hide_mem(PID, pShellCode, MM_NOACCESS);

	hide_mem(PID, (void*)inst_callbak_addr, MM_NOACCESS);
	return status;
}

NTSTATUS inst_callback_set_callback(PVOID inst_callback) {
	NTSTATUS status = STATUS_SUCCESS;
	PACCESS_TOKEN Token{ 0 };
	PULONG TokenMask{ 0 };
	PVOID InstCallBack = inst_callback;//instcallback地址



	Token = PsReferencePrimaryToken(IoGetCurrentProcess());

	//设置调试位
	TokenMask = (PULONG)((ULONG_PTR)Token + 0x40);
	//21位是DEBUG权限(位20)
	TokenMask[0] |= 0x100000;
	TokenMask[1] |= 0x100000;
	TokenMask[2] |= 0x100000;

	//设置InstCallBack
	status = ZwSetInformationProcess(NtCurrentProcess(), ProcessInstrumentationCallback, &InstCallBack, sizeof(PVOID));

	if (!NT_SUCCESS(status)) Log("failed to set instcall back", true, status);
	else Log("set instcall back success", 0, 0);



	return status;
}

NTSTATUS inst_callback_inject(HANDLE process_id, UNICODE_STRING* us_dll_path) {
	PEPROCESS Process{ 0 };
	NTSTATUS status = STATUS_SUCCESS;
	KAPC_STATE Apc{ 0 };
	PUCHAR pDllMem = 0;
	PVOID InstCallBack = 0;//shellcode 所在的内存地址设置为instcallback的地址
	PVOID pManualMapData = 0, pShellCode = 0;//分配的内存,一个是映射结构属性地址,一个是ShellCode地址
	status = PsLookupProcessByProcessId(process_id, &Process);
	if (!NT_SUCCESS(status)) {
		MYLOG("failed to get process", true);
		return status;
	}
	//吧线程挂靠到目标进程
	KeStackAttachProcess(Process, &Apc);

	while (TRUE) {
		//吧dll读到内存中
		pDllMem = inst_callback_get_dll_memory(us_dll_path);
		if (!pDllMem) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		//吧dll加载到内存中
		status = inst_callback_alloc_memory(process_id, pDllMem, &InstCallBack, &pManualMapData);
		if (!NT_SUCCESS(status)) break;

		//设置instrcallback使其指向shellcode
		status = inst_callback_set_callback(InstCallBack);
		break;
	}

	//当bstart为开始置1也就是开始手动加载dll的时候callback就可以去掉了
	if (pManualMapData && MmIsAddressValid(pManualMapData)) {
		//有可能这个时候进程退出了 所以需要异常处理一下
		__try {
			while (1) {
				if (((Manual_Mapping_data*)pManualMapData)->bStart) break;
			}
		}
		__except (1) {

			MYLOG("process exit!", true);
			ObDereferenceObject(Process);
			KeUnstackDetachProcess(&Apc);
			return status;
		}
	}

	//卸载
	inst_callback_set_callback(0);                                                                     //进程退出
	if (pManualMapData && MmIsAddressValid(pManualMapData) && PsLookupProcessByProcessId(process_id, &Process) != STATUS_PENDING) {
		__try {
			//抹掉PE头
			*(PUCHAR)((((Manual_Mapping_data*)pManualMapData))->pBase) = 0;
			//可以执行执行dllmain函数了
			((Manual_Mapping_data*)pManualMapData)->bContinue = true;
		}
		__except (1) {

			MYLOG("process exit?", true);
		}
	}


	ObDereferenceObject(Process);
	KeUnstackDetachProcess(&Apc);
	//释放从文件读到内存中的dll
	if (pDllMem && MmIsAddressValid(pDllMem)) ExFreePool(pDllMem);
	return status;
}