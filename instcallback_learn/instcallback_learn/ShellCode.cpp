#include"ShellCode.h"
//使用自定位,找到pData 这里pData是通过RCX传进来的
void __stdcall InstruShellCode(Manual_Mapping_data* pData) {



	if (!pData->bFirst) return;

	//成功 立刻设置 防止重入
	pData->bFirst = false;
	//已经加载shellcode了可以卸载instrcall了
	pData->bStart = true;
	//拿到已经加载到内存中的PE结构起始地址
	char* pBase = pData->pBase;
	//拿到选项头
	auto* pOptionHeadr = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;


	//ImageBase 镜像基地址，或者说主模块基地址，在开启随机基址的情况下，该值仍然会有但是无效了。*

	char* LocationDelta = pBase - pOptionHeadr->ImageBase; //计算出差值 到时候需要将需要重定位的地址加上这个差值进行手动重定位

	//开始模拟重定位表进行手动重定位
	if (LocationDelta) {
		//第五项就是重定位表 从0开始数
		if (pOptionHeadr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			//VirtualAddress 该节拷贝到内存中的RVA
			//定位到重定位表数据
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOptionHeadr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			//计算重定位表的截至地址
			auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOptionHeadr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

			//开始遍历重定位表
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				//计算出重定位表中的TypeOffset数组的个数 也就是当前重定位表项中的保存的RVA的个数
				//重定位的个数不包括IMAGE_BASE_RELOCATION这个地方
				//重定位的偏移的大小是WORD
				UINT64 AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(short);//typeoffset中 RVA 占低12位
				//指向重定位的偏移
				//typedef struct _IMAGE_BASE_RELOCATION {
				//	DWORD   VirtualAddress; //重定位表起始地址的RVA
				//	DWORD   SizeOfBlock;
				//	//  WORD    TypeOffset[1];
				//Windows重定位表是按页涉及的
				//相近的地址,都放在了这一个RVA里面.
				//TypeOffset中高4位是这个重定表项的类型
				//低12位 表示在这个一页(4KB)的偏移

				//拿到第一个typeoffset中的RVA
				unsigned short* pRelativeInfo = reinterpret_cast<unsigned short*>(pRelocData + 1);
				//++pRelativeInfo 拿到第下个typeoffset中的RVA
				for (UINT64 i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) { //typeoffset的高4位是 重定位类型 如果是x64位直接寻址我们进行重定位
						//只有直接寻址才需要重定位
						//pBase+RVA==需要重定位页面
						//页面+0xfff & TypeOffset 就是要重定位的地址(一个直接地址)
						//计算出需要重定位的地址
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						//进行手动重定位
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				//下一个重定位表(毕竟不止一个页面需要重定位)
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<char*>(pRelocData) + pRelocData->SizeOfBlock);
			}

		}
	}
	/*
	IMAGE_DATA_DIRECTORY STRUCT
	DWORD   VirtualAddress; //表项的RVA 这里不写FA的原因是因为操作系统是在内存中填写该值（要等dll加载到内存中才能填）
	DWORD   Size;           //表项的大小 仅供参考，系统没用这个大小，系统是看该表结构来判断大小的

	_IMAGE_IMPORT_DESCRIPTOR
		IMAGE_THUNK_DATA 导入名称表（Import Name Table）  INT 的数组
			IMAGE_IMPOART_BY_NAME
		IMAGE_THUNK_DATA 导入地址表（Import Address Table）
			IATIMAGE_IMPOART_BY_NAME
	IMAGE_THUNK_DATA64 {
	union {
		ULONGLONG ForwarderString;  // PBYTE
		ULONGLONG Function;         // 当前dll模块导入的函数地址的RVA
		ULONGLONG Ordinal;          //Ordinal 被输入的API的序号值，当最高位为1的时候，该位启用，有效值只有两个字节，也就是低两位，MFCdll常用序号导出
		ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
	} u1;

	*/
	//修复IAT表中的函数地址 并且手动加载对应dll
	if (pOptionHeadr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		//拿到导入表描述符 一个dll对应一个导入表描述符 一个调入表描述符里面包含这个dll所导出的函数
		IMAGE_IMPORT_DESCRIPTOR* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOptionHeadr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		//指向模块名称字符串的RVA地址
		while (pImportDescr->Name) {
			//手动加载dll
			HMODULE hDll = pData->pLoadLibraryA(pBase + pImportDescr->Name);//应用层的inline hook确实可以保护拦截 但是我们这加载的都是他自己导入表的dll
			//单反正常思维的他都不可能拦截自己需要用的dll 要不然他自己也跑不起来
//拿到INT表和IAT表
//INT
			ULONG_PTR* pInt = (ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk);
			//IAT MFC的dll一般是靠名称导出的
			ULONG_PTR* pIat = (ULONG_PTR*)(pBase + pImportDescr->FirstThunk);
			//如果不存在int我们吧iat表给int 因为我们最后都是修改int表 直接改int表中保存的地址 ULONGLONG Function;
			if (!pInt) pInt = pIat;
			//Ordinal 被输入的API的序号值，当最高位为1的时候，该位启用，有效值只有两个字节，也就是低两位，MFCdll常用序号导出
			for (; *pIat; ++pIat, ++pInt) {
				//如果是序号导出最高位为1
				if (IMAGE_SNAP_BY_ORDINAL(*pInt)) {
					//如果是序号导出 低两个字节保存的是函数序号
					//修改 ULONGLONG Function;
					*pIat = (ULONG_PTR)pData->pGetProcAddress(hDll, (char*)(*pInt & 0xffff));

				}
				else
				{
					//如果是名称导出 
					//那我们先拿到IMAGE_IMPORT_BY_NAME保存的函数名字
					//因为你如果是序号导出 IMAGE_IMPORT_BY_NAME 中指向的函数名称是空的
					IMAGE_IMPORT_BY_NAME* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + *pInt);
					*pIat = (ULONG_PTR)pData->pGetProcAddress(hDll, pImport->Name);
				}
			}
			pImportDescr++; //拿到下一个dll的导入表描述符
		}
	}

	//手动调用TLS回调函数
	//就算你dll中没有用TLS机制 但不保证你要注入的dll包含其他库的dll里面里有没有用TLS
	//用了就要手动调用
	//注意一定要先手动重定位 再调用TLS回调函数 因为TLS回调函数 中保存的是VA地址
	//需要先通过重定位表进行重定位
#define DLL_PROCESS_ATTACH 1 
	if (pOptionHeadr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptionHeadr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		//注意 这里要进行重定位
		//TLS表的CallBack要加LocationDelta
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks); //拿到TLS回到函数表
		//遍历TLS回调函数表
		for (; pCallback && *pCallback; ++pCallback) {
			//手动调用
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}


	//修复x64下异常表
	auto excep = pOptionHeadr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (excep.Size) {
		pData->pRtlAddFunctionTable((_IMAGE_RUNTIME_FUNCTION_ENTRY*)(pBase + excep.VirtualAddress), excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase);

	}

	//等待抹掉PE头和卸载instrcallback
	while (!pData->bContinue);
	//执行DllMain函数
	((f_DLL_ENTRY_POINT)(pBase + pOptionHeadr->AddressOfEntryPoint))(pBase, DLL_PROCESS_ATTACH, 0);


}