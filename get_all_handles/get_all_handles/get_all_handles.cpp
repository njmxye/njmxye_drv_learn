// 包含Windows头文件，提供Windows API函数和数据类型的声明
#include <Windows.h>
// 包含标准输入输出流，用于控制台打印
#include <iostream>

// 定义系统信息类常量 - 16表示获取系统句柄信息
#define SystemHandleInformation 16
// 定义对象信息类常量 - 0表示获取对象基本信息
#define ObjectBasicInformation 0
// 定义对象信息类常量 - 1表示获取对象名称信息
#define ObjectNameInformation 1
// 定义对象信息类常量 - 2表示获取对象类型信息
#define ObjectTypeInformation 2
// 定义内存页大小 - Windows系统默认4KB
#define PAGE_SIZE 0x1000
// 定义NT_SUCCESS宏 - 判断NTStatus返回值是否成功（>=0表示成功）
#define NT_SUCCESS(x) ((x) >= 0)
// 定义状态码 - 表示缓冲区长度不匹配，需要重新分配
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

// 定义系统信息类枚举 - 用于NtQuerySystemInformation函数的第一个参数
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,                    // 系统基本信息
    SystemPerformanceInformation = 2,               // 系统性能信息
    SystemTimeOfDayInformation = 3,                 // 系统时间信息
    SystemProcessInformation = 5,                   // 系统进程信息
    SystemProcessorPerformanceInformation = 8,     // 处理器性能信息
    SystemInterruptInformation = 23,                // 中断信息
    SystemExceptionInformation = 33,               // 异常信息
    SystemRegistryQuotaInformation = 37,           // 注册表配额信息
    SystemLookasideInformation = 45                // Lookaside信息
} SYSTEM_INFORMATION_CLASS;

// 定义函数指针类型 - 指向NtQuerySystemInformation函数的指针
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,     // 系统信息类（告诉内核想要什么数据）
    PVOID SystemInformation,          // 输出缓冲区指针（内核把数据拷到这里）
    ULONG SystemInformationLength,    // 缓冲区长度（告诉内核缓冲区有多大）
    PULONG ReturnLength               // 实际返回长度（内核告诉你实际用了多少字节）
    );

// 动态获取NtQuerySystemInformation函数地址
// LoadLibraryA加载ntdll.dll，GetProcAddress获取函数地址
_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQuerySystemInformation");

// 定义单个句柄结构体 - 表示一个进程打开的一个句柄
typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;        // 拥有这个句柄的进程ID号
    BYTE ObjectTypeNumber;  // 句柄类型编号（文件、注册表、进程等）
    BYTE Flags;            // 句柄标志位
    USHORT Handle;         // 句柄值（进程内部的句柄编号）
    PVOID Object;          // 内核对象地址（内核空间地址）
    ACCESS_MASK GrantedAccess; // 访问权限掩码（允许对这个句柄做什么操作）
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

// 定义句柄信息结构体 - 包含所有句柄的数组和数量
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;              // 系统当前句柄总数
    SYSTEM_HANDLE Handles[1];       // 句柄数组（实际长度由HandleCount决定）
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

// 主函数 - 程序入口
int main() {
    // 初始化缓冲区大小为4KB，实际返回大小变量
    ULONG guess_size = PAGE_SIZE, real_size = 0;
    // 分配初始缓冲区，用于接收句柄信息
    SYSTEM_HANDLE_INFORMATION* handle_information = (SYSTEM_HANDLE_INFORMATION*)malloc(PAGE_SIZE);

    // 循环调用NtQuerySystemInformation直到缓冲区足够大
    // 如果返回STATUS_INFO_LENGTH_MISMATCH表示缓冲区太小，需要重新分配
    while (NtQuerySystemInformation(SystemHandleInformation, handle_information, guess_size, &real_size) == STATUS_INFO_LENGTH_MISMATCH)
    {
        free(handle_information);           // 释放旧缓冲区
        guess_size = real_size;            // 使用内核告诉我们的实际大小
        // 重新分配足够大的缓冲区
        handle_information= (SYSTEM_HANDLE_INFORMATION*)malloc(guess_size);
    }
    
    // 打印实际使用的缓冲区大小，让我们知道句柄信息有多大
    std::cout << "real size" << guess_size << std::endl;
    
    // 遍历所有句柄并打印详细信息
    for (int32_t idx = 0;  idx < handle_information->HandleCount;  idx++)
    {
        auto info = handle_information->Handles[idx];  // 获取当前句柄信息
        // 打印进程ID、句柄值、内核对象地址和访问权限
        std::cout << "pid:" <<info.ProcessId << "\t\thandle:" << info.Handle << "\t\tobject:" << info.Object << "\t\taccess" << info.GrantedAccess << std::endl;
    }

    return 0;  // 程序正常结束
}