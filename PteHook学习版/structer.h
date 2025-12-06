#pragma once
#include<ntifs.h>
#include<ntddk.h>

#define MAX_HOOK_COUNT 10

typedef struct _HOOK_INFO {
	HANDLE pid;
	char originBytes[14];
	void* originAddr;
	

}HOOK_INFO, *PHOOK_INFO;