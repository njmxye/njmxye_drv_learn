#pragma once
#include <ntddk.h>
void Log(const char* sz_info, bool is_error, ULONG err_code);