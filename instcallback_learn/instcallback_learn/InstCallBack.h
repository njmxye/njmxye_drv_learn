#pragma once
#include "ShellCode.h"
#include "Logger.h"
NTSTATUS inst_callback_inject(HANDLE process_id, UNICODE_STRING* ws_dll_path);