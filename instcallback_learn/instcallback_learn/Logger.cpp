#include "Logger.h"

void Log(const char* sz_info, bool is_error, ULONG err_code) {

	if (is_error) DbgPrintEx(77, 0, "[inst_callback_err]:%s err_code:%x\r\n", sz_info, err_code);
	else DbgPrintEx(77, 0, "[inst_callback_info]:%s\r\n", sz_info);
}