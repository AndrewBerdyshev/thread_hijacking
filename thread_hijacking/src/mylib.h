#pragma once
#include <Windows.h>
#include <cstdint>
#include <TlHelp32.h>

namespace mylib
{
	size_t GetFuncSize(void* func);
	uint32_t GetProcessID(const char* processName);
	uint32_t GetThreadID(uint32_t processID);
}