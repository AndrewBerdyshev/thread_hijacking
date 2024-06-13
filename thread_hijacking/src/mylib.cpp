#include "mylib.h"

size_t mylib::GetFuncSize(void* func)
{
	size_t result = 0;
	for (; *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(func) + result++) != 0xCCCCCCCC;);
	return result + 3; // 0xCCCCCCCC included.
}

uint32_t mylib::GetProcessID(const char* processName)
{
	auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);

	Process32First(snapshot, &entry);
	do
	{
		if (!strcmp(entry.szExeFile, processName))
		{
			CloseHandle(snapshot);
			return entry.th32ProcessID;
		}
	} while (Process32Next(snapshot, &entry));
	CloseHandle(snapshot);
	return NULL;
}

uint32_t mylib::GetThreadID(uint32_t processID)
{
	auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	THREADENTRY32 entry;
	entry.dwSize = sizeof(entry);

	Thread32First(snapshot, &entry);
	do
	{
		if (entry.th32OwnerProcessID == processID)
		{
			CloseHandle(snapshot);
			return entry.th32ThreadID;
		}
	} while (Thread32Next(snapshot, &entry));
	CloseHandle(snapshot);
	return NULL;
}
