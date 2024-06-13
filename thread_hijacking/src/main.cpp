#include "thread_hijacking.h"

int main()
{
	const auto process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, mylib::GetProcessID("notepad.exe"));
	auto str = "C:\\Users\\anber\\source\\repos\\AndrewBerdyshev\\manual_mapping\\manual_mapping\\build\\cheat.dll";
	const auto alloc = VirtualAllocEx(process, nullptr, 90, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(process, alloc, str, 90, nullptr);
	threadhijacking::ThreadHijacking(process, LoadLibraryA, alloc);
	return 0;
}