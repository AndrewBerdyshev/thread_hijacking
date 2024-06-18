#include "../src/thread_hijacking.h"

int main()
{
	// Failed. Why? HUI ZNAET!
	const auto process = OpenProcess(PROCESS_ALL_ACCESS, false, mylib::GetProcessID("cs2.exe"));
	const auto alloc = VirtualAllocEx(process, nullptr, 78, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	const char path[] = { "C:\\Users\\anber\\source\\repos\\AndrewBerdyshev\\temp_dll\\x64\\Release\\temp_dll.dll" };
	WriteProcessMemory(process, alloc, path, 78, nullptr);
	threadhijacking::ThreadHijacking(process, LoadLibraryA, alloc);
	return 0;
}