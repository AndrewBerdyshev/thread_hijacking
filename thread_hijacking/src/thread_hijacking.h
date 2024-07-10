#pragma once
#include <Windows.h>
#include <cstdint>
#include <handle_hijacking.h>

namespace threadhijacking
{
	void ThreadHijacking(IOCTLProcess* process, ThreadProcess* thread, void* remoteOurFunc, void* param);
}