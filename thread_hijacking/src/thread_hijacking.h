#pragma once
#include <Windows.h>
#include <cstdint>
#include <handle_hijacking.h>
#include <iostream>

namespace threadhijacking
{
	void ThreadHijacking(IOCTLProcess* process, ThreadProcess* thread, void* remoteOurFunc, void* param);
}