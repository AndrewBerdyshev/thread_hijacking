#pragma once
#include <Windows.h>
#include <cstdint>
#include <mylib.h>

namespace threadhijacking
{
	void ThreadHijacking(const HANDLE process, void* remoteOurFunc, void* param);
}