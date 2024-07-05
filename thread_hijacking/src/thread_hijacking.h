#pragma once
#include <Windows.h>
#include <cstdint>
#include <mylib.h>
#pragma comment(lib, "external\\mylib.lib")

namespace threadhijacking
{
	void ThreadHijacking(const HANDLE process, void* remoteOurFunc, void* param);
}