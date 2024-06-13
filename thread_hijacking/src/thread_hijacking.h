#pragma once
#include "mylib.h"

namespace threadhijacking
{
	void ThreadHijacking(const HANDLE process, void* remoteOurFunc, void* param);
}