#include "thread_hijacking.h"

void threadhijacking::ThreadHijacking(const HANDLE process, void* remoteOurFunc, void* param)
{
    // Shellcode to execute remoteourFunc.
    uint8_t shellcode[] = {
        // Preserve registers.
        0x50, // push rax
        0x51, // push rcx
        0x52, // push rdx
        0x53, // push rbx
        0x55, // push rbp
        0x56, // push rsi
        0x57, // push rdi

        // Execute our func.
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, <funcArg>
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <funcAddr>
        0xff, 0xd0, // call rax

        // Recover registers.
        0x5f, // pop rdi
        0x5e, // pop rsi
        0x5d, // pop rbp
        0x5b, // pop rbx
        0x5a, // pop rdx
        0x59, // pop rcx
        0x58, // pop rax

        // jmp to saved rip.
        0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00, // mov [rsp-08], <ra1>
        0xc7, 0x44, 0x24, 0xfc, 0x00, 0x00, 0x00, 0x00, // mov [rsp-04], <ra2>
        0x48, 0x83, 0xec, 0x08, // sub rsp,08
        0xc3, // ret
    };
    auto funcArg = reinterpret_cast<uint64_t>(param);
    memcpy(shellcode + 9, &funcArg, 8);
    auto funcAddr = reinterpret_cast<uint64_t>(remoteOurFunc);
    memcpy(shellcode + 19, &funcAddr, 8);

    // Find a thread, stop thread, fake rip.
    auto threadID = mylib::GetThreadID(GetProcessId(process));
    auto thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadID);
    SuspendThread(thread);
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thread, &context);

    auto ra1 = static_cast<uint32_t>(context.Rip & 0xFFFFFFFF);
    memcpy(shellcode + 40, &ra1, 4);
    auto ra2 = static_cast<uint32_t>(context.Rip >> 32);
    memcpy(shellcode + 48, &ra2, 4);

    // Upload shellcode.
    const auto alloc = VirtualAllocEx(process, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(process, alloc, &shellcode, sizeof(shellcode), nullptr);

    context.Rip = reinterpret_cast<uint64_t>(alloc);
    SetThreadContext(thread, &context);
    ResumeThread(thread);
    CloseHandle(thread);
    VirtualFreeEx(process, alloc, sizeof(shellcode), MEM_RELEASE);
}