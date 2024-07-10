#include "thread_hijacking.h"

void threadhijacking::ThreadHijacking(IOCTLProcess* process, ThreadProcess* thread, void* remoteOurFunc, void* param)
{
    // Shellcode to execute remoteourFunc.
    uint8_t shellcode[] = {
        // Preserve registers.
        0x50, // push rax
        0x53, // push rbx
        0x51, // push rcx
        0x52, // push rdx
        0x56, // push rsi
        0x57, // push rdi
        0x41, 0x50, // push r8
        0x41, 0x51, // push r9
        0x41, 0x52, // push r10
        0x41, 0x53, // push r11
        0x41, 0x54, // push r12
        0x41, 0x55, // push r13
        0x41, 0x56, // push r14
        0x41, 0x57, // push r15
        0x48, 0x83, 0xec, 0x28, // sub rsp, 40 // Works fine if rsp address on suspending ends with 8. no reason for alligning then...

        // Execute our func.
        //0x48, 0x83, 0xe4, 0xf0, // and rsp, 0xFFFFFFFFFFFFFFF0 - align the stack.
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, <funcArg>
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <funcAddr>
        0xff, 0xd0, // call rax

        0x48, 0x83, 0xc4, 0x28, // add rsp, 40
        // Restore registers.
        0x41, 0x5f, // pop r15
        0x41, 0x5e, // pop r14
        0x41, 0x5d, // pop r13
        0x41, 0x5c, // pop r12
        0x41, 0x5b, // pop r11
        0x41, 0x5a, // pop r10
        0x41, 0x59, // pop r9
        0x41, 0x58, // pop r8
        0x5f, // pop rdi
        0x5e, // pop rsi
        0x5a, // pop rdx
        0x59, // pop rcx
        0x5b, // pop rbx
        0x58, // pop rax

        // Jump to original code.
        0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00, // mov [rsp-08], <ra1>
        0xc7, 0x44, 0x24, 0xfc, 0x00, 0x00, 0x00, 0x00, // mov [rsp-04], <ra2>
        0x48, 0x83, 0xec, 0x08, // sub rsp,08 - will be restored by ret.
        0xc3, // ret
    };

    auto funcArg = reinterpret_cast<uint64_t>(param);
    memcpy(shellcode + 32-4, &funcArg, 8);
    auto funcAddr = reinterpret_cast<uint64_t>(remoteOurFunc);
    memcpy(shellcode + 42-4, &funcAddr, 8);

    // Find a thread, stop thread, fake rip.
    auto threadID = thread->GetThreadId();
    auto tempThread = thread->OpenThread(threadID);
    thread->SuspendThread(tempThread);

    const auto alloc = process->Alloc(sizeof(shellcode));

    auto rip = reinterpret_cast<uint64_t>(alloc);
    thread->ChangeRip(tempThread, &rip);

    auto ra1 = static_cast<uint32_t>(rip & 0xFFFFFFFF);
    memcpy(shellcode + 82 - 4, &ra1, 4);
    auto ra2 = static_cast<uint32_t>(rip >> 32);
    memcpy(shellcode + 90 - 4, &ra2, 4);

    process->Write(alloc, reinterpret_cast<uint8_t*>(&shellcode), sizeof(shellcode));

    thread->ResumeThread(tempThread);
    thread->CloseHandle(tempThread);
    process->Free(alloc, sizeof(shellcode));
}