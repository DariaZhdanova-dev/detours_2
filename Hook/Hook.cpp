#include "Hook.h"
#define MAX_PRINT_TEXT_LENGTH 1024
void DebugOut(const char* fmt, ...)
{
    char s[MAX_PRINT_TEXT_LENGTH];
    va_list args;
    va_start(args, fmt);
    vsnprintf(s, MAX_PRINT_TEXT_LENGTH, fmt, args);
    va_end(args);
    OutputDebugStringA(s);
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("");
        LAB2_PRINTF("Process Attach...");
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        break;

    case DLL_THREAD_ATTACH:
        LAB2_PRINTF("Thread Attach...");
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        LAB2_PRINTF("Thread Detach...");
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:
        LAB2_PRINTF("Process Detach...");
        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
 