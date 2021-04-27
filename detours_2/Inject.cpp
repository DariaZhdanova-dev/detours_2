#include "Inject.h"
#include <psapi.h>

DWORD GetProcess(LPCTSTR procName)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    DWORD aProcesses[1024], cbNeeded=0, cProcesses =0;
    unsigned int i;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 0;
    }
    cProcesses = cbNeeded / sizeof(DWORD);
    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            if (NULL != hProcess)
            {
                DWORD err = GetProcessImageFileName(hProcess, szProcessName, MAX_PATH);
                if (err == 0)
                {
                    if (lstrcmp(szProcessName, procName) == 0)
                    {
                        return aProcesses[i];
                    }
                }
            }
            CloseHandle(hProcess);
        }
    }
    return 0;
}

DWORD getProcessID(LPCTSTR procName)
{
    DWORD processID = 0;
    HANDLE snapHandle;
    PROCESSENTRY32 processEntry = { 0 };
    if ((snapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
    {
        return 0;
    }
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    Process32First(snapHandle, &processEntry);
    do {
        if (wcscmp(processEntry.szExeFile, procName) == 0) {
            return processEntry.th32ProcessID;
        }
    } while (Process32Next(snapHandle, &processEntry));

    if (snapHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(snapHandle);
    }
    return 0;
}

BOOL setPrivilege(HANDLE hToken, LPCTSTR szPrivName, BOOL fEnable) 
{
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    LookupPrivilegeValue(NULL, szPrivName, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    return((GetLastError() == ERROR_SUCCESS));
}

HANDLE lab2_injection(DWORD procID, LPCWSTR dllname)
{
    HANDLE hCurrentProc = GetCurrentProcess();
    HANDLE hToken = NULL;
    LPVOID dll_name = NULL;
    HANDLE processHandel = NULL;
    DWORD dwWritten = 0;
    LPVOID load_library = NULL;
    DWORD ThreadID = 0;
    HANDLE hThread = NULL;
    if (!OpenProcessToken(hCurrentProc, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        LAB2_PRINTF("OpenProcessToken Error 0x%x!", GetLastError());
        goto clean;
    }
    else 
    {
        if (!setPrivilege(hToken, SE_DEBUG_NAME, TRUE)) 
        {
            LAB2_PRINTF("SetPrivlegesSE_DEBUG_NAME 0x%x", GetLastError());
            goto clean;
        }
    }
    processHandel = OpenProcess(PROCESS_ALL_ACCESS, false, procID);
    dll_name = VirtualAllocEx(processHandel, NULL, MAX_PATH * sizeof(TCHAR), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (WriteProcessMemory(processHandel, dll_name, dllname, (lstrlen(dllname)+1)*sizeof(TCHAR), &dwWritten) == 0) {
        LAB2_PRINTF("WriteProcessMemory error Ox%x", GetLastError());
        goto clean;
    }
#ifdef UNICODE
    load_library = GetProcAddress(LoadLibrary(TEXT("kernel32.dll")), "LoadLibraryW");
#else
    LPVOID load_library = GetProcAddress(LoadLibrary(TEXT("kernel32.dll")), "LoadLibraryA");
#endif
    hThread = CreateRemoteThread(processHandel, NULL, 0, (LPTHREAD_START_ROUTINE)load_library, dll_name, 0, &ThreadID);
    if (hThread == NULL) 
    {
        LAB2_PRINTF("WriteProcessMemory error Ox%x", GetLastError());
        goto clean;
    }
clean:
    if (processHandel != NULL)
    {
        CloseHandle(processHandel);
    }
    if (hToken != NULL)
    {
        CloseHandle(hToken);
    }
    return hThread;
}
    
void usage()
{
	printf("\nLAB2Inject.exe <target_proc>...");
}

int main(int argc, char ** argv)
{
    LPCTSTR proc_name = TEXT("notepad.exe");
    LPCTSTR dll_name = TEXT("Hook.dll");
    TCHAR full_dll_path[MAX_PATH];
    memset(full_dll_path, 0, MAX_PATH);
    if (GetFullPathName(dll_name, sizeof(full_dll_path) / sizeof(TCHAR), full_dll_path, NULL) == 0)
    {
        LAB2_PRINTF("error: unable get full path of %s", dll_name);
        return 2;
    }
	if (argc < 1)
	{
		usage();
		return 1;
	}
	LAB2_PRINTF("Starting ... ");
    
    lab2_injection(getProcessID(proc_name), full_dll_path);
	return 0;
} 