from __future__ import annotations
from typing import Set

malapi = {
    "enumeration": [
        "CreateToolhelp32Snapshot",
        "EnumDeviceDrivers",
        "EnumProcesses",
        "EnumProcessModules",
        "EnumProcessModulesEx",
        "FindFirstFileA",
        "FindNextFileA",
        "GetLogicalProcessorInformation",
        "GetLogicalProcessorInformationEx",
        "GetModuleBaseNameA",
        "GetSystemDefaultLangId",
        "GetVersionExA",
        "GetWindowsDirectoryA",
        "IsWoW64Process",
        "Module32First",
        "Module32Next",
        "Process32First",
        "Process32Next",
        "ReadProcessMemory",
        "Thread32First",
        "Thread32Next",
        "GetSystemDirectoryA",
        "GetSystemTime",
        "ReadFile",
        "GetComputerNameA",
        "VirtualQueryEx",
        "GetProcessIdOfThread",
        "GetProcessId",
        "GetCurrentThread",
        "GetCurrentThreadId",
        "GetThreadId",
        "GetThreadInformation",
        "GetCurrentProcess",
        "GetCurrentProcessId",
        "SearchPathA",
        "GetFileTime",
        "GetFileAttributesA",
        "LookupPrivilegeValueA",
        "LookupAccountNameA",
        "GetCurrentHwProfileA",
        "GetUserNameA",
        "RegEnumKeyExA",
        "RegEnumValueA",
        "RegQueryInfoKeyA",
        "RegQueryMultipleValuesA",
        "RegQueryValueExA",
        "NtQueryDirectoryFile",
        "NtQueryInformationProcess",
        "NtQuerySystemEnvironmentValueEx",
        "EnumDesktopWindows",
        "EnumWindows",
        "NetShareEnum",
        "NetShareGetInfo",
        "NetShareCheck",
        "GetAdaptersInfo",
        "PathFileExistsA",
        "GetNativeSystemInfo",
        "RtlGetVersion",
        "GetIpNetTable",
        "GetLogicalDrives",
        "GetDriveTypeA",
        "RegEnumKeyA",
        "WNetEnumResourceA",
        "WNetCloseEnum",
        "FindFirstUrlCacheEntryA",
        "FindNextUrlCacheEntryA",
        "WNetAddConnection2A",
        "WNetAddConnectionA",
        "EnumResourceTypesA",
        "EnumResourceTypesExA",
        "GetSystemTimeAsFileTime",
        "GetThreadLocale",
        "EnumSystemLocalesA",
    ],
    "injection": [
        "CreateFileMappingA",
        "CreateProcessA",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "GetModuleHandleA",
        "GetProcAddress",
        "GetThreadContext",
        "HeapCreate",
        "LoadLibraryA",
        "LoadLibraryExA",
        "LocalAlloc",
        "MapViewOfFile",
        "MapViewOfFile2",
        "MapViewOfFile3",
        "MapViewOfFileEx",
        "OpenThread",
        "Process32First",
        "Process32Next",
        "QueueUserAPC",
        "ReadProcessMemory",
        "ResumeThread",
        "SetProcessDEPPolicy",
        "SetThreadContext",
        "SuspendThread",
        "Thread32First",
        "Thread32Next",
        "Toolhelp32ReadProcessMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "VirtualAllocExNuma",
        "VirtualAlloc2",
        "VirtualAlloc2FromApp",
        "VirtualAllocFromApp",
        "VirtualProtectFromApp",
        "CreateThread",
        "WaitForSingleObject",
        "OpenProcess",
        "OpenFileMappingA",
        "GetProcessHeap",
        "GetProcessHeaps",
        "HeapAlloc",
        "HeapReAlloc",
        "GlobalAlloc",
        "AdjustTokenPrivileges",
        "CreateProcessAsUserA",
        "OpenProcessToken",
        "CreateProcessWithTokenW",
        "NtAdjustPrivilegesToken",
        "NtAllocateVirtualMemory",
        "NtContinue",
        "NtCreateProcess",
        "NtCreateProcessEx",
        "NtCreateSection",
        "NtCreateThread",
        "NtCreateThreadEx",
        "NtCreateUserProcess",
        "NtDuplicateObject",
        "NtMapViewOfSection",
        "NtOpenProcess",
        "NtOpenThread",
        "NtProtectVirtualMemory",
        "NtQueueApcThread",
        "NtQueueApcThreadEx",
        "NtQueueApcThreadEx2",
        "NtReadVirtualMemory",
        "NtResumeThread",
        "NtUnmapViewOfSection",
        "NtWaitForMultipleObjects",
        "NtWaitForSingleObject",
        "NtWriteVirtualMemory",
        "RtlCreateHeap",
        "LdrLoadDll",
        "RtlMoveMemory",
        "RtlCopyMemory",
        "SetPropA",
        "WaitForSingleObjectEx",
        "WaitForMultipleObjects",
        "WaitForMultipleObjectsEx",
        "KeInsertQueueApc",
        "Wow64SetThreadContext",
        "NtSuspendProcess",
        "NtResumeProcess",
        "DuplicateToken",
        "NtReadVirtualMemoryEx",
        "CreateProcessInternal",
        "EnumSystemLocalesA",
        "UuidFromStringA",
    ],
    "evasion": [
        "CreateFileMappingA",
        "DeleteFileA",
        "GetModuleHandleA",
        "GetProcAddress",
        "LoadLibraryA",
        "LoadLibraryExA",
        "LoadResource",
        "SetEnvironmentVariableA",
        "SetFileTime",
        "Sleep",
        "WaitForSingleObject",
        "SetFileAttributesA",
        "SleepEx",
        "NtDelayExecution",
        "NtWaitForMultipleObjects",
        "NtWaitForSingleObject",
        "CreateWindowExA",
        "RegisterHotKey",
        "timeSetEvent",
        "IcmpSendEcho",
        "WaitForSingleObjectEx",
        "WaitForMultipleObjects",
        "WaitForMultipleObjectsEx",
        "SetWaitableTimer",
        "CreateTimerQueueTimer",
        "CreateWaitableTimer",
        "SetWaitableTimer",
        "SetTimer",
        "Select",
        "ImpersonateLoggedOnUser",
        "SetThreadToken",
        "DuplicateToken",
        "SizeOfResource",
        "LockResource",
        "CreateProcessInternal",
        "TimeGetTime",
        "EnumSystemLocalesA",
        "UuidFromStringA",
    ],
    "spying": [
        "AttachThreadInput",
        "CallNextHookEx",
        "GetAsyncKeyState",
        "GetClipboardData",
        "GetDC",
        "GetDCEx",
        "GetForegroundWindow",
        "GetKeyboardState",
        "GetKeyState",
        "GetMessageA",
        "GetRawInputData",
        "GetWindowDC",
        "MapVirtualKeyA",
        "MapVirtualKeyExA",
        "PeekMessageA",
        "PostMessageA",
        "PostThreadMessageA",
        "RegisterHotKey",
        "RegisterRawInputDevices",
        "SendMessageA",
        "SendMessageCallbackA",
        "SendMessageTimeoutA",
        "SendNotifyMessageA",
        "SetWindowsHookExA",
        "SetWinEventHook",
        "UnhookWindowsHookEx",
        "BitBlt",
        "StretchBlt",
        "GetKeynameTextA",
    ],
    "internet": [
        "WinExec",
        "FtpPutFileA",
        "HttpOpenRequestA",
        "HttpSendRequestA",
        "HttpSendRequestExA",
        "InternetCloseHandle",
        "InternetOpenA",
        "InternetOpenUrlA",
        "InternetReadFile",
        "InternetReadFileExA",
        "InternetWriteFile",
        "URLDownloadToFile",
        "URLDownloadToCacheFile",
        "URLOpenBlockingStream",
        "URLOpenStream",
        "Accept",
        "Bind",
        "Connect",
        "Gethostbyname",
        "Inet_addr",
        "Recv",
        "Send",
        "WSAStartup",
        "Gethostname",
        "Socket",
        "WSACleanup",
        "Listen",
        "ShellExecuteA",
        "ShellExecuteExA",
        "DnsQuery_A",
        "DnsQueryEx",
        "WNetOpenEnumA",
        "FindFirstUrlCacheEntryA",
        "FindNextUrlCacheEntryA",
        "InternetConnectA",
        "InternetSetOptionA",
        "WSASocketA",
        "Closesocket",
        "WSAIoctl",
        "ioctlsocket",
        "HttpAddRequestHeaders",
    ],
    "antidebugging": [
        "CreateToolhelp32Snapshot",
        "GetLogicalProcessorInformation",
        "GetLogicalProcessorInformationEx",
        "GetTickCount",
        "OutputDebugStringA",
        "CheckRemoteDebuggerPresent",
        "Sleep",
        "GetSystemTime",
        "GetComputerNameA",
        "SleepEx",
        "IsDebuggerPresent",
        "GetUserNameA",
        "NtQueryInformationProcess",
        "ExitWindowsEx",
        "FindWindowA",
        "FindWindowExA",
        "GetForegroundWindow",
        "GetTickCount64",
        "QueryPerformanceFrequency",
        "QueryPerformanceCounter",
        "GetNativeSystemInfo",
        "RtlGetVersion",
        "GetSystemTimeAsFileTime",
        "CountClipboardFormats",
    ],
    "ransomware": [
        "CryptAcquireContextA",
        "EncryptFileA",
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptCreateHash",
        "CryptHashData",
        "CryptDeriveKey",
        "CryptSetKeyParam",
        "CryptGetHashParam",
        "CryptSetKeyParam",
        "CryptDestroyKey",
        "CryptGenRandom",
        "DecryptFileA",
        "FlushEfsCache",
        "GetLogicalDrives",
        "GetDriveTypeA",
        "CryptStringToBinary",
        "CryptBinaryToString",
        "CryptReleaseContext",
        "CryptDestroyHash",
        "EnumSystemLocalesA",
    ],
    "helper": [
        "ConnectNamedPipe",
        "CopyFileA",
        "CreateFileA",
        "CreateMutexA",
        "CreateMutexExA",
        "DeviceIoControl",
        "FindResourceA",
        "FindResourceExA",
        "GetModuleBaseNameA",
        "GetModuleFileNameA",
        "GetModuleFileNameExA",
        "GetTempPathA",
        "IsWoW64Process",
        "MoveFileA",
        "MoveFileExA",
        "PeekNamedPipe",
        "WriteFile",
        "TerminateThread",
        "CopyFile2",
        "CopyFileExA",
        "CreateFile2",
        "GetTempFileNameA",
        "TerminateProcess",
        "SetCurrentDirectory",
        "FindClose",
        "SetThreadPriority",
        "UnmapViewOfFile",
        "ControlService",
        "ControlServiceExA",
        "CreateServiceA",
        "DeleteService",
        "OpenSCManagerA",
        "OpenServiceA",
        "RegOpenKeyA",
        "RegOpenKeyExA",
        "StartServiceA",
        "StartServiceCtrlDispatcherA",
        "RegCreateKeyExA",
        "RegCreateKeyA",
        "RegSetValueExA",
        "RegSetKeyValueA",
        "RegDeleteValueA",
        "RegOpenKeyExA",
        "RegEnumKeyExA",
        "RegEnumValueA",
        "RegGetValueA",
        "RegFlushKey",
        "RegGetKeySecurity",
        "RegLoadKeyA",
        "RegLoadMUIStringA",
        "RegOpenCurrentUser",
        "RegOpenKeyTransactedA",
        "RegOpenUserClassesRoot",
        "RegOverridePredefKey",
        "RegReplaceKeyA",
        "RegRestoreKeyA",
        "RegSaveKeyA",
        "RegSaveKeyExA",
        "RegSetKeySecurity",
        "RegUnLoadKeyA",
        "RegConnectRegistryA",
        "RegCopyTreeA",
        "RegCreateKeyTransactedA",
        "RegDeleteKeyA",
        "RegDeleteKeyExA",
        "RegDeleteKeyTransactedA",
        "RegDeleteKeyValueA",
        "RegDeleteTreeA",
        "RegDeleteValueA",
        "RegCloseKey",
        "NtClose",
        "NtCreateFile",
        "NtDeleteKey",
        "NtDeleteValueKey",
        "NtMakeTemporaryObject",
        "NtSetContextThread",
        "NtSetInformationProcess",
        "NtSetInformationThread",
        "NtSetSystemEnvironmentValueEx",
        "NtSetValueKey",
        "NtShutdownSystem",
        "NtTerminateProcess",
        "NtTerminateThread",
        "RtlSetProcessIsCritical",
        "DrawTextExA",
        "GetDesktopWindow",
        "SetClipboardData",
        "SetWindowLongA",
        "SetWindowLongPtrA",
        "OpenClipboard",
        "SetForegroundWindow",
        "BringWindowToTop",
        "SetFocus",
        "ShowWindow",
        "NetShareSetInfo",
        "NetShareAdd",
        "NtQueryTimer",
        "GetIpNetTable",
        "GetLogicalDrives",
        "GetDriveTypeA",
        "CreatePipe",
        "RegEnumKeyA",
        "WNetOpenEnumA",
        "WNetEnumResourceA",
        "WNetAddConnection2A",
        "CallWindowProcA",
        "NtResumeProcess",
        "lstrcatA",
        "ImpersonateLoggedOnUser",
        "SetThreadToken",
        "SizeOfResource",
        "LockResource",
        "UuidFromStringA",
    ],
}


def get_malapis_set(category: str | None = None) -> Set[str]:
    if category:
        return set(
            filter(
                lambda x: not x.startswith("Nt"),
                [api for api in malapi[category]],
            )
        )

    return set(
        filter(
            lambda x: not x.startswith("Nt"),
            [api for cat in malapi for api in malapi[cat]],
        )
    )


def api_in_malapi(api: str, category: str | None = None) -> str | None:
    def remove_ext(api: str) -> str:
        if api.endswith("Ex"):
            return api[:-2]
        if api.endswith("A") or api.endswith("W"):
            return api[:-1]
        if api.endswith("ExA"):
            return api[::-3]
        if api.endswith("ExW"):
            return api[::-3]
        return api

    malapi_set = get_malapis_set(category)
    
    for mal in malapi_set:
        if api.lower() == mal.lower():
            return mal
    for mal in malapi_set:
        if remove_ext(api).lower() == mal.lower():
            return mal
    return None
