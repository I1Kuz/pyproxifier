"""Win32 handle utilities and ctypes helper routines for 64-bit and 32-bit Windows."""

from __future__ import annotations

import sys


def is_invalid_handle(handle: int | None | object) -> bool:
    """Returns True if the Win32 HANDLE / HWND is NULL or INVALID_HANDLE_VALUE.

    Correctly handles:
    - None or 0 (NULL handle)
    - Signed 32-bit (-1)
    - Unsigned 32-bit (0xFFFFFFFF)
    - Unsigned 64-bit (0xFFFFFFFFFFFFFFFF)
    - ctypes pointer objects (e.g. c_void_p, wintypes.HANDLE)
    """
    if handle is None:
        return True
    if isinstance(handle, int):
        return handle in (0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    # Handle ctypes pointers (c_void_p, wintypes.HANDLE)
    val = getattr(handle, "value", "NOT_FOUND")
    if val is None:
        return True
    if isinstance(val, int):
        return val in (0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    return False


def handle_to_int(handle: int | None | object) -> int | None:
    """Safely extracts integer pointer address from an int, c_void_p, or wintypes.HANDLE.

    Returns None if handle is invalid or cannot be converted to int.
    """
    if is_invalid_handle(handle):
        return None
    if isinstance(handle, int):
        return handle
    val = getattr(handle, "value", None)
    if isinstance(val, int):
        return val
    try:
        return int(handle)  # pyright: ignore[reportArgumentType]
    except (ValueError, TypeError):
        return None


def setup_win32_prototypes() -> None:
    """Configures 64-bit safe ctypes prototypes for Windows system DLLs.

    Prevents 64-bit pointer truncation and handle leaks on 64-bit Windows.
    """
    if sys.platform != "win32":
        return

    import ctypes
    from ctypes import wintypes

    if not hasattr(ctypes, "windll"):
        return

    k = ctypes.windll.kernel32
    k.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k.OpenMutexW.restype = wintypes.HANDLE
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    k.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    k.CreateFileW.restype = wintypes.HANDLE
    k.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    k.WaitNamedPipeW.restype = wintypes.BOOL
    k.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    k.ReadFile.restype = wintypes.BOOL
    k.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    k.WriteFile.restype = wintypes.BOOL
    k.DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    k.DeviceIoControl.restype = wintypes.BOOL

    a = ctypes.windll.advapi32
    a.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    a.OpenSCManagerW.restype = wintypes.HANDLE
    a.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    a.OpenServiceW.restype = wintypes.HANDLE
    a.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    a.CloseServiceHandle.restype = wintypes.BOOL
    a.QueryServiceStatusEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    a.QueryServiceStatusEx.restype = wintypes.BOOL

    u = ctypes.windll.user32
    u.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    u.FindWindowW.restype = wintypes.HWND
    u.IsHungAppWindow.argtypes = [wintypes.HWND]
    u.IsHungAppWindow.restype = wintypes.BOOL
    u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    u.GetWindowThreadProcessId.restype = wintypes.DWORD
    u.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    u.ShowWindow.restype = wintypes.BOOL
    u.SetForegroundWindow.argtypes = [wintypes.HWND]
    u.SetForegroundWindow.restype = wintypes.BOOL
    u.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    u.PostMessageW.restype = wintypes.BOOL


# Automatically configure prototypes on module load
setup_win32_prototypes()
