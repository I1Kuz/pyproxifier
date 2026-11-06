"""Window Message & Mutex IPC for running Proxifier instances."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging

import psutil  # type: ignore[import-untyped]

from pyproxifier.ipc.win32 import handle_to_int, is_invalid_handle

logger = logging.getLogger(__name__)

PROXIFIER_MUTEX_GLOBAL = r"Global\ProxifierRunning"
PROXIFIER_MUTEX_V4 = r"Global\Proxifier32Mutex1040"
PROXIFIER_MUTEX_V3 = r"Global\ProxifierStd300Mutex"
PROXIFIER_MUTEX_PID_FMT = r"Global\ProxifierProcIdMutex%d"
PROXIFIER_MUTEX_SEND_DELAY = r"Global\ProxifierExtraOptionSendDelay"

PROXIFIER_WINDOW_CLASS = "Proxifier32Cls"
PROXIFIER_WINDOW_TITLE = "Proxifier"

SYNCHRONIZE = 0x00100000
WM_CLOSE = 0x0010
SW_HIDE = 0
SW_RESTORE = 9


class WindowIPC:
    """Manages Window Message and Mutex IPC for active Proxifier instances."""

    @classmethod
    def is_instance_running(cls) -> bool:
        """Checks if a Proxifier instance is currently running by querying kernel mutexes."""
        kernel32 = ctypes.windll.kernel32
        for mutex_name in (PROXIFIER_MUTEX_GLOBAL, PROXIFIER_MUTEX_V4, PROXIFIER_MUTEX_V3):
            handle = kernel32.OpenMutexW(SYNCHRONIZE, False, mutex_name)
            if not is_invalid_handle(handle):
                kernel32.CloseHandle(handle)
                return True
        return False

    @classmethod
    def is_pid_proxifier(cls, pid: int) -> bool:
        """Authoritatively verifies whether a given PID belongs to a Proxifier process via kernel mutex."""
        if pid <= 0:
            return False
        kernel32 = ctypes.windll.kernel32
        mutex_name = PROXIFIER_MUTEX_PID_FMT % pid
        handle = kernel32.OpenMutexW(SYNCHRONIZE, False, mutex_name)
        if not is_invalid_handle(handle):
            kernel32.CloseHandle(handle)
            return True
        return False

    @classmethod
    def find_proxifier_pids(cls) -> list[int]:
        """Discovers all running Proxifier process IDs via kernel mutex enumeration."""
        if not cls.is_instance_running():
            return []

        pids: list[int] = []
        for proc in psutil.process_iter(["pid"]):
            try:
                p = proc.info.get("pid")
                if p and p > 0 and cls.is_pid_proxifier(p):
                    pids.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return pids

    @classmethod
    def is_send_delay_enabled(cls) -> bool:
        """Returns True if the Proxifier packet send delay extra option mutex is active."""
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenMutexW(SYNCHRONIZE, False, PROXIFIER_MUTEX_SEND_DELAY)
        if not is_invalid_handle(handle):
            kernel32.CloseHandle(handle)
            return True
        return False

    @classmethod
    def find_window(cls) -> int | None:
        """Finds the HWND handle of the primary Proxifier window (Proxifier32Cls)."""
        user32 = ctypes.windll.user32
        hwnd = user32.FindWindowW(PROXIFIER_WINDOW_CLASS, None)
        int_hwnd = handle_to_int(hwnd)
        if int_hwnd:
            return int_hwnd

        # Fallback to search by title
        hwnd_by_title = user32.FindWindowW(None, PROXIFIER_WINDOW_TITLE)
        return handle_to_int(hwnd_by_title)

    @classmethod
    def is_hung(cls, hwnd: int) -> bool:
        """Checks if the Proxifier window message loop is hanging."""
        user32 = ctypes.windll.user32
        return bool(user32.IsHungAppWindow(hwnd))

    @classmethod
    def get_window_pid(cls, hwnd: int) -> int | None:
        """Retrieves process ID owning the Proxifier window handle."""
        user32 = ctypes.windll.user32
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return pid.value if pid.value > 0 else None

    @classmethod
    def bring_to_front(cls) -> bool:
        """Restores and brings the Proxifier main window to foreground."""
        hwnd = cls.find_window()
        if not hwnd:
            return False
        user32 = ctypes.windll.user32
        user32.ShowWindow(hwnd, SW_RESTORE)
        user32.SetForegroundWindow(hwnd)
        return True

    @classmethod
    def minimize_to_tray(cls) -> bool:
        """Hides Proxifier main window to system tray."""
        hwnd = cls.find_window()
        if not hwnd:
            return False
        user32 = ctypes.windll.user32
        user32.ShowWindow(hwnd, SW_HIDE)
        return True

    @classmethod
    def post_close_message(cls) -> bool:
        """Sends WM_CLOSE message to the Proxifier window to request graceful shutdown."""
        hwnd = cls.find_window()
        if not hwnd:
            return False
        user32 = ctypes.windll.user32
        return bool(user32.PostMessageW(hwnd, WM_CLOSE, 0, 0))

