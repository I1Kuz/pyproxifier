"""Direct Kernel WFP Driver IPC (\\\\.\\ProxifierDrv) for ProxifierDrv.sys."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
from types import TracebackType

from pyproxifier.ipc.win32 import handle_to_int, is_invalid_handle

logger = logging.getLogger(__name__)

DEVICE_NAME = r"\\.\ProxifierDrv"

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1

ERROR_ACCESS_DENIED = 5
ERROR_SHARING_VIOLATION = 32
ERROR_FILE_NOT_FOUND = 2


class DriverIPC:
    """Manages low-level kernel IPC with the ProxifierDrv Windows Filtering Platform driver."""

    def __init__(self, device_name: str = DEVICE_NAME) -> None:
        self.device_name = device_name
        self._handle: int | None = None

    @classmethod
    def is_device_present(cls, device_name: str = DEVICE_NAME) -> bool:
        """Determines if the ProxifierDrv kernel device object is present in Windows kernel namespace.

        Works without Administrator privileges by testing kernel object existence.
        """
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            device_name,
            0,  # Query access only
            0,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if not is_invalid_handle(handle):
            kernel32.CloseHandle(handle)
            return True

        err = kernel32.GetLastError()
        # If access is denied (5) or sharing violation (32), the kernel driver device object definitely exists
        return err in (ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION)

    @property
    def is_connected(self) -> bool:
        return not is_invalid_handle(self._handle)

    def open(self, write_access: bool = False) -> None:
        """Opens a direct handle to \\\\.\\ProxifierDrv (requires Admin privileges)."""
        if self.is_connected:
            return

        kernel32 = ctypes.windll.kernel32
        desired_access = (GENERIC_READ | GENERIC_WRITE) if write_access else GENERIC_READ
        handle = kernel32.CreateFileW(
            self.device_name,
            desired_access,
            0,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        int_handle = handle_to_int(handle)
        if int_handle is None:
            err = kernel32.GetLastError()
            raise PermissionError(
                f"Failed to open '{self.device_name}' (Windows error {err}). Administrator privileges required."
            )

        self._handle = int_handle

    def close(self) -> None:
        """Closes the kernel device handle."""
        if self._handle is not None and not is_invalid_handle(self._handle):
            kernel32 = ctypes.windll.kernel32
            kernel32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> DriverIPC:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def ioctl(
        self,
        control_code: int,
        in_data: bytes = b"",
        out_buffer_size: int = 1024,
    ) -> bytes:
        """Dispatches a DeviceIoControl request to ProxifierDrv.sys."""
        if not self.is_connected or self._handle is None:
            raise ConnectionError("Driver handle is not open.")

        kernel32 = ctypes.windll.kernel32
        out_buf = ctypes.create_string_buffer(out_buffer_size)
        bytes_returned = wintypes.DWORD()

        success = kernel32.DeviceIoControl(
            self._handle,
            control_code,
            in_data,
            len(in_data),
            out_buf,
            out_buffer_size,
            ctypes.byref(bytes_returned),
            None,
        )
        if not success:
            err = kernel32.GetLastError()
            raise OSError(f"DeviceIoControl (code {hex(control_code)}) failed: Windows error {err}")

        return out_buf.raw[: bytes_returned.value]

