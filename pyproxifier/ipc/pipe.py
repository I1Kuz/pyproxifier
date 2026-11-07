"""Named Pipe IPC client for Proxifier Windows Service and IPC inter-session communication."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
import time
from types import TracebackType

from pyproxifier.ipc.win32 import handle_to_int, is_invalid_handle
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.parser import ProfileParser

logger = logging.getLogger(__name__)

PIPE_NAME = r"\\.\pipe\proxifier"
SERVICE_MUTEX_NAME = r"Global\ProxifierServiceRunning"

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
SYNCHRONIZE = 0x00100000
INVALID_HANDLE_VALUE = -1


MAX_PIPE_PAYLOAD_SIZE = 5 * 1024 * 1024  # 5 MB maximum allowed by Proxifier pipe


class NamedPipeClient:
    """Client for Proxifier's native Named Pipe IPC (\\\\.\\pipe\\proxifier)."""

    def __init__(self, pipe_name: str = PIPE_NAME, timeout_ms: int = 500) -> None:
        self.pipe_name = pipe_name
        self.timeout_ms = timeout_ms
        self._handle: int | None = None

    @classmethod
    def is_pipe_available(cls, pipe_name: str = PIPE_NAME, timeout_ms: int = 100) -> bool:
        """Checks if the Proxifier named pipe is active and accepting connections."""
        kernel32 = ctypes.windll.kernel32
        res = kernel32.WaitNamedPipeW(pipe_name, timeout_ms)
        if res:
            return True
        err = kernel32.GetLastError()
        return err in (5, 231)  # ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY

    @classmethod
    def is_service_running(cls) -> bool:
        """Checks if Proxifier Windows Service is running by querying its global mutex."""
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenMutexW(SYNCHRONIZE, False, SERVICE_MUTEX_NAME)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False

    @property
    def is_connected(self) -> bool:
        return not is_invalid_handle(self._handle)

    def connect(self) -> None:
        """Opens a handle to the Proxifier named pipe with retry on transient busy states."""
        if self.is_connected:
            return

        kernel32 = ctypes.windll.kernel32
        deadline = time.time() + (self.timeout_ms / 1000.0)

        while True:
            handle = kernel32.CreateFileW(
                self.pipe_name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            int_handle = handle_to_int(handle)
            if int_handle is not None:
                self._handle = int_handle
                return

            err = kernel32.GetLastError()
            # If pipe is busy with another client, wait and retry up to deadline
            if err == 231 and time.time() < deadline:  # ERROR_PIPE_BUSY
                kernel32.WaitNamedPipeW(self.pipe_name, 50)
                continue

            raise ConnectionError(f"Failed to connect to named pipe '{self.pipe_name}': Windows error {err}")

    def close(self) -> None:
        """Closes the named pipe handle."""
        if not is_invalid_handle(self._handle) and self._handle is not None:
            kernel32 = ctypes.windll.kernel32
            kernel32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> NamedPipeClient:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def send(self, data: bytes) -> int:
        """Writes bytes to the connected named pipe."""
        if not self.is_connected or self._handle is None:
            raise ConnectionError("Not connected to named pipe.")

        kernel32 = ctypes.windll.kernel32
        total_written = 0

        while total_written < len(data):
            chunk = data[total_written:]
            bytes_written = wintypes.DWORD()
            success = kernel32.WriteFile(
                self._handle,
                chunk,
                len(chunk),
                ctypes.byref(bytes_written),
                None,
            )
            if not success or bytes_written.value == 0:
                err = kernel32.GetLastError()
                raise OSError(f"Failed to write to named pipe: Windows error {err}")
            total_written += bytes_written.value

        return total_written

    def receive(self, buffer_size: int = 4096) -> bytes:
        """Reads bytes from the connected named pipe."""
        if not self.is_connected or self._handle is None:
            raise ConnectionError("Not connected to named pipe.")

        kernel32 = ctypes.windll.kernel32
        buf = ctypes.create_string_buffer(buffer_size)
        bytes_read = wintypes.DWORD()
        success = kernel32.ReadFile(
            self._handle,
            buf,
            buffer_size,
            ctypes.byref(bytes_read),
            None,
        )
        if not success:
            err = kernel32.GetLastError()
            raise OSError(f"Failed to read from named pipe: Windows error {err}")

        return buf.raw[: bytes_read.value]

    def transact(self, data: bytes, buffer_size: int = 4096) -> bytes:
        """Sends data and returns response in a single transaction."""
        self.send(data)
        return self.receive(buffer_size=buffer_size)

    def send_profile(self, profile: str | bytes | ProxifierProfile) -> int:
        """Transmits profile configuration data directly over the named pipe.

        Args:
            profile: ProxifierProfile instance, raw XML string, or XML bytes.

        Returns:
            Number of bytes written to the pipe.
        """
        if isinstance(profile, bytes):
            payload = profile
        elif isinstance(profile, str):
            payload = profile.encode("utf-8")
        else:
            payload = ProfileParser.to_xml(profile).encode("utf-8")

        if len(payload) > MAX_PIPE_PAYLOAD_SIZE:
            raise ValueError(
                f"Profile payload size ({len(payload)} bytes) exceeds Proxifier pipe maximum of {MAX_PIPE_PAYLOAD_SIZE} bytes (5 MB)."
            )

        if not self.is_connected:
            self.connect()

        return self.send(payload)

