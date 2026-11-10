"""Inter-Process Communication (IPC) modules for Proxifier."""

from pyproxifier.ipc.driver import DriverIPC
from pyproxifier.ipc.manager import IPCManager
from pyproxifier.ipc.pipe import NamedPipeClient
from pyproxifier.ipc.service import ServiceIPC
from pyproxifier.ipc.socket import ControlSocketClient
from pyproxifier.ipc.window import WindowIPC

__all__ = [
    "ControlSocketClient",
    "DriverIPC",
    "IPCManager",
    "NamedPipeClient",
    "ServiceIPC",
    "WindowIPC",
]

