"""Unified Inter-Process Communication (IPC) Manager for Proxifier.

Coordinates:
1. Native TCP Control Socket API (zero-restart, in-memory profile hot-reload).
2. Window Message IPC (Proxifier32Cls / Global\\Proxifier32Mutex1040).
3. Named Pipe IPC (\\\\.\\pipe\\proxifier).
4. Direct Kernel WFP Driver IPC (\\\\.\\ProxifierDrv).
"""

from __future__ import annotations

import logging
from pathlib import Path
import tempfile

from pyproxifier.exceptions import ControlSocketConnectionError
from pyproxifier.ipc.driver import DriverIPC
from pyproxifier.ipc.pipe import NamedPipeClient
from pyproxifier.ipc.service import ServiceIPC
from pyproxifier.ipc.socket import ControlSocketClient
from pyproxifier.ipc.window import WindowIPC
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.parser import ProfileParser
from pyproxifier.process import ProcessController
from pyproxifier.validator import Validator

logger = logging.getLogger(__name__)


class IPCManager:
    """Central controller coordinating all Proxifier IPC mechanisms without restarts or disk tampering."""

    def __init__(
        self,
        default_socket_port: int = 19876,
        executable: Path | str | None = None,
    ) -> None:
        self.default_socket_port = default_socket_port
        self.executable = executable
        self.window = WindowIPC
        self.driver = DriverIPC
        self.pipe = NamedPipeClient
        self.service = ServiceIPC

    def get_socket_client(
        self, port: int | None = None, host: str = "127.0.0.1", timeout: float = 5.0
    ) -> ControlSocketClient:
        """Returns a configured ControlSocketClient instance."""
        target_port = port or self.default_socket_port
        return ControlSocketClient(host=host, port=target_port, timeout=timeout)

    def is_socket_ready(self, port: int | None = None, host: str = "127.0.0.1") -> bool:
        """Returns True if the native TCP Control Socket is listening and responsive."""
        target_port = port or self.default_socket_port
        return ControlSocketClient.is_available(port=target_port, host=host)

    def is_pipe_ready(self) -> bool:
        """Returns True if the Proxifier named pipe is active."""
        return NamedPipeClient.is_pipe_available()

    def is_driver_ready(self) -> bool:
        """Returns True if the ProxifierDrv WFP kernel device is loaded in kernel space."""
        return DriverIPC.is_device_present()

    def is_service_ready(self) -> bool:
        """Returns True if Proxifier Windows Service is running."""
        return ServiceIPC.is_service_running()

    def is_proxifier_running(self) -> bool:
        """Returns True if Proxifier process or active mutex is detected on the system."""
        return WindowIPC.is_instance_running() or ProcessController.is_running()

    def convert_profile(self, source_profile: Path | str) -> bool:
        """Converts an older format profile (.prx) or profile file using Proxifier native converter."""
        return ProcessController.convert_and_quit(source_profile, executable=self.executable)

    def register_license(self, license_key: str) -> bool:
        """Registers Proxifier license key using native command-line activation."""
        return ProcessController.register_license(license_key, executable=self.executable)

    def apply_profile(
        self,
        profile: ProxifierProfile,
        socket_port: int | None = None,
        validate: bool = True,
    ) -> bool:
        """Applies a configuration profile to Proxifier exclusively via IPC.

        Zero process restarting, zero manual profile pasting.

        Order of IPC mechanisms:
        1. Native TCP Control Socket (in-memory hot-reload without touching disk).
        2. If Proxifier is not running: launches in control-socket mode and connects immediately.
        3. If Proxifier is running and Named Pipe is ready: hot-reloads directly via \\\\.\\pipe\\proxifier.
        4. Fallback: native silent-load IPC (which communicates directly with the running instance).
        """
        if validate:
            Validator.validate_profile(profile)

        port = socket_port or self.default_socket_port

        # Strategy 1: Control Socket is already listening
        if self.is_socket_ready(port=port):
            with self.get_socket_client(port=port) as client:
                client.load_config(profile)
            return True

        # Strategy 2: Proxifier is not running at all -> start directly in Control Socket mode
        if not self.is_proxifier_running():
            client = ControlSocketClient.start_and_connect(
                port=port,
                executable=self.executable,
            )
            try:
                client.load_config(profile)
                return True
            finally:
                client.disconnect()

        # Strategy 3: Proxifier is running -> prefer native Named Pipe IPC (in-memory, no disk files)
        if self.is_pipe_ready():
            try:
                pipe_client = self.pipe()
                with pipe_client:
                    pipe_client.send_profile(profile)
                return True
            except Exception as e:
                logger.debug("Named pipe profile delivery failed, falling back to silent-load: %s", e)

        # Strategy 4: Fallback to native silent-load IPC (which communicates directly with the running instance)
        xml_str = ProfileParser.to_xml(profile)
        with tempfile.NamedTemporaryFile("w", suffix=".ppx", delete=False, encoding="utf-8") as f:
            f.write(xml_str)
            tmp_path = Path(f.name)

        try:
            return ProcessController.silent_load(tmp_path, executable=self.executable)
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def graceful_exit(self, socket_port: int | None = None) -> bool:
        """Gracefully shuts down Proxifier using native IPC without process termination."""
        port = socket_port or self.default_socket_port

        # Try TCP Control Socket exit command first
        if self.is_socket_ready(port=port):
            try:
                with self.get_socket_client(port=port) as client:
                    client.exit()
                return True
            except ControlSocketConnectionError:
                pass

        # Try Window Message WM_CLOSE
        if WindowIPC.post_close_message():
            return True

        return False

