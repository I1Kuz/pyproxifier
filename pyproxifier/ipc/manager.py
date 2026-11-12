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
from pyproxifier.ipc.status import ApplyResult, ApplyStatus
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
        self.last_apply_result: ApplyResult | None = None
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
        use_socket: bool | None = None,
        silent: bool = True,
        validate: bool = True,
    ) -> bool:
        """Applies a configuration profile to Proxifier exclusively via IPC.

        Returns True if profile was applied or dispatched, False otherwise.
        For detailed status information, see apply_profile_detailed() or self.last_apply_result.
        """
        res = self.apply_profile_detailed(
            profile=profile,
            socket_port=socket_port,
            use_socket=use_socket,
            silent=silent,
            validate=validate,
        )
        return res.applied

    def apply_profile_detailed(
        self,
        profile: ProxifierProfile,
        socket_port: int | None = None,
        use_socket: bool | None = None,
        silent: bool = True,
        validate: bool = True,
    ) -> ApplyResult:
        """Applies a configuration profile and returns explicit ApplyResult status.

        Order of IPC mechanisms:
        1. Native TCP Control Socket (in-memory hot-reload without touching disk) - if use_socket is not False.
        2. If Proxifier is not running: launches in control-socket mode and connects - if use_socket is not False.
        3. If Proxifier is running and Named Pipe is ready: hot-reloads directly via \\\\.\\pipe\\proxifier.
        4. Fallback: native process execution IPC (communicates directly with running instance or launches GUI).

        Respects use_socket: if False, completely disables Control Socket strategies.
        Respects silent: if False, executes CLI loader without 'silent-load' parameter.
        """
        if validate:
            Validator.validate_profile(profile)

        port = socket_port or self.default_socket_port

        # Strategy 1: Control Socket is already listening (if socket enabled)
        if use_socket is not False and self.is_socket_ready(port=port):
            with self.get_socket_client(port=port) as client:
                client.load_config(profile)
            result = ApplyResult(
                applied=True,
                status=ApplyStatus.SOCKET_CONFIRMED,
                message="Profile applied and confirmed via active TCP Control Socket.",
            )
            self.last_apply_result = result
            return result

        # Strategy 2: Proxifier is not running at all -> start directly in Control Socket mode
        if use_socket is not False and not self.is_proxifier_running():
            client = ControlSocketClient.start_and_connect(
                port=port,
                executable=self.executable,
            )
            try:
                client.load_config(profile)
                result = ApplyResult(
                    applied=True,
                    status=ApplyStatus.SOCKET_CONFIRMED,
                    message="Proxifier started in Control Socket mode and profile applied.",
                )
                self.last_apply_result = result
                return result
            finally:
                client.disconnect()

        # Strategy 3: Proxifier is running -> prefer native Named Pipe IPC (in-memory, no disk files)
        if self.is_pipe_ready():
            try:
                pipe_client = self.pipe()
                with pipe_client:
                    pipe_client.send_profile(profile)
                result = ApplyResult(
                    applied=True,
                    status=ApplyStatus.PIPE_DISPATCHED,
                    message="Profile dispatched via Windows Named Pipe.",
                )
                self.last_apply_result = result
                return result
            except Exception as e:
                logger.debug("Named pipe profile delivery failed, falling back to process load: %s", e)

        # Strategy 4: Fallback to process execution IPC
        was_running = self.is_proxifier_running()
        xml_str = ProfileParser.to_xml(profile)
        with tempfile.NamedTemporaryFile("w", suffix=".ppx", delete=False, encoding="utf-8") as f:
            f.write(xml_str)
            tmp_path = Path(f.name)

        try:
            ok = ProcessController.silent_load(
                tmp_path,
                executable=self.executable,
                silent=silent,
            )
            if ok:
                status = ApplyStatus.COMMAND_DELIVERED if was_running else ApplyStatus.PROCESS_SPAWNED
                result = ApplyResult(
                    applied=True,
                    status=status,
                    message="Profile dispatched to Proxifier process.",
                )
            else:
                result = ApplyResult(
                    applied=False,
                    status=ApplyStatus.FAILED,
                    message="Proxifier process loader returned failure.",
                )
            self.last_apply_result = result
            return result
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

