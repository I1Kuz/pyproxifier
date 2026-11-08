"""Native TCP Control Socket client for real-time programmatic control of Proxifier."""

from __future__ import annotations

from pathlib import Path
import socket
import subprocess
import time
from types import TracebackType
from typing import Any

from pyproxifier.exceptions import (
    ControlSocketCommandError,
    ControlSocketConnectionError,
    ProxifierNotFoundError,
)
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.parser import ProfileParser
from pyproxifier.process import ProcessController
from pyproxifier.validator import Validator


class ControlSocketClient:
    """Client for Proxifier's undocumented native TCP Control Socket API.

    Enables dynamic, zero-restart configuration updates, version queries,
    and graceful shutdowns via local socket communication.
    """

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 19876

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        timeout: float = 5.0,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._proc: subprocess.Popen[Any] | None = None

    @classmethod
    def is_available(
        cls,
        port: int = DEFAULT_PORT,
        host: str = DEFAULT_HOST,
        timeout: float = 0.5,
    ) -> bool:
        """Tests whether a Proxifier Control Socket server is currently accepting connections."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            sock.close()
            return True
        except OSError:
            sock.close()
            return False

    @property
    def is_connected(self) -> bool:
        """Returns True if the client socket is active."""
        return self._sock is not None

    def connect(self) -> None:
        """Establishes a TCP connection to the Proxifier Control Socket server."""
        if self._sock is not None:
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
            self._sock = sock
        except (OSError, socket.error) as err:
            sock.close()
            raise ControlSocketConnectionError(
                f"Failed to connect to Proxifier Control Socket at {self.host}:{self.port}: {err}"
            ) from err

    def disconnect(self) -> None:
        """Closes the TCP connection cleanly."""
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self._sock.close()
                self._sock = None

    def __enter__(self) -> ControlSocketClient:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.disconnect()

    @classmethod
    def start_and_connect(
        cls,
        port: int = DEFAULT_PORT,
        host: str = DEFAULT_HOST,
        executable: Path | str | None = None,
        startup_delay: float = 1.0,
        timeout: float = 5.0,
    ) -> ControlSocketClient:
        """Launches Proxifier in Control Socket mode and connects to it."""
        exe = ProcessController.find_proxifier_binary(executable)
        if not exe.is_file():
            raise ProxifierNotFoundError([str(exe)])

        proc = subprocess.Popen(
            [str(exe), "control-socket", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline = time.time() + max(startup_delay, 1.0)
        while time.time() < deadline:
            if cls.is_available(port=port, host=host, timeout=0.1):
                break
            time.sleep(0.05)

        client = cls(host=host, port=port, timeout=timeout)
        try:
            client.connect()
            client._proc = proc
            return client
        except Exception:
            try:
                proc.terminate()
            except OSError:
                pass
            raise

    def send_command(self, command: str, body: bytes = b"") -> tuple[str, bytes]:
        """Frames and sends a command, then reads and parses the response.

        Wire protocol format:
            Request:  <command> <body_len>\\r\\n<body>
            Response: OK <body_len>\\r\\n<body>
                      ERROR <details>\\r\\n
        """
        if self._sock is None:
            raise ControlSocketConnectionError("Not connected to Proxifier Control Socket.")

        header = f"{command} {len(body)}\r\n".encode("utf-8")
        msg = header + body

        try:
            self._sock.sendall(msg)

            # Read response header line (up to \r\n)
            header_bytes = self._recv_line()
            header_str = header_bytes.decode("latin1", errors="replace").strip()

            if not header_str:
                raise ControlSocketConnectionError("Remote server closed connection unexpectedly.")

            if header_str.startswith("ERROR"):
                parts = header_str.split(None, 2)
                err_code = parts[1] if len(parts) > 1 else None
                err_msg = parts[2] if len(parts) > 2 else header_str
                raise ControlSocketCommandError(command=command, error_code=err_code, message=err_msg)

            if not header_str.startswith("OK"):
                raise ControlSocketCommandError(
                    command=command,
                    message=f"Unexpected response status: {header_str}",
                )

            # Parse payload length from 'OK <len>'
            parts = header_str.split(None, 1)
            body_len = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

            resp_body = self._recv_exact(body_len) if body_len > 0 else b""
            return header_str, resp_body

        except socket.timeout as err:
            raise ControlSocketConnectionError(f"Control Socket timed out while executing '{command}'.") from err
        except OSError as err:
            self.disconnect()
            raise ControlSocketConnectionError(f"Socket I/O error during '{command}': {err}") from err

    def _recv_line(self) -> bytes:
        """Reads one byte at a time until \\n."""
        assert self._sock is not None
        buf = bytearray()
        while True:
            chunk = self._sock.recv(1)
            if not chunk:
                break
            buf.extend(chunk)
            if chunk == b"\n":
                break
            if len(buf) > 65536:
                raise ControlSocketConnectionError("Line buffer exceeded 64KB limit.")
        return bytes(buf)

    def _recv_exact(self, length: int) -> bytes:
        """Reads exactly length bytes from socket."""
        assert self._sock is not None
        buf = bytearray()
        while len(buf) < length:
            chunk = self._sock.recv(min(length - len(buf), 4096))
            if not chunk:
                raise ControlSocketConnectionError("Unexpected EOF while reading response body.")
            buf.extend(chunk)
        return bytes(buf)

    def get_version(self) -> str:
        """Queries Proxifier internal version string (e.g. '1000')."""
        _, body = self.send_command("get_version")
        return body.decode("utf-8", errors="replace").strip()

    def load_config(
        self,
        config: str | bytes | ProxifierProfile,
        validate: bool = False,
    ) -> None:
        """Loads and applies a Proxifier profile dynamically in memory without restarting.

        Accepts a ProxifierProfile object, XML string, or XML bytes.
        """
        if isinstance(config, ProxifierProfile):
            if validate:
                Validator.validate_profile(config)
            xml_bytes = ProfileParser.to_xml(config).encode("utf-8")
        elif isinstance(config, str):
            xml_bytes = config.encode("utf-8")
        else:
            xml_bytes = config

        self.send_command("load_config", xml_bytes)

    def load_config_file(self, profile_path: Path | str) -> None:
        """Instructs Proxifier to load a profile from a specified file path."""
        p = Path(profile_path)
        path_bytes = str(p.resolve()).encode("utf-8")
        self.send_command("load_config_file", path_bytes)

    def exit(self) -> None:
        """Gracefully closes the Proxifier application."""
        try:
            self.send_command("exit")
        except ControlSocketConnectionError:
            # Proxifier may terminate the connection immediately upon initiating shutdown
            pass
        finally:
            self.disconnect()
            if self._proc is not None:
                try:
                    self._proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                self._proc = None

