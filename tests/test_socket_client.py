# pyright: reportPrivateUsage=false
"""Unit tests for ControlSocketClient and native Control Socket wire protocol."""

from pathlib import Path
import socket
import subprocess
import threading
from typing import Generator
from unittest import mock
import pytest

from pyproxifier.exceptions import (
    ControlSocketCommandError,
    ControlSocketConnectionError,
    ProxifierNotFoundError,
)
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.socket_client import ControlSocketClient


class MockControlSocketServer:
    """Mock TCP server implementing Proxifier Control Socket protocol for unit testing."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.bind((self.host, 0))
        self.port: int = self.server_sock.getsockname()[1]
        self.server_sock.listen(1)
        self.received_commands: list[tuple[str, bytes]] = []
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        self.server_sock.settimeout(0.5)
        while not self._stop_event.is_set():
            try:
                conn, _ = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            self._handle_client(conn)

    def _handle_client(self, conn: socket.socket) -> None:
        conn.settimeout(2.0)
        try:
            while not self._stop_event.is_set():
                # Read command line until \n
                line_buf = bytearray()
                while True:
                    ch = conn.recv(1)
                    if not ch:
                        return
                    line_buf.extend(ch)
                    if ch == b"\n":
                        break

                line = line_buf.decode("utf-8", errors="replace").strip()
                if not line:
                    return

                parts = line.split(None, 1)
                cmd_name = parts[0]
                body_len = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

                body = bytearray()
                while len(body) < body_len:
                    ch = conn.recv(min(body_len - len(body), 4096))
                    if not ch:
                        break
                    body.extend(ch)

                self.received_commands.append((cmd_name, bytes(body)))

                # Respond based on command
                if cmd_name == "get_version":
                    conn.sendall(b"OK 4\r\n1000")
                elif cmd_name == "exit":
                    conn.sendall(b"OK 0\r\n")
                    return
                elif cmd_name in ("load_config", "load_config_file"):
                    conn.sendall(b"OK 0\r\n")
                elif cmd_name == "trigger_error":
                    conn.sendall(b"ERROR 400 Invalid argument\r\n")
                elif cmd_name == "weird_status":
                    conn.sendall(b"UNKNOWN_STATUS 0\r\n")
                elif cmd_name == "incomplete_body":
                    conn.sendall(b"OK 100\r\npartial")
                    conn.close()
                    return
                elif cmd_name == "empty_resp":
                    conn.close()
                    return
                else:
                    conn.sendall(b"ERROR 101 Unknown command\r\n")
        except (OSError, socket.timeout):
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._stop_event.set()
        try:
            self.server_sock.close()
        except OSError:
            pass
        self._thread.join(timeout=1.0)


@pytest.fixture
def mock_server() -> Generator[MockControlSocketServer, None, None]:
    server = MockControlSocketServer()
    yield server
    server.close()


def test_control_socket_is_available(mock_server: MockControlSocketServer) -> None:
    assert ControlSocketClient.is_available(port=mock_server.port, host=mock_server.host) is True
    assert ControlSocketClient.is_available(port=59998, host="127.0.0.1", timeout=0.1) is False


def test_control_socket_get_version(mock_server: MockControlSocketServer) -> None:
    with ControlSocketClient(host=mock_server.host, port=mock_server.port) as client:
        assert client.is_connected
        # Second call to connect is a no-op
        client.connect()
        ver = client.get_version()
        assert ver == "1000"

    assert len(mock_server.received_commands) == 1
    assert mock_server.received_commands[0] == ("get_version", b"")


def test_control_socket_load_config_variants(mock_server: MockControlSocketServer) -> None:
    # 1. Bytes
    sample_xml = b"<ProxifierProfile></ProxifierProfile>"
    with ControlSocketClient(host=mock_server.host, port=mock_server.port) as client:
        client.load_config(sample_xml)

    # 2. String
    str_xml = "<ProxifierProfile version='102'></ProxifierProfile>"
    with ControlSocketClient(host=mock_server.host, port=mock_server.port) as client:
        client.load_config(str_xml)

    # 3. ProxifierProfile with validate=True
    profile = ProxifierProfile.create_default()
    with ControlSocketClient(host=mock_server.host, port=mock_server.port) as client:
        client.load_config(profile, validate=True)

    assert len(mock_server.received_commands) == 3


def test_control_socket_load_config_file(mock_server: MockControlSocketServer) -> None:
    p = Path("C:/dummy/profile.ppx")
    with ControlSocketClient(host=mock_server.host, port=mock_server.port) as client:
        client.load_config_file(p)

    assert len(mock_server.received_commands) == 1
    cmd, body = mock_server.received_commands[0]
    assert cmd == "load_config_file"
    assert b"profile.ppx" in body


def test_control_socket_exit(mock_server: MockControlSocketServer) -> None:
    mock_proc = mock.MagicMock()
    with ControlSocketClient(host=mock_server.host, port=mock_server.port) as client:
        client._proc = mock_proc
        client.exit()
        assert not client.is_connected
        mock_proc.wait.assert_called_once()

    assert len(mock_server.received_commands) == 1
    assert mock_server.received_commands[0] == ("exit", b"")


def test_control_socket_exit_process_kill() -> None:
    mock_proc = mock.MagicMock()
    mock_proc.wait.side_effect = subprocess.TimeoutExpired(cmd=["test"], timeout=2.0)
    client = ControlSocketClient()
    client._proc = mock_proc
    # Not connected, exit should still clean up proc
    client.exit()
    mock_proc.kill.assert_called_once()


def test_control_socket_error_responses(mock_server: MockControlSocketServer) -> None:
    with ControlSocketClient(host=mock_server.host, port=mock_server.port) as client:
        # Standard error
        with pytest.raises(ControlSocketCommandError) as exc_info:
            client.send_command("trigger_error")
        assert exc_info.value.command == "trigger_error"
        assert exc_info.value.error_code == "400"

        # Weird status not OK / ERROR
        with pytest.raises(ControlSocketCommandError, match="Unexpected response status"):
            client.send_command("weird_status")

        # Empty response / unexpected EOF
        with pytest.raises(ControlSocketConnectionError, match="closed connection unexpectedly"):
            client.send_command("empty_resp")


def test_control_socket_incomplete_body(mock_server: MockControlSocketServer) -> None:
    with ControlSocketClient(host=mock_server.host, port=mock_server.port) as client:
        with pytest.raises(ControlSocketConnectionError, match="Unexpected EOF"):
            client.send_command("incomplete_body")


def test_control_socket_timeouts_and_errors() -> None:
    client = ControlSocketClient(host="127.0.0.1", port=19876)

    # Test socket timeout during command
    mock_sock = mock.MagicMock()
    mock_sock.sendall.return_value = None
    mock_sock.recv.side_effect = socket.timeout()
    client._sock = mock_sock
    with pytest.raises(ControlSocketConnectionError, match="timed out"):
        client.send_command("get_version")

    # Test socket OSError during command
    mock_sock_err = mock.MagicMock()
    mock_sock_err.sendall.side_effect = OSError("Network down")
    client._sock = mock_sock_err
    with pytest.raises(ControlSocketConnectionError, match="Socket I/O error"):
        client.send_command("get_version")


def test_control_socket_start_and_connect() -> None:
    # Exe not found
    with mock.patch("pyproxifier.process.ProcessController.find_proxifier_binary", return_value=Path(r"C:\missing.exe")):
        with mock.patch.object(Path, "is_file", return_value=False):
            with pytest.raises(ProxifierNotFoundError):
                ControlSocketClient.start_and_connect(port=19876)

    # Success start and connect
    fake_exe = Path(r"C:\Proxifier\Proxifier.exe")
    with mock.patch("pyproxifier.process.ProcessController.find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            mock_proc = mock.MagicMock()
            with mock.patch("subprocess.Popen", return_value=mock_proc):
                with mock.patch.object(ControlSocketClient, "is_available", return_value=True):
                    with mock.patch.object(ControlSocketClient, "connect") as mock_conn:
                        client = ControlSocketClient.start_and_connect(port=19876)
                        assert client._proc == mock_proc
                        mock_conn.assert_called_once()

    # Failure during connect cleans up process
    with mock.patch("pyproxifier.process.ProcessController.find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            mock_proc = mock.MagicMock()
            with mock.patch("subprocess.Popen", return_value=mock_proc):
                with mock.patch.object(ControlSocketClient, "is_available", return_value=True):
                    with mock.patch.object(ControlSocketClient, "connect", side_effect=OSError("Refused")):
                        with pytest.raises(OSError):
                            ControlSocketClient.start_and_connect(port=19876)
                        mock_proc.terminate.assert_called_once()


def test_recv_line_overflow() -> None:
    client = ControlSocketClient()
    mock_sock = mock.MagicMock()
    mock_sock.recv.return_value = b"A" * 70000
    client._sock = mock_sock
    with pytest.raises(ControlSocketConnectionError, match="Line buffer exceeded"):
        client._recv_line()


def test_control_socket_connection_failures_and_cleanup() -> None:
    # 1. Connection error during connect()
    client = ControlSocketClient(host="127.0.0.1", port=19876)
    with mock.patch("socket.socket") as mock_sock_cls:
        mock_sock_inst = mock.MagicMock()
        mock_sock_inst.connect.side_effect = OSError("Connection refused")
        mock_sock_cls.return_value = mock_sock_inst
        with pytest.raises(ControlSocketConnectionError, match="Failed to connect"):
            client.connect()
        mock_sock_inst.close.assert_called_once()

    # 2. OSError during disconnect shutdown
    client._sock = mock.MagicMock()
    client._sock.shutdown.side_effect = OSError("Socket not connected")
    client.disconnect()
    assert client._sock is None

    # 3. start_and_connect waiting loop and terminate exception
    fake_exe = Path(r"C:\Proxifier\Proxifier.exe")
    with mock.patch("pyproxifier.process.ProcessController.find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            mock_proc = mock.MagicMock()
            mock_proc.terminate.side_effect = OSError("Access denied")
            with mock.patch("subprocess.Popen", return_value=mock_proc):
                # is_available returns False on first call, True on second
                with mock.patch.object(ControlSocketClient, "is_available", side_effect=[False, True]):
                    with mock.patch.object(ControlSocketClient, "connect"):
                        c = ControlSocketClient.start_and_connect(port=19876, startup_delay=0.1)
                        assert c._proc == mock_proc

            # connect failure when terminate raises OSError during cleanup
            mock_proc_fail = mock.MagicMock()
            mock_proc_fail.terminate.side_effect = OSError("Denied")
            with mock.patch("subprocess.Popen", return_value=mock_proc_fail):
                with mock.patch.object(ControlSocketClient, "is_available", return_value=True):
                    with mock.patch.object(ControlSocketClient, "connect", side_effect=RuntimeError("Crash")):
                        with pytest.raises(RuntimeError):
                            ControlSocketClient.start_and_connect(port=19876)
                        mock_proc_fail.terminate.assert_called_once()

