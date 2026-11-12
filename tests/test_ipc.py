"""Unit tests for native IPC mechanisms (Window Message, Named Pipe, WFP Driver, and IPCManager)."""

import ctypes
from pathlib import Path
from typing import Any
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from pyproxifier.ipc import (
    ControlSocketClient,
    DriverIPC,
    IPCManager,
    NamedPipeClient,
    ServiceIPC,
    WindowIPC,
)
from pyproxifier.ipc.win32 import handle_to_int, is_invalid_handle
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.models.proxy import ProxyItem, ProxyProtocol
from pyproxifier.models.rule import ActionType, RuleItem


# ===========================================================================
# Win32 Utility Tests
# ===========================================================================

def test_is_invalid_handle() -> None:
    assert is_invalid_handle(None) is True
    assert is_invalid_handle(0) is True
    assert is_invalid_handle(-1) is True
    assert is_invalid_handle(0xFFFFFFFF) is True
    assert is_invalid_handle(0xFFFFFFFFFFFFFFFF) is True
    assert is_invalid_handle(1234) is False
    assert is_invalid_handle(0x15c) is False
    assert is_invalid_handle(ctypes.c_void_p(0)) is True
    assert is_invalid_handle(ctypes.c_void_p(None)) is True
    assert is_invalid_handle(ctypes.c_void_p(-1)) is True
    assert is_invalid_handle(ctypes.c_void_p(0x15c)) is False


def test_handle_to_int() -> None:
    assert handle_to_int(None) is None
    assert handle_to_int(0) is None
    assert handle_to_int(-1) is None
    assert handle_to_int(0xFFFFFFFF) is None
    assert handle_to_int(0xFFFFFFFFFFFFFFFF) is None
    assert handle_to_int(1234) == 1234
    assert handle_to_int(0x15c) == 0x15c
    assert handle_to_int(ctypes.c_void_p(0)) is None
    assert handle_to_int(ctypes.c_void_p(-1)) is None
    assert handle_to_int(ctypes.c_void_p(0x15c)) == 0x15c


# ===========================================================================
# WindowIPC Tests
# ===========================================================================

def test_window_ipc_is_instance_running_true() -> None:
    with patch("ctypes.windll.kernel32.OpenMutexW", return_value=123):
        with patch("ctypes.windll.kernel32.CloseHandle") as mock_close:
            assert WindowIPC.is_instance_running() is True
            mock_close.assert_called_once_with(123)


def test_window_ipc_is_instance_running_false() -> None:
    with patch("ctypes.windll.kernel32.OpenMutexW", return_value=0):
        assert WindowIPC.is_instance_running() is False


def test_window_ipc_find_window_by_class() -> None:
    with patch("ctypes.windll.user32.FindWindowW", side_effect=[0x1234, 0]):
        hwnd = WindowIPC.find_window()
        assert hwnd == 0x1234


def test_window_ipc_find_window_fallback_title() -> None:
    with patch("ctypes.windll.user32.FindWindowW", side_effect=[0, 0x5678]):
        hwnd = WindowIPC.find_window()
        assert hwnd == 0x5678


def test_window_ipc_find_window_not_found() -> None:
    with patch("ctypes.windll.user32.FindWindowW", return_value=0):
        hwnd = WindowIPC.find_window()
        assert hwnd is None


def test_window_ipc_is_hung() -> None:
    with patch("ctypes.windll.user32.IsHungAppWindow", return_value=1):
        assert WindowIPC.is_hung(0x1234) is True
    with patch("ctypes.windll.user32.IsHungAppWindow", return_value=0):
        assert WindowIPC.is_hung(0x1234) is False


def test_window_ipc_get_window_pid() -> None:
    def fake_get_pid(_hwnd: int, byref_val: Any) -> int:
        byref_val._obj.value = 4321
        return 1

    with patch("ctypes.windll.user32.GetWindowThreadProcessId", side_effect=fake_get_pid):
        pid = WindowIPC.get_window_pid(0x1234)
        assert pid == 4321


def test_window_ipc_bring_to_front() -> None:
    with patch.object(WindowIPC, "find_window", return_value=0x1234):
        with patch("ctypes.windll.user32.ShowWindow") as mock_show:
            with patch("ctypes.windll.user32.SetForegroundWindow") as mock_set:
                assert WindowIPC.bring_to_front() is True
                mock_show.assert_called_once()
                mock_set.assert_called_once_with(0x1234)

    with patch.object(WindowIPC, "find_window", return_value=None):
        assert WindowIPC.bring_to_front() is False


def test_window_ipc_minimize_to_tray() -> None:
    with patch.object(WindowIPC, "find_window", return_value=0x1234):
        with patch("ctypes.windll.user32.ShowWindow") as mock_show:
            assert WindowIPC.minimize_to_tray() is True
            mock_show.assert_called_once()

    with patch.object(WindowIPC, "find_window", return_value=None):
        assert WindowIPC.minimize_to_tray() is False


def test_window_ipc_post_close_message() -> None:
    with patch.object(WindowIPC, "find_window", return_value=0x1234):
        with patch("ctypes.windll.user32.PostMessageW", return_value=1) as mock_post:
            assert WindowIPC.post_close_message() is True
            mock_post.assert_called_once_with(0x1234, 0x0010, 0, 0)

    with patch.object(WindowIPC, "find_window", return_value=None):
        assert WindowIPC.post_close_message() is False


def test_window_ipc_is_pid_proxifier() -> None:
    with patch("ctypes.windll.kernel32.OpenMutexW", return_value=123):
        with patch("ctypes.windll.kernel32.CloseHandle") as mock_close:
            assert WindowIPC.is_pid_proxifier(12204) is True
            mock_close.assert_called_once_with(123)

    with patch("ctypes.windll.kernel32.OpenMutexW", return_value=0):
        assert WindowIPC.is_pid_proxifier(99999) is False


def test_window_ipc_find_proxifier_pids() -> None:
    fake_proc1 = MagicMock()
    fake_proc1.info = {"pid": 12204}
    fake_proc2 = MagicMock()
    fake_proc2.info = {"pid": 5555}

    def check_pid(pid: int) -> bool:
        return pid == 12204

    with patch.object(WindowIPC, "is_instance_running", return_value=True):
        with patch("psutil.process_iter", return_value=[fake_proc1, fake_proc2]):
            with patch.object(WindowIPC, "is_pid_proxifier", side_effect=check_pid):
                pids = WindowIPC.find_proxifier_pids()
                assert pids == [12204]

    with patch.object(WindowIPC, "is_instance_running", return_value=False):
        assert WindowIPC.find_proxifier_pids() == []


def test_window_ipc_is_send_delay_enabled() -> None:
    with patch("ctypes.windll.kernel32.OpenMutexW", return_value=123):
        with patch("ctypes.windll.kernel32.CloseHandle") as mock_close:
            assert WindowIPC.is_send_delay_enabled() is True
            mock_close.assert_called_once_with(123)

    with patch("ctypes.windll.kernel32.OpenMutexW", return_value=0):
        assert WindowIPC.is_send_delay_enabled() is False


# ===========================================================================
# NamedPipeClient Tests
# ===========================================================================

def test_named_pipe_is_pipe_available() -> None:
    with patch("ctypes.windll.kernel32.WaitNamedPipeW", return_value=1):
        assert NamedPipeClient.is_pipe_available() is True
    with patch("ctypes.windll.kernel32.WaitNamedPipeW", return_value=0):
        assert NamedPipeClient.is_pipe_available() is False


def test_named_pipe_is_service_running() -> None:
    with patch("ctypes.windll.kernel32.OpenMutexW", return_value=456):
        with patch("ctypes.windll.kernel32.CloseHandle") as mock_close:
            assert NamedPipeClient.is_service_running() is True
            mock_close.assert_called_once_with(456)

    with patch("ctypes.windll.kernel32.OpenMutexW", return_value=0):
        assert NamedPipeClient.is_service_running() is False


def test_named_pipe_connect_and_close() -> None:
    client = NamedPipeClient()
    assert client.is_connected is False

    with patch("ctypes.windll.kernel32.CreateFileW", return_value=789):
        client.connect()
        assert client.is_connected is True

        with patch("ctypes.windll.kernel32.CloseHandle") as mock_close:
            client.close()
            assert client.is_connected is False
            mock_close.assert_called_once_with(789)


def test_named_pipe_connect_failure() -> None:
    client = NamedPipeClient()
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=-1):
        with patch("ctypes.windll.kernel32.GetLastError", return_value=2):
            with pytest.raises(ConnectionError, match="Failed to connect to named pipe"):
                client.connect()


def test_named_pipe_context_manager() -> None:
    client = NamedPipeClient()
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=789):
        with patch("ctypes.windll.kernel32.CloseHandle") as mock_close:
            with client as c:
                assert c.is_connected is True
            assert client.is_connected is False
            mock_close.assert_called_once_with(789)


def test_named_pipe_send_and_receive_unconnected() -> None:
    client = NamedPipeClient()
    with pytest.raises(ConnectionError, match="Not connected"):
        _ = client.send(b"test")
    with pytest.raises(ConnectionError, match="Not connected"):
        _ = client.receive()


def test_named_pipe_send_success() -> None:
    client = NamedPipeClient()
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=123):
        client.connect()

    def fake_write(_handle: int, _buf: bytes, size: int, byref_written: Any, _overlapped: Any) -> int:
        byref_written._obj.value = size
        return 1

    with patch("ctypes.windll.kernel32.WriteFile", side_effect=fake_write):
        res = client.send(b"hello")
        assert res == 5


def test_named_pipe_send_error() -> None:
    client = NamedPipeClient()
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=123):
        client.connect()
    with patch("ctypes.windll.kernel32.WriteFile", return_value=0):
        with patch("ctypes.windll.kernel32.GetLastError", return_value=5):
            with pytest.raises(OSError, match="Failed to write to named pipe"):
                _ = client.send(b"hello")


def test_named_pipe_receive_error() -> None:
    client = NamedPipeClient()
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=123):
        client.connect()
    with patch("ctypes.windll.kernel32.ReadFile", return_value=0):
        with patch("ctypes.windll.kernel32.GetLastError", return_value=109):
            with pytest.raises(OSError, match="Failed to read from named pipe"):
                _ = client.receive()


def test_named_pipe_transact() -> None:
    client = NamedPipeClient()
    with patch.object(client, "send", return_value=5) as mock_send:
        with patch.object(client, "receive", return_value=b"response") as mock_recv:
            resp = client.transact(b"request")
            assert resp == b"response"
            mock_send.assert_called_once_with(b"request")
            mock_recv.assert_called_once_with(buffer_size=4096)


def test_named_pipe_send_profile_bytes() -> None:
    client = NamedPipeClient()
    with (
        patch.object(client, "connect") as mock_connect,
        patch.object(client, "send", return_value=12) as mock_send,
    ):
        n = client.send_profile(b"<ProxifierProfile/>")
        assert n == 12
        mock_connect.assert_called_once()
        mock_send.assert_called_once_with(b"<ProxifierProfile/>")


def test_named_pipe_send_profile_str() -> None:
    client = NamedPipeClient()
    client._handle = 1234  # pyright: ignore[reportPrivateUsage]
    with patch.object(client, "send", return_value=19) as mock_send:
        n = client.send_profile("<ProxifierProfile/>")
        assert n == 19
        mock_send.assert_called_once_with(b"<ProxifierProfile/>")


def test_named_pipe_send_profile_oversized() -> None:
    client = NamedPipeClient()
    huge = b"A" * (6 * 1024 * 1024)
    with pytest.raises(ValueError, match="exceeds Proxifier pipe maximum"):
        _ = client.send_profile(huge)


# ===========================================================================
# DriverIPC Tests
# ===========================================================================

def test_driver_is_device_present_handle_ok() -> None:
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=123):
        with patch("ctypes.windll.kernel32.CloseHandle") as mock_close:
            assert DriverIPC.is_device_present() is True
            mock_close.assert_called_once_with(123)


def test_driver_is_device_present_access_denied() -> None:
    # Handle = -1, but GetLastError = 5 (ERROR_ACCESS_DENIED) -> Device exists!
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=-1):
        with patch("ctypes.windll.kernel32.GetLastError", return_value=5):
            assert DriverIPC.is_device_present() is True


def test_driver_is_device_present_not_found() -> None:
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=-1):
        with patch("ctypes.windll.kernel32.GetLastError", return_value=2):  # ERROR_FILE_NOT_FOUND
            assert DriverIPC.is_device_present() is False


def test_driver_open_and_close() -> None:
    drv = DriverIPC()
    assert drv.is_connected is False

    with patch("ctypes.windll.kernel32.CreateFileW", return_value=999):
        drv.open(write_access=True)
        assert drv.is_connected is True

        with patch("ctypes.windll.kernel32.CloseHandle") as mock_close:
            drv.close()
            assert drv.is_connected is False
            mock_close.assert_called_once_with(999)


def test_driver_open_permission_denied() -> None:
    drv = DriverIPC()
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=-1):
        with patch("ctypes.windll.kernel32.GetLastError", return_value=5):
            with pytest.raises(PermissionError, match="Administrator privileges required"):
                drv.open()


def test_driver_context_manager() -> None:
    drv = DriverIPC()
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=999):
        with patch("ctypes.windll.kernel32.CloseHandle") as mock_close:
            with drv as d:
                assert d.is_connected is True
            assert drv.is_connected is False
            mock_close.assert_called_once_with(999)


def test_driver_ioctl_unconnected() -> None:
    drv = DriverIPC()
    with pytest.raises(ConnectionError, match="Driver handle is not open"):
        _ = drv.ioctl(0x1234)


def test_driver_ioctl_success() -> None:
    drv = DriverIPC()
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=999):
        drv.open()
    with patch("ctypes.windll.kernel32.DeviceIoControl", return_value=1):
        out = drv.ioctl(0x1234, in_data=b"test")
        assert isinstance(out, bytes)


def test_driver_ioctl_error() -> None:
    drv = DriverIPC()
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=999):
        drv.open()
    with patch("ctypes.windll.kernel32.DeviceIoControl", return_value=0):
        with patch("ctypes.windll.kernel32.GetLastError", return_value=1):
            with pytest.raises(OSError, match="DeviceIoControl"):
                _ = drv.ioctl(0x1234)


# ===========================================================================
# IPCManager Tests
# ===========================================================================

@pytest.fixture
def sample_profile() -> ProxifierProfile:
    prof = ProxifierProfile()
    prof.proxies.append(ProxyItem(id=100, address="127.0.0.1", port=9050, protocol_type=ProxyProtocol.SOCKS5))
    prof.rules.append(RuleItem(name="Default", action_type=ActionType.DIRECT))
    return prof


def test_ipc_manager_status_checks() -> None:
    mgr = IPCManager()
    with patch.object(ControlSocketClient, "is_available", return_value=True):
        assert mgr.is_socket_ready() is True

    with patch.object(NamedPipeClient, "is_pipe_available", return_value=True):
        assert mgr.is_pipe_ready() is True

    with patch.object(DriverIPC, "is_device_present", return_value=True):
        assert mgr.is_driver_ready() is True

    with patch.object(WindowIPC, "is_instance_running", return_value=True):
        assert mgr.is_proxifier_running() is True


def test_ipc_manager_apply_strategy_1_socket_listening(sample_profile: ProxifierProfile) -> None:
    mgr = IPCManager()
    mock_client = MagicMock()

    with patch.object(mgr, "is_socket_ready", return_value=True):
        with patch.object(mgr, "get_socket_client", return_value=mock_client):
            mock_client.__enter__.return_value = mock_client
            result = mgr.apply_profile(sample_profile)
            assert result is True
            mock_client.load_config.assert_called_once_with(sample_profile)


def test_ipc_manager_apply_strategy_2_not_running(sample_profile: ProxifierProfile) -> None:
    mgr = IPCManager()
    mock_client = MagicMock()

    with patch.object(mgr, "is_socket_ready", return_value=False):
        with patch.object(mgr, "is_proxifier_running", return_value=False):
            with patch.object(ControlSocketClient, "start_and_connect", return_value=mock_client):
                result = mgr.apply_profile(sample_profile)
                assert result is True
                mock_client.load_config.assert_called_once_with(sample_profile)
                mock_client.disconnect.assert_called_once()


def test_ipc_manager_apply_strategy_3_running_pipe_delivery(
    sample_profile: ProxifierProfile,
) -> None:
    mgr = IPCManager()
    mock_pipe = MagicMock()

    with patch.object(mgr, "is_socket_ready", return_value=False):
        with patch.object(mgr, "is_proxifier_running", return_value=True):
            with patch.object(mgr, "is_pipe_ready", return_value=True):
                with patch.object(mgr, "pipe", return_value=mock_pipe):
                    mock_pipe.__enter__.return_value = mock_pipe
                    result = mgr.apply_profile(sample_profile)
                    assert result is True
                    mock_pipe.send_profile.assert_called_once_with(sample_profile)


def test_ipc_manager_apply_strategy_4_running_fallback_silent_load(
    sample_profile: ProxifierProfile,
) -> None:
    mgr = IPCManager()

    with patch.object(mgr, "is_socket_ready", return_value=False):
        with patch.object(mgr, "is_proxifier_running", return_value=True):
            with patch.object(mgr, "is_pipe_ready", return_value=False):
                with patch("pyproxifier.process.ProcessController.silent_load", return_value=True) as mock_silent:
                    result = mgr.apply_profile(sample_profile)
                    assert result is True
                    mock_silent.assert_called_once()


def test_ipc_manager_apply_detailed_status_distinction(sample_profile: ProxifierProfile) -> None:
    from pyproxifier.ipc.status import ApplyStatus

    mgr = IPCManager()

    # 1. When Proxifier was NOT running, strategy 4 reports PROCESS_SPAWNED
    with patch.object(mgr, "is_socket_ready", return_value=False):
        with patch.object(mgr, "is_proxifier_running", return_value=False):
            with patch.object(mgr, "is_pipe_ready", return_value=False):
                with patch("pyproxifier.process.ProcessController.silent_load", return_value=True):
                    res = mgr.apply_profile_detailed(sample_profile, use_socket=False)
                    assert res.applied is True
                    assert res.status == ApplyStatus.PROCESS_SPAWNED

    # 2. When Proxifier WAS running, strategy 4 reports COMMAND_DELIVERED
    with patch.object(mgr, "is_socket_ready", return_value=False):
        with patch.object(mgr, "is_proxifier_running", return_value=True):
            with patch.object(mgr, "is_pipe_ready", return_value=False):
                with patch("pyproxifier.process.ProcessController.silent_load", return_value=True):
                    res2 = mgr.apply_profile_detailed(sample_profile, use_socket=False)
                    assert res2.applied is True
                    assert res2.status == ApplyStatus.COMMAND_DELIVERED

    # 3. When silent_load fails, strategy 4 reports FAILED
    with patch.object(mgr, "is_socket_ready", return_value=False):
        with patch.object(mgr, "is_proxifier_running", return_value=True):
            with patch.object(mgr, "is_pipe_ready", return_value=False):
                with patch("pyproxifier.process.ProcessController.silent_load", return_value=False):
                    res3 = mgr.apply_profile_detailed(sample_profile, use_socket=False)
                    assert res3.applied is False
                    assert res3.status == ApplyStatus.FAILED
                    assert bool(res3) is False


def test_ipc_manager_graceful_exit_via_socket() -> None:
    mgr = IPCManager()
    mock_client = MagicMock()

    with patch.object(mgr, "is_socket_ready", return_value=True):
        with patch.object(mgr, "get_socket_client", return_value=mock_client):
            mock_client.__enter__.return_value = mock_client
            assert mgr.graceful_exit() is True
            mock_client.exit.assert_called_once()


def test_ipc_manager_graceful_exit_via_window_message() -> None:
    mgr = IPCManager()

    with patch.object(mgr, "is_socket_ready", return_value=False):
        with patch.object(WindowIPC, "post_close_message", return_value=True) as mock_post:
            assert mgr.graceful_exit() is True
            mock_post.assert_called_once()


def test_ipc_manager_graceful_exit_failed() -> None:
    mgr = IPCManager()

    with patch.object(mgr, "is_socket_ready", return_value=False):
        with patch.object(WindowIPC, "post_close_message", return_value=False):
            assert mgr.graceful_exit() is False


# ===========================================================================
# ServiceIPC & CLI Automation Tests
# ===========================================================================

def test_service_ipc_find_binary(tmp_path: Path) -> None:
    fake_exe = tmp_path / "ServiceManager.exe"
    fake_exe.write_bytes(b"MZ")
    assert ServiceIPC.find_service_manager_binary(custom_path=fake_exe) == fake_exe


def test_service_ipc_is_service_running_via_mutex() -> None:
    with patch("ctypes.windll.kernel32.OpenMutexW", return_value=123):
        with patch("ctypes.windll.kernel32.CloseHandle") as mock_close:
            assert ServiceIPC.is_service_running() is True
            mock_close.assert_called_once_with(123)


def test_service_ipc_is_service_running_via_scm() -> None:
    with patch("ctypes.windll.kernel32.OpenMutexW", return_value=0):
        with patch("ctypes.windll.advapi32.OpenSCManagerW", return_value=0x10):
            with patch("ctypes.windll.advapi32.OpenServiceW", return_value=0x20):
                def fake_query(_svc: int, _info: int, buf: Any, _sz: int, _needed: Any) -> int:
                    # Set status.dwCurrentState = 4 (SERVICE_RUNNING)
                    buf._obj.dwCurrentState = 4
                    return 1

                with patch("ctypes.windll.advapi32.QueryServiceStatusEx", side_effect=fake_query):
                    with patch("ctypes.windll.advapi32.CloseServiceHandle"):
                        assert ServiceIPC.is_service_running() is True


def test_service_ipc_commands(tmp_path: Path) -> None:
    fake_exe = tmp_path / "ServiceManager.exe"
    fake_exe.write_bytes(b"MZ")

    with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
        assert ServiceIPC.install(silent=True, custom_binary=fake_exe) is True
        mock_run.assert_called_with([str(fake_exe), "silent-install"], stdout=-3, stderr=-3, timeout=10.0, check=False)

    with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
        assert ServiceIPC.uninstall(silent=False, custom_binary=fake_exe) is True
        mock_run.assert_called_with([str(fake_exe), "uninstall"], stdout=-3, stderr=-3, timeout=10.0, check=False)

    with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
        assert ServiceIPC.start(silent=True, custom_binary=fake_exe) is True
        mock_run.assert_called_with([str(fake_exe), "silent-start"], stdout=-3, stderr=-3, timeout=10.0, check=False)

    with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
        assert ServiceIPC.stop(silent=True, custom_binary=fake_exe) is True
        mock_run.assert_called_with([str(fake_exe), "silent-stop"], stdout=-3, stderr=-3, timeout=10.0, check=False)


def test_service_ipc_deploy_service_profile(tmp_path: Path, sample_profile: ProxifierProfile) -> None:
    dest = tmp_path / "ServiceProfile.ppx"
    out_path = ServiceIPC.deploy_service_profile(sample_profile, custom_destination=dest)
    assert out_path.is_file()
    assert "<ProxifierProfile" in out_path.read_text(encoding="utf-8")


def test_process_controller_convert_and_quit(tmp_path: Path) -> None:
    fake_exe = tmp_path / "Proxifier.exe"
    fake_exe.write_bytes(b"MZ")
    fake_prx = tmp_path / "old.prx"
    fake_prx.write_text("old content", encoding="utf-8")

    from pyproxifier.process import ProcessController

    with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
        res = ProcessController.convert_and_quit(fake_prx, executable=fake_exe)
        assert res is True
        mock_run.assert_called_once_with(
            [str(fake_exe), str(fake_prx), "convert-and-quit"],
            stdout=-3,
            stderr=-3,
            timeout=5.0,
            check=False,
        )


def test_process_controller_register_license(tmp_path: Path) -> None:
    fake_exe = tmp_path / "Proxifier.exe"
    fake_exe.write_bytes(b"MZ")

    from pyproxifier.process import ProcessController

    with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
        res = ProcessController.register_license("2T3Z1-ABCDE-FGHIJ-KLMNO-PQRST", executable=fake_exe)
        assert res is True
        mock_run.assert_called_once_with(
            [str(fake_exe), "register", "2T3Z1-ABCDE-FGHIJ-KLMNO-PQRST"],
            stdout=-3,
            stderr=-3,
            timeout=5.0,
            check=False,
        )


def test_ipc_manager_helpers(tmp_path: Path) -> None:
    mgr = IPCManager()
    with patch.object(ServiceIPC, "is_service_running", return_value=True):
        assert mgr.is_service_ready() is True

    fake_file = tmp_path / "test.prx"
    fake_file.write_text("prx", encoding="utf-8")
    with patch("pyproxifier.process.ProcessController.convert_and_quit", return_value=True) as mock_conv:
        assert mgr.convert_profile(fake_file) is True
        mock_conv.assert_called_once()

    with patch("pyproxifier.process.ProcessController.register_license", return_value=True) as mock_reg:
        assert mgr.register_license("KEY") is True
        mock_reg.assert_called_once()


def test_win32_edge_cases() -> None:
    from pyproxifier.ipc.win32 import setup_win32_prototypes

    # Object without value attribute and not int
    assert is_invalid_handle(object()) is False

    # handle_to_int with uncastable object
    assert handle_to_int(object()) is None

    # setup_win32_prototypes when platform is not win32
    with patch("sys.platform", "linux"):
        setup_win32_prototypes()

    # setup_win32_prototypes when ctypes has no windll
    with patch("sys.platform", "win32"):
        with patch.object(ctypes, "windll", create=True):
            del ctypes.windll
            setup_win32_prototypes()


def test_driver_open_already_connected() -> None:
    driver = DriverIPC()
    driver._handle = 1234  # pyright: ignore[reportPrivateUsage]
    assert driver.is_connected is True
    # Calling open when already connected should return immediately
    driver.open()
    assert driver._handle == 1234  # pyright: ignore[reportPrivateUsage]


def test_pipe_edge_cases(sample_profile: ProxifierProfile) -> None:
    pipe = NamedPipeClient()
    pipe._handle = 1234  # pyright: ignore[reportPrivateUsage]
    assert pipe.is_connected is True

    # 1. connect when already connected
    pipe.connect()
    assert pipe._handle == 1234  # pyright: ignore[reportPrivateUsage]

    # 2. connect retry on ERROR_PIPE_BUSY (231)
    pipe_busy = NamedPipeClient()
    with patch("ctypes.windll.kernel32.CreateFileW", return_value=-1):
        with patch("ctypes.windll.kernel32.GetLastError", side_effect=[231, 2]):
            with patch("ctypes.windll.kernel32.WaitNamedPipeW", return_value=True) as mock_wait:
                with pytest.raises(ConnectionError):
                    pipe_busy.connect()
                mock_wait.assert_called_once()

    # 3. receive success and timeout
    pipe2 = NamedPipeClient()
    pipe2._handle = 1234  # pyright: ignore[reportPrivateUsage]
    with patch("ctypes.windll.kernel32.ReadFile", return_value=True):
        assert isinstance(pipe2.receive(), bytes)

    # 4. send_profile with ProxifierProfile instance
    pipe3 = NamedPipeClient()
    pipe3._handle = 1234  # pyright: ignore[reportPrivateUsage]
    with patch.object(pipe3, "send", return_value=128):
        bytes_sent = pipe3.send_profile(sample_profile)
        assert bytes_sent == 128


def test_window_edge_cases() -> None:
    # is_pid_proxifier with pid <= 0
    assert WindowIPC.is_pid_proxifier(0) is False
    assert WindowIPC.is_pid_proxifier(-10) is False

    # find_proxifier_pids with psutil exceptions
    import psutil
    proc_err1 = MagicMock()
    type(proc_err1).info = mock.PropertyMock(side_effect=psutil.NoSuchProcess(10))
    proc_err2 = MagicMock()
    type(proc_err2).info = mock.PropertyMock(side_effect=psutil.AccessDenied())

    with patch.object(WindowIPC, "is_instance_running", return_value=True):
        with patch("psutil.process_iter", return_value=[proc_err1, proc_err2]):
            assert WindowIPC.find_proxifier_pids() == []


def test_ipc_manager_fallbacks_and_errors(sample_profile: ProxifierProfile, tmp_path: Path) -> None:
    mgr = IPCManager()

    # get_socket_client default port
    sc = mgr.get_socket_client()
    assert sc.port == 19876

    # apply_profile: Strategy 3 pipe delivery fails -> logs debug and falls back to Strategy 4
    with patch.object(mgr, "is_socket_ready", return_value=False):
        with patch.object(mgr, "is_proxifier_running", return_value=True):
            with patch.object(mgr, "is_pipe_ready", return_value=True):
                mock_pipe = MagicMock()
                mock_pipe.__enter__.return_value = mock_pipe
                mock_pipe.send_profile.side_effect = RuntimeError("Pipe write failed")
                with patch.object(mgr, "pipe", return_value=mock_pipe):
                    with patch("pyproxifier.process.ProcessController.silent_load", return_value=True) as mock_sl:
                        with patch("pathlib.Path.unlink", side_effect=OSError("Locked")):
                            assert mgr.apply_profile(sample_profile, validate=False) is True
                            mock_sl.assert_called_once()

    # graceful_exit: ControlSocketConnectionError falls back to window message
    from pyproxifier.exceptions import ControlSocketConnectionError
    with patch.object(mgr, "is_socket_ready", return_value=True):
        mock_sc = MagicMock()
        mock_sc.__enter__.return_value = mock_sc
        mock_sc.exit.side_effect = ControlSocketConnectionError("Disconnected")
        with patch.object(mgr, "get_socket_client", return_value=mock_sc):
            with patch.object(WindowIPC, "post_close_message", return_value=True):
                assert mgr.graceful_exit() is True


def test_service_ipc_scenarios(tmp_path: Path, sample_profile: ProxifierProfile) -> None:
    from pyproxifier.exceptions import ProcessError

    # 1. find_service_manager_binary without custom path
    with patch("pyproxifier.process.ProcessController.find_tool_binary", return_value=Path(r"C:\ServiceManager.exe")):
        assert ServiceIPC.find_service_manager_binary() == Path(r"C:\ServiceManager.exe")

    with patch("ctypes.windll.advapi32.CloseServiceHandle", return_value=True):
        # 2. is_service_running: SCM handle invalid
        with patch("ctypes.windll.kernel32.OpenMutexW", return_value=0):
            with patch("ctypes.windll.advapi32.OpenSCManagerW", return_value=0):
                assert ServiceIPC.is_service_running() is False

        # 3. is_service_running: service handle invalid
        with patch("ctypes.windll.kernel32.OpenMutexW", return_value=0):
            with patch("ctypes.windll.advapi32.OpenSCManagerW", return_value=100):
                with patch("ctypes.windll.advapi32.OpenServiceW", return_value=0):
                    assert ServiceIPC.is_service_running() is False

        # 4. is_service_running: QueryServiceStatusEx returns False
        with patch("ctypes.windll.kernel32.OpenMutexW", return_value=0):
            with patch("ctypes.windll.advapi32.OpenSCManagerW", return_value=100):
                with patch("ctypes.windll.advapi32.OpenServiceW", return_value=200):
                    with patch("ctypes.windll.advapi32.QueryServiceStatusEx", return_value=False):
                        assert ServiceIPC.is_service_running() is False

        # 5. is_service_installed checks
        with patch("ctypes.windll.advapi32.OpenSCManagerW", return_value=0):
            assert ServiceIPC.is_service_installed() is False

        with patch("ctypes.windll.advapi32.OpenSCManagerW", return_value=100):
            with patch("ctypes.windll.advapi32.OpenServiceW", return_value=0):
                assert ServiceIPC.is_service_installed() is False

        with patch("ctypes.windll.advapi32.OpenSCManagerW", return_value=100):
            with patch("ctypes.windll.advapi32.OpenServiceW", return_value=200):
                assert ServiceIPC.is_service_installed() is True

    # 6. _run_service_manager_command: binary not found
    with patch.object(ServiceIPC, "find_service_manager_binary", return_value=None):
        with pytest.raises(ProcessError, match="ServiceManager.exe not found"):
            ServiceIPC.install()

    # 7. _run_service_manager_command: TimeoutExpired / OSError
    fake_exe = tmp_path / "ServiceManager.exe"
    fake_exe.write_bytes(b"MZ")
    with patch.object(ServiceIPC, "find_service_manager_binary", return_value=fake_exe):
        with patch("subprocess.run", side_effect=OSError("Execution failed")):
            assert ServiceIPC.uninstall() is False

    # 8. resolve_service_profile_path fallback & primary
    p_data = tmp_path / "ProgramData"
    primary_dir = p_data / "Proxifier4" / "Profiles"
    primary_dir.mkdir(parents=True)
    with patch.dict("os.environ", {"ProgramData": str(p_data)}):
        assert ServiceIPC.resolve_service_profile_path() == primary_dir / "ServiceProfile.ppx"

    # Fallback to Proxifier/Profiles
    primary_dir.rmdir()
    fallback_dir = p_data / "Proxifier" / "Profiles"
    fallback_dir.mkdir(parents=True)
    with patch.dict("os.environ", {"ProgramData": str(p_data)}):
        assert ServiceIPC.resolve_service_profile_path() == fallback_dir / "ServiceProfile.ppx"

    # 9. deploy_service_profile from file
    fake_source = tmp_path / "Source.ppx"
    fake_source.write_text("<ProxifierProfile />", encoding="utf-8")
    dest_path = tmp_path / "ServiceProfile.ppx"
    res_deploy = ServiceIPC.deploy_service_profile(fake_source, custom_destination=dest_path)
    assert res_deploy == dest_path
    assert dest_path.is_file()

    # 10. deploy_service_profile from missing file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        ServiceIPC.deploy_service_profile(tmp_path / "missing.ppx", custom_destination=dest_path)

