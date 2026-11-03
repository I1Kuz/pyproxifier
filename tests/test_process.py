"""Unit tests for ProcessController process execution, discovery, and lifecycle management."""

from __future__ import annotations

from pathlib import Path
import subprocess
from unittest import mock
import psutil
import pytest

from pyproxifier.exceptions import ProxifierNotFoundError
from pyproxifier.process import ProcessController


def test_find_proxifier_binary() -> None:
    # 1. Custom path exists
    with mock.patch.object(Path, "is_file", return_value=True):
        custom = Path(r"C:\Custom\Proxifier.exe")
        assert ProcessController.find_proxifier_binary(custom) == custom

    # 2. Discovered via registry
    class FakeKey:
        def __enter__(self) -> FakeKey:
            return self

        def __exit__(self, *args: object) -> None:
            pass

    mock_winreg = mock.MagicMock()
    mock_winreg.OpenKey.return_value = FakeKey()
    mock_winreg.QueryValueEx.return_value = (r"C:\RegistryInstall", 1)

    with mock.patch.dict("sys.modules", {"winreg": mock_winreg}):
        with mock.patch.object(Path, "is_file", side_effect=lambda: True):
            found = ProcessController.find_proxifier_binary()
            assert "RegistryInstall" in str(found)

    # 3. Fallback when nothing found
    with mock.patch.dict("sys.modules", {"winreg": None}):
        with mock.patch.object(Path, "is_file", return_value=False):
            fallback = ProcessController.find_proxifier_binary()
            assert "Proxifier.exe" in str(fallback)


def test_find_tool_binary() -> None:
    # Custom dir
    with mock.patch.object(Path, "is_file", return_value=True):
        res = ProcessController.find_tool_binary("ProxyChecker.exe", custom_dir=r"C:\Custom")
        assert res == Path(r"C:\Custom\ProxyChecker.exe")

    # Found in Proxifier binary parent
    fake_prox = Path(r"C:\Program Files\Proxifier\Proxifier.exe")
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_prox):
        with mock.patch.object(Path, "is_file", side_effect=[True, True]):
            tool = ProcessController.find_tool_binary("ProxyChecker.exe")
            assert tool == Path(r"C:\Program Files\Proxifier\ProxyChecker.exe")

    # Not found anywhere
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=Path(r"C:\None\Proxifier.exe")):
        with mock.patch.object(Path, "is_file", return_value=False):
            assert ProcessController.find_tool_binary("ProxyChecker.exe") is None


def test_is_running_and_get_running_processes() -> None:
    # Mock psutil processes
    proc1 = mock.MagicMock()
    proc1.info = {"name": "Proxifier.exe", "pid": 1234}
    proc2 = mock.MagicMock()
    proc2.info = {"name": "chrome.exe", "pid": 5678}
    proc_err = mock.MagicMock()
    type(proc_err).info = mock.PropertyMock(side_effect=psutil.NoSuchProcess(9999))

    with mock.patch("psutil.process_iter", return_value=[proc_err, proc1, proc2]):
        assert ProcessController.is_running() is True
        procs = ProcessController.get_running_processes()
        assert len(procs) == 1
        assert procs[0].info["pid"] == 1234

    # When not running
    with mock.patch("psutil.process_iter", return_value=[proc2]):
        assert ProcessController.is_running() is False
        assert ProcessController.get_running_processes() == []


def test_start() -> None:
    fake_exe = Path(r"C:\Proxifier\Proxifier.exe")

    # Executable not found
    with mock.patch.object(Path, "is_file", return_value=False):
        with pytest.raises(ProxifierNotFoundError):
            ProcessController.start(executable=fake_exe)

    # Success start with profile and silent=True
    with mock.patch.object(Path, "is_file", return_value=True):
        with mock.patch("subprocess.Popen") as mock_popen:
            mock_popen.return_value = mock.MagicMock()
            profile = Path(r"C:\Profiles\test.ppx")
            proc = ProcessController.start(profile_path=profile, silent=True, executable=fake_exe)
            assert proc is not None
            mock_popen.assert_called_once_with(
                [str(fake_exe), str(profile), "silent-load"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


def test_silent_load() -> None:
    fake_exe = Path(r"C:\Proxifier\Proxifier.exe")
    fake_profile = Path(r"C:\Profiles\test.ppx")

    # Exe not found
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=False):
            with pytest.raises(ProxifierNotFoundError):
                ProcessController.silent_load(fake_profile, executable=fake_exe)

    # Profile not found
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", side_effect=[True, False]):
            with pytest.raises(FileNotFoundError):
                ProcessController.silent_load(fake_profile, executable=fake_exe)

    # Success normal exit
    mock_proc = mock.MagicMock()
    mock_proc.wait.return_value = 0
    mock_proc.returncode = 0
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("subprocess.Popen", return_value=mock_proc):
                assert ProcessController.silent_load(fake_profile, executable=fake_exe) is True

    # TimeoutExpired (running in GUI background)
    mock_proc_timeout = mock.MagicMock()
    mock_proc_timeout.wait.side_effect = subprocess.TimeoutExpired(cmd=["test"], timeout=0.8)
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("subprocess.Popen", return_value=mock_proc_timeout):
                assert ProcessController.silent_load(fake_profile, executable=fake_exe) is True


def test_kill() -> None:
    # No processes running
    with mock.patch.object(ProcessController, "get_running_processes", return_value=[]):
        assert ProcessController.kill() == 0

    # Processes running
    mock_p1 = mock.MagicMock()
    mock_p2 = mock.MagicMock()
    mock_p2.terminate.side_effect = psutil.AccessDenied()
    mock_p1.kill.side_effect = psutil.AccessDenied()

    with mock.patch.object(ProcessController, "get_running_processes", return_value=[mock_p1, mock_p2]):
        with mock.patch("psutil.wait_procs", return_value=([], [mock_p1])):
            killed = ProcessController.kill(timeout=1.0)
            assert killed == 2
            mock_p1.terminate.assert_called_once()
            mock_p1.kill.assert_called_once()


def test_convert_and_quit() -> None:
    fake_exe = Path(r"C:\Proxifier\Proxifier.exe")
    fake_profile = Path(r"C:\Profiles\old.prx")

    # Exe not found
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=False):
            with pytest.raises(ProxifierNotFoundError):
                ProcessController.convert_and_quit(fake_profile, executable=fake_exe)

    # Profile not found
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", side_effect=[True, False]):
            with pytest.raises(FileNotFoundError):
                ProcessController.convert_and_quit(fake_profile, executable=fake_exe)

    # Run success
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.MagicMock(returncode=0)
                assert ProcessController.convert_and_quit(fake_profile, executable=fake_exe) is True


def test_register_license() -> None:
    fake_exe = Path(r"C:\Proxifier\Proxifier.exe")

    # Exe not found
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=False):
            with pytest.raises(ProxifierNotFoundError):
                ProcessController.register_license("KEY-12345", executable=fake_exe)

    # Empty key
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            with pytest.raises(ValueError, match="License key cannot be empty"):
                ProcessController.register_license("   ", executable=fake_exe)

    # Run success
    with mock.patch.object(ProcessController, "find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.MagicMock(returncode=0)
                assert ProcessController.register_license("KFZUS-77N28-R95CY-...", executable=fake_exe) is True
