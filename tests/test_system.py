"""Unit and integration tests for system management and process control."""

from pathlib import Path
import tempfile
from unittest import mock
import pytest

from pyproxifier.exceptions import DriverError, RegistryAccessError
from pyproxifier.models import ProxifierProfile
from pyproxifier.system import SystemManager


def test_silent_install_args_builder() -> None:
    installer = r"C:\Temp\ProxifierSetup.exe"
    args = SystemManager.build_silent_install_args(installer, install_dir=r"C:\Custom\Proxifier")
    assert "/VERYSILENT" in args
    assert "/NORESTART" in args
    assert '/DIR="C:\\Custom\\Proxifier"' in args

    # Without install_dir
    args_no_dir = SystemManager.build_silent_install_args(installer)
    assert len(args_no_dir) == 5
    assert not any(a.startswith('/DIR=') for a in args_no_dir)


def test_install_and_get_license() -> None:
    mock_winreg = mock.MagicMock()
    mock_key = mock.MagicMock(__enter__=mock.MagicMock())
    mock_winreg.CreateKeyEx.return_value = mock_key
    mock_winreg.OpenKey.return_value = mock_key
    mock_winreg.QueryValueEx.side_effect = [("TEST-KEY", 1), ("Test Owner", 1)]

    with mock.patch.dict("sys.modules", {"winreg": mock_winreg}):
        # 1. Install user-level license
        assert SystemManager.install_license("TEST-KEY", "Test Owner", system_wide=False) is True
        mock_winreg.CreateKeyEx.assert_called()

        # 2. Install system-wide license (triggers WOW6432Node write success)
        assert SystemManager.install_license("TEST-KEY", "Test Owner", system_wide=True) is True

        # 2b. Install system-wide license when WOW64 raises OSError
        mock_winreg.CreateKeyEx.side_effect = [mock_key, OSError("WOW64 not available")]
        assert SystemManager.install_license("TEST-KEY", "Test Owner", system_wide=True) is True
        mock_winreg.CreateKeyEx.side_effect = None

        # 3. Read installed license
        lic = SystemManager.get_installed_license(system_wide=False)
        assert lic == ("TEST-KEY", "Test Owner")

        # 4. Read installed license when not found
        mock_winreg.OpenKey.side_effect = FileNotFoundError()
        assert SystemManager.get_installed_license() is None

        # 5. PermissionError -> RegistryAccessError
        mock_winreg.CreateKeyEx.side_effect = PermissionError("Access denied")
        with pytest.raises(RegistryAccessError, match="Permission denied"):
            SystemManager.install_license("K", "O")

        # 6. General Exception -> RegistryAccessError
        mock_winreg.CreateKeyEx.side_effect = RuntimeError("Crash")
        with pytest.raises(RegistryAccessError, match="Failed to install license"):
            SystemManager.install_license("K", "O")


def test_driver_status_and_lifecycle() -> None:
    # 1. is_driver_running True
    mock_proc_running = mock.MagicMock(stdout="STATE: 4 RUNNING", returncode=0)
    with mock.patch("subprocess.run", return_value=mock_proc_running):
        assert SystemManager.is_driver_running() is True

    # 2. is_driver_running False
    mock_proc_stopped = mock.MagicMock(stdout="STATE: 1 STOPPED", returncode=0)
    with mock.patch("subprocess.run", return_value=mock_proc_stopped):
        assert SystemManager.is_driver_running() is False

    # 3. is_driver_running Exception
    with mock.patch("subprocess.run", side_effect=OSError("sc.exe failed")):
        assert SystemManager.is_driver_running() is False

    # 4. start_driver when already running
    with mock.patch.object(SystemManager, "is_driver_running", return_value=True):
        assert SystemManager.start_driver() is True

    # 5. start_driver success via net start
    with mock.patch.object(SystemManager, "is_driver_running", return_value=False):
        with mock.patch("subprocess.run", return_value=mock.MagicMock(returncode=0, stdout="Started successfully")):
            assert SystemManager.start_driver() is True

    # 6. start_driver already started output
    with mock.patch.object(SystemManager, "is_driver_running", return_value=False):
        with mock.patch("subprocess.run", return_value=mock.MagicMock(returncode=2, stdout="service has already been started")):
            assert SystemManager.start_driver() is True

    # 7. start_driver failure exception -> DriverError
    with mock.patch.object(SystemManager, "is_driver_running", return_value=False):
        with mock.patch("subprocess.run", side_effect=OSError("net start failed")):
            with pytest.raises(DriverError, match="Failed to start"):
                SystemManager.start_driver()

    # 8. stop_driver when already stopped
    with mock.patch.object(SystemManager, "is_driver_running", return_value=False):
        assert SystemManager.stop_driver() is True

    # 9. stop_driver success
    with mock.patch.object(SystemManager, "is_driver_running", return_value=True):
        with mock.patch("subprocess.run", return_value=mock.MagicMock(returncode=0)):
            assert SystemManager.stop_driver() is True

    # 10. stop_driver exception -> DriverError
    with mock.patch.object(SystemManager, "is_driver_running", return_value=True):
        with mock.patch("subprocess.run", side_effect=OSError("net stop failed")):
            with pytest.raises(DriverError, match="Failed to stop"):
                SystemManager.stop_driver()


def test_deploy_global_profile() -> None:
    profile = ProxifierProfile.create_default()

    # 1. Custom destination with ProxifierProfile instance
    with tempfile.TemporaryDirectory() as tmpdir:
        dest_path = Path(tmpdir) / "GlobalDefault.ppx"
        result = SystemManager.deploy_global_profile(profile, custom_destination=dest_path)
        assert result.is_file()
        assert dest_path.is_file()

        # 2. Deploy from file path source
        dest_copy = Path(tmpdir) / "CopiedDefault.ppx"
        result_copy = SystemManager.deploy_global_profile(dest_path, custom_destination=dest_copy)
        assert result_copy.is_file()
        assert dest_copy.is_file()

        # 3. Source file does not exist -> FileNotFoundError
        with pytest.raises(FileNotFoundError):
            SystemManager.deploy_global_profile(Path(tmpdir) / "nonexistent.ppx", custom_destination=dest_copy)

    # 4. Default ProgramData destination
    with tempfile.TemporaryDirectory() as tmpdir:
        with mock.patch.dict("os.environ", {"ProgramData": tmpdir}):
            res_default = SystemManager.deploy_global_profile(profile)
            assert res_default == Path(tmpdir) / "Proxifier" / "Default.ppx"
            assert res_default.is_file()
