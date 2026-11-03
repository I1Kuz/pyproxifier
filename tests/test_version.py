"""Unit tests for installed Proxifier version detection and package version metadata."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from pyproxifier.version import __version__, get_installed_proxifier_version


def test_version_string() -> None:
    assert __version__ == "1.0.0"


def test_version_detection_scenarios() -> None:
    fake_exe = Path(r"C:\Proxifier\Proxifier.exe")

    # 1. Binary not found
    with mock.patch("pyproxifier.process.ProcessController.find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=False):
            assert get_installed_proxifier_version() is None

    # 2. Proxifier4 AppData exists
    with mock.patch("pyproxifier.process.ProcessController.find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch.object(Path, "exists", return_value=True):
                assert get_installed_proxifier_version() == 4

    # 3. Proxifier (v3) AppData exists
    with mock.patch("pyproxifier.process.ProcessController.find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            def exists_side_effect(self: Path) -> bool:
                return "Proxifier4" not in str(self) and "Proxifier" in str(self)

            with mock.patch.object(Path, "exists", autospec=True, side_effect=exists_side_effect):
                assert get_installed_proxifier_version() == 3

    # 4. Registry check (first hive raises OSError, second succeeds)
    with mock.patch("pyproxifier.process.ProcessController.find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch.object(Path, "exists", return_value=False):
                mock_winreg = mock.MagicMock()
                mock_winreg.OpenKey.side_effect = [OSError("Not found"), mock.MagicMock(__enter__=mock.MagicMock())]
                with mock.patch.dict("sys.modules", {"winreg": mock_winreg}):
                    assert get_installed_proxifier_version() == 4

    # 5. Default fallback
    with mock.patch("pyproxifier.process.ProcessController.find_proxifier_binary", return_value=fake_exe):
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch.object(Path, "exists", return_value=False):
                with mock.patch.dict("sys.modules", {"winreg": None}):
                    assert get_installed_proxifier_version() == 4
