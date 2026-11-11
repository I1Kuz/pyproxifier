"""Unit tests for the Proxifier main client facade."""

from pathlib import Path
import tempfile
from unittest import mock
import pytest

from pyproxifier.client import Proxifier
from pyproxifier.exceptions import ProfileNotFoundError, ProxyNotFoundError
from pyproxifier.models import ActionType, ProxifierProfile, ProxyProtocol


def test_facade_initialization_and_operations() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        profile_path = Path(tmpdir) / "custom.ppx"

        # 1. Initialize when file missing (creates default)
        prox = Proxifier(profile_path=profile_path)
        assert profile_path.is_file()

        # 2. Initialize when file already exists (loads existing)
        prox_existing = Proxifier(profile_path=profile_path)
        assert prox_existing.profile_path == profile_path

        # 3. Initialize with create_if_missing=False on non-existent path
        missing_path = Path(tmpdir) / "nonexistent.ppx"
        with pytest.raises(ProfileNotFoundError):
            Proxifier(profile_path=missing_path, create_if_missing=False)

        # 4. Profile property setter
        new_prof = ProxifierProfile.create_default()
        prox.profile = new_prof
        assert prox.profile is new_prof
        assert prox.proxies.profile is new_prof

        # Add proxy via facade shortcut
        p = prox.add_proxy("10.0.0.1", 1080, ProxyProtocol.SOCKS5, label="Main")
        assert p.id == 100

        # Add proxy from URL shortcut
        p_url = prox.add_proxy_url("socks5://alice:secret@10.0.0.2:1080", label="FromURL")
        assert p_url.id == 101
        assert p_url.username == "alice"
        assert p_url.password == "secret"

        # Add rule via facade shortcut
        r = prox.add_rule("RouteSlack", applications="slack.exe", action=ActionType.PROXY, target_id=p.id)
        assert r.name == "RouteSlack"

        # Validate
        prox.validate()

        # Save
        prox.save()

        # Reload
        prox.load()
        assert len(prox.profile.proxies) == 2
        assert prox.profile.proxies[0].label == "Main"


def test_facade_presets() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        profile_path = Path(tmpdir) / "preset_test.ppx"
        prox = Proxifier(profile_path=profile_path)

        # First call creates AllowedHosts rule
        prox.set_lockdown_mode(allowed_targets="10.0.0.1", apply=False)
        assert prox.rules.get("Default").action_type == ActionType.BLOCK
        assert prox.rules.get("AllowedHosts").targets == "10.0.0.1"

        # Second call updates existing AllowedHosts rule
        prox.set_lockdown_mode(allowed_targets="10.0.0.2", apply=False)
        assert prox.rules.get("AllowedHosts").targets == "10.0.0.2"


def test_facade_apply_and_persistence() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        profile_path = Path(tmpdir) / "apply_test.ppx"
        prox = Proxifier(profile_path=profile_path)

        with mock.patch.object(prox.ipc, "apply_profile", return_value=True) as mock_ipc_apply:
            # apply with save_to_disk=True
            res = prox.apply(save_to_disk=True)
            assert res is True
            mock_ipc_apply.assert_called_once()

            # Add proxy with apply=True
            p = prox.add_proxy("1.2.3.4", 1080, apply=True)
            assert p.address == "1.2.3.4"

            # Add proxy url with apply=True
            p2 = prox.add_proxy_url("socks5://1.2.3.5:1080", apply=True)
            assert p2.address == "1.2.3.5"

            # Add rule with apply=True
            r = prox.add_rule("AppRule", action=ActionType.DIRECT, apply=True)
            assert r.name == "AppRule"

            # Set direct mode with apply=True
            prox.set_direct_mode(apply=True)


def test_facade_lifecycle_and_socket() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        profile_path = Path(tmpdir) / "life_test.ppx"
        prox = Proxifier(profile_path=profile_path)

        # is_running
        with mock.patch("pyproxifier.process.ProcessController.is_running", return_value=True):
            assert prox.is_running() is True

        # start
        with mock.patch("pyproxifier.process.ProcessController.start") as mock_start:
            prox.start(silent=True)
            mock_start.assert_called_once()

        # stop with graceful exit success
        with mock.patch.object(prox.ipc, "graceful_exit", return_value=True):
            assert prox.stop() == 1

        # stop with graceful exit failure -> calls kill
        with mock.patch.object(prox.ipc, "graceful_exit", return_value=False):
            with mock.patch("pyproxifier.process.ProcessController.kill", return_value=1) as mock_kill:
                assert prox.stop() == 1
                mock_kill.assert_called_once()

        # restart
        with mock.patch.object(prox, "stop") as mock_stop:
            with mock.patch.object(prox, "start") as mock_restart_start:
                prox.restart()
                mock_stop.assert_called_once()
                mock_restart_start.assert_called_once_with(silent=True)

        # control_socket
        mock_sock_client = mock.MagicMock()
        with mock.patch("pyproxifier.client.ControlSocketClient", return_value=mock_sock_client) as mock_cls:
            res_sock = prox.control_socket(port=19876)
            mock_cls.assert_called_once_with(host="127.0.0.1", port=19876, timeout=5.0)
            mock_sock_client.connect.assert_called_once()
            assert res_sock == mock_sock_client


def test_facade_checker_methods() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        profile_path = Path(tmpdir) / "check_test.ppx"
        prox = Proxifier(profile_path=profile_path)
        p = prox.add_proxy("127.0.0.1", 1, ProxyProtocol.SOCKS5, label="LoopbackProxy")

        # check_proxy by proxy item
        res = prox.check_proxy(p, timeout=0.1)
        assert res.proxy == p
        assert not res.is_alive  # Port 1 is closed

        # check_proxy by ID
        res_by_id = prox.check_proxy(p.id, timeout=0.1)
        assert res_by_id.proxy.id == p.id

        # check_proxy by label
        res_by_label = prox.check_proxy("LoopbackProxy", timeout=0.1)
        assert res_by_label.proxy.id == p.id

        # check_proxy with ad-hoc address
        res_adhoc = prox.check_proxy("127.0.0.1:1", timeout=0.1)
        assert res_adhoc.proxy.address == "127.0.0.1"

        # check_proxy with invalid identifier -> ProxyNotFoundError
        with pytest.raises(ProxyNotFoundError):
            prox.check_proxy(99999, timeout=0.1)

        # launch_proxy_checker with proxy item
        with mock.patch("subprocess.Popen") as mock_popen:
            mock_popen.return_value = mock.MagicMock()
            res_launch = prox.launch_proxy_checker(p)
            assert res_launch is True
            assert mock_popen.called
            call_args = mock_popen.call_args[0][0]
            assert "127.0.0.1:1" in call_args

            # launch_proxy_checker with None
            assert prox.launch_proxy_checker(None) is True

            # launch_proxy_checker with string
            assert prox.launch_proxy_checker("192.168.1.1:8080") is True

        prox.set_direct_mode(apply=False)
        assert prox.rules.get("Default").action_type == ActionType.DIRECT


def test_facade_service_and_cli_methods() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        profile_path = Path(tmpdir) / "cli_test.ppx"
        prox = Proxifier(profile_path=profile_path)

        assert prox.service is not None

        with mock.patch.object(prox.ipc, "convert_profile", return_value=True) as mock_conv:
            assert prox.convert_profile(profile_path) is True
            mock_conv.assert_called_once_with(profile_path)

        with mock.patch.object(prox.ipc, "register_license", return_value=True) as mock_reg:
            assert prox.register_license("KEY-12345") is True
            mock_reg.assert_called_once_with("KEY-12345")
