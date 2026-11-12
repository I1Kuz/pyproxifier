"""Main Proxifier controller facade."""

import logging
from pathlib import Path
import subprocess

from pyproxifier.checker import ProxyChecker, ProxyCheckResult
from pyproxifier.exceptions import ProfileNotFoundError
from pyproxifier.ipc import ApplyResult, ControlSocketClient, IPCManager, ServiceIPC
from pyproxifier.managers.config_manager import ConfigManager
from pyproxifier.managers.proxy_manager import ProxyManager
from pyproxifier.managers.rule_manager import RuleManager
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.models.proxy import ProxyItem, ProxyProtocol
from pyproxifier.models.rule import ActionType, RuleItem
from pyproxifier.process import ProcessController
from pyproxifier.system import SystemManager
from pyproxifier.validator import Validator

logger = logging.getLogger(__name__)


class Proxifier:
    """Primary facade for programmatic control of Proxifier.

    Coordinates profile loading/saving, proxy server management,
    routing rules, validation, and process control.

    Example:
        ```python
        from pyproxifier import Proxifier, ProxyProtocol, ActionType

        prox = Proxifier()
        proxy = prox.proxies.add("1.2.3.4", 1080, ProxyProtocol.SOCKS5, label="Primary")
        prox.rules.add("Browsers", applications="chrome.exe", action=ActionType.PROXY, target_id=proxy.id)
        prox.apply()
        ```
    """

    config: type[ConfigManager] = ConfigManager
    validator: type[Validator] = Validator
    system: type[SystemManager] = SystemManager
    checker: type[ProxyChecker] = ProxyChecker
    service: type[ServiceIPC] = ServiceIPC

    def __init__(
        self,
        profile_path: Path | str | None = None,
        executable: Path | str | None = None,
        auto_save: bool = True,
        create_if_missing: bool = True,
    ) -> None:
        self.executable: Path = ProcessController.find_proxifier_binary(executable)
        self.auto_save: bool = auto_save
        self.last_apply_result: ApplyResult | None = None
        self.ipc: IPCManager = IPCManager(executable=self.executable)

        # Resolve active profile path via ConfigManager (Single Responsibility)
        self.profile_path: Path = ConfigManager.resolve_profile_path(profile_path)

        # Load or initialize profile
        if self.profile_path.is_file():
            self._profile: ProxifierProfile = ConfigManager.load(self.profile_path, validate=False)
        elif create_if_missing:
            self._profile = ConfigManager.new_default()
            self._sync_managers()
            self.save(validate=False)
        else:
            raise ProfileNotFoundError(str(self.profile_path))

        # Initialize managers
        self._sync_managers()

    def _sync_managers(self) -> None:
        """Binds managers to the current active profile instance."""
        self.proxies: ProxyManager = ProxyManager(self._profile)
        self.rules: RuleManager = RuleManager(self._profile)

    def _persist_if_needed(self, apply: bool) -> None:
        """Helper to centralize apply and auto_save persistence logic."""
        if apply:
            self.apply()
        elif self.auto_save:
            self.save()

    @property
    def profile(self) -> ProxifierProfile:
        """Returns the active ProxifierProfile instance."""
        return self._profile

    @profile.setter
    def profile(self, val: ProxifierProfile) -> None:
        """Sets a new active ProxifierProfile and updates managers."""
        self._profile = val
        self._sync_managers()

    def load(self, path: Path | str | None = None, validate: bool = True) -> ProxifierProfile:
        """Loads a profile from file and makes it the active profile."""
        target = ConfigManager.resolve_profile_path(path) if path else self.profile_path
        self._profile = ConfigManager.load(target, validate=validate)
        self.profile_path = target
        self._sync_managers()
        return self._profile

    def save(
        self,
        path: Path | str | None = None,
        validate: bool = True,
        backup: bool = False,
    ) -> Path:
        """Saves the current active profile to disk with atomic write semantics."""
        target = Path(path) if path else self.profile_path
        saved_path = ConfigManager.save(target, self._profile, validate=validate, backup=backup)
        self.profile_path = saved_path
        return saved_path

    def validate(self) -> None:
        """Validates the active profile. Raises ValidationError subclasses if issues found."""
        Validator.validate_profile(self._profile)

    def apply(
        self,
        silent: bool = True,
        use_socket: bool | None = None,
        socket_port: int | None = None,
        save_to_disk: bool = False,
    ) -> bool:
        """Applies the current configuration directly to Proxifier via native IPC.

        Zero process restarting, zero manual profile pasting.
        Uses in-memory TCP Control Socket or native message IPC.

        If save_to_disk=True, also writes the configuration to the active profile file on disk.
        If use_socket=False, bypasses TCP Control Socket mechanisms.
        If silent=False, executes CLI loader without 'silent-load' argument.
        """
        self.validate()
        if save_to_disk or self.auto_save:
            self.save()

        ok = self.ipc.apply_profile(
            self._profile,
            socket_port=socket_port,
            use_socket=use_socket,
            silent=silent,
            validate=False,
        )
        self.last_apply_result = self.ipc.last_apply_result
        return ok

    def apply_detailed(
        self,
        silent: bool = True,
        use_socket: bool | None = None,
        socket_port: int | None = None,
        save_to_disk: bool = False,
    ) -> ApplyResult:
        """Applies configuration and returns explicit ApplyResult status details."""
        self.apply(
            silent=silent,
            use_socket=use_socket,
            socket_port=socket_port,
            save_to_disk=save_to_disk,
        )
        assert self.last_apply_result is not None
        return self.last_apply_result

    def control_socket(
        self,
        port: int = 19876,
        host: str = "127.0.0.1",
        timeout: float = 5.0,
    ) -> ControlSocketClient:
        """Establishes and returns a connected ControlSocketClient for direct native IPC."""
        client = ControlSocketClient(host=host, port=port, timeout=timeout)
        client.connect()
        return client

    # -----------------------------------------------------------------------
    # Process Lifecycle
    # -----------------------------------------------------------------------

    def is_running(self) -> bool:
        """Returns True if Proxifier process is currently active."""
        return ProcessController.is_running()

    def start(self, silent: bool = False) -> subprocess.Popen[bytes]:
        """Starts the Proxifier process."""
        return ProcessController.start(
            profile_path=self.profile_path,
            silent=silent,
            executable=self.executable,
        )

    def stop(self, timeout: float = 3.0) -> int:
        """Gracefully stops Proxifier via native IPC, falling back to process termination if needed."""
        if self.ipc.graceful_exit():
            return 1
        return ProcessController.kill(timeout=timeout)

    def restart(self) -> None:
        """Restarts the Proxifier process with the active profile."""
        self.stop()
        self.start(silent=True)

    def convert_profile(self, source_path: Path | str) -> bool:
        """Converts an older format profile (.prx) or profile file using Proxifier's native converter."""
        return self.ipc.convert_profile(source_path)

    def register_license(self, license_key: str) -> bool:
        """Registers Proxifier license key using native command-line activation."""
        return self.ipc.register_license(license_key)

    # -----------------------------------------------------------------------
    # Preset & Shortcut Methods
    # -----------------------------------------------------------------------

    def set_direct_mode(self, apply: bool = True) -> None:
        """Switches Proxifier to Direct mode (bypasses proxy for all connections)."""
        self.rules.set_default_action(ActionType.DIRECT)
        self._persist_if_needed(apply)

    def set_lockdown_mode(self, allowed_targets: str | None = None, apply: bool = True) -> None:
        """Switches Proxifier to lockdown mode (blocks all external internet traffic)."""
        self.rules.ensure_localhost_rule(ActionType.DIRECT)
        if allowed_targets:
            rule = self.rules.find("AllowedHosts")
            if not rule:
                self.rules.add("AllowedHosts", ActionType.DIRECT, targets=allowed_targets)
            else:
                rule.targets = allowed_targets
                rule.action_type = ActionType.DIRECT
        self.rules.set_default_action(ActionType.BLOCK)
        self._persist_if_needed(apply)

    def add_proxy(
        self,
        address: str,
        port: int,
        protocol: ProxyProtocol | str = ProxyProtocol.SOCKS5,
        username: str | None = None,
        password: str | None = None,
        label: str | None = None,
        apply: bool = False,
    ) -> ProxyItem:
        """Convenience shortcut to add a proxy server."""
        proxy = self.proxies.add(
            address=address,
            port=port,
            protocol=protocol,
            username=username,
            password=password,
            label=label,
        )
        self._persist_if_needed(apply)
        return proxy

    def add_proxy_url(
        self,
        url: str,
        label: str | None = None,
        apply: bool = False,
    ) -> ProxyItem:
        """Convenience shortcut to add a proxy server from a URL string."""
        proxy = self.proxies.add_url(url=url, label=label)
        self._persist_if_needed(apply)
        return proxy

    def add_rule(
        self,
        name: str,
        action: ActionType | str = ActionType.DIRECT,
        target_id: int | None = None,
        applications: str | None = None,
        targets: str | None = None,
        ports: str | None = None,
        enabled: bool = True,
        apply: bool = False,
    ) -> RuleItem:
        """Convenience shortcut to add a routing rule."""
        rule = self.rules.add(
            name=name,
            action=action,
            target_id=target_id,
            applications=applications,
            targets=targets,
            ports=ports,
            enabled=enabled,
        )
        self._persist_if_needed(apply)
        return rule

    def check_proxy(
        self,
        proxy: ProxyItem | int | str,
        timeout: float = 4.0,
    ) -> ProxyCheckResult:
        """Tests availability and latency of a proxy server using native protocol handshakes."""
        if isinstance(proxy, ProxyItem):
            p_item = proxy
        else:
            found = self.proxies.find(proxy)
            if found is not None:
                p_item = found
            elif isinstance(proxy, str) and ("://" in proxy or ":" in proxy):
                url = proxy if "://" in proxy else f"socks5://{proxy}"
                p_item = ProxyItem.from_url(url)
            else:
                p_item = self.proxies.get(proxy)
        return self.checker.check(p_item, timeout=timeout)

    def launch_proxy_checker(
        self,
        proxy: ProxyItem | int | str | None = None,
    ) -> bool:
        """Launches the official Proxifier ProxyChecker.exe GUI utility.

        Optionally passes the target proxy address to the checker.
        """
        p_item: ProxyItem | str | None
        if proxy is None:
            p_item = None
        elif isinstance(proxy, ProxyItem):
            p_item = proxy
        else:
            found = self.proxies.find(proxy)
            p_item = found if found is not None else str(proxy)

        return self.checker.launch_official_checker(p_item)
