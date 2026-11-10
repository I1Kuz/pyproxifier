"""pyproxifier - Comprehensive Python library for programmatic Proxifier management."""

from pyproxifier.checker import ProxyChecker, ProxyCheckResult
from pyproxifier.client import Proxifier
from pyproxifier.exceptions import (
    ChainNotFoundError,
    ChainReferenceNotFoundError,
    ControlSocketCommandError,
    ControlSocketConnectionError,
    ControlSocketError,
    DriverError,
    EntityNotFoundError,
    InvalidAddressError,
    InvalidPortError,
    ProcessError,
    ProfileCorruptedError,
    ProfileError,
    ProfileNotFoundError,
    ProfileParseError,
    ProxifierError,
    ProxifierNotFoundError,
    ProxyNotFoundError,
    ProxyReferenceNotFoundError,
    RegistryAccessError,
    RuleConfigurationError,
    RuleNotFoundError,
    ValidationError,
)
from pyproxifier.managers.config_manager import ConfigManager
from pyproxifier.managers.proxy_manager import ProxyManager
from pyproxifier.managers.rule_manager import RuleManager
from pyproxifier.models.chain import ChainItem, ChainType
from pyproxifier.models.options import (
    DnsOptions,
    EncryptionMode,
    ProfileOptions,
    UdpMode,
)
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.models.proxy import ProxyItem, ProxyProtocol
from pyproxifier.models.rule import ActionType, RuleItem
from pyproxifier.parser import ProfileParser
from pyproxifier.process import ProcessController
from pyproxifier.ipc import (
    ControlSocketClient,
    DriverIPC,
    IPCManager,
    NamedPipeClient,
    ServiceIPC,
    WindowIPC,
)
from pyproxifier.system import SystemManager
from pyproxifier.validator import Validator
from pyproxifier.version import __version__

__all__ = [
    "ActionType",
    "ChainItem",
    "ChainNotFoundError",
    "ChainReferenceNotFoundError",
    "ChainType",
    "ConfigManager",
    "ControlSocketClient",
    "ControlSocketCommandError",
    "ControlSocketConnectionError",
    "ControlSocketError",
    "DnsOptions",
    "DriverError",
    "DriverIPC",
    "EncryptionMode",
    "EntityNotFoundError",
    "IPCManager",
    "InvalidAddressError",
    "InvalidPortError",
    "NamedPipeClient",
    "ProcessController",
    "ProcessError",
    "ProfileCorruptedError",
    "ProfileError",
    "ProfileNotFoundError",
    "ProfileOptions",
    "ProfileParseError",
    "ProfileParser",
    "Proxifier",
    "ProxifierError",
    "ProxifierNotFoundError",
    "ProxifierProfile",
    "ProxyCheckResult",
    "ProxyChecker",
    "ProxyItem",
    "ProxyManager",
    "ProxyNotFoundError",
    "ProxyProtocol",
    "ProxyReferenceNotFoundError",
    "RegistryAccessError",
    "RuleConfigurationError",
    "RuleItem",
    "RuleManager",
    "RuleNotFoundError",
    "ServiceIPC",
    "SystemManager",
    "UdpMode",
    "ValidationError",
    "Validator",
    "WindowIPC",
    "__version__",
]
