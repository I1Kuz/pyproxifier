"""Exception hierarchy for pyproxifier.

Provides strongly-typed, comprehensive exceptions for profile errors,
validation failures, entity lookups, and system/process operations.
"""

from typing import Any


class ProxifierError(Exception):
    """Base exception class for all pyproxifier errors."""

    def __init__(self, message: str, *args: Any) -> None:
        super().__init__(message, *args)
        self.message = message

    def __str__(self) -> str:
        return self.message


# ---------------------------------------------------------------------------
# Profile & Parser Exceptions
# ---------------------------------------------------------------------------


class ProfileError(ProxifierError):
    """Base exception for profile-related operations."""


class ProfileNotFoundError(ProfileError):
    """Raised when a specified .ppx profile file cannot be found."""

    def __init__(self, path: str | None = None, message: str | None = None) -> None:
        msg = message or f"Proxifier profile not found at: {path}"
        super().__init__(msg)
        self.path = path


class ProfileParseError(ProfileError):
    """Raised when parsing a .ppx XML profile fails due to malformed XML or invalid structure."""

    def __init__(self, message: str, line: int | None = None) -> None:
        line_info = f" (line {line})" if line is not None else ""
        super().__init__(f"Profile parsing error{line_info}: {message}")
        self.line = line


class ProfileCorruptedError(ProfileError):
    """Raised when the profile XML is missing essential sections or metadata."""


# ---------------------------------------------------------------------------
# Validation Exceptions
# ---------------------------------------------------------------------------


class ValidationError(ProxifierError):
    """Base exception for profile and entity validation failures."""


class InvalidPortError(ValidationError):
    """Raised when a port or port range string is invalid (out of 1-65535 or malformed)."""

    def __init__(self, port_value: Any, message: str | None = None) -> None:
        msg = message or f"Invalid port or port range: {port_value!r}. Must be between 1 and 65535."
        super().__init__(msg)
        self.port_value = port_value


class InvalidAddressError(ValidationError):
    """Raised when a host, IP address, or CIDR mask is invalid."""

    def __init__(self, address: Any, message: str | None = None) -> None:
        msg = message or f"Invalid address, IP, or mask format: {address!r}"
        super().__init__(msg)
        self.address = address


class ProxyReferenceNotFoundError(ValidationError):
    """Raised when a rule or chain references a proxy ID that does not exist in the profile."""

    def __init__(self, proxy_id: int | str, context: str | None = None) -> None:
        ctx = f" in {context}" if context else ""
        super().__init__(f"Referenced proxy id={proxy_id} does not exist{ctx}.")
        self.proxy_id = proxy_id
        self.context = context


class ChainReferenceNotFoundError(ValidationError):
    """Raised when a rule references a chain ID that does not exist in the profile."""

    def __init__(self, chain_id: int | str, context: str | None = None) -> None:
        ctx = f" in {context}" if context else ""
        super().__init__(f"Referenced chain id={chain_id} does not exist{ctx}.")
        self.chain_id = chain_id
        self.context = context


class RuleConfigurationError(ValidationError):
    """Raised when a routing rule configuration is incomplete or invalid."""


# ---------------------------------------------------------------------------
# Entity Lookup Exceptions
# ---------------------------------------------------------------------------


class EntityNotFoundError(ProxifierError):
    """Base exception when an entity (proxy, chain, rule) is not found."""


class ProxyNotFoundError(EntityNotFoundError):
    """Raised when a proxy server with the specified ID or label is not found."""

    def __init__(self, identifier: Any) -> None:
        super().__init__(f"Proxy server not found: {identifier!r}")
        self.identifier = identifier


class ChainNotFoundError(EntityNotFoundError):
    """Raised when a proxy chain with the specified ID or name is not found."""

    def __init__(self, identifier: Any) -> None:
        super().__init__(f"Proxy chain not found: {identifier!r}")
        self.identifier = identifier


class RuleNotFoundError(EntityNotFoundError):
    """Raised when a proxification rule with the specified name is not found."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Routing rule '{name}' not found.")
        self.name = name


# ---------------------------------------------------------------------------
# Control Socket / IPC Exceptions
# ---------------------------------------------------------------------------


class ControlSocketError(ProxifierError):
    """Base exception for native Control Socket IPC errors."""


class ControlSocketConnectionError(ControlSocketError):
    """Raised when connection to Proxifier's native TCP Control Socket fails."""


class ControlSocketCommandError(ControlSocketError):
    """Raised when Proxifier returns an error in response to a Control Socket command."""

    def __init__(self, command: str, error_code: str | int | None = None, message: str | None = None) -> None:
        code_str = f" [Code: {error_code}]" if error_code is not None else ""
        msg = f"Control Socket command '{command}' failed{code_str}: {message or 'Unknown error'}"
        super().__init__(msg)
        self.command = command
        self.error_code = error_code



class ProcessError(ProxifierError):
    """Base exception for process and system execution failures."""


class ProxifierNotFoundError(ProcessError):
    """Raised when the Proxifier executable cannot be found on the system."""

    def __init__(self, searched_paths: list[str] | None = None) -> None:
        paths_info = f" Searched paths: {searched_paths}" if searched_paths else ""
        super().__init__(f"Proxifier executable not found.{paths_info}")
        self.searched_paths = searched_paths


class DriverError(ProcessError):
    """Raised when checking, starting, or stopping the Proxifier WFP driver (ProxifierDrv) fails."""


class RegistryAccessError(ProcessError):
    """Raised when accessing or modifying the Windows Registry fails (e.g. license deployment)."""
