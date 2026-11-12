"""Data models for Proxifier proxy servers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING
from urllib.parse import quote, unquote, urlsplit

if TYPE_CHECKING:
    from pyproxifier.models.xml_element import XMLElement


class ProxyProtocol(str, Enum):
    """Supported Proxifier proxy protocols."""

    SOCKS5 = "SOCKS5"
    SOCKS4 = "SOCKS4"
    HTTPS = "HTTPS"
    HTTP = "HTTP"

    @classmethod
    def from_str(cls, val: str) -> ProxyProtocol:
        val_upper = val.strip().upper()
        for member in cls:
            if member.value == val_upper:
                return member
        raise ValueError(f"Unsupported proxy protocol: {val!r}")


@dataclass
class ProxyItem:
    """Represents a single proxy server entry (<Proxy> in <ProxyList>).

    Attributes:
        id: Unique integer identifier in the profile (e.g. 100, 101).
        address: Hostname, IPv4, or IPv6 address.
        port: Integer port number (1-65535).
        protocol_type: Protocol type (SOCKS5, SOCKS4, HTTPS, HTTP).
        username: Optional username for authentication.
        password: Optional password for authentication.
        options: Integer bitmask options (default 48 for SOCKS5/HTTPS/HTTP, 52 for SOCKS4).
        label: Optional user-friendly display name.
        auth_enabled: Explicit flag whether authentication is enabled (if None, inferred from username/password).
    """

    id: int = 100
    address: str = ""
    port: int = 1080
    protocol_type: ProxyProtocol | str = ProxyProtocol.SOCKS5
    username: str | None = None
    password: str | None = None
    options: int = 48
    label: str | None = None
    auth_enabled: bool | None = None
    extra_attributes: dict[str, str] = field(default_factory=dict)
    extra_elements: list[XMLElement] = field(default_factory=list)
    auth_extra_attributes: dict[str, str] = field(default_factory=dict)
    auth_extra_elements: list[XMLElement] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.protocol_type, ProxyProtocol):
            try:
                self.protocol_type = ProxyProtocol.from_str(str(self.protocol_type))
            except ValueError:
                pass
        self.port = int(self.port)
        self.id = int(self.id)
        if self.protocol_type == ProxyProtocol.SOCKS4 and self.options == 48:
            self.options = 52

    @property
    def protocol_name(self) -> str:
        """Returns uppercase protocol name string (e.g. 'SOCKS5')."""
        return (
            self.protocol_type.value
            if isinstance(self.protocol_type, ProxyProtocol)
            else str(self.protocol_type).upper()
        )

    @property
    def has_auth(self) -> bool:
        """True if authentication credentials are provided or explicitly enabled."""
        if self.auth_enabled is not None:
            return self.auth_enabled
        return bool(self.username or self.password)

    def to_url(self) -> str:
        """Formats proxy as standard URL representation (e.g. socks5://user:pass@host:port)."""
        proto = self.protocol_name.lower()
        auth = ""
        if self.has_auth and self.username is not None:
            user_part = quote(self.username, safe="")
            pwd_part = f":{quote(self.password, safe='')}" if self.password is not None else ""
            auth = f"{user_part}{pwd_part}@"
        host = (
            f"[{self.address}]"
            if ":" in self.address and not (self.address.startswith("[") and self.address.endswith("]"))
            else self.address
        )
        return f"{proto}://{auth}{host}:{self.port}"

    @classmethod
    def from_url(
        cls,
        url: str,
        id: int = 100,
        label: str | None = None,
        options: int | None = None,
    ) -> ProxyItem:
        """Parses a proxy URL (e.g. 'socks5://user:pass@1.2.3.4:1080') into a ProxyItem."""
        parsed = urlsplit(url)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError(
                f"Invalid proxy URL: {url!r}. Expected format: protocol://[user:pass@]host:port"
            )

        port = parsed.port or (1080 if "socks" in parsed.scheme.lower() else 8080)
        protocol = ProxyProtocol.from_str(parsed.scheme)
        username = unquote(parsed.username) if parsed.username else None
        password = unquote(parsed.password) if parsed.password else None

        opt_val = options
        if opt_val is None:
            opt_val = 52 if protocol == ProxyProtocol.SOCKS4 else 48

        return cls(
            id=id,
            address=parsed.hostname,
            port=port,
            protocol_type=protocol,
            username=username,
            password=password,
            label=label,
            options=opt_val,
        )
