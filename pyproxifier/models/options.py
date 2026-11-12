"""Data models for Proxifier profile global options and settings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyproxifier.models.xml_element import XMLElement


class UdpMode(str, Enum):
    """UDP packet handling mode in Proxifier."""

    BLOCK_ALL = "mode_block_all"
    BYPASS = "mode_bypass"
    PROXY = "mode_proxy"

    @classmethod
    def from_str(cls, val: str) -> "UdpMode":
        val_lower = val.strip().lower()
        for member in cls:
            if member.value == val_lower:
                return member
        raise ValueError(f"Unsupported UDP mode: {val!r}")


class EncryptionMode(str, Enum):
    """Password encryption method used in .ppx profile files."""

    DISABLED = "disabled"
    BASIC = "basic"  # Windows DPAPI tied to current user account
    PASSWORD = "password"  # AES-256 with Master Password

    @classmethod
    def from_str(cls, val: str) -> "EncryptionMode":
        val_lower = val.strip().lower()
        for member in cls:
            if member.value == val_lower:
                return member
        raise ValueError(f"Unsupported encryption mode: {val!r}")


@dataclass
class DnsOptions:
    """DNS and hostname resolution settings under <Options><Resolve>."""

    auto_mode_detection: bool = False
    via_proxy: bool = True
    block_non_a: bool = True
    exclusion_list: str = "%ComputerName%; localhost; *.local; dns.msftncsi.com"
    exclusion_only_from_list: bool = False
    dns_udp_mode: int = 0
    extra_attributes: dict[str, str] = field(default_factory=dict)
    extra_elements: list[XMLElement] = field(default_factory=list)
    exclusion_list_extra_attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class ProfileOptions:
    """Represents global <Options> in a Proxifier .ppx profile.

    Attributes:
        dns: Name resolution and DNS settings.
        encryption_mode: Password encryption mode ('disabled', 'basic', or 'password').
        connection_loop_detection: Detects and stops infinite connection routing loops.
        connection_loop_resolve: Detects DNS resolution loops.
        udp_mode: UDP traffic routing behavior.
        leak_prevention_mode: Drops packets during profile/network switches to avoid IP leaks.
        process_other_users: Proxifies processes belonging to other Windows user sessions.
        process_services: Proxifies background Windows Services (e.g. Windows Update).
        handle_direct_connections: Monitors and logs connections even if routed Direct.
        http_proxies_support: Enables support for plain HTTP proxies (port 80/443).
    """

    dns: DnsOptions = field(default_factory=DnsOptions)
    encryption_mode: EncryptionMode | str = EncryptionMode.DISABLED
    connection_loop_detection: bool = True
    connection_loop_resolve: bool = True
    udp_mode: UdpMode | str = UdpMode.BLOCK_ALL
    leak_prevention_mode: bool = True
    process_other_users: bool = False
    process_services: bool = False
    handle_direct_connections: bool = False
    http_proxies_support: bool = False
    extra_attributes: dict[str, str] = field(default_factory=dict)
    extra_elements: list[XMLElement] = field(default_factory=list)
    encryption_extra_attributes: dict[str, str] = field(default_factory=dict)
    udp_extra_attributes: dict[str, str] = field(default_factory=dict)
    connection_loop_extra_attributes: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.encryption_mode, EncryptionMode):
            try:
                self.encryption_mode = EncryptionMode.from_str(str(self.encryption_mode))
            except ValueError:
                pass
        if not isinstance(self.udp_mode, UdpMode):
            try:
                self.udp_mode = UdpMode.from_str(str(self.udp_mode))
            except ValueError:
                pass
