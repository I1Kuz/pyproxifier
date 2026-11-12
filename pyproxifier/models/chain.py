"""Data models for Proxifier proxy chains."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyproxifier.models.xml_element import XMLElement


class ChainType(str, Enum):
    """Proxy chain behavior type."""

    SIMPLE = "simple"
    REDUNDANCY = "redundancy"
    LOAD_BALANCING = "load_balancing"

    @classmethod
    def from_str(cls, val: str) -> "ChainType":
        val_lower = val.strip().lower()
        for member in cls:
            if member.value == val_lower:
                return member
        raise ValueError(f"Unsupported chain type: {val!r}")


@dataclass
class ChainItem:
    """Represents a proxy chain entry (<Chain> in <ChainList>).

    Attributes:
        id: Unique integer identifier in the profile (e.g. 1, 2).
        name: Name or label for the chain.
        chain_type: Strategy (simple sequential, redundancy failover, load balancing).
        proxy_ids: Ordered list of proxy IDs belonging to this chain.
        redundancy_timeout_sec: Timeout before switching to the next proxy (Redundancy only).
        redundancy_recheck_sec: Background recheck interval for failed proxies in seconds.
        load_balance_same_pid: If true, keep same proxy for connections from the same PID.
    """

    id: int = 1
    name: str = "NewChain"
    chain_type: ChainType | str = ChainType.SIMPLE
    proxy_ids: list[int] = field(default_factory=list)
    redundancy_timeout_sec: int | None = None
    redundancy_recheck_sec: int | None = None
    redundancy_try_direct: bool = False
    load_balance_same_pid: bool = False
    extra_attributes: dict[str, str] = field(default_factory=dict)
    extra_elements: list[XMLElement] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.chain_type, ChainType):
            try:
                self.chain_type = ChainType.from_str(str(self.chain_type))
            except ValueError:
                pass
        self.id = int(self.id)
        self.proxy_ids = [int(pid) for pid in self.proxy_ids]

    @property
    def type_name(self) -> str:
        """Returns canonical lowercase chain type string ('simple', 'redundancy', 'load_balancing')."""
        if isinstance(self.chain_type, ChainType):
            return self.chain_type.value
        try:
            return ChainType.from_str(str(self.chain_type)).value
        except ValueError:
            return str(self.chain_type).lower()
