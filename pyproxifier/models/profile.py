"""Root profile model representing a Proxifier configuration document (.ppx)."""

from __future__ import annotations

from dataclasses import dataclass, field
import importlib
from pathlib import Path
import sys

from pyproxifier.models.chain import ChainItem
from pyproxifier.models.options import ProfileOptions
from pyproxifier.models.proxy import ProxyItem
from pyproxifier.models.rule import ActionType, RuleItem


@dataclass
class ProxifierProfile:
    """Root representation of a Proxifier profile (.ppx XML).

    Holds global options, configured proxies, proxy chains, and routing rules.
    """

    version: str = "102"
    platform: str = "Windows"
    product_id: str = "0"
    product_minver: str = "400"
    options: ProfileOptions = field(default_factory=ProfileOptions)
    proxies: list[ProxyItem] = field(default_factory=list)
    chains: list[ChainItem] = field(default_factory=list)
    rules: list[RuleItem] = field(default_factory=list)

    def find_proxy(self, identifier: int | str) -> ProxyItem | None:
        """Finds a proxy by integer ID, string ID, or label."""
        id_int = identifier if isinstance(identifier, int) else (int(identifier) if identifier.isdigit() else None)
        id_lower = str(identifier).lower()
        for p in self.proxies:
            if id_int is not None and p.id == id_int:
                return p
            if p.label and p.label.lower() == id_lower:
                return p
        return None

    def find_chain(self, identifier: int | str) -> ChainItem | None:
        """Finds a chain by integer ID, string ID, or name."""
        id_int = identifier if isinstance(identifier, int) else (int(identifier) if identifier.isdigit() else None)
        id_lower = str(identifier).lower()
        for c in self.chains:
            if id_int is not None and c.id == id_int:
                return c
            if c.name and c.name.lower() == id_lower:
                return c
        return None

    def find_rule(self, name: str) -> RuleItem | None:
        """Finds a routing rule by case-insensitive name."""
        name_clean = name.strip().lower()
        for r in self.rules:
            if r.name.lower() == name_clean:
                return r
        return None

    def to_xml(self) -> str:
        """Serializes profile into XML string via ProfileParser."""
        mod = sys.modules.get("pyproxifier.parser") or importlib.import_module("pyproxifier.parser")
        return mod.ProfileParser.to_xml(self)

    @classmethod
    def from_xml(cls, xml_source: str | bytes | Path) -> ProxifierProfile:
        """Deserializes profile from XML string, bytes, or file via ProfileParser."""
        mod = sys.modules.get("pyproxifier.parser") or importlib.import_module("pyproxifier.parser")
        return mod.ProfileParser.from_xml(xml_source)

    @classmethod
    def create_default(cls) -> ProxifierProfile:
        """Creates a standard clean default profile matching Proxifier's Default.ppx."""
        profile = cls()
        profile.rules.append(
            RuleItem(
                name="Localhost",
                targets="localhost; 127.0.0.1; %ComputerName%; ::1",
                action_type=ActionType.DIRECT,
            )
        )
        profile.rules.append(
            RuleItem(
                name="Default",
                action_type=ActionType.DIRECT,
            )
        )
        return profile

    @classmethod
    def create_direct(cls) -> ProxifierProfile:
        """Creates a Direct profile routing all traffic directly."""
        profile = cls.create_default()
        profile.options.handle_direct_connections = False
        return profile

    @classmethod
    def create_lockdown(cls, allowed_targets: str | None = None) -> ProxifierProfile:
        """Creates a safe lockdown profile where all internet traffic is Blocked by default."""
        profile = cls()
        profile.rules.append(
            RuleItem(
                name="Localhost",
                targets="localhost; 127.0.0.1; %ComputerName%; ::1",
                action_type=ActionType.DIRECT,
            )
        )
        if allowed_targets:
            profile.rules.append(
                RuleItem(
                    name="AllowedHosts",
                    targets=allowed_targets,
                    action_type=ActionType.DIRECT,
                )
            )
        profile.rules.append(
            RuleItem(
                name="Default",
                action_type=ActionType.BLOCK,
            )
        )
        return profile
