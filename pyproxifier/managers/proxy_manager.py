"""Manager for Proxifier proxy servers and proxy chains."""

from __future__ import annotations

from typing import Any

from pyproxifier.exceptions import (
    ChainNotFoundError,
    ProxyNotFoundError,
    ValidationError,
)
from pyproxifier.managers.rule_manager import RuleManager
from pyproxifier.models.chain import ChainItem, ChainType
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.models.proxy import ProxyItem, ProxyProtocol
from pyproxifier.models.rule import ActionType


def _allocate_id(existing_ids: set[int], start: int = 1) -> int:
    """Allocates the lowest available integer ID greater than or equal to start."""
    cand = start
    while cand in existing_ids:
        cand += 1
    return cand


class ProxyManager:
    """Manages addition, retrieval, modification, and removal of proxy servers and chains."""

    def __init__(
        self, profile: ProxifierProfile, rule_manager: RuleManager | None = None
    ) -> None:
        self._profile = profile
        self._rule_manager_ref = rule_manager

    @property
    def profile(self) -> ProxifierProfile:
        return self._profile

    @property
    def _rule_manager(self) -> RuleManager:
        if self._rule_manager_ref is None:
            self._rule_manager_ref = RuleManager(self._profile)
        return self._rule_manager_ref

    # -----------------------------------------------------------------------
    # Proxy Server Operations
    # -----------------------------------------------------------------------

    def add(
        self,
        address: str,
        port: int,
        protocol: ProxyProtocol | str = ProxyProtocol.SOCKS5,
        username: str | None = None,
        password: str | None = None,
        label: str | None = None,
        proxy_id: int | None = None,
        options: int | None = None,
        auth_enabled: bool | None = None,
    ) -> ProxyItem:
        """Adds a new proxy server to the profile.

        If proxy_id is None, automatically allocates the next available ID (>= 100).
        """
        if proxy_id is not None and proxy_id <= 0:
            raise ValidationError(f"Proxy ID must be a positive integer, got {proxy_id}")

        if proxy_id is None:
            existing_ids = {p.id for p in self._profile.proxies}
            proxy_id = _allocate_id(existing_ids, start=100)
        else:
            if any(p.id == proxy_id for p in self._profile.proxies):
                raise ValidationError(f"Proxy with id={proxy_id} already exists.")

        proto_str = protocol.value if isinstance(protocol, ProxyProtocol) else str(protocol).upper()
        if proto_str == "HTTP":
            self._profile.options.http_proxies_support = True

        opt_val = options
        if opt_val is None:
            opt_val = 52 if "SOCKS4" in proto_str else 48

        proxy = ProxyItem(
            id=proxy_id,
            address=address,
            port=port,
            protocol_type=protocol,
            username=username,
            password=password,
            options=opt_val,
            label=label,
            auth_enabled=auth_enabled,
        )
        self._profile.proxies.append(proxy)
        return proxy

    def get(self, identifier: int | str) -> ProxyItem:
        """Retrieves a proxy by integer ID or string label. Raises ProxyNotFoundError if not found."""
        proxy = self.find(identifier)
        if not proxy:
            raise ProxyNotFoundError(identifier)
        return proxy

    def find(self, identifier: int | str) -> ProxyItem | None:
        """Retrieves a proxy by integer ID or string label, or returns None if not found."""
        return self._profile.find_proxy(identifier)

    def list(self) -> list[ProxyItem]:
        """Returns a list of all configured proxy servers."""
        return list(self._profile.proxies)

    def update(self, identifier: int | str, /, **updates: Any) -> ProxyItem:
        """Updates attributes of an existing proxy server."""
        proxy = self.get(identifier)
        old_id = proxy.id
        if "id" in updates:
            new_id = int(updates["id"])
            if new_id <= 0:
                raise ValidationError(f"Proxy ID must be a positive integer, got {new_id}")
            if new_id != old_id and any(p.id == new_id for p in self._profile.proxies):
                raise ValidationError(f"Proxy with id={new_id} already exists.")
            # Cascade ID updates across rules and chains
            for rule in self._profile.rules:
                if (
                    rule.action_name == ActionType.PROXY.value
                    and rule.target_id is not None
                    and rule.target_id == old_id
                ):
                    rule.target_id = new_id
            for chain in self._profile.chains:
                chain.proxy_ids = [new_id if pid == old_id else pid for pid in chain.proxy_ids]

        for key, val in updates.items():
            if not hasattr(proxy, key):
                raise AttributeError(f"ProxyItem has no attribute {key!r}")
            setattr(proxy, key, val)

        if proxy.protocol_type == ProxyProtocol.HTTP:
            self._profile.options.http_proxies_support = True

        return proxy

    def add_url(
        self,
        url: str,
        label: str | None = None,
        proxy_id: int | None = None,
        options: int | None = None,
    ) -> ProxyItem:
        """Adds a proxy from a standard URL string (e.g. 'socks5://user:pass@1.2.3.4:1080')."""
        temp = ProxyItem.from_url(url, id=1, label=label, options=options)
        return self.add(
            address=temp.address,
            port=temp.port,
            protocol=temp.protocol_type,
            username=temp.username,
            password=temp.password,
            label=label or temp.label,
            proxy_id=proxy_id,
            options=options,
        )

    def _get_referencing_chains(self, proxy_id: int) -> list[str]:
        """Returns the names of all chains that contain the given proxy ID."""
        return [c.name for c in self._profile.chains if proxy_id in c.proxy_ids]

    def _remove_proxy_from_chains(self, proxy_id: int) -> None:
        """Removes the given proxy ID from all chains. If a chain becomes empty, cleans it up."""
        empty_chains: list[ChainItem] = []
        for chain in self._profile.chains:
            if proxy_id in chain.proxy_ids:
                chain.proxy_ids = [pid for pid in chain.proxy_ids if pid != proxy_id]
                if not chain.proxy_ids:
                    empty_chains.append(chain)
        for empty_chain in empty_chains:
            self._rule_manager.unbind_target(ActionType.CHAIN, empty_chain.id)
            self._profile.chains.remove(empty_chain)

    def remove(self, identifier: int | str, force: bool = False) -> bool:
        """Removes a proxy server from the profile.

        If force=False, checks if the proxy is referenced by rules or chains.
        If referenced and force=False, raises ValidationError.
        If force=True, unbinds referencing rules (sets action to Direct) and removes from chains.
        """
        proxy = self.get(identifier)

        # Check references
        if not force:
            referencing_rules = self._rule_manager.has_target_reference(
                ActionType.PROXY, proxy.id
            )
            referencing_chains = self._get_referencing_chains(proxy.id)
            if referencing_rules or referencing_chains:
                err_parts: list[str] = []
                if referencing_rules:
                    err_parts.append(f"rules {referencing_rules}")
                if referencing_chains:
                    err_parts.append(f"chains {referencing_chains}")
                raise ValidationError(
                    f"Cannot delete proxy id={proxy.id} ('{proxy.label or proxy.address}'): "
                    f"it is currently referenced in {', '.join(err_parts)}. "
                    f"Pass force=True to remove anyway."
                )

        # If force=True, clean up references in rules and chains
        if force:
            self._rule_manager.unbind_target(ActionType.PROXY, proxy.id)
            self._remove_proxy_from_chains(proxy.id)

        self._profile.proxies.remove(proxy)
        return True

    def clear(self, force: bool = False) -> int:
        """Removes all proxies. Returns count of removed proxies."""
        count = len(self._profile.proxies)
        if not force and count > 0:
            referencing_rules = self._rule_manager.has_target_reference(ActionType.PROXY)
            referencing_chains = [c.name for c in self._profile.chains if c.proxy_ids]
            if referencing_rules or referencing_chains:
                err_parts: list[str] = []
                if referencing_rules:
                    err_parts.append(f"rules {referencing_rules}")
                if referencing_chains:
                    err_parts.append(f"chains {referencing_chains}")
                raise ValidationError(
                    f"Cannot clear proxies: active references found in {', '.join(err_parts)}. "
                    "Pass force=True to clear anyway."
                )
        self._profile.proxies.clear()
        if force:
            self._rule_manager.unbind_target(ActionType.PROXY)
            # Empty chains are now defunct, clean them up and unbind their rules
            for chain in self._profile.chains:
                self._rule_manager.unbind_target(ActionType.CHAIN, chain.id)
            self._profile.chains.clear()
        return count

    # -----------------------------------------------------------------------
    # Chain Operations
    # -----------------------------------------------------------------------

    def create_chain(
        self,
        name: str,
        chain_type: ChainType | str = ChainType.SIMPLE,
        proxy_ids: list[int] | None = None,
        redundancy_timeout: int | None = None,
        redundancy_recheck: int | None = None,
        chain_id: int | None = None,
    ) -> ChainItem:
        """Creates a new proxy chain in the profile."""
        if chain_id is not None and chain_id <= 0:
            raise ValidationError(f"Chain ID must be a positive integer, got {chain_id}")

        if chain_id is None:
            existing_ids = {c.id for c in self._profile.chains}
            chain_id = _allocate_id(existing_ids, start=1)
        else:
            if any(c.id == chain_id for c in self._profile.chains):
                raise ValidationError(f"Chain with id={chain_id} already exists.")

        chain = ChainItem(
            id=chain_id,
            name=name,
            chain_type=chain_type,
            proxy_ids=proxy_ids or [],
            redundancy_timeout_sec=redundancy_timeout,
            redundancy_recheck_sec=redundancy_recheck,
        )
        self._profile.chains.append(chain)
        return chain

    def get_chain(self, identifier: int | str) -> ChainItem:
        """Retrieves a chain by integer ID or name. Raises ChainNotFoundError if not found."""
        chain = self._profile.find_chain(identifier)
        if not chain:
            raise ChainNotFoundError(identifier)
        return chain

    def list_chains(self) -> list[ChainItem]:
        """Returns a list of all configured proxy chains."""
        return list(self._profile.chains)

    def update_chain(self, identifier: int | str, /, **updates: Any) -> ChainItem:
        """Updates attributes of an existing proxy chain, cascading ID updates to rules."""
        chain = self.get_chain(identifier)
        old_id = chain.id
        if "id" in updates:
            new_id = int(updates["id"])
            if new_id <= 0:
                raise ValidationError(f"Chain ID must be a positive integer, got {new_id}")
            if new_id != old_id and any(c.id == new_id for c in self._profile.chains):
                raise ValidationError(f"Chain with id={new_id} already exists.")
            # Cascade chain ID updates across rules
            for rule in self._profile.rules:
                if (
                    rule.action_name == ActionType.CHAIN.value
                    and rule.target_id is not None
                    and rule.target_id == old_id
                ):
                    rule.target_id = new_id

        for key, val in updates.items():
            if not hasattr(chain, key):
                raise AttributeError(f"ChainItem has no attribute {key!r}")
            setattr(chain, key, val)

        return chain

    def remove_chain(self, identifier: int | str, force: bool = False) -> bool:
        """Removes a proxy chain from the profile."""
        chain = self.get_chain(identifier)
        if not force:
            referencing_rules = self._rule_manager.has_target_reference(
                ActionType.CHAIN, chain.id
            )
            if referencing_rules:
                raise ValidationError(
                    f"Cannot delete chain id={chain.id} ('{chain.name}'): "
                    f"referenced in rules {referencing_rules}. Pass force=True to remove anyway."
                )
        if force:
            self._rule_manager.unbind_target(ActionType.CHAIN, chain.id)

        self._profile.chains.remove(chain)
        return True
