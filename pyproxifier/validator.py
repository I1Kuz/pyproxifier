"""Configuration Validator for Proxifier profiles.

Validates ports, IP addresses, CIDR notation, application masks,
protocol constraints, and referential ID integrity across proxies, chains, and rules.
"""

import ipaddress
import re

from pyproxifier.exceptions import (
    ChainReferenceNotFoundError,
    InvalidAddressError,
    InvalidPortError,
    ProxyReferenceNotFoundError,
    RuleConfigurationError,
    ValidationError,
)
from pyproxifier.models.chain import ChainItem
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.models.proxy import ProxyItem, ProxyProtocol
from pyproxifier.models.rule import ActionType, RuleItem


class Validator:
    """Validates Proxifier configuration profiles and their individual components."""

    @staticmethod
    def validate_port_number(port: int | str, context: str = "") -> int:
        """Validates that a single port is an integer in the 1..65535 range."""
        try:
            p = int(port)
        except (ValueError, TypeError) as e:
            ctx = f" ({context})" if context else ""
            raise InvalidPortError(port, f"Port must be an integer between 1 and 65535{ctx}.") from e

        if not (1 <= p <= 65535):
            ctx = f" ({context})" if context else ""
            raise InvalidPortError(port, f"Port {p} is out of valid range 1..65535{ctx}.")
        return p

    @classmethod
    def validate_ports_string(cls, ports_str: str | None) -> None:
        """Validates a Proxifier ports specification string (e.g. '80; 443; 8000-8080')."""
        if not ports_str or not ports_str.strip():
            return

        tokens = [t.strip() for t in ports_str.split(";") if t.strip()]
        for token in tokens:
            if "-" in token:
                parts = token.split("-")
                if len(parts) != 2:
                    raise InvalidPortError(token, f"Invalid port range format: '{token}'")
                start = cls.validate_port_number(parts[0], f"start of range '{token}'")
                end = cls.validate_port_number(parts[1], f"end of range '{token}'")
                if start > end:
                    raise InvalidPortError(
                        token,
                        f"Port range start ({start}) cannot be greater than end ({end}) in '{token}'.",
                    )
            else:
                cls.validate_port_number(token, "single port")

    @classmethod
    def validate_target_token(cls, token: str) -> None:
        """Validates a single target token: IP, CIDR, range, wildcard host, or special variable."""
        clean = token.strip().strip('"').strip("[]")
        if not clean:
            return

        # Special system variables (e.g. %ComputerName%, %SimpleHostnames%, or any %ENV_VAR%)
        if (clean.startswith("%") and clean.endswith("%")) or clean.lower() == "localhost":
            return

        # IP range (e.g. 192.168.1.1-192.168.1.100 or 2001:db8::-2001:db8::1)
        if "-" in clean and not clean.startswith("-"):
            parts = clean.split("-")
            if len(parts) == 2:
                p1, p2 = parts[0].strip(), parts[1].strip()
                is_ipv4_range = bool(re.match(r"^[\d\.]+$", p1) and re.match(r"^[\d\.]+$", p2))
                is_ipv6_range = bool(
                    ":" in p1
                    and ":" in p2
                    and re.match(r"^[0-9a-fA-F:]+$", p1)
                    and re.match(r"^[0-9a-fA-F:]+$", p2)
                )
                if is_ipv4_range or is_ipv6_range:
                    try:
                        ipaddress.ip_address(p1)
                        ipaddress.ip_address(p2)
                        return
                    except ValueError as e:
                        raise InvalidAddressError(clean, f"Invalid IP address in range '{clean}': {e}") from e

        # Single IP address (IPv4 or IPv6)
        try:
            ipaddress.ip_address(clean)
            return
        except ValueError:
            pass

        # CIDR notation (e.g. 192.168.0.0/24)
        if "/" in clean:
            try:
                ipaddress.ip_network(clean, strict=False)
                return
            except ValueError as e:
                raise InvalidAddressError(clean, f"Invalid CIDR network format: '{clean}'") from e

        # Semicolons and spaces are forbidden inside individual tokens
        if ";" in clean or " " in clean:
            raise InvalidAddressError(clean, f"Target token contains invalid whitespace or semicolons: '{clean}'")

        # Hostname with optional wildcards (*.example.com, ??.domain.com)
        pattern = r"^[a-zA-Z0-9_\-\.\*\?]+$"
        if not re.match(pattern, clean):
            raise InvalidAddressError(clean, f"Target token contains illegal symbols: '{clean}'")

    @classmethod
    def validate_targets_string(cls, targets_str: str | None) -> None:
        """Validates a semicolon-separated target hosts string."""
        if not targets_str or not targets_str.strip():
            return

        tokens = [t.strip() for t in targets_str.split(";") if t.strip()]
        for token in tokens:
            cls.validate_target_token(token)

    @classmethod
    def validate_applications_string(cls, apps_str: str | None) -> None:
        """Validates a semicolon-separated applications filter string."""
        if not apps_str or not apps_str.strip():
            return

        tokens = [t.strip() for t in apps_str.split(";") if t.strip()]
        for token in tokens:
            # Check pid= filter syntax
            if token.lower().startswith("pid="):
                pid_val = token[4:].strip()
                if not pid_val.isdigit():
                    raise ValidationError(
                        f"Invalid process ID in application filter: '{token}'. Must be numeric (e.g. 'pid=1234')."
                    )

    @classmethod
    def validate_proxy(cls, proxy: ProxyItem) -> None:
        """Validates a single proxy server entry."""
        if proxy.id <= 0:
            raise ValidationError(f"Proxy ID must be a positive integer, got {proxy.id}")
        if not proxy.address.strip():
            raise InvalidAddressError(proxy.address, "Proxy address cannot be empty.")

        clean_addr = proxy.address.strip().strip("[]")
        if " " in clean_addr or ";" in clean_addr:
            raise InvalidAddressError(
                proxy.address, f"Proxy address cannot contain spaces or semicolons: '{proxy.address}'"
            )
        try:
            ipaddress.ip_address(clean_addr)
        except ValueError:
            if not re.match(r"^[a-zA-Z0-9_\-\.]+$", clean_addr):
                raise InvalidAddressError(
                    proxy.address, f"Proxy address contains illegal characters: '{proxy.address}'"
                )

        cls.validate_port_number(proxy.port, f"Proxy ID {proxy.id}")

    @classmethod
    def validate_chain(cls, chain: ChainItem, existing_proxy_ids: set[int]) -> None:
        """Validates a proxy chain and verifies all proxy IDs exist."""
        if chain.id <= 0:
            raise ValidationError(f"Chain ID must be a positive integer, got {chain.id}")
        if not chain.proxy_ids:
            raise ValidationError(f"Chain '{chain.name}' (id={chain.id}) must contain at least one proxy ID.")

        for pid in chain.proxy_ids:
            if pid not in existing_proxy_ids:
                raise ProxyReferenceNotFoundError(
                    pid, f"Chain '{chain.name}' (id={chain.id})"
                )

    @classmethod
    def validate_rule(
        cls,
        rule: RuleItem,
        existing_proxy_ids: set[int],
        existing_chain_ids: set[int],
    ) -> None:
        """Validates a single routing rule, checking ports, targets, applications, and referential targets."""
        if not rule.name or not rule.name.strip():
            raise RuleConfigurationError("Rule name cannot be empty.")

        cls.validate_ports_string(rule.ports)
        cls.validate_targets_string(rule.targets)
        cls.validate_applications_string(rule.applications)

        action_name = rule.action_name
        if action_name == ActionType.PROXY.value:
            if rule.target_id is None:
                raise RuleConfigurationError(
                    f"Rule '{rule.name}' has action 'Proxy' but no proxy target_id was specified."
                )
            if rule.target_id not in existing_proxy_ids:
                raise ProxyReferenceNotFoundError(
                    rule.target_id, f"Rule '{rule.name}'"
                )

        elif action_name == ActionType.CHAIN.value:
            if rule.target_id is None:
                raise RuleConfigurationError(
                    f"Rule '{rule.name}' has action 'Chain' but no chain target_id was specified."
                )
            if rule.target_id not in existing_chain_ids:
                raise ChainReferenceNotFoundError(
                    rule.target_id, f"Rule '{rule.name}'"
                )

    @classmethod
    def validate_profile(cls, profile: ProxifierProfile) -> None:
        """Performs complete validation on a ProxifierProfile.

        Checks:
        1. All proxy server definitions and IDs.
        2. All proxy chain definitions and their referenced proxy IDs.
        3. All rules, targets, ports, applications, and action target references.
        4. HTTP proxy constraints and options.
        5. Position of the mandatory 'Default' rule.
        """
        proxy_ids: set[int] = set()
        has_http_proxy = False

        for proxy in profile.proxies:
            cls.validate_proxy(proxy)
            if proxy.id in proxy_ids:
                raise ValidationError(f"Duplicate proxy id={proxy.id} detected in profile.")
            proxy_ids.add(proxy.id)
            if proxy.protocol_type == ProxyProtocol.HTTP:
                has_http_proxy = True

        chain_ids: set[int] = set()
        for chain in profile.chains:
            cls.validate_chain(chain, proxy_ids)
            if chain.id in chain_ids:
                raise ValidationError(f"Duplicate chain id={chain.id} detected in profile.")
            chain_ids.add(chain.id)

            # Check HTTP proxy position in chain (must be last proxy if present)
            proxy_map = {p.id: p for p in profile.proxies}
            for idx, pid in enumerate(chain.proxy_ids):
                p_item = proxy_map.get(pid)
                if p_item and p_item.protocol_type == ProxyProtocol.HTTP:
                    if idx != len(chain.proxy_ids) - 1:
                        raise ValidationError(
                            f"In chain '{chain.name}', HTTP proxy (id={pid}) must be the last proxy in the chain."
                        )

        # Check HTTP proxy support flag in options
        if has_http_proxy and not profile.options.http_proxies_support:
            profile.options.http_proxies_support = True

        # Validate rules
        if not profile.rules:
            raise ValidationError("Profile must contain at least the mandatory 'Default' rule.")

        rule_names: set[str] = set()
        for rule in profile.rules:
            cls.validate_rule(rule, proxy_ids, chain_ids)
            r_lower = rule.name.lower()
            if r_lower in rule_names:
                raise ValidationError(f"Duplicate rule name '{rule.name}' detected in profile.")
            rule_names.add(r_lower)

        # Check Default rule presence and final position
        default_rule = profile.find_rule("Default")
        if not default_rule:
            raise ValidationError(
                "Profile is missing the mandatory system 'Default' rule."
            )
        if profile.rules[-1].name.lower() != "default":
            raise ValidationError(
                f"The 'Default' rule must be the last rule in the rule list (currently last is '{profile.rules[-1].name}')."
            )
