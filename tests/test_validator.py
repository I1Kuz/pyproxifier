"""Unit tests for configuration validator."""

import pytest

from pyproxifier.exceptions import (
    ChainReferenceNotFoundError,
    InvalidAddressError,
    InvalidPortError,
    ProxyReferenceNotFoundError,
    RuleConfigurationError,
    ValidationError,
)
from pyproxifier.models import (
    ActionType,
    ChainItem,
    ProxifierProfile,
    ProxyItem,
    ProxyProtocol,
    RuleItem,
)
from pyproxifier.validator import Validator


def test_validate_ports() -> None:
    Validator.validate_port_number(80)
    Validator.validate_port_number(65535)

    with pytest.raises(InvalidPortError):
        Validator.validate_port_number(0)

    with pytest.raises(InvalidPortError):
        Validator.validate_port_number(70000)

    with pytest.raises(InvalidPortError):
        Validator.validate_port_number("not_a_number")

    Validator.validate_ports_string("80; 443; 8000-8080")
    Validator.validate_ports_string(None)
    Validator.validate_ports_string("")

    with pytest.raises(InvalidPortError, match="Invalid port range format"):
        Validator.validate_ports_string("80-443-8080")

    with pytest.raises(InvalidPortError):
        Validator.validate_ports_string("80; invalid_port")

    with pytest.raises(InvalidPortError):
        Validator.validate_ports_string("9000-8000")  # start > end


def test_validate_targets() -> None:
    Validator.validate_target_token("")
    Validator.validate_target_token("   ")
    Validator.validate_target_token("127.0.0.1")
    Validator.validate_target_token("::1")
    Validator.validate_target_token("[::1]")
    Validator.validate_target_token("192.168.1.1-192.168.1.50")
    Validator.validate_target_token("10.0.0.0/8")
    Validator.validate_target_token("*.google.com")
    Validator.validate_target_token("%ComputerName%")
    Validator.validate_target_token("%computername%")
    Validator.validate_target_token("localhost")
    Validator.validate_target_token("api-service.com")
    Validator.validate_target_token("sub-domain.api-test.co.uk")
    Validator.validate_target_token("2001:db8::-2001:db8::10")
    Validator.validate_target_token("%SimpleHostnames%")

    Validator.validate_targets_string("localhost; 127.0.0.1; *.google.com; 192.168.0.0/16")
    Validator.validate_targets_string(None)
    Validator.validate_targets_string("")

    with pytest.raises(InvalidAddressError):
        Validator.validate_target_token("invalid space.com")

    # Invalid CIDR network format
    with pytest.raises(InvalidAddressError, match="Invalid CIDR network format"):
        Validator.validate_target_token("192.168.1.1/99")

    # Invalid illegal symbols
    with pytest.raises(InvalidAddressError, match="illegal symbols"):
        Validator.validate_target_token("host$name!")

    # Invalid octet in IP range
    with pytest.raises(InvalidAddressError):
        Validator.validate_target_token("192.168.1.500-192.168.1.600")


def test_validate_applications() -> None:
    Validator.validate_applications_string("chrome.exe; firefox.exe; pid=1234; *.exe")
    Validator.validate_applications_string(None)
    Validator.validate_applications_string("")

    with pytest.raises(ValidationError):
        Validator.validate_applications_string("chrome.exe; pid=invalid")


def test_validate_proxy_and_chain_entities() -> None:
    # Proxy ID <= 0
    with pytest.raises(ValidationError, match="positive integer"):
        Validator.validate_proxy(ProxyItem(id=0, address="1.1.1.1", port=1080))

    # Chain ID <= 0
    with pytest.raises(ValidationError, match="positive integer"):
        Validator.validate_chain(ChainItem(id=0, name="C", proxy_ids=[100]), {100})

    # Empty chain proxy IDs
    with pytest.raises(ValidationError, match="at least one proxy ID"):
        Validator.validate_chain(ChainItem(id=1, name="C", proxy_ids=[]), set())

    # Empty rule name
    with pytest.raises(RuleConfigurationError, match="Rule name cannot be empty"):
        Validator.validate_rule(RuleItem(name="  ", action_type=ActionType.DIRECT), set(), set())

    # Action=Proxy without target_id
    with pytest.raises(RuleConfigurationError, match="no proxy target_id was specified"):
        Validator.validate_rule(RuleItem(name="R", action_type=ActionType.PROXY, target_id=None), set(), set())

    # Action=Chain without target_id
    with pytest.raises(RuleConfigurationError, match="no chain target_id was specified"):
        Validator.validate_rule(RuleItem(name="R", action_type=ActionType.CHAIN, target_id=None), set(), set())


def test_profile_validation_rules_and_duplicates() -> None:
    p = ProxifierProfile.create_default()

    # Duplicate proxy ID
    p.proxies = [
        ProxyItem(id=100, address="1.1.1.1", port=1080),
        ProxyItem(id=100, address="1.1.1.2", port=1080),
    ]
    with pytest.raises(ValidationError, match="Duplicate proxy id=100"):
        Validator.validate_profile(p)

    # Valid proxies and duplicate chain ID
    p.proxies = [
        ProxyItem(id=100, address="1.1.1.1", port=1080),
        ProxyItem(id=101, address="1.1.1.2", port=1080),
    ]
    p.chains = [
        ChainItem(id=1, name="C1", proxy_ids=[100]),
        ChainItem(id=1, name="C2", proxy_ids=[101]),
    ]
    with pytest.raises(ValidationError, match="Duplicate chain id=1"):
        Validator.validate_profile(p)

    # HTTP proxy must be last in chain
    http_p = ProxyItem(id=102, address="1.1.1.3", port=8080, protocol_type=ProxyProtocol.HTTP)
    p.proxies.append(http_p)
    p.chains = [
        ChainItem(id=1, name="ChainWithHTTP", proxy_ids=[102, 100]),  # HTTP is first, not last
    ]
    with pytest.raises(ValidationError, match="must be the last proxy in the chain"):
        Validator.validate_profile(p)

    # HTTP proxy at end of chain successfully auto-enables http_proxies_support
    p.chains = [
        ChainItem(id=1, name="ChainWithHTTP", proxy_ids=[100, 102]),  # HTTP is last
    ]
    p.options.http_proxies_support = False
    Validator.validate_profile(p)
    assert p.options.http_proxies_support is True

    # Duplicate rule names
    p.rules.insert(0, RuleItem(name="MyRule", action_type=ActionType.DIRECT))
    p.rules.insert(1, RuleItem(name="myrule", action_type=ActionType.DIRECT))
    with pytest.raises(ValidationError, match="Duplicate rule name"):
        Validator.validate_profile(p)


def test_referential_integrity_missing_proxy() -> None:
    p = ProxifierProfile.create_default()
    p.rules.insert(
        0,
        RuleItem(
            name="BrokenRule",
            action_type=ActionType.PROXY,
            target_id=999,  # Does not exist
        ),
    )
    with pytest.raises(ProxyReferenceNotFoundError):
        Validator.validate_profile(p)


def test_referential_integrity_lowercase_action() -> None:
    p = ProxifierProfile.create_default()
    p.rules.insert(
        0,
        RuleItem(
            name="BrokenRuleLower",
            action_type="proxy",  # lowercase string
            target_id=999,
        ),
    )
    with pytest.raises(ProxyReferenceNotFoundError):
        Validator.validate_profile(p)


def test_referential_integrity_missing_chain() -> None:
    p = ProxifierProfile.create_default()
    p.rules.insert(
        0,
        RuleItem(
            name="BrokenChainRule",
            action_type=ActionType.CHAIN,
            target_id=5,  # Does not exist
        ),
    )
    with pytest.raises(ChainReferenceNotFoundError):
        Validator.validate_profile(p)


def test_chain_referential_integrity() -> None:
    p = ProxifierProfile.create_default()
    p.chains.append(ChainItem(id=1, name="BadChain", proxy_ids=[888]))
    with pytest.raises(ProxyReferenceNotFoundError):
        Validator.validate_profile(p)


def test_default_rule_required_at_end() -> None:
    p = ProxifierProfile.create_default()
    # Move Default rule to top
    p.rules.insert(0, p.rules.pop())
    with pytest.raises(ValidationError):
        Validator.validate_profile(p)


def test_empty_rules_rejected() -> None:
    p = ProxifierProfile.create_default()
    p.rules.clear()
    with pytest.raises(ValidationError):
        Validator.validate_profile(p)

    # Missing Default rule
    p.rules = [RuleItem(name="OnlyOneRule", action_type=ActionType.DIRECT)]
    with pytest.raises(ValidationError, match="missing the mandatory system 'Default' rule"):
        Validator.validate_profile(p)


def test_validate_proxy_address() -> None:
    # Valid addresses
    Validator.validate_proxy(ProxyItem(address="127.0.0.1", port=1080))
    Validator.validate_proxy(ProxyItem(address="[::1]", port=1080))
    Validator.validate_proxy(ProxyItem(address="proxy.example.com", port=1080))

    # Invalid addresses
    with pytest.raises(InvalidAddressError):
        Validator.validate_proxy(ProxyItem(address="", port=1080))

    with pytest.raises(InvalidAddressError):
        Validator.validate_proxy(ProxyItem(address="host with spaces", port=1080))

    with pytest.raises(InvalidAddressError):
        Validator.validate_proxy(ProxyItem(address="host;semicolon", port=1080))

    with pytest.raises(InvalidAddressError):
        Validator.validate_proxy(ProxyItem(address="host$illegal", port=1080))
