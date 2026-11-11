"""Unit tests for pyproxifier models and exceptions."""

import pytest

from pyproxifier.exceptions import (
    ChainNotFoundError,
    ChainReferenceNotFoundError,
    ControlSocketCommandError,
    InvalidAddressError,
    InvalidPortError,
    ProfileNotFoundError,
    ProfileParseError,
    ProxifierError,
    ProxifierNotFoundError,
    ProxyNotFoundError,
    ProxyReferenceNotFoundError,
    RuleNotFoundError,
)
from pyproxifier.models import (
    ActionType,
    ChainItem,
    ChainType,
    EncryptionMode,
    ProfileOptions,
    ProxifierProfile,
    ProxyItem,
    ProxyProtocol,
    RuleItem,
    UdpMode,
)


def test_exception_classes_and_formatting() -> None:
    # ProxifierError __str__
    err = ProxifierError("Something failed")
    assert str(err) == "Something failed"

    # ProfileNotFoundError
    pnf1 = ProfileNotFoundError(path=r"C:\fake.ppx")
    assert "fake.ppx" in str(pnf1)
    pnf2 = ProfileNotFoundError(message="Custom message")
    assert str(pnf2) == "Custom message"

    # ProfileParseError
    ppe1 = ProfileParseError("Bad XML", line=42)
    assert "line 42" in str(ppe1)
    ppe2 = ProfileParseError("Bad XML")
    assert "Profile parsing error: Bad XML" in str(ppe2)

    # InvalidPortError
    ipe1 = InvalidPortError(70000)
    assert "70000" in str(ipe1)
    ipe2 = InvalidPortError("abc", message="Invalid port string")
    assert str(ipe2) == "Invalid port string"

    # InvalidAddressError
    iae1 = InvalidAddressError("bad.host%%")
    assert "bad.host%%" in str(iae1)
    iae2 = InvalidAddressError("bad", message="Bad IP")
    assert str(iae2) == "Bad IP"

    # Reference errors
    prnf = ProxyReferenceNotFoundError(100, context="Rule 'Web'")
    assert "100" in str(prnf)
    assert "Rule 'Web'" in str(prnf)
    crnf = ChainReferenceNotFoundError(1, context="Rule 'ChainRule'")
    assert "1" in str(crnf)
    assert "Rule 'ChainRule'" in str(crnf)

    # Entity not found
    cnf = ChainNotFoundError("MyChain")
    assert "MyChain" in str(cnf)
    assert cnf.identifier == "MyChain"

    pnfe = ProxyNotFoundError("MyProxy")
    assert "MyProxy" in str(pnfe)
    assert pnfe.identifier == "MyProxy"

    rnf = RuleNotFoundError("MyRule")
    assert "MyRule" in str(rnf)

    # ProxifierNotFoundError
    prf1 = ProxifierNotFoundError()
    assert "Proxifier executable not found" in str(prf1)
    prf2 = ProxifierNotFoundError(searched_paths=[r"C:\bin1", r"C:\bin2"])
    assert "bin1" in str(prf2)

    # ControlSocketCommandError
    csce1 = ControlSocketCommandError("get_version", error_code=101, message="Version unknown")
    assert "101" in str(csce1)
    assert "Version unknown" in str(csce1)
    csce2 = ControlSocketCommandError("load_config")
    assert "Unknown error" in str(csce2)


def test_proxy_item_defaults() -> None:
    p = ProxyItem(address="1.2.3.4", port=1080)
    assert p.protocol_type == ProxyProtocol.SOCKS5
    assert p.options == 48
    assert not p.has_auth
    assert p.to_url() == "socks5://1.2.3.4:1080"


def test_proxy_item_socks4_options() -> None:
    p = ProxyItem(address="1.2.3.4", port=1080, protocol_type=ProxyProtocol.SOCKS4)
    assert p.options == 52


def test_proxy_item_auth_url() -> None:
    p = ProxyItem(
        address="10.0.0.1",
        port=8080,
        protocol_type=ProxyProtocol.HTTPS,
        username="alice",
        password="secret",
    )
    assert p.has_auth
    assert p.to_url() == "https://alice:secret@10.0.0.1:8080"

    # If auth_enabled is explicitly False, to_url omits credentials
    p.auth_enabled = False
    assert not p.has_auth
    assert p.to_url() == "https://10.0.0.1:8080"


def test_proxy_item_from_url_and_ipv6() -> None:
    # URL parsing
    p = ProxyItem.from_url("socks5://alice:pass123@192.168.1.10:1080", label="TestURL")
    assert p.protocol_type == ProxyProtocol.SOCKS5
    assert p.address == "192.168.1.10"
    assert p.port == 1080
    assert p.username == "alice"
    assert p.password == "pass123"
    assert p.label == "TestURL"
    assert p.to_url() == "socks5://alice:pass123@192.168.1.10:1080"

    # URL without port defaults to 1080
    p_no_port = ProxyItem.from_url("socks5://192.168.1.10")
    assert p_no_port.port == 1080

    # URL with missing scheme or host raises ValueError
    with pytest.raises(ValueError, match="Invalid proxy URL"):
        ProxyItem.from_url("not_a_url")

    # IPv6 formatting in to_url
    p_ipv6 = ProxyItem(address="2001:db8::1", port=1080, protocol_type=ProxyProtocol.SOCKS5)
    assert p_ipv6.to_url() == "socks5://[2001:db8::1]:1080"


def test_proxy_protocol_enum_and_custom_types() -> None:
    assert ProxyProtocol.from_str("socks5") == ProxyProtocol.SOCKS5
    with pytest.raises(ValueError, match="Unsupported proxy protocol"):
        ProxyProtocol.from_str("INVALID")

    # ProxyItem with custom string protocol
    p = ProxyItem(address="1.1.1.1", port=1080, protocol_type="CUSTOM_PROTO")
    assert p.protocol_name == "CUSTOM_PROTO"


def test_chain_item_and_enum() -> None:
    c = ChainItem(id=1, name="RedundantChain", chain_type="redundancy", proxy_ids=[100, 101])
    assert c.chain_type == ChainType.REDUNDANCY
    assert c.proxy_ids == [100, 101]
    assert c.type_name == "redundancy"

    # Enum lookup
    assert ChainType.from_str("simple") == ChainType.SIMPLE
    with pytest.raises(ValueError, match="Unsupported chain type"):
        ChainType.from_str("UNKNOWN")

    # ChainItem with invalid chain_type string (retains string, type_name returns lowercase)
    c_custom = ChainItem(id=2, name="CustomChain", chain_type="custom_type")
    assert c_custom.type_name == "custom_type"


def test_options_and_enums() -> None:
    # UdpMode
    assert UdpMode.from_str("mode_block_all") == UdpMode.BLOCK_ALL
    with pytest.raises(ValueError, match="Unsupported UDP mode"):
        UdpMode.from_str("INVALID_UDP")

    # EncryptionMode
    assert EncryptionMode.from_str("basic") == EncryptionMode.BASIC
    with pytest.raises(ValueError, match="Unsupported encryption mode"):
        EncryptionMode.from_str("INVALID_ENC")

    # ProfileOptions with custom unknown string modes
    opts = ProfileOptions(
        encryption_mode="custom_enc",
        udp_mode="custom_udp",
    )
    assert opts.encryption_mode == "custom_enc"
    assert opts.udp_mode == "custom_udp"


def test_rule_item_and_enum() -> None:
    r = RuleItem(name="Browsers", action_type="Proxy", target_id=100, applications="chrome.exe")
    assert r.action_type == ActionType.PROXY
    assert r.target_id == 100
    assert not r.is_system_rule

    r_def = RuleItem(name="Default", action_type=ActionType.DIRECT)
    assert r_def.is_system_rule

    # Enum lookup
    assert ActionType.from_str("block") == ActionType.BLOCK
    with pytest.raises(ValueError, match="Unsupported action type"):
        ActionType.from_str("INVALID_ACTION")

    # Custom action string
    r_custom = RuleItem(name="CustomRule", action_type="custom_act", target_id="non_int_target")
    assert r_custom.action_name == "Custom_act"
    assert r_custom.target_id == "non_int_target"


def test_proxy_item_special_chars_url() -> None:
    p = ProxyItem(
        address="10.0.0.1",
        port=8080,
        protocol_type=ProxyProtocol.HTTPS,
        username="user@domain.com",
        password="p@ss:w/ord",
    )
    url = p.to_url()
    assert "user%40domain.com" in url
    assert "p%40ss%3Aw%2Ford" in url
    parsed = ProxyItem.from_url(url)
    assert parsed.username == "user@domain.com"
    assert parsed.password == "p@ss:w/ord"


def test_profile_presets_and_methods() -> None:
    default_p = ProxifierProfile.create_default()
    assert len(default_p.rules) == 2
    assert default_p.rules[0].name == "Localhost"
    assert default_p.rules[1].name == "Default"

    # Direct preset
    direct_p = ProxifierProfile.create_direct()
    assert direct_p.options.handle_direct_connections is False

    # Lockdown preset
    lockdown_p = ProxifierProfile.create_lockdown(allowed_targets="10.0.0.1")
    assert any(r.name == "AllowedHosts" for r in lockdown_p.rules)
    assert lockdown_p.rules[-1].action_type == ActionType.BLOCK

    # Add proxy and chain to test find_proxy and find_chain
    p1 = ProxyItem(id=100, address="1.1.1.1", port=1080, label="P1")
    default_p.proxies.append(p1)
    c1 = ChainItem(id=1, name="C1", proxy_ids=[100])
    default_p.chains.append(c1)

    # find_proxy by ID, string ID, and label
    assert default_p.find_proxy(100) == p1
    assert default_p.find_proxy("100") == p1
    assert default_p.find_proxy("P1") == p1
    assert default_p.find_proxy("Missing") is None

    # find_chain by ID, string ID, and name
    assert default_p.find_chain(1) == c1
    assert default_p.find_chain("1") == c1
    assert default_p.find_chain("C1") == c1
    assert default_p.find_chain("MissingChain") is None

    # find_rule by name
    assert default_p.find_rule("Localhost") is not None
    assert default_p.find_rule("MissingRule") is None


def test_profile_from_xml_and_to_xml() -> None:
    p = ProxifierProfile.create_default()
    xml_str = p.to_xml()
    assert "<ProxifierProfile" in xml_str

    reloaded = ProxifierProfile.from_xml(xml_str)
    assert len(reloaded.rules) == 2
    assert reloaded.rules[0].name == "Localhost"
