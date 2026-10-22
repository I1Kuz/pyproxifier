"""Unit tests for bidirectional XML parser."""

from pathlib import Path
import tempfile
from unittest import mock
import pytest

from pyproxifier.exceptions import ProfileCorruptedError, ProfileParseError
from pyproxifier.models import (
    ActionType,
    ChainItem,
    ChainType,
    ProxifierProfile,
    ProxyItem,
    ProxyProtocol,
)
from pyproxifier.parser import (
    ProfileParser,
    _get_elem_int,  # pyright: ignore[reportPrivateUsage]
    _get_enabled_bool,  # pyright: ignore[reportPrivateUsage]
)
import xml.etree.ElementTree as ET


SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ProxifierProfile version="102" platform="Windows" product_id="0" product_minver="400">
	<Options>
		<Resolve>
			<AutoModeDetection enabled="false" />
			<ViaProxy enabled="true" />
			<BlockNonATypes enabled="true" />
			<ExclusionList OnlyFromListMode="false">%ComputerName%; localhost; *.local</ExclusionList>
			<DnsUdpMode>0</DnsUdpMode>
		</Resolve>
		<Encryption mode="disabled" />
		<ConnectionLoopDetection enabled="true" resolve="true" />
		<Udp mode="mode_block_all" />
		<LeakPreventionMode enabled="true" />
		<ProcessOtherUsers enabled="false" />
		<ProcessServices enabled="false" />
		<HandleDirectConnections enabled="false" />
		<HttpProxiesSupport enabled="false" />
	</Options>
	<ProxyList>
		<Proxy id="100" type="SOCKS5">
			<Label>Primary US</Label>
			<Authentication enabled="true">
				<Username>myuser</Username>
				<Password>mypass</Password>
			</Authentication>
			<Options>48</Options>
			<Port>1080</Port>
			<Address>198.51.100.1</Address>
		</Proxy>
	</ProxyList>
	<ChainList>
		<Chain id="1" type="redundancy">
			<Name>Failover</Name>
			<Proxy id="100" />
			<Redundancy recheck="60" timeout="10" />
		</Chain>
	</ChainList>
	<RuleList>
		<Rule enabled="true">
			<Action type="Direct" />
			<Targets>localhost; 127.0.0.1; %ComputerName%; ::1</Targets>
			<Name>Localhost</Name>
		</Rule>
		<Rule enabled="true">
			<Action type="Chain">1</Action>
			<Applications>chrome.exe; msedge.exe</Applications>
			<Targets>*.google.com</Targets>
			<Ports>80; 443</Ports>
			<Name>Browsers</Name>
		</Rule>
		<Rule enabled="true">
			<Action type="Direct" />
			<Name>Default</Name>
		</Rule>
	</RuleList>
</ProxifierProfile>"""


def test_parse_sample_xml() -> None:
    profile = ProfileParser.from_xml(SAMPLE_XML)
    assert profile.version == "102"
    assert profile.platform == "Windows"
    assert len(profile.proxies) == 1
    p = profile.proxies[0]
    assert p.id == 100
    assert p.protocol_type == ProxyProtocol.SOCKS5
    assert p.label == "Primary US"
    assert p.username == "myuser"
    assert p.password == "mypass"
    assert p.address == "198.51.100.1"
    assert p.port == 1080

    assert len(profile.chains) == 1
    c = profile.chains[0]
    assert c.id == 1
    assert c.chain_type == ChainType.REDUNDANCY
    assert c.proxy_ids == [100]
    assert c.redundancy_timeout_sec == 10
    assert c.redundancy_recheck_sec == 60

    assert len(profile.rules) == 3
    r = profile.rules[1]
    assert r.name == "Browsers"
    assert r.action_type == ActionType.CHAIN
    assert r.target_id == 1
    assert r.applications == "chrome.exe; msedge.exe"
    assert r.ports == "80; 443"


def test_round_trip_serialization() -> None:
    profile = ProfileParser.from_xml(SAMPLE_XML)
    xml_out = ProfileParser.to_xml(profile)
    profile_reloaded = ProfileParser.from_xml(xml_out)

    assert len(profile_reloaded.proxies) == len(profile.proxies)
    assert len(profile_reloaded.chains) == len(profile.chains)
    assert len(profile_reloaded.rules) == len(profile.rules)
    assert profile_reloaded.proxies[0].address == profile.proxies[0].address


def test_from_xml_sources() -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".ppx", delete=False, encoding="utf-8") as f:
        f.write(SAMPLE_XML)
        f_path = Path(f.name)

    try:
        # 1. From Path object
        p1 = ProfileParser.from_xml(f_path)
        assert len(p1.rules) == 3

        # 2. From file path string (not starting with '<')
        p2 = ProfileParser.from_xml(str(f_path))
        assert len(p2.rules) == 3

        # 3. From bytes
        p3 = ProfileParser.from_xml(SAMPLE_XML.encode("utf-8"))
        assert len(p3.rules) == 3
    finally:
        f_path.unlink(missing_ok=True)


def test_invalid_xml_raises_parse_error() -> None:
    with pytest.raises(ProfileParseError):
        ProfileParser.from_xml("<IncompleteXml>")

    # General reading exception
    with pytest.raises(ProfileParseError, match="Error reading profile XML"):
        ProfileParser.from_xml(12345)  # pyright: ignore[reportArgumentType]

    # Pre-existing ProfileParseError re-raised
    with mock.patch("xml.etree.ElementTree.fromstring", side_effect=ProfileParseError("Direct error")):
        with pytest.raises(ProfileParseError, match="Direct error"):
            ProfileParser.from_xml("<ValidXml />")


def test_corrupted_root_tag_raises_error() -> None:
    with pytest.raises(ProfileCorruptedError):
        ProfileParser.from_xml("<WrongRoot></WrongRoot>")


def test_chain_extended_options_serialization() -> None:
    profile = ProxifierProfile.create_default()
    profile.proxies.append(ProxyItem(id=100, address="1.1.1.1", port=1080))
    profile.proxies.append(ProxyItem(id=101, address="2.2.2.2", port=1080))
    profile.chains.append(
        ChainItem(
            id=1,
            name="RedChain",
            chain_type=ChainType.REDUNDANCY,
            proxy_ids=[100, 101],
            redundancy_recheck_sec=60,
            redundancy_timeout_sec=10,
            redundancy_try_direct=True,
        )
    )
    profile.chains.append(
        ChainItem(
            id=2,
            name="LbChain",
            chain_type=ChainType.LOAD_BALANCING,
            proxy_ids=[100, 101],
            load_balance_same_pid=True,
        )
    )
    xml_str = ProfileParser.to_xml(profile)
    assert 'try_direct="true"' in xml_str
    assert '<LoadBalancing same_pid="true"' in xml_str

    reloaded = ProfileParser.from_xml(xml_str)
    c1 = reloaded.find_chain(1)
    assert c1 is not None
    assert c1.redundancy_try_direct is True
    assert c1.redundancy_recheck_sec == 60
    assert c1.redundancy_timeout_sec == 10

    c2 = reloaded.find_chain(2)
    assert c2 is not None
    assert c2.load_balance_same_pid is True


def test_parser_helper_functions_and_edge_attributes() -> None:
    root = ET.Element("Root")

    # _get_enabled_bool child missing
    assert _get_enabled_bool(root, "MissingTag", default=True) is True

    # _get_elem_int with non-integer string
    sub = ET.SubElement(root, "IntTag")
    sub.text = "not_an_int"
    assert _get_elem_int(root, "IntTag", default=999) == 999

    # XML with custom enum strings, invalid redundancy ints, and custom Action string with non-int target
    custom_xml = """<?xml version="1.0" encoding="UTF-8"?>
<ProxifierProfile version="102">
    <Options>
        <Encryption mode="custom_encryption_mode" />
        <Udp mode="custom_udp_mode" />
    </Options>
    <ChainList>
        <Chain id="1" type="redundancy">
            <Name>BadRedundancy</Name>
            <Redundancy recheck="invalid_num" timeout="invalid_num" />
        </Chain>
    </ChainList>
    <RuleList>
        <Rule enabled="true">
            <Action type="CustomActionType">not_numeric_id</Action>
            <Name>CustomRule</Name>
        </Rule>
    </RuleList>
</ProxifierProfile>"""

    prof = ProfileParser.from_xml(custom_xml)
    assert prof.options.encryption_mode == "custom_encryption_mode"
    assert prof.options.udp_mode == "custom_udp_mode"
    assert prof.chains[0].redundancy_recheck_sec is None
    assert prof.chains[0].redundancy_timeout_sec is None
    assert prof.rules[0].action_type == "CustomActionType"
    assert prof.rules[0].target_id is None
