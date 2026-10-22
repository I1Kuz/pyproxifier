"""Bidirectional XML Parser for Proxifier profiles (.ppx).

Handles complete serialization to XML and deserialization from XML files or strings,
preserving all Proxifier v4 and v3 configuration options.
"""

from pathlib import Path
from typing import Any, overload
import xml.etree.ElementTree as ET

from pyproxifier.exceptions import ProfileCorruptedError, ProfileParseError
from pyproxifier.models.chain import ChainItem, ChainType
from pyproxifier.models.options import (
    EncryptionMode,
    ProfileOptions,
    UdpMode,
)
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.models.proxy import ProxyItem
from pyproxifier.models.rule import ActionType, RuleItem


def _bool_str(val: bool) -> str:
    return "true" if val else "false"


def _parse_bool(val: str | None, default: bool = False) -> bool:
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes")


def _add_enabled_elem(
    parent: ET.Element,
    tag: str,
    enabled: bool,
    extra_attrs: dict[str, str] | None = None,
) -> ET.Element:
    """Creates a subelement with an 'enabled' XML attribute."""
    attrs = {"enabled": _bool_str(enabled)}
    if extra_attrs:
        attrs.update(extra_attrs)
    return ET.SubElement(parent, tag, attrs)


def _add_text_elem(
    parent: ET.Element,
    tag: str,
    text: Any,
    attrs: dict[str, str] | None = None,
) -> ET.Element | None:
    """Creates a subelement with text content if text is not None."""
    if text is None:
        return None
    el = ET.SubElement(parent, tag, attrs or {})
    el.text = str(text)
    return el


def _get_enabled_bool(
    parent: ET.Element, tag: str, default: bool = False, attr_name: str = "enabled"
) -> bool:
    """Finds a child element and parses its boolean attribute."""
    el = parent.find(tag)
    if el is None:
        return default
    return _parse_bool(el.attrib.get(attr_name), default)


def _get_elem_text(parent: ET.Element, tag: str) -> str | None:
    """Finds a child element and returns its stripped text, or None."""
    el = parent.find(tag)
    if el is not None and el.text is not None and el.text.strip():
        return el.text.strip()
    return None


@overload
def _get_elem_int(parent: ET.Element, tag: str, default: int) -> int: ...


@overload
def _get_elem_int(parent: ET.Element, tag: str, default: None = None) -> int | None: ...


def _get_elem_int(
    parent: ET.Element, tag: str, default: int | None = None
) -> int | None:
    """Finds a child element and parses its integer text, or returns default."""
    text = _get_elem_text(parent, tag)
    if text is not None:
        try:
            return int(text)
        except ValueError:
            pass
    return default


class ProfileParser:
    """Serializes and deserializes Proxifier profile (.ppx) documents."""

    @classmethod
    def to_xml(cls, profile: ProxifierProfile, use_tabs: bool = True) -> str:
        """Serializes ProxifierProfile into XML string format."""
        root = ET.Element(
            "ProxifierProfile",
            {
                "version": str(profile.version),
                "platform": str(profile.platform),
                "product_id": str(profile.product_id),
                "product_minver": str(profile.product_minver),
            },
        )

        # -----------------------------------------------------------
        # <Options>
        # -----------------------------------------------------------
        opts = profile.options
        opts_el = ET.SubElement(root, "Options")

        # <Resolve>
        resolve_el = ET.SubElement(opts_el, "Resolve")
        _add_enabled_elem(resolve_el, "AutoModeDetection", opts.dns.auto_mode_detection)
        _add_enabled_elem(resolve_el, "ViaProxy", opts.dns.via_proxy)
        _add_enabled_elem(resolve_el, "BlockNonATypes", opts.dns.block_non_a)

        excl_el = ET.SubElement(
            resolve_el,
            "ExclusionList",
            {"OnlyFromListMode": _bool_str(opts.dns.exclusion_only_from_list)},
        )
        excl_el.text = opts.dns.exclusion_list or ""

        _add_text_elem(resolve_el, "DnsUdpMode", opts.dns.dns_udp_mode)

        # Other options
        enc_mode = (
            opts.encryption_mode.value
            if isinstance(opts.encryption_mode, EncryptionMode)
            else str(opts.encryption_mode).lower()
        )
        ET.SubElement(opts_el, "Encryption", {"mode": enc_mode})

        _add_enabled_elem(
            opts_el,
            "ConnectionLoopDetection",
            opts.connection_loop_detection,
            {"resolve": _bool_str(opts.connection_loop_resolve)},
        )

        udp_val = (
            opts.udp_mode.value
            if isinstance(opts.udp_mode, UdpMode)
            else str(opts.udp_mode).lower()
        )
        ET.SubElement(opts_el, "Udp", {"mode": udp_val})

        _add_enabled_elem(opts_el, "LeakPreventionMode", opts.leak_prevention_mode)
        _add_enabled_elem(opts_el, "ProcessOtherUsers", opts.process_other_users)
        _add_enabled_elem(opts_el, "ProcessServices", opts.process_services)
        _add_enabled_elem(opts_el, "HandleDirectConnections", opts.handle_direct_connections)
        _add_enabled_elem(opts_el, "HttpProxiesSupport", opts.http_proxies_support)

        # -----------------------------------------------------------
        # <ProxyList>
        # -----------------------------------------------------------
        proxy_list_el = ET.SubElement(root, "ProxyList")
        for proxy in profile.proxies:
            p_el = ET.SubElement(
                proxy_list_el,
                "Proxy",
                {"id": str(proxy.id), "type": proxy.protocol_name},
            )

            if proxy.label:
                _add_text_elem(p_el, "Label", proxy.label)

            auth_active = (
                proxy.auth_enabled
                if proxy.auth_enabled is not None
                else proxy.has_auth
            )
            auth_el = _add_enabled_elem(p_el, "Authentication", auth_active)
            _add_text_elem(auth_el, "Username", proxy.username)
            _add_text_elem(auth_el, "Password", proxy.password)

            _add_text_elem(p_el, "Options", proxy.options)
            _add_text_elem(p_el, "Port", proxy.port)
            _add_text_elem(p_el, "Address", proxy.address)

        # -----------------------------------------------------------
        # <ChainList>
        # -----------------------------------------------------------
        chain_list_el = ET.SubElement(root, "ChainList")
        for chain in profile.chains:
            chain_attrs: dict[str, str] = {"id": str(chain.id)}
            if chain.type_name != ChainType.SIMPLE.value:
                chain_attrs["type"] = chain.type_name
            c_el = ET.SubElement(chain_list_el, "Chain", chain_attrs)

            _add_text_elem(c_el, "Name", chain.name)

            for pid in chain.proxy_ids:
                ET.SubElement(c_el, "Proxy", {"id": str(pid)})

            if chain.type_name == ChainType.REDUNDANCY.value:
                red_attrs: dict[str, str] = {}
                if chain.redundancy_recheck_sec is not None:
                    red_attrs["recheck"] = str(chain.redundancy_recheck_sec)
                if chain.redundancy_timeout_sec is not None:
                    red_attrs["timeout"] = str(chain.redundancy_timeout_sec)
                if chain.redundancy_try_direct:
                    red_attrs["try_direct"] = _bool_str(chain.redundancy_try_direct)
                ET.SubElement(c_el, "Redundancy", red_attrs)
            elif chain.type_name == ChainType.LOAD_BALANCING.value:
                lb_attrs: dict[str, str] = {
                    "same_pid": _bool_str(chain.load_balance_same_pid)
                }
                ET.SubElement(c_el, "LoadBalancing", lb_attrs)

        # -----------------------------------------------------------
        # <RuleList>
        # -----------------------------------------------------------
        rule_list_el = ET.SubElement(root, "RuleList")
        for rule in profile.rules:
            r_el = _add_enabled_elem(rule_list_el, "Rule", rule.enabled)

            # Canonical action name
            norm_action = rule.action_name
            action_attrs = {"type": norm_action}
            action_el = ET.SubElement(r_el, "Action", action_attrs)
            if (
                norm_action in (ActionType.PROXY.value, ActionType.CHAIN.value)
                and rule.target_id is not None
            ):
                action_el.text = str(rule.target_id)

            if rule.applications:
                _add_text_elem(r_el, "Applications", rule.applications)
            if rule.targets:
                _add_text_elem(r_el, "Targets", rule.targets)
            if rule.ports:
                _add_text_elem(r_el, "Ports", rule.ports)
            _add_text_elem(r_el, "Name", rule.name)

        indent_str = "\t" if use_tabs else "    "
        ET.indent(root, space=indent_str)
        raw_xml = ET.tostring(root, encoding="utf-8").decode("utf-8")
        return f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n{raw_xml}'

    @classmethod
    def from_xml(cls, xml_source: str | bytes | Path) -> ProxifierProfile:
        """Parses an XML string, bytes, or file path into a ProxifierProfile."""
        try:
            if isinstance(xml_source, Path):
                tree = ET.parse(str(xml_source))
                root = tree.getroot()
            else:
                # If it's a file path string that exists
                if (
                    isinstance(xml_source, str)
                    and not xml_source.strip().startswith("<")
                    and Path(xml_source).is_file()
                ):
                    tree = ET.parse(xml_source)
                    root = tree.getroot()
                else:
                    root = ET.fromstring(xml_source)
        except ET.ParseError as e:
            raise ProfileParseError(f"XML parsing failed: {e}", line=e.lineno if hasattr(e, 'lineno') else None) from e
        except Exception as e:
            if isinstance(e, ProfileParseError):
                raise
            raise ProfileParseError(f"Error reading profile XML: {e}") from e

        if root.tag != "ProxifierProfile":
            raise ProfileCorruptedError(
                f"Root XML element must be 'ProxifierProfile', got '{root.tag}'."
            )

        profile = ProxifierProfile(
            version=root.attrib.get("version", "102"),
            platform=root.attrib.get("platform", "Windows"),
            product_id=root.attrib.get("product_id", "0"),
            product_minver=root.attrib.get("product_minver", "400"),
        )

        # -----------------------------------------------------------
        # Parse <Options>
        # -----------------------------------------------------------
        opts_el = root.find("Options")
        if opts_el is not None:
            profile.options = cls._parse_options(opts_el)

        # -----------------------------------------------------------
        # Parse <ProxyList>
        # -----------------------------------------------------------
        proxy_list_el = root.find("ProxyList")
        if proxy_list_el is not None:
            for p_el in proxy_list_el.findall("Proxy"):
                proxy = cls._parse_proxy(p_el)
                profile.proxies.append(proxy)

        # -----------------------------------------------------------
        # Parse <ChainList>
        # -----------------------------------------------------------
        chain_list_el = root.find("ChainList")
        if chain_list_el is not None:
            for c_el in chain_list_el.findall("Chain"):
                chain = cls._parse_chain(c_el)
                profile.chains.append(chain)

        # -----------------------------------------------------------
        # Parse <RuleList>
        # -----------------------------------------------------------
        rule_list_el = root.find("RuleList")
        if rule_list_el is not None:
            for r_el in rule_list_el.findall("Rule"):
                rule = cls._parse_rule(r_el)
                profile.rules.append(rule)

        return profile

    @classmethod
    def _parse_options(cls, opts_el: ET.Element) -> ProfileOptions:
        options = ProfileOptions()

        # <Resolve>
        res_el = opts_el.find("Resolve")
        if res_el is not None:
            options.dns.auto_mode_detection = _get_enabled_bool(
                res_el, "AutoModeDetection", default=False
            )
            options.dns.via_proxy = _get_enabled_bool(
                res_el, "ViaProxy", default=True
            )
            options.dns.block_non_a = _get_enabled_bool(
                res_el, "BlockNonATypes", default=True
            )

            excl_el = res_el.find("ExclusionList")
            if excl_el is not None:
                options.dns.exclusion_list = excl_el.text or ""
                options.dns.exclusion_only_from_list = _parse_bool(
                    excl_el.attrib.get("OnlyFromListMode"), False
                )

            dns_udp_mode = _get_elem_int(res_el, "DnsUdpMode")
            if dns_udp_mode is not None:
                options.dns.dns_udp_mode = dns_udp_mode

        # <Encryption>
        enc_el = opts_el.find("Encryption")
        if enc_el is not None:
            mode = enc_el.attrib.get("mode", "disabled")
            try:
                options.encryption_mode = EncryptionMode.from_str(mode)
            except ValueError:
                options.encryption_mode = mode

        # <ConnectionLoopDetection>
        loop_el = opts_el.find("ConnectionLoopDetection")
        if loop_el is not None:
            options.connection_loop_detection = _parse_bool(
                loop_el.attrib.get("enabled"), True
            )
            options.connection_loop_resolve = _parse_bool(
                loop_el.attrib.get("resolve"), True
            )

        # <Udp>
        udp_el = opts_el.find("Udp")
        if udp_el is not None:
            mode = udp_el.attrib.get("mode", "mode_block_all")
            try:
                options.udp_mode = UdpMode.from_str(mode)
            except ValueError:
                options.udp_mode = mode

        # Boolean flags
        options.leak_prevention_mode = _get_enabled_bool(
            opts_el, "LeakPreventionMode", default=True
        )
        options.process_other_users = _get_enabled_bool(
            opts_el, "ProcessOtherUsers", default=False
        )
        options.process_services = _get_enabled_bool(
            opts_el, "ProcessServices", default=False
        )
        options.handle_direct_connections = _get_enabled_bool(
            opts_el, "HandleDirectConnections", default=False
        )
        options.http_proxies_support = _get_enabled_bool(
            opts_el, "HttpProxiesSupport", default=False
        )

        return options

    @classmethod
    def _parse_proxy(cls, p_el: ET.Element) -> ProxyItem:
        p_id = int(p_el.attrib.get("id", 100))
        p_type = p_el.attrib.get("type", "SOCKS5")
        label = _get_elem_text(p_el, "Label")

        username = None
        password = None
        auth_enabled = None
        auth_el = p_el.find("Authentication")
        if auth_el is not None:
            auth_enabled = _parse_bool(auth_el.attrib.get("enabled"), False)
            username = _get_elem_text(auth_el, "Username")
            password = _get_elem_text(auth_el, "Password")

        options = _get_elem_int(p_el, "Options", default=48)
        port = _get_elem_int(p_el, "Port", default=1080)
        address = _get_elem_text(p_el, "Address") or ""

        return ProxyItem(
            id=p_id,
            protocol_type=p_type,
            address=address,
            port=port,
            username=username,
            password=password,
            options=options,
            label=label,
            auth_enabled=auth_enabled,
        )

    @classmethod
    def _parse_chain(cls, c_el: ET.Element) -> ChainItem:
        c_id = int(c_el.attrib.get("id", 1))
        c_type = c_el.attrib.get("type", "simple")
        name = _get_elem_text(c_el, "Name") or f"Chain{c_id}"

        proxy_ids: list[int] = []
        for p_sub in c_el.findall("Proxy"):
            pid_str = p_sub.attrib.get("id")
            if pid_str:
                proxy_ids.append(int(pid_str))

        recheck_sec = None
        timeout_sec = None
        try_direct = False
        red_el = c_el.find("Redundancy")
        if red_el is not None:
            if "recheck" in red_el.attrib:
                try:
                    recheck_sec = int(red_el.attrib["recheck"])
                except ValueError:
                    pass
            if "timeout" in red_el.attrib:
                try:
                    timeout_sec = int(red_el.attrib["timeout"])
                except ValueError:
                    pass
            try_direct = _parse_bool(red_el.attrib.get("try_direct"), False)

        same_pid = False
        lb_el = c_el.find("LoadBalancing")
        if lb_el is not None:
            same_pid = _parse_bool(lb_el.attrib.get("same_pid"), False)

        return ChainItem(
            id=c_id,
            name=name,
            chain_type=c_type,
            proxy_ids=proxy_ids,
            redundancy_recheck_sec=recheck_sec,
            redundancy_timeout_sec=timeout_sec,
            redundancy_try_direct=try_direct,
            load_balance_same_pid=same_pid,
        )

    @classmethod
    def _parse_rule(cls, r_el: ET.Element) -> RuleItem:
        enabled = _parse_bool(r_el.attrib.get("enabled"), True)
        name = _get_elem_text(r_el, "Name") or "Unnamed"

        action_type: ActionType | str = ActionType.DIRECT
        target_id: int | None = None
        act_el = r_el.find("Action")
        if act_el is not None:
            type_str = act_el.attrib.get("type", "Direct")
            try:
                action_type = ActionType.from_str(type_str)
            except ValueError:
                action_type = type_str
            if act_el.text and act_el.text.strip():
                try:
                    target_id = int(act_el.text.strip())
                except ValueError:
                    pass

        applications = _get_elem_text(r_el, "Applications")
        targets = _get_elem_text(r_el, "Targets")
        ports = _get_elem_text(r_el, "Ports")

        return RuleItem(
            name=name,
            action_type=action_type,
            target_id=target_id,
            enabled=enabled,
            applications=applications,
            targets=targets,
            ports=ports,
        )

