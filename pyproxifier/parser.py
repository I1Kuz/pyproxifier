"""Bidirectional XML Parser for Proxifier profiles (.ppx).

Handles complete serialization to XML and deserialization from XML files or strings,
preserving all Proxifier v4 and v3 configuration options.
"""

from pathlib import Path
from typing import Any, cast, overload
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
from pyproxifier.models.xml_element import XMLElement


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


def _to_etree_elem(node: Any) -> ET.Element:
    """Converts an XMLElement or ET.Element into an ET.Element safely."""
    if hasattr(node, "to_etree"):
        elem: Any = node.to_etree()
        if isinstance(elem, ET.Element):
            return cast(ET.Element, elem)
    if isinstance(node, ET.Element):
        return cast(ET.Element, node)
    raise TypeError(f"Expected XMLElement or xml.etree.ElementTree.Element, got {type(node).__name__}")


def _get_enabled_bool(
    parent: ET.Element, tag: str, default: bool = False, attr_name: str = "enabled"
) -> bool:
    """Finds a child element and parses its boolean attribute."""
    el = parent.find(tag)
    if el is None:
        return default
    return _parse_bool(el.attrib.get(attr_name), default)


def _get_elem_text(parent: ET.Element, tag: str, strip: bool = True) -> str | None:
    """Finds a child element and returns its text, or None if element absent.

    When strip=True (default), returns stripped text or None if empty.
    When strip=False, preserves exact text including whitespace (crucial for passwords).
    """
    el = parent.find(tag)
    if el is None:
        return None
    if el.text is None:
        return "" if not strip else None
    if strip:
        stripped = el.text.strip()
        return stripped if stripped else None
    return el.text


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
        """Serializes ProxifierProfile into XML string format preserving known and unmodeled elements."""
        root_attrs = {
            "version": str(profile.version),
            "platform": str(profile.platform),
            "product_id": str(profile.product_id),
            "product_minver": str(profile.product_minver),
        }
        root_attrs.update(profile.extra_attributes)
        root = ET.Element("ProxifierProfile", root_attrs)

        # -----------------------------------------------------------
        # <Options>
        # -----------------------------------------------------------
        opts = profile.options
        opts_el = ET.SubElement(root, "Options", dict(opts.extra_attributes))

        # <Resolve>
        res_attrs = dict(opts.dns.extra_attributes)
        resolve_el = ET.SubElement(opts_el, "Resolve", res_attrs)
        _add_enabled_elem(resolve_el, "AutoModeDetection", opts.dns.auto_mode_detection)
        _add_enabled_elem(resolve_el, "ViaProxy", opts.dns.via_proxy)
        _add_enabled_elem(resolve_el, "BlockNonATypes", opts.dns.block_non_a)

        excl_attrs = {"OnlyFromListMode": _bool_str(opts.dns.exclusion_only_from_list)}
        excl_attrs.update(opts.dns.exclusion_list_extra_attributes)
        excl_el = ET.SubElement(resolve_el, "ExclusionList", excl_attrs)
        excl_el.text = opts.dns.exclusion_list or ""

        _add_text_elem(resolve_el, "DnsUdpMode", opts.dns.dns_udp_mode)
        for extra_res in opts.dns.extra_elements:
            resolve_el.append(_to_etree_elem(extra_res))

        # Other options
        enc_mode = (
            opts.encryption_mode.value
            if isinstance(opts.encryption_mode, EncryptionMode)
            else str(opts.encryption_mode).lower()
        )
        enc_attrs = {"mode": enc_mode}
        enc_attrs.update(opts.encryption_extra_attributes)
        ET.SubElement(opts_el, "Encryption", enc_attrs)

        loop_attrs = {"resolve": _bool_str(opts.connection_loop_resolve)}
        loop_attrs.update(opts.connection_loop_extra_attributes)
        _add_enabled_elem(
            opts_el,
            "ConnectionLoopDetection",
            opts.connection_loop_detection,
            loop_attrs,
        )

        udp_val = (
            opts.udp_mode.value
            if isinstance(opts.udp_mode, UdpMode)
            else str(opts.udp_mode).lower()
        )
        udp_attrs = {"mode": udp_val}
        udp_attrs.update(opts.udp_extra_attributes)
        ET.SubElement(opts_el, "Udp", udp_attrs)

        _add_enabled_elem(opts_el, "LeakPreventionMode", opts.leak_prevention_mode)
        _add_enabled_elem(opts_el, "ProcessOtherUsers", opts.process_other_users)
        _add_enabled_elem(opts_el, "ProcessServices", opts.process_services)
        _add_enabled_elem(opts_el, "HandleDirectConnections", opts.handle_direct_connections)
        _add_enabled_elem(opts_el, "HttpProxiesSupport", opts.http_proxies_support)

        for extra_opt in opts.extra_elements:
            opts_el.append(_to_etree_elem(extra_opt))

        # -----------------------------------------------------------
        # <ProxyList>
        # -----------------------------------------------------------
        proxy_list_el = ET.SubElement(root, "ProxyList", dict(profile.proxy_list_extra_attributes))
        for proxy in profile.proxies:
            p_attrs = {"id": str(proxy.id), "type": proxy.protocol_name}
            p_attrs.update(proxy.extra_attributes)
            p_el = ET.SubElement(proxy_list_el, "Proxy", p_attrs)

            if proxy.label:
                _add_text_elem(p_el, "Label", proxy.label)

            auth_active = (
                proxy.auth_enabled
                if proxy.auth_enabled is not None
                else proxy.has_auth
            )
            auth_attrs = dict(proxy.auth_extra_attributes)
            auth_el = _add_enabled_elem(p_el, "Authentication", auth_active, auth_attrs)
            _add_text_elem(auth_el, "Username", proxy.username)
            _add_text_elem(auth_el, "Password", proxy.password)
            for extra_auth in proxy.auth_extra_elements:
                auth_el.append(_to_etree_elem(extra_auth))

            _add_text_elem(p_el, "Options", proxy.options)
            _add_text_elem(p_el, "Port", proxy.port)
            _add_text_elem(p_el, "Address", proxy.address)

            for extra_p in proxy.extra_elements:
                p_el.append(_to_etree_elem(extra_p))

        # -----------------------------------------------------------
        # <ChainList>
        # -----------------------------------------------------------
        chain_list_el = ET.SubElement(root, "ChainList", dict(profile.chain_list_extra_attributes))
        for chain in profile.chains:
            chain_attrs: dict[str, str] = {"id": str(chain.id)}
            if chain.type_name != ChainType.SIMPLE.value:
                chain_attrs["type"] = chain.type_name
            chain_attrs.update(chain.extra_attributes)
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

            for extra_c in chain.extra_elements:
                c_el.append(_to_etree_elem(extra_c))

        # -----------------------------------------------------------
        # <RuleList>
        # -----------------------------------------------------------
        rule_list_el = ET.SubElement(root, "RuleList", dict(profile.rule_list_extra_attributes))
        for rule in profile.rules:
            r_attrs = dict(rule.extra_attributes)
            r_el = _add_enabled_elem(rule_list_el, "Rule", rule.enabled, r_attrs)

            # Canonical action name
            norm_action = rule.action_name
            action_attrs = {"type": norm_action}
            action_attrs.update(rule.action_extra_attributes)
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

            for extra_r in rule.extra_elements:
                r_el.append(_to_etree_elem(extra_r))

        # -----------------------------------------------------------
        # Unmodeled Top-Level Elements (e.g. <FutureSection>)
        # -----------------------------------------------------------
        for extra_root in profile.extra_elements:
            root.append(_to_etree_elem(extra_root))

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

        known_root_attrs = {"version", "platform", "product_id", "product_minver"}
        extra_root_attrs = {k: v for k, v in root.attrib.items() if k not in known_root_attrs}

        profile = ProxifierProfile(
            version=root.attrib.get("version", "102"),
            platform=root.attrib.get("platform", "Windows"),
            product_id=root.attrib.get("product_id", "0"),
            product_minver=root.attrib.get("product_minver", "400"),
            extra_attributes=extra_root_attrs,
        )

        # -----------------------------------------------------------
        # Parse child sections (known and unmodeled)
        # -----------------------------------------------------------
        for child in root:
            if child.tag == "Options":
                profile.options = cls._parse_options(child)
            elif child.tag == "ProxyList":
                profile.proxy_list_extra_attributes.update(child.attrib)
                for p_el in child.findall("Proxy"):
                    proxy = cls._parse_proxy(p_el)
                    profile.proxies.append(proxy)
            elif child.tag == "ChainList":
                profile.chain_list_extra_attributes.update(child.attrib)
                for c_el in child.findall("Chain"):
                    chain = cls._parse_chain(c_el)
                    profile.chains.append(chain)
            elif child.tag == "RuleList":
                profile.rule_list_extra_attributes.update(child.attrib)
                for r_el in child.findall("Rule"):
                    rule = cls._parse_rule(r_el)
                    profile.rules.append(rule)
            else:
                profile.extra_elements.append(XMLElement.from_etree(child))

        return profile

    @classmethod
    def _parse_options(cls, opts_el: ET.Element) -> ProfileOptions:
        options = ProfileOptions()
        options.extra_attributes.update(opts_el.attrib)

        # <Resolve>
        res_el = opts_el.find("Resolve")
        if res_el is not None:
            options.dns.extra_attributes.update(res_el.attrib)
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
                options.dns.exclusion_list_extra_attributes.update(
                    {k: v for k, v in excl_el.attrib.items() if k != "OnlyFromListMode"}
                )

            dns_udp_mode = _get_elem_int(res_el, "DnsUdpMode")
            if dns_udp_mode is not None:
                options.dns.dns_udp_mode = dns_udp_mode

            known_dns_tags = {
                "AutoModeDetection",
                "ViaProxy",
                "BlockNonATypes",
                "ExclusionList",
                "DnsUdpMode",
            }
            for child in res_el:
                if child.tag not in known_dns_tags:
                    options.dns.extra_elements.append(XMLElement.from_etree(child))

        # <Encryption>
        enc_el = opts_el.find("Encryption")
        if enc_el is not None:
            mode = enc_el.attrib.get("mode", "disabled")
            options.encryption_extra_attributes.update(
                {k: v for k, v in enc_el.attrib.items() if k != "mode"}
            )
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
            options.connection_loop_extra_attributes.update(
                {k: v for k, v in loop_el.attrib.items() if k not in ("enabled", "resolve")}
            )

        # <Udp>
        udp_el = opts_el.find("Udp")
        if udp_el is not None:
            mode = udp_el.attrib.get("mode", "mode_block_all")
            options.udp_extra_attributes.update(
                {k: v for k, v in udp_el.attrib.items() if k != "mode"}
            )
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

        known_opt_tags = {
            "Resolve",
            "Encryption",
            "ConnectionLoopDetection",
            "Udp",
            "LeakPreventionMode",
            "ProcessOtherUsers",
            "ProcessServices",
            "HandleDirectConnections",
            "HttpProxiesSupport",
        }
        for child in opts_el:
            if child.tag not in known_opt_tags:
                options.extra_elements.append(XMLElement.from_etree(child))

        return options

    @classmethod
    def _parse_proxy(cls, p_el: ET.Element) -> ProxyItem:
        known_proxy_attrs = {"id", "type"}
        extra_proxy_attrs = {k: v for k, v in p_el.attrib.items() if k not in known_proxy_attrs}

        p_id = int(p_el.attrib.get("id", 100))
        p_type = p_el.attrib.get("type", "SOCKS5")
        label = _get_elem_text(p_el, "Label")

        username = None
        password = None
        auth_enabled = None
        auth_extra_attrs: dict[str, str] = {}
        auth_extra_elems: list[XMLElement] = []

        auth_el = p_el.find("Authentication")
        if auth_el is not None:
            auth_enabled = _parse_bool(auth_el.attrib.get("enabled"), False)
            auth_extra_attrs = {k: v for k, v in auth_el.attrib.items() if k != "enabled"}
            username = _get_elem_text(auth_el, "Username", strip=False)
            password = _get_elem_text(auth_el, "Password", strip=False)
            known_auth_tags = {"Username", "Password"}
            for child in auth_el:
                if child.tag not in known_auth_tags:
                    auth_extra_elems.append(XMLElement.from_etree(child))

        options = _get_elem_int(p_el, "Options", default=48)
        port = _get_elem_int(p_el, "Port", default=1080)
        address = _get_elem_text(p_el, "Address") or ""

        known_proxy_tags = {"Label", "Authentication", "Options", "Port", "Address"}
        extra_proxy_elems = [
            XMLElement.from_etree(child) for child in p_el if child.tag not in known_proxy_tags
        ]

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
            extra_attributes=extra_proxy_attrs,
            extra_elements=extra_proxy_elems,
            auth_extra_attributes=auth_extra_attrs,
            auth_extra_elements=auth_extra_elems,
        )

    @classmethod
    def _parse_chain(cls, c_el: ET.Element) -> ChainItem:
        c_id = int(c_el.attrib.get("id", 1))
        c_type = c_el.attrib.get("type", "simple")
        name = _get_elem_text(c_el, "Name") or f"Chain{c_id}"

        known_chain_attrs = {"id", "type"}
        extra_chain_attrs = {k: v for k, v in c_el.attrib.items() if k not in known_chain_attrs}

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

        known_chain_tags = {"Name", "Proxy", "Redundancy", "LoadBalancing"}
        extra_chain_elems = [
            XMLElement.from_etree(child) for child in c_el if child.tag not in known_chain_tags
        ]

        return ChainItem(
            id=c_id,
            name=name,
            chain_type=c_type,
            proxy_ids=proxy_ids,
            redundancy_recheck_sec=recheck_sec,
            redundancy_timeout_sec=timeout_sec,
            redundancy_try_direct=try_direct,
            load_balance_same_pid=same_pid,
            extra_attributes=extra_chain_attrs,
            extra_elements=extra_chain_elems,
        )

    @classmethod
    def _parse_rule(cls, r_el: ET.Element) -> RuleItem:
        enabled = _parse_bool(r_el.attrib.get("enabled"), True)
        name = _get_elem_text(r_el, "Name") or "Unnamed"

        known_rule_attrs = {"enabled"}
        extra_rule_attrs = {k: v for k, v in r_el.attrib.items() if k not in known_rule_attrs}

        action_type: ActionType | str = ActionType.DIRECT
        target_id: int | None = None
        action_extra_attrs: dict[str, str] = {}

        act_el = r_el.find("Action")
        if act_el is not None:
            type_str = act_el.attrib.get("type", "Direct")
            action_extra_attrs = {k: v for k, v in act_el.attrib.items() if k != "type"}
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

        known_rule_tags = {"Action", "Applications", "Targets", "Ports", "Name"}
        extra_rule_elems = [
            XMLElement.from_etree(child) for child in r_el if child.tag not in known_rule_tags
        ]

        return RuleItem(
            name=name,
            action_type=action_type,
            target_id=target_id,
            enabled=enabled,
            applications=applications,
            targets=targets,
            ports=ports,
            extra_attributes=extra_rule_attrs,
            extra_elements=extra_rule_elems,
            action_extra_attributes=action_extra_attrs,
        )

