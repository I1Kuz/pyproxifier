"""XML model for preserving arbitrary unmodeled XML elements and structure."""

from __future__ import annotations

from dataclasses import dataclass, field
import xml.etree.ElementTree as ET


@dataclass
class XMLElement:
    """Represents an unmodeled or custom XML element preserving tag, attributes, text, and nested hierarchy.

    Enables 100% round-trip fidelity for future/unknown Proxifier XML extensions.
    """

    tag: str
    attributes: dict[str, str] = field(default_factory=dict)
    text: str | None = None
    children: list[XMLElement] = field(default_factory=list)

    @classmethod
    def from_etree(cls, elem: ET.Element) -> XMLElement:
        """Constructs an XMLElement recursively from an xml.etree.ElementTree.Element."""
        has_children = len(elem) > 0
        raw_text = elem.text
        # If element has children and text is only formatting whitespace, omit it so ET.indent can format cleanly
        if has_children and raw_text is not None and not raw_text.strip():
            text = None
        else:
            text = raw_text

        return cls(
            tag=elem.tag,
            attributes=dict(elem.attrib),
            text=text,
            children=[cls.from_etree(child) for child in elem],
        )

    def to_etree(self) -> ET.Element:
        """Converts recursively back into an xml.etree.ElementTree.Element."""
        clean_attrs = {str(k): str(v) for k, v in self.attributes.items()}
        elem = ET.Element(self.tag, clean_attrs)
        if self.text is not None:
            elem.text = str(self.text)
        for child in self.children:
            elem.append(child.to_etree())
        return elem

    @classmethod
    def from_xml_string(cls, xml_str: str) -> XMLElement:
        """Parses an XML string into an XMLElement hierarchy."""
        return cls.from_etree(ET.fromstring(xml_str))

    def to_xml_string(self) -> str:
        """Serializes the XMLElement hierarchy into an XML string."""
        return ET.tostring(self.to_etree(), encoding="utf-8").decode("utf-8")

