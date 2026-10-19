"""Data models for Proxifier routing rules."""

from dataclasses import dataclass
from enum import Enum


class ActionType(str, Enum):
    """Action taken when a network connection matches a rule."""

    DIRECT = "Direct"
    BLOCK = "Block"
    PROXY = "Proxy"
    CHAIN = "Chain"

    @classmethod
    def from_str(cls, val: str) -> "ActionType":
        target = val.strip().lower()
        for member in cls:
            if member.value.lower() == target:
                return member
        raise ValueError(f"Unsupported action type: {val!r}")


@dataclass
class RuleItem:
    """Represents a single routing rule (<Rule> in <RuleList>).

    Proxifier processes rules from top to bottom. The first rule whose
    criteria match the outgoing connection determines the routing action.

    Attributes:
        name: Name of the rule.
        action_type: Action: Direct, Block, Proxy, or Chain.
        target_id: ID of the target Proxy (when Action=Proxy) or Chain (when Action=Chain).
        enabled: Whether the rule is active (ignored when disabled).
        applications: Semicolon-separated list of executable names or masks (e.g. 'chrome.exe; curl.exe').
        targets: Semicolon-separated hostnames, IPs, CIDR blocks, or masks (e.g. '*.google.com; 10.0.0.0/8').
        ports: Semicolon-separated port numbers or ranges (e.g. '80; 443; 8000-8080').
    """

    name: str
    action_type: ActionType | str = ActionType.DIRECT
    target_id: int | str | None = None
    enabled: bool = True
    applications: str | None = None
    targets: str | None = None
    ports: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action_type, ActionType):
            try:
                self.action_type = ActionType.from_str(str(self.action_type))
            except ValueError:
                pass
        if self.target_id is not None:
            try:
                self.target_id = int(self.target_id)
            except ValueError:
                pass

    @property
    def action_name(self) -> str:
        """Returns canonical title-case action string ('Direct', 'Block', 'Proxy', 'Chain')."""
        if isinstance(self.action_type, ActionType):
            return self.action_type.value
        try:
            return ActionType.from_str(str(self.action_type)).value
        except ValueError:
            return str(self.action_type).capitalize()

    @property
    def is_system_rule(self) -> bool:
        """True if this is one of the built-in system rules ('Localhost' or 'Default')."""
        return self.name.lower() in ("localhost", "default")
