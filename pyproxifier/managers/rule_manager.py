"""Manager for Proxifier routing rules."""

from __future__ import annotations

from typing import Any

from pyproxifier.exceptions import RuleNotFoundError, ValidationError
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.models.rule import ActionType, RuleItem


class RuleManager:
    """Manages routing rules, evaluation priority (top-to-bottom order), and rule states."""

    def __init__(self, profile: ProxifierProfile) -> None:
        self._profile = profile

    @property
    def profile(self) -> ProxifierProfile:
        return self._profile

    def add(
        self,
        name: str,
        action: ActionType | str = ActionType.DIRECT,
        target_id: int | None = None,
        applications: str | None = None,
        targets: str | None = None,
        ports: str | None = None,
        enabled: bool = True,
        before: str | None = None,
        after: str | None = None,
    ) -> RuleItem:
        """Adds a new routing rule.

        By default, the new rule is inserted immediately before the 'Default' rule,
        or at the end if no Default rule is present.
        """
        if self.find(name):
            raise ValidationError(f"Rule with name '{name}' already exists.")

        if after and after.strip().lower() == "default":
            raise ValidationError("No rule can be placed after the mandatory 'Default' rule.")

        rule = RuleItem(
            name=name,
            action_type=action,
            target_id=target_id,
            applications=applications,
            targets=targets,
            ports=ports,
            enabled=enabled,
        )

        if before:
            idx = self._index_of(before)
            self._profile.rules.insert(idx, rule)
        elif after:
            idx = self._index_of(after)
            self._profile.rules.insert(idx + 1, rule)
        else:
            # Default placement: before the last rule if it is 'Default'
            if self._profile.rules and self._profile.rules[-1].name.lower() == "default":
                self._profile.rules.insert(len(self._profile.rules) - 1, rule)
            else:
                self._profile.rules.append(rule)

        return rule

    def get(self, name: str) -> RuleItem:
        """Retrieves a rule by name. Raises RuleNotFoundError if not found."""
        rule = self.find(name)
        if not rule:
            raise RuleNotFoundError(name)
        return rule

    def find(self, name: str) -> RuleItem | None:
        """Finds a rule by name or returns None."""
        return self._profile.find_rule(name)

    def list(self) -> list[RuleItem]:
        """Returns the ordered list of rules (first evaluated to last evaluated)."""
        return list(self._profile.rules)

    def update(self, identifier: str, /, **updates: Any) -> RuleItem:
        """Updates attributes of an existing rule."""
        rule = self.get(identifier)
        if "name" in updates:
            new_name = str(updates["name"]).strip()
            if not new_name:
                raise ValidationError("Rule name cannot be empty.")
            if rule.name.lower() == "default" and new_name.lower() != "default":
                raise ValidationError("Cannot rename the mandatory 'Default' system rule.")
            if new_name.lower() != rule.name.lower() and self.find(new_name):
                raise ValidationError(f"Rule with name '{new_name}' already exists.")
        for key, val in updates.items():
            if not hasattr(rule, key):
                raise AttributeError(f"RuleItem has no attribute {key!r}")
            setattr(rule, key, val)
        return rule

    def remove(self, name: str) -> bool:
        """Removes a rule by name.

        Note: The 'Default' rule cannot be deleted, as Proxifier requires it.
        """
        rule = self.get(name)
        if rule.name.lower() == "default":
            raise ValidationError(
                "The 'Default' system rule cannot be removed. You can change its action instead using set_default_action()."
            )
        self._profile.rules.remove(rule)
        return True

    def enable(self, name: str) -> RuleItem:
        """Enables a rule."""
        return self.update(name, enabled=True)

    def disable(self, name: str) -> RuleItem:
        """Disables a rule."""
        return self.update(name, enabled=False)

    def move_up(self, name: str) -> None:
        """Moves a rule one step up in the evaluation priority order."""
        if name.strip().lower() == "default":
            return  # Default rule must always remain at the bottom

        idx = self._index_of(name)
        if idx <= 0:
            return  # Already at top
        self._profile.rules[idx - 1], self._profile.rules[idx] = (
            self._profile.rules[idx],
            self._profile.rules[idx - 1],
        )

    def move_down(self, name: str) -> None:
        """Moves a rule one step down in the evaluation priority order."""
        idx = self._index_of(name)
        last_allowed_idx = len(self._profile.rules) - 1
        # If the last rule is 'Default', user rules cannot be moved below it
        if self._profile.rules[-1].name.lower() == "default":
            last_allowed_idx -= 1

        if idx >= last_allowed_idx:
            return
        self._profile.rules[idx], self._profile.rules[idx + 1] = (
            self._profile.rules[idx + 1],
            self._profile.rules[idx],
        )

    def set_default_action(
        self, action: ActionType | str, target_id: int | None = None
    ) -> RuleItem:
        """Sets the action and target for the mandatory 'Default' fallback rule."""
        rule = self.find("Default")
        if not rule:
            rule = RuleItem(name="Default", action_type=action, target_id=target_id)
            self._profile.rules.append(rule)
        else:
            rule.action_type = action
            rule.target_id = target_id
        return rule

    def ensure_localhost_rule(
        self, action: ActionType | str = ActionType.DIRECT
    ) -> RuleItem:
        """Ensures the standard Localhost loopback bypass rule exists at the top."""
        rule = self.find("Localhost")
        if not rule:
            rule = RuleItem(
                name="Localhost",
                targets="localhost; 127.0.0.1; %ComputerName%; ::1",
                action_type=action,
            )
            self._profile.rules.insert(0, rule)
        else:
            rule.action_type = action
            idx = self._profile.rules.index(rule)
            if idx > 0:
                self._profile.rules.pop(idx)
                self._profile.rules.insert(0, rule)
        return rule

    def unbind_target(
        self, action_type: ActionType | str, target_id: int | str | None = None
    ) -> int:
        """Resets rules pointing to the given action and target_id to Direct action.

        If target_id is None, unbinds all rules matching action_type.
        Returns the number of unbind modifications made.
        """
        norm_action = (
            action_type.value
            if isinstance(action_type, ActionType)
            else ActionType.from_str(str(action_type)).value
        )
        target_id_int = int(target_id) if isinstance(target_id, int) or (isinstance(target_id, str) and target_id.isdigit()) else target_id
        count = 0
        for rule in self._profile.rules:
            if rule.action_name == norm_action:
                if target_id is None or rule.target_id == target_id_int:
                    rule.action_type = ActionType.DIRECT
                    rule.target_id = None
                    count += 1
        return count

    def has_target_reference(
        self, action_type: ActionType | str, target_id: int | str | None = None
    ) -> list[str]:
        """Returns the names of all rules referencing the given action and target_id."""
        norm_action = (
            action_type.value
            if isinstance(action_type, ActionType)
            else ActionType.from_str(str(action_type)).value
        )
        target_id_int = int(target_id) if isinstance(target_id, int) or (isinstance(target_id, str) and target_id.isdigit()) else target_id
        names: list[str] = []
        for rule in self._profile.rules:
            if rule.action_name == norm_action:
                if target_id is None or rule.target_id == target_id_int:
                    names.append(rule.name)
        return names

    def _index_of(self, name: str) -> int:
        for idx, r in enumerate(self._profile.rules):
            if r.name.lower() == name.strip().lower():
                return idx
        raise RuleNotFoundError(name)
