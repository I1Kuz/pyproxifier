"""Manager for Proxifier profile configuration files (.ppx).

Handles file loading, saving, discovery of profile directories,
global Default.ppx management, and template generation.
"""

from __future__ import annotations

import os
from pathlib import Path

from pyproxifier.constants import (
    DEFAULT_PROFILE_NAME,
    PROFILES_SUBDIR,
    PROXIFIER_V3_DIR_NAME,
    PROXIFIER_V4_DIR_NAME,
)
from pyproxifier.exceptions import ProfileNotFoundError
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.parser import ProfileParser
from pyproxifier.validator import Validator


class ConfigManager:
    """Manages profile file operations, directories, and profiles discovery."""

    @classmethod
    def get_user_profiles_dir(cls, v3: bool = False) -> Path:
        """Returns the user profiles directory (%APPDATA%\\Proxifier4\\Profiles)."""
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        sub = PROXIFIER_V3_DIR_NAME if v3 else PROXIFIER_V4_DIR_NAME
        dir_path = base / sub / PROFILES_SUBDIR
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path

    @classmethod
    def get_global_profile_path(cls) -> Path:
        """Returns the system-wide global profile path (%ProgramData%\\Proxifier\\Default.ppx)."""
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        target_dir = Path(program_data) / PROXIFIER_V3_DIR_NAME
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir / DEFAULT_PROFILE_NAME

    @classmethod
    def resolve_profile_path(cls, path: Path | str | None = None) -> Path:
        """Resolves a profile path from a path string, bare profile name, or None (defaults to Default.ppx)."""
        if not path:
            return cls.get_user_profiles_dir() / DEFAULT_PROFILE_NAME

        p = Path(path)
        # Direct existing file
        if p.is_file():
            return p.resolve()

        # Check in user profiles directory
        candidate_name = p.name if p.suffix.lower() == ".ppx" else f"{p.name}.ppx"
        user_candidate = cls.get_user_profiles_dir() / candidate_name
        if user_candidate.is_file():
            return user_candidate.resolve()

        # If user passed a bare name without folder paths, place it in user profiles dir
        if len(p.parts) == 1 and not p.is_absolute():
            return user_candidate.resolve()

        # Otherwise treat as path relative to current working directory
        if not p.suffix:
            p = p.with_suffix(".ppx")
        return p.resolve()

    @classmethod
    def list_user_profiles(cls, v3: bool = False) -> list[Path]:
        """Lists all profile files (.ppx and .prx) available in the user's profile directory."""
        profiles_dir = cls.get_user_profiles_dir(v3=v3)
        if not profiles_dir.exists():
            return []
        patterns = ["*.ppx", "*.prx"] if v3 else ["*.ppx"]
        found: list[Path] = []
        for pat in patterns:
            found.extend(profiles_dir.glob(pat))
        return sorted(found)

    @classmethod
    def load(cls, path: Path | str, validate: bool = True) -> ProxifierProfile:
        """Loads a profile from a .ppx file.

        Args:
            path: File path or profile name.
            validate: Whether to run configuration validation on the loaded profile.
        """
        p = cls.resolve_profile_path(path)
        if not p.is_file():
            raise ProfileNotFoundError(str(p))

        profile = ProfileParser.from_xml(p)
        if validate:
            Validator.validate_profile(profile)
        return profile

    @classmethod
    def save(
        cls,
        path: Path | str,
        profile: ProxifierProfile,
        validate: bool = True,
    ) -> Path:
        """Saves a profile to a .ppx file.

        Args:
            path: Destination file path.
            profile: ProxifierProfile instance to save.
            validate: Whether to validate the profile before saving.
        """
        if validate:
            Validator.validate_profile(profile)

        dest = Path(path)
        if not dest.suffix:
            dest = dest.with_suffix(".ppx")
        dest.parent.mkdir(parents=True, exist_ok=True)

        xml_content = ProfileParser.to_xml(profile)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(xml_content)

        return dest

    @classmethod
    def new_default(cls) -> ProxifierProfile:
        """Creates a clean default profile matching standard Proxifier setup."""
        return ProxifierProfile.create_default()

    @classmethod
    def new_direct(cls) -> ProxifierProfile:
        """Creates a direct profile routing all connections directly."""
        return ProxifierProfile.create_direct()

    @classmethod
    def new_lockdown(cls, allowed_targets: str | None = None) -> ProxifierProfile:
        """Creates a secure lockdown profile blocking all external traffic by default."""
        return ProxifierProfile.create_lockdown(allowed_targets=allowed_targets)
