"""Central constants for Proxifier paths, registry keys, and defaults."""

from pathlib import Path

# Windows Registry Keys
REGISTRY_INITEX_KEY = r"Software\Initex"
REGISTRY_PROXIFIER_KEY = r"Software\Initex\Proxifier"
REGISTRY_PROXIFIER_WOW64_KEY = r"Software\WOW6432Node\Initex\Proxifier"
REGISTRY_LICENSE_SUBKEY = r"Software\Initex\Proxifier\License"
REGISTRY_LICENSE_WOW64_SUBKEY = r"Software\WOW6432Node\Initex\Proxifier\License"

# Service & Driver
DRIVER_SERVICE_NAME = "ProxifierDrv"
PROXIFIER_PROCESS_NAME = "Proxifier"

# Profile & Default Files
DEFAULT_PROFILE_NAME = "Default.ppx"
PROXIFIER_V4_DIR_NAME = "Proxifier4"
PROXIFIER_V3_DIR_NAME = "Proxifier"
PROFILES_SUBDIR = "Profiles"

# Fallback Paths
DEFAULT_PROGRAM_FILES_X86 = Path(r"C:\Program Files (x86)\Proxifier\Proxifier.exe")
DEFAULT_PROGRAM_FILES_64 = Path(r"C:\Program Files\Proxifier\Proxifier.exe")

