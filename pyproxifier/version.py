"""Version metadata and installed Proxifier version detection."""

from pathlib import Path
from pyproxifier.process import ProcessController

__version__ = "1.0.0"


def get_installed_proxifier_version() -> int | None:
    """Attempts to determine the installed Proxifier major version (4 or 3)."""
    exe = ProcessController.find_proxifier_binary()
    if not exe.is_file():
        return None

    # Check parent folder / AppData indicators
    user_appdata = Path.home() / "AppData" / "Roaming"
    if (user_appdata / "Proxifier4").exists():
        return 4
    if (user_appdata / "Proxifier").exists():
        return 3

    # Check executable directory or registry
    try:
        import winreg

        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, r"Software\Initex\Proxifier") as _key:
                    _ = _key
                    # In v4, driver is ProxifierDrv
                    return 4
            except OSError:
                pass
    except Exception:
        pass

    return 4  # Default to v4
