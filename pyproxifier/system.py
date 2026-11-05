"""System automation and multi-machine deployment for Proxifier.

Provides silent license registration via Windows Registry,
WFP network driver (ProxifierDrv) management, and global profile deployment.
"""

import os
from pathlib import Path
import shutil
import subprocess

from pyproxifier.exceptions import DriverError, RegistryAccessError
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.parser import ProfileParser
from pyproxifier.validator import Validator


class SystemManager:
    """Automates multi-machine configuration, license deployment, driver status, and global settings."""

    # -----------------------------------------------------------------------
    # License Deployment via Registry
    # -----------------------------------------------------------------------

    @staticmethod
    def install_license(
        key: str,
        owner: str,
        system_wide: bool = False,
    ) -> bool:
        """Installs Proxifier license key into Windows Registry.

        Args:
            key: Proxifier registration key string.
            owner: Registered user or organization name.
            system_wide: If True, writes to HKEY_LOCAL_MACHINE (requires Admin privileges).
                         If False, writes to HKEY_CURRENT_USER.
        """
        try:
            import winreg

            hive = winreg.HKEY_LOCAL_MACHINE if system_wide else winreg.HKEY_CURRENT_USER
            subkey = r"Software\Initex\Proxifier\License"

            with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                winreg.SetValueEx(reg_key, "Key", 0, winreg.REG_SZ, key.strip())
                winreg.SetValueEx(reg_key, "Owner", 0, winreg.REG_SZ, owner.strip())

            # On 64-bit Windows, write to WOW6432Node if system_wide
            if system_wide:
                try:
                    wow_key = r"Software\WOW6432Node\Initex\Proxifier\License"
                    with winreg.CreateKeyEx(hive, wow_key, 0, winreg.KEY_SET_VALUE) as reg_key:
                        winreg.SetValueEx(reg_key, "Key", 0, winreg.REG_SZ, key.strip())
                        winreg.SetValueEx(reg_key, "Owner", 0, winreg.REG_SZ, owner.strip())
                except OSError:
                    pass

            return True
        except PermissionError as e:
            raise RegistryAccessError(
                f"Permission denied while writing Proxifier license to Registry: {e}. "
                "Administrator privileges may be required for system-wide registration."
            ) from e
        except Exception as e:
            raise RegistryAccessError(f"Failed to install license to Registry: {e}") from e

    @staticmethod
    def get_installed_license(system_wide: bool = False) -> tuple[str, str] | None:
        """Reads installed Proxifier license from the Windows Registry."""
        try:
            import winreg

            hive = winreg.HKEY_LOCAL_MACHINE if system_wide else winreg.HKEY_CURRENT_USER
            subkey = r"Software\Initex\Proxifier\License"

            with winreg.OpenKey(hive, subkey) as reg_key:
                key, _ = winreg.QueryValueEx(reg_key, "Key")
                owner, _ = winreg.QueryValueEx(reg_key, "Owner")
                return str(key), str(owner)
        except (OSError, FileNotFoundError):
            return None

    # -----------------------------------------------------------------------
    # WFP Network Driver Management (ProxifierDrv)
    # -----------------------------------------------------------------------

    @staticmethod
    def is_driver_running() -> bool:
        """Checks if the Proxifier WFP callout driver (ProxifierDrv) service is running."""
        try:
            proc = subprocess.run(
                ["sc.exe", "query", "ProxifierDrv"],
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            return "RUNNING" in proc.stdout
        except Exception:
            return False

    @classmethod
    def start_driver(cls) -> bool:
        """Starts the ProxifierDrv kernel driver service (requires Administrator rights)."""
        try:
            if cls.is_driver_running():
                return True
            proc = subprocess.run(
                ["net", "start", "ProxifierDrv"],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            out_lower = proc.stdout.lower()
            return proc.returncode == 0 or "already been started" in out_lower or "уже запущена" in out_lower
        except Exception as e:
            raise DriverError(f"Failed to start ProxifierDrv service: {e}") from e

    @classmethod
    def stop_driver(cls) -> bool:
        """Stops the ProxifierDrv kernel driver service (requires Administrator rights)."""
        try:
            if not cls.is_driver_running():
                return True
            proc = subprocess.run(
                ["net", "stop", "ProxifierDrv"],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            return proc.returncode == 0
        except Exception as e:
            raise DriverError(f"Failed to stop ProxifierDrv service: {e}") from e

    # -----------------------------------------------------------------------
    # Global Deployment
    # -----------------------------------------------------------------------

    @staticmethod
    def deploy_global_profile(
        profile_or_path: ProxifierProfile | Path | str,
        custom_destination: Path | str | None = None,
    ) -> Path:
        """Deploys a profile as Default.ppx for all users on the computer (%ProgramData%\\Proxifier\\Default.ppx)."""
        if custom_destination:
            dest = Path(custom_destination)
        else:
            p_data = os.environ.get("ProgramData", r"C:\ProgramData")
            dest = Path(p_data) / "Proxifier" / "Default.ppx"

        dest.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(profile_or_path, ProxifierProfile):
            Validator.validate_profile(profile_or_path)
            xml_content = ProfileParser.to_xml(profile_or_path)
            dest.write_text(xml_content, encoding="utf-8")
            return dest
        else:
            src = Path(profile_or_path)
            if not src.is_file():
                raise FileNotFoundError(f"Source profile not found: {src}")
            shutil.copyfile(src, dest)
            return dest

    @staticmethod
    def build_silent_install_args(
        installer_path: Path | str,
        install_dir: Path | str | None = None,
    ) -> list[str]:
        """Builds command-line arguments for unattended ProxifierSetup.exe installation."""
        args = [
            str(installer_path),
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/SP-",
        ]
        if install_dir:
            args.append(f'/DIR="{install_dir}"')
        return args
