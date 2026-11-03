"""Process execution and lifecycle management for Proxifier.exe."""

import os
from pathlib import Path
import subprocess
from typing import Any

import psutil  # type: ignore[import-untyped]

from pyproxifier.exceptions import ProxifierNotFoundError


class ProcessController:
    """Controls the Proxifier.exe process, handles silent-loading, discovery, and termination."""

    @staticmethod
    def find_proxifier_binary(custom_path: Path | str | None = None) -> Path:
        """Discovers the Proxifier executable location across custom paths, standard directories, and Windows Registry."""
        if custom_path:
            p = Path(custom_path)
            if p.is_file():
                return p

        candidates: list[Path] = []

        # Standard environment variables
        pf_x86 = os.environ.get("ProgramFiles(x86)")
        if pf_x86:
            candidates.append(Path(pf_x86) / "Proxifier" / "Proxifier.exe")
        pf = os.environ.get("ProgramFiles")
        if pf:
            candidates.append(Path(pf) / "Proxifier" / "Proxifier.exe")

        # Hardcoded standard fallbacks
        candidates.extend(
            [
                Path(r"C:\Program Files (x86)\Proxifier\Proxifier.exe"),
                Path(r"C:\Program Files\Proxifier\Proxifier.exe"),
            ]
        )

        # Windows Registry check
        try:
            import winreg

            for hkey in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for subkey in (
                    r"Software\Initex\Proxifier",
                    r"Software\WOW6432Node\Initex\Proxifier",
                ):
                    try:
                        with winreg.OpenKey(hkey, subkey) as key:
                            install_dir, _ = winreg.QueryValueEx(key, "InstallDir")
                            if install_dir:
                                candidates.insert(0, Path(install_dir) / "Proxifier.exe")
                    except (OSError, FileNotFoundError):
                        pass
        except (ImportError, AttributeError):
            pass

        for cand in candidates:
            if cand.is_file():
                return cand

        # Return first candidate or default
        return candidates[0] if candidates else Path(r"C:\Program Files (x86)\Proxifier\Proxifier.exe")

    @classmethod
    def find_tool_binary(cls, tool_name: str, custom_dir: Path | str | None = None) -> Path | None:
        """Finds helper utilities (ProxyChecker.exe, ServiceManager.exe) in Proxifier installation directory."""
        if custom_dir:
            cand = Path(custom_dir) / tool_name
            if cand.is_file():
                return cand

        prox_exe = cls.find_proxifier_binary()
        if prox_exe.is_file():
            cand = prox_exe.parent / tool_name
            if cand.is_file():
                return cand
        return None

    @classmethod
    def is_running(cls) -> bool:
        """Returns True if a Proxifier process is currently running on the system."""
        for proc in psutil.process_iter(["name"]):
            try:
                name = proc.info.get("name")
                if name and name.lower().startswith("proxifier"):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return False

    @classmethod
    def get_running_processes(cls) -> list[psutil.Process]:
        """Returns list of running Proxifier psutil Process instances."""
        procs: list[psutil.Process] = []
        for proc in psutil.process_iter(["name", "pid"]):
            try:
                name = proc.info.get("name")
                if name and name.lower().startswith("proxifier"):
                    procs.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs

    @classmethod
    def start(
        cls,
        profile_path: Path | str | None = None,
        silent: bool = False,
        executable: Path | str | None = None,
    ) -> subprocess.Popen[Any]:
        """Starts Proxifier with an optional profile.

        If silent=True, appends the 'silent-load' parameter.
        """
        exe = cls.find_proxifier_binary(executable)
        if not exe.is_file():
            raise ProxifierNotFoundError([str(exe)])

        cmd: list[str] = [str(exe)]
        if profile_path:
            cmd.append(str(profile_path))
            if silent:
                cmd.append("silent-load")

        return subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @classmethod
    def silent_load(
        cls,
        profile_path: Path | str,
        executable: Path | str | None = None,
    ) -> bool:
        """Instructs Proxifier to load the profile silently.

        If Proxifier is running, reloads into the active instance without prompting.
        If Proxifier is not running, launches it with this profile.
        Uses non-blocking Popen to prevent GUI handle deadlocks.
        """
        exe = cls.find_proxifier_binary(executable)
        if not exe.is_file():
            raise ProxifierNotFoundError([str(exe)])

        p_path = Path(profile_path)
        if not p_path.is_file():
            raise FileNotFoundError(f"Profile file does not exist: {p_path}")

        proc = subprocess.Popen(
            [str(exe), str(p_path), "silent-load"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            proc.wait(timeout=0.8)
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            # When started as primary GUI process, Proxifier stays alive in background, which is expected
            return True

    @classmethod
    def kill(cls, timeout: float = 3.0) -> int:
        """Gracefully terminates running Proxifier processes, falling back to force kill after timeout."""
        procs = cls.get_running_processes()
        if not procs:
            return 0

        for proc in procs:
            try:
                proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        _, alive = psutil.wait_procs(procs, timeout=timeout)
        for proc in alive:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return len(procs)

    @classmethod
    def convert_and_quit(
        cls,
        source_profile: Path | str,
        executable: Path | str | None = None,
        timeout: float = 5.0,
    ) -> bool:
        """Converts an older format profile (.prx) or existing profile using Proxifier's native converter.

        Invokes: Proxifier.exe <source_profile> convert-and-quit
        """
        exe = cls.find_proxifier_binary(executable)
        if not exe.is_file():
            raise ProxifierNotFoundError([str(exe)])

        p_path = Path(source_profile)
        if not p_path.is_file():
            raise FileNotFoundError(f"Profile file does not exist: {p_path}")

        res = subprocess.run(
            [str(exe), str(p_path), "convert-and-quit"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return res.returncode == 0

    @classmethod
    def register_license(
        cls,
        license_key: str,
        executable: Path | str | None = None,
        timeout: float = 5.0,
    ) -> bool:
        """Registers Proxifier using native command-line license activation.

        Invokes: Proxifier.exe register <license_key>
        """
        exe = cls.find_proxifier_binary(executable)
        if not exe.is_file():
            raise ProxifierNotFoundError([str(exe)])

        clean_key = license_key.strip()
        if not clean_key:
            raise ValueError("License key cannot be empty.")

        res = subprocess.run(
            [str(exe), "register", clean_key],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return res.returncode == 0
