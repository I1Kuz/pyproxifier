"""Windows Service IPC management for Proxifier (ServiceManager.exe & SCM)."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
import os
from pathlib import Path
import shutil
import subprocess

from pyproxifier.exceptions import ProcessError
from pyproxifier.ipc.win32 import is_invalid_handle
from pyproxifier.models.profile import ProxifierProfile
from pyproxifier.parser import ProfileParser
from pyproxifier.process import ProcessController
from pyproxifier.validator import Validator

logger = logging.getLogger(__name__)

SERVICE_NAME = "Proxifier"
SERVICE_MUTEX_NAME = r"Global\ProxifierServiceRunning"
SYNCHRONIZE = 0x00100000

# Windows SCM Access Rights
SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020

SERVICE_RUNNING = 0x00000004
SERVICE_STOPPED = 0x00000001


class ServiceIPC:
    """Manages Proxifier Windows Service lifecycle, silent automation, and ServiceProfile configuration."""

    @classmethod
    def find_service_manager_binary(cls, custom_path: Path | str | None = None) -> Path | None:
        """Locates the ServiceManager.exe binary."""
        if custom_path:
            p = Path(custom_path)
            if p.is_file():
                return p
        return ProcessController.find_tool_binary("ServiceManager.exe")

    @classmethod
    def is_service_running(cls) -> bool:
        """Determines if the Proxifier Windows Service is actively running.

        Checks the Global\\ProxifierServiceRunning kernel mutex first,
        then queries Windows Service Control Manager.
        """
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenMutexW(SYNCHRONIZE, False, SERVICE_MUTEX_NAME)
        if handle:
            kernel32.CloseHandle(handle)
            return True

        advapi32 = ctypes.windll.advapi32
        scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if is_invalid_handle(scm):
            return False

        try:
            service = advapi32.OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS)
            if is_invalid_handle(service):
                return False

            try:
                class SERVICE_STATUS_PROCESS(ctypes.Structure):
                    _fields_ = [
                        ("dwServiceType", wintypes.DWORD),
                        ("dwCurrentState", wintypes.DWORD),
                        ("dwControlsAccepted", wintypes.DWORD),
                        ("dwWin32ExitCode", wintypes.DWORD),
                        ("dwServiceSpecificExitCode", wintypes.DWORD),
                        ("dwCheckPoint", wintypes.DWORD),
                        ("dwWaitHint", wintypes.DWORD),
                        ("dwProcessId", wintypes.DWORD),
                        ("dwServiceFlags", wintypes.DWORD),
                    ]

                status = SERVICE_STATUS_PROCESS()
                bytes_needed = wintypes.DWORD()
                ok = advapi32.QueryServiceStatusEx(
                    service,
                    0,  # SC_STATUS_PROCESS_INFO
                    ctypes.byref(status),
                    ctypes.sizeof(status),
                    ctypes.byref(bytes_needed),
                )
                if ok:
                    return status.dwCurrentState == SERVICE_RUNNING
                return False
            finally:
                advapi32.CloseServiceHandle(service)
        finally:
            advapi32.CloseServiceHandle(scm)

    @classmethod
    def is_service_installed(cls) -> bool:
        """Checks if the Proxifier Windows Service is installed in Windows SCM."""
        advapi32 = ctypes.windll.advapi32
        scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if is_invalid_handle(scm):
            return False
        try:
            service = advapi32.OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS)
            if is_invalid_handle(service):
                return False
            try:
                return True
            finally:
                advapi32.CloseServiceHandle(service)
        finally:
            advapi32.CloseServiceHandle(scm)

    @classmethod
    def _run_service_manager_command(
        cls, command: str, custom_binary: Path | str | None = None
    ) -> bool:
        """Executes a ServiceManager command."""
        exe = cls.find_service_manager_binary(custom_binary)
        if not exe or not exe.is_file():
            raise ProcessError(f"ServiceManager.exe not found at '{exe}'")

        try:
            res = subprocess.run(
                [str(exe), command],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10.0,
                check=False,
            )
            return res.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    @classmethod
    def install(cls, silent: bool = True, custom_binary: Path | str | None = None) -> bool:
        """Installs the Proxifier Windows Service (requires Administrator privileges)."""
        cmd = "silent-install" if silent else "install"
        return cls._run_service_manager_command(cmd, custom_binary=custom_binary)

    @classmethod
    def uninstall(cls, silent: bool = True, custom_binary: Path | str | None = None) -> bool:
        """Uninstalls the Proxifier Windows Service (requires Administrator privileges)."""
        cmd = "silent-uninstall" if silent else "uninstall"
        return cls._run_service_manager_command(cmd, custom_binary=custom_binary)

    @classmethod
    def start(cls, silent: bool = True, custom_binary: Path | str | None = None) -> bool:
        """Starts the Proxifier Windows Service."""
        cmd = "silent-start" if silent else "start"
        return cls._run_service_manager_command(cmd, custom_binary=custom_binary)

    @classmethod
    def stop(cls, silent: bool = True, custom_binary: Path | str | None = None) -> bool:
        """Stops the Proxifier Windows Service."""
        cmd = "silent-stop" if silent else "stop"
        return cls._run_service_manager_command(cmd, custom_binary=custom_binary)

    @classmethod
    def resolve_service_profile_path(cls) -> Path:
        """Resolves target path for the service profile (ServiceProfile.ppx)."""
        p_data = os.environ.get("ProgramData", r"C:\ProgramData")
        primary = Path(p_data) / "Proxifier4" / "Profiles" / "ServiceProfile.ppx"
        if primary.parent.is_dir() or primary.is_file():
            return primary
        fallback = Path(p_data) / "Proxifier" / "Profiles" / "ServiceProfile.ppx"
        return primary if not fallback.parent.is_dir() else fallback

    @classmethod
    def deploy_service_profile(
        cls,
        profile_or_path: ProxifierProfile | Path | str,
        custom_destination: Path | str | None = None,
    ) -> Path:
        """Deploys a profile as ServiceProfile.ppx for the Proxifier Windows Service."""
        dest = Path(custom_destination) if custom_destination else cls.resolve_service_profile_path()
        dest.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(profile_or_path, ProxifierProfile):
            Validator.validate_profile(profile_or_path)
            xml_str = ProfileParser.to_xml(profile_or_path)
            dest.write_text(xml_str, encoding="utf-8")
        else:
            src = Path(profile_or_path)
            if not src.is_file():
                raise FileNotFoundError(f"Source profile not found: {src}")
            if src.resolve() != dest.resolve():
                shutil.copyfile(src, dest)

        return dest

