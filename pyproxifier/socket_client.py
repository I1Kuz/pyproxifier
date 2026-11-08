"""Backward-compatibility module re-exporting ControlSocketClient from pyproxifier.ipc."""

from pyproxifier.ipc.socket import ControlSocketClient

__all__ = ["ControlSocketClient"]
