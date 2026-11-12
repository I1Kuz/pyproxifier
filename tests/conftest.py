"""Pytest fixtures and cross-platform compatibility configuration."""

import ctypes
from unittest.mock import MagicMock

# On non-Windows operating systems (e.g. Linux CI containers),
# ctypes does not expose 'windll'. We provide a mock so tests that patch
# Windows API functions (kernel32, advapi32, user32) execute smoothly without AttributeError.
if not hasattr(ctypes, "windll"):
    mock_windll = MagicMock()
    mock_windll.kernel32 = MagicMock()
    mock_windll.advapi32 = MagicMock()
    mock_windll.user32 = MagicMock()
    ctypes.windll = mock_windll  # pyright: ignore[reportAttributeAccessIssue]
