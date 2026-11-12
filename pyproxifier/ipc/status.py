"""Status and result models for IPC profile application."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ApplyStatus(str, Enum):
    """Specific mechanism and confirmation state of profile application."""

    SOCKET_CONFIRMED = "socket_confirmed"    # Profile applied and confirmed by Control Socket (ACK received)
    PIPE_DISPATCHED = "pipe_dispatched"      # Profile bytes written to Named Pipe
    PROCESS_SPAWNED = "process_spawned"      # Proxifier process launched with profile and running as GUI
    COMMAND_DELIVERED = "command_delivered"  # Silent-load command delivered to running instance (exit code 0)
    FAILED = "failed"


@dataclass
class ApplyResult:
    """Result of applying a configuration profile via IPC or process execution.

    Implements __bool__ to allow seamless usage in conditional checks:
        if client.apply():
            ...
    while providing exact delivery mechanism details.
    """

    applied: bool
    status: ApplyStatus
    message: str = ""

    def __bool__(self) -> bool:
        return self.applied

