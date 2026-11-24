from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LogEntry:
    """Один розібраний рядок access.log."""

    ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    bytes_sent: int
    referer: str
    user_agent: str
    line_hash: str

    def __post_init__(self) -> None:
        if not 100 <= self.status <= 599:
            raise ValueError(f"Некоректний HTTP-статус: {self.status}")
        if self.bytes_sent < 0:
            raise ValueError("Розмір відповіді не може бути від'ємним")