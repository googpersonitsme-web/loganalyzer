from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class LogSourceRow(Base):
    """Джерело логів: один сайт."""

    __tablename__ = "log_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class LogEntryRow(Base):
    """Один розібраний рядок логу. Час зберігаємо в UTC."""

    __tablename__ = "log_entries"
    __table_args__ = (
        UniqueConstraint("source_id", "line_hash", name="uq_entry_source_hash"),
        Index("ix_entries_timestamp", "timestamp"),
        Index("ix_entries_ip", "ip"),
        Index("ix_entries_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("log_sources.id"))
    ip: Mapped[str] = mapped_column(String(45))
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    method: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(String(2048))
    protocol: Mapped[str] = mapped_column(String(16))
    status: Mapped[int] = mapped_column(SmallInteger)
    bytes_sent: Mapped[int] = mapped_column(BigInteger)
    referer: Mapped[str] = mapped_column(String(2048))
    user_agent: Mapped[str] = mapped_column(String(1024))
    line_hash: Mapped[str] = mapped_column(String(64))


class DetectionRuleRow(Base):
    """Правило виявлення."""

    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    rule_type: Mapped[str] = mapped_column(String(32))
    params: Mapped[dict] = mapped_column(JSON)
    window_minutes: Mapped[int] = mapped_column()
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class IncidentRow(Base):
    """Інцидент: правило спрацювало для одного IP в одному вікні часу."""

    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint(
            "rule_id", "source_id", "ip", "window_start", name="uq_incident_key"
        ),
        Index("ix_incidents_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("detection_rules.id"))
    source_id: Mapped[int] = mapped_column(ForeignKey("log_sources.id"))
    ip: Mapped[str] = mapped_column(String(45))
    window_start: Mapped[datetime] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(16), default="open")
    version: Mapped[int] = mapped_column(default=1)
    entries_count: Mapped[int] = mapped_column()
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IncidentEntryRow(Base):
    """Зв'язок багато-до-багатьох: які записи логу належать інциденту."""

    __tablename__ = "incident_entries"

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"), primary_key=True, autoincrement=False
    )
    entry_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("log_entries.id"), primary_key=True, autoincrement=False
    )


class UserRow(Base):
    """Користувач системи."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())