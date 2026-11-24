from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from loganalyzer.domain.rules import IncidentStatus, check_transition
from loganalyzer.storage.tables import (
    DetectionRuleRow,
    IncidentEntryRow,
    IncidentRow,
    LogEntryRow,
)


class IncidentNotFound(Exception):
    """Інциденту з таким номером нема."""


def change_status(
    session: Session,
    incident_id: int,
    target: IncidentStatus,
    note: str | None = None,
) -> IncidentRow:
    """Змінює статус. Рядок блокується (FOR UPDATE), тому два аналітики
    одночасно не зможуть закрити один інцидент: другий отримає помилку."""
    try:
        row = session.scalar(
            select(IncidentRow).where(IncidentRow.id == incident_id).with_for_update()
        )
        if row is None:
            raise IncidentNotFound(f"Інцидент №{incident_id} не знайдено")

        check_transition(IncidentStatus(row.status), target)

        row.status = target.value
        row.version += 1
        if note:
            row.note = note
        if target is IncidentStatus.CLOSED:
            row.closed_at = datetime.now(UTC).replace(tzinfo=None)
        session.commit()
        return row
    except Exception:
        session.rollback()
        raise


def list_incidents(
    session: Session, status: IncidentStatus | None = None, limit: int = 100
) -> list[tuple[IncidentRow, str]]:
    stmt = (
        select(IncidentRow, DetectionRuleRow.name)
        .join(DetectionRuleRow, DetectionRuleRow.id == IncidentRow.rule_id)
        .order_by(IncidentRow.id)
        .limit(limit)
    )
    if status is not None:
        stmt = stmt.where(IncidentRow.status == status.value)
    return [(inc, name) for inc, name in session.execute(stmt)]


def get_incident(
    session: Session, incident_id: int, sample: int = 5
) -> tuple[IncidentRow, str, list[LogEntryRow]]:
    found = session.execute(
        select(IncidentRow, DetectionRuleRow.name)
        .join(DetectionRuleRow, DetectionRuleRow.id == IncidentRow.rule_id)
        .where(IncidentRow.id == incident_id)
    ).first()
    if found is None:
        raise IncidentNotFound(f"Інцидент №{incident_id} не знайдено")
    incident, rule_name = found
    entries = list(
        session.scalars(
            select(LogEntryRow)
            .join(IncidentEntryRow, IncidentEntryRow.entry_id == LogEntryRow.id)
            .where(IncidentEntryRow.incident_id == incident_id)
            .order_by(LogEntryRow.timestamp)
            .limit(sample)
        )
    )
    return incident, rule_name, entries