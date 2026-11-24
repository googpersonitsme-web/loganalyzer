from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from loganalyzer.domain.rules import RuleType, make_matcher
from loganalyzer.storage.tables import (
    DetectionRuleRow,
    IncidentEntryRow,
    IncidentRow,
    LogEntryRow,
)


@dataclass
class DetectionResult:
    rule_name: str
    matched_entries: int
    incidents_created: int
    incidents_existing: int


def run_rule(session: Session, rule: DetectionRuleRow, source_id: int) -> DetectionResult:
    matcher = make_matcher(RuleType(rule.rule_type), rule.params)
    min_hits: int = rule.params["min_hits"]
    window = rule.window_minutes * 60

    stmt = select(
        LogEntryRow.id,
        LogEntryRow.ip,
        LogEntryRow.timestamp,
        LogEntryRow.path,
        LogEntryRow.status,
        LogEntryRow.user_agent,
    ).where(LogEntryRow.source_id == source_id)

    # Групуємо збіги за (IP, початок вікна часу)
    groups: dict[tuple[str, int], list[int]] = defaultdict(list)
    matched = 0
    for row in session.execute(stmt):
        if not matcher(row.path, row.status, row.user_agent):
            continue
        matched += 1
        seconds = int(row.timestamp.replace(tzinfo=UTC).timestamp())
        groups[(row.ip, seconds // window * window)].append(row.id)

    created = 0
    existing = 0
    for (ip, start), entry_ids in groups.items():
        if len(entry_ids) < min_hits:
            continue
        window_start = datetime.fromtimestamp(start, tz=UTC).replace(tzinfo=None)
        try:
            # Savepoint: якщо такий інцидент уже є, відкочується лише він
            with session.begin_nested():
                incident = IncidentRow(
                    rule_id=rule.id,
                    source_id=source_id,
                    ip=ip,
                    window_start=window_start,
                    entries_count=len(entry_ids),
                )
                session.add(incident)
                session.flush()
                session.execute(
                    insert(IncidentEntryRow),
                    [{"incident_id": incident.id, "entry_id": i} for i in entry_ids],
                )
            created += 1
        except IntegrityError:
            existing += 1  # унікальний ключ не дав створити дубль

    session.commit()
    return DetectionResult(rule.name, matched, created, existing)


def run_all(session: Session, source_id: int) -> list[DetectionResult]:
    rules = session.scalars(
        select(DetectionRuleRow).where(DetectionRuleRow.enabled.is_(True))
    ).all()
    return [run_rule(session, rule, source_id) for rule in rules]