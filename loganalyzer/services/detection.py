from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import ColumnElement, and_, func, insert, literal, literal_column, select
from sqlalchemy.dialects.mysql import insert as mysql_insert
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
    """Повільна версія: рахує у Python. Лишається як еталон для порівняння."""
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
            existing += 1

    session.commit()
    return DetectionResult(rule.name, matched, created, existing)


def _sql_condition(rule_type: RuleType, params: dict) -> ColumnElement[bool]:
    """Умова збігу, записана мовою SQL."""
    if rule_type is RuleType.PATH_REGEX:
        return LogEntryRow.path.regexp_match(params["pattern"], flags="i")
    if rule_type is RuleType.STATUS_BURST:
        return LogEntryRow.status.in_(params["statuses"])
    if rule_type is RuleType.USER_AGENT:
        needle = params["contains"].lower()
        return func.lower(LogEntryRow.user_agent).contains(needle, autoescape=True)
    raise ValueError("Невідомий тип правила")


def run_rule_sql(session: Session, rule: DetectionRuleRow, source_id: int) -> DetectionResult:
    """Швидка версія: групування і підрахунок робить база даних."""
    rule_type = RuleType(rule.rule_type)
    min_hits: int = rule.params["min_hits"]
    window: int = rule.window_minutes * 60  # ціле число, безпечно вставляти в запит
    base = and_(LogEntryRow.source_id == source_id, _sql_condition(rule_type, rule.params))

    # Початок вікна часу (в секундах) для кожного запису. Час у базі в UTC.
    bucket: ColumnElement[int] = literal_column(
        "FLOOR(TIMESTAMPDIFF(SECOND, '1970-01-01', log_entries.timestamp)"
        f" / {window}) * {window}"
    )

    matched = session.scalar(select(func.count()).select_from(LogEntryRow).where(base)) or 0

    groups = session.execute(
        select(LogEntryRow.ip, bucket, func.count())
        .where(base)
        .group_by(LogEntryRow.ip, bucket)
        .having(func.count() >= min_hits)
    ).all()

    conn = session.connection()
    created = 0
    existing = 0
    for ip, start, count in groups:
        window_start = datetime.fromtimestamp(int(start), tz=UTC).replace(tzinfo=None)
        window_end = window_start + timedelta(seconds=window)

        # INSERT IGNORE: якщо такий інцидент уже є, база його просто пропустить
        result = conn.execute(
            mysql_insert(IncidentRow)
            .prefix_with("IGNORE")
            .values(
                rule_id=rule.id,
                source_id=source_id,
                ip=ip,
                window_start=window_start,
                entries_count=int(count),
            )
        )
        if result.rowcount == 0:
            existing += 1
            continue
        created += 1

        # Прив'язуємо записи до інциденту одним запитом INSERT ... SELECT
        conn.execute(
            mysql_insert(IncidentEntryRow).from_select(
                ["incident_id", "entry_id"],
                select(literal(result.lastrowid), LogEntryRow.id).where(
                    base,
                    LogEntryRow.ip == ip,
                    LogEntryRow.timestamp >= window_start,
                    LogEntryRow.timestamp < window_end,
                ),
            )
        )

    session.commit()
    return DetectionResult(rule.name, int(matched), created, existing)


def run_all(session: Session, source_id: int) -> list[DetectionResult]:
    rules = session.scalars(
        select(DetectionRuleRow).where(DetectionRuleRow.enabled.is_(True))
    ).all()
    return [run_rule_sql(session, rule, source_id) for rule in rules]