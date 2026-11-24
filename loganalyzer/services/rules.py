from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from loganalyzer.domain.rules import RuleType
from loganalyzer.storage.tables import DetectionRuleRow


class RuleExists(Exception):
    """Правило з такою назвою вже є."""


def create_rule(
    session: Session,
    name: str,
    rule_type: RuleType,
    params: dict,
    window_minutes: int,
) -> DetectionRuleRow:
    name = name.strip()
    if not name:
        raise ValueError("Назва правила не може бути порожньою")
    if not 1 <= window_minutes <= 1440:
        raise ValueError("Вікно має бути від 1 до 1440 хвилин")

    row = DetectionRuleRow(
        name=name,
        rule_type=rule_type.value,
        params=params,
        window_minutes=window_minutes,
    )
    session.add(row)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise RuleExists(f"Правило «{name}» уже існує") from None
    return row


def list_rules(session: Session) -> list[DetectionRuleRow]:
    return list(session.scalars(select(DetectionRuleRow).order_by(DetectionRuleRow.id)))