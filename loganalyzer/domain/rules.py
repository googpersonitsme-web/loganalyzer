import re
from collections.abc import Callable
from enum import StrEnum


class RuleType(StrEnum):
    PATH_REGEX = "path_regex"      # шлях збігається з виразом
    STATUS_BURST = "status_burst"  # багато відповідей із певним статусом
    USER_AGENT = "user_agent"      # User-Agent містить текст


class IncidentStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


# Дозволені переходи. Із closed вийти не можна.
_ALLOWED: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.OPEN: {IncidentStatus.ACKNOWLEDGED, IncidentStatus.CLOSED},
    IncidentStatus.ACKNOWLEDGED: {IncidentStatus.CLOSED},
    IncidentStatus.CLOSED: set(),
}


class InvalidTransition(Exception):
    """Такий перехід статусу заборонений."""


def check_transition(current: IncidentStatus, target: IncidentStatus) -> None:
    if target not in _ALLOWED[current]:
        raise InvalidTransition(
            f"Перехід {current.value} -> {target.value} заборонений"
        )


def build_params(
    rule_type: RuleType,
    *,
    pattern: str | None = None,
    statuses: list[int] | None = None,
    contains: str | None = None,
    min_hits: int = 1,
) -> dict:
    """Перевіряє параметри правила і повертає їх у вигляді словника."""
    if min_hits < 1:
        raise ValueError("--min-hits має бути не менше 1")

    if rule_type is RuleType.PATH_REGEX:
        if not pattern:
            raise ValueError("Для цього типу потрібен параметр --pattern")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Некоректний регулярний вираз: {exc}") from exc
        return {"pattern": pattern, "min_hits": min_hits}

    if rule_type is RuleType.STATUS_BURST:
        if not statuses:
            raise ValueError("Для цього типу потрібен параметр --statuses")
        if any(not 100 <= s <= 599 for s in statuses):
            raise ValueError("HTTP-статус має бути від 100 до 599")
        return {"statuses": sorted(set(statuses)), "min_hits": min_hits}

    if rule_type is RuleType.USER_AGENT:
        if not contains:
            raise ValueError("Для цього типу потрібен параметр --contains")
        return {"contains": contains, "min_hits": min_hits}

    raise ValueError("Невідомий тип правила")


def make_matcher(
    rule_type: RuleType, params: dict
) -> Callable[[str, int, str], bool]:
    """Повертає функцію (path, status, user_agent) -> збіг чи ні."""
    if rule_type is RuleType.PATH_REGEX:
        regex = re.compile(params["pattern"], re.IGNORECASE)
        return lambda path, status, ua: regex.search(path) is not None

    if rule_type is RuleType.STATUS_BURST:
        statuses = set(params["statuses"])
        return lambda path, status, ua: status in statuses

    if rule_type is RuleType.USER_AGENT:
        needle = params["contains"].lower()
        return lambda path, status, ua: needle in ua.lower()

    raise ValueError("Невідомий тип правила")