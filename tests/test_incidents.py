from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import func, select

from loganalyzer.domain.rules import IncidentStatus, InvalidTransition
from loganalyzer.services.detection import run_rule
from loganalyzer.services.incidents import change_status
from loganalyzer.storage.db import SessionLocal
from loganalyzer.storage.tables import IncidentEntryRow, IncidentRow


def test_detection_creates_incidents_with_entries(session, imported, rule):
    result = run_rule(session, rule, imported)
    assert result.incidents_created == 2   # IP 1.1.1.1 і 2.2.2.2
    first = session.scalars(select(IncidentRow).order_by(IncidentRow.id)).first()
    assert first.entries_count == 2        # два запити /.git/HEAD
    links = session.scalar(
        select(func.count()).select_from(IncidentEntryRow)
        .where(IncidentEntryRow.incident_id == first.id)
    )
    assert links == 2                      # зв'язок «багато-до-багатьох»


def test_repeated_detection_creates_no_duplicates(session, imported, rule):
    run_rule(session, rule, imported)
    again = run_rule(session, rule, imported)
    assert again.incidents_created == 0
    assert again.incidents_existing == 2


def test_double_close_is_forbidden(session, open_incident):
    change_status(session, open_incident, IncidentStatus.CLOSED)
    with pytest.raises(InvalidTransition):
        change_status(session, open_incident, IncidentStatus.CLOSED)


def test_closed_incident_cannot_be_acknowledged(session, open_incident):
    change_status(session, open_incident, IncidentStatus.CLOSED)
    with pytest.raises(InvalidTransition):
        change_status(session, open_incident, IncidentStatus.ACKNOWLEDGED)


def test_closed_stays_closed_after_new_detection(session, imported, rule, open_incident):
    change_status(session, open_incident, IncidentStatus.CLOSED, "перевірено")
    run_rule(session, rule, imported)
    session.expire_all()
    row = session.get(IncidentRow, open_incident)
    assert row.status == "closed"
    assert row.note == "перевірено"
    assert row.closed_at is not None


def test_concurrent_close_only_one_wins(open_incident):
    """8 потоків одночасно закривають один інцидент: успіх лише в одного."""

    def attempt(_):
        with SessionLocal() as s:
            try:
                change_status(s, open_incident, IncidentStatus.CLOSED)
                return "ok"
            except InvalidTransition:
                return "rejected"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))

    assert results.count("ok") == 1
    assert results.count("rejected") == 7
    with SessionLocal() as s:
        row = s.get(IncidentRow, open_incident)
        assert row.status == "closed"
        assert row.version == 2  # змінився рівно один раз