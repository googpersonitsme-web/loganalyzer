from sqlalchemy import select

from loganalyzer.services.detection import run_rule, run_rule_sql
from loganalyzer.storage.tables import IncidentRow


def test_sql_detection_creates_same_incidents(session, imported, rule):
    fast = run_rule_sql(session, rule, imported)
    assert fast.matched_entries == 3
    assert fast.incidents_created == 2
    first = session.scalars(select(IncidentRow).order_by(IncidentRow.id)).first()
    assert first.entries_count == 2

    # Повільна версія після швидкої не знаходить нічого нового: результати збігаються
    slow = run_rule(session, rule, imported)
    assert slow.incidents_created == 0
    assert slow.incidents_existing == 2


def test_sql_detection_is_idempotent(session, imported, rule):
    run_rule_sql(session, rule, imported)
    again = run_rule_sql(session, rule, imported)
    assert again.incidents_created == 0
    assert again.incidents_existing == 2