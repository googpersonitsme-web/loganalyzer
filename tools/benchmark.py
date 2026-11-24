"""Вимірювання продуктивності. Запуск: python -m tools.benchmark logs/big.log"""

import os
import sys
import time

# Працюємо лише з окремою базою для вимірювань
os.environ["DATABASE_URL"] = (
    "mysql+pymysql://loguser:logpass@127.0.0.1:3306/loganalyzer_perf?charset=utf8mb4"
)

from sqlalchemy import delete, func, select

from loganalyzer.cli import SEED_RULES
from loganalyzer.domain.rules import build_params
from loganalyzer.services.detection import run_rule, run_rule_sql
from loganalyzer.services.rules import create_rule, list_rules
from loganalyzer.storage.db import SessionLocal, engine
from loganalyzer.storage.importer import get_or_create_source, import_file
from loganalyzer.storage.tables import (
    Base,
    IncidentEntryRow,
    IncidentRow,
    LogEntryRow,
)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/big.log"
    assert engine.url.database == "loganalyzer_perf", "Лише тестова база!"

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    with SessionLocal() as session:
        source_id = get_or_create_source(session, "perf.site")

        start = time.perf_counter()
        result = import_file(session, source_id, path)
        seconds = time.perf_counter() - start
        print(f"Імпорт: {result.inserted} рядків за {seconds:.1f} с "
              f"({result.inserted / seconds:.0f} рядків/с)")

        start = time.perf_counter()
        again = import_file(session, source_id, path)
        seconds = time.perf_counter() - start
        print(f"Повторний імпорт: додано {again.inserted}, за {seconds:.1f} с")

        for item in SEED_RULES:
            params = build_params(item["rule_type"], **item["params"])
            create_rule(session, item["name"], item["rule_type"], params,
                        item["window_minutes"])
        rules = list_rules(session)

        print()
        print(f"{'Версія':<8}{'Правило':<28}{'Збігів':>8}{'Інцидентів':>12}{'Секунд':>9}")
        totals: dict[str, float] = {}
        counts: dict[str, int] = {}
        for label, function in (("Python", run_rule), ("SQL", run_rule_sql)):
            session.execute(delete(IncidentEntryRow))
            session.execute(delete(IncidentRow))
            session.commit()
            totals[label] = 0.0
            for rule in rules:
                start = time.perf_counter()
                res = function(session, rule, source_id)
                seconds = time.perf_counter() - start
                totals[label] += seconds
                print(f"{label:<8}{rule.name:<28}{res.matched_entries:>8}"
                      f"{res.incidents_created:>12}{seconds:>9.2f}")
            counts[label] = session.scalar(select(func.count()).select_from(IncidentRow)) or 0

        print()
        print(f"Усього інцидентів: Python {counts['Python']}, SQL {counts['SQL']}")
        print(f"Загальний час: Python {totals['Python']:.2f} с, SQL {totals['SQL']:.2f} с, "
              f"прискорення у {totals['Python'] / totals['SQL']:.1f} раза")

        start = time.perf_counter()
        session.execute(
            select(LogEntryRow.ip, func.count())
            .group_by(LogEntryRow.ip).order_by(func.count().desc()).limit(10)
        ).all()
        print(f"Топ-10 IP по всій базі: {time.perf_counter() - start:.2f} с")


if __name__ == "__main__":
    main()