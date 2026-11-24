import hashlib
from collections import Counter
from dataclasses import dataclass, replace
from datetime import UTC
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert
from sqlalchemy.orm import Session

from loganalyzer.domain.models import LogEntry
from loganalyzer.parsing.reader import ParseStats, read_entries
from loganalyzer.storage.tables import LogEntryRow, LogSourceRow


@dataclass
class ImportResult:
    read: int
    inserted: int
    skipped_duplicates: int
    parse_errors: int


def get_or_create_source(session: Session, name: str) -> int:
    source = session.scalar(select(LogSourceRow).where(LogSourceRow.name == name))
    if source is None:
        source = LogSourceRow(name=name)
        session.add(source)
        session.commit()
    return source.id


def _to_row(entry: LogEntry, source_id: int) -> dict:
    # MySQL DATETIME не має часового поясу, тому зберігаємо UTC
    utc_time = entry.timestamp.astimezone(UTC).replace(tzinfo=None)
    return {
        "source_id": source_id,
        "ip": entry.ip,
        "timestamp": utc_time,
        "method": entry.method[:16],
        "path": entry.path[:2048],
        "protocol": entry.protocol[:16],
        "status": entry.status,
        "bytes_sent": entry.bytes_sent,
        "referer": entry.referer[:2048],
        "user_agent": entry.user_agent[:1024],
        "line_hash": entry.line_hash,
    }


def _flush(session: Session, batch: list[dict]) -> int:
    """Записує пачку. INSERT IGNORE пропускає те, що вже є в базі."""
    if not batch:
        return 0
    result = session.connection().execute(
        insert(LogEntryRow).prefix_with("IGNORE"), batch
    )
    session.commit()
    return result.rowcount


def import_file(
    session: Session, source_id: int, path: str | Path, batch_size: int = 1000
) -> ImportResult:
    stats = ParseStats()
    seen: Counter[str] = Counter()  # скільки разів цей рядок уже траплявся у файлі
    batch: list[dict] = []
    inserted = 0

    for entry in read_entries(path, stats):
        n = seen[entry.line_hash]
        seen[entry.line_hash] += 1
        unique_hash = hashlib.sha256(f"{entry.line_hash}#{n}".encode()).hexdigest()
        entry = replace(entry, line_hash=unique_hash)

        batch.append(_to_row(entry, source_id))
        if len(batch) >= batch_size:
            inserted += _flush(session, batch)
            batch.clear()

    inserted += _flush(session, batch)
    return ImportResult(
        read=stats.parsed,
        inserted=inserted,
        skipped_duplicates=stats.parsed - inserted,
        parse_errors=stats.errors,
    )