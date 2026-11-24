from sqlalchemy import func, select

from loganalyzer.storage.importer import get_or_create_source, import_file
from loganalyzer.storage.tables import LogEntryRow


def _count(session):
    return session.scalar(select(func.count()).select_from(LogEntryRow))


def test_import_is_idempotent(session, log_file):
    source_id = get_or_create_source(session, "test.site")

    first = import_file(session, source_id, log_file)
    assert first.read == 4
    assert first.inserted == 4          # два однакові рядки не губляться
    assert _count(session) == 4

    second = import_file(session, source_id, log_file)
    assert second.inserted == 0         # повторний імпорт нічого не додає
    assert second.skipped_duplicates == 4
    assert _count(session) == 4


def test_bad_lines_are_counted_not_fatal(session, tmp_path, log_file):
    path = tmp_path / "mixed.log"
    path.write_text(log_file.read_text(encoding="utf-8") + "сміття\n", encoding="utf-8")
    source_id = get_or_create_source(session, "test.site")

    result = import_file(session, source_id, path)
    assert result.parse_errors == 1
    assert result.inserted == 4