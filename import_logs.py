import sys

from sqlalchemy import func, select

from loganalyzer.storage.db import SessionLocal, init_db
from loganalyzer.storage.importer import get_or_create_source, import_file
from loganalyzer.storage.tables import LogEntryRow

path = sys.argv[1] if len(sys.argv) > 1 else "access.log"
site = sys.argv[2] if len(sys.argv) > 2 else "magickey.com.ua"

init_db()
with SessionLocal() as session:
    source_id = get_or_create_source(session, site)
    result = import_file(session, source_id, path)
    total = session.scalar(
        select(func.count()).select_from(LogEntryRow).where(LogEntryRow.source_id == source_id)
    )

print(f"Сайт:               {site}")
print(f"Прочитано рядків:   {result.read}")
print(f"Додано в базу:      {result.inserted}")
print(f"Пропущено (вже є):  {result.skipped_duplicates}")
print(f"Биті рядки:         {result.parse_errors}")
print(f"Усього в базі:      {total}")