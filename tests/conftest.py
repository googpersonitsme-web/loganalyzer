import os

# ВАЖЛИВО: це має бути до імпорту програми, щоб тести використали тестову базу
os.environ["DATABASE_URL"] = (
    "mysql+pymysql://loguser:logpass@127.0.0.1:3306/loganalyzer_test?charset=utf8mb4"
)

import pytest
from sqlalchemy import select, text

from loganalyzer.domain.rules import RuleType, build_params
from loganalyzer.services.detection import run_rule
from loganalyzer.services.rules import create_rule
from loganalyzer.storage.db import SessionLocal, engine, init_db
from loganalyzer.storage.importer import get_or_create_source, import_file
from loganalyzer.storage.tables import Base, IncidentRow

# Запобіжник: ніколи не чистимо справжню базу
assert engine.url.database == "loganalyzer_test", "Тести мають працювати лише з тестовою базою!"

LINES = [
    '1.1.1.1 - - [23/Nov/2026:05:00:01 +0200] "GET /.git/HEAD HTTP/1.0" 404 392 "-" "Mozilla/5.0"',
    '1.1.1.1 - - [23/Nov/2026:05:00:01 +0200] "GET /.git/HEAD HTTP/1.0" 404 392 "-" "Mozilla/5.0"',
    '1.1.1.1 - - [23/Nov/2026:05:00:02 +0200] "GET /index.php HTTP/1.0" 200 100 "-" "Mozilla/5.0"',
        '2.2.2.2 - - [23/Nov/2026:05:00:03 +0200] "GET /wp-login.php HTTP/1.0" '
    '404 395 "-" "Mozilla/5.0"',
]


@pytest.fixture(scope="session", autouse=True)
def _schema():
    init_db()


@pytest.fixture(autouse=True)
def clean_db():
    """Перед кожним тестом очищає всі таблиці тестової бази."""
    with engine.begin() as conn:
        conn.execute(text("SET FOREIGN_KEY_CHECKS=0"))
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(text(f"TRUNCATE TABLE {table.name}"))
        conn.execute(text("SET FOREIGN_KEY_CHECKS=1"))


@pytest.fixture
def session():
    with SessionLocal() as s:
        yield s


@pytest.fixture
def log_file(tmp_path):
    path = tmp_path / "access.log"
    path.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def imported(session, log_file):
    """ID джерела, у яке вже імпортовано тестовий лог."""
    source_id = get_or_create_source(session, "test.site")
    import_file(session, source_id, log_file)
    return source_id


@pytest.fixture
def rule(session):
    params = build_params(RuleType.PATH_REGEX, pattern=r"\.git|wp-login", min_hits=1)
    return create_rule(session, "Тестове правило", RuleType.PATH_REGEX, params, 60)


@pytest.fixture
def open_incident(session, imported, rule):
    """ID першого відкритого інциденту (у тестових даних їх два)."""
    run_rule(session, rule, imported)
    session.commit()
    return session.scalars(select(IncidentRow.id).order_by(IncidentRow.id)).first()