from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from loganalyzer.config import DATABASE_URL
from loganalyzer.storage.tables import Base

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def init_db() -> None:
    """Створює таблиці, якщо їх ще нема."""
    Base.metadata.create_all(engine)