from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from loganalyzer.domain.roles import Role
from loganalyzer.storage.tables import UserRow

_hasher = PasswordHasher()


class UserExists(Exception):
    """Користувач з таким логіном уже є."""


class AuthFailed(Exception):
    """Невірний логін або пароль."""


def create_user(session: Session, username: str, password: str, role: Role) -> UserRow:
    username = username.strip()
    if not 3 <= len(username) <= 50:
        raise ValueError("Логін має бути від 3 до 50 символів")
    if len(password) < 8:
        raise ValueError("Пароль має бути не коротший за 8 символів")

    row = UserRow(
        username=username,
        password_hash=_hasher.hash(password),
        role=role.value,
    )
    session.add(row)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise UserExists(f"Користувач «{username}» уже існує") from None
    return row


def authenticate(session: Session, username: str, password: str) -> UserRow:
    """Перевіряє логін і пароль. Повідомлення однакове в обох випадках,
    щоб не підказувати, чи існує такий логін."""
    row = session.scalar(select(UserRow).where(UserRow.username == username))
    if row is None:
        raise AuthFailed("Невірний логін або пароль")
    try:
        _hasher.verify(row.password_hash, password)
    except (VerificationError, InvalidHashError):
        raise AuthFailed("Невірний логін або пароль") from None
    return row