from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from loganalyzer.config import SECRET_KEY, TOKEN_MINUTES
from loganalyzer.domain.roles import Action, PermissionDenied, Role, require
from loganalyzer.storage.db import SessionLocal
from loganalyzer.storage.tables import UserRow

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_session() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session


def create_token(user: UserRow) -> str:
    payload = {
        "sub": user.username,
        "exp": datetime.now(UTC) + timedelta(minutes=TOKEN_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def current_user(
    token: str = Depends(oauth2), session: Session = Depends(get_session)
) -> UserRow:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Недійсний або прострочений токен") from None
    user = session.scalar(select(UserRow).where(UserRow.username == data.get("sub")))
    if user is None:
        raise HTTPException(401, "Користувача не знайдено")
    return user


def needs(action: Action):
    """Залежність: пускає лише ті ролі, яким дозволена дія."""

    def checker(user: UserRow = Depends(current_user)) -> UserRow:
        try:
            require(Role(user.role), action)
        except PermissionDenied as exc:
            raise HTTPException(403, str(exc)) from None
        return user

    return checker