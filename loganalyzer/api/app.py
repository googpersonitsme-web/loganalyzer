from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from loganalyzer.api import schemas
from loganalyzer.api.auth import create_token, get_session, needs
from loganalyzer.domain.roles import Action
from loganalyzer.domain.rules import IncidentStatus, InvalidTransition, build_params
from loganalyzer.services import detection, incidents, rules, users
from loganalyzer.storage.db import init_db
from loganalyzer.storage.tables import IncidentRow, LogEntryRow, LogSourceRow


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(title="Аналізатор логів вебсервера", version="1.0", lifespan=lifespan)

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/auth/login", tags=["Вхід"])
def login(
    form: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)
):
    try:
        user = users.authenticate(session, form.username, form.password)
    except users.AuthFailed as exc:
        raise HTTPException(401, str(exc)) from None
    return {"access_token": create_token(user), "token_type": "bearer", "role": user.role}


# ---------- Правила ----------

@app.get("/rules", response_model=list[schemas.RuleOut], tags=["Правила"],
         dependencies=[Depends(needs(Action.VIEW))])
def get_rules(session: Session = Depends(get_session)):
    return rules.list_rules(session)


@app.post("/rules", response_model=schemas.RuleOut, status_code=201, tags=["Правила"],
          dependencies=[Depends(needs(Action.CREATE_RULE))])
def post_rule(body: schemas.RuleCreate, session: Session = Depends(get_session)):
    try:
        params = build_params(
            body.rule_type, pattern=body.pattern, statuses=body.statuses,
            contains=body.contains, min_hits=body.min_hits,
        )
        return rules.create_rule(session, body.name, body.rule_type, params, body.window_minutes)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except rules.RuleExists as exc:
        raise HTTPException(409, str(exc)) from None


# ---------- Перевірка логів ----------

@app.post("/detect", response_model=list[schemas.DetectOut], tags=["Виявлення"],
          dependencies=[Depends(needs(Action.CREATE_RULE))])
def post_detect(site: str = "magickey.com.ua", session: Session = Depends(get_session)):
    source = session.scalar(select(LogSourceRow).where(LogSourceRow.name == site))
    if source is None:
        raise HTTPException(404, f"Сайт «{site}» не знайдено")
    return detection.run_all(session, source.id)


# ---------- Інциденти ----------

@app.get("/incidents", response_model=schemas.Page, tags=["Інциденти"],
         dependencies=[Depends(needs(Action.VIEW))])
def get_incidents(
    status: IncidentStatus | None = None,
    ip: str | None = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
):
    """Список з посторінковим виведенням і фільтрами на сервері."""
    stmt = select(IncidentRow)
    if status is not None:
        stmt = stmt.where(IncidentRow.status == status.value)
    if ip:
        stmt = stmt.where(IncidentRow.ip == ip)
    total = session.scalar(select(func.count()).select_from(stmt.subquery()))
    items = session.scalars(stmt.order_by(IncidentRow.id).limit(limit).offset(offset)).all()
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/incidents/{incident_id}", response_model=schemas.IncidentDetail, tags=["Інциденти"],
         dependencies=[Depends(needs(Action.VIEW))])
def get_incident(incident_id: int, session: Session = Depends(get_session)):
    try:
        inc, rule_name, entries = incidents.get_incident(session, incident_id)
    except incidents.IncidentNotFound as exc:
        raise HTTPException(404, str(exc)) from None
    return {"incident": inc, "rule_name": rule_name, "sample_entries": entries}


def _change(incident_id: int, target: IncidentStatus, note, session: Session):
    try:
        return incidents.change_status(session, incident_id, target, note)
    except incidents.IncidentNotFound as exc:
        raise HTTPException(404, str(exc)) from None
    except InvalidTransition as exc:
        raise HTTPException(409, str(exc)) from None


@app.post("/incidents/{incident_id}/acknowledge", response_model=schemas.IncidentOut,
          tags=["Інциденти"], dependencies=[Depends(needs(Action.CHANGE_INCIDENT))])
def post_ack(incident_id: int, session: Session = Depends(get_session)):
    return _change(incident_id, IncidentStatus.ACKNOWLEDGED, None, session)


@app.post("/incidents/{incident_id}/close", response_model=schemas.IncidentOut,
          tags=["Інциденти"], dependencies=[Depends(needs(Action.CHANGE_INCIDENT))])
def post_close(
    incident_id: int,
    body: schemas.IncidentAction | None = None,
    session: Session = Depends(get_session),
):
    return _change(incident_id, IncidentStatus.CLOSED, body.note if body else None, session)


# ---------- Аналітика ----------

@app.get("/analytics/top-ips", tags=["Аналітика"], dependencies=[Depends(needs(Action.VIEW))])
def top_ips(limit: int = Query(10, ge=1, le=100), session: Session = Depends(get_session)):
    rows = session.execute(
        select(LogEntryRow.ip, func.count().label("requests"))
        .group_by(LogEntryRow.ip).order_by(func.count().desc()).limit(limit)
    )
    return [{"ip": ip, "requests": n} for ip, n in rows]


@app.get("/analytics/statuses", tags=["Аналітика"], dependencies=[Depends(needs(Action.VIEW))])
def statuses(session: Session = Depends(get_session)):
    rows = session.execute(
        select(LogEntryRow.status, func.count()).group_by(LogEntryRow.status)
        .order_by(LogEntryRow.status)
    )
    return [{"status": s, "count": n} for s, n in rows]