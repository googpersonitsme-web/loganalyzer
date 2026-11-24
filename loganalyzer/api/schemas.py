from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from loganalyzer.domain.rules import RuleType


class RuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    rule_type: RuleType
    window_minutes: int = Field(default=60, ge=1, le=1440)
    min_hits: int = Field(default=1, ge=1)
    pattern: str | None = None
    statuses: list[int] | None = None
    contains: str | None = None


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    rule_type: str
    window_minutes: int
    params: dict
    enabled: bool


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule_id: int
    ip: str
    window_start: datetime
    status: str
    version: int
    entries_count: int
    note: str | None
    closed_at: datetime | None


class EntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int


class IncidentDetail(BaseModel):
    incident: IncidentOut
    rule_name: str
    sample_entries: list[EntryOut]


class IncidentAction(BaseModel):
    note: str | None = Field(default=None, max_length=500)


class Page(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[IncidentOut]


class DetectOut(BaseModel):
    rule_name: str
    matched_entries: int
    incidents_created: int
    incidents_existing: int