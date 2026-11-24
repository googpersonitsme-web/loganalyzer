import pytest
from fastapi.testclient import TestClient

from loganalyzer.api.app import app
from loganalyzer.domain.roles import Role
from loganalyzer.services.users import create_user

client = TestClient(app)
PASSWORD = "Password123"


@pytest.fixture
def users(session):
    create_user(session, "boss", PASSWORD, Role.ADMIN)
    create_user(session, "anna", PASSWORD, Role.ANALYST)
    create_user(session, "viewer1", PASSWORD, Role.VIEWER)


def auth(username):
    r = client.post("/auth/login", data={"username": username, "password": PASSWORD})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def test_no_token_is_401():
    assert client.get("/incidents").status_code == 401


@pytest.mark.usefixtures("users")
def test_wrong_password_is_401():
    r = client.post("/auth/login", data={"username": "anna", "password": "wrong-pass"})
    assert r.status_code == 401


@pytest.mark.usefixtures("users")
def test_viewer_can_read_but_not_close(open_incident):
    headers = auth("viewer1")
    assert client.get("/incidents", headers=headers).status_code == 200
    r = client.post(f"/incidents/{open_incident}/close", headers=headers)
    assert r.status_code == 403


@pytest.mark.usefixtures("users")
def test_analyst_closes_once_then_conflict(open_incident):
    headers = auth("anna")
    first = client.post(f"/incidents/{open_incident}/close", headers=headers)
    assert first.status_code == 200
    assert first.json()["status"] == "closed"
    second = client.post(f"/incidents/{open_incident}/close", headers=headers)
    assert second.status_code == 409


@pytest.mark.usefixtures("users")
def test_unknown_incident_is_404():
    r = client.post("/incidents/99999/close", headers=auth("anna"))
    assert r.status_code == 404


@pytest.mark.usefixtures("users")
def test_pagination_and_filter(open_incident):
    headers = auth("viewer1")
    page = client.get("/incidents?limit=1&offset=0", headers=headers).json()
    assert page["total"] == 2
    assert len(page["items"]) == 1
    closed = client.get("/incidents?status=closed", headers=headers).json()
    assert closed["total"] == 0


@pytest.mark.usefixtures("users")
def test_bad_limit_is_422():
    r = client.get("/incidents?limit=0", headers=auth("viewer1"))
    assert r.status_code == 422


@pytest.mark.usefixtures("users")
def test_rule_creation_rules():
    body = {"name": "Моє правило", "rule_type": "user_agent", "contains": "Photon"}
    assert client.post("/rules", json=body, headers=auth("viewer1")).status_code == 403
    assert client.post("/rules", json=body, headers=auth("anna")).status_code == 201
    assert client.post("/rules", json=body, headers=auth("anna")).status_code == 409
    bad = {"name": "Погане", "rule_type": "path_regex", "pattern": "["}
    assert client.post("/rules", json=bad, headers=auth("anna")).status_code == 422