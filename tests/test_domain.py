import pytest

from loganalyzer.domain.roles import Action, Role, can
from loganalyzer.domain.rules import (
    IncidentStatus as S,
)
from loganalyzer.domain.rules import (
    InvalidTransition,
    RuleType,
    build_params,
    check_transition,
    make_matcher,
)


@pytest.mark.parametrize("current,target", [
    (S.OPEN, S.ACKNOWLEDGED), (S.OPEN, S.CLOSED), (S.ACKNOWLEDGED, S.CLOSED),
])
def test_allowed_transitions(current, target):
    check_transition(current, target)  # не має кидати помилку


@pytest.mark.parametrize("current,target", [
    (S.CLOSED, S.CLOSED), (S.CLOSED, S.OPEN), (S.CLOSED, S.ACKNOWLEDGED),
    (S.ACKNOWLEDGED, S.OPEN), (S.OPEN, S.OPEN),
])
def test_forbidden_transitions(current, target):
    with pytest.raises(InvalidTransition):
        check_transition(current, target)


def test_bad_regex_rejected():
    with pytest.raises(ValueError):
        build_params(RuleType.PATH_REGEX, pattern="[")


def test_missing_parameter_rejected():
    with pytest.raises(ValueError):
        build_params(RuleType.USER_AGENT)


def test_min_hits_must_be_positive():
    with pytest.raises(ValueError):
        build_params(RuleType.PATH_REGEX, pattern="x", min_hits=0)


def test_status_out_of_range_rejected():
    with pytest.raises(ValueError):
        build_params(RuleType.STATUS_BURST, statuses=[700])


def test_path_matcher():
    m = make_matcher(RuleType.PATH_REGEX, {"pattern": r"\.git"})
    assert m("/.git/HEAD", 404, "x")
    assert not m("/index.php", 200, "x")


def test_user_agent_matcher_ignores_case():
    m = make_matcher(RuleType.USER_AGENT, {"contains": "EMAIL-guesser"})
    assert m("/", 200, "Mozilla (compatible; email-guesser/1.0)")


def test_roles():
    assert not can(Role.VIEWER, Action.CHANGE_INCIDENT)
    assert can(Role.VIEWER, Action.VIEW)
    assert can(Role.ANALYST, Action.CHANGE_INCIDENT)
    assert not can(Role.ANALYST, Action.MANAGE_USERS)
    assert all(can(Role.ADMIN, a) for a in Action)