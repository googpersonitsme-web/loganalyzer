from enum import StrEnum


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


class Action(StrEnum):
    VIEW = "view"                  # дивитися інциденти й аналітику
    CREATE_RULE = "create_rule"    # створювати правила
    CHANGE_INCIDENT = "change_incident"  # брати в роботу й закривати
    IMPORT_LOGS = "import_logs"    # завантажувати логи
    MANAGE_USERS = "manage_users"  # керувати користувачами


_PERMISSIONS: dict[Role, set[Action]] = {
    Role.VIEWER: {Action.VIEW},
    Role.ANALYST: {Action.VIEW, Action.CREATE_RULE, Action.CHANGE_INCIDENT},
    Role.ADMIN: set(Action),
}


class PermissionDenied(Exception):
    """У ролі немає права на цю дію."""


def can(role: Role, action: Action) -> bool:
    return action in _PERMISSIONS[role]


def require(role: Role, action: Action) -> None:
    if not can(role, action):
        raise PermissionDenied(
            f"Роль «{role.value}» не має права на дію «{action.value}»"
        )