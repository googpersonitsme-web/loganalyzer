import argparse
import getpass
import sys
from typing import Any

from sqlalchemy import select

from loganalyzer.domain.roles import Role
from loganalyzer.domain.rules import (
    IncidentStatus,
    InvalidTransition,
    RuleType,
    build_params,
)
from loganalyzer.services import detection, incidents, rules, users
from loganalyzer.storage.db import SessionLocal, init_db
from loganalyzer.storage.tables import LogSourceRow

DEFAULT_SITE = "magickey.com.ua"

SEED_RULES: list[dict[str, Any]] = [
    {
        "name": "Пошук прихованих файлів",
        "rule_type": RuleType.PATH_REGEX,
        "window_minutes": 60,
        "params": {
            "pattern": r"/\.(git|env|svn)|wp-login|wp-admin|xmlrpc|phpmyadmin|archivarix",
            "min_hits": 1,
        },
    },
    {
        "name": "Багато 404 від одного IP",
        "rule_type": RuleType.STATUS_BURST,
        "window_minutes": 10,
        "params": {"statuses": [404], "min_hits": 8},
    },
    {
        "name": "Бот-збирач пошти",
        "rule_type": RuleType.USER_AGENT,
        "window_minutes": 60,
        "params": {"contains": "email-guesser", "min_hits": 3},
    },
]


def _source_id(session, site: str) -> int:
    source = session.scalar(select(LogSourceRow).where(LogSourceRow.name == site))
    if source is None:
        raise LookupError(f"Сайт «{site}» не знайдено. Спочатку виконайте import_logs.py")
    return source.id


def cmd_seed_rules(args, session) -> None:
    for item in SEED_RULES:
        params = build_params(item["rule_type"], **item["params"])
        try:
            rules.create_rule(
                session, item["name"], item["rule_type"], params, item["window_minutes"]
            )
            print(f"Створено: {item['name']}")
        except rules.RuleExists:
            print(f"Вже є:    {item['name']}")


def cmd_create_rule(args, session) -> None:
    rule_type = RuleType(args.type)
    statuses = [int(s) for s in args.statuses.split(",")] if args.statuses else None
    params = build_params(
        rule_type,
        pattern=args.pattern,
        statuses=statuses,
        contains=args.contains,
        min_hits=args.min_hits,
    )
    row = rules.create_rule(session, args.name, rule_type, params, args.window)
    print(f"Правило №{row.id} «{row.name}» створено")


def cmd_list_rules(args, session) -> None:
    for r in rules.list_rules(session):
        print(f"#{r.id:<3} {r.name:<30} {r.rule_type:<13} вікно {r.window_minutes} хв  {r.params}")


def cmd_detect(args, session) -> None:
    source_id = _source_id(session, args.site)
    for res in detection.run_all(session, source_id):
        print(
            f"{res.rule_name:<30} збігів: {res.matched_entries:<4} "
            f"нових інцидентів: {res.incidents_created:<3} вже було: {res.incidents_existing}"
        )


def cmd_list_incidents(args, session) -> None:
    status = IncidentStatus(args.status) if args.status else None
    items = incidents.list_incidents(session, status)
    if not items:
        print("Інцидентів нема")
    for inc, rule_name in items:
        print(
            f"#{inc.id:<3} {inc.status:<13} {inc.ip:<16} "
            f"{inc.window_start:%Y-%m-%d %H:%M} UTC  записів: {inc.entries_count:<3} {rule_name}"
        )


def cmd_show_incident(args, session) -> None:
    inc, rule_name, entries = incidents.get_incident(session, args.id)
    print(f"Інцидент №{inc.id}: {rule_name}")
    print(f"IP: {inc.ip}   статус: {inc.status}   записів: {inc.entries_count}")
    if inc.note:
        print(f"Примітка: {inc.note}")
    print("Перші записи:")
    for e in entries:
        print(f"  {e.timestamp:%H:%M:%S} {e.status} {e.method} {e.path[:70]}")


def cmd_ack(args, session) -> None:
    inc = incidents.change_status(session, args.id, IncidentStatus.ACKNOWLEDGED)
    print(f"Інцидент №{inc.id}: взято в роботу")


def cmd_close(args, session) -> None:
    inc = incidents.change_status(session, args.id, IncidentStatus.CLOSED, args.note)
    print(f"Інцидент №{inc.id}: закрито")


def cmd_create_user(args, session) -> None:
    password = getpass.getpass("Пароль (не менше 8 символів): ")
    row = users.create_user(session, args.username, password, Role(args.role))
    print(f"Користувача «{row.username}» створено, роль: {row.role}")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m loganalyzer", description="Аналізатор логів вебсервера"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("seed-rules", help="створити готові правила")

    p = sub.add_parser("create-rule", help="створити своє правило")
    p.add_argument("--name", required=True)
    p.add_argument("--type", required=True, choices=[t.value for t in RuleType])
    p.add_argument("--window", type=int, default=60, help="вікно в хвилинах")
    p.add_argument("--min-hits", type=int, default=1, help="поріг спрацювання")
    p.add_argument("--pattern", help="регулярний вираз для шляху")
    p.add_argument("--statuses", help="статуси через кому, наприклад 404,429")
    p.add_argument("--contains", help="текст у User-Agent")

    sub.add_parser("list-rules", help="показати правила")

    p = sub.add_parser("detect", help="перевірити логи за правилами")
    p.add_argument("--site", default=DEFAULT_SITE)

    p = sub.add_parser("list-incidents", help="показати інциденти")
    p.add_argument("--status", choices=[s.value for s in IncidentStatus])

    p = sub.add_parser("show-incident", help="деталі інциденту")
    p.add_argument("id", type=int)

    p = sub.add_parser("ack", help="взяти інцидент в роботу")
    p.add_argument("id", type=int)

    p = sub.add_parser("close", help="закрити інцидент")
    p.add_argument("id", type=int)
    p.add_argument("--note", help="коментар")

    p = sub.add_parser("create-user", help="створити користувача")
    p.add_argument("--username", required=True)
    p.add_argument("--role", required=True, choices=[r.value for r in Role])

    args = parser.parse_args(argv)
    handlers = {
        "seed-rules": cmd_seed_rules,
        "create-rule": cmd_create_rule,
        "list-rules": cmd_list_rules,
        "detect": cmd_detect,
        "list-incidents": cmd_list_incidents,
        "show-incident": cmd_show_incident,
        "create-user": cmd_create_user,
        "ack": cmd_ack,
        "close": cmd_close,
    }

    init_db()  # додає нові таблиці, якщо їх ще нема
    try:
        with SessionLocal() as session:
            handlers[args.command](args, session)
    except (
        ValueError, LookupError, InvalidTransition,
        rules.RuleExists, incidents.IncidentNotFound, users.UserExists,
    ) as exc:
        print(f"Помилка: {exc}")
        sys.exit(1)