import pytest

from loganalyzer import cli


def run(*args):
    cli.main(list(args))


def test_seed_rules_twice(capsys):
    run("seed-rules")
    assert "Створено" in capsys.readouterr().out
    run("seed-rules")
    assert "Вже є" in capsys.readouterr().out


def test_detect_and_list(capsys, imported):
    run("seed-rules")
    run("detect", "--site", "test.site")
    out = capsys.readouterr().out
    assert "Пошук прихованих файлів" in out
    run("list-incidents")
    assert "open" in capsys.readouterr().out


def test_show_ack_close_flow(capsys, imported):
    run("seed-rules")
    run("detect", "--site", "test.site")
    run("list-rules")
    run("show-incident", "1")
    assert "Інцидент №1" in capsys.readouterr().out
    run("ack", "1")
    run("close", "1", "--note", "перевірено")
    with pytest.raises(SystemExit):
        run("close", "1")
    assert "заборонений" in capsys.readouterr().out


def test_unknown_site_exits(capsys):
    with pytest.raises(SystemExit):
        run("detect", "--site", "nope.site")
    assert "не знайдено" in capsys.readouterr().out


def test_create_rule_command(capsys):
    run("create-rule", "--name", "UA", "--type", "user_agent",
        "--contains", "Photon", "--min-hits", "3")
    assert "створено" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        run("create-rule", "--name", "Погане", "--type", "path_regex", "--pattern", "[")


def test_create_user_command(capsys, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt: "Password123")
    run("create-user", "--username", "newuser", "--role", "viewer")
    assert "створено" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        run("create-user", "--username", "newuser", "--role", "viewer")