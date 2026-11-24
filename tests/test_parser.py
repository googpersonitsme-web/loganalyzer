from datetime import timedelta

import pytest

from loganalyzer.parsing.parser import ParseError, parse_line

GOOD = (
    '195.234.109.78 - - [23/Nov/2026:05:09:37 +0200] '
    '"GET /a/b.jpg HTTP/1.0" 404 443 "-" "Photon/1.0"'
)


def test_parse_good_line():
    e = parse_line(GOOD)
    assert e.ip == "195.234.109.78"
    assert e.method == "GET"
    assert e.path == "/a/b.jpg"
    assert e.protocol == "HTTP/1.0"
    assert e.status == 404
    assert e.bytes_sent == 443
    assert e.user_agent == "Photon/1.0"


def test_timezone_is_kept():
    assert parse_line(GOOD).timestamp.utcoffset() == timedelta(hours=2)


def test_dash_in_bytes_means_zero():
    line = GOOD.replace("404 443", "304 -")
    assert parse_line(line).bytes_sent == 0


def test_garbage_line_raises():
    with pytest.raises(ParseError):
        parse_line("це не рядок логу")


def test_status_out_of_range_raises():
    with pytest.raises(ParseError):
        parse_line(GOOD.replace("404 443", "999 443"))


def test_same_line_gives_same_hash():
    assert parse_line(GOOD).line_hash == parse_line(GOOD + "\n").line_hash