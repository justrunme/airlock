import pytest

from airlock.sed_parser import SedParseError, parse

GOOD = [
    "s/a/b/g",
    "1d",
    "$=",
    "/^#/d;/^$/d",
    "10,20p",
    "1~2p",
    "/start/,+3p",
    "\\|/x|p",
    "/x/I!d",
    "/err/{=;p}",
    "y/abc/xyz/",
    "5q",
    "Q 3",
    "s/a/b/2i",
    "h;G;x;D;P;l",
]
BAD = [
    "1e id",
    "s/a/b/e",
    "s/a/b/w /tmp/x",
    "w /tmp/x",
    "W /tmp/x",
    "r /etc/passwd",
    "R /etc/passwd",
    ":a;ba",
    "s/a/b/;tz",
    "F",
    "z",
    "1{p",
    "s/a/b",
    "v",
]


@pytest.mark.parametrize("script", GOOD)
def test_parse_accepts_subset(script):
    parse(script)


@pytest.mark.parametrize("script", BAD)
def test_parse_rejects_outside_subset(script):
    with pytest.raises(SedParseError):
        parse(script)
