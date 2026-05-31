"""Tests for the iocflow CLI."""
import json

from iocflow.cli import main


def test_cli_human_summary(capsys):
    rc = main(["c2 at 185.220.101.5"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "185.220.101.5" in out
    assert "ip" in out


def test_cli_json(capsys):
    rc = main(["--json", "c2 at 185.220.101.5"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["ips"] == ["185.220.101.5"]


def test_cli_no_refang(capsys):
    main(["--no-refang", "evil[.]com"])
    out = capsys.readouterr().out
    # defanged domain should not resolve to a domain indicator
    assert "evil.com" not in out
