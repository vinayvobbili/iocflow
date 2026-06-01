"""Tests for the iocflow CLI (offline — no API keys, deterministic layers only)."""
import json

import pytest

from iocflow.cli import _inject_default, main

SAMPLE = "APT28 c2 at 185.220.101.5 dropping evil-payload.ru, CVE-2021-44228"


# --------------------------- default-to-extract -------------------------

def test_inject_default_bare_text():
    assert _inject_default(["c2 at 1.2.3.4"]) == ["extract", "c2 at 1.2.3.4"]


def test_inject_default_leading_flag():
    assert _inject_default(["--json", "x"]) == ["extract", "--json", "x"]


def test_inject_default_keeps_subcommand():
    assert _inject_default(["enrich", "x"]) == ["enrich", "x"]


def test_inject_default_empty_reads_stdin():
    assert _inject_default([]) == ["extract"]


def test_inject_default_passes_help_through():
    assert _inject_default(["--help"]) == ["--help"]


# --------------------------- extract (back-compat) ----------------------

def test_cli_human_summary(capsys):
    rc = main(["c2 at 185.220.101.5"])
    out = capsys.readouterr().out
    assert rc == 0 and "185.220.101.5" in out and "ip" in out


def test_cli_json(capsys):
    rc = main(["--json", "c2 at 185.220.101.5"])
    out = capsys.readouterr().out
    assert rc == 0 and json.loads(out)["ips"] == ["185.220.101.5"]


def test_cli_no_refang(capsys):
    main(["--no-refang", "evil[.]com"])
    assert "evil.com" not in capsys.readouterr().out


def test_cli_explicit_extract_subcommand(capsys):
    rc = main(["extract", "--json", "c2 at 185.220.101.5"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["ips"] == ["185.220.101.5"]


def test_cli_reads_stdin(capsys, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("hit 9.9.9.9"))
    main(["extract"])
    assert "9.9.9.9" in capsys.readouterr().out


# --------------------------- lifecycle subcommands ----------------------
# With no API keys the enrichment is empty, but the deterministic layers
# still run and the commands must succeed and emit valid JSON.

def test_cli_enrich_runs_offline(capsys):
    rc = main(["enrich", "--json", SAMPLE])
    assert rc == 0
    json.loads(capsys.readouterr().out)  # valid EnrichmentReport JSON


def test_cli_comment_runs_offline(capsys):
    rc = main(["comment", "--json", SAMPLE])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "severity" in data and "assessment" in data


def test_cli_hunt_runs_offline(capsys):
    rc = main(["hunt", "--json", "--dialect", "sigma", SAMPLE])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert any("185.220.101.5" in h["query"] for h in data["hunts"])


def test_cli_block_is_dry_run_by_default(capsys):
    rc = main(["block", SAMPLE])
    out = capsys.readouterr().out
    assert rc == 0 and "dry-run" in out and "COMMIT" not in out


def test_cli_version(capsys):
    from iocflow import __version__
    rc = main(["version"])
    assert rc == 0 and capsys.readouterr().out.strip() == __version__


def test_cli_version_flag_exits(capsys):
    from iocflow import __version__
    with pytest.raises(SystemExit) as exc:   # argparse --version exits
        main(["--version"])
    assert exc.value.code == 0 and __version__ in capsys.readouterr().out


# --------------------------- stix conversion ----------------------------

def test_cli_stix_to_bundle(capsys):
    rc = main(["stix", "--to", "--json", "c2 at 185.220.101.5"])
    out = capsys.readouterr().out
    assert rc == 0
    bundle = json.loads(out)
    assert bundle["type"] == "bundle"
    assert any(o["type"] == "indicator" for o in bundle["objects"])


def test_cli_stix_from_bundle(capsys):
    bundle = json.dumps({
        "type": "bundle", "objects": [
            {"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']",
             "pattern_type": "stix"},
        ],
    })
    rc = main(["stix", "--from", "--json", bundle])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["ips"] == ["1.2.3.4"]


# --------------------------- poll ---------------------------------------

def test_cli_poll_no_sources_configured(capsys, monkeypatch):
    monkeypatch.setattr("iocflow.sources.default_sources", lambda *a, **k: [])
    rc = main(["poll"])
    assert rc == 1
    assert "no sources configured" in capsys.readouterr().err


def test_cli_poll_runs_configured_source(capsys, monkeypatch):
    from iocflow.sources import Trigger

    class _Src:
        name = "stub"

        def poll(self):
            return [Trigger(source="stub", id="1", text="hit 185.220.101.5", title="t1")]

    monkeypatch.setattr("iocflow.sources.default_sources", lambda *a, **k: [_Src()])
    rc = main(["poll", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1 and data[0]["trigger"]["id"] == "1"


# --------------------------- module entry -------------------------------

def test_python_dash_m_iocflow_runs():
    import subprocess
    import sys
    out = subprocess.run([sys.executable, "-m", "iocflow", "c2 at 185.220.101.5"],
                         capture_output=True, text=True)
    assert out.returncode == 0 and "185.220.101.5" in out.stdout, out.stderr


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
