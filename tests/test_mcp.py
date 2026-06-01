"""Tests for the iocflow MCP layer.

The tool *functions* are SDK-free and tested directly (offline, no API keys).
The FastMCP server wiring is tested when the ``mcp`` extra is installed.
"""
import json

import pytest

from iocflow.mcp.tools import (
    MCP_TOOLS,
    assess_indicators,
    enrich_indicators,
    extract_iocs,
    from_stix_bundle,
    propose_blocks,
    suggest_hunts,
    to_stix_bundle,
)

SAMPLE = "APT28 c2 at 185.220.101.5 dropped evil.ru, CVE-2021-44228, hash " + "a" * 64


# ----------------------------- tool functions ---------------------------

def test_extract_iocs():
    out = extract_iocs(SAMPLE)
    assert out["ips"] == ["185.220.101.5"] and "evil.ru" in out["domains"]
    json.dumps(out)  # serializable


def test_enrich_indicators_offline():
    out = enrich_indicators(SAMPLE)
    assert "records" in out and "verdicts" in out


def test_assess_indicators_offline():
    out = assess_indicators(SAMPLE)
    assert "severity" in out and "assessment" in out


def test_suggest_hunts_dialect_filter():
    out = suggest_hunts(SAMPLE, dialects=["sigma"])
    assert out["hunts"] and all(h["source"] in ("deterministic", "llm") for h in out["hunts"])
    assert any("185.220.101.5" in h["query"] for h in out["hunts"])


def test_propose_blocks_is_dry_run():
    out = propose_blocks(SAMPLE)
    # nothing is actually blocked; every result is a dry run or skip
    assert all(r["status"] in ("dry_run", "skipped", "allowlisted") for r in out["results"])


def test_stix_round_trip():
    bundle = to_stix_bundle("c2 at 185.220.101.5")
    assert bundle["type"] == "bundle"
    back = from_stix_bundle(json.dumps(bundle))
    assert back["ips"] == ["185.220.101.5"]


def test_tool_list_names_and_docs():
    names = [f.__name__ for f in MCP_TOOLS]
    assert names == [
        "extract_iocs", "enrich_indicators", "assess_indicators",
        "suggest_hunts", "propose_blocks", "to_stix_bundle", "from_stix_bundle",
    ]
    # every tool has a docstring (MCP uses it as the tool description)
    assert all((f.__doc__ or "").strip() for f in MCP_TOOLS)


# ----------------------------- import isolation -------------------------

def test_importing_core_does_not_load_mcp():
    import subprocess
    import sys
    code = ("import sys, iocflow; "
            "assert 'iocflow.mcp' not in sys.modules; print('ok')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0 and "ok" in out.stdout, out.stderr


def test_importing_mcp_package_does_not_require_sdk():
    # Importing iocflow.mcp (and the tool functions) must not need the mcp SDK;
    # only build_server()/run() does. We simulate "SDK absent" by blocking it.
    import subprocess
    import sys
    code = (
        "import sys; "
        "sys.modules['mcp'] = None; "          # force `import mcp` to fail
        "import iocflow.mcp; "
        "from iocflow.mcp.tools import extract_iocs; "
        "assert extract_iocs('1.2.3.4')['ips'] == ['1.2.3.4']; "
        "print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0 and "ok" in out.stdout, out.stderr


# ----------------------------- server (needs the extra) -----------------

def test_build_server_registers_all_tools():
    pytest.importorskip("mcp")
    import asyncio

    from iocflow.mcp import build_server

    server = build_server()
    tools = asyncio.run(server.list_tools())
    assert {t.name for t in tools} == {f.__name__ for f in MCP_TOOLS}
    for t in tools:  # FastMCP derives an input schema from each signature
        assert (t.inputSchema or {}).get("properties")


def test_server_end_to_end_tool_call():
    pytest.importorskip("mcp")
    import asyncio

    from mcp.shared.memory import create_connected_server_and_client_session as connect

    from iocflow.mcp import build_server

    async def go():
        server = build_server()
        async with connect(server._mcp_server) as client:
            await client.initialize()
            res = await client.call_tool("extract_iocs", {"text": "c2 at 185.220.101.5"})
            return json.loads(res.content[0].text)

    payload = asyncio.run(go())
    assert payload["ips"] == ["185.220.101.5"]
