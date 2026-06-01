"""iocflow as an MCP server — drive the IOC lifecycle from any MCP client.

Exposes the deterministic lifecycle (:data:`~iocflow.mcp.tools.MCP_TOOLS`) over
the Model Context Protocol so an MCP-capable client (Claude Desktop, an IDE
assistant, your own agent) can extract, enrich, assess, hunt, propose blocks
(dry-run), and convert STIX — without importing iocflow as a library.

Run it (stdio transport, the MCP default):

    iocflow-mcp
    # or
    python -m iocflow.mcp

The ``mcp`` SDK is imported lazily inside :func:`build_server`, so importing this
module (and unit-testing the tool functions) does not require the extra.

Needs the extra: ``pip install "iocflow[mcp]"`` (Python 3.10+).
"""
from __future__ import annotations

from iocflow.mcp.tools import MCP_TOOLS


def build_server(name: str = "iocflow"):
    """Build a FastMCP server with every lifecycle tool registered.

    Raises a clear :class:`ImportError` if the ``mcp`` extra is not installed.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "iocflow MCP server needs the 'mcp' extra: pip install 'iocflow[mcp]'"
        ) from exc

    server = FastMCP(name)
    for fn in MCP_TOOLS:
        server.add_tool(fn)
    return server


def main(argv=None) -> int:
    """Console entry point (``iocflow-mcp``): serve over stdio."""
    build_server().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
