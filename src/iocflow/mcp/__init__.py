"""iocflow MCP server — the IOC lifecycle over the Model Context Protocol.

    from iocflow.mcp import build_server
    build_server().run()          # serve over stdio

Or via the console script / module:

    iocflow-mcp
    python -m iocflow.mcp

The seven tools (extract → enrich → assess → hunt → propose-blocks, plus STIX
in/out) are plain functions in :mod:`iocflow.mcp.tools`, registered on a FastMCP
server in :mod:`iocflow.mcp.server`. The ``mcp`` SDK is only needed to run the
server, not to import this package.

Needs the extra: ``pip install "iocflow[mcp]"`` (Python 3.10+).
"""
from iocflow.mcp.server import build_server, main
from iocflow.mcp.tools import MCP_TOOLS

__all__ = ["build_server", "main", "MCP_TOOLS"]
