"""Enable ``python -m iocflow.mcp`` to serve the MCP server."""
from iocflow.mcp.server import main

if __name__ == "__main__":
    raise SystemExit(main())
