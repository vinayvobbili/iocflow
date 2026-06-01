"""Run iocflow as an MCP server, and exercise it with an in-memory client.

The simplest way to serve is just the console script:

    pip install "iocflow[mcp]"      # Python 3.10+
    iocflow-mcp                     # serves over stdio

To wire it into Claude Desktop, add to claude_desktop_config.json:

    {
      "mcpServers": {
        "iocflow": { "command": "iocflow-mcp" }
      }
    }

This script instead connects an in-memory client to the server and calls a tool,
so you can see the round trip without any external client. Run:

    python examples/mcp_server.py
"""
import asyncio
import json

from iocflow.mcp import build_server


async def main() -> None:
    from mcp.shared.memory import create_connected_server_and_client_session as connect

    server = build_server()
    async with connect(server._mcp_server) as client:
        await client.initialize()

        tools = await client.list_tools()
        print("tools:", ", ".join(t.name for t in tools.tools))

        report = "Beaconing to 185.220.101.5 and evil-payload.ru, exploiting CVE-2021-44228."
        res = await client.call_tool("extract_iocs", {"text": report})
        entities = json.loads(res.content[0].text)
        print("\nextract_iocs:")
        print(f"  ips:     {entities['ips']}")
        print(f"  domains: {entities['domains']}")
        print(f"  cves:    {entities['cves']}")

        res = await client.call_tool("to_stix_bundle", {"text": report})
        bundle = json.loads(res.content[0].text)
        print(f"\nto_stix_bundle: {len(bundle['objects'])} objects "
              f"({', '.join(o['type'] for o in bundle['objects'])})")


if __name__ == "__main__":
    asyncio.run(main())
