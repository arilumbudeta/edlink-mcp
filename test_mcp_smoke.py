"""Smoke test: spawn edlink_mcp.py via stdio, initialize, list tools."""
import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = r"C:\Users\Lumi\Documents\EDLINK\edlink_mcp.py"


async def main() -> None:
    params = StdioServerParameters(command=sys.executable, args=[SERVER])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print("TOOLS:", json.dumps(names))
            for t in tools.tools:
                desc = (t.description or "").splitlines()[0][:70]
                print(f"  - {t.name}: {desc}")


asyncio.run(main())
