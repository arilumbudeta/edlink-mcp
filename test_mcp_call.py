"""Test: panggil edlink_login_status via MCP client (tanpa kredensial -> harus error bersih)."""
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
            result = await session.call_tool("edlink_login_status", {})
            print("is_error:", result.is_error)
            for block in result.content:
                print(block.text if hasattr(block, "text") else block)


asyncio.run(main())
