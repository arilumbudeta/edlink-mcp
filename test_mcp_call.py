"""Test: panggil edlink_login_status via MCP client (tanpa kredensial -> harus error bersih)."""
import asyncio
import json
import re
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = str(Path(__file__).resolve().with_name("edlink_mcp.py"))


async def main() -> None:
    params = StdioServerParameters(command=sys.executable, args=[SERVER])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("edlink_login_status", {})
            print("is_error:", result.isError)
            for block in result.content:
                text = block.text if hasattr(block, "text") else str(block)
                # Jangan pernah mencetak token/preview atau data akun di output test.
                text = re.sub(r'("token_preview"\s*:\s*")[^"]*(")', r"\1***\2", text)
                text = re.sub(r'("user"\s*:\s*")[^"]*(")', r"\1***\2", text)
                text = re.sub(r'("email"\s*:\s*")[^"]*(")', r"\1***\2", text)
                print(text)


asyncio.run(main())
