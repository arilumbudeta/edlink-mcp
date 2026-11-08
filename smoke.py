try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _MCPServer
except ImportError:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as _MCPServer

mcp = _MCPServer("smoke")


@mcp.tool()
def echo(text: str) -> str:
    """Echo text back."""
    return text


if __name__ == "__main__":
    mcp.run()
