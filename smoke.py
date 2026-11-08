from mcp.server.mcpserver import MCPServer

mcp = MCPServer("smoke", dependencies=["mcp[cli]==2.3.0"])


@mcp.tool()
def echo(text: str) -> str:
    """Echo text back."""
    return text


if __name__ == "__main__":
    mcp.run()
