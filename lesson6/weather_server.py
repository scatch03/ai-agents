from fastmcp import FastMCP

mcp = FastMCP("Погода")


@mcp.tool
def get_weather(city: str) -> str:
    """Поточна погода в місті. Використовуй, коли питають про погоду."""
    return f"{city}: +7°C, хмарно"


if __name__ == "__main__":
    mcp.run()
