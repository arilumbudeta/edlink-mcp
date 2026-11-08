"""Platform multi-user untuk EdLink MCP.

Modul ini menyediakan lapisan penyimpanan, autentikasi, dan OAuth untuk
menjalankan EdLink MCP sebagai layanan publik. Import bersifat opsional untuk
edlink_mcp.py: mode stdio tetap jalan tanpa paket ini.
"""

__all__ = ["db", "crypto", "identity", "security", "store"]
