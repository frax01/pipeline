"""
Seeder del DB demo per la PoC SQL injection su JexinSam/mssql_mcp_server.
Crea il database 'poc' con:
  - products (id, name)  -> tabella "lecita" che il tool e' pensato per leggere
  - pwned   (output)     -> tabella vuota dove l'exploit scrivera' l'output di whoami
Tutto avviene su un MSSQL locale in Docker: ambiente sacrificale e contenuto.
"""
import os
import pyodbc

DRIVER = os.environ.get("MSSQL_DRIVER", "ODBC Driver 18 for SQL Server")
HOST   = os.environ.get("MSSQL_HOST", "localhost")
USER   = os.environ.get("MSSQL_USER", "sa")
PW     = os.environ.get("MSSQL_PASSWORD", "Poc_Str0ng!Pass")

def cs(db):
    return (f"Driver={{{DRIVER}}};Server={HOST};UID={USER};PWD={PW};"
            f"Database={db};Encrypt=yes;TrustServerCertificate=yes;")

# 1) crea il database
with pyodbc.connect(cs("master"), autocommit=True) as c:
    c.cursor().execute("IF DB_ID('poc') IS NULL CREATE DATABASE poc;")

# 2) crea e popola le tabelle
with pyodbc.connect(cs("poc"), autocommit=True) as c:
    cur = c.cursor()
    cur.execute("IF OBJECT_ID('products') IS NOT NULL DROP TABLE products;")
    cur.execute("CREATE TABLE products (id INT, name NVARCHAR(100));")
    cur.execute("INSERT INTO products VALUES (1, N'Widget'), (2, N'Gadget');")
    cur.execute("IF OBJECT_ID('pwned') IS NOT NULL DROP TABLE pwned;")
    cur.execute("CREATE TABLE pwned (output NVARCHAR(4000));")

print("OK: DB 'poc' pronto -> products(2 righe), pwned(vuota)")
