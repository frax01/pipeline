# Hardcoded credential committed in mcp_server/.env

Form: https://github.com/dev8372/graphitiMCP/security/advisories/new

CWE: CWE-798 (Use of Hard-coded Credentials)

---

The value is in a committed `.env` file. Files of that name are by convention
excluded from version control precisely because they hold real values, which
is why I am flagging this one rather than treating it as a sample.

Locations:

  - `mcp_server/.env:11`

This report comes from an academic study of the Model Context Protocol
ecosystem carried out at Politecnico di Milano, in which we analysed 69,104
publicly published MCP servers. I am using the private reporting channel
declared in your SECURITY.md.

I am deliberately not including the credential values in this report. We have
never used them, attempted to authenticate with them, invoked any associated API
or otherwise tested whether they are currently active. The findings were
identified through static analysis and subsequently reviewed by hand.

Removing the values from the current version of the source would not, by itself,
fully address the exposure, since they remain readable in the repository's Git
history. The standard remediation is to issue new credentials, update the
configuration to use them, and only then revoke the exposed ones. Credentials
committed to a public repository should be considered compromised regardless of
whether they still work, as public code is continuously indexed and scanned by
automated collectors.

If any of these are placeholders, example values or already-rotated credentials,
no action is needed and I apologise for the noise. Our check on this class of
finding confirms at about 95%, so a small number will be wrong.

No response is required and there is no deadline. The study is academic and your
repository is not individually identified in it.

Contacts:
  Francesco Martignoni - Politecnico di Milano - francesco.martignoni@mail.polimi.it
  Michele Carminati - Associate Professor, Politecnico di Milano, DEIB - michele.carminati@polimi.it
  Stefano Longari - Assistant Professor, Politecnico di Milano, DEIB - stefano.longari@polimi.it
