# Database MCP Servers

This repository contains guarded PostgreSQL, Microsoft SQL Server, and MySQL
MCP servers under `database/`.

## Repository Policy

Never commit `.env` files, database dumps, certificates, private keys, local
test output, or credentials. The server `.env.example` files are tracked
variable references only; users do not need to create `.env` files in this
repository. Run the repository check before committing:

```bash
bash scripts/check-sensitive-files.sh
```

## Servers

- [PostgreSQL MCP](database/psql-mcp/README.md)
- [MSSQL MCP](database/mssql-mcp/README.md)
- [MySQL MCP](database/mysql-mcp/README.md)

## Add to Claude Code

First clone this repository from GitHub, install the dependencies for the
servers you need, and configure a dedicated, least-privilege database account.
Do not create an `.env` file in this repository. Claude Code stores each
server's variables in the user's MCP host configuration and supplies them to
the local stdio process when it starts.

```bash
git clone https://github.com/devgirishattri/mcp-servers.git
cd mcp-servers
(cd database/psql-mcp && npm install)
(cd database/mssql-mcp && npm install)
(cd database/mysql-mcp && npm install)
```

The `claude mcp add` commands below use the `local` scope, which registers the
server in the user's Claude Code configuration for the current project
directory only; run them from the project where the servers should be
available. Use `-s user` instead to make a registration available across all
of the user's projects, or `-s project` to write a shared `.mcp.json` into the
project — do not use project scope with literal credentials in a tracked file.

Set the absolute repository path, securely read each database password into a
temporary shell variable, and register only the servers you need. Replace the
example connection values with the user's own database settings.

PostgreSQL:

```bash
MCP_REPO=/absolute/path/to/mcp-servers
read -r -s POSTGRES_MCP_PASSWORD

claude mcp add postgresql -s local \
  -e DB_HOST=localhost \
  -e DB_PORT=5432 \
  -e DB_NAME=your_database \
  -e DB_USER=mcp_ro \
  -e "DB_PASSWORD=$POSTGRES_MCP_PASSWORD" \
  -e DB_SSL_MODE=disable \
  -- node "$MCP_REPO/database/psql-mcp/index.js"

unset POSTGRES_MCP_PASSWORD
```

Microsoft SQL Server:

```bash
MCP_REPO=/absolute/path/to/mcp-servers
read -r -s MSSQL_MCP_PASSWORD

claude mcp add mssql -s local \
  -e DB_HOST=localhost \
  -e DB_PORT=1433 \
  -e DB_NAME=your_database \
  -e DB_USER=mcp_ro \
  -e "DB_PASSWORD=$MSSQL_MCP_PASSWORD" \
  -e DB_ENCRYPT=true \
  -e DB_TRUST_SERVER_CERTIFICATE=true \
  -- node "$MCP_REPO/database/mssql-mcp/index.js"

unset MSSQL_MCP_PASSWORD
```

MySQL:

```bash
MCP_REPO=/absolute/path/to/mcp-servers
read -r -s MYSQL_MCP_PASSWORD

claude mcp add mysql -s local \
  -e DB_HOST=localhost \
  -e DB_PORT=3306 \
  -e DB_NAME=your_database \
  -e DB_USER=mcp_ro \
  -e "DB_PASSWORD=$MYSQL_MCP_PASSWORD" \
  -e DB_SSL_MODE=disable \
  -- node "$MCP_REPO/database/mysql-mcp/index.js"

unset MYSQL_MCP_PASSWORD
```

Confirm the registrations with `claude mcp list`. In an interactive Claude
Code session, use `/mcp` to inspect active servers and their tools. See the
[Claude Code MCP documentation](https://docs.anthropic.com/en/docs/claude-code/mcp)
for scopes and advanced configuration. Protect access to the user's Claude
Code configuration because client-supplied environment values include database
credentials.

## Remove from Claude Code

Remove only the registrations that are no longer needed, from the same project
directory and scope in which they were added:

```bash
claude mcp remove postgresql -s local
claude mcp remove mssql -s local
claude mcp remove mysql -s local
```

Confirm the result with `claude mcp list`. These commands remove the MCP
entries from the user's Claude Code configuration; they do not delete this
repository, database data, or database accounts.

## Add to Codex

First install the dependencies in the server directory and configure a
dedicated, least-privilege database account. Do not create an `.env` file in
this repository. Codex stores each server's variables in the user's MCP host
configuration and supplies them to the local stdio process when it starts.

The `codex mcp add` commands below use Codex's default user-level configuration
at `~/.codex/config.toml`. The registrations are therefore available across
projects for the current operating-system user on that Codex host; they are not
installed for other operating-system users. The current CLI has no project
scope option for `codex mcp add`. For project-only registration, add the
equivalent MCP tables manually to that trusted project's `.codex/config.toml`
and do not place literal credentials in a tracked project file.

Set the absolute repository path, securely read each database password into a
temporary shell variable, and register only the servers you need. Replace the
example connection values with the user's own database settings.

PostgreSQL:

```bash
MCP_REPO=/absolute/path/to/mcp-servers
read -r -s POSTGRES_MCP_PASSWORD

codex mcp add postgresql \
  --env DB_HOST=localhost \
  --env DB_PORT=5432 \
  --env DB_NAME=your_database \
  --env DB_USER=mcp_ro \
  --env "DB_PASSWORD=$POSTGRES_MCP_PASSWORD" \
  --env DB_SSL_MODE=disable \
  -- node "$MCP_REPO/database/psql-mcp/index.js"

unset POSTGRES_MCP_PASSWORD
```

Microsoft SQL Server:

```bash
MCP_REPO=/absolute/path/to/mcp-servers
read -r -s MSSQL_MCP_PASSWORD

codex mcp add mssql \
  --env DB_HOST=localhost \
  --env DB_PORT=1433 \
  --env DB_NAME=your_database \
  --env DB_USER=mcp_ro \
  --env "DB_PASSWORD=$MSSQL_MCP_PASSWORD" \
  --env DB_ENCRYPT=true \
  --env DB_TRUST_SERVER_CERTIFICATE=true \
  -- node "$MCP_REPO/database/mssql-mcp/index.js"

unset MSSQL_MCP_PASSWORD
```

MySQL:

```bash
MCP_REPO=/absolute/path/to/mcp-servers
read -r -s MYSQL_MCP_PASSWORD

codex mcp add mysql \
  --env DB_HOST=localhost \
  --env DB_PORT=3306 \
  --env DB_NAME=your_database \
  --env DB_USER=mcp_ro \
  --env "DB_PASSWORD=$MYSQL_MCP_PASSWORD" \
  --env DB_SSL_MODE=disable \
  -- node "$MCP_REPO/database/mysql-mcp/index.js"

unset MYSQL_MCP_PASSWORD
```

Confirm the registrations with `codex mcp list`. In an interactive Codex
session, use `/mcp` to inspect active servers. The ChatGPT desktop app, Codex
CLI, and the IDE extension share the same host configuration. See the
[Codex MCP documentation](https://developers.openai.com/codex/mcp) for advanced
configuration and tool approval controls. Protect access to the user's Codex
configuration because client-supplied environment values include database
credentials.

## Remove from Codex

Remove only the user-level registrations that are no longer needed:

```bash
codex mcp remove postgresql
codex mcp remove mssql
codex mcp remove mysql
```

Confirm the result with `codex mcp list`. These commands remove the MCP entries
from the user's Codex configuration; they do not delete this repository,
database data, or database accounts. For a server configured manually in a
project's `.codex/config.toml`, remove its `[mcp_servers.<server-name>]` table
from that project file instead.

## Verification

```bash
(cd database/psql-mcp && npm test)
(cd database/mssql-mcp && npm test)
(cd database/mysql-mcp && npm test)
```

Live integration suites are documented in each server README. CI runs unit,
syntax, dependency, sensitive-file, PostgreSQL integration, MSSQL integration,
and MySQL integration checks. Each server includes a Docker Compose environment
for isolated local verification. PostgreSQL defaults to host port `55432`, and
MySQL defaults to host port `53306`, to avoid colliding with standard local
installations.
