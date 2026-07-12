# PostgreSQL MCP Server

A Model Context Protocol (MCP) server for guarded PostgreSQL database access.

## Features

- Optional raw `SELECT` execution inside dedicated read-only transactions; disabled by default
- Schema, table, and column identifier validation and quoting
- Schema, table, and SELECT-function allowlists
- First-database-use rejection of superuser, administrative, server-file, backend-signaling, table-write, and sequence-write privileges in read mode
- Optional insert, update, and delete tools with a default-deny policy
- Structured, parameterized write filters with affected-row limits
- Request, input, row, response-size, connection, and statement limits
- Normalized database errors and value-free mutation audit events
- PostgreSQL session timezone configuration
- Disabled, encrypted, or certificate-verified TLS modes

## Installation

1. Navigate to the server directory:

   ```bash
   cd database/psql-mcp
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Register the server with an MCP host and supply its database variables there,
   as shown in the client integration sections below or in the repository
   README.

## Configuration

The server reads configuration from the environment supplied by the MCP host
when it starts the process. No `.env` file needs to be created in this project;
`.env.example` is a variable reference only.

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_NAME` | Database name | `postgres` |
| `DB_USER` | Dedicated database role; required and must not be empty | No default |
| `DB_PASSWORD` | Database password | Empty |
| `DB_TIMEZONE` | Session timezone | `UTC` |
| `DB_SSL_MODE` | `disable`, `require`, or `verify-full` | Local: `disable`; remote: `verify-full` |
| `DB_SSL_CA_FILE` | Optional CA file for `verify-full`; relative paths resolve from this directory | Node.js runtime-default CA trust |
| `MAX_CONNECTIONS` | Maximum pooled connections | `10` |
| `CONNECTION_TIMEOUT_MS` | Connection timeout in milliseconds | `10000` |
| `STATEMENT_TIMEOUT_MS` | Statement timeout; `0` disables it | `30000` |
| `MAX_ROWS` | Maximum rows returned by `execute_query`; `0` disables raw SELECT | `1000` |
| `MAX_AFFECTED_ROWS` | Maximum rows changed by one update/delete; `0` disables it | `100` |
| `MAX_RESPONSE_BYTES` | Maximum MCP text result size; `0` disables raw SELECT | `1000000` |
| `MAX_FIELD_BYTES` | Server-side maximum serialized field size for raw SELECT | `65536` |
| `MAX_COLUMNS` | Maximum columns returned by raw SELECT | `100` |
| `MAX_REQUEST_BYTES` | Maximum one-line MCP JSON-RPC request size | `262144` |
| `MAX_INPUT_BYTES` | Maximum serialized tool input/query component size | `65536` |
| `MAX_INPUT_ITEMS` | Maximum top-level parameter, data, or filter items | `100` |
| `MCP_MODE` | Separate deployment mode: `read` or `write` | `read` |
| `VERIFY_DB_PRIVILEGES` | Reject unsafe effective database privileges at first use | `true` |
| `ALLOW_ARBITRARY_SELECT` | Expose `execute_query`; requires read-only DB grants | `false` |
| `ALLOWED_SCHEMAS` | Comma-separated schema allowlist for structured tools | `public` |
| `ALLOWED_TABLES` | Optional comma-separated `schema.table` allowlist for structured tools | All tables in allowed schemas |
| `ALLOWED_COLUMNS` | Optional comma-separated `schema.table.column` allowlist for structured tools | All columns in allowed tables |
| `ALLOWED_SELECT_FUNCTIONS` | Lowercase functions permitted in optional raw SELECT queries; qualified calls require `schema.function` | Empty |
| `ALLOW_WRITES` | Expose and enable insert/update tools | `false` |
| `ALLOW_DELETE` | Expose and enable delete; also requires `ALLOW_WRITES=true` | `false` |
| `RETURN_MUTATION_ROWS` | Return full changed rows; otherwise return counts only | `false` |
| `AUDIT_LOG` | Emit value-free mutation audit events to stderr | `true` |
| `DEBUG` | Log non-secret connection details | `false` |

`DB_SSL_MODE=require` encrypts traffic without verifying the server certificate. Use `verify-full` for production verification, optionally with `DB_SSL_CA_FILE`. The legacy `DB_SSL=true` setting remains equivalent to `require` when `DB_SSL_MODE` is unset.

### Database role

Database permissions are the primary security boundary. Do not connect this server as `postgres`, a superuser, or a member of administrative roles. Create a dedicated non-superuser role and grant it access only to the schemas and objects the MCP is intended to read. For example, run an equivalent policy as a database administrator and replace the database, schema, owner, and secret values:

```sql
CREATE ROLE mcp_ro LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS PASSWORD 'use-a-generated-secret';
GRANT CONNECT ON DATABASE your_database TO mcp_ro;
GRANT USAGE ON SCHEMA reporting TO mcp_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA reporting TO mcp_ro;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA reporting
  GRANT SELECT ON TABLES TO mcp_ro;
ALTER ROLE mcp_ro SET default_transaction_read_only = on;
```

Audit direct, inherited, and `PUBLIC` function execution privileges for this role. In particular, do not grant `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program`, `pg_signal_backend`, or other administrative memberships. Use a separate, narrowly granted role if write tools are enabled.

## Available Tools

The default configuration exposes only:

- `describe_table`: Return the validated table structure.
- `list_tables`: List tables in a validated schema.
- `list_schemas`: List allowlisted non-system schemas.

Setting `ALLOW_ARBITRARY_SELECT=true` exposes `execute_query`; every called
function must also appear in `ALLOWED_SELECT_FUNCTIONS`, while dangerous host,
large-object, backend-signaling, and advisory-lock functions remain blocked.
`ALLOWED_COLUMNS` is intentionally incompatible with arbitrary SELECT; keep raw
SELECT disabled or expose curated views when column-level boundaries are needed.

`ALLOWED_SCHEMAS`, `ALLOWED_TABLES`, and `ALLOWED_COLUMNS` constrain structured
discovery and mutation tools. Raw SELECT table access is not inferred from SQL
text; constrain it with PostgreSQL grants or curated views. Function allowlist
entries are normalized to lowercase, schema-qualified calls require a matching
`schema.function` entry, and quoted identifiers are matched case-sensitively.
Mixed-case quoted function names therefore cannot be enabled through the
current environment-variable allowlist.

Write tools require a separate `MCP_MODE=write` deployment plus
`ALLOW_WRITES=true`. Delete additionally requires `ALLOW_DELETE=true`. Every
mutation tool request requires `confirm: true` after explicit user approval.

### Structured Filters

`execute_update` and `execute_delete` require a non-empty `filters` array. Filters are joined with `AND`; column names are validated and values are parameterized.

Supported operators are `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `like`, `in`, `is_null`, and `is_not_null`. Omit `value` for the two null operators.

```json
{
  "table": "users",
  "data": { "status": "inactive" },
  "filters": [
    { "column": "last_login_at", "operator": "lt", "value": "2025-01-01" },
    { "column": "status", "operator": "in", "value": ["pending", "active"] }
  ],
  "schema_name": "public",
  "confirm": true
}
```

Updates and deletes execute in serializable transactions. The server checks the target set before mutation and rolls the transaction back if it exceeds `MAX_AFFECTED_ROWS`.

Under concurrent writes, PostgreSQL can abort a serializable transaction with SQLSTATE `40001`. The tool returns an MCP error and the caller can retry the complete operation.

## Read Query Guards

When explicitly enabled, `execute_query`:

- accepts one statement beginning with `SELECT`;
- permits one optional trailing semicolon but rejects interior semicolons, SQL comments, transaction control, and mutation/DDL keywords outside string literals and quoted identifiers;
- forces PostgreSQL's extended query protocol, including for an empty parameter list, so the database parser rejects multiple statements;
- runs on a dedicated connection inside `BEGIN READ ONLY` and always rolls back;
- detects quoted, unquoted, and schema-qualified function calls, requires every call to be allowlisted, and always blocks known privileged functions;
- applies a server-side field cap, fetches one row at a time through a transaction-scoped cursor, and stops before `MAX_ROWS`, `MAX_COLUMNS`, or `MAX_RESPONSE_BYTES` is exceeded.

The query validator is defense in depth, not a replacement for database permissions. `VERIFY_DB_PRIVILEGES=true` rejects unsafe read-mode roles, but grants should still be restricted to the allowed schemas, tables, and functions.

## TLS Modes

- `disable`: Do not use TLS.
- `require`: Encrypt without certificate verification.
- `verify-full`: Verify the certificate chain and the DNS or IP identity in `DB_HOST` using Node.js runtime-default CA trust or `DB_SSL_CA_FILE`.

## Claude Code Integration

Supply the database variables when the user registers the MCP server. This
keeps configuration with the MCP host instead of creating an `.env` file in the
project. The password is read silently so its literal value is not saved in
shell history.

The command below uses Claude Code's `local` scope. Run it from the project
where this server should be available. Use `-s user` instead to make the
registration available across all of the user's projects. Do not use
`-s project` with literal credentials in a tracked `.mcp.json` file.

```bash
read -r -s POSTGRES_MCP_PASSWORD

claude mcp add postgresql -s local \
  -e DB_HOST=localhost \
  -e DB_PORT=5432 \
  -e DB_NAME=your_database \
  -e DB_USER=mcp_ro \
  -e "DB_PASSWORD=$POSTGRES_MCP_PASSWORD" \
  -e DB_SSL_MODE=disable \
  -- node /absolute/path/to/mcp-servers/database/psql-mcp/index.js

unset POSTGRES_MCP_PASSWORD
```

Confirm the registration with `claude mcp list`. Remove it from the same
project directory and scope with:

```bash
claude mcp remove postgresql -s local
```

Removing the registration does not delete this repository, database data, or
the database account.

## Codex Integration

Codex stores CLI-added MCP servers in the current user's default configuration
at `~/.codex/config.toml`, making them available across that user's projects on
the same Codex host. The current `codex mcp add` command has no project-scope
option. For project-only registration, add the equivalent MCP table manually
to a trusted project's `.codex/config.toml` and do not place literal
credentials in a tracked project file.

Supply the database variables during registration. The password is read
silently so its literal value is not saved in shell history:

```bash
read -r -s POSTGRES_MCP_PASSWORD

codex mcp add postgresql \
  --env DB_HOST=localhost \
  --env DB_PORT=5432 \
  --env DB_NAME=your_database \
  --env DB_USER=mcp_ro \
  --env "DB_PASSWORD=$POSTGRES_MCP_PASSWORD" \
  --env DB_SSL_MODE=disable \
  -- node /absolute/path/to/mcp-servers/database/psql-mcp/index.js

unset POSTGRES_MCP_PASSWORD
```

Confirm the registration with `codex mcp list`. Remove the user-level
registration with:

```bash
codex mcp remove postgresql
```

Removing the registration does not delete this repository, database data, or
the database account. Protect access to the user's Codex configuration because
client-supplied environment values include database credentials. See the
[Codex MCP documentation](https://developers.openai.com/codex/mcp) for advanced
configuration and tool approval controls.

## Development

```bash
npm test
npm run dev
```

For an isolated local PostgreSQL integration environment, use the included
Compose service. It binds to port `55432` by default so it can coexist with a
PostgreSQL instance on the standard port:

```bash
read -r -s POSTGRES_PASSWORD
export POSTGRES_PASSWORD
docker-compose up -d
DB_HOST=localhost DB_PORT=55432 DB_NAME=mcp_mcp_test DB_USER=postgres \
  DB_PASSWORD="$POSTGRES_PASSWORD" npm run test:integration
```

The integration suite is opt-in and reads administrator connection values from
`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD`. It creates an
isolated temporary schema and least-privilege login, verifies the MCP through
that login, and removes both afterward. Credentials are never written to the
repository.

These examples use the standalone `docker-compose` command installed by
Homebrew. Environments with the Docker Compose CLI plugin can use
`docker compose` instead.

## License

MIT
