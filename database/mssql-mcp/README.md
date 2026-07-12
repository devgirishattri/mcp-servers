# MCP MSSQL Server

A Model Context Protocol (MCP) server that provides tools for interacting with Microsoft SQL Server databases.

## Features

- **Query Execution**: Optional allowlisted SELECT queries; disabled by default
- **Schema Inspection**: List allowed schemas/tables and describe allowed table structures
- **Data Manipulation**: Optional insert, update, and delete tools with structured filters and affected-row limits
- **Stored Procedures**: Optional stored procedure execution with an allowlist
- **Connection Pooling**: Efficient connection management with configurable pool settings
- **Security**: Least-privilege verification, encrypted connections, object/function allowlists, normalized errors, and parameterized values

## Installation

1. From the workspace root, enter the server directory:
   ```bash
   cd database/mssql-mcp
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

Configure the following variables in the MCP host:

### Connection Settings
- `DB_HOST`: SQL Server hostname (default: localhost)
- `DB_PORT`: SQL Server port (default: 1433)
- `DB_USER`: Dedicated least-privilege database login (required; no default)
- `DB_PASSWORD`: Database password (default: empty)
- `DB_NAME`: Database name to connect to (default: master)

### Optional Settings
- `MAX_CONNECTIONS`: Maximum connections in pool (default: 10)
- `CONNECTION_TIMEOUT_MS`: Connection timeout in milliseconds (default: 10000)
- `STATEMENT_TIMEOUT_MS`: Statement timeout in milliseconds; set `0` to disable (default: 30000)
- `MAX_ROWS`: Maximum rows returned by `execute_query`; set `0` to disable (default: 1000)
- `MAX_AFFECTED_ROWS`: Maximum rows changed by one update/delete; set `0` to disable (default: 100)
- `MAX_RESPONSE_BYTES`: Maximum MCP text result size; set `0` to disable (default: 1000000)
- `MAX_FIELD_BYTES`: SQL Server `TEXTSIZE` cap for raw SELECT fields (default: 65536)
- `MAX_COLUMNS`: Maximum columns accepted from raw SELECT (default: 100)
- `MAX_REQUEST_BYTES`: Maximum one-line MCP request size (default: 262144)
- `MAX_INPUT_BYTES`: Maximum serialized tool input component (default: 65536)
- `MAX_INPUT_ITEMS`: Maximum top-level parameter/data/filter items (default: 100)
- `DB_ENCRYPT`: Enable connection encryption (default: true)
- `DB_TRUST_SERVER_CERTIFICATE`: Trust server certificate (default: true locally, false remotely)
- `DEBUG`: Enable startup connection logging (default: false)
- `MCP_MODE`: Separate deployment mode, `read` or `write` (default: read)
- `VERIFY_DB_PRIVILEGES`: Reject unsafe effective database privileges (default: true)
- `ALLOW_ARBITRARY_SELECT`: Expose `execute_query` (default: false)
- `ALLOW_DATABASE_LIST`: Expose `list_databases` (default: false)
- `ALLOWED_SCHEMAS`: Comma-separated schema allowlist (default: dbo)
- `ALLOWED_TABLES`: Optional comma-separated `schema.table` allowlist
- `ALLOWED_COLUMNS`: Optional comma-separated `schema.table.column` allowlist for structured tools
- `ALLOWED_SELECT_FUNCTIONS`: Comma-separated function allowlist for raw SELECT
- `ALLOW_WRITES`: Enable insert and update tools (default: false)
- `ALLOW_DELETE`: Enable delete tool; also requires `ALLOW_WRITES=true` (default: false)
- `RETURN_MUTATION_ROWS`: Return changed rows instead of counts only (default: false)
- `AUDIT_LOG`: Emit value-free mutation audit events to stderr (default: true)
- `ALLOW_STORED_PROCEDURES`: Enable stored procedure tool (default: false)
- `ALLOWED_PROCEDURES`: Comma-separated, schema-qualified stored procedure allowlist, such as `dbo.GetUsersByStatus`

## Available Tools

### Query Operations
- **execute_query**: Execute a single allowlisted SELECT with named parameters when `ALLOW_ARBITRARY_SELECT=true`

`ALLOWED_COLUMNS` is intentionally incompatible with arbitrary SELECT. Keep
raw SELECT disabled or expose curated views when column-level boundaries are
required.

### Schema Inspection
- **list_databases**: List user databases only when `ALLOW_DATABASE_LIST=true`
- **list_schemas**: List allowlisted, non-system schemas in the current database
- **list_tables**: List allowlisted tables in an allowlisted schema
- **describe_table**: Get allowed column details for an allowlisted table

### Data Manipulation
- **execute_insert**: Insert new records into a table when `ALLOW_WRITES=true`
- **execute_update**: Update records matching structured filters when `ALLOW_WRITES=true`
- **execute_delete**: Delete records matching structured filters when `ALLOW_WRITES=true` and `ALLOW_DELETE=true`

### Stored Procedures
- **execute_stored_procedure**: Execute allowlisted stored procedures in `MCP_MODE=write` when `ALLOW_STORED_PROCEDURES=true` and `confirm: true`

## Usage Examples

### Basic Query
```json
{
  "name": "execute_query",
  "arguments": {
    "query": "SELECT TOP 10 * FROM dbo.Users WHERE status = @status",
    "parameters": {
      "status": "active"
    }
  }
}
```

### List Tables
```json
{
  "name": "list_tables",
  "arguments": {
    "schema_name": "dbo"
  }
}
```

### Describe Table
```json
{
  "name": "describe_table",
  "arguments": {
    "table_name": "Users",
    "schema_name": "dbo"
  }
}
```

### Insert Data
```json
{
  "name": "execute_insert",
  "arguments": {
    "table": "Users",
    "data": {
      "name": "John Doe",
      "email": "john@example.com",
      "status": "active"
    },
    "schema_name": "dbo",
    "confirm": true
  }
}
```

### Update Data
```json
{
  "name": "execute_update",
  "arguments": {
    "table": "Users",
    "data": { "status": "inactive" },
    "filters": [
      { "column": "last_login_at", "operator": "lt", "value": "2025-01-01" },
      { "column": "status", "operator": "in", "value": ["pending", "active"] }
    ],
    "schema_name": "dbo",
    "confirm": true
  }
}
```

Structured filters are joined with `AND`. Supported operators are `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `like`, `in`, `is_null`, and `is_not_null`. Omit `value` for the two null operators.

Under concurrent writes, SQL Server can abort a serializable transaction because of a deadlock or serialization conflict. The tool returns an MCP error and the caller can retry the complete operation.

### Execute Stored Procedure
```json
{
  "name": "execute_stored_procedure",
  "arguments": {
    "procedure_name": "GetUsersByStatus",
    "parameters": {
      "status": "active",
      "limit": 100
    },
    "schema_name": "dbo",
    "confirm": true
  }
}
```

## Security Features

- **Parameterized Values**: Tool-supplied data and filter values are bound as parameters; identifiers are validated and quoted
- **Read-Only by Default**: Mutating tools and stored procedure execution are hidden unless explicitly enabled
- **Raw Query Disabled by Default**: `execute_query` requires explicit enablement and function allowlisting
- **Effective-Permission Check**: Read mode rejects administrative, table-write, and sequence-write capability
- **Row Limit Guard**: `execute_query` limits returned rows with `MAX_ROWS` by default
- **Affected-Row Guard**: Updates and deletes use serializable transactions and roll back when `MAX_AFFECTED_ROWS` is exceeded
- **Resource Limits**: MCP request, input, connection, statement, row, and response-size limits are configurable
- **Identifier Guards**: Schema, table, column, procedure, and parameter names are validated before SQL is assembled
- **Structured Write Filters**: Update/delete predicates use validated operators and parameterized values instead of raw SQL fragments
- **Stored Procedure Allowlist**: Procedure execution requires both an enable flag and `ALLOWED_PROCEDURES`
- **Encrypted Connections**: SSL/TLS encryption enabled by default
- **Connection Pooling**: Efficient resource management with configurable limits

For production certificate verification, set `DB_TRUST_SERVER_CERTIFICATE=false` and ensure the SQL Server certificate chains to a trusted CA.

The SELECT and function checks are defense in depth. Database permissions are
the primary security boundary, and `VERIFY_DB_PRIVILEGES=true` rejects unsafe
read-mode identities. Do not connect as `sa`, a sysadmin, or a broadly
privileged login. Create a dedicated login and database user, then grant
`SELECT` only on the specific schemas, views, or tables the MCP should expose.
For example, adapt and run the following as an administrator:

```sql
CREATE LOGIN mcp_ro WITH PASSWORD = 'use-a-generated-secret';
USE [your_database];
CREATE USER mcp_ro FOR LOGIN mcp_ro;
GRANT CONNECT TO mcp_ro;
GRANT SELECT ON OBJECT::reporting.McpOrders TO mcp_ro;
```

Use a separate `MCP_MODE=write` deployment and narrowly granted login if write
or stored-procedure tools are enabled. Mutation calls require `confirm: true`
and emit audit events without parameter values.

## Error Handling

Policy and validation errors are returned to the caller. Driver/database errors
are normalized to a generic message with a correlation identifier so object and
infrastructure details are not disclosed through MCP.

## Development

To run in development mode with debugging:

```bash
npm run dev
```

This starts the server with Node.js inspector enabled on the default debugging port.

Run the automated guard tests with:

```bash
npm test
```

For a reproducible local SQL Server test environment:

```bash
read -r -s MSSQL_SA_PASSWORD
export MSSQL_SA_PASSWORD
docker-compose up -d
DB_HOST=localhost DB_PORT=1433 DB_NAME=mcp_mcp_test DB_USER=sa \
  DB_PASSWORD="$MSSQL_SA_PASSWORD" npm run test:integration
```

The integration suite creates the `mcp_mcp_test` sample database and
`dbo.sample` table, uses a temporary least-privilege login for MCP checks, and
removes that login afterward. The sample database remains available for later
test runs.

This example uses the standalone `docker-compose` command installed by
Homebrew. Environments with the Docker Compose CLI plugin can use
`docker compose` instead.

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
read -r -s MSSQL_MCP_PASSWORD

claude mcp add mssql -s local \
  -e DB_HOST=localhost \
  -e DB_PORT=1433 \
  -e DB_NAME=your_database \
  -e DB_USER=mcp_ro \
  -e "DB_PASSWORD=$MSSQL_MCP_PASSWORD" \
  -e DB_ENCRYPT=true \
  -e DB_TRUST_SERVER_CERTIFICATE=true \
  -- node /absolute/path/to/mcp-servers/database/mssql-mcp/index.js

unset MSSQL_MCP_PASSWORD
```

Confirm the registration with `claude mcp list`. Remove it from the same
project directory and scope with:

```bash
claude mcp remove mssql -s local
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
read -r -s MSSQL_MCP_PASSWORD

codex mcp add mssql \
  --env DB_HOST=localhost \
  --env DB_PORT=1433 \
  --env DB_NAME=your_database \
  --env DB_USER=mcp_ro \
  --env "DB_PASSWORD=$MSSQL_MCP_PASSWORD" \
  --env DB_ENCRYPT=true \
  --env DB_TRUST_SERVER_CERTIFICATE=true \
  -- node /absolute/path/to/mcp-servers/database/mssql-mcp/index.js

unset MSSQL_MCP_PASSWORD
```

Confirm the registration with `codex mcp list`. Remove the user-level
registration with:

```bash
codex mcp remove mssql
```

Removing the registration does not delete this repository, database data, or
the database account. Protect access to the user's Codex configuration because
client-supplied environment values include database credentials. See the
[Codex MCP documentation](https://developers.openai.com/codex/mcp) for advanced
configuration and tool approval controls.

## License

MIT License - see package.json for details.

## Contributing

Contributions welcome! Please ensure all database operations maintain security best practices and include appropriate error handling.
