# MySQL MCP Server

A Model Context Protocol (MCP) server for guarded MySQL 8.4 database access.

## Features

- Schema, table, view, and column discovery constrained by allowlists
- Optional raw `SELECT` with positional parameters, function allowlisting, and read-only transactions
- Optional confirmed insert, update, and delete tools for a separate write deployment
- Active-role privilege verification using MySQL `SHOW GRANTS`
- Row, column, field, response, input, request, connection, and statement limits
- One-row result streaming with connection disposal when a result is stopped early
- Parameterized values and validated, backtick-quoted identifiers
- Sanitized database errors and value-free mutation audit events
- Disabled, encrypted, or certificate-verified TLS modes

Stored procedure execution is intentionally not included. This server targets MySQL 8.4 LTS; MariaDB compatibility is not claimed.

## Installation

```bash
cd database/mysql-mcp
npm install
```

Register the server with an MCP host and supply its database variables there,
as shown in Claude Code Integration below or in the repository README. No
`.env` file needs to be created in this project; `.env.example` is a variable
reference only.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | MySQL host | `localhost` |
| `DB_PORT` | MySQL port | `3306` |
| `DB_NAME` | Application database and default `schema_name`; required | No default |
| `DB_USER` | Dedicated least-privilege MySQL account; required | No default |
| `DB_PASSWORD` | MySQL password | Empty |
| `DB_TIMEZONE` | `Z`, `local`, or a numeric offset such as `+05:30` | `Z` |
| `DB_SSL_MODE` | `disable`, `require`, or `verify-full` | Local: `disable`; remote: `verify-full` |
| `DB_SSL_CA_FILE` | Optional CA file for `verify-full`; relative paths resolve here | Node.js runtime-default CA trust |
| `MAX_CONNECTIONS` | Maximum pooled connections | `10` |
| `CONNECTION_TIMEOUT_MS` | Connection timeout in milliseconds | `10000` |
| `STATEMENT_TIMEOUT_MS` | MySQL and driver query timeout; `0` disables it | `30000` |
| `MAX_ROWS` | Raw-query and metadata row cap; `0` disables raw queries | `1000` |
| `MAX_AFFECTED_ROWS` | Update/delete row cap; `0` disables the cap | `100` |
| `MAX_RESPONSE_BYTES` | Maximum MCP text result size; `0` disables raw queries | `1000000` |
| `MAX_FIELD_BYTES` | Maximum serialized field size before omission | `65536` |
| `MAX_COLUMNS` | Raw-query and table-description column cap | `100` |
| `MAX_REQUEST_BYTES` | Maximum one-line MCP JSON-RPC request size | `262144` |
| `MAX_INPUT_BYTES` | Maximum serialized query/input component size | `65536` |
| `MAX_INPUT_ITEMS` | Maximum top-level parameter, data, or filter items | `100` |
| `MCP_MODE` | Separate deployment mode: `read` or `write` | `read` |
| `VERIFY_DB_PRIVILEGES` | Verify direct and enabled-role grants before first database use | `true` |
| `ALLOW_ARBITRARY_SELECT` | Expose `execute_query` | `false` |
| `ALLOWED_SCHEMAS` | Comma-separated database allowlist | `DB_NAME` |
| `ALLOWED_TABLES` | Optional comma-separated `database.table` allowlist | All tables in allowed databases |
| `ALLOWED_COLUMNS` | Optional `database.table.column` allowlist for structured tools | All allowed table columns |
| `ALLOWED_SELECT_FUNCTIONS` | Functions permitted in raw `SELECT` | Empty |
| `ALLOW_WRITES` | Expose insert and update tools | `false` |
| `ALLOW_DELETE` | Expose delete; also requires `ALLOW_WRITES=true` | `false` |
| `RETURN_MUTATION_ROWS` | Return bounded mutation snapshots; requires positive affected-row and response limits | `false` |
| `AUDIT_LOG` | Emit value-free mutation audit events to stderr | `true` |
| `DEBUG` | Log non-secret connection diagnostics | `false` |

`DB_SSL_MODE=require` encrypts the connection without verifying the server certificate. Use `verify-full` for remote production databases and provide `DB_SSL_CA_FILE` when the server certificate does not chain to the system trust store.

Schema, table, and column allowlists use exact-case matching. Copy object names exactly as MySQL reports them, particularly on servers where table names are case-sensitive.

## Database Account Boundary

Database grants are the primary security boundary. Do not connect as `root`, an administrative account, or an account with global privileges. Create a dedicated account for each MCP deployment and grant access only to the exact objects it needs.

Example read account:

```sql
CREATE USER 'mcp_ro'@'%' IDENTIFIED BY 'use-a-generated-secret';
GRANT SELECT ON `your_database`.`safe_reporting_view` TO 'mcp_ro'@'%';
```

If the account may only connect locally, replace `%` with the appropriate host. Prefer curated views when only selected columns or filtered rows should be visible. A view's security mode and definer privileges affect the data it exposes, so audit those properties separately.

For write tools, create a different account and grant only the enabled operations on exact tables:

```sql
CREATE USER 'mcp_rw'@'%' IDENTIFIED BY 'use-a-different-generated-secret';
GRANT SELECT, INSERT, UPDATE ON `your_database`.`review_queue` TO 'mcp_rw'@'%';
```

Add `DELETE` only when `ALLOW_DELETE=true`. Do not grant `FILE`, `PROCESS`, `SUPER`, `EXECUTE`, `CREATE TEMPORARY TABLES`, dynamic administrative privileges, privilege delegation, or access to other databases.

At first database use, `VERIFY_DB_PRIVILEGES=true` expands the session's enabled roles through `SHOW GRANTS ... USING` and rejects:

- global privileges other than `USAGE`;
- administrative, DDL, routine, or privilege-delegation capabilities;
- DML that is not enabled for the current mode;
- grants outside `ALLOWED_SCHEMAS` or `ALLOWED_TABLES`.

The check is intentionally conservative. An account that relies on global grants plus partial revocation is rejected; grant access directly to the intended database objects instead.

## Available Tools

The default read configuration exposes:

- `list_schemas`: List allowed MySQL databases. MySQL treats database and schema as synonyms.
- `list_tables`: List allowed base tables and views in a database.
- `describe_table`: Return allowed column metadata for a table or view.

`ALLOW_ARBITRARY_SELECT=true` additionally exposes `execute_query`. Raw queries use an array of positional values for `?` placeholders:

```json
{
  "query": "SELECT id, status FROM reporting_view WHERE status = ? ORDER BY id",
  "parameters": ["active"]
}
```

`ALLOWED_COLUMNS` is incompatible with raw query mode. Use curated views for a database-enforced column boundary.

A separate `MCP_MODE=write` process with `ALLOW_WRITES=true` exposes `execute_insert` and `execute_update`. `ALLOW_DELETE=true` also exposes `execute_delete`. Every mutation tool call requires `confirm: true` after explicit user approval.

Structured update/delete filters are joined with `AND`. Supported operators are `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `like`, `in`, `is_null`, and `is_not_null`.

```json
{
  "table": "review_queue",
  "schema_name": "your_database",
  "data": { "status": "archived" },
  "filters": [
    { "column": "id", "operator": "in", "value": [12, 19] }
  ],
  "confirm": true
}
```

Updates and deletes run in serializable transactions. When `MAX_AFFECTED_ROWS` is positive, the target rows are locked and counted before mutation, and the transaction rolls back if the target exceeds the cap. Because MySQL does not provide generic DML `RETURNING`, `RETURN_MUTATION_ROWS=true` returns the inserted input or the bounded row snapshots captured before update/delete. It requires positive `MAX_AFFECTED_ROWS` and `MAX_RESPONSE_BYTES` limits.

## Raw Query Guards

When explicitly enabled, `execute_query`:

- accepts one statement beginning with `SELECT` and permits one trailing semicolon;
- uses `multipleStatements=false` and MySQL's server-side prepared-statement protocol, including when the parameter array is empty;
- rejects comments, interior semicolons, user/system variables, assignment, transaction/session commands, DDL, DML, `INTO OUTFILE`, `INTO DUMPFILE`, and locking reads;
- rejects quoted function names and requires every ordinary function call to be allowlisted;
- always blocks file, timing, named-lock, replication-wait, and session-state functions such as `LOAD_FILE`, `SLEEP`, `BENCHMARK`, `GET_LOCK`, and `LAST_INSERT_ID`;
- runs inside `START TRANSACTION READ ONLY` with a session execution timeout;
- streams one row at a time, replaces fields exceeding the field cap with an omission marker, and stops at the column, row, or response cap;
- destroys rather than pools a connection whenever result consumption stops early.

MySQL's `NO_BACKSLASH_ESCAPES` SQL mode changes how quoted text is parsed. To avoid an interpretation mismatch between the validator and database, raw queries containing a backslash inside any quoted literal or identifier are rejected. Bind such values as `?` parameters instead.

`START TRANSACTION READ ONLY` can still permit operations on temporary tables, so the query validator also rejects temporary-table and locking syntax. The validator remains defense in depth; least-privilege database grants are mandatory.

`MAX_FIELD_BYTES` limits what the MCP response retains, but a MySQL client receives a complete row packet before it can inspect and omit an oversized field. Configure the database server's `max_allowed_packet` appropriately and use curated views that exclude unneeded large `BLOB` or `TEXT` columns. Mutation snapshots are streamed and bounded before an update or delete proceeds.

## Claude Code Integration

Supply the database variables when the user registers the MCP server. This
keeps configuration with the MCP host instead of creating an `.env` file in the
project. The password is read silently so its literal value is not saved in
shell history.

```bash
read -r -s MYSQL_MCP_PASSWORD

claude mcp add mysql -s local \
  -e DB_HOST=localhost \
  -e DB_PORT=3306 \
  -e DB_NAME=your_database \
  -e DB_USER=mcp_ro \
  -e "DB_PASSWORD=$MYSQL_MCP_PASSWORD" \
  -e DB_SSL_MODE=disable \
  -- node /absolute/path/to/mcp-servers/database/mysql-mcp/index.js

unset MYSQL_MCP_PASSWORD
```

## Development and Integration Tests

```bash
npm test
npm audit --omit=dev
```

For an isolated MySQL 8.4 environment, the included Compose service binds host port `53306` by default:

```bash
read -r -s MYSQL_ROOT_PASSWORD
export MYSQL_ROOT_PASSWORD
docker-compose up -d

DB_HOST=localhost DB_PORT=53306 DB_USER=root \
  DB_PASSWORD="$MYSQL_ROOT_PASSWORD" npm run test:integration
```

The live suite uses the supplied administrator connection to provision isolated fixtures and accounts, validate rollback behavior, and clean them up afterward. It verifies discovery, raw-query limits, field omission, column allowlisting, controlled mutations, rollback of oversized mutations, and rejection of the administrator account. Temporary users and the database are removed afterward; credentials are never written to the repository.

Environments with the Docker Compose CLI plugin can use `docker compose` instead of `docker-compose`.

## License

MIT
