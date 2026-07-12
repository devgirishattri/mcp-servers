#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import dotenv from "dotenv";
import pg from "pg";
import {
  assertAllowedSchema,
  assertAllowedTable,
  assertAllowedColumn,
  allowedColumnNames,
  assertAllowedFunctions,
  assertInputBudget,
  auditMutation,
  createSafeErrorResult,
  createLimitedLineInput,
  createJsonResult as createSharedJsonResult,
  FILTERS_INPUT_SCHEMA,
  parseCsvSet,
  parseNonNegativeInteger as parseSharedNonNegativeInteger,
  parsePositiveInteger as parseSharedPositiveInteger,
  requireMutationConfirmation,
  validateDataObject as validateSharedDataObject,
  validateFilters as validateSharedFilters,
  validateIdentifier as validateSharedIdentifier,
} from "../shared/security.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const envPath = join(__dirname, ".env");
const envResult = dotenv.config({ path: envPath, override: false });
const debugEnabled = process.env.DEBUG === "true";

function debugLog(message) {
  if (debugEnabled) {
    console.error(message);
  }
}

if (envResult.error) {
  debugLog(`[PostgreSQL MCP] Error loading .env file: code=${envResult.error.code || envResult.error.name || "unknown"}`);
} else {
  debugLog(`[PostgreSQL MCP] .env file loaded from: ${envPath}`);
}

const { Pool } = pg;
const TIMEZONE_PATTERN = /^[A-Za-z0-9_+-]+(?:\/[A-Za-z0-9_+-]+)*$/;
const FORBIDDEN_SQL_PATTERN = /(;|--|\/\*|\*\/|\b(insert|update|delete|merge|drop|alter|create|truncate|exec|execute|grant|revoke|backup|restore|into|begin|commit|rollback|savepoint)\b)/i;

function maskSqlLiterals(query) {
  const characters = Array.from(query);

  for (let index = 0; index < query.length; index += 1) {
    const character = query[index];

    if (character === "'" || character === '"') {
      const quote = character;
      const escapeString =
        quote === "'" &&
        (query[index - 1] === "E" || query[index - 1] === "e") &&
        (index < 2 || !/[A-Za-z0-9_$]/.test(query[index - 2]));
      characters[index] = " ";
      index += 1;
      let terminated = false;

      while (index < query.length) {
        characters[index] = query[index] === "\n" ? "\n" : " ";
        if (query[index] === "\\" && escapeString) {
          index += 1;
          if (index < query.length) {
            characters[index] = query[index] === "\n" ? "\n" : " ";
          }
        } else if (query[index] === quote) {
          if (query[index + 1] === quote) {
            index += 1;
            characters[index] = " ";
          } else {
            terminated = true;
            break;
          }
        }
        index += 1;
      }
      if (!terminated) {
        throw new Error("Query contains an unterminated quoted literal or identifier.");
      }
      continue;
    }

    if (character === "$") {
      const tagMatch = query.slice(index).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/);
      if (!tagMatch) {
        continue;
      }

      const tag = tagMatch[0];
      const closingIndex = query.indexOf(tag, index + tag.length);
      if (closingIndex < 0) {
        throw new Error("Query contains an unterminated dollar-quoted literal.");
      }
      const endIndex = closingIndex + tag.length;
      while (index < endIndex) {
        characters[index] = query[index] === "\n" ? "\n" : " ";
        index += 1;
      }
      index -= 1;
    }
  }

  return characters.join("");
}

function normalizeSelectQuery(query) {
  if (typeof query !== "string" || query.trim().length === 0) {
    throw new Error("Query is required.");
  }

  let normalizedQuery = query.trim();
  const maskedQuery = maskSqlLiterals(normalizedQuery);
  if (maskedQuery.endsWith(";")) {
    normalizedQuery = normalizedQuery.slice(0, -1).trimEnd();
  }
  return normalizedQuery;
}

class PostgreSQLMCPServer {
  constructor() {
    this.mode = (process.env.MCP_MODE || "read").toLowerCase();
    if (!["read", "write"].includes(this.mode)) {
      throw new Error("MCP_MODE must be either read or write.");
    }
    this.allowWrites = process.env.ALLOW_WRITES === "true";
    this.allowDelete = process.env.ALLOW_DELETE === "true";
    this.returnMutationRows = process.env.RETURN_MUTATION_ROWS === "true";
    if (this.allowWrites && this.mode !== "write") {
      throw new Error("ALLOW_WRITES=true requires a separate MCP_MODE=write deployment.");
    }
    this.allowArbitrarySelect = process.env.ALLOW_ARBITRARY_SELECT === "true";
    this.allowedSchemas = parseCsvSet(process.env.ALLOWED_SCHEMAS, "public");
    this.allowedTables = parseCsvSet(process.env.ALLOWED_TABLES);
    this.allowedColumns = parseCsvSet(process.env.ALLOWED_COLUMNS);
    if (this.allowArbitrarySelect && this.allowedColumns.size > 0) {
      throw new Error(
        "ALLOWED_COLUMNS requires ALLOW_ARBITRARY_SELECT=false; expose curated views for raw-query deployments."
      );
    }
    this.allowedSelectFunctions = parseCsvSet(process.env.ALLOWED_SELECT_FUNCTIONS);
    this.forbiddenSelectFunctions = parseCsvSet(
      "pg_read_file,pg_read_binary_file,pg_ls_dir,pg_ls_logdir,pg_ls_waldir,pg_ls_tmpdir,pg_stat_file,pg_current_logfile,lo_import,lo_export,lo_get,lo_put,lo_from_bytea,pg_terminate_backend,pg_cancel_backend,pg_advisory_lock"
    );
    this.verifyDbPrivileges = process.env.VERIFY_DB_PRIVILEGES !== "false";
    this.maxRows = this.parseNonNegativeInteger(process.env.MAX_ROWS, 1000, "MAX_ROWS");
    this.maxAffectedRows = this.parseNonNegativeInteger(
      process.env.MAX_AFFECTED_ROWS,
      100,
      "MAX_AFFECTED_ROWS"
    );
    this.maxResponseBytes = this.parseNonNegativeInteger(
      process.env.MAX_RESPONSE_BYTES,
      1000000,
      "MAX_RESPONSE_BYTES"
    );
    this.maxFieldBytes = this.parsePositiveInteger(
      process.env.MAX_FIELD_BYTES,
      65536,
      "MAX_FIELD_BYTES"
    );
    this.maxColumns = this.parsePositiveInteger(
      process.env.MAX_COLUMNS,
      100,
      "MAX_COLUMNS"
    );
    this.statementTimeoutMs = this.parseNonNegativeInteger(
      process.env.STATEMENT_TIMEOUT_MS,
      30000,
      "STATEMENT_TIMEOUT_MS"
    );
    this.connectionTimeoutMs = this.parseNonNegativeInteger(
      process.env.CONNECTION_TIMEOUT_MS,
      10000,
      "CONNECTION_TIMEOUT_MS"
    );
    this.maxInputBytes = this.parsePositiveInteger(
      process.env.MAX_INPUT_BYTES,
      65536,
      "MAX_INPUT_BYTES"
    );
    this.maxInputItems = this.parsePositiveInteger(
      process.env.MAX_INPUT_ITEMS,
      100,
      "MAX_INPUT_ITEMS"
    );
    this.maxRequestBytes = this.parsePositiveInteger(
      process.env.MAX_REQUEST_BYTES,
      262144,
      "MAX_REQUEST_BYTES"
    );

    this.server = new Server(
      {
        name: "postgresql-mcp-server",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.pool = new Pool(this.buildConnectionConfig());
    this.securityVerificationPromise = null;
    this.securityVerified = false;
    this.setupToolHandlers();
    this.setupErrorHandlers();
  }

  parseNonNegativeInteger(value, defaultValue, label) {
    return parseSharedNonNegativeInteger(value, defaultValue, label);
  }

  parsePositiveInteger(value, defaultValue, label) {
    return parseSharedPositiveInteger(value, defaultValue, label);
  }

  buildSslConfig() {
    const host = (process.env.DB_HOST || "localhost").toLowerCase();
    const localHost = ["localhost", "127.0.0.1", "::1"].includes(host);
    const legacyMode = process.env.DB_SSL === "true" ? "require" : localHost ? "disable" : "verify-full";
    const mode = (process.env.DB_SSL_MODE || legacyMode).toLowerCase();

    if (mode === "disable") {
      return false;
    }

    if (mode === "require") {
      return { rejectUnauthorized: false };
    }

    if (mode === "verify-full") {
      const ssl = { rejectUnauthorized: true };
      const caFile = process.env.DB_SSL_CA_FILE;
      if (caFile) {
        const caPath = isAbsolute(caFile) ? caFile : resolve(__dirname, caFile);
        ssl.ca = readFileSync(caPath, "utf8");
      }
      return ssl;
    }

    throw new Error("DB_SSL_MODE must be one of: disable, require, verify-full.");
  }

  buildConnectionConfig() {
    const timezone = process.env.DB_TIMEZONE || "UTC";
    if (!TIMEZONE_PATTERN.test(timezone)) {
      throw new Error("DB_TIMEZONE contains unsupported characters.");
    }

    const user = process.env.DB_USER?.trim();
    if (!user) {
      throw new Error(
        "DB_USER is required. Configure a dedicated least-privilege, non-superuser PostgreSQL role."
      );
    }

    const config = {
      host: process.env.DB_HOST || "localhost",
      port: this.parsePositiveInteger(process.env.DB_PORT, 5432, "DB_PORT"),
      database: process.env.DB_NAME || "postgres",
      user,
      password: process.env.DB_PASSWORD || "",
      options: `-c timezone=${timezone} -c search_path=pg_catalog`,
      max: this.parsePositiveInteger(process.env.MAX_CONNECTIONS, 10, "MAX_CONNECTIONS"),
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: this.connectionTimeoutMs,
      statement_timeout: this.statementTimeoutMs,
      ssl: this.buildSslConfig(),
    };

    debugLog(
      `[PostgreSQL MCP] Connecting to: ${config.host}:${config.port}/${config.database} as ${config.user}`
    );
    debugLog(`[PostgreSQL MCP] SSL mode: ${process.env.DB_SSL_MODE || "legacy/default"}`);
    return config;
  }

  validateIdentifier(identifier, label = "identifier") {
    validateSharedIdentifier(identifier, label);
  }

  quoteIdentifier(identifier, label = "identifier") {
    this.validateIdentifier(identifier, label);
    return `"${identifier}"`;
  }

  quoteQualifiedName(schemaName, objectName, objectLabel = "object name") {
    return `${this.quoteIdentifier(schemaName, "schema name")}.${this.quoteIdentifier(
      objectName,
      objectLabel
    )}`;
  }

  validateParameters(parameters = []) {
    if (!Array.isArray(parameters)) {
      throw new Error("Parameters must be an array.");
    }
  }

  validateDataObject(data) {
    validateSharedDataObject(data, this.validateIdentifier.bind(this));
  }

  validateAllowedColumns(schemaName, tableName, columns) {
    for (const column of columns) {
      assertAllowedColumn(schemaName, tableName, column, this.allowedColumns);
    }
  }

  validateAllowedFilterColumns(schemaName, tableName, filters) {
    this.validateAllowedColumns(
      schemaName,
      tableName,
      filters.map((filter) => filter.column)
    );
  }

  validateSelectQuery(query) {
    if (!this.allowArbitrarySelect) {
      throw new Error(
        "execute_query is disabled. Set ALLOW_ARBITRARY_SELECT=true only with a database-enforced read-only role."
      );
    }
    const normalizedQuery = normalizeSelectQuery(query);
    assertInputBudget(normalizedQuery, "Query", this.maxInputBytes, 0);
    if (!/^select\b/i.test(normalizedQuery)) {
      throw new Error(
        "Only SELECT queries are allowed with execute_query. Use specific tools for INSERT, UPDATE, DELETE."
      );
    }

    const maskedQuery = maskSqlLiterals(normalizedQuery);
    if (FORBIDDEN_SQL_PATTERN.test(maskedQuery)) {
      throw new Error("Query contains forbidden SQL syntax.");
    }
    assertAllowedFunctions(
      maskedQuery,
      this.allowedSelectFunctions,
      this.forbiddenSelectFunctions
    );
    return normalizedQuery;
  }

  ensureWritesAllowed(operation) {
    if (this.mode !== "write") {
      throw new Error(`${operation} requires a separate MCP_MODE=write deployment.`);
    }
    if (!this.allowWrites) {
      throw new Error(`${operation} is disabled. Set ALLOW_WRITES=true to enable write tools.`);
    }
  }

  ensureDeleteAllowed() {
    this.ensureWritesAllowed("DELETE");
    if (!this.allowDelete) {
      throw new Error("DELETE is disabled. Set ALLOW_DELETE=true to enable delete operations.");
    }
  }

  validateFilters(filters) {
    validateSharedFilters(filters, this.validateIdentifier.bind(this));
  }

  buildFilterClause(filters, startIndex = 1) {
    this.validateFilters(filters);
    const values = [];
    let parameterIndex = startIndex;

    const clauses = filters.map((filter) => {
      const column = this.quoteIdentifier(filter.column, "filter column name");

      if (filter.operator === "is_null" || (filter.operator === "eq" && filter.value === null)) {
        return `${column} IS NULL`;
      }

      if (filter.operator === "is_not_null" || (filter.operator === "neq" && filter.value === null)) {
        return `${column} IS NOT NULL`;
      }

      if (filter.value === null) {
        throw new Error(`The ${filter.operator} operator does not accept null.`);
      }

      if (filter.operator === "in") {
        const placeholders = filter.value.map((value) => {
          values.push(value);
          const placeholder = `$${parameterIndex}`;
          parameterIndex += 1;
          return placeholder;
        });
        return `${column} IN (${placeholders.join(", ")})`;
      }

      const sqlOperators = {
        eq: "=",
        neq: "<>",
        gt: ">",
        gte: ">=",
        lt: "<",
        lte: "<=",
        like: "LIKE",
      };
      values.push(filter.value);
      const clause = `${column} ${sqlOperators[filter.operator]} $${parameterIndex}`;
      parameterIndex += 1;
      return clause;
    });

    return {
      clause: clauses.join(" AND "),
      values,
    };
  }

  createJsonResult(payload) {
    return createSharedJsonResult(payload, this.maxResponseBytes);
  }

  createErrorResult(error) {
    return createSafeErrorResult(error, this.maxResponseBytes, debugLog);
  }

  async ensureSecurityVerified() {
    if (!this.verifyDbPrivileges || this.securityVerified) {
      return;
    }
    if (!this.securityVerificationPromise) {
      this.securityVerificationPromise = (async () => {
        const result = await this.pool.query(`
          SELECT
            rolsuper,
            rolcreaterole,
            rolcreatedb,
            rolreplication,
            rolbypassrls,
            pg_has_role(current_user, 'pg_read_server_files', 'MEMBER') AS can_read_server_files,
            pg_has_role(current_user, 'pg_write_server_files', 'MEMBER') AS can_write_server_files,
            pg_has_role(current_user, 'pg_execute_server_program', 'MEMBER') AS can_execute_server_program,
            EXISTS (
              SELECT 1
              FROM pg_class AS candidate
              JOIN pg_namespace AS candidate_schema ON candidate_schema.oid = candidate.relnamespace
              WHERE candidate.relkind IN ('r', 'p', 'v', 'm', 'f')
                AND candidate_schema.nspname NOT IN ('pg_catalog', 'information_schema')
                AND (
                  has_table_privilege(current_user, candidate.oid, 'INSERT')
                  OR has_table_privilege(current_user, candidate.oid, 'UPDATE')
                  OR has_table_privilege(current_user, candidate.oid, 'DELETE')
                  OR has_table_privilege(current_user, candidate.oid, 'TRUNCATE')
                  OR has_table_privilege(current_user, candidate.oid, 'TRIGGER')
                )
            ) AS can_write_tables,
            EXISTS (
              SELECT 1
              FROM pg_class AS candidate
              JOIN pg_namespace AS candidate_schema ON candidate_schema.oid = candidate.relnamespace
              WHERE candidate.relkind = 'S'
                AND candidate_schema.nspname NOT IN ('pg_catalog', 'information_schema')
                AND (
                  has_sequence_privilege(current_user, candidate.oid, 'USAGE')
                  OR has_sequence_privilege(current_user, candidate.oid, 'UPDATE')
                )
            ) AS can_advance_sequences
          FROM pg_roles
          WHERE rolname = current_user
        `);
        const privileges = result.rows[0] || {};
        const unsafe = this.mode === "write"
          ? Object.entries(privileges).filter(([name, enabled]) =>
              !["can_write_tables", "can_advance_sequences"].includes(name) && enabled === true
            )
          : Object.entries(privileges).filter(([, enabled]) => enabled === true);
        if (unsafe.length > 0) {
          throw new Error(
            `Database role has unsafe privileges: ${unsafe.map(([name]) => name).join(", ")}.`
          );
        }
        this.securityVerified = true;
      })().finally(() => {
        this.securityVerificationPromise = null;
      });
    }
    return this.securityVerificationPromise;
  }

  getAvailableTools() {
    const tools = [
      {
        name: "execute_query",
        description: "Execute one read-only SELECT query on the PostgreSQL database",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: {
            query: {
              type: "string",
              description: "Single SQL SELECT query to execute",
            },
            parameters: {
              type: "array",
              description: "Optional positional parameters for the SELECT query",
              default: [],
            },
          },
          required: ["query"],
        },
      },
      {
        name: "describe_table",
        description: "Get the schema/structure of a database table",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: {
            table_name: { type: "string", description: "Name of the table to describe" },
            schema_name: {
              type: "string",
              description: "Schema name (optional, defaults to public)",
              default: "public",
            },
          },
          required: ["table_name"],
        },
      },
      {
        name: "list_tables",
        description: "List all tables in the database",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: {
            schema_name: {
              type: "string",
              description: "Schema name (optional, defaults to public)",
              default: "public",
            },
          },
        },
      },
      {
        name: "list_schemas",
        description: "List all schemas in the database",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: {},
        },
      },
    ];

    if (!this.allowArbitrarySelect) {
      tools.splice(tools.findIndex((tool) => tool.name === "execute_query"), 1);
    }

    if (this.allowWrites) {
      tools.push(
        {
          name: "execute_insert",
          description: "Insert one record into the PostgreSQL database",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              table: { type: "string", description: "Table name to insert into" },
              data: { type: "object", description: "Column/value pairs to insert" },
              schema_name: {
                type: "string",
                description: "Schema name (optional, defaults to public)",
                default: "public",
              },
              confirm: {
                type: "boolean",
                description: "Must be true after explicit user approval",
              },
            },
            required: ["table", "data", "confirm"],
          },
        },
        {
          name: "execute_update",
          description: "Update records matching structured filters",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              table: { type: "string", description: "Table name to update" },
              data: { type: "object", description: "Column/value pairs to update" },
              filters: FILTERS_INPUT_SCHEMA,
              schema_name: {
                type: "string",
                description: "Schema name (optional, defaults to public)",
                default: "public",
              },
              confirm: {
                type: "boolean",
                description: "Must be true after explicit user approval",
              },
            },
            required: ["table", "data", "filters", "confirm"],
          },
        }
      );
    }

    if (this.allowWrites && this.allowDelete) {
      tools.push({
        name: "execute_delete",
        description: "Delete records matching structured filters",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: {
            table: { type: "string", description: "Table name to delete from" },
            filters: FILTERS_INPUT_SCHEMA,
            schema_name: {
              type: "string",
              description: "Schema name (optional, defaults to public)",
              default: "public",
            },
            confirm: {
              type: "boolean",
              description: "Must be true after explicit user approval",
            },
          },
          required: ["table", "filters", "confirm"],
        },
      });
    }

    return tools;
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.getAvailableTools(),
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args = {} } = request.params;

      try {
        switch (name) {
          case "execute_query":
            return await this.executeQuery(args.query, args.parameters || []);
          case "describe_table":
            return await this.describeTable(args.table_name, args.schema_name || "public");
          case "list_tables":
            return await this.listTables(args.schema_name || "public");
          case "list_schemas":
            return await this.listSchemas();
          case "execute_insert":
            requireMutationConfirmation(args.confirm, "INSERT");
            return await this.executeInsert(args.table, args.data, args.schema_name || "public");
          case "execute_update":
            requireMutationConfirmation(args.confirm, "UPDATE");
            return await this.executeUpdate(
              args.table,
              args.data,
              args.filters,
              args.schema_name || "public"
            );
          case "execute_delete":
            requireMutationConfirmation(args.confirm, "DELETE");
            return await this.executeDelete(args.table, args.filters, args.schema_name || "public");
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return this.createErrorResult(error);
      }
    });
  }

  async setLocalStatementTimeout(client) {
    if (this.statementTimeoutMs > 0) {
      await client.query("SELECT set_config('statement_timeout', $1, true)", [
        `${this.statementTimeoutMs}ms`,
      ]);
    }
  }

  async rollbackQuietly(client) {
    try {
      await client.query("ROLLBACK");
    } catch (error) {
      debugLog(`[PostgreSQL MCP] Rollback failed: code=${error.code || error.name || "unknown"}`);
    }
  }

  async executeQuery(query, parameters = []) {
    const normalizedQuery = this.validateSelectQuery(query);
    this.validateParameters(parameters);
    assertInputBudget(parameters, "Parameters", this.maxInputBytes, this.maxInputItems);
    if (this.maxRows === 0 || this.maxResponseBytes === 0) {
      throw new Error("Raw SELECT requires positive MAX_ROWS and MAX_RESPONSE_BYTES limits.");
    }
    await this.ensureSecurityVerified();

    const client = await this.pool.connect();
    let transactionStarted = false;
    try {
      await client.query("BEGIN READ ONLY");
      transactionStarted = true;
      await this.setLocalStatementTimeout(client);

      const boundedQuery = `
        SELECT
          limited.row_json AS "__mcp_row",
          limited.column_count AS "__mcp_column_count"
        FROM (${normalizedQuery}) AS "__mcp_source"
        CROSS JOIN LATERAL (
          SELECT
            jsonb_object_agg(
              entry.key,
              CASE
                WHEN octet_length(entry.value::text) > ${this.maxFieldBytes}
                  THEN to_jsonb('[omitted: field exceeds MAX_FIELD_BYTES]'::text)
                ELSE entry.value
              END
            ) AS row_json,
            count(*)::integer AS column_count
          FROM (
            SELECT key, value
            FROM jsonb_each(to_jsonb("__mcp_source"))
            LIMIT ${this.maxColumns + 1}
          ) AS entry
        ) AS limited
      `;
      await client.query({
        text: `DECLARE "__mcp_cursor" NO SCROLL CURSOR FOR ${boundedQuery}`,
        values: parameters,
        queryMode: "extended",
      });

      const rows = [];
      let responseBytes = 256;
      let truncated = false;
      while (true) {
        const fetched = await client.query('FETCH FORWARD 1 FROM "__mcp_cursor"');
        if (fetched.rows.length === 0) {
          break;
        }
        const fetchedRow = fetched.rows[0];
        if (fetchedRow.__mcp_column_count > this.maxColumns) {
          throw new Error(`Query exceeds MAX_COLUMNS (${this.maxColumns}).`);
        }
        if (rows.length >= this.maxRows) {
          truncated = true;
          break;
        }
        const row = fetchedRow.__mcp_row || {};
        const rowBytes = Buffer.byteLength(JSON.stringify(row), "utf8");
        if (responseBytes + rowBytes > Math.max(0, this.maxResponseBytes - 512)) {
          truncated = true;
          break;
        }
        responseBytes += rowBytes;
        rows.push(row);
      }
      await client.query("ROLLBACK");
      transactionStarted = false;

      return this.createJsonResult({
        rows,
        rowCount: rows.length,
        truncated,
        fields: rows[0]
          ? Object.keys(rows[0]).map((name) => ({ name, dataTypeID: null }))
          : [],
      });
    } catch (error) {
      if (transactionStarted) {
        await this.rollbackQuietly(client);
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async describeTable(tableName, schemaName = "public") {
    this.validateIdentifier(tableName, "table name");
    this.validateIdentifier(schemaName, "schema name");
    assertAllowedTable(schemaName, tableName, this.allowedSchemas, this.allowedTables);
    await this.ensureSecurityVerified();

    const allowedColumns = allowedColumnNames(schemaName, tableName, this.allowedColumns);
    if (this.allowedColumns.size > 0 && allowedColumns.length === 0) {
      throw new Error(`No columns are allowlisted for: ${schemaName}.${tableName}`);
    }
    const query = `
      SELECT
        column_name,
        data_type,
        is_nullable,
        column_default,
        character_maximum_length,
        numeric_precision,
        numeric_scale
      FROM information_schema.columns
      WHERE table_name = $1 AND table_schema = $2
        AND ($3::text[] IS NULL OR lower(column_name) = ANY($3::text[]))
      ORDER BY ordinal_position
    `;

    const result = await this.pool.query(query, [
      tableName,
      schemaName,
      allowedColumns.length > 0 ? allowedColumns : null,
    ]);
    return this.createJsonResult({
      table: `${schemaName}.${tableName}`,
      columns: result.rows,
      rowCount: result.rowCount,
    });
  }

  async listTables(schemaName = "public") {
    this.validateIdentifier(schemaName, "schema name");
    assertAllowedSchema(schemaName, this.allowedSchemas);
    await this.ensureSecurityVerified();
    const result = await this.pool.query(
      `
        SELECT table_name, table_type
        FROM information_schema.tables
        WHERE table_schema = $1
        ORDER BY table_name
      `,
      [schemaName]
    );

    const rows = this.allowedTables.size === 0
      ? result.rows
      : result.rows.filter((row) =>
          this.allowedTables.has(`${schemaName}.${row.table_name}`.toLowerCase())
        );
    return this.createJsonResult({
      schema: schemaName,
      tables: rows,
      rowCount: rows.length,
    });
  }

  async listSchemas() {
    await this.ensureSecurityVerified();
    const result = await this.pool.query(`
      SELECT schema_name
      FROM information_schema.schemata
      WHERE schema_name NOT IN ('information_schema', 'pg_catalog', 'pg_toast')
      ORDER BY schema_name
    `);

    const schemas = result.rows
      .map((row) => row.schema_name)
      .filter((schema) => this.allowedSchemas.size === 0 || this.allowedSchemas.has(schema.toLowerCase()));
    return this.createJsonResult({
      schemas,
      rowCount: schemas.length,
    });
  }

  async executeInsert(table, data, schemaName = "public") {
    this.ensureWritesAllowed("INSERT");
    this.validateIdentifier(table, "table name");
    this.validateIdentifier(schemaName, "schema name");
    this.validateDataObject(data);
    assertAllowedTable(schemaName, table, this.allowedSchemas, this.allowedTables);
    this.validateAllowedColumns(schemaName, table, Object.keys(data));
    assertInputBudget(data, "Data", this.maxInputBytes, this.maxInputItems);
    await this.ensureSecurityVerified();

    const columns = Object.keys(data);
    const values = Object.values(data);
    const columnList = columns.map((column) => this.quoteIdentifier(column, "column name")).join(", ");
    const placeholders = columns.map((_, index) => `$${index + 1}`).join(", ");
    const tableName = this.quoteQualifiedName(schemaName, table, "table name");
    const result = await this.pool.query(
      `
        INSERT INTO ${tableName} (${columnList})
        VALUES (${placeholders})
        ${this.returnMutationRows ? "RETURNING *" : ""}
      `,
      values
    );

    auditMutation("postgresql", "insert", { schema: schemaName, table, rowsAffected: result.rowCount });
    return this.createJsonResult({
      inserted: this.returnMutationRows ? result.rows[0] : undefined,
      rowCount: result.rowCount,
    });
  }

  async preflightAffectedRows(client, tableName, filters) {
    if (this.maxAffectedRows === 0) {
      return;
    }

    const filter = this.buildFilterClause(filters);
    const result = await client.query(
      `SELECT 1 FROM ${tableName} WHERE ${filter.clause} LIMIT ${this.maxAffectedRows + 1} FOR UPDATE`,
      filter.values
    );

    if (result.rowCount > this.maxAffectedRows) {
      throw new Error(
        `Operation would affect more than MAX_AFFECTED_ROWS (${this.maxAffectedRows}) rows.`
      );
    }
  }

  async executeUpdate(table, data, filters, schemaName = "public") {
    this.ensureWritesAllowed("UPDATE");
    this.validateIdentifier(table, "table name");
    this.validateIdentifier(schemaName, "schema name");
    this.validateDataObject(data);
    this.validateFilters(filters);
    assertAllowedTable(schemaName, table, this.allowedSchemas, this.allowedTables);
    this.validateAllowedColumns(schemaName, table, Object.keys(data));
    this.validateAllowedFilterColumns(schemaName, table, filters);
    assertInputBudget(data, "Data", this.maxInputBytes, this.maxInputItems);
    assertInputBudget(filters, "Filters", this.maxInputBytes, this.maxInputItems);
    await this.ensureSecurityVerified();

    const columns = Object.keys(data);
    const values = Object.values(data);
    const setClause = columns
      .map((column, index) => `${this.quoteIdentifier(column, "column name")} = $${index + 1}`)
      .join(", ");
    const filter = this.buildFilterClause(filters, values.length + 1);
    const tableName = this.quoteQualifiedName(schemaName, table, "table name");
    const client = await this.pool.connect();
    let transactionStarted = false;

    try {
      await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
      transactionStarted = true;
      await this.setLocalStatementTimeout(client);
      await this.preflightAffectedRows(client, tableName, filters);

      const result = await client.query(
        `UPDATE ${tableName} SET ${setClause} WHERE ${filter.clause} ${this.returnMutationRows ? "RETURNING *" : ""}`,
        [...values, ...filter.values]
      );
      if (this.maxAffectedRows > 0 && result.rowCount > this.maxAffectedRows) {
        throw new Error(
          `Operation affected more than MAX_AFFECTED_ROWS (${this.maxAffectedRows}) rows.`
        );
      }

      await client.query("COMMIT");
      transactionStarted = false;
      auditMutation("postgresql", "update", { schema: schemaName, table, rowsAffected: result.rowCount });
      return this.createJsonResult({
        updated: this.returnMutationRows ? result.rows : undefined,
        rowCount: result.rowCount,
      });
    } catch (error) {
      if (transactionStarted) {
        await this.rollbackQuietly(client);
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async executeDelete(table, filters, schemaName = "public") {
    this.ensureDeleteAllowed();
    this.validateIdentifier(table, "table name");
    this.validateIdentifier(schemaName, "schema name");
    this.validateFilters(filters);
    assertAllowedTable(schemaName, table, this.allowedSchemas, this.allowedTables);
    this.validateAllowedFilterColumns(schemaName, table, filters);
    assertInputBudget(filters, "Filters", this.maxInputBytes, this.maxInputItems);
    await this.ensureSecurityVerified();

    const tableName = this.quoteQualifiedName(schemaName, table, "table name");
    const filter = this.buildFilterClause(filters);
    const client = await this.pool.connect();
    let transactionStarted = false;

    try {
      await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
      transactionStarted = true;
      await this.setLocalStatementTimeout(client);
      await this.preflightAffectedRows(client, tableName, filters);

      const result = await client.query(
        `DELETE FROM ${tableName} WHERE ${filter.clause} ${this.returnMutationRows ? "RETURNING *" : ""}`,
        filter.values
      );
      if (this.maxAffectedRows > 0 && result.rowCount > this.maxAffectedRows) {
        throw new Error(
          `Operation affected more than MAX_AFFECTED_ROWS (${this.maxAffectedRows}) rows.`
        );
      }

      await client.query("COMMIT");
      transactionStarted = false;
      auditMutation("postgresql", "delete", { schema: schemaName, table, rowsAffected: result.rowCount });
      return this.createJsonResult({
        deleted: this.returnMutationRows ? result.rows : undefined,
        rowCount: result.rowCount,
      });
    } catch (error) {
      if (transactionStarted) {
        await this.rollbackQuietly(client);
      }
      throw error;
    } finally {
      client.release();
    }
  }

  setupErrorHandlers() {
    this.server.onerror = () => {
      console.error("[MCP Error] Internal protocol error.");
    };
    this.pool.on("error", () => {
      console.error(
        "[PostgreSQL MCP] An idle database connection failed; the pool will replace it."
      );
    });
  }

  async shutdown() {
    await this.pool.end();
  }

  async run() {
    const transport = new StdioServerTransport(
      createLimitedLineInput(process.stdin, this.maxRequestBytes),
      process.stdout
    );
    await this.server.connect(transport);

    const stop = async () => {
      await this.shutdown();
      process.exit(0);
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    console.error("PostgreSQL MCP server running on stdio");
  }
}

const isMainModule = process.argv[1] && resolve(process.argv[1]) === __filename;
if (isMainModule) {
  const server = new PostgreSQLMCPServer();
  server.run().catch((error) => {
    console.error(`[PostgreSQL MCP] Startup failed: code=${error.code || error.name || "unknown"}`);
    process.exitCode = 1;
  });
}

export {
  FILTERS_INPUT_SCHEMA,
  FORBIDDEN_SQL_PATTERN,
  maskSqlLiterals,
  normalizeSelectQuery,
  PostgreSQLMCPServer,
};
