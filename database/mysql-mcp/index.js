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
import mysql from "mysql2";
import {
  assertAllowedFunctions,
  assertInputBudget,
  auditMutation,
  createJsonResult as createSharedJsonResult,
  createLimitedLineInput,
  createSafeErrorResult,
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
  if (debugEnabled) console.error(message);
}

if (envResult.error) {
  debugLog(`[MySQL MCP] Error loading .env file: code=${envResult.error.code || envResult.error.name || "unknown"}`);
} else {
  debugLog(`[MySQL MCP] .env file loaded from: ${envPath}`);
}

const TIMEZONE_PATTERN = /^(?:Z|local|[+-](?:0\d|1[0-4]):[0-5]\d)$/i;
const FORBIDDEN_SQL_PATTERN = /(;|--|#|\/\*|\*\/|@|:=|\b(insert|update|delete|replace|merge|drop|alter|create|truncate|call|do|handler|load|grant|revoke|rename|analyze|optimize|repair|flush|reset|purge|kill|install|uninstall|begin|start|commit|rollback|savepoint|release|lock|unlock|set|use|into|outfile|dumpfile|temporary)\b)/i;
const LOCKING_READ_PATTERN = /\b(?:for\s+(?:update|share)|lock\s+in\s+share\s+mode)\b/i;
const QUOTED_FUNCTION_PATTERN = /(?:`(?:``|[^`])+`|"(?:""|[^"])+")\s*\(/;

function maskSqlLiterals(query) {
  const characters = Array.from(query);

  for (let index = 0; index < query.length; index += 1) {
    const quote = query[index];
    if (!["'", '"', "`"].includes(quote)) continue;

    characters[index] = " ";
    index += 1;
    let terminated = false;
    while (index < query.length) {
      characters[index] = query[index] === "\n" ? "\n" : " ";
      if (query[index] === "\\") {
        throw new Error(
          "Backslashes inside quoted raw SQL are not permitted because MySQL sql_mode changes their parsing."
        );
      }
      if (query[index] === quote) {
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

function splitTopLevelCommas(value) {
  const parts = [];
  let current = "";
  let depth = 0;
  let quoted = false;

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "`") {
      current += character;
      if (quoted && value[index + 1] === "`") {
        current += value[index + 1];
        index += 1;
      } else {
        quoted = !quoted;
      }
      continue;
    }
    if (!quoted && character === "(") depth += 1;
    if (!quoted && character === ")") depth -= 1;
    if (!quoted && depth === 0 && character === ",") {
      parts.push(current.trim());
      current = "";
    } else {
      current += character;
    }
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function unquoteGrantIdentifier(identifier) {
  const trimmed = identifier.trim();
  if (trimmed.startsWith("`") && trimmed.endsWith("`")) {
    return trimmed.slice(1, -1).replaceAll("``", "`");
  }
  return trimmed;
}

function parseGrantScope(scope) {
  const trimmed = scope.trim();
  if (trimmed === "*.*") return { kind: "global" };

  const separator = trimmed.indexOf(".");
  if (separator < 0) throw new Error("Database role has an unrecognized grant scope.");
  const schema = unquoteGrantIdentifier(trimmed.slice(0, separator));
  const object = unquoteGrantIdentifier(trimmed.slice(separator + 1));
  if (object === "*") return { kind: "schema", schema };
  return { kind: "table", schema, table: object };
}

function parseExactCsvSet(value, fallback = "") {
  return new Set(
    String(value ?? fallback)
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
  );
}

function assertExactAllowedSchema(schemaName, allowedSchemas) {
  if (allowedSchemas.size > 0 && !allowedSchemas.has(schemaName)) {
    throw new Error(`Schema is not allowlisted: ${schemaName}`);
  }
}

function assertExactAllowedTable(schemaName, tableName, allowedSchemas, allowedTables) {
  assertExactAllowedSchema(schemaName, allowedSchemas);
  if (allowedTables.size > 0 && !allowedTables.has(`${schemaName}.${tableName}`)) {
    throw new Error(`Table is not allowlisted: ${schemaName}.${tableName}`);
  }
}

function assertExactAllowedColumn(schemaName, tableName, columnName, allowedColumns) {
  if (allowedColumns.size > 0 && !allowedColumns.has(`${schemaName}.${tableName}.${columnName}`)) {
    throw new Error(`Column is not allowlisted: ${schemaName}.${tableName}.${columnName}`);
  }
}

function exactAllowedColumnNames(schemaName, tableName, allowedColumns) {
  if (allowedColumns.size === 0) return [];
  const prefix = `${schemaName}.${tableName}.`;
  return Array.from(allowedColumns)
    .filter((name) => name.startsWith(prefix))
    .map((name) => name.slice(prefix.length));
}

class MySQLMCPServer {
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
    this.defaultSchema = process.env.DB_NAME?.trim();
    if (!this.defaultSchema) {
      throw new Error("DB_NAME is required and must name a dedicated application database.");
    }
    validateSharedIdentifier(this.defaultSchema, "DB_NAME");
    this.allowArbitrarySelect = process.env.ALLOW_ARBITRARY_SELECT === "true";
    this.allowedSchemas = parseExactCsvSet(process.env.ALLOWED_SCHEMAS);
    if (this.allowedSchemas.size === 0) {
      this.allowedSchemas.add(this.defaultSchema);
    }
    this.allowedTables = parseExactCsvSet(process.env.ALLOWED_TABLES);
    this.allowedColumns = parseExactCsvSet(process.env.ALLOWED_COLUMNS);
    if (this.allowArbitrarySelect && this.allowedColumns.size > 0) {
      throw new Error(
        "ALLOWED_COLUMNS requires ALLOW_ARBITRARY_SELECT=false; expose curated views for raw-query deployments."
      );
    }
    this.allowedSelectFunctions = parseCsvSet(process.env.ALLOWED_SELECT_FUNCTIONS);
    this.forbiddenSelectFunctions = parseCsvSet(
      "load_file,sleep,benchmark,get_lock,release_lock,is_free_lock,is_used_lock,service_get_read_locks,service_release_locks,master_pos_wait,source_pos_wait,wait_for_executed_gtid_set,last_insert_id,row_count,found_rows,connection_id"
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
    this.maxColumns = this.parsePositiveInteger(process.env.MAX_COLUMNS, 100, "MAX_COLUMNS");
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
    if (this.returnMutationRows && this.maxAffectedRows === 0) {
      throw new Error("RETURN_MUTATION_ROWS=true requires a positive MAX_AFFECTED_ROWS limit.");
    }
    if (this.returnMutationRows && this.maxResponseBytes === 0) {
      throw new Error("RETURN_MUTATION_ROWS=true requires a positive MAX_RESPONSE_BYTES limit.");
    }

    this.server = new Server(
      { name: "mysql-mcp-server", version: "1.0.0" },
      { capabilities: { tools: {} } }
    );
    this.pool = mysql.createPool(this.buildConnectionConfig());
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
    const mode = (process.env.DB_SSL_MODE || (localHost ? "disable" : "verify-full")).toLowerCase();
    if (mode === "disable") return undefined;
    if (mode === "require") return { rejectUnauthorized: false };
    if (mode === "verify-full") {
      const ssl = { rejectUnauthorized: true };
      if (process.env.DB_SSL_CA_FILE) {
        const caPath = isAbsolute(process.env.DB_SSL_CA_FILE)
          ? process.env.DB_SSL_CA_FILE
          : resolve(__dirname, process.env.DB_SSL_CA_FILE);
        ssl.ca = readFileSync(caPath, "utf8");
      }
      return ssl;
    }
    throw new Error("DB_SSL_MODE must be one of: disable, require, verify-full.");
  }

  buildConnectionConfig() {
    const user = process.env.DB_USER?.trim();
    if (!user) {
      throw new Error(
        "DB_USER is required. Configure a dedicated least-privilege, non-administrative MySQL account."
      );
    }
    const timezone = process.env.DB_TIMEZONE || "Z";
    if (!TIMEZONE_PATTERN.test(timezone)) {
      throw new Error("DB_TIMEZONE must be Z, local, or a numeric offset such as +05:30.");
    }
    const config = {
      host: process.env.DB_HOST || "localhost",
      port: this.parsePositiveInteger(process.env.DB_PORT, 3306, "DB_PORT"),
      database: this.defaultSchema,
      user,
      password: process.env.DB_PASSWORD || "",
      timezone,
      ssl: this.buildSslConfig(),
      waitForConnections: true,
      connectionLimit: this.parsePositiveInteger(
        process.env.MAX_CONNECTIONS,
        10,
        "MAX_CONNECTIONS"
      ),
      queueLimit: 20,
      connectTimeout: this.connectionTimeoutMs,
      multipleStatements: false,
      supportBigNumbers: true,
      bigNumberStrings: true,
      dateStrings: true,
      enableKeepAlive: true,
    };
    debugLog(
      `[MySQL MCP] Connecting to: ${config.host}:${config.port}/${config.database} as ${config.user}`
    );
    debugLog(`[MySQL MCP] SSL mode: ${process.env.DB_SSL_MODE || "default"}`);
    return config;
  }

  validateIdentifier(identifier, label = "identifier") {
    validateSharedIdentifier(identifier, label);
  }

  quoteIdentifier(identifier, label = "identifier") {
    this.validateIdentifier(identifier, label);
    return `\`${identifier}\``;
  }

  quoteQualifiedName(schemaName, objectName, objectLabel = "object name") {
    return `${this.quoteIdentifier(schemaName, "schema name")}.${this.quoteIdentifier(
      objectName,
      objectLabel
    )}`;
  }

  validateParameters(parameters = []) {
    if (!Array.isArray(parameters)) throw new Error("Parameters must be an array.");
  }

  validateDataObject(data) {
    validateSharedDataObject(data, this.validateIdentifier.bind(this));
  }

  validateAllowedColumns(schemaName, tableName, columns) {
    for (const column of columns) {
      assertExactAllowedColumn(schemaName, tableName, column, this.allowedColumns);
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
        "execute_query is disabled. Set ALLOW_ARBITRARY_SELECT=true only with a database-enforced read-only account."
      );
    }
    const normalizedQuery = normalizeSelectQuery(query);
    assertInputBudget(normalizedQuery, "Query", this.maxInputBytes, 0);
    if (!/^select\b/i.test(normalizedQuery)) {
      throw new Error(
        "Only SELECT queries are allowed with execute_query. Use specific tools for INSERT, UPDATE, DELETE."
      );
    }
    if (QUOTED_FUNCTION_PATTERN.test(normalizedQuery)) {
      throw new Error("Quoted function names are not permitted in raw SELECT queries.");
    }
    const maskedQuery = maskSqlLiterals(normalizedQuery);
    if (FORBIDDEN_SQL_PATTERN.test(maskedQuery) || LOCKING_READ_PATTERN.test(maskedQuery)) {
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

  buildFilterClause(filters) {
    this.validateFilters(filters);
    const values = [];
    const clauses = filters.map((filter) => {
      const column = this.quoteIdentifier(filter.column, "filter column name");
      if (filter.operator === "is_null" || (filter.operator === "eq" && filter.value === null)) {
        return `${column} IS NULL`;
      }
      if (
        filter.operator === "is_not_null" ||
        (filter.operator === "neq" && filter.value === null)
      ) {
        return `${column} IS NOT NULL`;
      }
      if (filter.value === null) {
        throw new Error(`The ${filter.operator} operator does not accept null.`);
      }
      if (filter.operator === "in") {
        const placeholders = filter.value.map((value) => {
          values.push(value);
          return "?";
        });
        return `${column} IN (${placeholders.join(", ")})`;
      }
      const operators = {
        eq: "=",
        neq: "<>",
        gt: ">",
        gte: ">=",
        lt: "<",
        lte: "<=",
        like: "LIKE",
      };
      values.push(filter.value);
      return `${column} ${operators[filter.operator]} ?`;
    });
    return { clause: clauses.join(" AND "), values };
  }

  createJsonResult(payload) {
    return createSharedJsonResult(payload, this.maxResponseBytes);
  }

  createErrorResult(error) {
    return createSafeErrorResult(error, this.maxResponseBytes, debugLog);
  }

  metadataRowLimit() {
    return this.maxRows > 0 ? Math.min(this.maxRows, 10000) : 1000;
  }

  query(target, sql, values = [], options = {}) {
    return new Promise((resolvePromise, rejectPromise) => {
      const method = values.length > 0 ? "execute" : "query";
      target[method](
        {
          sql,
          values,
          timeout: this.statementTimeoutMs > 0 ? this.statementTimeoutMs : undefined,
          ...options,
        },
        (error, rows, fields) => {
          if (error) rejectPromise(error);
          else resolvePromise({ rows, fields: fields || [] });
        }
      );
    });
  }

  getConnection() {
    return new Promise((resolvePromise, rejectPromise) => {
      this.pool.getConnection((error, connection) => {
        if (error) rejectPromise(error);
        else resolvePromise(connection);
      });
    });
  }

  destroyConnectionForError(connection, error) {
    if (!error.connectionDestroyed) {
      connection.destroy();
      error.connectionDestroyed = true;
    }
  }

  isUnsafeTransactionError(error) {
    return Boolean(
      error?.connectionDestroyed ||
      error?.fatal ||
      [
        "PROTOCOL_SEQUENCE_TIMEOUT",
        "PROTOCOL_CONNECTION_LOST",
        "PROTOCOL_ENQUEUE_AFTER_FATAL_ERROR",
        "PROTOCOL_ENQUEUE_AFTER_QUIT",
        "PROTOCOL_PACKETS_OUT_OF_ORDER",
        "ECONNRESET",
        "ETIMEDOUT",
        "EPIPE",
      ].includes(error?.code)
    );
  }

  async executeTransactionControl(connection, statement) {
    try {
      return await this.query(connection, statement);
    } catch (error) {
      this.destroyConnectionForError(connection, error);
      throw error;
    }
  }

  async handleTransactionError(connection, error, transactionStarted) {
    if (error.connectionDestroyed) return true;
    if (this.isUnsafeTransactionError(error)) {
      this.destroyConnectionForError(connection, error);
      return true;
    }
    if (transactionStarted) {
      return !(await this.rollbackQuietly(connection));
    }
    return false;
  }

  async rollbackQuietly(connection) {
    try {
      await this.query(connection, "ROLLBACK");
      return true;
    } catch (error) {
      debugLog(`[MySQL MCP] Rollback failed: code=${error.code || error.name || "unknown"}`);
      connection.destroy();
      return false;
    }
  }

  async setSessionLimits(connection) {
    await this.query(
      connection,
      `SET SESSION MAX_EXECUTION_TIME = ${this.statementTimeoutMs}`
    );
  }

  allowedGrantPrivileges() {
    const allowed = new Set(["USAGE", "SELECT", "SHOW VIEW"]);
    if (this.mode === "write" && this.allowWrites) {
      allowed.add("INSERT");
      allowed.add("UPDATE");
      if (this.allowDelete) allowed.add("DELETE");
    }
    return allowed;
  }

  validateGrantStatement(grant) {
    if (typeof grant !== "string") {
      throw new Error("Database role returned an unrecognized grant record.");
    }
    if (/\bWITH\s+(?:GRANT|ADMIN)\s+OPTION\b/i.test(grant)) {
      throw new Error("Database role has unsafe privilege delegation capability.");
    }
    if (/^GRANT\s+PROXY\b/i.test(grant)) {
      throw new Error("Database role has unsafe PROXY capability.");
    }
    if (!/^GRANT\b/i.test(grant) || !/\sON\s/i.test(grant)) return;

    const match = grant.match(/^GRANT\s+(.+?)\s+ON\s+(?:(TABLE|FUNCTION|PROCEDURE)\s+)?(.+?)\s+TO\s+/i);
    if (!match) throw new Error("Database role has an unrecognized privilege grant.");
    if (match[2] && /FUNCTION|PROCEDURE/i.test(match[2])) {
      throw new Error("Database role has unsafe stored-routine privileges.");
    }

    const privileges = splitTopLevelCommas(match[1]).map((entry) =>
      entry.replace(/\s*\([^)]*\)\s*$/, "").trim().toUpperCase()
    );
    const allowedPrivileges = this.allowedGrantPrivileges();
    const unsafePrivileges = privileges.filter((privilege) => !allowedPrivileges.has(privilege));
    if (unsafePrivileges.length > 0) {
      throw new Error(`Database role has unsafe privileges: ${unsafePrivileges.join(", ")}.`);
    }

    const scope = parseGrantScope(match[3]);
    if (scope.kind === "global") {
      if (privileges.some((privilege) => privilege !== "USAGE")) {
        throw new Error("Database role has unsafe global privileges.");
      }
      return;
    }
    assertExactAllowedSchema(scope.schema, this.allowedSchemas);
    if (scope.kind === "schema" && this.allowedTables.size > 0) {
      if (privileges.some((privilege) => privilege !== "USAGE")) {
        throw new Error("Database-wide privileges exceed ALLOWED_TABLES.");
      }
      return;
    }
    if (scope.kind === "table") {
      assertExactAllowedTable(
        scope.schema,
        scope.table,
        this.allowedSchemas,
        this.allowedTables
      );
    }
  }

  async ensureSecurityVerified() {
    if (!this.verifyDbPrivileges || this.securityVerified) return;
    if (!this.securityVerificationPromise) {
      this.securityVerificationPromise = (async () => {
        const connection = await this.getConnection();
        let destroyed = false;
        try {
          const { rows: roles } = await this.query(
            connection,
            "SELECT ROLE_NAME, ROLE_HOST FROM INFORMATION_SCHEMA.ENABLED_ROLES ORDER BY ROLE_NAME, ROLE_HOST"
          );
          const usingClause = roles.length > 0
            ? ` USING ${roles
                .map((role) => `${mysql.escape(role.ROLE_NAME)}@${mysql.escape(role.ROLE_HOST)}`)
                .join(", ")}`
            : "";
          const { rows: grants } = await this.query(
            connection,
            `SHOW GRANTS FOR CURRENT_USER()${usingClause}`
          );
          for (const row of grants) {
            this.validateGrantStatement(Object.values(row)[0]);
          }
          this.securityVerified = true;
        } catch (error) {
          if (this.isUnsafeTransactionError(error)) {
            this.destroyConnectionForError(connection, error);
            destroyed = true;
          }
          throw error;
        } finally {
          if (!destroyed) connection.release();
        }
      })().finally(() => {
        this.securityVerificationPromise = null;
      });
    }
    return this.securityVerificationPromise;
  }

  getAvailableTools() {
    const schemaDefault = this.defaultSchema;
    const tools = [
      {
        name: "execute_query",
        description: "Execute one guarded, read-only SELECT query on MySQL",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: {
            query: { type: "string", description: "Single SQL SELECT query to execute" },
            parameters: {
              type: "array",
              description: "Optional positional values for ? placeholders",
              default: [],
            },
          },
          required: ["query"],
        },
      },
      {
        name: "describe_table",
        description: "Get the allowed structure of a MySQL table or view",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: {
            table_name: { type: "string", description: "Table or view name" },
            schema_name: {
              type: "string",
              description: "Database name; defaults to DB_NAME",
              default: schemaDefault,
            },
          },
          required: ["table_name"],
        },
      },
      {
        name: "list_tables",
        description: "List allowlisted tables and views in an allowed MySQL database",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: {
            schema_name: {
              type: "string",
              description: "Database name; defaults to DB_NAME",
              default: schemaDefault,
            },
          },
        },
      },
      {
        name: "list_schemas",
        description: "List allowed MySQL databases (schemas)",
        inputSchema: { type: "object", additionalProperties: false, properties: {} },
      },
    ];
    if (!this.allowArbitrarySelect) tools.shift();

    if (this.allowWrites) {
      tools.push(
        {
          name: "execute_insert",
          description: "Insert one record into an allowed MySQL table",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              table: { type: "string", description: "Table name" },
              data: { type: "object", description: "Column/value pairs" },
              schema_name: { type: "string", default: schemaDefault },
              confirm: { type: "boolean", description: "Must be true after explicit approval" },
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
              table: { type: "string", description: "Table name" },
              data: { type: "object", description: "Column/value pairs" },
              filters: FILTERS_INPUT_SCHEMA,
              schema_name: { type: "string", default: schemaDefault },
              confirm: { type: "boolean", description: "Must be true after explicit approval" },
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
            table: { type: "string", description: "Table name" },
            filters: FILTERS_INPUT_SCHEMA,
            schema_name: { type: "string", default: schemaDefault },
            confirm: { type: "boolean", description: "Must be true after explicit approval" },
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
            return await this.describeTable(args.table_name, args.schema_name || this.defaultSchema);
          case "list_tables":
            return await this.listTables(args.schema_name || this.defaultSchema);
          case "list_schemas":
            return await this.listSchemas();
          case "execute_insert":
            requireMutationConfirmation(args.confirm, "INSERT");
            return await this.executeInsert(args.table, args.data, args.schema_name || this.defaultSchema);
          case "execute_update":
            requireMutationConfirmation(args.confirm, "UPDATE");
            return await this.executeUpdate(
              args.table,
              args.data,
              args.filters,
              args.schema_name || this.defaultSchema
            );
          case "execute_delete":
            requireMutationConfirmation(args.confirm, "DELETE");
            return await this.executeDelete(args.table, args.filters, args.schema_name || this.defaultSchema);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return this.createErrorResult(error);
      }
    });
  }

  normalizeRow(row) {
    const normalized = {};
    for (const [column, value] of Object.entries(row)) {
      let output = Buffer.isBuffer(value) ? value.toString("base64") : value;
      let serialized;
      try {
        serialized = JSON.stringify(output);
      } catch {
        output = String(output);
        serialized = JSON.stringify(output);
      }
      if (Buffer.byteLength(serialized ?? "", "utf8") > this.maxFieldBytes) {
        output = "[omitted: field exceeds MAX_FIELD_BYTES]";
      }
      normalized[column] = output;
    }
    return normalized;
  }

  async executeQuery(query, parameters = []) {
    const normalizedQuery = this.validateSelectQuery(query);
    this.validateParameters(parameters);
    assertInputBudget(parameters, "Parameters", this.maxInputBytes, this.maxInputItems);
    if (this.maxRows === 0 || this.maxResponseBytes === 0) {
      throw new Error("Raw SELECT requires positive MAX_ROWS and MAX_RESPONSE_BYTES limits.");
    }
    await this.ensureSecurityVerified();

    const connection = await this.getConnection();
    let transactionStarted = false;
    let destroyed = false;
    let streamActive = false;
    let stream;
    try {
      await this.setSessionLimits(connection);
      await this.executeTransactionControl(connection, "START TRANSACTION READ ONLY");
      transactionStarted = true;

      let fields = [];
      const command = connection.execute({
        sql: normalizedQuery,
        values: parameters,
        timeout: this.statementTimeoutMs > 0 ? this.statementTimeoutMs : undefined,
        rowsAsArray: false,
      });
      command.once("fields", (receivedFields) => {
        fields = receivedFields || [];
      });
      stream = command.stream({ highWaterMark: 1 });
      streamActive = true;
      const rows = [];
      let responseBytes = 256;
      let truncated = false;

      for await (const rawRow of stream) {
        if (fields.length > this.maxColumns || Object.keys(rawRow).length > this.maxColumns) {
          throw new Error(`Query exceeds MAX_COLUMNS (${this.maxColumns}).`);
        }
        if (rows.length >= this.maxRows) {
          truncated = true;
          connection.destroy();
          destroyed = true;
          stream.destroy();
          break;
        }
        const row = this.normalizeRow(rawRow);
        const rowBytes = Buffer.byteLength(JSON.stringify(row), "utf8");
        if (responseBytes + rowBytes > Math.max(0, this.maxResponseBytes - 512)) {
          truncated = true;
          connection.destroy();
          destroyed = true;
          stream.destroy();
          break;
        }
        responseBytes += rowBytes;
        rows.push(row);
      }
      streamActive = false;

      if (fields.length > this.maxColumns) {
        throw new Error(`Query exceeds MAX_COLUMNS (${this.maxColumns}).`);
      }

      if (!destroyed) {
        if (!(await this.rollbackQuietly(connection))) {
          destroyed = true;
          throw new Error("Failed to close the read-only transaction safely.");
        }
        transactionStarted = false;
      }
      return this.createJsonResult({
        rows,
        rowCount: rows.length,
        truncated,
        fields: fields.map((field) => ({ name: field.name, type: field.type })),
      });
    } catch (error) {
      if (streamActive && !destroyed) {
        this.destroyConnectionForError(connection, error);
        destroyed = true;
        stream?.destroy();
      }
      if (!destroyed) {
        destroyed = await this.handleTransactionError(connection, error, transactionStarted);
      }
      throw error;
    } finally {
      if (!destroyed) connection.release();
    }
  }

  async describeTable(tableName, schemaName = this.defaultSchema) {
    this.validateIdentifier(tableName, "table name");
    this.validateIdentifier(schemaName, "schema name");
    assertExactAllowedTable(schemaName, tableName, this.allowedSchemas, this.allowedTables);
    await this.ensureSecurityVerified();

    const allowedColumns = exactAllowedColumnNames(schemaName, tableName, this.allowedColumns);
    if (this.allowedColumns.size > 0 && allowedColumns.length === 0) {
      throw new Error(`No columns are allowlisted for: ${schemaName}.${tableName}`);
    }
    const columnFilter = allowedColumns.length > 0
      ? ` AND BINARY COLUMN_NAME IN (${allowedColumns.map(() => "BINARY ?").join(", ")})`
      : "";
    const { rows: found } = await this.query(
      this.pool,
      `SELECT COLUMN_NAME AS column_name, DATA_TYPE AS data_type, COLUMN_TYPE AS column_type,
              IS_NULLABLE AS is_nullable, COLUMN_DEFAULT AS column_default,
              CHARACTER_MAXIMUM_LENGTH AS character_maximum_length,
              NUMERIC_PRECISION AS numeric_precision, NUMERIC_SCALE AS numeric_scale,
              EXTRA AS extra
         FROM INFORMATION_SCHEMA.COLUMNS
        WHERE BINARY TABLE_SCHEMA = BINARY ? AND BINARY TABLE_NAME = BINARY ?${columnFilter}
        ORDER BY ORDINAL_POSITION
        LIMIT ${this.maxColumns + 1}`,
      [schemaName, tableName, ...allowedColumns]
    );
    const truncated = found.length > this.maxColumns;
    const rows = found.slice(0, this.maxColumns);
    return this.createJsonResult({
      table: `${schemaName}.${tableName}`,
      columns: rows,
      rowCount: rows.length,
      truncated,
    });
  }

  async listTables(schemaName = this.defaultSchema) {
    this.validateIdentifier(schemaName, "schema name");
    assertExactAllowedSchema(schemaName, this.allowedSchemas);
    await this.ensureSecurityVerified();
    const limit = this.metadataRowLimit();
    const tablePrefix = `${schemaName}.`;
    const allowlistedNames = this.allowedTables.size === 0
      ? []
      : Array.from(this.allowedTables)
          .filter((name) => name.startsWith(tablePrefix))
          .map((name) => name.slice(tablePrefix.length));
    if (this.allowedTables.size > 0 && allowlistedNames.length === 0) {
      return this.createJsonResult({ schema: schemaName, tables: [], rowCount: 0, truncated: false });
    }
    const tablePredicate = allowlistedNames.length > 0
      ? ` AND BINARY TABLE_NAME IN (${allowlistedNames.map(() => "BINARY ?").join(", ")})`
      : "";
    const { rows: found } = await this.query(
      this.pool,
      `SELECT TABLE_NAME AS table_name, TABLE_TYPE AS table_type
         FROM INFORMATION_SCHEMA.TABLES
        WHERE BINARY TABLE_SCHEMA = BINARY ? AND TABLE_TYPE IN ('BASE TABLE', 'VIEW')${tablePredicate}
        ORDER BY TABLE_NAME
        LIMIT ${limit + 1}`,
      [schemaName, ...allowlistedNames]
    );
    const filtered = this.allowedTables.size === 0
      ? found
      : found.filter((row) =>
          this.allowedTables.has(`${schemaName}.${row.table_name}`)
        );
    const truncated = filtered.length > limit;
    const tables = filtered.slice(0, limit);
    return this.createJsonResult({ schema: schemaName, tables, rowCount: tables.length, truncated });
  }

  async listSchemas() {
    await this.ensureSecurityVerified();
    const limit = this.metadataRowLimit();
    const allowedSchemaNames = Array.from(this.allowedSchemas);
    const schemaPredicate = allowedSchemaNames.length > 0
      ? ` AND BINARY SCHEMA_NAME IN (${allowedSchemaNames.map(() => "BINARY ?").join(", ")})`
      : "";
    const { rows } = await this.query(
      this.pool,
      `SELECT SCHEMA_NAME AS schema_name
         FROM INFORMATION_SCHEMA.SCHEMATA
        WHERE SCHEMA_NAME NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')${schemaPredicate}
        ORDER BY SCHEMA_NAME
        LIMIT ${limit + 1}`,
      allowedSchemaNames
    );
    const filtered = rows
      .map((row) => row.schema_name)
      .filter((schema) => this.allowedSchemas.size === 0 || this.allowedSchemas.has(schema));
    const truncated = filtered.length > limit;
    const schemas = filtered.slice(0, limit);
    return this.createJsonResult({ schemas, rowCount: schemas.length, truncated });
  }

  async executeInsert(table, data, schemaName = this.defaultSchema) {
    this.ensureWritesAllowed("INSERT");
    this.validateIdentifier(table, "table name");
    this.validateIdentifier(schemaName, "schema name");
    this.validateDataObject(data);
    assertExactAllowedTable(schemaName, table, this.allowedSchemas, this.allowedTables);
    this.validateAllowedColumns(schemaName, table, Object.keys(data));
    assertInputBudget(data, "Data", this.maxInputBytes, this.maxInputItems);
    await this.ensureSecurityVerified();

    const columns = Object.keys(data);
    const values = Object.values(data);
    const tableName = this.quoteQualifiedName(schemaName, table, "table name");
    const connection = await this.getConnection();
    let transactionStarted = false;
    let destroyed = false;
    try {
      await this.executeTransactionControl(connection, "START TRANSACTION");
      transactionStarted = true;
      const { rows: result } = await this.query(
        connection,
        `INSERT INTO ${tableName} (${columns
          .map((column) => this.quoteIdentifier(column, "column name"))
          .join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`,
        values
      );
      await this.executeTransactionControl(connection, "COMMIT");
      transactionStarted = false;
      auditMutation("mysql", "insert", { schema: schemaName, table, rowsAffected: result.affectedRows });
      return this.createJsonResult({
        inserted: this.returnMutationRows ? { ...data, insertId: result.insertId } : undefined,
        rowCount: result.affectedRows,
        insertId: String(result.insertId ?? ""),
      });
    } catch (error) {
      destroyed = await this.handleTransactionError(connection, error, transactionStarted);
      throw error;
    } finally {
      if (!destroyed) connection.release();
    }
  }

  mutationProjection(schemaName, tableName) {
    const columns = exactAllowedColumnNames(schemaName, tableName, this.allowedColumns);
    return columns.length > 0
      ? columns.map((column) => this.quoteIdentifier(column, "column name")).join(", ")
      : "*";
  }

  async preflightAffectedRows(connection, tableName, filter, schemaName, table) {
    if (this.maxAffectedRows === 0) return [];
    const projection = this.returnMutationRows ? this.mutationProjection(schemaName, table) : "1";
    const sql = `SELECT ${projection} FROM ${tableName} WHERE ${filter.clause} LIMIT ${this.maxAffectedRows + 1} FOR UPDATE`;
    if (this.returnMutationRows) {
      return this.streamMutationSnapshots(connection, sql, filter.values);
    }
    const { rows } = await this.query(
      connection,
      sql,
      filter.values
    );
    if (rows.length > this.maxAffectedRows) {
      throw new Error(
        `Operation would affect more than MAX_AFFECTED_ROWS (${this.maxAffectedRows}) rows.`
      );
    }
    return rows;
  }

  async streamMutationSnapshots(connection, sql, values) {
    let fields = [];
    let stream;
    let streamActive = false;
    const rows = [];
    let responseBytes = 256;
    let tooManyRows = false;

    try {
      const command = connection.execute({
        sql,
        values,
        timeout: this.statementTimeoutMs > 0 ? this.statementTimeoutMs : undefined,
        rowsAsArray: false,
      });
      command.once("fields", (receivedFields) => {
        fields = receivedFields || [];
      });
      stream = command.stream({ highWaterMark: 1 });
      streamActive = true;

      for await (const rawRow of stream) {
        if (fields.length > this.maxColumns || Object.keys(rawRow).length > this.maxColumns) {
          throw new Error(`Mutation snapshot exceeds MAX_COLUMNS (${this.maxColumns}).`);
        }
        if (rows.length >= this.maxAffectedRows) {
          tooManyRows = true;
          continue;
        }

        const row = this.normalizeRow(rawRow);
        const prettyRow = JSON.stringify(row, null, 2);
        const embeddedIndentBytes = (prettyRow.match(/\n/g) || []).length * 4;
        const rowBytes = Buffer.byteLength(prettyRow, "utf8") + embeddedIndentBytes + 8;
        if (responseBytes + rowBytes > Math.max(0, this.maxResponseBytes - 512)) {
          throw new Error(
            "Mutation snapshots exceed MAX_RESPONSE_BYTES. Refine the filters or disable RETURN_MUTATION_ROWS."
          );
        }
        responseBytes += rowBytes;
        rows.push(row);
      }
      streamActive = false;

      if (fields.length > this.maxColumns) {
        throw new Error(`Mutation snapshot exceeds MAX_COLUMNS (${this.maxColumns}).`);
      }

      if (tooManyRows) {
        throw new Error(
          `Operation would affect more than MAX_AFFECTED_ROWS (${this.maxAffectedRows}) rows.`
        );
      }
      return rows;
    } catch (error) {
      if (streamActive) {
        this.destroyConnectionForError(connection, error);
        stream?.destroy();
      }
      throw error;
    }
  }

  async executeUpdate(table, data, filters, schemaName = this.defaultSchema) {
    this.ensureWritesAllowed("UPDATE");
    this.validateIdentifier(table, "table name");
    this.validateIdentifier(schemaName, "schema name");
    this.validateDataObject(data);
    this.validateFilters(filters);
    assertExactAllowedTable(schemaName, table, this.allowedSchemas, this.allowedTables);
    this.validateAllowedColumns(schemaName, table, Object.keys(data));
    this.validateAllowedFilterColumns(schemaName, table, filters);
    assertInputBudget(data, "Data", this.maxInputBytes, this.maxInputItems);
    assertInputBudget(filters, "Filters", this.maxInputBytes, this.maxInputItems);
    await this.ensureSecurityVerified();

    const tableName = this.quoteQualifiedName(schemaName, table, "table name");
    const filter = this.buildFilterClause(filters);
    const columns = Object.keys(data);
    const connection = await this.getConnection();
    let transactionStarted = false;
    let destroyed = false;
    try {
      await this.executeTransactionControl(
        connection,
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
      );
      await this.executeTransactionControl(connection, "START TRANSACTION");
      transactionStarted = true;
      const snapshots = await this.preflightAffectedRows(connection, tableName, filter, schemaName, table);
      const { rows: result } = await this.query(
        connection,
        `UPDATE ${tableName} SET ${columns
          .map((column) => `${this.quoteIdentifier(column, "column name")} = ?`)
          .join(", ")} WHERE ${filter.clause}`,
        [...Object.values(data), ...filter.values]
      );
      if (this.maxAffectedRows > 0 && result.affectedRows > this.maxAffectedRows) {
        throw new Error(
          `Operation affected more than MAX_AFFECTED_ROWS (${this.maxAffectedRows}) rows.`
        );
      }
      await this.executeTransactionControl(connection, "COMMIT");
      transactionStarted = false;
      auditMutation("mysql", "update", { schema: schemaName, table, rowsAffected: result.affectedRows });
      return this.createJsonResult({
        matchedBeforeUpdate: this.returnMutationRows ? snapshots : undefined,
        rowCount: result.affectedRows,
        changedRows: result.changedRows,
      });
    } catch (error) {
      destroyed = await this.handleTransactionError(connection, error, transactionStarted);
      throw error;
    } finally {
      if (!destroyed) connection.release();
    }
  }

  async executeDelete(table, filters, schemaName = this.defaultSchema) {
    this.ensureDeleteAllowed();
    this.validateIdentifier(table, "table name");
    this.validateIdentifier(schemaName, "schema name");
    this.validateFilters(filters);
    assertExactAllowedTable(schemaName, table, this.allowedSchemas, this.allowedTables);
    this.validateAllowedFilterColumns(schemaName, table, filters);
    assertInputBudget(filters, "Filters", this.maxInputBytes, this.maxInputItems);
    await this.ensureSecurityVerified();

    const tableName = this.quoteQualifiedName(schemaName, table, "table name");
    const filter = this.buildFilterClause(filters);
    const connection = await this.getConnection();
    let transactionStarted = false;
    let destroyed = false;
    try {
      await this.executeTransactionControl(
        connection,
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
      );
      await this.executeTransactionControl(connection, "START TRANSACTION");
      transactionStarted = true;
      const snapshots = await this.preflightAffectedRows(connection, tableName, filter, schemaName, table);
      const { rows: result } = await this.query(
        connection,
        `DELETE FROM ${tableName} WHERE ${filter.clause}`,
        filter.values
      );
      if (this.maxAffectedRows > 0 && result.affectedRows > this.maxAffectedRows) {
        throw new Error(
          `Operation affected more than MAX_AFFECTED_ROWS (${this.maxAffectedRows}) rows.`
        );
      }
      await this.executeTransactionControl(connection, "COMMIT");
      transactionStarted = false;
      auditMutation("mysql", "delete", { schema: schemaName, table, rowsAffected: result.affectedRows });
      return this.createJsonResult({
        deleted: this.returnMutationRows ? snapshots : undefined,
        rowCount: result.affectedRows,
      });
    } catch (error) {
      destroyed = await this.handleTransactionError(connection, error, transactionStarted);
      throw error;
    } finally {
      if (!destroyed) connection.release();
    }
  }

  setupErrorHandlers() {
    this.server.onerror = () => console.error("[MCP Error] Internal protocol error.");
    this.pool.on("error", () => {
      console.error("[MySQL MCP] An idle database connection failed; the pool will replace it.");
    });
  }

  shutdown() {
    return new Promise((resolvePromise, rejectPromise) => {
      this.pool.end((error) => {
        if (error) rejectPromise(error);
        else resolvePromise();
      });
    });
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
    console.error("MySQL MCP server running on stdio");
  }
}

const isMainModule = process.argv[1] && resolve(process.argv[1]) === __filename;
if (isMainModule) {
  const server = new MySQLMCPServer();
  server.run().catch((error) => {
    console.error(`[MySQL MCP] Startup failed: code=${error.code || error.name || "unknown"}`);
    process.exitCode = 1;
  });
}

export {
  FORBIDDEN_SQL_PATTERN,
  LOCKING_READ_PATTERN,
  maskSqlLiterals,
  MySQLMCPServer,
  normalizeSelectQuery,
  parseGrantScope,
};
