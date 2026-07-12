#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import sql from "mssql";
import dotenv from "dotenv";
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';
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
} from '../shared/security.js';

// Get the directory of this script
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables from the MCP server's directory
const envPath = join(__dirname, '.env');
const result = dotenv.config({ path: envPath, override: false });
const debugEnabled = process.env.DEBUG === 'true';

function debugLog(message) {
  if (debugEnabled) {
    console.error(message);
  }
}

if (result.error) {
  debugLog(`[MSSQL MCP] Error loading .env file: code=${result.error.code || result.error.name || 'unknown'}`);
} else {
  debugLog(`[MSSQL MCP] .env file loaded from: ${envPath}`);
}

const PARAMETER_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const FORBIDDEN_SQL_PATTERN = /(;|--|\/\*|\*\/|\b(insert|update|delete|merge|drop|alter|create|truncate|exec|execute|grant|revoke|backup|restore|into)\b)/i;

function maskSqlLiterals(query) {
  const characters = query.split('');
  const blankCharacter = (index) => {
    characters[index] = query[index] === '\n' ? '\n' : ' ';
  };

  for (let index = 0; index < query.length; index += 1) {
    // Double quotes delimit identifiers with QUOTED_IDENTIFIER ON and strings when it is OFF.
    if (query[index] === "'" || query[index] === '"') {
      const quote = query[index];
      blankCharacter(index);
      index += 1;

      while (index < query.length) {
        blankCharacter(index);
        if (query[index] === quote) {
          if (query[index + 1] === quote) {
            index += 1;
            blankCharacter(index);
          } else {
            break;
          }
        }
        index += 1;
      }
      continue;
    }

    // T-SQL bracketed identifiers escape a closing bracket as ]].
    if (query[index] === '[') {
      blankCharacter(index);
      index += 1;

      while (index < query.length) {
        blankCharacter(index);
        if (query[index] === ']') {
          if (query[index + 1] === ']') {
            index += 1;
            blankCharacter(index);
          } else {
            break;
          }
        }
        index += 1;
      }
    }
  }

  return characters.join('');
}

class MSSQLMCPServer {
  constructor() {
    this.mode = (process.env.MCP_MODE || 'read').toLowerCase();
    if (!['read', 'write'].includes(this.mode)) {
      throw new Error('MCP_MODE must be either read or write.');
    }
    this.allowWrites = process.env.ALLOW_WRITES === 'true';
    this.allowDelete = process.env.ALLOW_DELETE === 'true';
    if (this.allowWrites && this.mode !== 'write') {
      throw new Error('ALLOW_WRITES=true requires a separate MCP_MODE=write deployment.');
    }
    this.allowArbitrarySelect = process.env.ALLOW_ARBITRARY_SELECT === 'true';
    this.allowDatabaseList = process.env.ALLOW_DATABASE_LIST === 'true';
    this.allowStoredProcedures = process.env.ALLOW_STORED_PROCEDURES === 'true';
    if (this.allowStoredProcedures && this.mode !== 'write') {
      throw new Error('ALLOW_STORED_PROCEDURES=true requires a separate MCP_MODE=write deployment.');
    }
    this.returnMutationRows = process.env.RETURN_MUTATION_ROWS === 'true';
    this.allowedProcedures = this.parseAllowList(process.env.ALLOWED_PROCEDURES);
    this.allowedSelectFunctions = parseCsvSet(process.env.ALLOWED_SELECT_FUNCTIONS);
    this.allowedSchemas = parseCsvSet(process.env.ALLOWED_SCHEMAS, 'dbo');
    this.allowedTables = parseCsvSet(process.env.ALLOWED_TABLES);
    this.allowedColumns = parseCsvSet(process.env.ALLOWED_COLUMNS);
    if (this.allowArbitrarySelect && this.allowedColumns.size > 0) {
      throw new Error(
        'ALLOWED_COLUMNS requires ALLOW_ARBITRARY_SELECT=false; expose curated views for raw-query deployments.'
      );
    }
    this.verifyDbPrivileges = process.env.VERIFY_DB_PRIVILEGES !== 'false';
    this.maxRows = this.parseNonNegativeInteger(process.env.MAX_ROWS, 1000, 'MAX_ROWS');
    this.maxAffectedRows = this.parseNonNegativeInteger(
      process.env.MAX_AFFECTED_ROWS,
      100,
      'MAX_AFFECTED_ROWS'
    );
    this.maxResponseBytes = this.parseNonNegativeInteger(
      process.env.MAX_RESPONSE_BYTES,
      1000000,
      'MAX_RESPONSE_BYTES'
    );
    this.maxFieldBytes = this.parsePositiveInteger(
      process.env.MAX_FIELD_BYTES,
      65536,
      'MAX_FIELD_BYTES'
    );
    this.maxColumns = this.parsePositiveInteger(
      process.env.MAX_COLUMNS,
      100,
      'MAX_COLUMNS'
    );
    this.statementTimeoutMs = this.parseNonNegativeInteger(
      process.env.STATEMENT_TIMEOUT_MS,
      30000,
      'STATEMENT_TIMEOUT_MS'
    );
    this.connectionTimeoutMs = this.parseNonNegativeInteger(
      process.env.CONNECTION_TIMEOUT_MS,
      10000,
      'CONNECTION_TIMEOUT_MS'
    );
    this.maxInputBytes = this.parsePositiveInteger(
      process.env.MAX_INPUT_BYTES,
      65536,
      'MAX_INPUT_BYTES'
    );
    this.maxInputItems = this.parsePositiveInteger(
      process.env.MAX_INPUT_ITEMS,
      100,
      'MAX_INPUT_ITEMS'
    );
    this.maxRequestBytes = this.parsePositiveInteger(
      process.env.MAX_REQUEST_BYTES,
      262144,
      'MAX_REQUEST_BYTES'
    );

    this.server = new Server(
      {
        name: "mssql-mcp-server",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Initialize database connection pool
    this.pool = null;
    this.poolPromise = null;
    this.config = this.buildConnectionConfig();

    this.setupToolHandlers();
    this.setupErrorHandlers();
  }

  buildConnectionConfig() {
    const user = process.env.DB_USER?.trim();
    if (!user) {
      throw new Error(
        'DB_USER is required. Configure a dedicated least-privilege SQL Server login.'
      );
    }

    const server = process.env.DB_HOST || 'localhost';
    const localServer = ['localhost', '127.0.0.1', '::1'].includes(server.toLowerCase());
    const config = {
      user,
      password: process.env.DB_PASSWORD || '',
      server,
      port: this.parsePositiveInteger(process.env.DB_PORT, 1433, 'DB_PORT'),
      database: process.env.DB_NAME || 'master',
      connectionTimeout: this.connectionTimeoutMs,
      requestTimeout: this.statementTimeoutMs,
      pool: {
        max: this.parsePositiveInteger(process.env.MAX_CONNECTIONS, 10, 'MAX_CONNECTIONS'),
        min: 0,
        idleTimeoutMillis: 30000,
        acquireTimeoutMillis: 2000,
      },
      options: {
        encrypt: process.env.DB_ENCRYPT !== 'false',
        trustServerCertificate: process.env.DB_TRUST_SERVER_CERTIFICATE === undefined
          ? localServer
          : process.env.DB_TRUST_SERVER_CERTIFICATE === 'true',
        enableArithAbort: true,
      },
    };

    debugLog(`[MSSQL MCP] Connecting to: ${config.server}:${config.port}/${config.database} as ${config.user}`);
    debugLog(`[MSSQL MCP] Encrypt: ${config.options.encrypt}, Trust Certificate: ${config.options.trustServerCertificate}`);

    return config;
  }

  parseAllowList(value) {
    return parseCsvSet(value);
  }

  parseNonNegativeInteger(value, defaultValue, label) {
    return parseSharedNonNegativeInteger(value, defaultValue, label);
  }

  parsePositiveInteger(value, defaultValue, label) {
    return parseSharedPositiveInteger(value, defaultValue, label);
  }

  validateIdentifier(identifier, label = 'identifier') {
    validateSharedIdentifier(identifier, label);
  }

  quoteIdentifier(identifier, label = 'identifier') {
    this.validateIdentifier(identifier, label);
    return `[${identifier}]`;
  }

  quoteQualifiedName(schemaName, objectName, objectLabel = 'object name') {
    return `${this.quoteIdentifier(schemaName, 'schema name')}.${this.quoteIdentifier(objectName, objectLabel)}`;
  }

  validateParameters(parameters = {}) {
    if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) {
      throw new Error('Parameters must be an object of named values.');
    }

    for (const key of Object.keys(parameters)) {
      if (!PARAMETER_PATTERN.test(key)) {
        throw new Error(`Invalid parameter name: ${key}`);
      }
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

  ensureWritesAllowed(operation) {
    if (this.mode !== 'write') {
      throw new Error(`${operation} requires a separate MCP_MODE=write deployment.`);
    }
    if (!this.allowWrites) {
      throw new Error(`${operation} is disabled. Set ALLOW_WRITES=true to enable write tools.`);
    }
  }

  ensureDeleteAllowed() {
    this.ensureWritesAllowed('DELETE');
    if (!this.allowDelete) {
      throw new Error('DELETE is disabled. Set ALLOW_DELETE=true to enable delete operations.');
    }
  }

  ensureStoredProceduresAllowed(schemaName, procedureName) {
    if (this.mode !== 'write') {
      throw new Error('Stored procedure execution requires a separate MCP_MODE=write deployment.');
    }
    if (!this.allowStoredProcedures) {
      throw new Error('Stored procedure execution is disabled. Set ALLOW_STORED_PROCEDURES=true to enable it.');
    }

    const qualifiedName = `${schemaName}.${procedureName}`.toLowerCase();
    if (!this.allowedProcedures.has(qualifiedName)) {
      throw new Error(`Stored procedure is not allowlisted: ${schemaName}.${procedureName}`);
    }
  }

  validateSelectQuery(query) {
    if (!this.allowArbitrarySelect) {
      throw new Error('execute_query is disabled. Set ALLOW_ARBITRARY_SELECT=true only with a database-enforced read-only login.');
    }
    if (typeof query !== 'string' || query.trim().length === 0) {
      throw new Error('Query is required.');
    }

    assertInputBudget(query, 'Query', this.maxInputBytes, 0);
    const trimmedQuery = query.trim();
    if (!/^select\b/i.test(trimmedQuery)) {
      throw new Error('Only SELECT queries are allowed with execute_query. Use specific tools for INSERT, UPDATE, DELETE.');
    }

    const maskedQuery = maskSqlLiterals(trimmedQuery);
    if (FORBIDDEN_SQL_PATTERN.test(maskedQuery)) {
      throw new Error('Query contains forbidden SQL syntax.');
    }
    if (/\bNEXT\s+VALUE\s+FOR\b/i.test(maskedQuery)) {
      throw new Error('Query contains a sequence operation that is not permitted.');
    }
    assertAllowedFunctions(maskedQuery, this.allowedSelectFunctions);
  }

  validateFilters(filters) {
    validateSharedFilters(filters, this.validateIdentifier.bind(this));
  }

  buildFilterClause(filters) {
    this.validateFilters(filters);
    const parameters = {};

    const clauses = filters.map((filter, filterIndex) => {
      const column = this.quoteIdentifier(filter.column, 'filter column name');

      if (filter.operator === 'is_null' || (filter.operator === 'eq' && filter.value === null)) {
        return `${column} IS NULL`;
      }

      if (filter.operator === 'is_not_null' || (filter.operator === 'neq' && filter.value === null)) {
        return `${column} IS NOT NULL`;
      }

      if (filter.value === null) {
        throw new Error(`The ${filter.operator} operator does not accept null.`);
      }

      if (filter.operator === 'in') {
        const placeholders = filter.value.map((value, valueIndex) => {
          const parameterName = `filter_${filterIndex}_${valueIndex}`;
          parameters[parameterName] = value;
          return `@${parameterName}`;
        });
        return `${column} IN (${placeholders.join(', ')})`;
      }

      const sqlOperators = {
        eq: '=',
        neq: '<>',
        gt: '>',
        gte: '>=',
        lt: '<',
        lte: '<=',
        like: 'LIKE',
      };
      const parameterName = `filter_${filterIndex}`;
      parameters[parameterName] = filter.value;
      return `${column} ${sqlOperators[filter.operator]} @${parameterName}`;
    });

    return {
      clause: clauses.join(' AND '),
      parameters,
    };
  }

  addParameters(request, parameters) {
    for (const [key, value] of Object.entries(parameters)) {
      request.input(key, value);
    }
  }

  createJsonResult(payload) {
    return createSharedJsonResult(payload, this.maxResponseBytes);
  }

  createErrorResult(error) {
    return createSafeErrorResult(error, this.maxResponseBytes, debugLog);
  }

  async verifyConnectionSecurity(pool) {
    if (!this.verifyDbPrivileges) {
      return;
    }
    const result = await pool.request().query(`
      SELECT
        IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin,
        IS_MEMBER('db_owner') AS is_db_owner,
        IS_MEMBER('db_ddladmin') AS is_db_ddladmin,
        IS_MEMBER('db_datawriter') AS is_db_datawriter,
        HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CONTROL') AS has_database_control,
        HAS_PERMS_BY_NAME(NULL, 'SERVER', 'CONTROL SERVER') AS has_server_control,
        CASE WHEN EXISTS (
          SELECT 1
          FROM sys.tables AS candidate
          WHERE HAS_PERMS_BY_NAME(
            QUOTENAME(SCHEMA_NAME(candidate.schema_id)) + '.' + QUOTENAME(candidate.name),
            'OBJECT',
            'INSERT'
          ) = 1
          OR HAS_PERMS_BY_NAME(
            QUOTENAME(SCHEMA_NAME(candidate.schema_id)) + '.' + QUOTENAME(candidate.name),
            'OBJECT',
            'UPDATE'
          ) = 1
          OR HAS_PERMS_BY_NAME(
            QUOTENAME(SCHEMA_NAME(candidate.schema_id)) + '.' + QUOTENAME(candidate.name),
            'OBJECT',
            'DELETE'
          ) = 1
        ) THEN 1 ELSE 0 END AS has_table_write_permission,
        CASE WHEN EXISTS (
          SELECT 1
          FROM sys.sequences AS candidate
          WHERE HAS_PERMS_BY_NAME(
            QUOTENAME(SCHEMA_NAME(candidate.schema_id)) + '.' + QUOTENAME(candidate.name),
            'OBJECT',
            'UPDATE'
          ) = 1
          OR HAS_PERMS_BY_NAME(
            QUOTENAME(SCHEMA_NAME(candidate.schema_id)) + '.' + QUOTENAME(candidate.name),
            'OBJECT',
            'ALTER'
          ) = 1
        ) THEN 1 ELSE 0 END AS has_sequence_write_permission
    `);
    const privileges = result.recordset?.[0] || {};
    const unsafe = this.mode === 'write'
      ? Object.entries(privileges).filter(([name, enabled]) =>
          !['has_table_write_permission', 'has_sequence_write_permission'].includes(name) &&
          Number(enabled) === 1
        )
      : Object.entries(privileges).filter(([, enabled]) => Number(enabled) === 1);
    if (unsafe.length > 0) {
      throw new Error(
        `Database login has unsafe privileges: ${unsafe.map(([name]) => name).join(', ')}.`
      );
    }
  }

  async getPool() {
    if (this.pool) {
      return this.pool;
    }
    if (!this.poolPromise) {
      this.poolPromise = (async () => {
        const pool = new sql.ConnectionPool(this.config);
        try {
          await pool.connect();
          pool.on('error', () => {
            console.error('[MSSQL MCP] An idle database connection failed; the pool will replace it.');
          });
          await this.verifyConnectionSecurity(pool);
          this.pool = pool;
          debugLog(`[MSSQL MCP] Successfully connected to SQL Server`);
          return pool;
      } catch (error) {
        await pool.close().catch(() => {});
          debugLog(`[MSSQL MCP] Connection failed: code=${error.code || error.name || 'unknown'}`);
          throw error;
        } finally {
          this.poolPromise = null;
        }
      })();
    }
    return this.poolPromise;
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const tools = [
        {
          name: "execute_query",
          description: "Execute a SELECT query on the SQL Server database",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              query: {
                type: "string",
                description: "SQL SELECT query to execute",
              },
              parameters: {
                type: "object",
                description: "Optional named parameters for parameterized queries",
                default: {},
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
              table_name: {
                type: "string",
                description: "Name of the table to describe",
              },
              schema_name: {
                type: "string",
                description: "Schema name (optional, defaults to 'dbo')",
                default: "dbo",
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
                description: "Schema name (optional, defaults to 'dbo')",
                default: "dbo",
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
        {
          name: "list_databases",
          description: "List all databases on the SQL Server instance",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {},
          },
        },
      ];

      if (!this.allowArbitrarySelect) {
        tools.splice(tools.findIndex((tool) => tool.name === 'execute_query'), 1);
      }
      if (!this.allowDatabaseList) {
        tools.splice(tools.findIndex((tool) => tool.name === 'list_databases'), 1);
      }

      if (this.allowWrites) {
        tools.push(
        {
          name: "execute_insert",
          description: "Execute an INSERT statement on the SQL Server database",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              table: {
                type: "string",
                description: "Table name to insert into",
              },
              data: {
                type: "object",
                description: "Key-value pairs of column names and values to insert",
              },
              schema_name: {
                type: "string",
                description: "Schema name (optional, defaults to 'dbo')",
                default: "dbo",
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
          description: "Execute an UPDATE statement on the SQL Server database",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              table: {
                type: "string",
                description: "Table name to update",
              },
              data: {
                type: "object",
                description: "Key-value pairs of column names and new values",
              },
              filters: FILTERS_INPUT_SCHEMA,
              schema_name: {
                type: "string",
                description: "Schema name (optional, defaults to 'dbo')",
                default: "dbo",
              },
              confirm: {
                type: "boolean",
                description: "Must be true after explicit user approval",
              },
            },
            required: ["table", "data", "filters", "confirm"],
          },
        });
      }

      if (this.allowWrites && this.allowDelete) {
        tools.push(
        {
          name: "execute_delete",
          description: "Execute a DELETE statement on the SQL Server database",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              table: {
                type: "string",
                description: "Table name to delete from",
              },
              filters: FILTERS_INPUT_SCHEMA,
              schema_name: {
                type: "string",
                description: "Schema name (optional, defaults to 'dbo')",
                default: "dbo",
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

      if (this.allowStoredProcedures) {
        tools.push(
        {
          name: "execute_stored_procedure",
          description: "Execute a stored procedure on the SQL Server database",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              procedure_name: {
                type: "string",
                description: "Name of the stored procedure to execute",
              },
              parameters: {
                type: "object",
                description: "Named parameters for the stored procedure",
                default: {},
              },
              schema_name: {
                type: "string",
                description: "Schema name (optional, defaults to 'dbo')",
                default: "dbo",
              },
              confirm: {
                type: "boolean",
                description: "Must be true after explicit user approval",
              },
            },
            required: ["procedure_name", "confirm"],
          },
        });
      }

      return { tools };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args = {} } = request.params;

      try {
        switch (name) {
          case "execute_query":
            return await this.executeQuery(args.query, args.parameters || {});

          case "describe_table":
            return await this.describeTable(args.table_name, args.schema_name || 'dbo');

          case "list_tables":
            return await this.listTables(args.schema_name || 'dbo');

          case "list_schemas":
            return await this.listSchemas();

          case "list_databases":
            return await this.listDatabases();

          case "execute_insert":
            requireMutationConfirmation(args.confirm, 'INSERT');
            return await this.executeInsert(args.table, args.data, args.schema_name || 'dbo');

          case "execute_update":
            requireMutationConfirmation(args.confirm, 'UPDATE');
            return await this.executeUpdate(
              args.table,
              args.data,
              args.filters,
              args.schema_name || 'dbo'
            );

          case "execute_delete":
            requireMutationConfirmation(args.confirm, 'DELETE');
            return await this.executeDelete(
              args.table,
              args.filters,
              args.schema_name || 'dbo'
            );

          case "execute_stored_procedure":
            requireMutationConfirmation(args.confirm, 'Stored procedure execution');
            return await this.executeStoredProcedure(
              args.procedure_name,
              args.parameters || {},
              args.schema_name || 'dbo'
            );

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return this.createErrorResult(error);
      }
    });
  }

  async executeQuery(query, parameters = {}) {
    this.validateSelectQuery(query);
    this.validateParameters(parameters);
    assertInputBudget(parameters, 'Parameters', this.maxInputBytes, this.maxInputItems);
    if (this.maxRows === 0 || this.maxResponseBytes === 0) {
      throw new Error('Raw SELECT requires positive MAX_ROWS and MAX_RESPONSE_BYTES limits.');
    }

    const pool = await this.getPool();
    const request = pool.request();

    this.addParameters(request, parameters);
    const { rows: recordset, truncated, fields } = await this.executeBoundedSelect(
      request,
      query
    );

    return this.createJsonResult({
      recordsets: [recordset],
      recordset,
      fields,
      rowCount: recordset?.length ?? 0,
      truncated,
    });
  }

  async executeBoundedSelect(request, query) {
    const rows = [];
    let fields = [];
    let responseBytes = 256;
    let cancellationReason = null;
    let truncated = false;
    const readable = request.toReadableStream({ highWaterMark: 1 });

    request.on('recordset', (columns) => {
      fields = Object.keys(columns || {});
      if (fields.length > this.maxColumns && !cancellationReason) {
        cancellationReason = 'columns';
        request.cancel();
      }
    });

    const completion = request.query(`SET TEXTSIZE ${this.maxFieldBytes}; ${query}`);
    try {
      for await (const row of readable) {
        if (rows.length >= this.maxRows) {
          truncated = true;
          cancellationReason = 'rows';
          request.cancel();
          break;
        }
        const rowBytes = Buffer.byteLength(JSON.stringify(row), 'utf8');
        if (responseBytes + rowBytes > Math.max(0, this.maxResponseBytes - 512)) {
          truncated = true;
          cancellationReason = 'bytes';
          request.cancel();
          break;
        }
        responseBytes += rowBytes;
        rows.push(row);
      }
    } catch (error) {
      if (!cancellationReason) {
        throw error;
      }
    }

    await completion.catch((error) => {
      if (!cancellationReason) {
        throw error;
      }
    });
    if (cancellationReason === 'columns') {
      throw new Error(`Query exceeds MAX_COLUMNS (${this.maxColumns}).`);
    }
    return { rows, fields, truncated };
  }

  async describeTable(tableName, schemaName = 'dbo') {
    this.validateIdentifier(tableName, 'table name');
    this.validateIdentifier(schemaName, 'schema name');
    assertAllowedTable(schemaName, tableName, this.allowedSchemas, this.allowedTables);

    const allowedColumns = allowedColumnNames(schemaName, tableName, this.allowedColumns);
    if (this.allowedColumns.size > 0 && allowedColumns.length === 0) {
      throw new Error(`No columns are allowlisted for: ${schemaName}.${tableName}`);
    }
    const columnFilter = allowedColumns.length > 0
      ? `AND LOWER(COLUMN_NAME) IN (${allowedColumns.map((_, index) => `@allowedColumn_${index}`).join(', ')})`
      : '';
    const query = `
      SELECT
        COLUMN_NAME,
        DATA_TYPE,
        IS_NULLABLE,
        COLUMN_DEFAULT,
        CHARACTER_MAXIMUM_LENGTH,
        NUMERIC_PRECISION,
        NUMERIC_SCALE,
        ORDINAL_POSITION
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_NAME = @tableName AND TABLE_SCHEMA = @schemaName
      ${columnFilter}
      ORDER BY ORDINAL_POSITION;
    `;

    const pool = await this.getPool();
    const request = pool.request();
    request.input('tableName', sql.NVarChar, tableName);
    request.input('schemaName', sql.NVarChar, schemaName);
    allowedColumns.forEach((column, index) => {
      request.input(`allowedColumn_${index}`, sql.NVarChar, column);
    });

    const result = await request.query(query);

    return this.createJsonResult({
      table: `${schemaName}.${tableName}`,
      columns: result.recordset,
      rowCount: result.recordset.length,
    });
  }

  async listTables(schemaName = 'dbo') {
    this.validateIdentifier(schemaName, 'schema name');
    assertAllowedSchema(schemaName, this.allowedSchemas);

    const query = `
      SELECT TABLE_NAME, TABLE_TYPE
      FROM INFORMATION_SCHEMA.TABLES
      WHERE TABLE_SCHEMA = @schemaName
      ORDER BY TABLE_NAME;
    `;

    const pool = await this.getPool();
    const request = pool.request();
    request.input('schemaName', sql.NVarChar, schemaName);

    const result = await request.query(query);
    const rows = this.allowedTables.size === 0
      ? result.recordset
      : result.recordset.filter((row) =>
          this.allowedTables.has(`${schemaName}.${row.TABLE_NAME}`.toLowerCase())
        );

    return this.createJsonResult({
      schema: schemaName,
      tables: rows,
      rowCount: rows.length,
    });
  }

  async listSchemas() {
    const query = `
      SELECT SCHEMA_NAME
      FROM INFORMATION_SCHEMA.SCHEMATA
      WHERE SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA', 'sys', 'guest')
      ORDER BY SCHEMA_NAME;
    `;

    const pool = await this.getPool();
    const request = pool.request();
    const result = await request.query(query);
    const schemas = result.recordset
      .map(row => row.SCHEMA_NAME)
      .filter(schema => this.allowedSchemas.size === 0 || this.allowedSchemas.has(schema.toLowerCase()));

    return this.createJsonResult({
      schemas,
      rowCount: schemas.length,
    });
  }

  async listDatabases() {
    if (!this.allowDatabaseList) {
      throw new Error('Database listing is disabled.');
    }
    const query = `
      SELECT name as database_name
      FROM sys.databases
      WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb')
      ORDER BY name;
    `;

    const pool = await this.getPool();
    const request = pool.request();
    const result = await request.query(query);

    return this.createJsonResult({
      databases: result.recordset.map(row => row.database_name),
      rowCount: result.recordset.length,
    });
  }

  async executeInsert(table, data, schemaName = 'dbo') {
    this.ensureWritesAllowed('INSERT');
    this.validateIdentifier(table, 'table name');
    this.validateIdentifier(schemaName, 'schema name');
    this.validateDataObject(data);
    assertAllowedTable(schemaName, table, this.allowedSchemas, this.allowedTables);
    this.validateAllowedColumns(schemaName, table, Object.keys(data));
    assertInputBudget(data, 'Data', this.maxInputBytes, this.maxInputItems);

    const columns = Object.keys(data);
    const values = Object.values(data);

    const columnList = columns.map(col => this.quoteIdentifier(col, 'column name')).join(', ');
    const parameterList = columns.map(col => `@${col}`).join(', ');
    const tableName = this.quoteQualifiedName(schemaName, table, 'table name');

    const query = `
      INSERT INTO ${tableName} (${columnList})
      ${this.returnMutationRows ? 'OUTPUT INSERTED.*' : ''}
      VALUES (${parameterList});
    `;

    const pool = await this.getPool();
    const request = pool.request();

    // Add parameters
    columns.forEach((col, index) => {
      request.input(col, values[index]);
    });

    const result = await request.query(query);

    auditMutation('mssql', 'insert', { schema: schemaName, table, rowsAffected: result.rowsAffected[0] });
    return this.createJsonResult({
      inserted: this.returnMutationRows ? result.recordset : undefined,
      rowsAffected: result.rowsAffected[0],
      rowCount: result.rowsAffected[0],
    });
  }

  async rollbackTransactionQuietly(transaction) {
    try {
      await transaction.rollback();
    } catch (error) {
      debugLog(`[MSSQL MCP] Rollback failed: code=${error.code || error.name || 'unknown'}`);
    }
  }

  createTransaction(pool) {
    return new sql.Transaction(pool);
  }

  createTransactionRequest(transaction) {
    return new sql.Request(transaction);
  }

  async preflightAffectedRows(transaction, tableName, filter) {
    if (this.maxAffectedRows === 0) {
      return;
    }

    const request = this.createTransactionRequest(transaction);
    this.addParameters(request, filter.parameters);
    const result = await request.query(`
      SELECT TOP (${this.maxAffectedRows + 1}) 1 AS target
      FROM ${tableName} WITH (UPDLOCK, HOLDLOCK)
      WHERE ${filter.clause};
    `);

    if (result.recordset.length > this.maxAffectedRows) {
      throw new Error(
        `Operation would affect more than MAX_AFFECTED_ROWS (${this.maxAffectedRows}) rows.`
      );
    }
  }

  async executeUpdate(table, data, filters, schemaName = 'dbo') {
    this.ensureWritesAllowed('UPDATE');
    this.validateIdentifier(table, 'table name');
    this.validateIdentifier(schemaName, 'schema name');
    this.validateDataObject(data);
    this.validateFilters(filters);
    assertAllowedTable(schemaName, table, this.allowedSchemas, this.allowedTables);
    this.validateAllowedColumns(schemaName, table, Object.keys(data));
    this.validateAllowedFilterColumns(schemaName, table, filters);
    assertInputBudget(data, 'Data', this.maxInputBytes, this.maxInputItems);
    assertInputBudget(filters, 'Filters', this.maxInputBytes, this.maxInputItems);

    const columns = Object.keys(data);
    const values = Object.values(data);
    const setClause = columns.map(col => `${this.quoteIdentifier(col, 'column name')} = @set_${col}`).join(', ');
    const tableName = this.quoteQualifiedName(schemaName, table, 'table name');
    const pool = await this.getPool();
    const transaction = this.createTransaction(pool);
    let transactionStarted = false;

    try {
      await transaction.begin(sql.ISOLATION_LEVEL.SERIALIZABLE);
      transactionStarted = true;
      const filter = this.buildFilterClause(filters);
      await this.preflightAffectedRows(transaction, tableName, filter);

      const request = this.createTransactionRequest(transaction);
      columns.forEach((col, index) => {
        request.input(`set_${col}`, values[index]);
      });
      this.addParameters(request, filter.parameters);
      const result = await request.query(`
        UPDATE ${tableName}
        SET ${setClause}
        ${this.returnMutationRows ? 'OUTPUT INSERTED.*' : ''}
        WHERE ${filter.clause};
      `);
      const rowsAffected = result.rowsAffected[0];
      if (this.maxAffectedRows > 0 && rowsAffected > this.maxAffectedRows) {
        throw new Error(
          `Operation affected more than MAX_AFFECTED_ROWS (${this.maxAffectedRows}) rows.`
        );
      }

      await transaction.commit();
      transactionStarted = false;
      auditMutation('mssql', 'update', { schema: schemaName, table, rowsAffected });
      return this.createJsonResult({
        updated: this.returnMutationRows ? result.recordset : undefined,
        rowsAffected,
        rowCount: rowsAffected,
      });
    } catch (error) {
      if (transactionStarted) {
        await this.rollbackTransactionQuietly(transaction);
      }
      throw error;
    }
  }

  async executeDelete(table, filters, schemaName = 'dbo') {
    this.ensureDeleteAllowed();
    this.validateIdentifier(table, 'table name');
    this.validateIdentifier(schemaName, 'schema name');
    this.validateFilters(filters);
    assertAllowedTable(schemaName, table, this.allowedSchemas, this.allowedTables);
    this.validateAllowedFilterColumns(schemaName, table, filters);
    assertInputBudget(filters, 'Filters', this.maxInputBytes, this.maxInputItems);

    const tableName = this.quoteQualifiedName(schemaName, table, 'table name');
    const pool = await this.getPool();
    const transaction = this.createTransaction(pool);
    let transactionStarted = false;

    try {
      await transaction.begin(sql.ISOLATION_LEVEL.SERIALIZABLE);
      transactionStarted = true;
      const filter = this.buildFilterClause(filters);
      await this.preflightAffectedRows(transaction, tableName, filter);

      const request = this.createTransactionRequest(transaction);
      this.addParameters(request, filter.parameters);
      const result = await request.query(`
        DELETE FROM ${tableName}
        ${this.returnMutationRows ? 'OUTPUT DELETED.*' : ''}
        WHERE ${filter.clause};
      `);
      const rowsAffected = result.rowsAffected[0];
      if (this.maxAffectedRows > 0 && rowsAffected > this.maxAffectedRows) {
        throw new Error(
          `Operation affected more than MAX_AFFECTED_ROWS (${this.maxAffectedRows}) rows.`
        );
      }

      await transaction.commit();
      transactionStarted = false;
      auditMutation('mssql', 'delete', { schema: schemaName, table, rowsAffected });
      return this.createJsonResult({
        deleted: this.returnMutationRows ? result.recordset : undefined,
        rowsAffected,
        rowCount: rowsAffected,
      });
    } catch (error) {
      if (transactionStarted) {
        await this.rollbackTransactionQuietly(transaction);
      }
      throw error;
    }
  }

  async executeStoredProcedure(procedureName, parameters = {}, schemaName = 'dbo') {
    this.validateIdentifier(procedureName, 'procedure name');
    this.validateIdentifier(schemaName, 'schema name');
    this.validateParameters(parameters);
    this.ensureStoredProceduresAllowed(schemaName, procedureName);
    assertAllowedSchema(schemaName, this.allowedSchemas);
    assertInputBudget(parameters, 'Parameters', this.maxInputBytes, this.maxInputItems);

    const pool = await this.getPool();
    const request = pool.request();

    // Add parameters
    for (const [key, value] of Object.entries(parameters)) {
      request.input(key, value);
    }

    const result = await request.execute(`${schemaName}.${procedureName}`);

    auditMutation('mssql', 'stored_procedure', { schema: schemaName, procedure: procedureName });
    return this.createJsonResult({
      recordsets: result.recordsets,
      recordset: result.recordset,
      output: result.output,
      returnValue: result.returnValue,
      rowsAffected: result.rowsAffected,
      rowCount: result.recordset?.length ?? 0,
    });
  }

  setupErrorHandlers() {
    this.server.onerror = () => {
      console.error("[MCP Error] Internal protocol error.");
    };

    process.on('SIGINT', async () => {
      if (this.pool) {
        await this.pool.close();
      }
      process.exit(0);
    });

    process.on('SIGTERM', async () => {
      if (this.pool) {
        await this.pool.close();
      }
      process.exit(0);
    });
  }

  async run() {
    const transport = new StdioServerTransport(
      createLimitedLineInput(process.stdin, this.maxRequestBytes),
      process.stdout
    );
    await this.server.connect(transport);
    console.error("MSSQL MCP server running on stdio");
  }
}

const isMainModule = process.argv[1] && resolve(process.argv[1]) === __filename;
if (isMainModule) {
  const server = new MSSQLMCPServer();
  server.run().catch((error) => {
    console.error(`[MSSQL MCP] Startup failed: code=${error.code || error.name || 'unknown'}`);
    process.exitCode = 1;
  });
}

export {
  FILTERS_INPUT_SCHEMA,
  FORBIDDEN_SQL_PATTERN,
  maskSqlLiterals,
  MSSQLMCPServer,
};
