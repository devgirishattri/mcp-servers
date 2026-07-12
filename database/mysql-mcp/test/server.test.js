import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import test from "node:test";
import {
  maskSqlLiterals,
  MySQLMCPServer,
  normalizeSelectQuery,
  parseGrantScope,
} from "../index.js";
import { createLimitedLineInput } from "../../shared/security.js";

function createServer(overrides = {}) {
  return Object.assign(Object.create(MySQLMCPServer.prototype), {
    mode: "write",
    allowWrites: false,
    allowDelete: false,
    returnMutationRows: false,
    defaultSchema: "appdb",
    allowArbitrarySelect: true,
    allowedSchemas: new Set(["appdb"]),
    allowedTables: new Set(),
    allowedColumns: new Set(),
    allowedSelectFunctions: new Set(),
    forbiddenSelectFunctions: new Set(),
    verifyDbPrivileges: false,
    securityVerified: true,
    securityVerificationPromise: null,
    maxRows: 1000,
    maxAffectedRows: 100,
    maxResponseBytes: 1000000,
    maxFieldBytes: 65536,
    maxColumns: 100,
    maxInputBytes: 65536,
    maxInputItems: 100,
    maxRequestBytes: 262144,
    statementTimeoutMs: 30000,
    connectionTimeoutMs: 10000,
    ...overrides,
  });
}

async function withEnvironment(changes, callback) {
  const previous = new Map(Object.keys(changes).map((key) => [key, process.env[key]]));
  for (const [key, value] of Object.entries(changes)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return await callback();
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function streamingConnection(
  rows,
  fields = [{ name: "value", type: 3 }],
  {
    rollbackFails = false,
    mutationError = null,
    selectError = null,
    mutationResult = { affectedRows: 1, changedRows: 1 },
    statementErrors = {},
  } = {}
) {
  const state = { released: false, destroyed: false, statements: [], preparedExecutions: 0 };
  return {
    state,
    query(options, callback) {
      if (callback) {
        state.statements.push(options.sql);
        if (statementErrors[options.sql]) {
          queueMicrotask(() => callback(statementErrors[options.sql]));
        } else if (rollbackFails && options.sql === "ROLLBACK") {
          queueMicrotask(() => callback(Object.assign(new Error("rollback failed"), { code: "ECONNRESET" })));
        } else if (/^SELECT\b/i.test(options.sql) && selectError) {
          queueMicrotask(() => callback(selectError));
        } else if (/^(?:UPDATE|DELETE|INSERT)\b/i.test(options.sql)) {
          if (mutationError) queueMicrotask(() => callback(mutationError));
          else queueMicrotask(() => callback(null, mutationResult, []));
        } else {
          queueMicrotask(() => callback(null, [], []));
        }
        return undefined;
      }
      state.statements.push(options.sql);
      const command = new EventEmitter();
      command.stream = () => {
        command.emit("fields", fields);
        return Readable.from(rows, { objectMode: true });
      };
      return command;
    },
    execute(options, callback) {
      state.preparedExecutions += 1;
      return this.query(options, callback);
    },
    release() {
      state.released = true;
    },
    destroy() {
      state.destroyed = true;
    },
  };
}

test("raw SELECT accepts literals and quoted identifiers but rejects executable syntax", () => {
  const server = createServer();
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT 'delete; --' AS status"));
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT `insert` FROM sample"));
  assert.equal(server.validateSelectQuery(" SELECT 1; \n"), "SELECT 1");
  assert.throws(() => server.validateSelectQuery("SELECT 1; SELECT 2"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("SELECT 1 -- comment"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("SELECT 1 # comment"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("SELECT 1 /* comment */"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("DELETE FROM users"), /Only SELECT queries/);
});

test("literal masking fails closed across MySQL backslash sql_mode ambiguity", () => {
  const server = createServer();
  const escapedQuoteExploit = String.raw`SELECT 'safe\'; DELETE FROM users; SELECT 'x'`;
  const noBackslashEscapesVariant = String.raw`SELECT 'safe\\'; DELETE FROM users; SELECT 'x'`;
  assert.throws(() => server.validateSelectQuery(escapedQuoteExploit), /Backslashes inside quoted raw SQL/);
  assert.throws(() => server.validateSelectQuery(noBackslashEscapesVariant), /Backslashes inside quoted raw SQL/);
  assert.throws(() => maskSqlLiterals(String.raw`SELECT 'C:\temp'`), /Backslashes inside quoted raw SQL/);
  assert.match(maskSqlLiterals("SELECT 'it''s safe' AS value"), /^SELECT\s+AS value$/);
  assert.throws(() => maskSqlLiterals("SELECT 'unterminated"), /unterminated/);
});

test("session variables, output files, locking reads, and dangerous functions are blocked", () => {
  const server = createServer({
    allowedSelectFunctions: new Set(["count", "load_file", "sleep"]),
    forbiddenSelectFunctions: new Set(["load_file", "sleep"]),
  });
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT count(*) FROM sample"));
  assert.throws(() => server.validateSelectQuery("SELECT @value := 1"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("SELECT * FROM sample FOR UPDATE"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("SELECT * FROM sample FOR SHARE"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("SELECT * FROM sample INTO OUTFILE '/tmp/x'"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("SELECT LOAD_FILE('/etc/passwd')"), /forbidden function/);
  assert.throws(() => server.validateSelectQuery("SELECT SLEEP(10)"), /forbidden function/);
  assert.throws(() => server.validateSelectQuery("SELECT lower(name) FROM sample"), /not allowlisted/);
  assert.throws(() => server.validateSelectQuery("SELECT `count`(*) FROM sample"), /Quoted function names/);
});

test("query normalization removes only one executable trailing semicolon", () => {
  assert.equal(normalizeSelectQuery(" SELECT 'semi;' AS value; \n"), "SELECT 'semi;' AS value");
  assert.equal(normalizeSelectQuery("SELECT 1;;"), "SELECT 1;");
});

test("structured filters quote identifiers and bind values", () => {
  const server = createServer();
  const filter = server.buildFilterClause([
    { column: "id", operator: "eq", value: 42 },
    { column: "status", operator: "in", value: ["active", "pending"] },
    { column: "deleted_at", operator: "is_null" },
  ]);
  assert.equal(
    filter.clause,
    "`id` = ? AND `status` IN (?, ?) AND `deleted_at` IS NULL"
  );
  assert.deepEqual(filter.values, [42, "active", "pending"]);
  assert.throws(
    () => server.buildFilterClause([{ column: "id; DROP", operator: "eq", value: 1 }]),
    /Invalid filter column name/
  );
  assert.throws(() => server.buildFilterClause([]), /non-empty array/);
});

test("tool exposure is default deny", () => {
  assert.deepEqual(
    createServer({ allowArbitrarySelect: false }).getAvailableTools().map((tool) => tool.name),
    ["describe_table", "list_tables", "list_schemas"]
  );
  assert.equal(createServer().getAvailableTools().some((tool) => tool.name === "execute_query"), true);
  const writes = createServer({ allowWrites: true }).getAvailableTools().map((tool) => tool.name);
  assert.equal(writes.includes("execute_insert"), true);
  assert.equal(writes.includes("execute_update"), true);
  assert.equal(writes.includes("execute_delete"), false);
  assert.equal(
    createServer({ allowWrites: true, allowDelete: true })
      .getAvailableTools()
      .some((tool) => tool.name === "execute_delete"),
    true
  );
});

test("runtime mutation guards remain active", () => {
  const server = createServer();
  assert.throws(() => server.ensureWritesAllowed("INSERT"), /ALLOW_WRITES=true/);
  assert.throws(() => server.ensureDeleteAllowed(), /ALLOW_WRITES=true/);
  assert.doesNotThrow(() => createServer({ allowWrites: true }).ensureWritesAllowed("UPDATE"));
});

test("mutation failure plus rollback failure destroys and never releases the connection", async () => {
  const connection = streamingConnection([], [], {
    rollbackFails: true,
    mutationError: Object.assign(new Error("update failed"), { code: "ER_LOCK_DEADLOCK" }),
  });
  const server = createServer({
    allowWrites: true,
    getConnection: async () => connection,
  });
  await assert.rejects(
    server.executeUpdate(
      "users",
      { status: "inactive" },
      [{ column: "id", operator: "eq", value: 1 }]
    ),
    /update failed/
  );
  assert.equal(connection.state.statements.includes("ROLLBACK"), true);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("INSERT transaction-start timeout destroys without rollback or release", async () => {
  const timeout = Object.assign(new Error("transaction start timed out"), {
    code: "PROTOCOL_SEQUENCE_TIMEOUT",
    fatal: false,
  });
  const connection = streamingConnection([], [], {
    statementErrors: { "START TRANSACTION": timeout },
  });
  const server = createServer({ allowWrites: true, getConnection: async () => connection });
  await assert.rejects(server.executeInsert("users", { id: 1 }), /timed out/);
  assert.equal(timeout.connectionDestroyed, true);
  assert.equal(connection.state.statements.includes("ROLLBACK"), false);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("DML protocol timeout destroys immediately and never queues rollback", async () => {
  const timeout = Object.assign(new Error("write timed out"), {
    code: "PROTOCOL_SEQUENCE_TIMEOUT",
    fatal: false,
  });
  const connection = streamingConnection([], [], { mutationError: timeout });
  const server = createServer({ allowWrites: true, getConnection: async () => connection });
  await assert.rejects(server.executeInsert("users", { id: 1 }), /write timed out/);
  assert.equal(timeout.connectionDestroyed, true);
  assert.equal(connection.state.statements.includes("ROLLBACK"), false);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("buffered preflight timeout destroys immediately and prevents UPDATE", async () => {
  const timeout = Object.assign(new Error("preflight timed out"), {
    code: "PROTOCOL_SEQUENCE_TIMEOUT",
    fatal: false,
  });
  const connection = streamingConnection([], [], { selectError: timeout });
  const server = createServer({ allowWrites: true, getConnection: async () => connection });
  await assert.rejects(
    server.executeUpdate(
      "users",
      { status: "inactive" },
      [{ column: "id", operator: "eq", value: 1 }]
    ),
    /preflight timed out/
  );
  assert.equal(timeout.connectionDestroyed, true);
  assert.equal(connection.state.statements.some((sql) => sql.startsWith("UPDATE")), false);
  assert.equal(connection.state.statements.includes("ROLLBACK"), false);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("COMMIT failure destroys immediately and never queues rollback", async () => {
  const commitError = Object.assign(new Error("commit response lost"), { code: "ECONNRESET" });
  const connection = streamingConnection([], [], {
    statementErrors: { COMMIT: commitError },
  });
  const server = createServer({ allowWrites: true, getConnection: async () => connection });
  await assert.rejects(server.executeInsert("users", { id: 1 }), /commit response lost/);
  assert.equal(commitError.connectionDestroyed, true);
  assert.equal(connection.state.statements.includes("ROLLBACK"), false);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("transaction-isolation failure destroys ambiguous session state", async () => {
  const isolationError = Object.assign(new Error("isolation failed"), {
    code: "ER_UNKNOWN_ERROR",
  });
  const connection = streamingConnection([], [], {
    statementErrors: { "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE": isolationError },
  });
  const server = createServer({ allowWrites: true, getConnection: async () => connection });
  await assert.rejects(
    server.executeUpdate(
      "users",
      { status: "inactive" },
      [{ column: "id", operator: "eq", value: 1 }]
    ),
    /isolation failed/
  );
  assert.equal(isolationError.connectionDestroyed, true);
  assert.equal(connection.state.statements.includes("START TRANSACTION"), false);
  assert.equal(connection.state.statements.includes("ROLLBACK"), false);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("mutation snapshots stream, normalize fields, and complete before UPDATE", async () => {
  const connection = streamingConnection(
    [{ id: 1, payload: "x".repeat(100) }],
    [{ name: "id" }, { name: "payload" }]
  );
  const server = createServer({
    allowWrites: true,
    returnMutationRows: true,
    maxAffectedRows: 2,
    maxFieldBytes: 10,
    maxResponseBytes: 2000,
    getConnection: async () => connection,
  });
  const result = JSON.parse(
    (
      await server.executeUpdate(
        "users",
        { status: "inactive" },
        [{ column: "id", operator: "eq", value: 1 }]
      )
    ).content[0].text
  );
  assert.equal(result.matchedBeforeUpdate[0].payload, "[omitted: field exceeds MAX_FIELD_BYTES]");
  const preflightIndex = connection.state.statements.findIndex((sql) => sql.startsWith("SELECT"));
  const updateIndex = connection.state.statements.findIndex((sql) => sql.startsWith("UPDATE"));
  assert.equal(preflightIndex >= 0 && updateIndex > preflightIndex, true);
  assert.equal(connection.state.released, true);
});

test("mutation snapshot response overflow destroys the transaction before UPDATE", async () => {
  const connection = streamingConnection(
    [{ id: 1, payload: "x".repeat(1000) }, { id: 2, payload: "y".repeat(1000) }],
    [{ name: "id" }, { name: "payload" }]
  );
  const server = createServer({
    allowWrites: true,
    returnMutationRows: true,
    maxAffectedRows: 5,
    maxFieldBytes: 2000,
    maxResponseBytes: 700,
    getConnection: async () => connection,
  });
  await assert.rejects(
    server.executeUpdate(
      "users",
      { status: "inactive" },
      [{ column: "id", operator: "gte", value: 1 }]
    ),
    /MAX_RESPONSE_BYTES/
  );
  assert.equal(connection.state.statements.some((sql) => sql.startsWith("UPDATE")), false);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("mutation snapshot column overflow destroys the transaction before DELETE", async () => {
  const connection = streamingConnection(
    [{ id: 1, payload: "value" }],
    [{ name: "id" }, { name: "payload" }]
  );
  const server = createServer({
    allowWrites: true,
    allowDelete: true,
    returnMutationRows: true,
    maxAffectedRows: 5,
    maxColumns: 1,
    getConnection: async () => connection,
  });
  await assert.rejects(
    server.executeDelete("users", [{ column: "id", operator: "eq", value: 1 }]),
    /MAX_COLUMNS/
  );
  assert.equal(connection.state.statements.some((sql) => sql.startsWith("DELETE")), false);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("zero-row mutation snapshot still enforces field-count MAX_COLUMNS before UPDATE", async () => {
  const connection = streamingConnection(
    [],
    [{ name: "id" }, { name: "payload" }]
  );
  const server = createServer({
    allowWrites: true,
    returnMutationRows: true,
    maxAffectedRows: 5,
    maxColumns: 1,
    getConnection: async () => connection,
  });
  await assert.rejects(
    server.executeUpdate(
      "users",
      { status: "inactive" },
      [{ column: "id", operator: "eq", value: 999 }]
    ),
    /MAX_COLUMNS/
  );
  assert.equal(connection.state.statements.some((sql) => sql.startsWith("UPDATE")), false);
  assert.equal(connection.state.statements.includes("ROLLBACK"), true);
  assert.equal(connection.state.destroyed, false);
  assert.equal(connection.state.released, true);
});

test("raw SELECT streams rows inside a read-only transaction and destroys a truncated connection", async () => {
  const connection = streamingConnection([{ value: 1 }, { value: 2 }, { value: 3 }]);
  const server = createServer({ maxRows: 2, getConnection: async () => connection });
  const result = JSON.parse((await server.executeQuery("SELECT value FROM sample", [])).content[0].text);
  assert.deepEqual(connection.state.statements.slice(0, 2), [
    "SET SESSION MAX_EXECUTION_TIME = 30000",
    "START TRANSACTION READ ONLY",
  ]);
  assert.equal(result.rowCount, 2);
  assert.equal(result.truncated, true);
  assert.equal(connection.state.preparedExecutions >= 1, true);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("raw SELECT releases a fully consumed connection after rollback", async () => {
  const connection = streamingConnection([{ value: 1 }]);
  const server = createServer({ getConnection: async () => connection });
  const result = JSON.parse((await server.executeQuery("SELECT value FROM sample", [])).content[0].text);
  assert.equal(result.truncated, false);
  assert.equal(connection.state.statements.at(-1), "ROLLBACK");
  assert.equal(connection.state.released, true);
  assert.equal(connection.state.destroyed, false);
});

test("raw SELECT destroys and never releases a connection when rollback fails", async () => {
  const connection = streamingConnection(
    [{ value: 1 }],
    [{ name: "value", type: 3 }],
    { rollbackFails: true }
  );
  const server = createServer({ getConnection: async () => connection });
  await assert.rejects(server.executeQuery("SELECT value FROM sample"), /close the read-only transaction/);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("raw SELECT transaction-start timeout honors destroyed state without rollback", async () => {
  const timeout = Object.assign(new Error("read transaction timed out"), {
    code: "PROTOCOL_SEQUENCE_TIMEOUT",
    fatal: false,
  });
  const connection = streamingConnection([], [], {
    statementErrors: { "START TRANSACTION READ ONLY": timeout },
  });
  const server = createServer({ getConnection: async () => connection });
  await assert.rejects(server.executeQuery("SELECT value FROM sample"), /timed out/);
  assert.equal(timeout.connectionDestroyed, true);
  assert.equal(connection.state.statements.includes("ROLLBACK"), false);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("raw pre-transaction session-limit timeout destroys without rollback", async () => {
  const timeout = Object.assign(new Error("session limit timed out"), {
    code: "PROTOCOL_SEQUENCE_TIMEOUT",
    fatal: false,
  });
  const connection = streamingConnection([], [], {
    statementErrors: { "SET SESSION MAX_EXECUTION_TIME = 30000": timeout },
  });
  const server = createServer({ getConnection: async () => connection });
  await assert.rejects(server.executeQuery("SELECT value FROM sample"), /session limit timed out/);
  assert.equal(timeout.connectionDestroyed, true);
  assert.equal(connection.state.statements.includes("START TRANSACTION READ ONLY"), false);
  assert.equal(connection.state.statements.includes("ROLLBACK"), false);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
});

test("MAX_COLUMNS stream failure destroys rather than reuses the connection", async () => {
  const connection = streamingConnection(
    [{ first: 1, second: 2 }],
    [{ name: "first" }, { name: "second" }]
  );
  const server = createServer({ maxColumns: 1, getConnection: async () => connection });
  await assert.rejects(server.executeQuery("SELECT first, second FROM sample"), /MAX_COLUMNS/);
  assert.equal(connection.state.destroyed, true);
  assert.equal(connection.state.released, false);
  assert.equal(connection.state.statements.includes("ROLLBACK"), false);
});

test("zero-row raw SELECT still enforces field-count MAX_COLUMNS", async () => {
  const connection = streamingConnection(
    [],
    [{ name: "first" }, { name: "second" }]
  );
  const server = createServer({ maxColumns: 1, getConnection: async () => connection });
  await assert.rejects(server.executeQuery("SELECT first, second FROM sample"), /MAX_COLUMNS/);
  assert.equal(connection.state.statements.includes("ROLLBACK"), true);
  assert.equal(connection.state.destroyed, false);
  assert.equal(connection.state.released, true);
});

test("field and response limits are enforced during streaming", async () => {
  const connection = streamingConnection([{ value: "x".repeat(100) }]);
  const server = createServer({ maxFieldBytes: 10, getConnection: async () => connection });
  const result = JSON.parse((await server.executeQuery("SELECT value FROM sample")).content[0].text);
  assert.equal(result.rows[0].value, "[omitted: field exceeds MAX_FIELD_BYTES]");

  const responseConnection = streamingConnection([{ value: "x".repeat(1000) }]);
  const responseServer = createServer({
    maxResponseBytes: 700,
    getConnection: async () => responseConnection,
  });
  const limited = JSON.parse(
    (await responseServer.executeQuery("SELECT value FROM sample")).content[0].text
  );
  assert.equal(limited.truncated, true);
  assert.equal(responseConnection.state.destroyed, true);
});

test("disabled raw-query caps are rejected before a connection is acquired", async () => {
  const server = createServer({ maxRows: 0, getConnection: async () => assert.fail() });
  await assert.rejects(server.executeQuery("SELECT 1"), /requires positive MAX_ROWS/);
});

test("metadata queries are bounded before allocation", async () => {
  const calls = [];
  const server = createServer({
    maxRows: 2,
    maxColumns: 1,
    query: async (_target, sql, values) => {
      calls.push({ sql, values });
      if (sql.includes("INFORMATION_SCHEMA.COLUMNS")) {
        return { rows: [{ column_name: "id" }, { column_name: "note" }] };
      }
      return { rows: [{ table_name: "a" }, { table_name: "b" }, { table_name: "c" }] };
    },
    pool: {},
  });
  const described = JSON.parse((await server.describeTable("sample")).content[0].text);
  assert.equal(described.rowCount, 1);
  assert.equal(described.truncated, true);
  const listed = JSON.parse((await server.listTables()).content[0].text);
  assert.equal(listed.rowCount, 2);
  assert.equal(listed.truncated, true);
  assert.match(calls[0].sql, /LIMIT 2/);
  assert.match(calls[0].sql, /BINARY TABLE_SCHEMA = BINARY \?/);
  assert.match(calls[0].sql, /BINARY TABLE_NAME = BINARY \?/);
  assert.deepEqual(calls[0].values, ["appdb", "sample"]);
  assert.match(calls[1].sql, /LIMIT 3/);
  assert.deepEqual(calls[1].values, ["appdb"]);
});

test("metadata allowlists are applied before SQL LIMIT", async () => {
  const calls = [];
  const server = createServer({
    maxRows: 1,
    allowedSchemas: new Set(["appdb"]),
    allowedTables: new Set(["appdb.z_report"]),
    query: async (_target, sql, values) => {
      calls.push({ sql, values });
      if (sql.includes("INFORMATION_SCHEMA.TABLES")) {
        return { rows: [{ table_name: "z_report", table_type: "VIEW" }] };
      }
      return { rows: [{ schema_name: "appdb" }] };
    },
    pool: {},
  });
  const tables = JSON.parse((await server.listTables("appdb")).content[0].text);
  assert.deepEqual(tables.tables.map((row) => row.table_name), ["z_report"]);
  assert.match(calls[0].sql, /BINARY TABLE_NAME IN \(BINARY \?\).*LIMIT 2/s);
  assert.deepEqual(calls[0].values, ["appdb", "z_report"]);

  const schemas = JSON.parse((await server.listSchemas()).content[0].text);
  assert.deepEqual(schemas.schemas, ["appdb"]);
  assert.match(calls[1].sql, /BINARY SCHEMA_NAME IN \(BINARY \?\).*LIMIT 2/s);
  assert.deepEqual(calls[1].values, ["appdb"]);
});

test("grant scopes parse global, database, and table forms", () => {
  assert.deepEqual(parseGrantScope("*.*"), { kind: "global" });
  assert.deepEqual(parseGrantScope("`appdb`.*"), { kind: "schema", schema: "appdb" });
  assert.deepEqual(parseGrantScope("`appdb`.`sample`"), {
    kind: "table",
    schema: "appdb",
    table: "sample",
  });
});

test("least-privilege grant verification rejects administrative and out-of-scope access", () => {
  const server = createServer({ mode: "read", allowedTables: new Set(["appdb.sample"]) });
  assert.doesNotThrow(() => server.validateGrantStatement("GRANT USAGE ON *.* TO `mcp`@`%`"));
  assert.doesNotThrow(() =>
    server.validateGrantStatement("GRANT SELECT ON `appdb`.`sample` TO `mcp`@`%`")
  );
  assert.throws(
    () => server.validateGrantStatement("GRANT FILE ON *.* TO `mcp`@`%`"),
    /unsafe privileges/
  );
  assert.throws(
    () => server.validateGrantStatement("GRANT SELECT ON `other`.`sample` TO `mcp`@`%`"),
    /not allowlisted/
  );
  assert.throws(
    () => server.validateGrantStatement("GRANT SELECT ON `appdb`.* TO `mcp`@`%`"),
    /exceed ALLOWED_TABLES/
  );
  assert.throws(
    () => server.validateGrantStatement("GRANT EXECUTE ON FUNCTION `appdb`.`f` TO `mcp`@`%`"),
    /stored-routine/
  );
  assert.throws(
    () => server.validateGrantStatement("GRANT USAGE ON *.* TO `mcp`@`%` WITH GRANT OPTION"),
    /delegation/
  );
});

test("MySQL object allowlists and grant matching preserve exact case", async () => {
  const server = createServer({
    defaultSchema: "appdb",
    allowedSchemas: new Set(["appdb"]),
    allowedTables: new Set(["appdb.safe"]),
    allowedColumns: new Set(["appdb.safe.Id"]),
  });
  assert.doesNotThrow(() => server.validateGrantStatement("GRANT SELECT ON `appdb`.`safe` TO `mcp`@`%`"));
  assert.throws(
    () => server.validateGrantStatement("GRANT SELECT ON `appdb`.`Safe` TO `mcp`@`%`"),
    /not allowlisted/
  );
  assert.throws(() => server.validateAllowedColumns("appdb", "safe", ["id"]), /not allowlisted/);
  await assert.rejects(server.listTables("AppDb"), /not allowlisted/);
});

test("write-mode grant verification permits only enabled DML capabilities", () => {
  const server = createServer({ mode: "write", allowWrites: true, allowDelete: false });
  assert.doesNotThrow(() =>
    server.validateGrantStatement("GRANT SELECT, INSERT, UPDATE ON `appdb`.* TO `mcp`@`%`")
  );
  assert.throws(
    () => server.validateGrantStatement("GRANT DELETE ON `appdb`.* TO `mcp`@`%`"),
    /unsafe privileges/
  );
  assert.throws(
    () => server.validateGrantStatement("GRANT CREATE TEMPORARY TABLES ON `appdb`.* TO `mcp`@`%`"),
    /unsafe privileges/
  );
});

test("enabled roles are expanded before grant validation", async () => {
  const statements = [];
  const connection = { release() {} };
  const server = createServer({
    verifyDbPrivileges: true,
    securityVerified: false,
    getConnection: async () => connection,
    query: async (_target, sql) => {
      statements.push(sql);
      if (sql.includes("ENABLED_ROLES")) {
        return { rows: [{ ROLE_NAME: "mcp_read", ROLE_HOST: "%" }] };
      }
      return { rows: [{ grant: "GRANT SELECT ON `appdb`.* TO `mcp`@`%`" }] };
    },
  });
  await server.ensureSecurityVerified();
  assert.match(statements[1], /SHOW GRANTS FOR CURRENT_USER\(\) USING 'mcp_read'@'%'/);
});

test("privilege-query protocol timeout destroys and never releases its explicit connection", async () => {
  const state = { destroyed: false, released: false };
  const connection = {
    destroy() {
      state.destroyed = true;
    },
    release() {
      state.released = true;
    },
  };
  const timeout = Object.assign(new Error("privilege query timed out"), {
    code: "PROTOCOL_SEQUENCE_TIMEOUT",
    fatal: false,
  });
  const server = createServer({
    verifyDbPrivileges: true,
    securityVerified: false,
    securityVerificationPromise: null,
    getConnection: async () => connection,
    query: async () => {
      throw timeout;
    },
  });
  await assert.rejects(server.ensureSecurityVerified(), /privilege query timed out/);
  assert.equal(timeout.connectionDestroyed, true);
  assert.equal(state.destroyed, true);
  assert.equal(state.released, false);
});

test("numeric, TLS, connection, and required database configuration are strict", async () => {
  const server = createServer();
  assert.equal(server.parseNonNegativeInteger("100", 1, "LIMIT"), 100);
  assert.throws(() => server.parseNonNegativeInteger("100rows", 1, "LIMIT"), /non-negative integer/);
  assert.throws(() => server.parsePositiveInteger("0", 1, "PORT"), /greater than zero/);

  await withEnvironment({ DB_HOST: "remote.example", DB_SSL_MODE: undefined }, () => {
    assert.deepEqual(server.buildSslConfig(), { rejectUnauthorized: true });
  });
  await withEnvironment({ DB_SSL_MODE: "require" }, () => {
    assert.deepEqual(server.buildSslConfig(), { rejectUnauthorized: false });
  });
  await withEnvironment({ DB_SSL_MODE: "invalid" }, () => {
    assert.throws(() => server.buildSslConfig(), /disable, require, verify-full/);
  });
  await withEnvironment(
    {
      DB_USER: "mcp_ro",
      DB_PASSWORD: "p@ss:word",
      DB_PORT: "3307",
      DB_TIMEZONE: "+05:30",
      DB_SSL_MODE: "disable",
      MAX_CONNECTIONS: "7",
    },
    () => {
      const config = server.buildConnectionConfig();
      assert.equal(config.user, "mcp_ro");
      assert.equal(config.password, "p@ss:word");
      assert.equal(config.port, 3307);
      assert.equal(config.connectionLimit, 7);
      assert.equal(config.multipleStatements, false);
    }
  );
  await withEnvironment({ DB_NAME: undefined, DB_USER: "mcp_ro" }, () => {
    assert.throws(() => new MySQLMCPServer(), /DB_NAME is required/);
  });
  await withEnvironment(
    {
      DB_NAME: "appdb",
      DB_USER: "mcp_ro",
      RETURN_MUTATION_ROWS: "true",
      MAX_AFFECTED_ROWS: "10",
      MAX_RESPONSE_BYTES: "0",
    },
    () => {
      assert.throws(
        () => new MySQLMCPServer(),
        /RETURN_MUTATION_ROWS=true requires a positive MAX_RESPONSE_BYTES/
      );
    }
  );
  await withEnvironment(
    {
      DB_NAME: "AppDb",
      DB_USER: "mcp_ro",
      DB_SSL_MODE: "disable",
      ALLOWED_SCHEMAS: " , , ",
      ALLOWED_TABLES: undefined,
      ALLOWED_COLUMNS: undefined,
      ALLOW_ARBITRARY_SELECT: "false",
      ALLOW_WRITES: "false",
      ALLOW_DELETE: "false",
      RETURN_MUTATION_ROWS: "false",
    },
    async () => {
      const configured = new MySQLMCPServer();
      try {
        assert.deepEqual(Array.from(configured.allowedSchemas), ["AppDb"]);
      } finally {
        await configured.shutdown();
      }
    }
  );
});

test("column allowlists and input budgets fail before database access", async () => {
  const server = createServer({
    allowedColumns: new Set(["appdb.users.id", "appdb.users.status"]),
    maxInputBytes: 20,
  });
  assert.doesNotThrow(() => server.validateAllowedColumns("appdb", "users", ["id", "status"]));
  assert.throws(
    () => server.validateAllowedColumns("appdb", "users", ["password_hash"]),
    /not allowlisted/
  );
  assert.throws(() => server.validateSelectQuery(`SELECT '${"x".repeat(30)}'`), /MAX_INPUT_BYTES/);
});

test("oversized results and database errors are safely normalized", () => {
  const server = createServer({ maxResponseBytes: 300 });
  const result = server.createJsonResult({ rows: [{ value: "x".repeat(500) }], rowCount: 1 });
  assert.equal(JSON.parse(result.content[0].text).truncated, true);
  const error = server.createErrorResult(
    Object.assign(new Error("Table private.secret does not exist"), { code: "ER_NO_SUCH_TABLE" })
  );
  assert.match(error.content[0].text, /Database operation failed/);
  assert.doesNotMatch(error.content[0].text, /private|secret|ER_NO_SUCH_TABLE/);
});

test("stdio input is rejected before an oversized JSON-RPC line reaches the SDK", async () => {
  const limited = createLimitedLineInput(Readable.from([Buffer.from("12345\n")]), 4);
  await assert.rejects(
    async () => {
      for await (const _chunk of limited) {
        // Consume the stream so the limiter applies.
      }
    },
    /MAX_REQUEST_BYTES/
  );
});
