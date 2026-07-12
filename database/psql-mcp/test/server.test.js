import assert from "node:assert/strict";
import test from "node:test";
import { Readable } from "node:stream";
import {
  maskSqlLiterals,
  normalizeSelectQuery,
  PostgreSQLMCPServer,
} from "../index.js";
import { createLimitedLineInput } from "../../shared/security.js";

function createServer(overrides = {}) {
  return Object.assign(Object.create(PostgreSQLMCPServer.prototype), {
    mode: "write",
    allowWrites: false,
    allowDelete: false,
    allowArbitrarySelect: true,
    allowedSchemas: new Set(["public"]),
    allowedTables: new Set(),
    allowedColumns: new Set(),
    allowedSelectFunctions: new Set(),
    forbiddenSelectFunctions: new Set(),
    maxInputBytes: 65536,
    maxInputItems: 100,
    maxRows: 1000,
    maxAffectedRows: 100,
    maxResponseBytes: 1000000,
    maxFieldBytes: 65536,
    maxColumns: 100,
    statementTimeoutMs: 30000,
    connectionTimeoutMs: 10000,
    ...overrides,
  });
}

async function withEnvironment(changes, callback) {
  const previous = {};
  for (const [key, value] of Object.entries(changes)) {
    previous[key] = process.env[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  try {
    return await callback();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

test("execute_query rejects stacked statements, transaction control, comments, and mutations", () => {
  const server = createServer();
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT $1::integer"));
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT 'delete; --' AS status"));
  assert.doesNotThrow(() =>
    server.validateSelectQuery(String.raw`SELECT E'escaped\'; delete; still literal' AS status`)
  );
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT "insert" FROM sample'));
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT $$drop; /* text */$$ AS content"));
  assert.equal(server.validateSelectQuery(" SELECT 1; \n"), "SELECT 1");
  assert.throws(() => server.validateSelectQuery("SELECT 1; SELECT 2"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("SELECT 1;;"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("SELECT 1 -- comment"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("SELECT value INTO copied FROM sample"), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery("DELETE FROM users"), /Only SELECT queries/);
  for (const control of ["BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT checkpoint"]) {
    assert.throws(() => server.validateSelectQuery(control), /Only SELECT queries/);
  }
});

test("literal masking follows PostgreSQL ordinary, escape, quoted, and dollar string rules", () => {
  const masked = maskSqlLiterals("SELECT 'delete; --', \"insert\", $$drop /* text */$$ FROM sample");
  assert.match(masked, /^SELECT\s+,\s+,\s+FROM sample$/);
  assert.match(
    maskSqlLiterals(String.raw`SELECT 'safe\'; COMMIT; DELETE FROM users; SELECT 'x'`),
    /; COMMIT; DELETE FROM users;/
  );
  assert.doesNotMatch(
    maskSqlLiterals(String.raw`SELECT E'safe\'; COMMIT; still literal' AS value`),
    /COMMIT/
  );
  assert.match(maskSqlLiterals("SELECT 'it''s safe; still literal' AS value"), /^SELECT\s+AS value$/);
  assert.match(maskSqlLiterals("SELECT $tag$semi; COMMIT$tag$ AS value"), /^SELECT\s+AS value$/);
  assert.throws(() => maskSqlLiterals("SELECT 'unterminated"), /unterminated/);
  assert.throws(() => maskSqlLiterals("SELECT $tag$unterminated"), /unterminated/);
});

test("the standard-conforming-string exploit is rejected", () => {
  const server = createServer();
  const exploit = String.raw`SELECT 'safe\'; COMMIT; DELETE FROM users; SELECT 'x'`;
  assert.throws(() => server.validateSelectQuery(exploit), /forbidden SQL syntax/);
});

test("execute_query uses a read-only transaction, timeout, and row cap", async () => {
  const queries = [];
  const fetchedRows = [
    { __mcp_row: { value: 1 }, __mcp_column_count: 1 },
    { __mcp_row: { value: 2 }, __mcp_column_count: 1 },
    { __mcp_row: { value: 3 }, __mcp_column_count: 1 },
  ];
  const client = {
    async query(query, parameters) {
      queries.push({ query, parameters });
      if (typeof query === "string" && query.startsWith("FETCH FORWARD")) {
        return {
          rows: fetchedRows.length > 0 ? [fetchedRows.shift()] : [],
        };
      }
      return { rows: [], rowCount: 0 };
    },
    release() {},
  };
  const server = createServer({
    maxRows: 2,
    pool: { connect: async () => client },
  });

  const result = await server.executeQuery("  SELECT value FROM sample; \n", []);
  const payload = JSON.parse(result.content[0].text);
  assert.equal(queries[0].query, "BEGIN READ ONLY");
  assert.match(queries[1].query, /set_config\('statement_timeout'/);
  assert.match(
    queries[2].query.text,
    /DECLARE "__mcp_cursor".*FROM \(SELECT value FROM sample\)/s
  );
  assert.deepEqual(queries[2].query.values, []);
  assert.equal(queries[2].query.queryMode, "extended");
  assert.equal(queries[3].query, 'FETCH FORWARD 1 FROM "__mcp_cursor"');
  assert.equal(queries[6].query, "ROLLBACK");
  assert.equal(payload.rowCount, 2);
  assert.equal(payload.truncated, true);
});

test("execute_query refuses disabled row or response caps", async () => {
  const server = createServer({
    maxRows: 0,
  });

  await assert.rejects(server.executeQuery(" SELECT 1; ", []), /requires positive MAX_ROWS/);
});

test("structured filters quote identifiers and parameterize values", () => {
  const server = createServer();
  const result = server.buildFilterClause(
    [
      { column: "id", operator: "eq", value: 42 },
      { column: "status", operator: "in", value: ["active", "pending"] },
      { column: "deleted_at", operator: "is_null" },
    ],
    3
  );

  assert.equal(
    result.clause,
    '"id" = $3 AND "status" IN ($4, $5) AND "deleted_at" IS NULL'
  );
  assert.deepEqual(result.values, [42, "active", "pending"]);
  assert.throws(
    () => server.buildFilterClause([{ column: "id; DROP TABLE users", operator: "eq", value: 1 }]),
    /Invalid filter column name/
  );
  assert.throws(() => server.buildFilterClause([]), /non-empty array/);
});

test("write tools use the default-deny exposure model", () => {
  const readOnlyNames = createServer({ allowArbitrarySelect: false }).getAvailableTools().map((tool) => tool.name);
  assert.deepEqual(readOnlyNames, ["describe_table", "list_tables", "list_schemas"]);

  const rawSelectNames = createServer().getAvailableTools().map((tool) => tool.name);
  assert.equal(rawSelectNames.includes("execute_query"), true);

  const writeNames = createServer({ allowWrites: true }).getAvailableTools().map((tool) => tool.name);
  assert.equal(writeNames.includes("execute_insert"), true);
  assert.equal(writeNames.includes("execute_update"), true);
  assert.equal(writeNames.includes("execute_delete"), false);

  const deleteNames = createServer({ allowWrites: true, allowDelete: true })
    .getAvailableTools()
    .map((tool) => tool.name);
  assert.equal(deleteNames.includes("execute_delete"), true);
});

test("runtime write guards remain active when tools are called directly", () => {
  const server = createServer();
  assert.throws(() => server.ensureWritesAllowed("INSERT"), /ALLOW_WRITES=true/);
  assert.throws(() => server.ensureDeleteAllowed(), /ALLOW_WRITES=true/);
});

test("MAX_AFFECTED_ROWS rolls back before an oversized PostgreSQL update", async () => {
  const queries = [];
  const client = {
    async query(query) {
      queries.push(query);
      if (query.startsWith("SELECT 1 FROM")) {
        return { rows: [{}, {}, {}], rowCount: 3 };
      }
      return { rows: [], rowCount: 0 };
    },
    release() {},
  };
  const server = createServer({
    allowWrites: true,
    maxAffectedRows: 2,
    pool: { connect: async () => client },
  });

  await assert.rejects(
    server.executeUpdate(
      "users",
      { status: "inactive" },
      [{ column: "id", operator: "gte", value: 1 }]
    ),
    /more than MAX_AFFECTED_ROWS/
  );
  assert.equal(queries.includes("ROLLBACK"), true);
  assert.equal(queries.some((query) => query.startsWith("UPDATE")), false);
});

test("numeric configuration parsing rejects partial and unsafe values", () => {
  const server = createServer();
  assert.equal(server.parseNonNegativeInteger("100", 1, "LIMIT"), 100);
  assert.throws(() => server.parseNonNegativeInteger("100rows", 1, "LIMIT"), /non-negative integer/);
  assert.throws(() => server.parsePositiveInteger("0", 1, "PORT"), /greater than zero/);
});

test("TLS modes support disable, require, and verify-full", async () => {
  const server = createServer();
  await withEnvironment({ DB_SSL: undefined, DB_SSL_MODE: "disable", DB_SSL_CA_FILE: undefined }, () => {
    assert.equal(server.buildSslConfig(), false);
  });
  await withEnvironment({ DB_SSL_MODE: "require", DB_SSL_CA_FILE: undefined }, () => {
    assert.deepEqual(server.buildSslConfig(), { rejectUnauthorized: false });
  });
  await withEnvironment({ DB_SSL_MODE: "verify-full", DB_SSL_CA_FILE: undefined }, () => {
    assert.deepEqual(server.buildSslConfig(), { rejectUnauthorized: true });
  });
  await withEnvironment({ DB_SSL_MODE: "invalid" }, () => {
    assert.throws(() => server.buildSslConfig(), /disable, require, verify-full/);
  });
  await withEnvironment({ DB_HOST: "remote.example", DB_SSL: undefined, DB_SSL_MODE: undefined }, () => {
    assert.deepEqual(server.buildSslConfig(), { rejectUnauthorized: true });
  });
});

test("connection configuration keeps credentials structured and applies timezone", async () => {
  const server = createServer();
  await withEnvironment(
    {
      DB_HOST: "db.example",
      DB_PORT: "5433",
      DB_NAME: "sample",
      DB_USER: "user@domain",
      DB_PASSWORD: "p@ss:word",
      DB_TIMEZONE: "Asia/Kolkata",
      DB_SSL_MODE: "disable",
      MAX_CONNECTIONS: "5",
    },
    () => {
      const config = server.buildConnectionConfig();
      assert.equal(config.user, "user@domain");
      assert.equal(config.password, "p@ss:word");
      assert.equal(config.options, "-c timezone=Asia/Kolkata -c search_path=pg_catalog");
    }
  );
});

test("connection configuration requires an explicit non-empty DB_USER", async () => {
  const server = createServer();
  await withEnvironment({ DB_USER: undefined }, () => {
    assert.throws(() => server.buildConnectionConfig(), /DB_USER is required/);
  });
  await withEnvironment({ DB_USER: "   " }, () => {
    assert.throws(() => server.buildConnectionConfig(), /DB_USER is required/);
  });
});

test("pool idle-client errors are handled without exposing driver details", () => {
  let poolErrorHandler;
  const server = createServer({
    server: {},
    pool: {
      on(event, handler) {
        assert.equal(event, "error");
        poolErrorHandler = handler;
      },
    },
  });
  const originalConsoleError = console.error;
  const output = [];
  console.error = (...args) => output.push(args.join(" "));
  try {
    server.setupErrorHandlers();
    assert.equal(typeof poolErrorHandler, "function");
    assert.doesNotThrow(() => poolErrorHandler(new Error("password=secret host=private")));
  } finally {
    console.error = originalConsoleError;
  }
  assert.match(output[0], /idle database connection failed/i);
  assert.doesNotMatch(output[0], /secret|private/);
});

test("query normalization removes only one executable trailing semicolon", () => {
  assert.equal(normalizeSelectQuery(" SELECT 'semi;' AS value; \n"), "SELECT 'semi;' AS value");
  assert.equal(normalizeSelectQuery("SELECT $$semi;$$"), "SELECT $$semi;$$");
  assert.equal(normalizeSelectQuery("SELECT 1;;"), "SELECT 1;");
});

test("oversized results are capped and tool errors are marked", () => {
  const server = createServer({ maxResponseBytes: 300 });
  const result = server.createJsonResult({ rows: [{ value: "x".repeat(500) }], rowCount: 1 });
  const payload = JSON.parse(result.content[0].text);
  assert.equal(payload.truncated, true);
  assert.ok(Buffer.byteLength(result.content[0].text, "utf8") <= 300);

  const error = server.createErrorResult(new Error("blocked"));
  assert.equal(error.isError, true);
  assert.match(error.content[0].text, /blocked/);
});

test("raw SELECT functions require an allowlist and dangerous functions remain forbidden", () => {
  const server = createServer({
    allowedSelectFunctions: new Set(["count", "pg_read_file"]),
    forbiddenSelectFunctions: new Set(["pg_read_file"]),
  });
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT count(*) FROM sample"));
  assert.throws(() => server.validateSelectQuery("SELECT lower(name) FROM sample"), /not allowlisted/);
  assert.throws(() => server.validateSelectQuery("SELECT pg_read_file('/etc/passwd')"), /forbidden/);
});

test("schema policies and input budgets fail before database access", async () => {
  const server = createServer({
    allowedSchemas: new Set(["public"]),
    maxInputBytes: 20,
    pool: { query: async () => assert.fail("database should not be queried") },
  });
  await assert.rejects(server.describeTable("users", "private"), /not allowlisted/);
  assert.throws(() => server.validateSelectQuery(`SELECT '${"x".repeat(30)}'`), /MAX_INPUT_BYTES/);
});

test("column policies apply to structured data and filters", () => {
  const server = createServer({
    allowedColumns: new Set(["public.users.id", "public.users.status"]),
  });
  assert.doesNotThrow(() =>
    server.validateAllowedColumns("public", "users", ["id", "status"])
  );
  assert.throws(
    () => server.validateAllowedColumns("public", "users", ["password_hash"]),
    /not allowlisted/
  );
  assert.throws(
    () =>
      server.validateAllowedFilterColumns("public", "users", [
        { column: "email", operator: "eq", value: "a@example.test" },
      ]),
    /not allowlisted/
  );
});

test("database errors are normalized before returning through MCP", () => {
  const server = createServer();
  const result = server.createErrorResult(
    Object.assign(new Error("relation private.secret does not exist"), { code: "42P01" })
  );
  assert.match(result.content[0].text, /Database operation failed/);
  assert.doesNotMatch(result.content[0].text, /private|secret|42P01/);
});

test("privileged PostgreSQL roles are rejected", async () => {
  const server = createServer({
    verifyDbPrivileges: true,
    securityVerified: false,
    securityVerificationPromise: null,
    pool: {
      query: async () => ({ rows: [{ rolsuper: true, rolcreaterole: false }] }),
    },
  });
  await assert.rejects(server.ensureSecurityVerified(), /unsafe privileges: rolsuper/);
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
