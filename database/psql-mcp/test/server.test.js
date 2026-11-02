import assert from "node:assert/strict";
import test, { describe } from "node:test";
import { Readable } from "node:stream";
import {
  FORBIDDEN_SELECT_FUNCTIONS,
  maskSqlLiterals,
  normalizeSelectQuery,
  parseAllowedSchemas,
  PostgreSQLMCPServer,
} from "../index.js";
import {
  createLimitedLineInput,
  isPrivilegeVerificationFresh,
  objectsOutsideAllowlist,
  parseCsvSet,
  parsePrivilegeRecheckMs,
} from "../../shared/security.js";

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

test("blank schema allowlists fall back to the secure documented default", () => {
  assert.deepEqual(Array.from(parseCsvSet(undefined, "public")), ["public"]);
  assert.deepEqual(Array.from(parseCsvSet("", "public")), ["public"]);
  assert.deepEqual(Array.from(parseCsvSet(" , ", "public")), ["public"]);
  assert.deepEqual(Array.from(parseCsvSet("reporting", "public")), ["reporting"]);
  assert.deepEqual(Array.from(parseAllowedSchemas("pg_catalog,pg_temp,pg_temp_3")), ["public"]);
  assert.deepEqual(Array.from(parseAllowedSchemas("reporting,pg_toast_temp_3")), ["reporting"]);
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
    const ssl = server.buildSslConfig();
    assert.equal(ssl.rejectUnauthorized, true);
    assert.equal(typeof ssl.checkServerIdentity, "function");
  });
  await withEnvironment({ DB_SSL_MODE: "invalid" }, () => {
    assert.throws(() => server.buildSslConfig(), /disable, require, verify-full/);
  });
  await withEnvironment({ DB_HOST: "remote.example", DB_SSL: undefined, DB_SSL_MODE: undefined }, () => {
    const ssl = server.buildSslConfig();
    assert.equal(ssl.rejectUnauthorized, true);
    assert.equal(
      ssl.checkServerIdentity("localhost", {
        subject: { CN: "localhost" },
        subjectaltname: "DNS:remote.example",
      }),
      undefined
    );
  });
  await withEnvironment({ DB_HOST: "127.0.0.1", DB_SSL_MODE: "verify-full" }, () => {
    const ssl = server.buildSslConfig();
    assert.equal(
      ssl.checkServerIdentity("localhost", {
        subject: { CN: "localhost" },
        subjectaltname: "IP Address:127.0.0.1",
      }),
      undefined
    );
    assert.ok(
      ssl.checkServerIdentity("localhost", {
        subject: { CN: "localhost" },
        subjectaltname: "DNS:localhost",
      }) instanceof Error
    );
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
      DB_SEARCH_PATH: undefined,
      DB_SSL_MODE: "disable",
      ALLOW_INSECURE_TLS: "true",
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

describe("DB_SEARCH_PATH connection configuration", () => {
  const environment = {
    DB_USER: "mcp_reader",
    DB_TIMEZONE: "UTC",
    DB_PORT: "5432",
    DB_SSL_MODE: "disable",
    MAX_CONNECTIONS: "10",
  };

  for (const [value, expected] of [
    [undefined, "pg_catalog"],
    ["public", "pg_catalog,public"],
    ["pg_catalog,public", "pg_catalog,public"],
    [" public , audit ", "pg_catalog,public,audit"],
    ["public,pg_catalog", "pg_catalog,public,pg_catalog"],
    ["_private,Audit_2", "pg_catalog,_private,Audit_2"],
  ]) {
    test(`${JSON.stringify(value) ?? "unset"} yields ${expected}`, async () => {
      await withEnvironment({ ...environment, DB_SEARCH_PATH: value }, () => {
        assert.equal(
          createServer().buildConnectionConfig().options,
          `-c timezone=UTC -c search_path=${expected}`
        );
      });
    });
  }

  for (const value of ["public;drop", "pub lic", '"public"', "$user", "", "public,,audit", ",public", "public,", "   ", "2public", "public -c timezone=UTC"]) {
    test(`rejects ${JSON.stringify(value)}`, async () => {
      await withEnvironment({ ...environment, DB_SEARCH_PATH: value }, () => {
        assert.throws(() => createServer().buildConnectionConfig(), {
          message: "DB_SEARCH_PATH contains unsupported characters.",
        });
      });
    });
  }
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
    allowedSelectFunctions: new Set([
      "count",
      "custom$function",
      "safe.foo",
      "sécurisé",
      "upper",
      "pg_catalog.count",
      ...FORBIDDEN_SELECT_FUNCTIONS,
    ]),
    forbiddenSelectFunctions: new Set(FORBIDDEN_SELECT_FUNCTIONS),
  });
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT count(*) FROM sample"));
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT "count"(*) FROM sample'));
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT pg_catalog.count(*) FROM sample"));
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT "pg_catalog"."count"(*) FROM sample'));
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT "safe"."foo"()'));
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT count(upper(name)) FROM sample"));
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT custom$function()"));
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT sécurisé()"));
  assert.doesNotThrow(() =>
    server.validateSelectQuery('SELECT * FROM (VALUES (1)) AS "items"("value")')
  );
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT "insert" FROM sample'));
  assert.throws(() => server.validateSelectQuery("SELECT lower(name) FROM sample"), /not allowlisted/);
  assert.throws(() => server.validateSelectQuery("SELECT unlisted$function()"), /not allowlisted/);
  assert.throws(() => server.validateSelectQuery("SELECT nonautorisé()"), /not allowlisted/);
  assert.throws(() => server.validateSelectQuery('SELECT "Safe"."Foo"()'), /not allowlisted/);
  assert.throws(
    () => server.validateSelectQuery("SELECT count(lower(name)) FROM sample"),
    /not allowlisted/
  );
  assert.throws(() => server.validateSelectQuery("SELECT pg_read_file('/etc/passwd')"), /forbidden/);
  assert.throws(
    () => server.validateSelectQuery('SELECT "pg_catalog"."pg_read_file"($$/etc/passwd$$)'),
    /forbidden/
  );
  assert.throws(
    () => server.validateSelectQuery('SELECT pg_catalog."pg_read_file"($$/etc/passwd$$)'),
    /forbidden/
  );
  assert.throws(
    () => server.validateSelectQuery('SELECT "pg_catalog".pg_read_file($$/etc/passwd$$)'),
    /forbidden/
  );
  for (const functionName of FORBIDDEN_SELECT_FUNCTIONS) {
    assert.throws(
      () => server.validateSelectQuery(`SELECT ${functionName}(1)`),
      /forbidden/
    );
  }
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
  let verificationSql;
  const server = createServer({
    verifyDbPrivileges: true,
    securityVerified: false,
    securityVerificationPromise: null,
    pool: {
      query: async (query) => {
        verificationSql = query;
        return { rows: [{ rolsuper: true, rolcreaterole: false }] };
      },
    },
  });
  await assert.rejects(server.ensureSecurityVerified(), /unsafe privileges: rolsuper/);
  assert.match(verificationSql, /pg_signal_backend/);

  const signalServer = createServer({
    verifyDbPrivileges: true,
    securityVerified: false,
    securityVerificationPromise: null,
    pool: {
      query: async () => ({ rows: [{ can_signal_backend: true }] }),
    },
  });
  await assert.rejects(
    signalServer.ensureSecurityVerified(),
    /unsafe privileges: can_signal_backend/
  );
});

function verificationPool(privileges, relations, counter = { privilege: 0, relations: 0 }) {
  return {
    counter,
    query: async (text) => {
      if (text.includes("has_any_column_privilege")) {
        counter.relations += 1;
        return { rows: relations };
      }
      counter.privilege += 1;
      return { rows: [privileges] };
    },
  };
}

async function captureStderr(callback) {
  const original = console.error;
  const lines = [];
  console.error = (...args) => lines.push(args.join(" "));
  try {
    await callback();
  } finally {
    console.error = original;
  }
  return lines;
}

test("pg_read_all_data and pg_write_all_data memberships are rejected in both modes", async () => {
  let verificationSql = "";
  for (const mode of ["read", "write"]) {
    for (const flag of ["can_read_all_data", "can_write_all_data"]) {
      const server = createServer({
        mode,
        verifyDbPrivileges: true,
        securityVerified: false,
        securityVerificationPromise: null,
        pool: {
          query: async (text) => {
            verificationSql = text;
            return { rows: [{ rolsuper: false, [flag]: true }] };
          },
        },
      });
      await assert.rejects(server.ensureSecurityVerified(), new RegExp(`unsafe privileges: ${flag}`));
    }
  }
  assert.match(verificationSql, /rolname = 'pg_read_all_data'/);
  assert.doesNotMatch(verificationSql, /pg_has_role\(current_user, 'pg_read_all_data'/);
});

test("PostgreSQL grants outside the allowlists are refused with raw SELECT and logged otherwise", async () => {
  const relations = [
    { schema_name: "public", object_name: "orders" },
    { schema_name: "hr", object_name: "pay" },
  ];
  const raw = createServer({
    mode: "read",
    verifyDbPrivileges: true,
    securityVerified: false,
    securityVerificationPromise: null,
    grantScopeSummary: "",
    pool: verificationPool({ rolsuper: false }, relations),
  });
  const errors = await captureStderr(() =>
    assert.rejects(raw.ensureSecurityVerified(), /1 object\(s\) outside ALLOWED_SCHEMAS\/ALLOWED_TABLES/)
  );
  assert.match(errors.join("\n"), /ERROR: .*hr\.pay/);
  assert.equal(raw.securityVerified, false);

  const structured = createServer({
    mode: "read",
    allowArbitrarySelect: false,
    verifyDbPrivileges: true,
    securityVerified: false,
    securityVerificationPromise: null,
    grantScopeSummary: "",
    pool: verificationPool({ rolsuper: false }, relations),
  });
  const warnings = await captureStderr(() => structured.ensureSecurityVerified());
  assert.equal(structured.securityVerified, true);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /WARNING: .*1 object\(s\).*hr\.pay/);
  assert.doesNotMatch(warnings[0], /public\.orders/);
});

test("PostgreSQL privileges are re-verified after PRIVILEGE_RECHECK_SECONDS", async () => {
  const pool = verificationPool({ rolsuper: false }, []);
  const server = createServer({
    mode: "read",
    verifyDbPrivileges: true,
    privilegeRecheckMs: 60000,
    securityVerified: true,
    securityVerifiedAt: Date.now(),
    securityVerificationPromise: null,
    grantScopeSummary: "",
    pool,
  });
  await server.ensureSecurityVerified();
  assert.equal(pool.counter.privilege, 0);

  server.securityVerifiedAt = Date.now() - 61000;
  await Promise.all([server.ensureSecurityVerified(), server.ensureSecurityVerified()]);
  assert.equal(pool.counter.privilege, 1);
  assert.equal(pool.counter.relations, 1);
  assert.ok(Date.now() - server.securityVerifiedAt < 5000);

  server.securityVerifiedAt = Date.now() - 61000;
  server.pool = verificationPool({ rolsuper: true }, []);
  await assert.rejects(server.ensureSecurityVerified(), /unsafe privileges: rolsuper/);
  assert.equal(server.securityVerified, false);
});

test("shared privilege recheck and allowlist helpers", () => {
  assert.equal(parsePrivilegeRecheckMs(undefined), 300000);
  assert.equal(parsePrivilegeRecheckMs("0"), 0);
  assert.equal(parsePrivilegeRecheckMs("30"), 30000);
  assert.throws(() => parsePrivilegeRecheckMs("-1"), /PRIVILEGE_RECHECK_SECONDS/);

  assert.equal(isPrivilegeVerificationFresh(false, Date.now(), 0), false);
  assert.equal(isPrivilegeVerificationFresh(true, 1, 0), true);
  assert.equal(isPrivilegeVerificationFresh(true, 1000, 500, 1400), true);
  assert.equal(isPrivilegeVerificationFresh(true, 1000, 500, 1500), false);

  const objects = [
    { schema: "Public", name: "Orders" },
    { schema: "public", name: "audit" },
    { schema: "hr", name: "pay" },
  ];
  assert.deepEqual(objectsOutsideAllowlist(objects, new Set(["public"]), new Set()), [objects[2]]);
  assert.deepEqual(
    objectsOutsideAllowlist(objects, new Set(["public"]), new Set(["public.orders"])),
    [objects[1], objects[2]]
  );
  assert.deepEqual(objectsOutsideAllowlist(objects, new Set(), new Set()), []);
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

test("literal masking stays aligned after astral characters", () => {
  const emoji = "\u{1F600}";
  const query = `SELECT '${emoji.repeat(8)}' AS a, b FROM t`;
  const masked = maskSqlLiterals(query);
  assert.equal(masked.length, query.length);
  assert.ok(masked.endsWith(" AS a, b FROM t"));
  assert.equal(
    maskSqlLiterals(`SELECT "${emoji}" , lower(x)`, { preserveQuotedIdentifiers: true }),
    `SELECT "${emoji}" , lower(x)`
  );
});

test("astral characters in a literal cannot hide a non-allowlisted or forbidden function", () => {
  const emoji = "\u{1F600}";
  const server = createServer({ forbiddenSelectFunctions: new Set(FORBIDDEN_SELECT_FUNCTIONS) });
  assert.throws(
    () => server.validateSelectQuery(`SELECT 1 AS k, '${emoji.repeat(8)}' = lower(name) AS m FROM t`),
    /not allowlisted: lower/
  );
  const allowingSleep = createServer({
    allowedSelectFunctions: new Set(["pg_sleep"]),
    forbiddenSelectFunctions: new Set(FORBIDDEN_SELECT_FUNCTIONS),
  });
  assert.throws(
    () => allowingSleep.validateSelectQuery(`SELECT 1 AS k, '${emoji.repeat(12)}' = pg_sleep(1)::text AS m`),
    /forbidden function: pg_sleep/
  );
});

test("insecure PostgreSQL TLS modes are refused for non-loopback hosts unless explicitly allowed", async () => {
  const server = createServer();
  for (const mode of ["disable", "require"]) {
    await withEnvironment(
      { DB_HOST: "db.example", DB_SSL: undefined, DB_SSL_MODE: mode, ALLOW_INSECURE_TLS: undefined },
      () => {
        assert.throws(() => server.buildSslConfig(), new RegExp(`DB_SSL_MODE=${mode} .* ALLOW_INSECURE_TLS`));
      }
    );
  }
  await withEnvironment(
    { DB_HOST: "db.example", DB_SSL: "true", DB_SSL_MODE: undefined, ALLOW_INSECURE_TLS: undefined },
    () => {
      assert.throws(() => server.buildSslConfig(), /DB_SSL_MODE=require/);
    }
  );
  await withEnvironment(
    { DB_HOST: "db.example", DB_SSL_MODE: "require", ALLOW_INSECURE_TLS: "true" },
    () => {
      assert.deepEqual(server.buildSslConfig(), { rejectUnauthorized: false });
    }
  );
  await withEnvironment({ DB_HOST: "127.0.0.2", DB_SSL_MODE: "disable", ALLOW_INSECURE_TLS: undefined }, () => {
    assert.equal(server.buildSslConfig(), false);
  });
});

test("returned mutation rows omit columns outside ALLOWED_COLUMNS", async () => {
  const server = createServer({
    allowWrites: true,
    allowDelete: true,
    returnMutationRows: true,
    verifyDbPrivileges: false,
    allowedColumns: new Set(["public.users.id", "public.users.status"]),
  });
  const returned = [{ id: 7, status: "inactive", password_hash: "secret" }];
  server.pool = {
    async query() {
      return { rows: returned, rowCount: 1 };
    },
    async connect() {
      return {
        async query(text) {
          if (typeof text === "string" && /^(UPDATE|DELETE)/.test(text)) {
            return { rows: returned, rowCount: 1 };
          }
          return { rows: [{ "?column?": 1 }], rowCount: 1 };
        },
        release() {},
      };
    },
  };

  const inserted = JSON.parse(
    (await server.executeInsert("users", { id: 7, status: "inactive" })).content[0].text
  );
  assert.deepEqual(inserted.inserted, { id: 7, status: "inactive" });
  const filters = [{ column: "id", operator: "eq", value: 7 }];
  const updated = JSON.parse(
    (await server.executeUpdate("users", { status: "inactive" }, filters)).content[0].text
  );
  assert.deepEqual(updated.updated, [{ id: 7, status: "inactive" }]);
  const deleted = JSON.parse((await server.executeDelete("users", filters)).content[0].text);
  assert.deepEqual(deleted.deleted, [{ id: 7, status: "inactive" }]);
});

test("RETURN_MUTATION_ROWS requires positive affected-row and response limits", async () => {
  for (const [key, label] of [
    ["MAX_AFFECTED_ROWS", /positive MAX_AFFECTED_ROWS/],
    ["MAX_RESPONSE_BYTES", /positive MAX_RESPONSE_BYTES/],
  ]) {
    await withEnvironment(
      { DB_USER: "mcp_ro", DB_HOST: undefined, DB_SSL_MODE: undefined, RETURN_MUTATION_ROWS: "true", [key]: "0" },
      () => {
        assert.throws(() => new PostgreSQLMCPServer(), label);
      }
    );
  }
});

test("failed audited tool calls emit an audit event without values", async () => {
  const server = createServer({ allowArbitrarySelect: false });
  const handlers = [];
  server.server = {
    setRequestHandler(_schema, handler) {
      handlers.push(handler);
    },
  };
  server.setupToolHandlers();
  const logged = [];
  const originalError = console.error;
  console.error = (message) => logged.push(message);
  try {
    await withEnvironment({ AUDIT_LOG: undefined }, async () => {
      const result = await handlers[1]({
        params: { name: "execute_query", arguments: { query: "SELECT 'secret-value'" } },
      });
      assert.equal(result.isError, true);
    });
  } finally {
    console.error = originalError;
  }
  const line = logged.find((entry) => entry.startsWith("[MCP Audit]"));
  const event = JSON.parse(line.slice("[MCP Audit] ".length));
  assert.equal(event.category, "tool_failure");
  assert.equal(event.operation, "execute_query");
  assert.equal(event.errorType, "policy");
  assert.doesNotMatch(line, /secret-value/);
});
