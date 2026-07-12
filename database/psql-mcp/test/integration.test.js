import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import pg from "pg";
import { PostgreSQLMCPServer } from "../index.js";

const enabled = process.env.RUN_INTEGRATION_TESTS === "true";
const { Pool } = pg;

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

test("live PostgreSQL security and query behavior", { skip: !enabled, timeout: 60000 }, async () => {
  const adminConfig = {
    host: process.env.TEST_DB_HOST || process.env.DB_HOST || "localhost",
    port: Number(process.env.TEST_DB_PORT || process.env.DB_PORT || 5432),
    database: process.env.TEST_DB_NAME || process.env.DB_NAME,
    user: process.env.TEST_DB_USER || process.env.DB_USER,
    password: process.env.TEST_DB_PASSWORD || process.env.DB_PASSWORD,
    ssl: false,
  };
  assert.ok(adminConfig.database, "TEST_DB_NAME or DB_NAME is required");
  assert.ok(adminConfig.user, "TEST_DB_USER or DB_USER is required");

  const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
  const schema = `mcp_it_${suffix}`;
  const role = `mcp_it_ro_${suffix}`;
  const rolePassword = randomUUID();
  const admin = new Pool(adminConfig);
  let server;

  try {
    await admin.query(`CREATE ROLE "${role}" LOGIN PASSWORD '${rolePassword}'`);
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.query(`CREATE TABLE "${schema}".sample (id integer PRIMARY KEY, note text NOT NULL)`);
    await admin.query(`INSERT INTO "${schema}".sample VALUES (1, 'first'), (2, 'second'), (3, 'third')`);
    await admin.query(`GRANT CONNECT ON DATABASE "${adminConfig.database}" TO "${role}"`);
    await admin.query(`GRANT USAGE ON SCHEMA "${schema}" TO "${role}"`);
    await admin.query(`GRANT SELECT ON "${schema}".sample TO "${role}"`);

    await withEnvironment(
      {
        DB_HOST: adminConfig.host,
        DB_PORT: String(adminConfig.port),
        DB_NAME: adminConfig.database,
        DB_USER: role,
        DB_PASSWORD: rolePassword,
        DB_SSL_MODE: "disable",
        MCP_MODE: "read",
        ALLOW_WRITES: "false",
        ALLOW_DELETE: "false",
        ALLOW_ARBITRARY_SELECT: "true",
        ALLOWED_SCHEMAS: schema,
        ALLOWED_TABLES: `${schema}.sample`,
        ALLOWED_SELECT_FUNCTIONS: "repeat,generate_series",
        VERIFY_DB_PRIVILEGES: "true",
        MAX_ROWS: "2",
      },
      async () => {
        server = new PostgreSQLMCPServer();
        const listed = JSON.parse((await server.listTables(schema)).content[0].text);
        assert.deepEqual(listed.tables.map((row) => row.table_name), ["sample"]);

        const result = JSON.parse(
          (await server.executeQuery(`SELECT id, note FROM "${schema}".sample ORDER BY id;`))
            .content[0].text
        );
        assert.equal(result.rowCount, 2);
        assert.equal(result.truncated, true);

        const strings = JSON.parse(
          (await server.executeQuery(String.raw`SELECT 'ordinary' AS a, E'escape\n' AS b, $$dollar;value$$ AS c;`))
            .content[0].text
        );
        assert.equal(strings.rows[0].a, "ordinary");
        assert.equal(strings.rows[0].c, "dollar;value");

        const fieldLimited = JSON.parse(
          (await server.executeQuery("SELECT repeat('x', 200000) AS oversized"))
            .content[0].text
        );
        assert.equal(
          fieldLimited.rows[0].oversized,
          "[omitted: field exceeds MAX_FIELD_BYTES]"
        );

        const originalMaxRows = server.maxRows;
        const originalMaxResponseBytes = server.maxResponseBytes;
        server.maxRows = 100;
        server.maxResponseBytes = 5000;
        try {
          const responseLimited = JSON.parse(
            (
              await server.executeQuery(
                "SELECT generate_series(1, 100) AS id, repeat('x', 1000) AS payload"
              )
            ).content[0].text
          );
          assert.equal(responseLimited.truncated, true);
          assert.ok(responseLimited.rowCount > 0 && responseLimited.rowCount < 100);
        } finally {
          server.maxRows = originalMaxRows;
          server.maxResponseBytes = originalMaxResponseBytes;
        }

        await assert.rejects(server.executeQuery("SELECT 1; SELECT 2"), /forbidden SQL syntax/);
        await assert.rejects(server.executeQuery("COMMIT"), /Only SELECT queries/);
        await assert.rejects(
          server.executeQuery("SELECT pg_read_file('/etc/passwd')"),
          /forbidden function/
        );
        assert.throws(() => server.validateSelectQuery("SELECT 1 -- comment"), /forbidden SQL syntax/);
        await assert.rejects(server.describeTable("sample", "public"), /not allowlisted/);

        await withEnvironment(
          {
            ALLOW_ARBITRARY_SELECT: "false",
            ALLOWED_COLUMNS: `${schema}.sample.id`,
          },
          async () => {
            const columnServer = new PostgreSQLMCPServer();
            try {
              const described = JSON.parse(
                (await columnServer.describeTable("sample", schema)).content[0].text
              );
              assert.deepEqual(described.columns.map((column) => column.column_name), ["id"]);
            } finally {
              await columnServer.shutdown();
            }
          }
        );
      }
    );

    await withEnvironment(
      {
        DB_HOST: adminConfig.host,
        DB_PORT: String(adminConfig.port),
        DB_NAME: adminConfig.database,
        DB_USER: adminConfig.user,
        DB_PASSWORD: adminConfig.password,
        DB_SSL_MODE: "disable",
        VERIFY_DB_PRIVILEGES: "true",
      },
      async () => {
        const privilegedServer = new PostgreSQLMCPServer();
        try {
          await assert.rejects(privilegedServer.ensureSecurityVerified(), /unsafe privileges/);
        } finally {
          await privilegedServer.shutdown();
        }
      }
    );
  } finally {
    if (server) await server.shutdown();
    await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => {});
    await admin.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1 AND pid <> pg_backend_pid()`,
      [role]
    ).catch(() => {});
    await admin.query(`DROP OWNED BY "${role}"`).catch(() => {});
    await admin.query(`DROP ROLE IF EXISTS "${role}"`).catch(() => {});
    await admin.end();
  }
});
