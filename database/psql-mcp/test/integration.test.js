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
  const writeRole = `mcp_it_rw_${suffix}`;
  const writeRolePassword = randomUUID();
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
        ALLOWED_SELECT_FUNCTIONS: "repeat,generate_series,pg_catalog.count",
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

        const quotedFunction = JSON.parse(
          (
            await server.executeQuery(
              `SELECT "pg_catalog"."count"(*) AS total FROM "${schema}".sample`
            )
          ).content[0].text
        );
        assert.equal(quotedFunction.rows[0].total, 3);

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
        await assert.rejects(
          server.executeQuery('SELECT "pg_catalog"."pg_read_file"($$/etc/passwd$$)'),
          /forbidden function/
        );
        await assert.rejects(
          server.executeQuery("SELECT pg_try_advisory_lock(1)"),
          /forbidden function/
        );
        assert.throws(() => server.validateSelectQuery("SELECT 1 -- comment"), /forbidden SQL syntax/);
        const smiles = JSON.parse(
          (
            await server.executeQuery(
              `SELECT '\u{1F600}' AS smile, id FROM "${schema}".sample ORDER BY id`
            )
          ).content[0].text
        );
        assert.equal(smiles.rows[0].smile, "\u{1F600}");
        assert.throws(
          () =>
            server.validateSelectQuery(
              `SELECT 1 AS k, '${"\u{1F600}".repeat(8)}' = lower(note) AS m FROM "${schema}".sample`
            ),
          /not allowlisted: lower/
        );
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

    await admin.query(`GRANT pg_signal_backend TO "${role}"`);
    try {
      await withEnvironment(
        {
          DB_HOST: adminConfig.host,
          DB_PORT: String(adminConfig.port),
          DB_NAME: adminConfig.database,
          DB_USER: role,
          DB_PASSWORD: rolePassword,
          DB_SSL_MODE: "disable",
          MCP_MODE: "read",
          VERIFY_DB_PRIVILEGES: "true",
        },
        async () => {
          const signalingServer = new PostgreSQLMCPServer();
          try {
            await assert.rejects(
              signalingServer.ensureSecurityVerified(),
              /unsafe privileges: can_signal_backend/
            );
          } finally {
            await signalingServer.shutdown();
          }
        }
      );
    } finally {
      await admin.query(`REVOKE pg_signal_backend FROM "${role}"`);
    }

    const readRoleEnvironment = {
      DB_HOST: adminConfig.host,
      DB_PORT: String(adminConfig.port),
      DB_NAME: adminConfig.database,
      DB_USER: role,
      DB_PASSWORD: rolePassword,
      DB_SSL_MODE: "disable",
      MCP_MODE: "read",
      ALLOWED_SCHEMAS: schema,
      ALLOWED_TABLES: `${schema}.sample`,
      VERIFY_DB_PRIVILEGES: "true",
    };

    // A column grant on a table outside ALLOWED_TABLES widens what raw SELECT can read.
    await admin.query(`CREATE TABLE "${schema}".outside (id integer, payroll text)`);
    await admin.query(`GRANT SELECT (id) ON "${schema}".outside TO "${role}"`);
    try {
      await withEnvironment({ ...readRoleEnvironment, ALLOW_ARBITRARY_SELECT: "true" }, async () => {
        const rawServer = new PostgreSQLMCPServer();
        try {
          await assert.rejects(
            rawServer.ensureSecurityVerified(),
            /1 object\(s\) outside ALLOWED_SCHEMAS\/ALLOWED_TABLES/
          );
        } finally {
          await rawServer.shutdown();
        }
      });
      await withEnvironment({ ...readRoleEnvironment, ALLOW_ARBITRARY_SELECT: "false" }, async () => {
        const structuredServer = new PostgreSQLMCPServer();
        try {
          await structuredServer.ensureSecurityVerified();
          assert.match(structuredServer.grantScopeSummary, /\.outside\b/);
        } finally {
          await structuredServer.shutdown();
        }
      });
    } finally {
      await admin.query(`REVOKE SELECT (id) ON "${schema}".outside FROM "${role}"`);
    }

    await admin.query(`GRANT pg_read_all_data TO "${role}"`);
    try {
      await withEnvironment({ ...readRoleEnvironment, ALLOW_ARBITRARY_SELECT: "false" }, async () => {
        const readAllServer = new PostgreSQLMCPServer();
        try {
          await assert.rejects(readAllServer.ensureSecurityVerified(), /unsafe privileges: can_read_all_data/);
        } finally {
          await readAllServer.shutdown();
        }
      });
    } finally {
      await admin.query(`REVOKE pg_read_all_data FROM "${role}"`);
    }

    // A grant added while the server runs is caught by the next periodic re-check.
    await withEnvironment(
      { ...readRoleEnvironment, ALLOW_ARBITRARY_SELECT: "true", PRIVILEGE_RECHECK_SECONDS: "60" },
      async () => {
        const recheckServer = new PostgreSQLMCPServer();
        try {
          await recheckServer.ensureSecurityVerified();
          await admin.query(`GRANT pg_signal_backend TO "${role}"`);
          await recheckServer.ensureSecurityVerified();
          recheckServer.securityVerifiedAt -= 61000;
          await assert.rejects(
            recheckServer.ensureSecurityVerified(),
            /unsafe privileges: can_signal_backend/
          );
        } finally {
          await admin.query(`REVOKE pg_signal_backend FROM "${role}"`);
          await recheckServer.shutdown();
        }
      }
    );

    await admin.query(`CREATE ROLE "${writeRole}" LOGIN PASSWORD '${writeRolePassword}'`);
    await admin.query(
      `CREATE TABLE "${schema}".secrets (id integer PRIMARY KEY, note text NOT NULL, secret text NOT NULL DEFAULT 'hidden')`
    );
    await admin.query(`GRANT CONNECT ON DATABASE "${adminConfig.database}" TO "${writeRole}"`);
    await admin.query(`GRANT USAGE ON SCHEMA "${schema}" TO "${writeRole}"`);
    await admin.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON "${schema}".secrets TO "${writeRole}"`);
    await withEnvironment(
      {
        DB_HOST: adminConfig.host,
        DB_PORT: String(adminConfig.port),
        DB_NAME: adminConfig.database,
        DB_USER: writeRole,
        DB_PASSWORD: writeRolePassword,
        DB_SSL_MODE: "disable",
        MCP_MODE: "write",
        ALLOW_WRITES: "true",
        ALLOW_DELETE: "true",
        ALLOW_ARBITRARY_SELECT: "false",
        ALLOWED_SCHEMAS: schema,
        ALLOWED_TABLES: `${schema}.secrets`,
        ALLOWED_COLUMNS: `${schema}.secrets.id,${schema}.secrets.note`,
        RETURN_MUTATION_ROWS: "true",
        VERIFY_DB_PRIVILEGES: "true",
      },
      async () => {
        const writeServer = new PostgreSQLMCPServer();
        try {
          const inserted = JSON.parse(
            (await writeServer.executeInsert("secrets", { id: 1, note: "visible" }, schema)).content[0].text
          );
          assert.deepEqual(inserted.inserted, { id: 1, note: "visible" });
          const filters = [{ column: "id", operator: "eq", value: 1 }];
          const updated = JSON.parse(
            (await writeServer.executeUpdate("secrets", { note: "changed" }, filters, schema)).content[0].text
          );
          assert.deepEqual(updated.updated, [{ id: 1, note: "changed" }]);
          const deleted = JSON.parse(
            (await writeServer.executeDelete("secrets", filters, schema)).content[0].text
          );
          assert.deepEqual(deleted.deleted, [{ id: 1, note: "changed" }]);
        } finally {
          await writeServer.shutdown();
        }
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
    for (const name of [role, writeRole]) {
      await admin.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1 AND pid <> pg_backend_pid()`,
        [name]
      ).catch(() => {});
      await admin.query(`DROP OWNED BY "${name}"`).catch(() => {});
      await admin.query(`DROP ROLE IF EXISTS "${name}"`).catch(() => {});
    }
    await admin.end();
  }
});
