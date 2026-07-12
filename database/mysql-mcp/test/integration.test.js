import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import mysql from "mysql2/promise";
import { MySQLMCPServer } from "../index.js";

const enabled = process.env.RUN_INTEGRATION_TESTS === "true";

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

test("live MySQL security, limits, metadata, and controlled writes", { skip: !enabled, timeout: 120000 }, async () => {
  const host = process.env.TEST_DB_HOST || process.env.DB_HOST || "localhost";
  const port = Number(process.env.TEST_DB_PORT || process.env.DB_PORT || 53306);
  const adminUser = process.env.TEST_DB_USER || process.env.DB_USER || "root";
  const adminPassword = process.env.TEST_DB_PASSWORD || process.env.DB_PASSWORD;
  assert.ok(adminPassword, "TEST_DB_PASSWORD or DB_PASSWORD is required");

  const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
  const database = `mcp_it_${suffix}`;
  const readUser = `mcp_ro_${suffix}`;
  const writeUser = `mcp_rw_${suffix}`;
  const readPassword = randomUUID();
  const writePassword = randomUUID();
  const account = (user) => `${mysql.escape(user)}@'%'`;
  const admin = await mysql.createPool({
    host,
    port,
    user: adminUser,
    password: adminPassword,
    waitForConnections: true,
    connectionLimit: 2,
    multipleStatements: false,
  });
  let readServer;
  let writeServer;

  try {
    await admin.query(`CREATE DATABASE \`${database}\``);
    await admin.query(
      `CREATE TABLE \`${database}\`.sample (id integer NOT NULL PRIMARY KEY, note varchar(255) NOT NULL)`
    );
    const values = Array.from({ length: 100 }, (_, index) => [index + 1, `row-${index + 1}`]);
    await admin.query(`INSERT INTO \`${database}\`.sample (id, note) VALUES ?`, [values]);
    await admin.query(`CREATE USER ${account(readUser)} IDENTIFIED BY ${mysql.escape(readPassword)}`);
    await admin.query(`GRANT SELECT ON \`${database}\`.sample TO ${account(readUser)}`);
    await admin.query(`CREATE USER ${account(writeUser)} IDENTIFIED BY ${mysql.escape(writePassword)}`);
    await admin.query(
      `GRANT SELECT, INSERT, UPDATE, DELETE ON \`${database}\`.sample TO ${account(writeUser)}`
    );

    await withEnvironment(
      {
        DB_HOST: host,
        DB_PORT: String(port),
        DB_NAME: database,
        DB_USER: readUser,
        DB_PASSWORD: readPassword,
        DB_SSL_MODE: "disable",
        MCP_MODE: "read",
        ALLOW_WRITES: "false",
        ALLOW_DELETE: "false",
        ALLOW_ARBITRARY_SELECT: "true",
        ALLOWED_SCHEMAS: database,
        ALLOWED_TABLES: `${database}.sample`,
        ALLOWED_COLUMNS: undefined,
        ALLOWED_SELECT_FUNCTIONS: "repeat",
        VERIFY_DB_PRIVILEGES: "true",
        MAX_ROWS: "2",
        MAX_COLUMNS: "10",
        MAX_FIELD_BYTES: "64",
        MAX_RESPONSE_BYTES: "5000",
      },
      async () => {
        readServer = new MySQLMCPServer();
        const listed = JSON.parse((await readServer.listTables(database)).content[0].text);
        assert.deepEqual(listed.tables.map((row) => row.table_name), ["sample"]);

        const described = JSON.parse(
          (await readServer.describeTable("sample", database)).content[0].text
        );
        assert.deepEqual(described.columns.map((column) => column.column_name), ["id", "note"]);

        const selected = JSON.parse(
          (
            await readServer.executeQuery(
              `SELECT id, note FROM \`${database}\`.sample ORDER BY id`,
              []
            )
          ).content[0].text
        );
        assert.equal(selected.rowCount, 2);
        assert.equal(selected.truncated, true);

        const fieldLimited = JSON.parse(
          (await readServer.executeQuery("SELECT REPEAT('x', 1000) AS oversized")).content[0].text
        );
        assert.equal(
          fieldLimited.rows[0].oversized,
          "[omitted: field exceeds MAX_FIELD_BYTES]"
        );

        assert.throws(
          () => readServer.validateSelectQuery("SELECT * FROM sample INTO OUTFILE '/tmp/export'"),
          /forbidden SQL syntax/
        );
        assert.throws(
          () => readServer.validateSelectQuery("SELECT * FROM sample FOR UPDATE"),
          /forbidden SQL syntax/
        );
        assert.throws(
          () => readServer.validateSelectQuery("SELECT LOAD_FILE('/etc/passwd')"),
          /forbidden function/
        );
      }
    );
    await readServer.shutdown();
    readServer = undefined;

    await withEnvironment(
      {
        DB_HOST: host,
        DB_PORT: String(port),
        DB_NAME: database,
        DB_USER: readUser,
        DB_PASSWORD: readPassword,
        DB_SSL_MODE: "disable",
        MCP_MODE: "read",
        ALLOW_WRITES: "false",
        ALLOW_DELETE: "false",
        ALLOW_ARBITRARY_SELECT: "false",
        ALLOWED_SCHEMAS: database,
        ALLOWED_TABLES: `${database}.sample`,
        ALLOWED_COLUMNS: `${database}.sample.id`,
        VERIFY_DB_PRIVILEGES: "true",
      },
      async () => {
        const columnServer = new MySQLMCPServer();
        try {
          const described = JSON.parse(
            (await columnServer.describeTable("sample", database)).content[0].text
          );
          assert.deepEqual(described.columns.map((column) => column.column_name), ["id"]);
        } finally {
          await columnServer.shutdown();
        }
      }
    );

    await withEnvironment(
      {
        DB_HOST: host,
        DB_PORT: String(port),
        DB_NAME: database,
        DB_USER: writeUser,
        DB_PASSWORD: writePassword,
        DB_SSL_MODE: "disable",
        MCP_MODE: "write",
        ALLOW_WRITES: "true",
        ALLOW_DELETE: "true",
        ALLOW_ARBITRARY_SELECT: "false",
        ALLOWED_SCHEMAS: database,
        ALLOWED_TABLES: `${database}.sample`,
        ALLOWED_COLUMNS: undefined,
        VERIFY_DB_PRIVILEGES: "true",
        MAX_AFFECTED_ROWS: "2",
        RETURN_MUTATION_ROWS: "true",
      },
      async () => {
        writeServer = new MySQLMCPServer();
        const inserted = JSON.parse(
          (await writeServer.executeInsert("sample", { id: 101, note: "inserted" }, database))
            .content[0].text
        );
        assert.equal(inserted.rowCount, 1);

        const updated = JSON.parse(
          (
            await writeServer.executeUpdate(
              "sample",
              { note: "updated" },
              [{ column: "id", operator: "eq", value: 101 }],
              database
            )
          ).content[0].text
        );
        assert.equal(updated.rowCount, 1);
        assert.equal(updated.matchedBeforeUpdate[0].note, "inserted");

        await assert.rejects(
          writeServer.executeUpdate(
            "sample",
            { note: "too-many" },
            [{ column: "id", operator: "gte", value: 1 }],
            database
          ),
          /more than MAX_AFFECTED_ROWS/
        );
        const [unchanged] = await admin.query(
          `SELECT COUNT(*) AS count FROM \`${database}\`.sample WHERE note = 'too-many'`
        );
        assert.equal(unchanged[0].count, 0);

        const deleted = JSON.parse(
          (
            await writeServer.executeDelete(
              "sample",
              [{ column: "id", operator: "eq", value: 101 }],
              database
            )
          ).content[0].text
        );
        assert.equal(deleted.rowCount, 1);
        assert.equal(deleted.deleted[0].note, "updated");
      }
    );
    await writeServer.shutdown();
    writeServer = undefined;

    await withEnvironment(
      {
        DB_HOST: host,
        DB_PORT: String(port),
        DB_NAME: database,
        DB_USER: adminUser,
        DB_PASSWORD: adminPassword,
        DB_SSL_MODE: "disable",
        MCP_MODE: "read",
        ALLOW_WRITES: "false",
        ALLOW_DELETE: "false",
        ALLOW_ARBITRARY_SELECT: "false",
        ALLOWED_SCHEMAS: database,
        ALLOWED_TABLES: `${database}.sample`,
        ALLOWED_COLUMNS: undefined,
        VERIFY_DB_PRIVILEGES: "true",
      },
      async () => {
        const privilegedServer = new MySQLMCPServer();
        try {
          await assert.rejects(privilegedServer.ensureSecurityVerified(), /unsafe privilege/);
        } finally {
          await privilegedServer.shutdown();
        }
      }
    );
  } finally {
    if (readServer) await readServer.shutdown().catch(() => {});
    if (writeServer) await writeServer.shutdown().catch(() => {});
    await admin.query(`DROP USER IF EXISTS ${account(readUser)}`).catch(() => {});
    await admin.query(`DROP USER IF EXISTS ${account(writeUser)}`).catch(() => {});
    await admin.query(`DROP DATABASE IF EXISTS \`${database}\``).catch(() => {});
    await admin.end();
  }
});
