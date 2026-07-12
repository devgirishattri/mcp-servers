import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import sql from 'mssql';
import { MSSQLMCPServer } from '../index.js';

const enabled = process.env.RUN_INTEGRATION_TESTS === 'true';

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

test('live MSSQL security, limits, and pool behavior', { skip: !enabled, timeout: 120000 }, async () => {
  const host = process.env.TEST_DB_HOST || process.env.DB_HOST || 'localhost';
  const port = Number(process.env.TEST_DB_PORT || process.env.DB_PORT || 1433);
  const adminUser = process.env.TEST_DB_USER || process.env.DB_USER || 'sa';
  const adminPassword = process.env.TEST_DB_PASSWORD || process.env.DB_PASSWORD;
  const database = process.env.TEST_DB_NAME || 'mcp_mcp_test';
  assert.ok(adminPassword, 'TEST_DB_PASSWORD or DB_PASSWORD is required');

  const baseConfig = {
    server: host,
    port,
    user: adminUser,
    password: adminPassword,
    options: { encrypt: true, trustServerCertificate: true },
    connectionTimeout: 30000,
    requestTimeout: 30000,
  };
  const suffix = randomUUID().replaceAll('-', '').slice(0, 12);
  const login = `mcp_it_ro_${suffix}`;
  const loginPassword = `Mcp!${randomUUID()}aA1`;
  let master;
  let testDb;
  let server;

  try {
    master = await new sql.ConnectionPool({ ...baseConfig, database: 'master' }).connect();
    await master.request().query(`IF DB_ID('${database}') IS NULL CREATE DATABASE [${database}]`);
    testDb = await new sql.ConnectionPool({ ...baseConfig, database }).connect();
    await testDb.request().query(`
      IF OBJECT_ID('dbo.sample', 'U') IS NULL
        CREATE TABLE dbo.sample (id int NOT NULL PRIMARY KEY, note nvarchar(100) NOT NULL);
      DELETE FROM dbo.sample;
      INSERT INTO dbo.sample (id, note) VALUES (1, N'first'), (2, N'second'), (3, N'third');
      IF OBJECT_ID('dbo.mcp_test_sequence', 'SO') IS NULL
        EXEC('CREATE SEQUENCE dbo.mcp_test_sequence AS bigint START WITH 1 INCREMENT BY 1');
    `);
    await master.request().query(`CREATE LOGIN [${login}] WITH PASSWORD = '${loginPassword}', CHECK_POLICY = ON`);
    await testDb.request().query(`
      CREATE USER [${login}] FOR LOGIN [${login}];
      GRANT CONNECT TO [${login}];
      GRANT SELECT ON dbo.sample TO [${login}];
      GRANT VIEW DEFINITION ON dbo.sample TO [${login}];
    `);

    await withEnvironment(
      {
        DB_HOST: host,
        DB_PORT: String(port),
        DB_NAME: database,
        DB_USER: login,
        DB_PASSWORD: loginPassword,
        DB_ENCRYPT: 'true',
        DB_TRUST_SERVER_CERTIFICATE: 'true',
        MCP_MODE: 'read',
        ALLOW_WRITES: 'false',
        ALLOW_DELETE: 'false',
        ALLOW_ARBITRARY_SELECT: 'true',
        ALLOW_DATABASE_LIST: 'false',
        ALLOWED_SCHEMAS: 'dbo',
        ALLOWED_TABLES: 'dbo.sample',
        ALLOWED_SELECT_FUNCTIONS: 'cast,replicate,nvarchar',
        VERIFY_DB_PRIVILEGES: 'true',
        MAX_ROWS: '2',
      },
      async () => {
        server = new MSSQLMCPServer();
        const pools = await Promise.all([server.getPool(), server.getPool(), server.getPool()]);
        assert.equal(pools[0], pools[1]);
        assert.equal(pools[1], pools[2]);

        const listed = JSON.parse((await server.listTables('dbo')).content[0].text);
        assert.deepEqual(listed.tables.map((row) => row.TABLE_NAME), ['sample']);

        const result = JSON.parse(
          (await server.executeQuery('SELECT id, note FROM dbo.sample ORDER BY id')).content[0].text
        );
        assert.equal(result.rowCount, 2);
        assert.equal(result.truncated, true);

        const fieldLimited = JSON.parse(
          (
            await server.executeQuery(
              "SELECT CAST(REPLICATE(N'x', 100000) AS nvarchar(max)) AS oversized"
            )
          ).content[0].text
        );
        assert.ok(Buffer.byteLength(fieldLimited.recordset[0].oversized, 'utf8') <= 65536);

        const originalMaxRows = server.maxRows;
        const originalMaxResponseBytes = server.maxResponseBytes;
        server.maxRows = 100;
        server.maxResponseBytes = 5000;
        try {
          const responseLimited = JSON.parse(
            (
              await server.executeQuery(
                "SELECT REPLICATE(N'x', 1000) AS payload FROM (VALUES (1),(2),(3),(4),(5),(6),(7),(8),(9),(10)) AS a(n) CROSS JOIN (VALUES (1),(2),(3),(4),(5),(6),(7),(8),(9),(10)) AS b(n)"
              )
            ).content[0].text
          );
          assert.equal(responseLimited.truncated, true);
          assert.ok(responseLimited.rowCount > 0 && responseLimited.rowCount < 100);
        } finally {
          server.maxRows = originalMaxRows;
          server.maxResponseBytes = originalMaxResponseBytes;
        }

        const sequenceBefore = await testDb.request().query(
          "SELECT current_value FROM sys.sequences WHERE name = 'mcp_test_sequence' AND schema_id = SCHEMA_ID('dbo')"
        );
        await assert.rejects(
          server.executeQuery('SELECT NEXT VALUE FOR dbo.mcp_test_sequence AS value'),
          /sequence operation/
        );
        const sequenceAfter = await testDb.request().query(
          "SELECT current_value FROM sys.sequences WHERE name = 'mcp_test_sequence' AND schema_id = SCHEMA_ID('dbo')"
        );
        assert.equal(
          sequenceAfter.recordset[0].current_value,
          sequenceBefore.recordset[0].current_value
        );
        await assert.rejects(
          server.executeQuery("SELECT BulkColumn FROM OPENROWSET(BULK 'C:\\Windows\\win.ini', SINGLE_CLOB) AS source"),
          /not allowlisted/
        );
        assert.throws(() => server.validateSelectQuery('SELECT 1; SELECT 2'), /forbidden SQL syntax/);
        await assert.rejects(server.describeTable('sample', 'audit'), /not allowlisted/);

        await withEnvironment(
          {
            ALLOW_ARBITRARY_SELECT: 'false',
            ALLOWED_COLUMNS: 'dbo.sample.id',
          },
          async () => {
            const columnServer = new MSSQLMCPServer();
            try {
              const described = JSON.parse(
                (await columnServer.describeTable('sample', 'dbo')).content[0].text
              );
              assert.deepEqual(described.columns.map((column) => column.COLUMN_NAME), ['id']);
            } finally {
              if (columnServer.pool) await columnServer.pool.close();
            }
          }
        );
      }
    );

    await withEnvironment(
      {
        DB_HOST: host,
        DB_PORT: String(port),
        DB_NAME: database,
        DB_USER: adminUser,
        DB_PASSWORD: adminPassword,
        DB_ENCRYPT: 'true',
        DB_TRUST_SERVER_CERTIFICATE: 'true',
        VERIFY_DB_PRIVILEGES: 'true',
      },
      async () => {
        const privilegedServer = new MSSQLMCPServer();
        try {
          await assert.rejects(privilegedServer.getPool(), /unsafe privileges/);
        } finally {
          if (privilegedServer.pool) await privilegedServer.pool.close();
        }
      }
    );
  } finally {
    if (server?.pool) await server.pool.close();
    if (testDb) {
      await testDb.request().query(`DROP USER IF EXISTS [${login}]`).catch(() => {});
      await testDb.close();
    }
    if (master) {
      await master.request().query(`DROP LOGIN IF EXISTS [${login}]`).catch(() => {});
      await master.close();
    }
    await sql.close();
  }
});
