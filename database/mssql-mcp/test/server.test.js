import assert from 'node:assert/strict';
import test from 'node:test';
import { maskSqlLiterals, MSSQLMCPServer } from '../index.js';

function createServer(overrides = {}) {
  return Object.assign(Object.create(MSSQLMCPServer.prototype), {
    mode: 'write',
    allowWrites: false,
    allowDelete: false,
    allowArbitrarySelect: true,
    allowedSchemas: new Set(['dbo']),
    allowedTables: new Set(),
    allowedColumns: new Set(),
    allowedSelectFunctions: new Set(),
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

test('execute_query accepts SQL keywords inside T-SQL literals and identifiers', () => {
  const server = createServer();
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT @value AS value'));
  assert.doesNotThrow(() =>
    server.validateSelectQuery("SELECT TOP 1 name FROM sys.objects WHERE name = 'delete'")
  );
  assert.doesNotThrow(() =>
    server.validateSelectQuery("SELECT name FROM sys.objects WHERE status IN ('insert', 'update')")
  );
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT 'it''s a drop test' AS value"));
  assert.doesNotThrow(() =>
    server.validateSelectQuery(String.raw`SELECT 'C:\path\to\delete' AS path_value`)
  );
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT N'delete' AS value"));
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT "delete" FROM sys.objects'));
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT [delete] FROM sys.objects'));
});

test('execute_query still rejects executable batch, comment, and mutation syntax', () => {
  const server = createServer();
  assert.throws(() => server.validateSelectQuery('SELECT 1; DROP TABLE x'), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery('SELECT 1 -- comment'), /forbidden SQL syntax/);
  assert.throws(
    () => server.validateSelectQuery('SELECT name FROM sys.objects /* comment */'),
    /forbidden SQL syntax/
  );
  assert.throws(() => server.validateSelectQuery('SELECT 1; DELETE FROM t'), /forbidden SQL syntax/);
  assert.throws(() => server.validateSelectQuery('DELETE FROM users'), /Only SELECT queries/);
});

test('literal masking preserves executable tokens only', () => {
  const maskedSegments = ["'delete; --'", "'insert'", '"update"', '[drop]]name]'];
  const query = `SELECT ${maskedSegments[0]} AS text_value, N${maskedSegments[1]} AS unicode_value, ${maskedSegments[2]} AS quoted_value, ${maskedSegments[3]} FROM sample WHERE action = delete`;
  const expected = maskedSegments.reduce(
    (masked, segment) => masked.replace(segment, ' '.repeat(segment.length)),
    query
  );

  assert.equal(maskSqlLiterals(query), expected);
  assert.match(maskSqlLiterals(query), /FROM sample WHERE action = delete$/);
});

test('structured filters quote identifiers and parameterize values', () => {
  const server = createServer();
  const result = server.buildFilterClause([
    { column: 'id', operator: 'eq', value: 42 },
    { column: 'status', operator: 'in', value: ['active', 'pending'] },
    { column: 'deleted_at', operator: 'is_null' },
  ]);

  assert.equal(
    result.clause,
    '[id] = @filter_0 AND [status] IN (@filter_1_0, @filter_1_1) AND [deleted_at] IS NULL'
  );
  assert.deepEqual(result.parameters, {
    filter_0: 42,
    filter_1_0: 'active',
    filter_1_1: 'pending',
  });
  assert.throws(
    () => server.buildFilterClause([{ column: 'id; DROP TABLE users', operator: 'eq', value: 1 }]),
    /Invalid filter column name/
  );
  assert.throws(() => server.buildFilterClause([]), /non-empty array/);
});

test('runtime write guards use default-deny semantics', () => {
  const server = createServer();
  assert.throws(() => server.ensureWritesAllowed('INSERT'), /ALLOW_WRITES=true/);
  assert.throws(() => server.ensureDeleteAllowed(), /ALLOW_WRITES=true/);

  const writes = createServer({ allowWrites: true });
  assert.doesNotThrow(() => writes.ensureWritesAllowed('UPDATE'));
  assert.throws(() => writes.ensureDeleteAllowed(), /ALLOW_DELETE=true/);
});

test('stored procedure allowlists require an exact schema-qualified match', () => {
  const server = createServer({
    allowStoredProcedures: true,
    allowedProcedures: new Set(['dbo.getusers']),
  });
  assert.doesNotThrow(() => server.ensureStoredProceduresAllowed('dbo', 'GetUsers'));
  assert.throws(
    () => server.ensureStoredProceduresAllowed('audit', 'GetUsers'),
    /not allowlisted/
  );
});

test('MAX_AFFECTED_ROWS rolls back before an oversized MSSQL update', async () => {
  const queries = [];
  const transaction = {
    async begin() {},
    async commit() {},
    async rollback() {
      queries.push('ROLLBACK');
    },
  };
  const server = createServer({ allowWrites: true, maxAffectedRows: 2 });
  server.getPool = async () => ({});
  server.createTransaction = () => transaction;
  server.createTransactionRequest = () => ({
    input() {},
    async query(query) {
      queries.push(query.trim());
      return { recordset: [{}, {}, {}], rowsAffected: [3] };
    },
  });

  await assert.rejects(
    server.executeUpdate(
      'Users',
      { status: 'inactive' },
      [{ column: 'id', operator: 'gte', value: 1 }]
    ),
    /more than MAX_AFFECTED_ROWS/
  );
  assert.equal(queries.includes('ROLLBACK'), true);
  assert.equal(queries.some((query) => query.startsWith('UPDATE')), false);
});

test('numeric configuration parsing rejects partial and unsafe values', () => {
  const server = createServer();
  assert.equal(server.parseNonNegativeInteger('100', 1, 'LIMIT'), 100);
  assert.throws(() => server.parseNonNegativeInteger('100rows', 1, 'LIMIT'), /non-negative integer/);
  assert.throws(() => server.parsePositiveInteger('0', 1, 'PORT'), /greater than zero/);
});

test('connection limits and timeouts are passed to the driver', async () => {
  const server = createServer({ statementTimeoutMs: 12000, connectionTimeoutMs: 4000 });
  await withEnvironment(
    {
      DB_USER: 'mcp_ro',
      DB_PORT: '1434',
      MAX_CONNECTIONS: '7',
      DB_ENCRYPT: 'true',
      DB_TRUST_SERVER_CERTIFICATE: 'false',
    },
    () => {
      const config = server.buildConnectionConfig();
      assert.equal(config.port, 1434);
      assert.equal(config.pool.max, 7);
      assert.equal(config.requestTimeout, 12000);
      assert.equal(config.connectionTimeout, 4000);
      assert.equal(config.options.encrypt, true);
      assert.equal(config.options.trustServerCertificate, false);
    }
  );
});

test('remote SQL Server connections verify certificates by default', async () => {
  const server = createServer({ statementTimeoutMs: 12000, connectionTimeoutMs: 4000 });
  await withEnvironment(
    {
      DB_USER: 'mcp_ro',
      DB_HOST: 'remote.example',
      DB_TRUST_SERVER_CERTIFICATE: undefined,
    },
    () => {
      const config = server.buildConnectionConfig();
      assert.equal(config.options.encrypt, true);
      assert.equal(config.options.trustServerCertificate, false);
    }
  );
});

test('connection configuration requires an explicit non-empty DB_USER', async () => {
  const server = createServer();
  await withEnvironment({ DB_USER: undefined }, () => {
    assert.throws(() => server.buildConnectionConfig(), /DB_USER is required/);
  });
  await withEnvironment({ DB_USER: '   ' }, () => {
    assert.throws(() => server.buildConnectionConfig(), /DB_USER is required/);
  });
});

test('oversized results are capped and tool errors are marked', () => {
  const server = createServer({ maxResponseBytes: 300 });
  const result = server.createJsonResult({ recordset: [{ value: 'x'.repeat(500) }], rowCount: 1 });
  const payload = JSON.parse(result.content[0].text);
  assert.equal(payload.truncated, true);
  assert.ok(Buffer.byteLength(result.content[0].text, 'utf8') <= 300);

  const error = server.createErrorResult(new Error('blocked'));
  assert.equal(error.isError, true);
  assert.match(error.content[0].text, /blocked/);
});

test('secure defaults hide arbitrary SELECT and database enumeration', () => {
  const server = createServer({ allowArbitrarySelect: false, allowDatabaseList: false });
  const names = [];
  server.server = {
    setRequestHandler(_schema, handler) {
      names.push(handler);
    },
  };
  server.setupToolHandlers();
  assert.throws(() => server.validateSelectQuery('SELECT 1'), /disabled/);
});

test('T-SQL sequence and non-allowlisted function access is blocked', () => {
  const server = createServer({ allowedSelectFunctions: new Set(['count']) });
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT count(*) FROM sample'));
  assert.throws(
    () => server.validateSelectQuery('SELECT NEXT VALUE FOR dbo.sequence_name AS value'),
    /sequence operation/
  );
  assert.throws(
    () => server.validateSelectQuery("SELECT BulkColumn FROM OPENROWSET(BULK 'file', SINGLE_CLOB) AS source"),
    /not allowlisted/
  );
});

test('schema policies and input budgets fail before database access', async () => {
  const server = createServer({ allowedSchemas: new Set(['dbo']), maxInputBytes: 20 });
  await assert.rejects(server.describeTable('Users', 'private'), /not allowlisted/);
  assert.throws(() => server.validateSelectQuery(`SELECT '${'x'.repeat(30)}'`), /MAX_INPUT_BYTES/);
});

test('column policies apply to structured data and filters', () => {
  const server = createServer({
    allowedColumns: new Set(['dbo.users.id', 'dbo.users.status']),
  });
  assert.doesNotThrow(() => server.validateAllowedColumns('dbo', 'users', ['id', 'status']));
  assert.throws(
    () => server.validateAllowedColumns('dbo', 'users', ['password_hash']),
    /not allowlisted/
  );
  assert.throws(
    () =>
      server.validateAllowedFilterColumns('dbo', 'users', [
        { column: 'email', operator: 'eq', value: 'a@example.test' },
      ]),
    /not allowlisted/
  );
});

test('database errors are normalized before returning through MCP', () => {
  const server = createServer();
  const result = server.createErrorResult(
    Object.assign(new Error('Invalid object private.SecretTable'), {
      name: 'RequestError',
      code: 'EREQUEST',
    })
  );
  assert.match(result.content[0].text, /Database operation failed/);
  assert.doesNotMatch(result.content[0].text, /private|SecretTable|EREQUEST/);
});
