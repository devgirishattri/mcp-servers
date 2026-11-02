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
    /forbidden SQL syntax|not allowlisted/
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

test('execute_query rejects additional T-SQL statements that need no semicolon', () => {
  const server = createServer();
  for (const query of [
    'SELECT 1 SET TEXTSIZE 2147483647',
    'SELECT 1 BEGIN TRAN',
    'SELECT 1 COMMIT',
    'SELECT 1 USE master',
    "SELECT 1 WAITFOR DELAY '00:00:05'",
    'SELECT 1 DECLARE @x int',
    'SELECT 1 DBCC FREEPROCCACHE',
    'SELECT 1 KILL 55',
    'SELECT 1 SHUTDOWN',
    'SELECT 1 RECONFIGURE',
    'SELECT 1 CHECKPOINT',
    'SELECT 1 REVERT',
    'SELECT 1 DENY SELECT ON dbo.t TO public',
    'SELECT 1 IF 1 = 1 SELECT 2',
    'SELECT 1 WHILE 1 = 0 BREAK',
    'SELECT 1 RECEIVE * FROM dbo.q',
    'SELECT 1 DISABLE TRIGGER t ON dbo.x',
    'SELECT 1 END CONVERSATION @h',
  ]) {
    assert.throws(() => server.validateSelectQuery(query), /forbidden SQL syntax/, query);
  }
});

test('execute_query still accepts ordinary SELECT syntax around the new keyword guard', () => {
  const server = createServer({ allowedSelectFunctions: new Set(['count']) });
  assert.doesNotThrow(() =>
    server.validateSelectQuery(
      'SELECT id, CASE WHEN status = 1 THEN 1 ELSE 0 END AS active FROM dbo.t ORDER BY id OFFSET 0 ROWS FETCH NEXT 10 ROWS ONLY'
    )
  );
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT [set], [open], [close], "begin" FROM dbo.t'));
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT 'set use begin' AS note, count(*) FROM dbo.t"));
  assert.doesNotThrow(() => server.validateSelectQuery('SELECT settings, opened_at, end_date FROM dbo.t'));
});

test('quoted T-SQL function names cannot bypass the function allowlist', () => {
  const server = createServer();
  assert.throws(() => server.validateSelectQuery('SELECT dbo.f(1)'), /not allowlisted/);
  for (const query of [
    'SELECT [dbo].[f](1)',
    'SELECT dbo.[f] (1)',
    'SELECT "dbo"."f"(1)',
    'SELECT [f]]x](1)',
  ]) {
    assert.throws(() => server.validateSelectQuery(query), /Quoted function names/, query);
  }
  assert.doesNotThrow(() => server.validateSelectQuery("SELECT '[x](1)' AS literal_text"));
});

test('unterminated T-SQL quotes and brackets fail closed', () => {
  const server = createServer();
  assert.throws(() => server.validateSelectQuery("SELECT 'open"), /unterminated/);
  assert.throws(() => server.validateSelectQuery('SELECT [open'), /unterminated/);
  assert.throws(() => server.validateSelectQuery('SELECT "open'), /unterminated/);
});

test('identifier-preserving masking keeps quoted identifiers and blanks string literals', () => {
  const query = "SELECT [a'b], \"c\", 'd[e]' FROM t";
  assert.equal(
    maskSqlLiterals(query, { preserveQuotedIdentifiers: true }),
    `SELECT [a'b], "c", ${' '.repeat(6)} FROM t`
  );
  assert.equal(maskSqlLiterals('SELECT N\'\u{1F600}\' AS a, b').endsWith(' AS a, b'), true);
});

test('raw SELECT runs inside a transaction that is always rolled back', async () => {
  const events = [];
  const server = createServer();
  server.getPool = async () => ({});
  server.createTransaction = () => ({
    async begin() {
      events.push('BEGIN');
    },
    async commit() {
      events.push('COMMIT');
    },
    async rollback() {
      events.push('ROLLBACK');
    },
  });
  server.createTransactionRequest = () => ({ input() {} });
  server.executeBoundedSelect = async () => {
    events.push('QUERY');
    return { rows: [{ id: 1 }], fields: ['id'], truncated: false };
  };

  const result = JSON.parse((await server.executeQuery('SELECT id FROM dbo.t')).content[0].text);
  assert.equal(result.rowCount, 1);
  assert.deepEqual(events, ['BEGIN', 'QUERY', 'ROLLBACK']);

  events.length = 0;
  server.executeBoundedSelect = async () => {
    events.push('QUERY');
    throw new Error('stream failed');
  };
  await assert.rejects(server.executeQuery('SELECT id FROM dbo.t'), /stream failed/);
  assert.deepEqual(events, ['BEGIN', 'QUERY', 'ROLLBACK']);
});

test('bounded SELECT enables XACT_ABORT before the caller query', async () => {
  const server = createServer();
  let sent;
  const request = {
    on() {},
    cancel() {},
    toReadableStream() {
      return (async function* rows() {})();
    },
    query(text) {
      sent = text;
      return Promise.resolve({});
    },
  };
  await server.executeBoundedSelect(request, 'SELECT 1 AS one');
  assert.equal(sent, 'SET XACT_ABORT ON; SET TEXTSIZE 65536; SELECT 1 AS one');
});

test('returned mutation rows omit columns outside ALLOWED_COLUMNS', async () => {
  const server = createServer({
    allowWrites: true,
    returnMutationRows: true,
    allowedColumns: new Set(['dbo.users.id', 'dbo.users.status']),
  });
  server.getPool = async () => ({});
  server.createTransaction = () => ({ async begin() {}, async commit() {}, async rollback() {} });
  server.createTransactionRequest = () => ({
    input() {},
    async query(query) {
      if (query.includes('SELECT TOP')) return { recordset: [{ target: 1 }], rowsAffected: [1] };
      return {
        recordset: [{ Id: 7, Status: 'inactive', password_hash: 'secret' }],
        rowsAffected: [1],
      };
    },
  });

  const result = JSON.parse(
    (
      await server.executeUpdate('users', { status: 'inactive' }, [
        { column: 'id', operator: 'eq', value: 7 },
      ])
    ).content[0].text
  );
  assert.deepEqual(result.updated, [{ Id: 7, Status: 'inactive' }]);
});

test('RETURN_MUTATION_ROWS requires positive affected-row and response limits', async () => {
  for (const [key, label] of [
    ['MAX_AFFECTED_ROWS', /positive MAX_AFFECTED_ROWS/],
    ['MAX_RESPONSE_BYTES', /positive MAX_RESPONSE_BYTES/],
  ]) {
    await withEnvironment(
      { DB_USER: 'mcp_ro', RETURN_MUTATION_ROWS: 'true', [key]: '0', DB_HOST: undefined },
      () => {
        assert.throws(() => new MSSQLMCPServer(), label);
      }
    );
  }
});

test('insecure SQL Server transport is refused for non-loopback hosts unless explicitly allowed', async () => {
  const server = createServer();
  await withEnvironment(
    { DB_USER: 'mcp_ro', DB_HOST: 'db.example', DB_TRUST_SERVER_CERTIFICATE: 'true', ALLOW_INSECURE_TLS: undefined },
    () => {
      assert.throws(() => server.buildConnectionConfig(), /DB_TRUST_SERVER_CERTIFICATE=true .* ALLOW_INSECURE_TLS/);
    }
  );
  await withEnvironment(
    { DB_USER: 'mcp_ro', DB_HOST: 'db.example', DB_ENCRYPT: 'false', DB_TRUST_SERVER_CERTIFICATE: undefined, ALLOW_INSECURE_TLS: undefined },
    () => {
      assert.throws(() => server.buildConnectionConfig(), /DB_ENCRYPT=false/);
    }
  );
  await withEnvironment(
    { DB_USER: 'mcp_ro', DB_HOST: 'db.example', DB_TRUST_SERVER_CERTIFICATE: 'true', ALLOW_INSECURE_TLS: 'true' },
    () => {
      assert.equal(server.buildConnectionConfig().options.trustServerCertificate, true);
    }
  );
  await withEnvironment(
    { DB_USER: 'mcp_ro', DB_HOST: '127.0.0.1', DB_TRUST_SERVER_CERTIFICATE: 'true', ALLOW_INSECURE_TLS: undefined },
    () => {
      assert.equal(server.buildConnectionConfig().options.trustServerCertificate, true);
    }
  );
});

test('privilege verification covers views, server permissions, and write-mode exceptions', async () => {
  let sentQuery = '';
  const poolWith = (row) => ({
    request: () => ({
      async query(text) {
        sentQuery = text;
        return { recordset: [row] };
      },
    }),
  });
  const reader = createServer({ mode: 'read', verifyDbPrivileges: true });
  await assert.doesNotReject(reader.verifyConnectionSecurity(poolWith({ is_sysadmin: 0, can_shutdown: null })));
  assert.match(sentQuery, /HAS_PERMS_BY_NAME\(NULL, NULL, 'CONTROL SERVER'\)/);
  assert.doesNotMatch(sentQuery, /'SERVER', 'CONTROL SERVER'/);
  assert.match(sentQuery, /candidate\.type IN \('U', 'V', 'SN'\)/);
  await assert.rejects(
    reader.verifyConnectionSecurity(poolWith({ has_object_write_permission: 1 })),
    /has_object_write_permission/
  );
  await assert.rejects(
    reader.verifyConnectionSecurity(poolWith({ can_alter_any_connection: 1 })),
    /can_alter_any_connection/
  );

  const writer = createServer({ mode: 'write', verifyDbPrivileges: true });
  await assert.doesNotReject(
    writer.verifyConnectionSecurity(
      poolWith({ has_object_write_permission: 1, has_database_write_permission: 1, has_sequence_write_permission: 1 })
    )
  );
  await assert.rejects(
    writer.verifyConnectionSecurity(poolWith({ has_object_alter_permission: 1 })),
    /has_object_alter_permission/
  );
});

test('stored procedure output is bounded while the procedure runs to completion', async () => {
  const { EventEmitter } = await import('node:events');
  const server = createServer({ maxRows: 2, maxFieldBytes: 20 });
  const request = new EventEmitter();
  request.cancel = () => {
    throw new Error('should not cancel');
  };
  request.execute = async () => {
    request.emit('recordset', { id: {}, note: {} });
    for (let id = 1; id <= 5; id += 1) {
      request.emit('row', { id, note: id === 2 ? 'x'.repeat(50) : 'ok' });
    }
    return { output: { total: 5 }, returnValue: 0, rowsAffected: [5] };
  };

  const result = await server.executeBoundedProcedure(request, 'dbo.listUsers');
  assert.equal(request.stream, true);
  assert.equal(result.rowCount, 2);
  assert.equal(result.truncated, true);
  assert.deepEqual(result.recordsets, [
    [
      { id: 1, note: 'ok' },
      { id: 2, note: '[omitted: field exceeds MAX_FIELD_BYTES]' },
    ],
  ]);
  assert.deepEqual(result.output, { total: 5 });

  const failing = new EventEmitter();
  failing.execute = async () => {
    failing.emit('error', new Error('procedure failed'));
    return {};
  };
  await assert.rejects(server.executeBoundedProcedure(failing, 'dbo.fail'), /procedure failed/);

  const wide = new EventEmitter();
  let cancelled = false;
  wide.cancel = () => {
    cancelled = true;
  };
  wide.execute = async () => {
    wide.emit('recordset', Object.fromEntries(Array.from({ length: 101 }, (_, i) => [`c${i}`, {}])));
    return {};
  };
  await assert.rejects(server.executeBoundedProcedure(wide, 'dbo.wide'), /MAX_COLUMNS/);
  assert.equal(cancelled, true);
});

test('failed audited tool calls emit an audit event without values', async () => {
  const server = createServer({ allowArbitrarySelect: false });
  const handlers = [];
  server.server = {
    setRequestHandler(_schema, handler) {
      handlers.push(handler);
    },
  };
  server.setupToolHandlers();
  const callTool = handlers[1];
  const logged = [];
  const originalError = console.error;
  console.error = (message) => logged.push(message);
  try {
    await withEnvironment({ AUDIT_LOG: undefined }, async () => {
      const result = await callTool({
        params: { name: 'execute_query', arguments: { query: "SELECT 'secret-value'" } },
      });
      assert.equal(result.isError, true);
    });
  } finally {
    console.error = originalError;
  }
  const event = JSON.parse(logged.find((line) => line.startsWith('[MCP Audit]')).slice('[MCP Audit] '.length));
  assert.equal(event.category, 'tool_failure');
  assert.equal(event.operation, 'execute_query');
  assert.equal(event.errorType, 'policy');
  assert.match(event.reference, /^[0-9a-f-]{36}$/);
  assert.doesNotMatch(JSON.stringify(event), /secret-value/);
});
