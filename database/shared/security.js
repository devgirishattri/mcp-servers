import { randomUUID } from "node:crypto";
import { Transform } from "node:stream";

const DATABASE_ERROR_NAMES = new Set([
  "ConnectionError",
  "RequestError",
  "TransactionError",
  "PreparedStatementError",
]);
const NON_FUNCTION_TOKENS = new Set([
  "in",
  "exists",
  "over",
  "partition",
  "values",
  "from",
  "join",
  "apply",
  "case",
  "when",
]);
const IDENTIFIER_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const FILTER_OPERATORS = new Set([
  "eq",
  "neq",
  "gt",
  "gte",
  "lt",
  "lte",
  "like",
  "in",
  "is_null",
  "is_not_null",
]);
export const FILTER_KEYS = new Set(["column", "operator", "value"]);
export const FILTERS_INPUT_SCHEMA = {
  type: "array",
  minItems: 1,
  description: "Non-empty list of validated predicates joined with AND",
  items: {
    type: "object",
    additionalProperties: false,
    properties: {
      column: { type: "string", description: "Column name" },
      operator: { type: "string", enum: Array.from(FILTER_OPERATORS) },
      value: { description: "Predicate value; omitted for is_null and is_not_null" },
    },
    required: ["column", "operator"],
  },
};

export function parseNonNegativeInteger(value, defaultValue, label) {
  if (value === undefined || value === "") return defaultValue;
  if (!/^\d+$/.test(String(value))) {
    throw new Error(`${label} must be a non-negative integer.`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${label} must be a safe non-negative integer.`);
  }
  return parsed;
}

export function parsePositiveInteger(value, defaultValue, label) {
  const parsed = parseNonNegativeInteger(value, defaultValue, label);
  if (parsed === 0) throw new Error(`${label} must be greater than zero.`);
  return parsed;
}

export function validateIdentifier(identifier, label = "identifier") {
  if (typeof identifier !== "string" || !IDENTIFIER_PATTERN.test(identifier)) {
    throw new Error(
      `Invalid ${label}. Use letters, numbers, and underscores only, starting with a letter or underscore.`
    );
  }
}

export function validateDataObject(data, validate = validateIdentifier) {
  if (!data || typeof data !== "object" || Array.isArray(data) || Object.keys(data).length === 0) {
    throw new Error("Data must be a non-empty object.");
  }
  for (const column of Object.keys(data)) validate(column, "column name");
}

export function validateFilters(filters, validate = validateIdentifier) {
  if (!Array.isArray(filters) || filters.length === 0) {
    throw new Error("Filters must be a non-empty array.");
  }
  for (const filter of filters) {
    if (!filter || typeof filter !== "object" || Array.isArray(filter)) {
      throw new Error("Each filter must be an object.");
    }
    for (const key of Object.keys(filter)) {
      if (!FILTER_KEYS.has(key)) throw new Error(`Unsupported filter property: ${key}`);
    }
    validate(filter.column, "filter column name");
    if (!FILTER_OPERATORS.has(filter.operator)) {
      throw new Error(`Unsupported filter operator: ${filter.operator}`);
    }
    const hasValue = Object.prototype.hasOwnProperty.call(filter, "value");
    if (["is_null", "is_not_null"].includes(filter.operator)) {
      if (hasValue) throw new Error(`${filter.operator} does not accept a value.`);
    } else if (!hasValue) {
      throw new Error(`${filter.operator} requires a value.`);
    }
    if (filter.operator === "in" && (!Array.isArray(filter.value) || filter.value.length === 0)) {
      throw new Error("The in operator requires a non-empty array value.");
    }
  }
}

export function createJsonResult(payload, maxResponseBytes) {
  let text = JSON.stringify(payload, null, 2);
  const responseBytes = Buffer.byteLength(text, "utf8");
  if (maxResponseBytes > 0 && responseBytes > maxResponseBytes) {
    text = JSON.stringify(
      {
        truncated: true,
        message: "Result omitted because it exceeded MAX_RESPONSE_BYTES. Refine the request or increase the limit.",
        responseBytes,
        maxResponseBytes,
        rowCount: payload.rowCount ?? payload.rowsAffected ?? null,
      },
      null,
      2
    );
    if (Buffer.byteLength(text, "utf8") > maxResponseBytes) {
      text = `Result exceeded MAX_RESPONSE_BYTES (${maxResponseBytes}).`.slice(0, maxResponseBytes);
    }
  }
  return { content: [{ type: "text", text }] };
}

export function parseCsvSet(value, fallback = "") {
  const parse = (source) => new Set(
    String(source ?? "")
      .split(",")
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean)
  );
  const parsed = parse(value);
  return parsed.size > 0 || fallback === "" ? parsed : parse(fallback);
}

export function assertAllowedSchema(schemaName, allowedSchemas) {
  if (allowedSchemas.size > 0 && !allowedSchemas.has(schemaName.toLowerCase())) {
    throw new Error(`Schema is not allowlisted: ${schemaName}`);
  }
}

export function assertAllowedTable(schemaName, tableName, allowedSchemas, allowedTables) {
  assertAllowedSchema(schemaName, allowedSchemas);
  if (allowedTables.size === 0) {
    return;
  }

  const qualifiedName = `${schemaName}.${tableName}`.toLowerCase();
  if (!allowedTables.has(qualifiedName)) {
    throw new Error(`Table is not allowlisted: ${schemaName}.${tableName}`);
  }
}

export function assertAllowedColumn(schemaName, tableName, columnName, allowedColumns) {
  if (allowedColumns.size === 0) {
    return;
  }
  const qualifiedName = `${schemaName}.${tableName}.${columnName}`.toLowerCase();
  if (!allowedColumns.has(qualifiedName)) {
    throw new Error(`Column is not allowlisted: ${schemaName}.${tableName}.${columnName}`);
  }
}

export function allowedColumnNames(schemaName, tableName, allowedColumns) {
  if (allowedColumns.size === 0) {
    return [];
  }
  const prefix = `${schemaName}.${tableName}.`.toLowerCase();
  return Array.from(allowedColumns)
    .filter((name) => name.startsWith(prefix))
    .map((name) => name.slice(prefix.length));
}

export function assertInputBudget(value, label, maxBytes, maxItems) {
  if (maxItems > 0) {
    const itemCount = Array.isArray(value)
      ? value.length
      : value && typeof value === "object"
        ? Object.keys(value).length
        : 0;
    if (itemCount > maxItems) {
      throw new Error(`${label} exceeds MAX_INPUT_ITEMS (${maxItems}).`);
    }
  }

  if (maxBytes > 0) {
    let serialized;
    try {
      serialized = JSON.stringify(value);
    } catch {
      throw new Error(`${label} must be JSON-serializable.`);
    }
    if (Buffer.byteLength(serialized ?? "", "utf8") > maxBytes) {
      throw new Error(`${label} exceeds MAX_INPUT_BYTES (${maxBytes}).`);
    }
  }
}

export function assertAllowedFunctions(maskedQuery, allowedFunctions, forbiddenFunctions = new Set()) {
  const identifierPattern = `(?:"(?:[^"]|"")*"|[\\p{L}_][\\p{L}\\p{N}_$]*)`;
  const queryWithoutDerivedColumnAliases = maskedQuery.replace(
    new RegExp(`\\bAS\\s+${identifierPattern}\\s*\\([^)]*\\)`, "giu"),
    " "
  );
  const calls = queryWithoutDerivedColumnAliases.matchAll(
    new RegExp(
      `(?<![\\p{L}\\p{N}_$"])(?:(${identifierPattern})\\s*\\.\\s*)?(${identifierPattern})\\s*\\(`,
      "gu"
    )
  );

  const normalizeIdentifier = (identifier) => {
    if (identifier.startsWith('"')) {
      return identifier.slice(1, -1).replace(/""/g, '"');
    }
    return identifier.toLowerCase();
  };

  for (const match of calls) {
    const qualifier = match[1] ? normalizeIdentifier(match[1]) : null;
    const shortName = normalizeIdentifier(match[2]);
    const qualifiedName = qualifier ? `${qualifier}.${shortName}` : shortName;
    if (!qualifier && !match[2].startsWith('"') && NON_FUNCTION_TOKENS.has(shortName)) {
      continue;
    }
    if (forbiddenFunctions.has(qualifiedName) || forbiddenFunctions.has(shortName)) {
      throw new Error(`Query calls a forbidden function: ${qualifiedName}`);
    }
    const allowed = qualifier
      ? allowedFunctions.has(qualifiedName)
      : allowedFunctions.has(shortName);
    if (!allowed) {
      throw new Error(`Query function is not allowlisted: ${qualifiedName}`);
    }
  }
}

export function requireMutationConfirmation(confirmed, operation) {
  if (confirmed !== true) {
    throw new Error(`${operation} requires confirm=true after explicit user approval.`);
  }
}

export function auditMutation(engine, operation, metadata = {}) {
  if (process.env.AUDIT_LOG === "false") {
    return;
  }
  const event = {
    timestamp: new Date().toISOString(),
    category: "database_mutation",
    engine,
    operation,
    ...metadata,
  };
  console.error(`[MCP Audit] ${JSON.stringify(event)}`);
}

export function createSafeErrorResult(error, maxResponseBytes, log = () => {}) {
  const errorId = randomUUID();
  const isDatabaseError =
    DATABASE_ERROR_NAMES.has(error?.name) ||
    typeof error?.code === "string" ||
    typeof error?.number === "number";
  const publicMessage = isDatabaseError
    ? `Database operation failed. Reference: ${errorId}`
    : error?.message || `Operation failed. Reference: ${errorId}`;

  if (isDatabaseError) {
    log(`Database error ${errorId}: code=${error?.code || error?.name || "unknown"}`);
  }

  let text = `Error: ${publicMessage}`;
  if (maxResponseBytes > 0 && Buffer.byteLength(text, "utf8") > maxResponseBytes) {
    text = `Error response exceeded MAX_RESPONSE_BYTES. Reference: ${errorId}`.slice(
      0,
      maxResponseBytes
    );
  }
  return {
    isError: true,
    content: [{ type: "text", text }],
  };
}

export function createLimitedLineInput(input, maxBytes) {
  let currentLineBytes = 0;
  const limiter = new Transform({
    transform(chunk, _encoding, callback) {
      for (const byte of chunk) {
        if (byte === 10) {
          currentLineBytes = 0;
        } else {
          currentLineBytes += 1;
          if (maxBytes > 0 && currentLineBytes > maxBytes) {
            callback(new Error(`MCP request exceeds MAX_REQUEST_BYTES (${maxBytes}).`));
            return;
          }
        }
      }
      callback(null, chunk);
    },
  });
  return input.pipe(limiter);
}
