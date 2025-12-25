# @ap0h/sqli-detector

A **safe, pure JavaScript** SQL injection detection library with **zero dependencies**.

[![npm version](https://img.shields.io/npm/v/@ap0h/sqli-detector.svg)](https://github.com/ap0h/sql-injection-detector/packages)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔒 **Zero dependencies** - No supply chain risks
- 🚀 **Pure JavaScript** - No Python, no external processes
- 🎯 **High accuracy** - Detects 20+ attack patterns
- 📊 **Risk scoring** - Threat levels from SAFE to CRITICAL
- 🐘 **PostgreSQL support** - Detects `pg_sleep`, `pg_read_file`, etc.
- 🔧 **TypeScript ready** - Full type definitions included

## Installation

```bash
# From GitHub Packages
npm install @ap0h/sqli-detector --registry=https://npm.pkg.github.com
```

Or add to your `.npmrc`:
```
@ap0h:registry=https://npm.pkg.github.com
```

Then:
```bash
npm install @ap0h/sqli-detector
```

## Quick Start

```javascript
const { detectSql, sanitize } = require('@ap0h/sqli-detector');

// Detect SQL injection
const result = detectSql("' OR '1'='1");
console.log(result.isSqlInjection);  // true
console.log(result.threatLevel);      // 'HIGH'
```

## Real-World Example: Protecting API Query Parameters

```javascript
const { detectSql } = require('@ap0h/sqli-detector');
const express = require('express');
const app = express();

// Middleware to protect against SQL injection
function sqlInjectionGuard(req, res, next) {
  for (const [key, value] of Object.entries(req.query)) {
    if (typeof value !== 'string') continue;
    
    const result = detectSql(value);
    
    if (result.isSqlInjection) {
      console.log(`🚨 SQL Injection blocked!`);
      console.log(`   Parameter: ${key}`);
      console.log(`   Value: ${value}`);
      console.log(`   Threat: ${result.threatLevel}`);
      console.log(`   Score: ${result.score}`);
      
      return res.status(400).json({ error: 'Invalid input' });
    }
  }
  next();
}

app.use(sqlInjectionGuard);

// Your protected endpoint
app.get('/api/search', (req, res) => {
  const search = req.query.q;
  // Safe to use with parameterized query
  res.json({ results: [] });
});

app.listen(3000);
```

### What happens with an attack:

```
GET /api/search?q='1'='1' OR pg_sleep(5)--

Console output:
🚨 SQL Injection blocked!
   Parameter: q
   Value: '1'='1' OR pg_sleep(5)--
   Threat: CRITICAL
   Score: 25

Response: 400 Bad Request
```

### Safe inputs pass through:

```
GET /api/search?q=bitcoin          → ✅ Allowed (score: 0)
GET /api/search?q=ethereum%20price → ✅ Allowed (score: 0)
GET /api/search?q=O'Brien          → ✅ Allowed (score: 0)
```

## API Reference

### `detectSql(input, options?)`

Main detection function.

```javascript
const result = detectSql("' UNION SELECT * FROM users--");

// Result:
{
  isSqlInjection: true,
  score: 15,
  threatLevel: 'HIGH',      // 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  tokens: ['UNION', 'COMMENT']
}
```

**Options:**
- `threshold` (number, default: 5) - Score threshold for detection
- `detailed` (boolean, default: false) - Include match details

### `explain(input)`

Get detailed analysis with explanations.

```javascript
const { explain } = require('@ap0h/sqli-detector');

const analysis = explain("' OR '1'='1");

// Returns:
{
  isSqlInjection: true,
  score: 12,
  threatLevel: 'HIGH',
  findings: [
    {
      pattern: 'BOOLEAN',
      explanation: 'Boolean-based injection pattern',
      matches: ["'1'='1"]
    },
    {
      pattern: 'TAUTOLOGY', 
      explanation: 'Tautology attack (always-true condition)',
      matches: ["' OR '1'='1"]
    }
  ],
  recommendation: 'BLOCK this input - high likelihood of SQL injection attack'
}
```

### `sanitize(input)`

Basic string escaping. **Always prefer parameterized queries!**

```javascript
const { sanitize } = require('@ap0h/sqli-detector');

sanitize("O'Brien");     // "O''Brien"
sanitize("test\\path");  // "test\\\\path"
```

### `detectSqlAsync(input)`

Promise-based detection for async workflows.

```javascript
const { detectSqlAsync } = require('@ap0h/sqli-detector');

const result = await detectSqlAsync(userInput);
if (!result.success) {
  // SQL injection detected - block request
}
```

## Detection Coverage

| Attack Type | Example | Threat Level |
|-------------|---------|--------------|
| Boolean injection | `' OR '1'='1` | HIGH |
| UNION injection | `' UNION SELECT * FROM users--` | HIGH |
| DROP TABLE | `'; DROP TABLE users;--` | CRITICAL |
| Time-based (MySQL) | `' AND SLEEP(5)--` | HIGH |
| Time-based (PostgreSQL) | `'||pg_sleep(5)||'` | HIGH |
| Login bypass | `admin'--` | MEDIUM |
| File read | `LOAD_FILE('/etc/passwd')` | CRITICAL |
| Schema enumeration | `information_schema.tables` | HIGH |
| CHAR bypass | `CHAR(65)+CHAR(66)` | MEDIUM |
| Comment injection | `admin'/*` | MEDIUM |

## Threat Levels

| Level | Score | Action |
|-------|-------|--------|
| SAFE | 0 | Allow |
| LOW | 1-4 | Allow (monitor) |
| MEDIUM | 5-9 | Block or review |
| HIGH | 10-19 | Block |
| CRITICAL | 20+ | Block + alert |

## Important: Defense in Depth

This detector is a **first line of defense**. Always combine with:

```javascript
// ✅ ALWAYS use parameterized queries
const results = await db.query(
  'SELECT * FROM users WHERE name = $1',
  [userInput]  // Parameterized - safe even if injection slips through
);

// ❌ NEVER concatenate user input into SQL
const results = await db.query(
  `SELECT * FROM users WHERE name = '${userInput}'`  // DANGEROUS!
);
```

## TypeScript

Full TypeScript support included:

```typescript
import { detectSql, DetectionResult } from '@ap0h/sqli-detector';

const result: DetectionResult = detectSql(userInput);

if (result.isSqlInjection) {
  // Handle attack
}
```

## Support

If this library helped protect your application, consider supporting development:

**Solana:** `25iWiaiKvUjkG1DoA9MujPiEdE6kTbKokchfE4ohNMnT`

## License

MIT

## Contributing

Issues and PRs welcome at [GitHub](https://github.com/ap0h/sql-injection-detector).
