/**
 * SQL Injection Detector - Usage Examples
 * 
 * Shows how to integrate the detector into your API endpoints
 */

const { detectSql, explain, sanitize } = require('./index');

// ============================================================================
// EXAMPLE 1: Basic Usage
// ============================================================================

console.log('=== Example 1: Basic Detection ===\n');

const userInput = "'1'='1' OR pg_sleep(5)--";
const result = detectSql(userInput);

console.log('User input:', userInput);
console.log('Is SQL Injection:', result.isSqlInjection);
console.log('Threat Level:', result.threatLevel);
console.log('Score:', result.score);
console.log();

// ============================================================================
// EXAMPLE 2: Express.js Middleware
// ============================================================================

console.log('=== Example 2: Express.js Middleware ===\n');

/**
 * Middleware to protect against SQL injection in query parameters
 * 
 * Usage:
 *   app.use(sqlInjectionGuard);
 *   
 *   // Or for specific routes:
 *   app.get('/api/search', sqlInjectionGuard, searchHandler);
 */
function sqlInjectionGuard(req, res, next) {
  // Check all query parameters
  for (const [key, value] of Object.entries(req.query || {})) {
    if (typeof value !== 'string') continue;
    
    const result = detectSql(value);
    
    if (result.isSqlInjection) {
      console.log(`[SECURITY] Blocked SQL injection attempt:`);
      console.log(`  IP: ${req.ip}`);
      console.log(`  Path: ${req.path}`);
      console.log(`  Param: ${key}`);
      console.log(`  Value: ${value}`);
      console.log(`  Threat: ${result.threatLevel}`);
      
      return res.status(400).json({
        error: 'Invalid input detected',
        code: 'INVALID_INPUT',
        // Don't reveal detection details to attacker
      });
    }
  }
  
  // Also check body parameters if JSON
  if (req.body && typeof req.body === 'object') {
    for (const [key, value] of Object.entries(req.body)) {
      if (typeof value !== 'string') continue;
      
      const result = detectSql(value);
      
      if (result.isSqlInjection) {
        return res.status(400).json({
          error: 'Invalid input detected',
          code: 'INVALID_INPUT',
        });
      }
    }
  }
  
  next();
}

// Simulate Express request/response
const mockReq = {
  ip: '192.168.1.1',
  path: '/api/search',
  query: { search: "'1'='1' OR pg_sleep(5)--" },
};
const mockRes = {
  status: (code) => ({
    json: (data) => console.log(`Response ${code}:`, data)
  })
};
const mockNext = () => console.log('✅ Request allowed to proceed');

sqlInjectionGuard(mockReq, mockRes, mockNext);
console.log();

// ============================================================================
// EXAMPLE 3: Direct Database Query Protection (with Drizzle/Prisma/etc)
// ============================================================================

console.log('=== Example 3: Before Database Query ===\n');

/**
 * Validate search input before using in database query
 */
function validateAndSearch(searchTerm) {
  // STEP 1: Check for SQL injection
  const check = detectSql(searchTerm);
  
  if (check.isSqlInjection) {
    throw new Error(`Potential SQL injection detected: ${check.threatLevel}`);
  }
  
  // STEP 2: Even if passed, always use parameterized queries!
  // This is your defense in depth
  
  // With Drizzle ORM (safe - parameterized):
  // const results = await db.query.prediction_event.findMany({
  //   where: ilike(prediction_event.title, `%${searchTerm}%`)
  // });
  
  // NEVER do this (vulnerable):
  // const results = await db.execute(`
  //   SELECT * FROM prediction_event 
  //   WHERE title ILIKE '%${searchTerm}%'
  // `);
  
  console.log(`✅ Search term "${searchTerm}" passed validation`);
  return { success: true };
}

// Test with safe input
try {
  validateAndSearch('bitcoin');
} catch (e) {
  console.log('❌', e.message);
}

// Test with malicious input (YOUR ATTACK)
try {
  validateAndSearch("test'||pg_sleep(1)||'");
} catch (e) {
  console.log('❌ Attack blocked:', e.message);
}
console.log();

// ============================================================================
// EXAMPLE 4: Detailed Logging for Security Analysis
// ============================================================================

console.log('=== Example 4: Security Logging ===\n');

function logSecurityEvent(userInput, ipAddress) {
  const analysis = explain(userInput);
  
  if (analysis.isSqlInjection) {
    const securityLog = {
      timestamp: new Date().toISOString(),
      event: 'SQL_INJECTION_ATTEMPT',
      severity: analysis.threatLevel,
      score: analysis.score,
      ip: ipAddress,
      input: userInput.substring(0, 100), // Truncate for logs
      patterns: analysis.tokens,
      findings: analysis.findings.map(f => ({
        pattern: f.pattern,
        matched: f.matches,
      })),
    };
    
    // In production: send to your logging service (Datadog, etc)
    console.log('Security Event:', JSON.stringify(securityLog, null, 2));
    
    return true; // Attack detected
  }
  
  return false; // Safe
}

logSecurityEvent("admin' OR '1'='1", '10.0.0.1');
console.log();

// ============================================================================
// EXAMPLE 5: Custom Threshold for Different Endpoints
// ============================================================================

console.log('=== Example 5: Custom Sensitivity ===\n');

// Public search - more permissive (threshold 8)
function publicSearch(query) {
  const result = detectSql(query, { threshold: 8 });
  return !result.isSqlInjection;
}

// Admin endpoint - strict mode (threshold 3)
function adminQuery(query) {
  const result = detectSql(query, { threshold: 3 });
  return !result.isSqlInjection;
}

console.log("Input: \"admin'\"");
console.log('  Public endpoint (threshold 8):', publicSearch("admin'") ? '✅ Allowed' : '❌ Blocked');
console.log('  Admin endpoint (threshold 3):', adminQuery("admin'") ? '✅ Allowed' : '❌ Blocked');
console.log();

// ============================================================================
// EXAMPLE 6: Hono.js / Elysia / Modern Frameworks
// ============================================================================

console.log('=== Example 6: Hono.js Usage ===\n');

console.log(`
// Hono.js middleware example:

import { Hono } from 'hono';
import { detectSql } from './sql-injection-detector-safe';

const app = new Hono();

// Middleware
app.use('*', async (c, next) => {
  const query = c.req.query();
  
  for (const [key, value] of Object.entries(query)) {
    if (typeof value === 'string') {
      const result = detectSql(value);
      if (result.isSqlInjection) {
        return c.json({ error: 'Invalid input' }, 400);
      }
    }
  }
  
  await next();
});

// Your endpoint
app.get('/api/search', async (c) => {
  const search = c.req.query('search');
  // Safe to use with parameterized query
  return c.json({ results: await searchDb(search) });
});
`);

// ============================================================================
// IMPORTANT REMINDER
// ============================================================================

console.log('═'.repeat(70));
console.log('⚠️  IMPORTANT: Defense in Depth');
console.log('═'.repeat(70));
console.log(`
This detector is a FIRST LINE of defense, but you should ALWAYS:

1. ✅ Use parameterized queries / prepared statements
   - Drizzle: db.query.table.findMany({ where: eq(col, value) })
   - Prisma: prisma.table.findMany({ where: { col: value } })
   - Raw SQL: db.execute(sql\`SELECT * FROM t WHERE c = \${value}\`)

2. ✅ Validate and sanitize input at the application layer
   - Type checking (is it a string? number? UUID?)
   - Length limits
   - Character whitelist for specific fields

3. ✅ Use least-privilege database users
   - Your app user shouldn't have DROP TABLE permissions

4. ✅ Log and monitor for attacks
   - Alert on repeated injection attempts from same IP
   - Block IPs with multiple failed attempts

The detector catches attacks BEFORE they reach your database,
but parameterized queries ensure safety even if something slips through.
`);

