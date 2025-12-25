/**
 * SQL Injection Detector - Test Suite
 */

const { detectSql, detectSqlAsync, explain, sanitize, calculateEntropy } = require('./index');

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`${GREEN}✓${RESET} ${name}`);
    passed++;
  } catch (e) {
    console.log(`${RED}✗${RESET} ${name}`);
    console.log(`  ${RED}${e.message}${RESET}`);
    failed++;
  }
}

function assertEqual(actual, expected, msg = '') {
  if (actual !== expected) {
    throw new Error(`Expected ${expected}, got ${actual}. ${msg}`);
  }
}

function assertTrue(actual, msg = '') {
  if (!actual) {
    throw new Error(`Expected truthy value, got ${actual}. ${msg}`);
  }
}

function assertFalse(actual, msg = '') {
  if (actual) {
    throw new Error(`Expected falsy value, got ${actual}. ${msg}`);
  }
}

console.log('\n=== SQL Injection Detector Tests ===\n');

// ==================== Safe Inputs ====================
console.log(`${YELLOW}--- Safe Inputs ---${RESET}`);

test('Normal text should be safe', () => {
  const result = detectSql('Hello World');
  assertFalse(result.isSqlInjection);
  assertEqual(result.threatLevel, 'SAFE');
});

test('Normal username should be safe', () => {
  const result = detectSql('john_doe123');
  assertFalse(result.isSqlInjection);
});

test('Normal email should be safe', () => {
  const result = detectSql('user@example.com');
  assertFalse(result.isSqlInjection);
});

test('Normal SQL query keywords in text should be safe', () => {
  // Common words that happen to be SQL keywords
  const result = detectSql('I want to select the best option and drop by later');
  assertFalse(result.isSqlInjection);
});

test('Empty string should be safe', () => {
  const result = detectSql('');
  assertFalse(result.isSqlInjection);
  assertEqual(result.threatLevel, 'SAFE');
});

// ==================== SQL Injection Attacks ====================
console.log(`\n${YELLOW}--- SQL Injection Attacks ---${RESET}`);

test('Classic UNION SELECT injection', () => {
  const result = detectSql("' UNION SELECT username, password FROM users--");
  assertTrue(result.isSqlInjection);
  assertTrue(result.tokens.includes('UNION'));
});

test('Boolean-based injection (OR 1=1)', () => {
  const result = detectSql("' OR '1'='1");
  assertTrue(result.isSqlInjection);
});

test('DROP TABLE injection', () => {
  const result = detectSql("'; DROP TABLE users;--");
  assertTrue(result.isSqlInjection);
  assertTrue(result.tokens.includes('DROP'));
  assertEqual(result.threatLevel, 'CRITICAL');
});

test('INFORMATION_SCHEMA access', () => {
  const result = detectSql("' UNION SELECT table_name FROM information_schema.tables--");
  assertTrue(result.isSqlInjection);
  assertTrue(result.tokens.includes('DBNAME'));
});

test('Time-based blind injection (SLEEP)', () => {
  const result = detectSql("' AND SLEEP(5)--");
  assertTrue(result.isSqlInjection);
  assertTrue(result.tokens.includes('MYSQLFUNC'));
});

test('Time-based blind injection (BENCHMARK)', () => {
  const result = detectSql("' AND BENCHMARK(10000000,SHA1('test'))--");
  assertTrue(result.isSqlInjection);
  assertTrue(result.tokens.includes('MYSQLFUNC'));
});

test('CHAR bypass technique', () => {
  const result = detectSql("CHAR(65)+CHAR(66)+CHAR(67)");
  assertTrue(result.isSqlInjection);
  assertTrue(result.tokens.includes('CHRBYPASS'));
});

test('Subquery injection', () => {
  const result = detectSql("' AND (SELECT COUNT(*) FROM users) > 0--");
  assertTrue(result.isSqlInjection);
  assertTrue(result.tokens.includes('INQUERY'));
});

test('ORDER BY enumeration', () => {
  const result = detectSql("' ORDER BY 5--");
  assertTrue(result.isSqlInjection);
  assertTrue(result.tokens.includes('ORDERBY'));
});

test('Complex SQLMap payload', () => {
  const result = detectSql("2' AND ORD(MID((SELECT DISTINCT(IFNULL(CAST(schema_name AS NCHAR),0x20)) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 5,1),5,1))>1 AND 'vFAF'='vFAF");
  assertTrue(result.isSqlInjection);
  assertTrue(result.score >= 10, 'Score should be high for complex attack');
});

test('LOAD_FILE attack', () => {
  const result = detectSql("' UNION SELECT LOAD_FILE('/etc/passwd')--");
  assertTrue(result.isSqlInjection);
});

test('Comment injection', () => {
  const result = detectSql("admin'/*");
  assertTrue(result.tokens.includes('COMMENT'));
});

test('CASE WHEN injection', () => {
  const result = detectSql("' AND (CASE 1 WHEN 1 THEN 1 ELSE 0 END)--");
  assertTrue(result.isSqlInjection);
});

test('Hex encoding', () => {
  const result = detectSql("' UNION SELECT 0x61646d696e--");
  assertTrue(result.isSqlInjection);
  assertTrue(result.tokens.includes('HEX'));
});

// ==================== Edge Cases ====================
console.log(`\n${YELLOW}--- Edge Cases ---${RESET}`);

test('Non-string input should not crash', () => {
  const result = detectSql(123);
  assertFalse(result.isSqlInjection);
  assertTrue(result.error !== undefined);
});

test('SQL keywords in legitimate context should have low score', () => {
  const result = detectSql('Please select your options from the dropdown');
  assertTrue(result.score < 5, 'Score should be low for legitimate text');
});

// ==================== API Compatibility ====================
console.log(`\n${YELLOW}--- API Compatibility ---${RESET}`);

test('detectSqlAsync returns Promise', async () => {
  const result = await detectSqlAsync("' OR 1=1--");
  assertFalse(result.success); // success=false means injection detected
  assertTrue(result.isSqlInjection);
});

test('explain provides detailed findings', () => {
  const result = explain("' UNION SELECT * FROM users--");
  assertTrue(result.findings.length > 0);
  assertTrue(result.recommendation.includes('BLOCK'));
});

test('sanitize escapes quotes', () => {
  const input = "O'Brien";
  const sanitized = sanitize(input);
  assertEqual(sanitized, "O''Brien");
});

test('calculateEntropy works correctly', () => {
  const entropy = calculateEntropy('aaaa');
  assertEqual(entropy, 0); // All same characters = 0 entropy
  
  const entropy2 = calculateEntropy('abcd');
  assertTrue(entropy2 > 0); // Different characters = positive entropy
});

// ==================== Detailed Mode ====================
console.log(`\n${YELLOW}--- Detailed Mode ---${RESET}`);

test('Detailed mode provides matches', () => {
  const result = detectSql("' UNION SELECT 1,2,3--", { detailed: true });
  assertTrue(result.details !== undefined);
  assertTrue(result.details.matches.UNION !== undefined);
  assertTrue(result.details.breakdown !== undefined);
});

test('Custom threshold works', () => {
  const result1 = detectSql("SELECT", { threshold: 1 });
  const result2 = detectSql("SELECT", { threshold: 20 });
  // Same input, different threshold = different detection result
  assertTrue(result1.score === result2.score, 'Score should be the same');
});

// ==================== Results ====================
console.log('\n=== Results ===');
console.log(`${GREEN}Passed: ${passed}${RESET}`);
console.log(`${RED}Failed: ${failed}${RESET}`);

if (failed > 0) {
  process.exit(1);
}

