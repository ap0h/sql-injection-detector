/**
 * SQL Injection Detector - Safe Pure JavaScript Implementation
 * 
 * A zero-dependency SQL injection detection library using regex-based
 * tokenization and rule-based scoring. No external processes, no pickle
 * deserialization, no supply chain risks.
 * 
 * @license MIT
 */

'use strict';

// Pattern weights for scoring (higher = more suspicious)
const PATTERN_WEIGHTS = {
  UNION: 12,        // UNION SELECT attacks
  DROP: 20,         // DROP TABLE/DATABASE (highest threat - always CRITICAL)
  INQUERY: 8,       // Subquery injection (SELECT in parentheses)
  DBNAME: 8,        // Database/schema enumeration
  DTCNAME: 7,       // table_name, column_name access
  FROMDB: 7,        // FROM dual/sysmaster/sysibm
  CASEWHEN: 6,      // CASE WHEN conditional injection
  CHRBYPASS: 6,     // CHAR() bypass techniques
  CAST: 5,          // CAST() type manipulation
  CONCAT: 5,        // String concatenation
  LIMIT: 4,         // LIMIT clause manipulation
  ORDERBY: 5,       // ORDER BY injection
  BOOLEAN: 4,       // Boolean-based injection
  PREFIX: 3,        // Quote/paren prefix attacks
  MYSQLFUNC: 5,     // MySQL function abuse (SLEEP, BENCHMARK)
  USUAL: 3,         // Common injection patterns
  NOTIN: 2,         // NOT IN clause
  GRPCONCAT: 2,     // GROUP_CONCAT
  DATABASE: 2,      // DATABASE() function
  COMMENT: 3,       // SQL comments
  HEX: 2,           // Hex encoding
  TAUTOLOGY: 5,     // Always-true conditions
  DANGEROUS_KEYWORD: 4, // Dangerous SQL keywords
  PGFUNC: 8,        // PostgreSQL dangerous functions (pg_sleep, pg_read_file)
  STRING_CONCAT_INJECT: 7, // String concatenation with function call
  QUOTE_COMMENT: 5, // Quote followed by comment (login bypass)
  PLAIN: 0,         // Plain text (not suspicious)
};

// Comprehensive SQL injection detection patterns
// Ported from the original Python regex with improvements
const SQL_PATTERNS = {
  // UNION-based injection
  UNION: /UNION\s+(ALL\s+)?SELECT/gi,
  
  // Stacked queries - DROP attacks
  DROP: /;\s*DROP\s+(TABLE|DATABASE)\s+(IF\s+EXISTS\s+)?\S+/gi,
  
  // Subquery injection
  INQUERY: /\(SELECT[^a-z_0-9]/gi,
  
  // Database/schema enumeration keywords
  DBNAME: /(?:m(?:s(?:ysaccessobjects|ysaces|ysobjects|ysqueries|ysrelationships|ysaccessstorage|ysaccessxml|ysmodules|ysmodules2|db)|aster\.\.sysdatabases|ysql\.db)|s(?:ys(?:\.database_name|aux)|chema(?:\W*\(|_name)|qlite(_temp)?_master)|d(?:atabas|b_nam)e\W*\(|information_schema|pg_(catalog|toast)|northwind|tempdb)/gi,
  
  // Table/column enumeration
  DTCNAME: /table_name|column_name|table_schema|schema_name/gi,
  
  // Database-specific FROM clauses
  FROMDB: /\sfrom\s(dual|sysmaster|sysibm)[\s.:]/gi,
  
  // CASE WHEN conditional injection
  CASEWHEN: /\(CASE\s(?:\d+\s|\(\d+=\d+\)\s|NULL\s)?WHEN\s(?:\d+|\(?\d+=\d+\)?|NULL)\sTHEN\s(?:\d+|\(\d+=\d+\)|NULL)\sELSE/gi,
  
  // CHAR/CHR bypass techniques
  CHRBYPASS: /(?:(?:CHA?R\(\d+\)(?:,|\|\||\+)\s?)+)|CHA?R\((?:\d+,\s?)+\d*\)/gi,
  
  // CAST type manipulation
  CAST: /CAST\(.*?AS\s+\w+\)/gi,
  
  // String concatenation
  CONCAT: /CONCAT\s*\([^)]*\)/gi,
  
  // LIMIT clause manipulation
  LIMIT: /LIMIT\s+\d+(?:\s*,\s*\d+)?/gi,
  
  // ORDER BY injection (for column enumeration)
  ORDERBY: /ORDER\s+BY\s+\d+(?:\s*(?:--|#|ASC|DESC))?/gi,
  
  // Boolean-based injection
  BOOLEAN: /['"]?\s*-?\d+\s*['"]?\s*(?:=|LIKE|<|>|<=|>=)\s*['"]?\s*-?\d+\s*['"]?(?:$|\s|\)|,|--|#)|['"]\S+['"]\s*(?:=|LIKE)\s*['"]\S+['"]/gi,
  
  // Prefix-based injection (quote/paren manipulation)
  PREFIX: /(?:['")]|(?:['")]|\d+|\w+)\s)(?:\|\||\&\&|and|or|as|where|IN\sBOOLEAN\sMODE)(?:\s|\()/gi,
  
  // Common injection patterns
  USUAL: /['"]\s*(?:\|\||\&\&|and|or)\s*['"]\s*['"]=/gi,
  
  // NOT IN clause
  NOTIN: /\snot\sin\s?\((?:\d+|['"]?\w+['"]?)\)/gi,
  
  // GROUP_CONCAT
  GRPCONCAT: /GROUP_CONCAT\s*\([^)]*\)/gi,
  
  // DATABASE() function
  DATABASE: /DATABASE\s*\(\s*\)/gi,
  
  // Dangerous MySQL functions (time-based, file access, etc.)
  MYSQLFUNC: /(?:SLEEP|BENCHMARK|LOAD_FILE|INTO\s+(?:OUT|DUMP)FILE|EXTRACTVALUE|UPDATEXML)\s*\(/gi,
  
  // PostgreSQL-specific dangerous functions
  PGFUNC: /(?:pg_sleep|pg_read_file|pg_ls_dir|pg_read_binary_file|pg_stat_file|lo_import|lo_export|pg_largeobject|pg_catalog|current_setting|set_config)\s*\(/gi,
  
  // String concatenation injection (PostgreSQL uses ||, MSSQL uses +)
  STRING_CONCAT_INJECT: /['"][^'"]*['"]\s*\|\|\s*\w+\s*\(/gi,
  
  // Comment injection (includes unclosed comments - common bypass technique)
  COMMENT: /(?:--(?:\s|$)|#(?:\s|$)|\/\*(?:.*?\*\/)?)/g,
  
  // Hex encoding bypass
  HEX: /0x[0-9a-fA-F]+/g,
  
  // Tautology (always true conditions)
  TAUTOLOGY: /(?:['"]?\s*(?:OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?)|(?:OR\s+['"]['"]\s*=\s*['"]['"'])/gi,
  
  // NULL byte injection
  NULLBYTE: /%00|\\x00|\\0/g,
  
  // Whitespace bypass
  WHITESPACE_BYPASS: /(?:\/\*.*?\*\/|\+|%20|%09|%0a|%0d)+(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP|FROM|WHERE)/gi,
  
  // Quote followed by comment (login bypass pattern)
  QUOTE_COMMENT: /['"](?:\s*--|\s*#|\s*\/\*)/g,
};

// Additional dangerous keywords that increase suspicion
const DANGEROUS_KEYWORDS = [
  'EXEC', 'EXECUTE', 'XP_', 'SP_', 'DECLARE', 'WAITFOR', 'DELAY',
  'SHUTDOWN', 'BACKUP', 'RESTORE', 'GRANT', 'REVOKE', 'TRUNCATE',
  'ALTER', 'CREATE', 'INSERT', 'UPDATE', 'DELETE', 'MERGE',
  'OPENROWSET', 'OPENDATASOURCE', 'BULK', 'CMDSHELL',
];

/**
 * Calculate Shannon entropy of a string
 * Higher entropy can indicate obfuscated/encoded payloads
 * @param {string} str - Input string
 * @returns {number} Entropy value
 */
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  
  const len = str.length;
  const frequencies = {};
  
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

/**
 * Tokenize input string and detect SQL injection patterns
 * @param {string} input - The string to analyze
 * @returns {Object} Token analysis results
 */
function tokenize(input) {
  const tokens = [];
  const matches = {};
  
  // Pre-process: detect and remove SQL comments
  let processed = input;
  
  // Match complete multi-line comments
  const completeComments = processed.match(/\/\*[\s\S]*?\*\//g) || [];
  processed = processed.replace(/\/\*[\s\S]*?\*\//g, ' ');
  
  // Match MySQL version comments /*!num */
  const inlineComments = processed.match(/\/\*!\d+/g) || [];
  processed = processed.replace(/\/\*!\d+|\*\//g, ' ');
  
  // Match unclosed comments (injection attempt)
  const unclosedComments = processed.match(/\/\*(?![^*]*\*\/)/g) || [];
  
  // Match line comments (-- or #)
  const lineComments = processed.match(/(?:--\s.*|#\s.*|--$|#$)/g) || [];
  
  const allComments = [...completeComments, ...inlineComments, ...unclosedComments, ...lineComments];
  if (allComments.length > 0) {
    tokens.push('COMMENT');
    matches.COMMENT = allComments;
  }
  
  // Check each pattern
  for (const [patternName, regex] of Object.entries(SQL_PATTERNS)) {
    if (patternName === 'COMMENT') continue; // Already handled
    
    const patternMatches = processed.match(regex);
    if (patternMatches && patternMatches.length > 0) {
      tokens.push(patternName);
      matches[patternName] = patternMatches;
    }
  }
  
  // Check for dangerous keywords
  const upperInput = processed.toUpperCase();
  const foundKeywords = DANGEROUS_KEYWORDS.filter(kw => 
    upperInput.includes(kw)
  );
  
  if (foundKeywords.length > 0) {
    tokens.push('DANGEROUS_KEYWORD');
    matches.DANGEROUS_KEYWORD = foundKeywords;
  }
  
  // If no suspicious tokens found, mark as plain
  if (tokens.length === 0) {
    tokens.push('PLAIN');
  }
  
  return { tokens, matches, processed };
}

/**
 * Calculate risk score based on detected patterns
 * @param {string[]} tokens - Detected pattern tokens
 * @param {Object} matches - Pattern match details
 * @param {string} input - Original input
 * @returns {Object} Score details
 */
function calculateScore(tokens, matches, input) {
  let score = 0;
  const breakdown = {};
  
  for (const token of tokens) {
    const weight = PATTERN_WEIGHTS[token] ?? 0; // Default to 0 for unknown/PLAIN
    if (weight === 0) continue; // Skip non-suspicious tokens
    
    const matchCount = matches[token]?.length || 1;
    const tokenScore = weight * Math.min(matchCount, 3); // Cap multiplier at 3
    
    score += tokenScore;
    breakdown[token] = tokenScore;
  }
  
  // Entropy bonus (high entropy might indicate encoding/obfuscation)
  const entropy = calculateEntropy(input);
  if (entropy > 5.5) {
    score += 2;
    breakdown.HIGH_ENTROPY = 2;
  }
  
  // Length-based adjustment (very long inputs are more suspicious)
  if (input.length > 500) {
    score += 1;
    breakdown.LONG_INPUT = 1;
  }
  
  // Multiple pattern combination bonus (attackers often chain techniques)
  if (tokens.length > 3) {
    const bonus = Math.min(tokens.length - 3, 5);
    score += bonus;
    breakdown.PATTERN_COMBINATION = bonus;
  }
  
  return { score, breakdown, entropy };
}

/**
 * Determine threat level based on score
 * @param {number} score - Calculated risk score
 * @returns {string} Threat level
 */
function getThreatLevel(score) {
  if (score === 0) return 'SAFE';
  if (score < 5) return 'LOW';
  if (score < 10) return 'MEDIUM';
  if (score < 20) return 'HIGH';
  return 'CRITICAL';
}

/**
 * Main detection function
 * @param {string} input - The SQL string or user input to analyze
 * @param {Object} options - Detection options
 * @param {number} options.threshold - Score threshold for detection (default: 5)
 * @param {boolean} options.detailed - Return detailed analysis (default: false)
 * @returns {Object} Detection result
 */
function detectSql(input, options = {}) {
  const { threshold = 5, detailed = false } = options;
  
  // Input validation
  if (typeof input !== 'string') {
    return {
      isSqlInjection: false,
      error: 'Input must be a string',
    };
  }
  
  if (input.length === 0) {
    return {
      isSqlInjection: false,
      score: 0,
      threatLevel: 'SAFE',
    };
  }
  
  // Tokenize and analyze
  const { tokens, matches, processed } = tokenize(input);
  const { score, breakdown, entropy } = calculateScore(tokens, matches, input);
  const threatLevel = getThreatLevel(score);
  const isSqlInjection = score >= threshold;
  
  const result = {
    isSqlInjection,
    score,
    threatLevel,
    tokens,
  };
  
  if (detailed) {
    result.details = {
      matches,
      breakdown,
      entropy: entropy.toFixed(3),
      inputLength: input.length,
      processedInput: processed.substring(0, 200) + (processed.length > 200 ? '...' : ''),
    };
  }
  
  return result;
}

/**
 * Quick check - returns boolean only (compatible with original API)
 * @param {string} input - Input to check
 * @returns {Promise<Object>} Detection result (Promise for API compatibility)
 */
async function detectSqlAsync(input) {
  const result = detectSql(input);
  return {
    success: !result.isSqlInjection,
    isSqlInjection: result.isSqlInjection,
    score: result.score,
    threatLevel: result.threatLevel,
  };
}

/**
 * Sanitize input by escaping dangerous characters
 * Note: This is a basic sanitization - always use parameterized queries!
 * @param {string} input - Input to sanitize
 * @returns {string} Sanitized input
 */
function sanitize(input) {
  if (typeof input !== 'string') return '';
  
  return input
    .replace(/'/g, "''")
    .replace(/\\/g, '\\\\')
    .replace(/\x00/g, '')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\x1a/g, '\\Z');
}

/**
 * Validate and explain why input is flagged
 * @param {string} input - Input to analyze
 * @returns {Object} Detailed explanation
 */
function explain(input) {
  const result = detectSql(input, { detailed: true });
  
  const explanations = {
    UNION: 'UNION-based injection attempt - trying to combine queries',
    DROP: 'Destructive SQL command detected (DROP TABLE/DATABASE)',
    INQUERY: 'Subquery injection - SELECT statement in unexpected location',
    DBNAME: 'Database enumeration attempt - accessing system tables',
    DTCNAME: 'Schema enumeration - querying table/column names',
    FROMDB: 'Accessing database-specific system tables',
    CASEWHEN: 'Conditional injection using CASE WHEN',
    CHRBYPASS: 'Character encoding bypass technique (CHAR/CHR)',
    CAST: 'Type casting manipulation',
    CONCAT: 'String concatenation (may indicate payload building)',
    LIMIT: 'LIMIT clause manipulation',
    ORDERBY: 'ORDER BY injection (column enumeration)',
    BOOLEAN: 'Boolean-based injection pattern',
    PREFIX: 'Quote/parenthesis manipulation attack',
    USUAL: 'Common SQL injection pattern',
    MYSQLFUNC: 'Dangerous MySQL function (SLEEP, BENCHMARK, LOAD_FILE)',
    PGFUNC: 'Dangerous PostgreSQL function (pg_sleep, pg_read_file, lo_import)',
    STRING_CONCAT_INJECT: 'String concatenation with function call - common PostgreSQL/MSSQL injection',
    QUOTE_COMMENT: 'Quote followed by comment - classic login bypass pattern',
    COMMENT: 'SQL comment injection (may bypass filters)',
    TAUTOLOGY: 'Tautology attack (always-true condition)',
    HEX: 'Hexadecimal encoding (obfuscation technique)',
    WHITESPACE_BYPASS: 'Whitespace bypass technique',
    DANGEROUS_KEYWORD: 'Dangerous SQL keyword detected',
    HIGH_ENTROPY: 'High entropy suggests encoded/obfuscated payload',
    LONG_INPUT: 'Unusually long input',
    PATTERN_COMBINATION: 'Multiple attack patterns combined',
  };
  
  const findings = [];
  for (const token of result.tokens) {
    if (explanations[token]) {
      findings.push({
        pattern: token,
        explanation: explanations[token],
        matches: result.details?.matches[token] || [],
      });
    }
  }
  
  return {
    ...result,
    findings,
    recommendation: result.isSqlInjection 
      ? 'BLOCK this input - high likelihood of SQL injection attack'
      : 'Input appears safe, but always use parameterized queries',
  };
}

// Export public API
module.exports = {
  detectSql,
  detectSqlAsync,  // Promise-based for compatibility with original API
  sanitize,
  explain,
  calculateEntropy,
  
  // Constants for customization
  PATTERN_WEIGHTS,
  SQL_PATTERNS,
  DANGEROUS_KEYWORDS,
};

