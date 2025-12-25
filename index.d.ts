/**
 * SQL Injection Detector - TypeScript Definitions
 */

export interface DetectionResult {
  isSqlInjection: boolean;
  score: number;
  threatLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  tokens: string[];
  error?: string;
  details?: {
    matches: Record<string, string[]>;
    breakdown: Record<string, number>;
    entropy: string;
    inputLength: number;
    processedInput: string;
  };
}

export interface DetectionOptions {
  /** Score threshold for detection (default: 5) */
  threshold?: number;
  /** Return detailed analysis (default: false) */
  detailed?: boolean;
}

export interface AsyncDetectionResult {
  success: boolean;
  isSqlInjection: boolean;
  score: number;
  threatLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface Finding {
  pattern: string;
  explanation: string;
  matches: string[];
}

export interface ExplainResult extends DetectionResult {
  findings: Finding[];
  recommendation: string;
}

/**
 * Main detection function
 * @param input - The SQL string or user input to analyze
 * @param options - Detection options
 * @returns Detection result
 */
export function detectSql(input: string, options?: DetectionOptions): DetectionResult;

/**
 * Async detection for API compatibility with original library
 * @param input - Input to check
 * @returns Promise with detection result
 */
export function detectSqlAsync(input: string): Promise<AsyncDetectionResult>;

/**
 * Sanitize input by escaping dangerous characters
 * Note: Always prefer parameterized queries over sanitization!
 * @param input - Input to sanitize
 * @returns Sanitized input
 */
export function sanitize(input: string): string;

/**
 * Detailed analysis with explanations
 * @param input - Input to analyze
 * @returns Detailed explanation of findings
 */
export function explain(input: string): ExplainResult;

/**
 * Calculate Shannon entropy of a string
 * @param str - Input string
 * @returns Entropy value
 */
export function calculateEntropy(str: string): number;

/** Pattern weights for scoring */
export const PATTERN_WEIGHTS: Record<string, number>;

/** SQL injection detection patterns */
export const SQL_PATTERNS: Record<string, RegExp>;

/** Dangerous SQL keywords */
export const DANGEROUS_KEYWORDS: string[];

