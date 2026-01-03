import {
  BaseAnalyzer,
  type AnalyzerContext,
  type Finding,
} from '@xorng/template-validator';

/**
 * Input validation patterns
 */
interface ValidationPattern {
  name: string;
  pattern: RegExp;
  severity: Finding['severity'];
  message: string;
  suggestion: string;
}

/**
 * Patterns for detecting missing input validation
 */
const VALIDATION_PATTERNS: ValidationPattern[] = [
  // Express.js direct body access
  {
    name: 'unvalidated-body',
    pattern: /req\.body\.[a-zA-Z_]+(?!\s*(?:\?\.|&&|!==|===|!=|==|\|\||typeof))/g,
    severity: 'high',
    message: 'Accessing request body without validation',
    suggestion: 'Use a validation library like Zod, Joi, or express-validator to validate request body',
  },
  // Query parameter access
  {
    name: 'unvalidated-query',
    pattern: /req\.query\.[a-zA-Z_]+(?!\s*(?:\?\.|&&|!==|===|!=|==|\|\||typeof))/g,
    severity: 'high',
    message: 'Accessing query parameters without validation',
    suggestion: 'Validate and sanitize query parameters before use',
  },
  // URL parameter access
  {
    name: 'unvalidated-params',
    pattern: /req\.params\.[a-zA-Z_]+(?!\s*(?:\?\.|&&|!==|===|!=|==|\|\||typeof))/g,
    severity: 'medium',
    message: 'Accessing URL parameters without validation',
    suggestion: 'Validate URL parameters against expected format',
  },
  // Cookie access
  {
    name: 'unvalidated-cookies',
    pattern: /req\.cookies\.[a-zA-Z_]+(?!\s*(?:\?\.|&&|!==|===|!=|==|\|\||typeof))/g,
    severity: 'medium',
    message: 'Accessing cookies without validation',
    suggestion: 'Validate cookie values before use',
  },
  // Direct type coercion
  {
    name: 'unsafe-type-coercion',
    pattern: /parseInt\s*\(\s*(?:req\.|request\.)|Number\s*\(\s*(?:req\.|request\.)/g,
    severity: 'medium',
    message: 'Direct type coercion of user input',
    suggestion: 'Validate input before type coercion, handle NaN cases',
  },
  // Array index access
  {
    name: 'unvalidated-array-index',
    pattern: /\[\s*(?:req\.|request\.)[^[\]]*\]/g,
    severity: 'high',
    message: 'Using user input as array index without validation',
    suggestion: 'Validate array indices are within expected bounds',
  },
  // Object key access
  {
    name: 'unvalidated-object-key',
    pattern: /\[\s*(?:req\.|request\.body|query|params)[^[\]]*\]/g,
    severity: 'high',
    message: 'Using user input as object key without validation',
    suggestion: 'Whitelist allowed keys or use a schema validator',
  },
  // File uploads
  {
    name: 'unvalidated-file-upload',
    pattern: /req\.files?(?:\.[a-zA-Z_]+)?(?!\s*(?:\?\.|&&|!==|===|!=|==|\|\||\.mimetype|\.size))/g,
    severity: 'high',
    message: 'File upload without apparent validation',
    suggestion: 'Validate file type, size, and scan for malware before processing',
  },
  // Header access
  {
    name: 'unvalidated-headers',
    pattern: /req\.headers\[['"]/g,
    severity: 'low',
    message: 'Direct header access',
    suggestion: 'Validate header values if used in security-sensitive operations',
  },
];

/**
 * Analyzer for input validation issues
 */
export class InputValidationAnalyzer extends BaseAnalyzer {
  readonly name = 'input-validation';
  readonly description = 'Detects missing or inadequate input validation';

  async analyze(code: string, context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = code.split('\n');

    // Check if there's evidence of validation being used
    const hasValidationLib = this.hasValidationLibrary(code);

    for (const pattern of VALIDATION_PATTERNS) {
      pattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.pattern.exec(code)) !== null) {
        // If using a validation library, reduce severity
        const severity = hasValidationLib
          ? this.reduceSeverity(pattern.severity)
          : pattern.severity;

        // Find line number
        const beforeMatch = code.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;
        const line = lines[lineNumber - 1] || '';

        // Skip if line has validation-related code
        if (this.lineHasValidation(line)) {
          continue;
        }

        const lastNewline = beforeMatch.lastIndexOf('\n');
        const column = match.index - (lastNewline + 1);

        findings.push({
          id: crypto.randomUUID(),
          type: 'security',
          severity,
          message: pattern.message,
          file: context.filePath,
          line: lineNumber,
          column,
          code: line.trim(),
          suggestion: pattern.suggestion,
          rule: pattern.name,
        });

        if (!pattern.pattern.global) break;
      }
    }

    return findings;
  }

  private hasValidationLibrary(code: string): boolean {
    const validationIndicators = [
      /import.*(?:zod|joi|yup|express-validator|class-validator)/i,
      /require\s*\(\s*["'](?:zod|joi|yup|express-validator|class-validator)["']\)/i,
      /\.validate\s*\(/,
      /\.parse\s*\(/,
      /\.safeParse\s*\(/,
      /z\.\w+\s*\(\)/,
      /Joi\.\w+\s*\(\)/,
    ];

    return validationIndicators.some(pattern => pattern.test(code));
  }

  private lineHasValidation(line: string): boolean {
    const validationPatterns = [
      /validate/i,
      /schema/i,
      /\.parse\s*\(/,
      /\.safeParse\s*\(/,
      /typeof\s+/,
      /instanceof/,
      /isNaN/,
      /Number\.isFinite/,
      /Number\.isInteger/,
      /Array\.isArray/,
      /\?\./,  // Optional chaining
      /if\s*\(/,  // Conditional check
      /\|\|/,  // OR fallback
      /\?\?/,  // Nullish coalescing
    ];

    return validationPatterns.some(pattern => pattern.test(line));
  }

  private reduceSeverity(severity: Finding['severity']): Finding['severity'] {
    switch (severity) {
      case 'critical':
        return 'high';
      case 'high':
        return 'medium';
      case 'medium':
        return 'low';
      default:
        return 'info';
    }
  }
}
