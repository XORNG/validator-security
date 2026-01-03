import {
  BaseAnalyzer,
  type AnalyzerContext,
  type AnalyzerResult,
  type Finding,
  type ValidationInput,
  type Severity,
} from '@xorng/template-validator';

/**
 * Validation pattern interface
 */
interface ValidationPattern {
  name: string;
  pattern: RegExp;
  message: string;
  suggestion: string;
  severity: Severity;
}

/**
 * Patterns for detecting missing input validation
 */
const VALIDATION_PATTERNS: ValidationPattern[] = [
  {
    name: 'unvalidated-body',
    pattern: /req\.body\.[A-Za-z_$][A-Za-z0-9_$]*/g,
    message: 'Potentially unvalidated request body access',
    suggestion: 'Validate and sanitize request body using a validation library like Zod or Joi',
    severity: 'high',
  },
  {
    name: 'unvalidated-params',
    pattern: /req\.params\.[A-Za-z_$][A-Za-z0-9_$]*/g,
    message: 'Potentially unvalidated URL parameter access',
    suggestion: 'Validate URL parameters before use',
    severity: 'high',
  },
  {
    name: 'unvalidated-query',
    pattern: /req\.query\.[A-Za-z_$][A-Za-z0-9_$]*/g,
    message: 'Potentially unvalidated query string access',
    suggestion: 'Validate and sanitize query parameters',
    severity: 'medium',
  },
  {
    name: 'unvalidated-headers',
    pattern: /req\.headers\[['"]/g,
    message: 'Potentially unvalidated header access',
    suggestion: 'Validate headers especially for security-sensitive operations',
    severity: 'medium',
  },
  {
    name: 'unvalidated-cookies',
    pattern: /req\.cookies\.[A-Za-z_$][A-Za-z0-9_$]*/g,
    message: 'Potentially unvalidated cookie access',
    suggestion: 'Validate cookies and use signed cookies for security',
    severity: 'medium',
  },
  {
    name: 'direct-json-parse',
    pattern: /JSON\.parse\s*\(\s*(?:req\.|body|input)/gi,
    message: 'Direct JSON.parse on user input without validation',
    suggestion: 'Wrap in try-catch and validate the parsed structure',
    severity: 'high',
  },
  {
    name: 'parseInt-no-radix',
    pattern: /parseInt\s*\([^)]+\)(?!\s*,\s*10)/g,
    message: 'parseInt without explicit radix parameter',
    suggestion: 'Always use parseInt(value, 10) to avoid unexpected behavior',
    severity: 'high',
  },
  {
    name: 'type-coercion',
    pattern: /==\s*(?:null|undefined|['"]['"]\s*==)/g,
    message: 'Loose equality comparison may lead to type confusion',
    suggestion: 'Use strict equality (===) for type-safe comparisons',
    severity: 'low',
  },
];

/**
 * Analyzer for input validation issues
 */
export class InputValidationAnalyzer extends BaseAnalyzer {
  constructor() {
    super(
      'input-validation',
      'Detects missing or inadequate input validation',
      'security',
      'medium'
    );
  }

  async analyze(input: ValidationInput, context: AnalyzerContext): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const lines = input.content.split('\n');
    const filename = input.filename || '';

    // Check if there's evidence of validation being used
    const hasValidationLib = this.hasValidationLibrary(input.content);

    for (const pattern of VALIDATION_PATTERNS) {
      pattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.pattern.exec(input.content)) !== null) {
        // If using a validation library, reduce severity
        const severity = hasValidationLib
          ? this.reduceSeverity(pattern.severity)
          : pattern.severity;

        // Find line number
        const beforeMatch = input.content.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;
        const line = lines[lineNumber - 1] || '';

        // Skip if line has validation-related code
        if (this.lineHasValidation(line)) {
          continue;
        }

        const lastNewline = beforeMatch.lastIndexOf('\n');
        const column = match.index - (lastNewline + 1);

        findings.push(this.createFinding(
          pattern.name,
          pattern.message,
          {
            severity,
            file: filename,
            line: lineNumber,
            column,
            code: line.trim(),
            suggestion: pattern.suggestion,
            type: 'security',
          }
        ));

        if (!pattern.pattern.global) break;
      }
    }

    return { findings };
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

  private reduceSeverity(severity: Severity): Severity {
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
