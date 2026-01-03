import {
  BaseAnalyzer,
  type AnalyzerContext,
  type Finding,
} from '@xorng/template-validator';

/**
 * Sensitive data patterns
 */
interface SensitivePattern {
  name: string;
  pattern: RegExp;
  message: string;
}

/**
 * Patterns for detecting secrets
 */
const SECRET_PATTERNS: SensitivePattern[] = [
  // API Keys
  {
    name: 'aws-access-key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    message: 'AWS Access Key ID detected',
  },
  {
    name: 'aws-secret-key',
    pattern: /(?:aws)?_?(?:secret)?_?(?:access)?_?key\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/gi,
    message: 'AWS Secret Access Key detected',
  },
  {
    name: 'github-token',
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
    message: 'GitHub token detected',
  },
  {
    name: 'npm-token',
    pattern: /npm_[A-Za-z0-9]{36}/g,
    message: 'NPM token detected',
  },
  {
    name: 'slack-token',
    pattern: /xox[baprs]-[0-9A-Za-z-]{10,}/g,
    message: 'Slack token detected',
  },
  {
    name: 'stripe-key',
    pattern: /(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}/g,
    message: 'Stripe API key detected',
  },
  {
    name: 'google-api-key',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    message: 'Google API key detected',
  },
  {
    name: 'twilio-key',
    pattern: /SK[0-9a-fA-F]{32}/g,
    message: 'Twilio API key detected',
  },
  {
    name: 'sendgrid-key',
    pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    message: 'SendGrid API key detected',
  },
  {
    name: 'mailchimp-key',
    pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    message: 'Mailchimp API key detected',
  },
  // Private Keys
  {
    name: 'private-key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    message: 'Private key detected',
  },
  // Database URLs
  {
    name: 'database-url',
    pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+:[^\s"'@]+@/gi,
    message: 'Database connection string with credentials detected',
  },
  // Generic secrets
  {
    name: 'jwt-token',
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    message: 'JWT token detected',
  },
  {
    name: 'generic-secret',
    pattern: /(?:secret|password|passwd|pwd|token|auth|apikey|api_key)["']?\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']/gi,
    message: 'Potential secret or credential detected',
  },
  // Email addresses (for PII detection)
  {
    name: 'email-hardcoded',
    pattern: /["'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["']/g,
    message: 'Hardcoded email address detected',
  },
];

/**
 * Analyzer for detecting secrets and sensitive data
 */
export class SecretsAnalyzer extends BaseAnalyzer {
  readonly name = 'secrets';
  readonly description = 'Detects hardcoded secrets and sensitive data';

  private patterns: SensitivePattern[];
  private skipFiles: RegExp[];

  constructor(options?: {
    customPatterns?: SensitivePattern[];
    skipFiles?: RegExp[];
  }) {
    super();
    this.patterns = options?.customPatterns || SECRET_PATTERNS;
    this.skipFiles = options?.skipFiles || [
      /\.test\./,
      /\.spec\./,
      /test\//,
      /tests\//,
      /__tests__\//,
      /\.example$/,
      /\.sample$/,
    ];
  }

  async analyze(code: string, context: AnalyzerContext): Promise<Finding[]> {
    // Skip test files and examples
    if (this.shouldSkip(context.filePath)) {
      return [];
    }

    const findings: Finding[] = [];
    const lines = code.split('\n');

    for (const pattern of this.patterns) {
      pattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.pattern.exec(code)) !== null) {
        // Find line number
        const beforeMatch = code.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;
        const line = lines[lineNumber - 1] || '';

        // Skip if it looks like a placeholder
        if (this.isPlaceholder(match[0])) {
          continue;
        }

        // Find column
        const lastNewline = beforeMatch.lastIndexOf('\n');
        const column = match.index - (lastNewline + 1);

        // Redact the actual secret in the output
        const redactedMatch = this.redact(match[0]);

        findings.push({
          id: crypto.randomUUID(),
          type: 'security',
          severity: 'critical',
          message: pattern.message,
          file: context.filePath,
          line: lineNumber,
          column,
          code: this.redactLine(line.trim()),
          suggestion: 'Remove this secret and use environment variables or a secure secrets manager',
          rule: `secret-${pattern.name}`,
          metadata: {
            secretType: pattern.name,
            redactedValue: redactedMatch,
          },
        });

        // Prevent infinite loops
        if (!pattern.pattern.global) break;
      }
    }

    return findings;
  }

  private shouldSkip(filePath: string): boolean {
    return this.skipFiles.some(pattern => pattern.test(filePath));
  }

  private isPlaceholder(value: string): boolean {
    const placeholders = [
      /xxx+/i,
      /your[_-]?(?:api[_-]?)?key/i,
      /replace[_-]?(?:this|me)/i,
      /placeholder/i,
      /example/i,
      /sample/i,
      /dummy/i,
      /test/i,
      /<.*>/,
      /\$\{.*\}/,
      /\{\{.*\}\}/,
    ];

    return placeholders.some(p => p.test(value));
  }

  private redact(value: string): string {
    if (value.length <= 8) {
      return '*'.repeat(value.length);
    }
    return value.substring(0, 4) + '****' + value.substring(value.length - 4);
  }

  private redactLine(line: string): string {
    // Redact anything that looks like a secret value
    return line.replace(
      /(?<=[:=]\s*["'])[A-Za-z0-9+/=_-]{16,}(?=["'])/g,
      (match) => this.redact(match)
    );
  }
}
