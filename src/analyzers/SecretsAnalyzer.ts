import {
  BaseAnalyzer,
  type AnalyzerContext,
  type AnalyzerResult,
  type Finding,
  type ValidationInput,
} from '@xorng/template-validator';

/**
 * Sensitive pattern interface
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
  {
    name: 'aws-access-key',
    pattern: /(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}/g,
    message: 'Potential AWS Access Key ID detected',
  },
  {
    name: 'aws-secret-key',
    pattern: /(?:aws)?[_-]?(?:secret)?[_-]?(?:access)?[_-]?key['"]*\s*[:=]\s*['"]\s*[A-Za-z0-9/+=]{40}/gi,
    message: 'Potential AWS Secret Access Key detected',
  },
  {
    name: 'github-token',
    pattern: /ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/g,
    message: 'Potential GitHub personal access token detected',
  },
  {
    name: 'generic-api-key',
    pattern: /['"]?(?:api[_-]?key|apikey|api_secret)['"]*\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/gi,
    message: 'Potential API key detected',
  },
  {
    name: 'private-key',
    pattern: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PRIVATE)\s+PRIVATE\s+KEY-----/gi,
    message: 'Private key detected',
  },
  {
    name: 'jwt-token',
    pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    message: 'Potential JWT token detected',
  },
  {
    name: 'slack-webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g,
    message: 'Slack webhook URL detected',
  },
  {
    name: 'stripe-key',
    pattern: /sk_live_[A-Za-z0-9]{24,}/g,
    message: 'Stripe live secret key detected',
  },
  {
    name: 'google-api-key',
    pattern: /AIza[A-Za-z0-9_\\-]{35}/g,
    message: 'Google API key detected',
  },
  {
    name: 'heroku-api-key',
    pattern: /heroku[_-]?api[_-]?key['"]?\s*[:=]\s*['"][A-Fa-f0-9-]{36}['"]/gi,
    message: 'Heroku API key detected',
  },
  {
    name: 'twilio-key',
    pattern: /SK[A-Fa-f0-9]{32}/g,
    message: 'Twilio API key detected',
  },
  {
    name: 'sendgrid-key',
    pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    message: 'SendGrid API key detected',
  },
  {
    name: 'database-url',
    pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@/gi,
    message: 'Database connection string with credentials detected',
  },
  {
    name: 'password-assignment',
    pattern: /(?:password|passwd|pwd|secret)['"]*\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    message: 'Potential hardcoded password detected',
  },
];

/**
 * Analyzer for detecting secrets and sensitive data
 */
export class SecretsAnalyzer extends BaseAnalyzer {
  private patterns: SensitivePattern[];
  private skipFiles: RegExp[];

  constructor(options?: {
    customPatterns?: SensitivePattern[];
    skipFiles?: RegExp[];
  }) {
    super(
      'secrets',
      'Detects hardcoded secrets and sensitive data',
      'security',
      'critical'
    );
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

  async analyze(input: ValidationInput, context: AnalyzerContext): Promise<AnalyzerResult> {
    const filename = input.filename || '';
    
    // Skip test files and examples
    if (this.shouldSkip(filename)) {
      return { findings: [] };
    }

    const findings: Finding[] = [];
    const lines = input.content.split('\n');

    for (const pattern of this.patterns) {
      pattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.pattern.exec(input.content)) !== null) {
        // Find line number
        const beforeMatch = input.content.substring(0, match.index);
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

  createFinding(data: any) {
    return {
      id: Math.random().toString(36).substring(7),
      ...data,
      createdAt: new Date().toISOString(),
      severity: data.severity || 'high'
    };
  }
          `secret-${pattern.name}`,
          pattern.message,
          {
            severity: 'critical',
            file: filename,
            line: lineNumber,
            column,
            code: this.redactLine(line.trim()),
            suggestion: 'Remove this secret and use environment variables or a secure secrets manager',
            type: 'security',
            metadata: {
              secretType: pattern.name,
              redactedValue: redactedMatch,
            },
          }
        ));

        // Prevent infinite loops
        if (!pattern.pattern.global) break;
      }
    }

    return { findings };
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
    ];

    return placeholders.some(p => p.test(value));
  }

  private redact(secret: string): string {
    if (secret.length <= 8) return '***';
    return secret.substring(0, 4) + '...' + secret.substring(secret.length - 4);
  }

  private redactLine(line: string): string {
    // Redact common secret patterns in the line
    return line
      .replace(/(['"])[A-Za-z0-9_\-\/+=]{20,}(['"])/g, '$1***REDACTED***$2')
      .replace(/:[^:]+@/g, ':***@');
  }
}
