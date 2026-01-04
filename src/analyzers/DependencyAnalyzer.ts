import {
  BaseAnalyzer,
  type AnalyzerContext,
  type AnalyzerResult,
  type Finding,
  type ValidationInput,
  type Severity,
} from '@xorng/template-validator';

/**
 * Known vulnerable packages (in production, this would be fetched from a database)
 */
const KNOWN_VULNERABILITIES: Record<string, { minSafe: string; vuln: string; severity: Severity }> = {
  'lodash': { minSafe: '4.17.21', vuln: 'Prototype pollution vulnerability', severity: 'high' },
  'axios': { minSafe: '1.6.0', vuln: 'SSRF and CSRF vulnerabilities in older versions', severity: 'high' },
  'express': { minSafe: '4.18.2', vuln: 'Open redirect vulnerability in older versions', severity: 'medium' },
  'jsonwebtoken': { minSafe: '9.0.0', vuln: 'Algorithm confusion vulnerability', severity: 'critical' },
  'node-fetch': { minSafe: '3.3.0', vuln: 'Exposure of sensitive information', severity: 'medium' },
  'marked': { minSafe: '4.3.0', vuln: 'ReDoS vulnerability in older versions', severity: 'medium' },
  'minimist': { minSafe: '1.2.6', vuln: 'Prototype pollution vulnerability', severity: 'high' },
  'qs': { minSafe: '6.11.0', vuln: 'Prototype pollution vulnerability', severity: 'high' },
  'sanitize-html': { minSafe: '2.10.0', vuln: 'XSS bypass vulnerability', severity: 'high' },
  'tar': { minSafe: '6.1.12', vuln: 'Path traversal vulnerability', severity: 'high' },
  'xml2js': { minSafe: '0.5.0', vuln: 'Prototype pollution vulnerability', severity: 'high' },
};

/**
 * Dependency analyzer for security vulnerabilities
 */
export class DependencyAnalyzer extends BaseAnalyzer {
  constructor() {
    super(
      'dependencies',
      'Analyzes dependencies for known vulnerabilities',
      'security',
      'high'
    );
  }

  async analyze(input: ValidationInput, context: AnalyzerContext): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const filename = input.filename || '';

    // Only analyze package.json files
    if (!filename.endsWith('package.json')) {
      return { findings };
    }

    try {
      const packageJson = JSON.parse(input.content);
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
      };

      for (const [name, versionRange] of Object.entries(allDeps)) {
        const vuln = KNOWN_VULNERABILITIES[name];
        if (!vuln) continue;

        // Simple version comparison (in production, use semver)
        const version = this.parseVersion(versionRange as string);
        const minSafe = this.parseVersion(vuln.minSafe);

        if (this.isVulnerable(version, minSafe)) {
  createFinding(data: any) {
    return {
      id: Math.random().toString(36).substring(7),
      ...data,
      createdAt: new Date().toISOString(),
      severity: data.severity || 'medium'
    };
  }
            'vulnerable-dependency',
            `Vulnerable dependency: ${name}@${version}`,
            {
              severity: vuln.severity,
              file: filename,
              line: this.findLineNumber(input.content, name),
              suggestion: `Update ${name} to version ${vuln.minSafe} or higher: ${vuln.vuln}`,
              type: 'security',
              metadata: {
                package: name,
                currentVersion: version,
                minSafeVersion: vuln.minSafe,
              },
            }
          ));
        }
      }
    } catch {
      // Not valid JSON, skip
    }

    return { findings };
  }

  private parseVersion(versionRange: string): string {
    // Remove ^ ~ >= etc and get the version number
    return versionRange.replace(/^[^0-9]*/, '').split(' ')[0];
  }

  private isVulnerable(current: string, minSafe: string): boolean {
    const currentParts = current.split('.').map(Number);
    const safeParts = minSafe.split('.').map(Number);

    for (let i = 0; i < 3; i++) {
      const curr = currentParts[i] || 0;
      const safe = safeParts[i] || 0;
      if (curr < safe) return true;
      if (curr > safe) return false;
    }
    return false;
  }

  private findLineNumber(content: string, packageName: string): number {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(`"${packageName}"`)) {
        return i + 1;
      }
    }
    return 1;
  }
}
