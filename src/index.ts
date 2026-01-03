import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  filterBySeverity,
  groupByFile,
  type Finding,
  type ValidationInput,
  type AnalyzerContext,
} from '@xorng/template-validator';
import { createLogger, registerTools, createToolHandler } from '@xorng/template-base';
import { z } from 'zod';

import { VulnerabilityAnalyzer } from './analyzers/VulnerabilityAnalyzer.js';
import { DependencyAnalyzer } from './analyzers/DependencyAnalyzer.js';
import { SecretsAnalyzer } from './analyzers/SecretsAnalyzer.js';
import { InputValidationAnalyzer } from './analyzers/InputValidationAnalyzer.js';

const logger = createLogger('info', 'validator-security');

// Initialize analyzers
const analyzers = {
  vulnerability: new VulnerabilityAnalyzer(),
  dependencies: new DependencyAnalyzer(),
  secrets: new SecretsAnalyzer(),
  inputValidation: new InputValidationAnalyzer(),
};

// Create MCP server
const server = new McpServer({
  name: 'validator-security',
  version: '0.1.0',
});

const transport = new StdioServerTransport();

// Analyze a single file
async function analyzeCode(
  code: string,
  filePath: string,
  options?: { analyzers?: string[] }
): Promise<Finding[]> {
  const input: ValidationInput = {
    content: code,
    filename: filePath,
    language: detectLanguage(filePath),
  };

  const context: AnalyzerContext = {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    logger: logger as any,
    requestId: crypto.randomUUID(),
  };

  const findings: Finding[] = [];
  const selectedAnalyzers = options?.analyzers || Object.keys(analyzers);

  for (const name of selectedAnalyzers) {
    const analyzer = analyzers[name as keyof typeof analyzers];
    if (analyzer) {
      const result = await analyzer.analyze(input, context);
      findings.push(...result.findings);
    }
  }

  return findings;
}

function detectLanguage(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase();
  const langMap: Record<string, string> = {
    ts: 'typescript',
    tsx: 'typescript',
    js: 'javascript',
    jsx: 'javascript',
    py: 'python',
    java: 'java',
    go: 'go',
    rs: 'rust',
    json: 'json',
    yml: 'yaml',
    yaml: 'yaml',
  };
  return langMap[ext || ''] || 'unknown';
}

// Register tools
const tools = [
  createToolHandler({
    name: 'scan',
    description: 'Perform a comprehensive security scan on code',
    inputSchema: z.object({
      code: z.string().describe('Code to scan'),
      filePath: z.string().describe('File path for context'),
      analyzers: z.array(z.enum(['vulnerability', 'dependencies', 'secrets', 'inputValidation']))
        .optional()
        .describe('Specific analyzers to run'),
    }),
    handler: async (input) => {
      const findings = await analyzeCode(input.code, input.filePath, {
        analyzers: input.analyzers,
      });
      
      return {
        findings,
        summary: {
          total: findings.length,
          critical: findings.filter(f => f.severity === 'critical').length,
          high: findings.filter(f => f.severity === 'high').length,
          medium: findings.filter(f => f.severity === 'medium').length,
          low: findings.filter(f => f.severity === 'low').length,
        },
      };
    },
  }),

  createToolHandler({
    name: 'scan-vulnerabilities',
    description: 'Scan for common security vulnerabilities (SQL injection, XSS, etc.)',
    inputSchema: z.object({
      code: z.string().describe('Code to scan'),
      filePath: z.string().describe('File path for context'),
    }),
    handler: async (input) => {
      return analyzeCode(input.code, input.filePath, { analyzers: ['vulnerability'] });
    },
  }),

  createToolHandler({
    name: 'scan-secrets',
    description: 'Scan for hardcoded secrets and credentials',
    inputSchema: z.object({
      code: z.string().describe('Code to scan'),
      filePath: z.string().describe('File path for context'),
    }),
    handler: async (input) => {
      return analyzeCode(input.code, input.filePath, { analyzers: ['secrets'] });
    },
  }),

  createToolHandler({
    name: 'scan-dependencies',
    description: 'Check package.json for vulnerable dependencies',
    inputSchema: z.object({
      packageJson: z.string().describe('Contents of package.json'),
      filePath: z.string().optional().default('package.json'),
    }),
    handler: async (input) => {
      return analyzeCode(input.packageJson, input.filePath || 'package.json', { analyzers: ['dependencies'] });
    },
  }),

  createToolHandler({
    name: 'scan-input-validation',
    description: 'Check for missing or inadequate input validation',
    inputSchema: z.object({
      code: z.string().describe('Code to scan'),
      filePath: z.string().describe('File path for context'),
    }),
    handler: async (input) => {
      return analyzeCode(input.code, input.filePath, { analyzers: ['inputValidation'] });
    },
  }),

  createToolHandler({
    name: 'generate-report',
    description: 'Generate a security report from scan findings',
    inputSchema: z.object({
      findings: z.array(z.any()).describe('Array of findings from scan'),
      format: z.enum(['summary', 'detailed']).default('summary'),
    }),
    handler: async (input) => {
      const findings = input.findings as Finding[];
      const grouped = groupByFile(findings);
      
      if (input.format === 'detailed') {
        const groupedObj: Record<string, Finding[]> = {};
        grouped.forEach((value, key) => {
          groupedObj[key] = value;
        });
        
        return {
          byFile: groupedObj,
          summary: {
            total: findings.length,
            critical: findings.filter(f => f.severity === 'critical').length,
            high: findings.filter(f => f.severity === 'high').length,
            medium: findings.filter(f => f.severity === 'medium').length,
            low: findings.filter(f => f.severity === 'low').length,
          },
        };
      }

      return {
        fileCount: grouped.size,
        findingCount: findings.length,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        topIssues: findings
          .filter(f => f.severity === 'critical' || f.severity === 'high')
          .slice(0, 5)
          .map(f => ({
            file: f.file,
            line: f.line,
            rule: f.rule,
            message: f.message,
          })),
      };
    },
  }),
];

// Register all tools
registerTools(server, tools, logger);

// Start server
async function main(): Promise<void> {
  logger.info('Starting security validator MCP server');
  await server.connect(transport);
  logger.info('Security validator MCP server connected');
}

main().catch((error) => {
  logger.error(error, 'Failed to start server');
  process.exit(1);
});
