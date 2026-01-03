# XORNG Security Validator

Security validation sub-agent for the XORNG framework.

## Overview

This validator provides comprehensive security analysis:

- **Vulnerability Scanner** - Detects SQL injection, XSS, command injection, etc.
- **Secrets Scanner** - Finds hardcoded API keys, tokens, and credentials
- **Dependency Analyzer** - Checks for vulnerable npm packages
- **Input Validation** - Identifies missing input sanitization

## Installation

```bash
npm install
npm run build
```

## Usage

### As MCP Server

```bash
npm start
```

### Available Tools

#### `scan`
Comprehensive security scan with all analyzers.

```json
{
  "code": "const query = 'SELECT * FROM users WHERE id = ' + userId;",
  "filePath": "src/db.ts",
  "analyzers": ["vulnerability", "secrets"]
}
```

#### `scan-vulnerabilities`
Check for common security vulnerabilities.

#### `scan-secrets`
Find hardcoded secrets and credentials.

#### `scan-dependencies`
Check package.json for vulnerable packages.

#### `scan-input-validation`
Detect missing input validation.

#### `generate-report`
Generate reports in summary, detailed, or SARIF format.

## Detected Vulnerabilities

### Code Vulnerabilities
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- Cross-Site Scripting (CWE-79)
- Code Injection / Eval (CWE-95)
- Insecure Randomness (CWE-330)
- Weak Cryptography (CWE-327)
- Prototype Pollution (CWE-1321)
- SSRF (CWE-918)
- Open Redirect (CWE-601)
- Unsafe Deserialization (CWE-502)

### Secrets
- AWS Keys
- GitHub Tokens
- Stripe Keys
- Google API Keys
- Slack Tokens
- JWT Tokens
- Private Keys
- Database URLs
- Generic credentials

### Dependencies
Known vulnerable versions of:
- lodash
- axios
- express
- jsonwebtoken
- node-fetch
- minimist
- And more...

## Example Output

```json
{
  "findings": [
    {
      "id": "abc-123",
      "type": "security",
      "severity": "critical",
      "message": "Potential SQL injection vulnerability",
      "file": "src/db.ts",
      "line": 15,
      "column": 10,
      "code": "const query = 'SELECT * FROM users WHERE id = ' + userId;",
      "suggestion": "Use parameterized queries instead of string concatenation",
      "rule": "sql-injection",
      "metadata": {
        "cwe": "CWE-89"
      }
    }
  ],
  "summary": {
    "total": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

## Docker

```bash
# Build
docker build -t xorng/validator-security .

# Run
docker run xorng/validator-security
```

## License

MIT
