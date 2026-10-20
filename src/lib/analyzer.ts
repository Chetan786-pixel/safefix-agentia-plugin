export type Severity = 'high' | 'medium' | 'low'

export type Finding = {
  rule: string
  severity: Severity
  line: number
  occurrences: number
  evidence: string
  recommendation: string
}

export type AnalysisReport = {
  secretsRedacted: boolean
  findings: Finding[]
  summary: {
    total: number
    high: number
    medium: number
    low: number
  }
}

const secretPatterns: Array<{ pattern: RegExp; replacement: string }> = [
  {
    // key=value, key: value, and JSON "key": "value"
    pattern:
      /((?<![A-Za-z0-9])(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|client[_-]?secret|consumer[_-]?secret|security[_-]?token|session[_-]?id)["']?\s*[:=]\s*)(["']?)[^\s"',;&]+/gi,
    replacement: '$1$2[REDACTED]',
  },
  {
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    replacement: '[REDACTED_PRIVATE_KEY]',
  },
  { pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, replacement: 'Bearer [REDACTED]' },
  {
    pattern: /(Authorization:\s*)Basic\s+[A-Za-z0-9+/=]{8,}/gi,
    replacement: '$1Basic [REDACTED]',
  },
  {
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g,
    replacement: '[REDACTED_JWT]',
  },
  { pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, replacement: '[REDACTED_AWS_ACCESS_KEY]' },
  { pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g, replacement: '[REDACTED_SLACK_TOKEN]' },
  // Salesforce
  { pattern: /\bforce:\/\/[^\s@]+@/gi, replacement: 'force://[REDACTED_SFDX_AUTH]@' },
  {
    pattern: /\b00D[A-Za-z0-9]{12,15}![A-Za-z0-9._-]{20,}/g,
    replacement: '[REDACTED_SALESFORCE_SESSION]',
  },
  // user:password@host in URLs
  {
    pattern: /\b([a-z][a-z0-9+.-]*:\/\/)[^\s:@/]+:[^\s@/]+@/gi,
    replacement: '$1[REDACTED]:[REDACTED]@',
  },
]

export function redactSecrets(input: string): {
  text: string
  changed: boolean
} {
  let text = input
  for (const { pattern, replacement } of secretPatterns) {
    text = text.replace(pattern, replacement)
  }
  return { text, changed: text !== input }
}

const rules: Array<{
  id: string
  pattern: RegExp
  severity: Severity
  recommendation: string
}> = [
  {
    id: 'AUTH_FAILURE',
    pattern: /\b(401 unauthorized|403 forbidden|authentication failed|invalid credentials)\b/i,
    severity: 'high',
    recommendation:
      'Verify account permissions and credential configuration. Never expose secret values.',
  },
  {
    id: 'SALESFORCE_AUTH_FAILURE',
    pattern: /(INVALID_SESSION_ID|INVALID_LOGIN|invalid_grant|expired access\/refresh token)/i,
    severity: 'high',
    recommendation:
      'Re-authenticate the org (sf org login) and check the connected app / refresh token. Never share the token itself.',
  },
  {
    id: 'APEX_GOVERNOR_LIMIT',
    pattern:
      /(System\.LimitException[^\n]*|Too many (SOQL queries|DML statements|query rows|DML rows|future calls)[^\n]*|Apex CPU time limit exceeded)/i,
    severity: 'high',
    recommendation:
      'Bulkify the code: move SOQL/DML out of loops and review triggers firing recursively.',
  },
  {
    id: 'LOW_CODE_COVERAGE',
    pattern:
      /(Average test coverage across all Apex Classes and Triggers is \d+%[^\n]*|code coverage[^\n]*below[^\n]*)/i,
    severity: 'high',
    recommendation:
      'Add or fix Apex tests until org-wide coverage reaches the required 75% before redeploying.',
  },
  {
    id: 'APEX_COMPILE_ERROR',
    pattern:
      /(Compile Error[^\n]*|Dependent class is invalid[^\n]*|Variable does not exist:[^\n]*|Invalid type:[^\n]*|Method does not exist or incorrect signature[^\n]*)/i,
    severity: 'medium',
    recommendation:
      'Fix the referenced symbol. A missing field or class often means a dependency was not deployed first.',
  },
  {
    id: 'MISSING_METADATA_DEPENDENCY',
    pattern: /no [A-Za-z]+ named [^\s]+ found/i,
    severity: 'medium',
    recommendation:
      'Include the missing component in the same deployment or deploy it to the target org first.',
  },
  {
    id: 'ROW_LOCK',
    pattern: /UNABLE_TO_LOCK_ROW/i,
    severity: 'medium',
    recommendation:
      'Check concurrent jobs or triggers updating the same records; consider retry logic or serial processing.',
  },
  {
    id: 'VALIDATION_FAILURE',
    pattern: /(FIELD_CUSTOM_VALIDATION_EXCEPTION|REQUIRED_FIELD_MISSING)[^\n]*/i,
    severity: 'medium',
    recommendation:
      'A validation rule or required field blocked the record. Check test data and the rule logic.',
  },
  {
    id: 'MISSING_CONFIGURATION',
    pattern:
      /(missing required (environment )?variable|undefined environment variable|configuration .* not found)/i,
    severity: 'medium',
    recommendation:
      'Check required environment variable names and local configuration. Do not commit secrets.',
  },
  {
    id: 'DEPENDENCY_FAILURE',
    pattern: /(module not found|cannot find module|package .* not found|npm err! code e404)/i,
    severity: 'medium',
    recommendation:
      'Check package names, dependency versions, registry access, and the lockfile.',
  },
  {
    id: 'NETWORK_FAILURE',
    pattern: /(econnrefused|etimedout|enotfound|network request failed)/i,
    severity: 'medium',
    recommendation:
      'Check service availability, DNS, network connectivity, and endpoint configuration.',
  },
  {
    id: 'TEST_FAILURE',
    pattern: /(tests? failed|assertionerror|test suite failed)/i,
    severity: 'low',
    recommendation:
      'Review the failing test and its assertion. Reproduce the failure before changing code.',
  },
  {
    id: 'PERMISSION_FAILURE',
    pattern: /(eacces|eperm|permission denied|access is denied)/i,
    severity: 'medium',
    recommendation:
      'Check file permissions and the current user. Avoid granting unnecessarily broad permissions.',
  },
]

export function analyzeLog(input: string): AnalysisReport {
  const { text, changed } = redactSecrets(input)
  const findings: Finding[] = []
  const lines = text.split(/\r?\n/)

  for (const rule of rules) {
    let firstLine = 0
    let occurrences = 0
    let evidence = ''

    lines.forEach((line, index) => {
      rule.pattern.lastIndex = 0
      const match = rule.pattern.exec(line)
      if (match) {
        occurrences += 1
        if (!firstLine) {
          firstLine = index + 1
          evidence = match[0].slice(0, 180)
        }
      }
    })

    if (occurrences > 0) {
      findings.push({
        rule: rule.id,
        severity: rule.severity,
        line: firstLine,
        occurrences,
        evidence,
        recommendation: rule.recommendation,
      })
    }
  }

  return {
    secretsRedacted: changed,
    findings,
    summary: {
      total: findings.length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
    },
  }
}