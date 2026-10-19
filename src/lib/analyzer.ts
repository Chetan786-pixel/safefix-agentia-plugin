
export type Severity = 'high' | 'medium' | 'low'

export type Finding = {
  rule: string
  severity: Severity
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

const secretPatterns: RegExp[] = [
  /\b(password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)\b(\s*[:=]\s*)(["']?)[^\s"',;]+/gi,
  /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\bAKIA[A-Z0-9]{16}\b/g,
]

export function redactSecrets(input: string): {
  text: string
  changed: boolean
} {
  let text = input

  text = text.replace(secretPatterns[0], '$1$2[REDACTED]')
  text = text.replace(secretPatterns[1], 'Bearer [REDACTED]')
  text = text.replace(secretPatterns[2], '[REDACTED_GITHUB_TOKEN]')
  text = text.replace(secretPatterns[3], '[REDACTED_AWS_ACCESS_KEY]')

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
    id: 'MISSING_CONFIGURATION',
    pattern: /(missing required (environment )?variable|undefined environment variable|configuration .* not found)/i,
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

  for (const rule of rules) {
    // Reset state in case a global regex is added in the future.
    rule.pattern.lastIndex = 0
    const match = rule.pattern.exec(text)

    if (match) {
      findings.push({
        rule: rule.id,
        severity: rule.severity,
        evidence: match[0].slice(0, 180),
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
