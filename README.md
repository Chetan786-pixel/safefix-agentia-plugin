# SafeFix — Agentia CLI Plugin

SafeFix analyzes local CI/CD and test logs, redacts selected common secret patterns, identifies known error patterns, and recommends troubleshooting steps.

**Important:** SafeFix is a pattern-based triage tool, not a complete security scanner. Redaction is best-effort and does not guarantee that every secret is removed. It does not execute fixes.

## Requirements

- Node.js 22.12 or newer
- Agentia CLI available on your PATH

## Setup

Install dependencies and build:

```powershell
npm install
npm test
npm run build
```

Link the plugin to Agentia from this directory:

```powershell
agentia plugins link .
```

## Usage

Analyze a log file:

```powershell
agentia safefix diagnose --file .\sample-error.log
```

The sample log is a local demo fixture and is ignored by Git. Create your own test log if it is absent.

JSON output:

```powershell
agentia safefix diagnose --file .\sample-error.log --json
```

The report includes detected findings, severity counts, recommendations, and whether a recognized secret pattern was redacted.

## Current detection rules

- Authentication failures
- Missing configuration
- Dependency failures
- Network failures
- Test failures
- Permission failures

Recognized secret patterns include selected API-key/password assignments, bearer tokens, GitHub-style tokens, and AWS access-key IDs. These patterns are not exhaustive.

## Tests

Run:

```powershell
npm test
```

Tests cover authentication, dependency and network errors, severity counts, unknown errors, and selected redaction patterns.

## Limitations

- Detection is rule-based; unknown error messages may not be classified.
- Redaction is best-effort. Review logs before sharing them.
- SafeFix recommends actions but does not execute fixes.
- The current implementation reads a user-provided local file. Review Agentia plugin permission metadata and host compatibility before distributing it.
- The dependency audit currently reports a transitive `braces` vulnerability through `oclif`. Do not use `npm audit fix --force` without validating compatibility.

## License

MIT

