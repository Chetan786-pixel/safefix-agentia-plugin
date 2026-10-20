# SafeFix — Agentia CLI Plugin

SafeFix is a **governed log triage** plugin for Agentia. It reads a local CI/CD, deployment or test log, **redacts secrets before anything leaves the machine**, detects known failure patterns (with Salesforce and Copado-style failures built in), and can optionally ask Copado AI for a diagnosis using only the redacted excerpt.

> **Important:** SafeFix is a pattern-based triage tool, not a complete security scanner. Redaction is best-effort and does not guarantee that every secret is removed. It never executes fixes.

## Why

AI diagnosis of a failed deployment is useful, but raw logs often contain session IDs, refresh tokens, passwords and connection strings. SafeFix puts a redaction step in front of the AI call and lets you **preview exactly what would be sent** (`--dry-run`) before anything is transmitted.

## Requirements

- Node.js 22.12 or newer
- Agentia CLI available on your PATH

## Setup

```powershell
npm install
npm run build
npm test
agentia plugins link .
```

The linked plugin runs the compiled code in `dist/`, so run `npm run build` after every code change.

## Usage

Local triage (no network, no AI):

```powershell
agentia safefix diagnose --file .\demo\salesforce-deploy-failure.log
```

Preview the exact, already-redacted request that would be sent to Copado AI (nothing is sent):

```powershell
agentia safefix diagnose --file .\demo\salesforce-deploy-failure.log --ai --dry-run
```

Request a Copado AI diagnosis (requires AI credentials, see below):

```powershell
agentia safefix diagnose --file .\demo\salesforce-deploy-failure.log --ai
```

The output is JSON: findings (rule, severity, first line number, occurrence count, evidence, recommendation), severity counts, and whether any secret was redacted.

### Copado AI credentials

`--ai` uses the Agentia AI host. Configure it once with your own values:

```powershell
agentia auth set --ai "<your-pak>" --ai-domain "<your-domain>" --ai-org <org-number>
```

If AI is unavailable or not configured, SafeFix **does not fail**: it prints the full local triage and an `aiDiagnosis.error` explaining what is missing.

## What gets redacted

Passwords and API keys (including inside JSON), access/refresh/ID tokens, client and consumer secrets, bearer and basic auth headers, JWTs, private key blocks, GitHub tokens, AWS access keys, Slack tokens, credentials inside URLs, and Salesforce-specific secrets: session IDs and SFDX auth URLs (`force://...`).

Example (from `demo/salesforce-deploy-failure.log`):

```text
Before: {"password": "hunter2-not-real", "user": "demo"}
After:  {"password": "[REDACTED]", "user": "demo"}

Before: force://PlatformCLI::fakeRefreshToken123456@login.salesforce.com
After:  force://[REDACTED_SFDX_AUTH]@login.salesforce.com
```

All values in the demo log are fake.

## Detection rules

General: authentication failures, missing configuration, dependency failures, network failures, test failures, permission failures.

Salesforce: authentication/session failures (`INVALID_SESSION_ID`, `invalid_grant`), Apex governor limits (`Too many SOQL queries: 101`), low Apex code coverage, Apex compile errors, missing metadata dependencies, row locks, validation failures.

## Development

```powershell
npm run build
npm test
```

Quality gates (`.agentia_quality_gates.cmd` / `.sh`) build the plugin and run the test suite; they exit non-zero on failure.

## Limitations

- Detection is rule-based; unknown error messages may not be classified.
- Redaction is best-effort. Review logs before sharing them.
- SafeFix recommends actions but does not execute fixes.
- When using `--ai`, only the last 10,000 characters of the redacted log are sent, together with the local triage notes.
- The plugin reads a user-provided local file. Review Agentia plugin permission metadata and host compatibility before distributing it.
- The dependency audit currently reports a transitive `braces` vulnerability through `oclif`. Do not use `npm audit fix --force` without validating compatibility.

## License

MIT