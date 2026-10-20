import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeLog, redactSecrets } from '../dist/lib/analyzer.js'

test('redacts passwords inside JSON', () => {
  const { text, changed } = redactSecrets('{"password": "hunter2-not-real", "user": "demo"}')
  assert.equal(changed, true)
  assert.ok(!text.includes('hunter2-not-real'))
  assert.ok(text.includes('"user": "demo"'))
})

test('redacts Salesforce session ids and SFDX auth urls', () => {
  const input = [
    'Authorization: OAuth 00D5g000001AbCdEAK!AQEAQfakefakefakefakefakefake1234567890',
    'force://PlatformCLI::fakeRefreshToken123456@login.salesforce.com',
  ].join('\n')
  const { text } = redactSecrets(input)
  assert.ok(!text.includes('AQEAQfakefake'))
  assert.ok(!text.includes('fakeRefreshToken123456'))
  assert.ok(text.includes('login.salesforce.com'))
})

test('redacts JWTs', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk'
  const { text } = redactSecrets(`token was ${jwt} here`)
  assert.ok(!text.includes(jwt))
})

test('redacts private key blocks', () => {
  const key = '-----BEGIN RSA PRIVATE KEY-----\nMIIFAKEFAKEFAKE\n-----END RSA PRIVATE KEY-----'
  const { text } = redactSecrets(`before\n${key}\nafter`)
  assert.ok(!text.includes('MIIFAKEFAKEFAKE'))
  assert.ok(text.includes('before') && text.includes('after'))
})

test('redacts credentials inside urls', () => {
  const { text } = redactSecrets('connecting to postgres://admin:s3cretpass@db.example.com/app')
  assert.ok(!text.includes('s3cretpass'))
  assert.ok(text.includes('db.example.com'))
})

test('leaves clean logs unchanged', () => {
  const input = 'Deployment finished in 12s'
  const { text, changed } = redactSecrets(input)
  assert.equal(changed, false)
  assert.equal(text, input)
})

test('detects Salesforce governor limits with line numbers', () => {
  const report = analyzeLog('ok\nSystem.LimitException: Too many SOQL queries: 101')
  const finding = report.findings.find((f) => f.rule === 'APEX_GOVERNOR_LIMIT')
  assert.ok(finding)
  assert.equal(finding.line, 2)
  assert.equal(finding.severity, 'high')
})

test('detects low Apex code coverage', () => {
  const report = analyzeLog(
    'Average test coverage across all Apex Classes and Triggers is 62%, at least 75% test coverage is required.',
  )
  assert.ok(report.findings.some((f) => f.rule === 'LOW_CODE_COVERAGE'))
})

test('counts repeated occurrences of the same rule', () => {
  const report = analyzeLog('ECONNREFUSED a\nECONNREFUSED b\nECONNREFUSED c')
  const finding = report.findings.find((f) => f.rule === 'NETWORK_FAILURE')
  assert.equal(finding.occurrences, 3)
  assert.equal(finding.line, 1)
})