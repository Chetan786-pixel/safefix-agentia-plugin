
import test from 'node:test'
import assert from 'node:assert/strict'
import { analyzeLog, redactSecrets } from '../dist/lib/analyzer.js'

test('detects authentication failures', () => {
  const report = analyzeLog('ERROR: Authentication failed (401 Unauthorized)')

  assert.equal(report.summary.total, 1)
  assert.equal(report.findings[0].rule, 'AUTH_FAILURE')
  assert.equal(report.summary.high, 1)
})

test('redacts API keys before reporting evidence', () => {
  const secret = 'sk_test_example123456'
  const { text, changed } = redactSecrets(`api_key=${secret}`)

  assert.equal(changed, true)
  assert.equal(text.includes(secret), false)
  assert.equal(text.includes('[REDACTED]'), true)
})

test('detects dependency failures', () => {
  const report = analyzeLog('Error: Module not found')

  assert.equal(report.findings[0].rule, 'DEPENDENCY_FAILURE')
  assert.equal(report.summary.medium, 1)
})

test('detects network failures', () => {
  const report = analyzeLog('Error: ECONNREFUSED')

  assert.equal(report.findings[0].rule, 'NETWORK_FAILURE')
})

test('does not invent findings for unknown errors', () => {
  const report = analyzeLog('Everything completed normally')

  assert.equal(report.summary.total, 0)
  assert.deepEqual(report.findings, [])
})

test('calculates severity counts correctly', () => {
  const report = analyzeLog(
    'Authentication failed\nModule not found\nTests failed',
  )

  assert.equal(report.summary.total, 3)
  assert.equal(report.summary.high, 1)
  assert.equal(report.summary.medium, 1)
  assert.equal(report.summary.low, 1)
})

test('redacts bearer tokens', () => {
  const { text } = redactSecrets('Authorization: Bearer abc.def.ghi')

  assert.equal(text.includes('abc.def.ghi'), false)
  assert.equal(text.includes('Bearer [REDACTED]'), true)
})
