
import { readFile } from 'node:fs/promises'
import { AgentiaCommand } from '@copado/agentia-plugin-sdk'
import { Flags } from '@oclif/core'
import { analyzeLog } from '../../lib/analyzer.js'

export default class SafefixDiagnose extends AgentiaCommand {
  static override description =
    'Analyze a log file, redact common secrets, and recommend safer troubleshooting steps'

  static override examples = [
    '$ agentia safefix diagnose --file ./sample-error.log',
    '$ agentia safefix diagnose --file ./sample-error.log --json',
  ]

  static override flags = {
    file: Flags.string({
      char: 'f',
      description: 'Path to the log file to analyze',
      required: true,
    }),
  }

  public async run() {
    const { flags } = await this.parse(SafefixDiagnose)

    let rawLog: string
    try {
      rawLog = await readFile(flags.file, 'utf8')
    } catch {
      this.error(
        `Cannot read log file "${flags.file}". Check that the file exists and is accessible.`,
      )
    }

    const analysis = analyzeLog(rawLog!)

    const report = {
      tool: 'SafeFix',
      version: '0.1.0',
      file: flags.file,
      ...analysis,
      note:
        'Pattern-based triage only. No fixes were executed. Redaction does not guarantee removal of every secret.',
    }

    this.log(JSON.stringify(report, null, 2))
    return report
  }
}
