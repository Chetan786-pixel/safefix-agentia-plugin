import { readFile, writeFile } from 'node:fs/promises'
import { AgentiaCommand } from '@copado/agentia-plugin-sdk'
import { Flags } from '@oclif/core'
import { redactSecrets } from '../../lib/analyzer.js'

export default class SafefixRedact extends AgentiaCommand {
  static override description =
    'Redact secrets from a log file so it can be shared safely (no AI, no network)'

  static override examples = [
    '$ agentia safefix redact --file ./build.log',
    '$ agentia safefix redact --file ./build.log --out ./build.redacted.log',
  ]

  static override flags = {
    file: Flags.string({
      char: 'f',
      description: 'Path to the log file',
      required: true,
    }),
    out: Flags.string({
      char: 'o',
      description: 'Write the redacted log to this file instead of printing it',
    }),
  }

  public async run() {
    const { flags } = await this.parse(SafefixRedact)

    let raw: string
    try {
      raw = await readFile(flags.file, 'utf8')
    } catch {
      this.error(
        `Cannot read log file "${flags.file}". Check that it exists and is accessible.`,
      )
    }

    const { text, changed } = redactSecrets(raw)

    if (flags.out) {
      await writeFile(flags.out, text, 'utf8')
      this.log(
        JSON.stringify({ file: flags.file, out: flags.out, secretsRedacted: changed }, null, 2),
      )
    } else {
      this.log(text)
    }
  }
}