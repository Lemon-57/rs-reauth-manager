import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { fileURLToPath, pathToFileURL } from 'node:url'
const root = fileURLToPath(new URL('../frontend/', import.meta.url))
const require = createRequire(root + 'package.json')
const { createServer } = await import(pathToFileURL(require.resolve('vite')).href)
const server = await createServer({ root, configFile: false, server: { middlewareMode: true, hmr: false } })
try {
  const { validateImportLine } = await server.ssrLoadModule('/src/importInput.ts')
  const secret = 'GEZDGNBVGY3TQOJQ'
  const lines = [
    `first@example.invalid----pass!----${secret}`,
    `second@example.invalid----pass!----${secret}----fixture-rt`,
    `third@example.invalid----pass!----mail-pass!----${secret}`,
    `fourth@example.invalid----pass!----mail-pass!----${secret}----v1.variable-length-refresh-token`,
    `fifth@example.invalid----pass!----ABCDEFGHIJKLMN23----${secret}`,
  ]
  for (const line of lines) assert.equal(validateImportLine(line), line)
  assert.equal(validateImportLine(lines.join('\r\n')), lines.join('\n'))
  for (const line of [`a@example.invalid----pass!----123456`, `a@example.invalid----pass!----mail!----123456`, `a@example.invalid----pass!----mail!----${secret}----bad rt`])
    assert.throws(() => validateImportLine(line), /2FA/)
  assert.throws(() => validateImportLine(lines[0] + '\n' + lines[0].toUpperCase()), /重复/)
  console.log('PASS four input formats, variable token length, Base32-like mailbox password, mixed batches and invalid input rejection')
} finally {
  await server.close()
}
