const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')

// Run only the browser's pure validation functions, without a page or credentials.
const script = fs.readFileSync(require('node:path').join(__dirname, 'web', 'app.js'), 'utf8')
const start = script.indexOf('function validSecret(')
const end = script.indexOf('async function refresh(', start)
assert(start >= 0 && end > start)
const validate = vm.runInNewContext(`${script.slice(start, end)}; validate`, { TextEncoder })
const cases = require('./validation_cases.json')
for (const { name, line, accepted } of cases) {
  if (accepted) assert.equal(validate(line), line, name)
  else assert.throws(() => validate(line), /第 1 行格式无效/, name)
}
const secret = 'JBSWY3DPEHPK3PXP'
const prefix = 'sample@example.com----test-only----'
const suffix = `----${secret}`
const maxMailbox = 'm'.repeat(2000 - Buffer.byteLength(prefix + suffix))
assert.equal(validate(prefix + maxMailbox + suffix), prefix + maxMailbox + suffix)
assert.throws(() => validate(prefix + maxMailbox + 'm' + suffix), /格式无效/)
const five = prefix + 'mailbox' + suffix + '----'
assert.equal(validate(five + 'r'.repeat(32768)), five + 'r'.repeat(32768))
assert.throws(() => validate(five + 'r'.repeat(32769)), /格式无效/)
// The fourth field is 2FA even when the third also resembles a secret. All
// four note fields count toward the existing 2000-byte note limit.
assert.throws(() => validate(prefix + secret.repeat(62) + '----' + secret.repeat(62)), /格式无效/)
assert.throws(() => validate(`\n${prefix}mailbox${suffix}\nSAMPLE@example.com ----test-only----${secret}`), /第 3 行邮箱重复/)
assert.throws(() => validate(`\n${prefix}mailbox${suffix}\ninvalid`), /第 3 行格式无效/)
console.log(`Browser validation passed: ${cases.length} shared cases and note/RT/duplicate boundaries`)
