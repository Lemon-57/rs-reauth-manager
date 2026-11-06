const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')

// Run only the browser's pure validation functions, without a page or credentials.
const script = fs.readFileSync(require('node:path').join(__dirname, 'web', 'app.js'), 'utf8')
const start = script.indexOf('function validSecret(')
const end = script.indexOf('async function refresh(', start)
assert(start >= 0 && end > start)
const validate = vm.runInNewContext(`${script.slice(start, end)}; validate`, { TextEncoder })
const base = 'sample@example.com----test-only----JBSWY3DPEHPK3PXP'
assert.equal(validate(base), base)
const four = 'sample@example.com----test-only----jbsw y3dp ehpk 3pxp----test-refresh-token'
assert.equal(validate(four), four)
for (const line of [
  'sample@example.com----test-only----bad_secret----test-refresh-token',
  `${base}----`,
  `${base}----test refresh token`,
]) assert.throws(() => validate(line), /2FA----RT/)
console.log('Browser validation contract passed')
