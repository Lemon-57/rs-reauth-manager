export function validateImportLine(text: string): string {
  const lines = text.split(/\r?\n/).map((line, index) => ({ line: line.trim(), number: index + 1 })).filter(item => item.line)
  if (new TextEncoder().encode(text).length > 500 * 1024) throw new Error('本批内容过长，请拆分提交')
  if (!lines.length) throw new Error('请至少输入一行账号')
  if (lines.length > 100) throw new Error('每批最多导入 100 行')
  const seen = new Set<string>()
  for (const { line, number } of lines) {
    const fields = line.split('----')
    if (![3, 4].includes(fields.length) || fields.some(value => !value || /[\r\n\x00-\x1f\x7f]/.test(value)) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields[0]!) || !/^[A-Z2-7]+=*$/i.test(fields[2]!) || (fields[3] && /\s/.test(fields[3])))
      throw new Error(`第 ${number} 行格式无效，请核对 邮箱----密码----2FA 或 邮箱----密码----2FA----RT`)
    const email = fields[0]!.toLowerCase()
    if (seen.has(email)) throw new Error(`第 ${number} 行邮箱在本批次重复，未提交任何账号`)
    seen.add(email)
  }
  return text.replace(/\r\n/g, '\n')
}
