function validTwoFactor(value: string) {
  const secret = value.trim().replaceAll(' ', '').toUpperCase()
  const core = secret.replace(/=+$/, '')
  return core.length >= 16 && [0, 2, 4, 5, 7].includes(core.length % 8) && /^[A-Z2-7]+$/.test(core)
    && (!secret.includes('=') || secret.length % 8 === 0)
}

export function validateImportLine(text: string): string {
  const lines = text.split(/\r?\n/).map((line, index) => ({ line: line.trim(), number: index + 1 })).filter(item => item.line)
  if (new TextEncoder().encode(text).length > 500 * 1024) throw new Error('本批内容过长，请拆分提交')
  if (!lines.length) throw new Error('请至少输入一行账号')
  const seen = new Set<string>()
  for (const { line, number } of lines) {
    const fields = line.split('----')
    if (![3, 4, 5].includes(fields.length) || fields.some(value => !value || /[\r\n\x00-\x1f\x7f]/.test(value)) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields[0]!))
      throw new Error(`第 ${number} 行格式无效，请按 邮箱----密码----[邮箱密码----]2FA[----RT] 输入，方括号内为可选字段`)
    const fourthIsTwoFactor = fields.length >= 4 && validTwoFactor(fields[3]!)
    const noteFields = fields.length === 5 || fields.length === 4 && fourthIsTwoFactor ? 4 : 3
    if (!validTwoFactor(fields[noteFields - 1]!) || fields[noteFields] && /\s/.test(fields[noteFields]!))
      throw new Error(`第 ${number} 行 2FA 密钥或 RT 格式无效，请核对字段顺序`)
    const email = fields[0]!.toLowerCase()
    if (seen.has(email)) throw new Error(`第 ${number} 行邮箱在本批次重复，未提交任何账号`)
    seen.add(email)
  }
  return text.replace(/\r\n/g, '\n')
}
