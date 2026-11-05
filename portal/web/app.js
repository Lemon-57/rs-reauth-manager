const $ = id => document.getElementById(id)
let jobs = [], busy = false, polling = false, timer, authenticated = false, destroyed = false
let requestId = ''
try { requestId = sessionStorage.getItem('import-request-id') || '' } catch { /* Optional non-sensitive progress marker. */ }
const labels = { queued: '等待处理', running: '处理中', success: '成功', failed: '失败', review: '待核对', interrupted: '已中断', cancelled: '已取消' }

async function api(path, value) {
  const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 60000)
  try {
    const response = await fetch(`/api/${path}`, {
      method: value === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      headers: value === undefined ? {} : { 'Content-Type': 'application/json' },
      ...(value === undefined ? {} : { body: JSON.stringify(value) }), signal: controller.signal,
    })
    const data = await response.json()
    if (!response.ok) {
      if (response.status === 401 || response.status === 403 && path !== 'login') showLogin()
      throw new Error(data.error || '请求未确认，请刷新任务核对')
    }
    return data
  } finally { clearTimeout(timeout) }
}
function showLogin() {
  authenticated = false; jobs = []; render()
  $('workspace').hidden = true; $('login-panel').hidden = false; $('logout').hidden = true
  $('accounts').value = ''; updateCount()
}
function showWorkspace() {
  authenticated = true
  $('workspace').hidden = false; $('login-panel').hidden = true; $('logout').hidden = false
}
function text(tag, content, className) {
  const element = document.createElement(tag)
  element.textContent = content
  if (className) element.className = className
  return element
}
function render() {
  const rows = $('scope').value === 'all' || !requestId ? jobs : jobs.filter(job => job.requestId.startsWith(`${requestId}:`))
  $('jobs').replaceChildren(); $('stats').replaceChildren()
  const counts = [ ['全部', rows.length, ''], ['处理中', rows.filter(j => ['running', 'queued'].includes(j.status)).length, ''], ['成功', rows.filter(j => j.status === 'success').length, 'success'], ['未完成', rows.filter(j => ['failed', 'review', 'interrupted', 'cancelled'].includes(j.status)).length, ''] ]
  for (const [label, count, cls] of counts) {
    const item = text('div', '', `stat ${cls}`); item.append(text('b', count), document.createTextNode(label)); $('stats').append(item)
  }
  for (const job of [...rows].reverse()) {
    const row = document.createElement('tr'), account = text('td', job.importInfo?.email || '等待识别')
    if (job.accountId) account.append(text('small', job.accountId))
    const state = document.createElement('td'); state.append(text('span', labels[job.status] || '待核对', `badge ${Object.hasOwn(labels, job.status) ? job.status : 'review'}`))
    const timestamp = job.finishedAt || job.startedAt
    row.append(account, state, text('td', job.message || '等待处理'), text('td', timestamp ? new Date(timestamp).toLocaleString('zh-CN', { hour12: false }) : '—'))
    $('jobs').append(row)
  }
  $('empty').hidden = rows.length > 0
}
function updateCount() { $('line-count').textContent = `${$('accounts').value.split(/\r?\n/).filter(s => s.trim()).length} 个账号` }
function validate(value) {
  if (new TextEncoder().encode(value).length > 500 * 1024) throw new Error('本批内容过长，请拆分提交')
  const lines = value.split(/\r?\n/).map((line, index) => ({ line: line.trim(), number: index + 1 })).filter(x => x.line)
  if (!lines.length || lines.length > 200) throw new Error('每批请输入 1 至 200 行账号')
  const seen = new Set()
  for (const { line, number } of lines) {
    const fields = line.split('----')
    if (![3, 4].includes(fields.length) || fields.some(f => !f) || /[\x00-\x1f\x7f]/.test(line) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields[0]) || !/^[A-Z2-7]+=*$/i.test(fields[2]) || fields[3] && /\s/.test(fields[3])) throw new Error(`第 ${number} 行格式无效，请核对 邮箱----密码----2FA`)
    const email = fields[0].toLowerCase()
    if (seen.has(email)) throw new Error(`第 ${number} 行邮箱重复，本批未提交`)
    seen.add(email)
  }
  return value
}
async function refresh() {
  if (!authenticated || polling) return
  polling = true
  try {
    const data = await api('jobs')
    if (!Array.isArray(data.jobs)) throw new Error('任务列表未确认，请稍后刷新')
    jobs = data.jobs; render()
    $('status').textContent = `更新于 ${new Date().toLocaleTimeString('zh-CN', { hour12: false })} · 关闭页面不会停止后台处理`
  } catch (e) { $('status').textContent = e.message || '任务读取失败，请刷新核对，勿重复提交' }
  finally { polling = false }
}
function schedule() {
  clearTimeout(timer)
  if (!destroyed) timer = setTimeout(async () => { if (!document.hidden) await refresh(); schedule() }, 5000)
}
$('login-form').addEventListener('submit', async event => {
  event.preventDefault(); if (busy) return
  busy = true; $('login-button').disabled = true; $('login-error').textContent = ''
  let password = $('password').value
  $('password').value = ''
  try { await api('login', { username: $('username').value, password }); showWorkspace(); await refresh() }
  catch (e) { $('login-error').textContent = e.message || '登录未确认，请重试' }
  finally { password = ''; busy = false; $('login-button').disabled = false }
})
$('import-form').addEventListener('submit', async event => {
  event.preventDefault(); if (busy) return
  let line
  try { line = validate($('accounts').value) } catch (e) { $('import-error').textContent = e.message; return }
  busy = true; $('submit').disabled = true; $('import-error').textContent = ''
  requestId = crypto.randomUUID()
  try { sessionStorage.setItem('import-request-id', requestId) } catch { /* Marker contains no account data. */ }
  $('scope').value = 'batch'; $('accounts').value = ''; updateCount()
  $('status').textContent = '正在提交，请勿重复提交…'
  try {
    const data = await api('import', { line, requestId })
    if (!Array.isArray(data.jobs) || !data.jobs.some(j => j.requestId.startsWith(`${requestId}:`))) throw new Error('未确认本次任务')
    jobs = data.jobs; render(); $('status').textContent = '已提交，后台正在处理'
  } catch (e) {
    $('import-error').textContent = `${e.message || '提交结果未确认'}。未自动重新提交，请先刷新核对账号与任务。`
  } finally { line = ''; busy = false; $('submit').disabled = false; await refresh() }
})
$('logout').addEventListener('click', async () => {
  if (busy) return
  try { await api('logout', {}); showLogin() } catch (e) { $('status').textContent = e.message }
})
$('accounts').addEventListener('input', updateCount)
$('clear').addEventListener('click', () => { $('accounts').value = ''; updateCount(); $('accounts').focus() })
$('scope').addEventListener('change', render)
$('refresh').addEventListener('click', refresh)
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh() })
window.addEventListener('pagehide', () => { destroyed = true; clearTimeout(timer); $('accounts').value = ''; $('password').value = '' })
window.addEventListener('pageshow', () => { if (destroyed) { destroyed = false; refresh(); schedule() } })
async function start() {
  try {
    const state = await api('session')
    if (state.authenticated) { showWorkspace(); await refresh() } else showLogin()
  } catch { showLogin(); $('login-error').textContent = '连接暂不可用，请稍后重试' }
  schedule()
}
start()
