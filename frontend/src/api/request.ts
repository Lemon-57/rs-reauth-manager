import { getHost } from './host'

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

// Adapted from the official workbench request boundary, not from host internals.
export async function request(method: 'GET' | 'POST', path: string, data?: unknown): Promise<unknown> {
  if (!/^api\/[a-z-]+$/.test(path)) throw new Error('插件管理路径必须是已注册的相对路径')
  if (method === 'GET' && data !== undefined) throw new Error('查询不能包含正文')
  const reply = await getHost().request({
    method, path,
    ...(data === undefined ? {} : { contentType: 'application/json', body: JSON.stringify(data) }),
  })
  if (reply.contentType.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json')
    throw new Error('插件返回了不支持的内容类型')
  let value: unknown
  try { value = JSON.parse(new TextDecoder().decode(reply.body)) }
  catch (cause) { throw new Error('插件返回了无效 JSON', { cause }) }
  if (reply.status < 200 || reply.status >= 300) {
    const message = isRecord(value) && isRecord(value.error) && typeof value.error.message === 'string'
      ? value.error.message : `插件请求失败（HTTP ${reply.status}）`
    throw new Error(message)
  }
  return value
}
