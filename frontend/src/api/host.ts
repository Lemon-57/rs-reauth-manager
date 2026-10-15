import type { Bridge } from '../types'

export function getHost(): Bridge {
  const host = window.codexProxyPlugin
  if (!host || host.version !== 2) throw new Error('请从网关的插件管理页面打开')
  return host
}
