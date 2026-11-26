import { computed, ref } from 'vue'
import { resolveColumns, useTableColumns, type TableColumn, type TableColumnOption } from '@codex-proxy/ui/table'

export function useAccountColumns<Row extends object>(source: TableColumn<Row>[], tableId: string) {
  // 正式插件页是无同源权限的沙箱；仅检测可用性，不读写其他站点偏好。
  try {
    if (typeof window !== 'undefined' && window.localStorage) return useTableColumns(source, tableId)
  } catch (error) {
    if (!(error instanceof Error) || error.name !== 'SecurityError') throw error
  }
  const overrides = ref<Record<string, boolean>>({})
  const order = ref<string[]>([])
  const states = computed(() => {
    const columns = resolveColumns(source)
    const ranks = new Map(order.value.map((key, index) => [key, index]))
    const movable = columns.filter(column => column.label && !column.sticky)
      .sort((a, b) => (ranks.get(a.key) ?? Number.MAX_SAFE_INTEGER) - (ranks.get(b.key) ?? Number.MAX_SAFE_INTEGER))
    let index = 0
    const result = columns.map(column => column.label && !column.sticky ? movable[index++]! : column)
      .map(column => ({ column, visible: column.hideable === false || (overrides.value[column.key] ?? !column.defaultHidden) }))
    if (!result.some(state => state.visible) && result[0]) result[0].visible = true
    return result
  })
  const visibleColumns = computed(() => states.value.filter(state => state.visible).map(state => state.column))
  const columnOptions = computed<TableColumnOption[]>(() => states.value.filter(state => state.column.label).map(({ column, visible }) => ({
    key: column.key, label: column.label!, visible,
    disabled: column.hideable === false || (visible && visibleColumns.value.length === 1),
    reorderable: !column.sticky,
  })))
  function setColumnVisible(key: string, visible: boolean) {
    const option = columnOptions.value.find(option => option.key === key)
    if (!option || option.disabled) return
    overrides.value = { ...overrides.value, [key]: visible }
  }
  function setColumnOrder(keys: string[]) {
    const movable = new Set(columnOptions.value.filter(option => option.reorderable).map(option => option.key))
    order.value = [...new Set(keys.filter(key => movable.has(key)))]
  }
  function resetColumns() { overrides.value = {}; order.value = [] }
  return { visibleColumns, columnOptions, setColumnVisible, setColumnOrder, resetColumns }
}
