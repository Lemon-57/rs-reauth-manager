export interface SupplierAccount { supplier?: string | null }
export const supplierMatches = (row: SupplierAccount, supplier: string) => !supplier || row.supplier?.trim() === supplier
export function supplierOptions(rows: SupplierAccount[]) {
  const names = [...new Set(rows.map(row => row.supplier?.trim()).filter((name): name is string => !!name))]
  return [{ value: '', label: '全部供应商' }, ...names.sort((a, b) => a.localeCompare(b, 'zh-CN')).map(value => ({ value, label: value }))]
}
