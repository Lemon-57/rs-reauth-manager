export interface AccountGroup { id: string; name: string }
export interface Account { id: string; name: string; email: string | null; enabled: boolean; planType: string | null; status: string; accessTokenExpiresAt: string | null; proxy: string | null; notesValid: boolean; groups: AccountGroup[] }
export interface Job { requestId: string; accountId: string; status: string; step: string; message: string; startedAt: number | null; finishedAt: number | null; workspaceChoices?: { id: string }[]; forceWorkspaceId?: string | null }
export interface Bridge { readonly version: 2; readonly theme: 'light' | 'dark'; request(input: { method: 'GET' | 'POST'; path: string; contentType?: string; body?: string }): Promise<{ status: number; contentType: string; body: ArrayBuffer }> }
declare global { interface Window { codexProxyPlugin?: Bridge } }
