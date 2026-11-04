import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
const root=fileURLToPath(new URL('..',import.meta.url))
const require=createRequire(path.join(root,'frontend/package.json'))
const {createServer}=await import(pathToFileURL(require.resolve('vite')).href)
const server=await createServer({root:path.join(root,'frontend'),configFile:false,server:{middlewareMode:true,hmr:false}})
const original=Object.getOwnPropertyDescriptor(globalThis,'window')
try {
 const {useAccountColumns}=await server.ssrLoadModule('/src/useAccountColumns.ts')
 const columns=[{key:'select',kind:'selection',hideable:false},{key:'identity',label:'Account',kind:'identity',hideable:false},{key:'plan',label:'Plan'},{key:'status',label:'Status'}]
 Object.defineProperty(globalThis,'window',{configurable:true,value:Object.defineProperty({},'localStorage',{get(){throw new DOMException('Sandbox storage unavailable','SecurityError')}})})
 const state=useAccountColumns(columns,'fixture')
 assert.deepEqual(state.visibleColumns.value.map(c=>c.key),['select','identity','plan','status'])
 state.setColumnVisible('plan',false);state.setColumnVisible('identity',false)
 assert.deepEqual(state.visibleColumns.value.map(c=>c.key),['select','identity','status'])
 state.setColumnOrder(['status','status','unknown','plan','identity'])
 assert.deepEqual(state.visibleColumns.value.map(c=>c.key),['select','status','identity'])
 state.resetColumns();assert.deepEqual(state.visibleColumns.value.map(c=>c.key),['select','identity','plan','status'])
 console.log('PASS blocked sandbox storage preserves rendering, column visibility, ordering, protected columns and reset without persistence')
 Object.defineProperty(globalThis,'window',{configurable:true,value:undefined})
 assert.equal(useAccountColumns(columns,'fixture').visibleColumns.value.length,4)
 console.log('PASS a missing browser storage context also renders with in-memory preferences')
} finally {
 if(original)Object.defineProperty(globalThis,'window',original);else delete globalThis.window
 await server.close()
}
