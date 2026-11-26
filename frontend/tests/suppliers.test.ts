import assert from 'node:assert/strict'
import test from 'node:test'
import {supplierOptions,supplierMatches} from '../src/suppliers.ts'
test('供应商选项来自完整目录，去空去重，保留精确名称及全部选项',()=>{
 const rows=[{supplier:' Vendor A '},{supplier:'Vendor A'},{supplier:'all'},{supplier:'Vendor B'},{supplier:null},{}]
 const options=supplierOptions(rows)
 assert.deepEqual(options[0],{value:'',label:'全部供应商'})
 assert.equal(options.length,4)
 assert.equal(options.filter(o=>o.value==='Vendor A').length,1)
 assert.equal(rows.filter(r=>supplierMatches(r,'')).length,6)
 assert.equal(rows.filter(r=>supplierMatches(r,'Vendor A')).length,2)
 assert.equal(rows.filter(r=>supplierMatches(r,'all')).length,1)
 assert.equal(rows.filter(r=>supplierMatches(r,'Vendor')).length,0)
})
