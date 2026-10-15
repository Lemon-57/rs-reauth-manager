<script setup lang="ts">
import { Search, RefreshCw, KeyRound, Square, X, AlertTriangle, CircleCheck } from '@lucide/vue'
import { ZButton } from '@codex-proxy/ui/button'
import { ZCheckbox } from '@codex-proxy/ui/checkbox'
import { ZDialog } from '@codex-proxy/ui/dialog'
import { ZIconButton } from '@codex-proxy/ui/icon-button'
import { ZInput } from '@codex-proxy/ui/input'
import { ZPagination } from '@codex-proxy/ui/pagination'
import { ZSelect } from '@codex-proxy/ui/select'
import { ZTable, type TableColumn } from '@codex-proxy/ui/table'
import { ZTag } from '@codex-proxy/ui/tag'
import { displayTime, isActive, planLabel, planType, progress, statusText } from './format'
import { useReauthManager } from './useReauthManager'
import type { Account } from './types'

const { accounts, selected, loading, busy, error, search, plan, filter, page, pageSize, showConfirm, targets, jobOf, ready, active, success, failed, eligibleCount, planOptions, filtered, visible, pageSelected, chosen, selectOne, selectPage, load, confirm, submit, cancel, pageCandidates } = useReauthManager()
const statusOptions = [{ value: 'all', label: '全部状态' }, { value: 'error', label: '账号异常' }, { value: 'ready', label: '可重新授权' }, { value: 'active', label: '处理中' }, { value: 'failed', label: '授权未完成' }, { value: 'success', label: '授权成功' }, { value: 'invalid', label: '备注或代理缺失' }, { value: 'disabled', label: '已停用' }]
const columns: TableColumn<Account>[] = [{ key: 'select', label: '', width: 44 }, { key: 'identity', label: '账号', kind: 'identity', minWidth: 290 }, { key: 'plan', label: '订阅', width: 85 }, { key: 'status', label: '账号状态', width: 110 }, { key: 'credentials', label: '登录资料', width: 112 }, { key: 'proxy', label: '账号代理', minWidth: 165 }, { key: 'expiry', label: '访问令牌到期', width: 170 }, { key: 'result', label: '重新授权', minWidth: 210 }, { key: 'actions', label: '操作', kind: 'actions', width: 86 }]
</script>

<template>
  <main>
    <div class="counters" role="status" aria-label="授权任务统计"><span>可处理 <b>{{ eligibleCount }}</b></span><span>队列 <b>{{ active }}</b></span><span class="success">成功 <b>{{ success }}</b></span><span :class="{ danger: failed }">未完成 <b>{{ failed }}</b></span></div>
    <div class="toolbar">
      <ZInput v-model="search" class="search" placeholder="搜索邮箱、账号或代理" clearable aria-label="搜索账号"><template #prefix><Search :size="16" /></template></ZInput>
      <ZSelect v-model="plan" class="filter" :options="planOptions" aria-label="会员标识筛选" />
      <ZSelect v-model="filter" class="filter" :options="statusOptions" aria-label="状态筛选" />
      <div class="commands"><ZIconButton title="读取最新账号" aria-label="读取最新账号" :disabled="loading || busy" @click="load"><RefreshCw :size="17" :class="{ spin: loading }" /></ZIconButton><ZButton v-if="active" :disabled="busy" @click="cancel()"><template #icon><Square :size="14" /></template>停止队列</ZButton><ZButton type="primary" :disabled="busy || !chosen.length" @click="confirm(chosen)"><template #icon><KeyRound :size="16" /></template>重新授权所选<span v-if="chosen.length">（{{ chosen.length }}）</span></ZButton></div>
    </div>
    <div class="selection"><ZCheckbox :model-value="pageSelected" :disabled="!pageCandidates.length || busy" label="选择当前页" @change="selectPage" /><span>已选 {{ chosen.length }} / {{ filtered.length }} 个账号</span><ZIconButton v-if="selected.length" size="small" title="清空选择" aria-label="清空选择" @click="selected = []"><X :size="14" /></ZIconButton></div>
    <div v-if="error" class="message danger" role="alert"><AlertTriangle :size="16" /><span>{{ error }}</span><ZIconButton title="关闭提示" aria-label="关闭提示" @click="error = ''"><X :size="14" /></ZIconButton></div>
    <ZTable :columns="columns" :data="visible" :row-key="a => a.id" :loading="loading && !accounts.length" :empty-text="loading ? '正在读取账号' : '没有匹配的 OAuth 账号'">
      <template #select="{ row }"><ZCheckbox :model-value="selected.includes(row.id)" :disabled="!ready(row) || busy" :aria-label="`选择 ${row.email || row.name}`" @change="selectOne(row.id, $event)" /></template>
      <template #identity="{ row }"><div class="identity" :title="`${row.name}\n${row.id}`"><span class="avatar" :class="{ green: row.planType === 'team' }">{{ (row.email || row.name).slice(0, 1).toUpperCase() }}</span><div class="identity-text"><span class="email">{{ row.email || row.name }}</span><div class="mobile-details"><span><ZTag :type="planType(row.planType)" size="small">{{ planLabel(row.planType || 'unknown') }}</ZTag> {{ statusText(row) }}</span><span :class="{ danger: !row.proxy || !row.notesValid }">{{ !row.proxy ? '未绑定代理' : !row.notesValid ? '备注待检查' : row.proxy }}</span><span :class="{ success: jobOf(row)?.status === 'success', danger: ['failed', 'review', 'interrupted'].includes(jobOf(row)?.status || '') }">{{ progress(jobOf(row)) }}<span v-if="jobOf(row)?.message"> · {{ jobOf(row)?.message }}</span></span></div></div></div></template>
      <template #plan="{ row }"><ZTag :type="planType(row.planType)" size="small">{{ planLabel(row.planType || 'unknown') }}</ZTag></template>
      <template #status="{ row }"><span class="status" :class="{ danger: row.status === 'error', muted: !row.enabled, success: row.enabled && row.status === 'normal' }"><i></i>{{ statusText(row) }}</span></template>
      <template #credentials="{ row }"><span :class="row.notesValid ? 'success' : 'danger'">{{ row.notesValid ? '资料齐全' : '备注待检查' }}</span></template>
      <template #proxy="{ row }"><span class="proxy" :title="row.proxy || '未绑定代理'">{{ row.proxy || '未绑定代理' }}</span></template>
      <template #expiry="{ row }"><span class="date">{{ displayTime(row.accessTokenExpiresAt) }}</span></template>
      <template #result="{ row }"><div class="result" :class="{ success: jobOf(row)?.status === 'success', danger: ['failed', 'review', 'interrupted'].includes(jobOf(row)?.status || '') }"><span><RefreshCw v-if="isActive(jobOf(row))" class="spin" :size="13" /><CircleCheck v-else-if="jobOf(row)?.status === 'success'" :size="14" />{{ progress(jobOf(row)) }}</span><small v-if="jobOf(row)?.message" :title="jobOf(row)?.message">{{ jobOf(row)?.message }}</small><time v-if="jobOf(row)?.finishedAt">{{ displayTime(jobOf(row)?.finishedAt) }}</time></div></template>
      <template #actions="{ row }"><ZIconButton v-if="isActive(jobOf(row))" title="取消该账号" :aria-label="`取消 ${row.email || row.name}`" :disabled="busy" @click="cancel(jobOf(row))"><Square :size="15" /></ZIconButton><ZIconButton v-else title="重新授权并写回原账号" :aria-label="`重新授权 ${row.email || row.name}`" :disabled="!ready(row) || busy" @click="confirm([row])"><KeyRound :size="17" /></ZIconButton></template>
    </ZTable>
    <ZPagination v-model:current-page="page" v-model:page-size="pageSize" :total="filtered.length" :page-sizes="[10, 20, 50, 100]" />
    <ZDialog v-model="showConfirm" title="确认重新授权" width="32rem" :show-close="!busy" :close-on-click-modal="!busy" :close-on-press-escape="!busy">
      <p>重新登录以下 {{ targets.length }} 个账号，新授权将写回原账号</p><ul class="targets"><li v-for="a in targets" :key="a.id">{{ a.email || a.name }}<span v-if="!a.enabled">已停用</span></li></ul><div class="muted"><p>保留启用状态、分组和账号代理</p><p>密码、2FA 密钥和 RT 不在页面展示</p></div><p v-if="error" class="danger">{{ error }}</p>
      <template #footer><ZButton :disabled="busy" @click="showConfirm = false">取消</ZButton><ZButton type="primary" :loading="busy" @click="submit"><template #icon><KeyRound :size="16" /></template>确认重新授权</ZButton></template>
    </ZDialog>
  </main>
</template>
