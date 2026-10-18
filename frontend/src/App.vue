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
import { displayTime, isActive, planLabel, planType, progress, resultMessage, statusText } from './format'
import { useReauthManager } from './useReauthManager'
import type { Account } from './types'

const { accounts, selected, loading, busy, error, search, plan, filter, page, pageSize, showConfirm, targets, jobOf, resultOf, ready, active, success, failed, eligibleCount, planOptions, filtered, visible, pageSelected, chosen, selectOne, selectPage, showResults, load, confirm, submit, cancel, pageCandidates, showForce, forceTarget, forceSource, forceWorkspace, forceConfirmed, canForce, openForce, submitForce, canFreeFallback, submitFreeFallback } = useReauthManager()
const statusOptions = [{ value: 'all', label: '全部状态' }, { value: 'error', label: '账号异常' }, { value: 'ready', label: '可重新授权' }, { value: 'active', label: '处理中' }, { value: 'failed', label: '本次未完成' }, { value: 'success', label: '本次成功' }, { value: 'invalid', label: '备注或代理缺失' }, { value: 'disabled', label: '已停用' }]
const columns: TableColumn<Account>[] = [{ key: 'select', label: '', width: 44 }, { key: 'identity', label: '账号', kind: 'identity', width: 300 }, { key: 'groups', label: '分组', kind: 'meta', width: 160 }, { key: 'plan', label: '订阅', width: 85 }, { key: 'status', label: '账号状态', width: 110 }, { key: 'credentials', label: '登录资料', width: 112 }, { key: 'proxy', label: '账号代理', minWidth: 165 }, { key: 'expiry', label: '访问令牌到期', width: 170 }, { key: 'result', label: '重新授权', minWidth: 210 }, { key: 'actions', label: '操作', kind: 'actions', width: 86 }]
</script>

<template>
  <main>
    <div class="counters" role="status" aria-label="授权任务统计">
      <ZButton variant="text" class="counter" :aria-pressed="filter === 'error'" aria-label="显示所有需要更新 RT 的异常账号" title="按 RS 异常状态统计，包含资料或代理未齐的账号" @click="showResults('error')"><span>可处理</span><b>{{ eligibleCount }}</b></ZButton>
      <span class="counter"><span><span>队列</span><b>{{ active }}</b></span></span>
      <ZButton type="success" variant="text" class="counter" :aria-pressed="filter === 'success'" aria-label="显示本次任务成功的账号" title="本次提交成功的账号，重新进入页面归零" @click="showResults('success')"><span>成功</span><b>{{ success }}</b></ZButton>
      <ZButton :type="failed ? 'danger' : 'default'" variant="text" class="counter" :aria-pressed="filter === 'failed'" aria-label="显示本次任务未完成的账号" title="本次提交失败、需核对或中断的账号，重新进入页面归零" @click="showResults('failed')"><span>未完成</span><b>{{ failed }}</b></ZButton>
    </div>
    <div class="toolbar">
      <ZInput v-model="search" class="search" placeholder="搜索邮箱、分组或代理" clearable aria-label="搜索账号"><template #prefix><Search :size="16" /></template></ZInput>
      <ZSelect v-model="plan" class="filter" :options="planOptions" aria-label="会员标识筛选" />
      <ZSelect v-model="filter" class="filter" :options="statusOptions" aria-label="状态筛选" />
      <div class="commands"><ZIconButton title="读取最新账号" aria-label="读取最新账号" :disabled="loading || busy" @click="load"><RefreshCw :size="17" :class="{ spin: loading }" /></ZIconButton><ZButton v-if="active" :disabled="busy" @click="cancel()"><template #icon><Square :size="14" /></template>停止队列</ZButton><ZButton type="primary" :disabled="busy || !chosen.length" @click="confirm(chosen)"><template #icon><KeyRound :size="16" /></template>重新授权所选<span v-if="chosen.length">（{{ chosen.length }}）</span></ZButton></div>
    </div>
    <div class="selection"><ZCheckbox :model-value="pageSelected" :disabled="!pageCandidates.length || busy" label="选择当前页" @change="selectPage" /><span>已选 {{ chosen.length }} / {{ filtered.length }} 个账号</span><ZIconButton v-if="selected.length" size="small" title="清空选择" aria-label="清空选择" @click="selected = []"><X :size="14" /></ZIconButton></div>
    <div v-if="error" class="message danger" role="alert"><AlertTriangle :size="16" /><span>{{ error }}</span><ZIconButton title="关闭提示" aria-label="关闭提示" @click="error = ''"><X :size="14" /></ZIconButton></div>
    <ZTable :columns="columns" :data="visible" :row-key="a => a.id" :loading="loading && !accounts.length" :empty-text="loading ? '正在读取账号' : '没有匹配的 OAuth 账号'">
      <template #select="{ row }"><ZCheckbox :model-value="selected.includes(row.id)" :disabled="!ready(row) || busy" :aria-label="`选择 ${row.email || row.name}`" @change="selectOne(row.id, $event)" /></template>
      <template #identity="{ row }"><div class="identity" :title="`${row.name}\n${row.id}`"><span class="avatar" :class="{ green: row.planType === 'team' }">{{ (row.email || row.name).slice(0, 1).toUpperCase() }}</span><div class="identity-text"><span class="email">{{ row.email || row.name }}</span><div class="mobile-details"><span>分组：{{ row.groups.map(group => group.name).join(" / ") || "未分组" }}</span><span><ZTag :type="planType(row.planType)" size="small">{{ planLabel(row.planType || 'unknown') }}</ZTag> {{ statusText(row) }}</span><span :class="{ danger: !row.proxy || !row.notesValid }">{{ !row.proxy ? '未绑定代理' : !row.notesValid ? '备注待检查' : row.proxy }}</span><span :class="{ success: resultOf(row)?.status === 'success', danger: ['failed', 'review', 'interrupted'].includes(resultOf(row)?.status || '') }">{{ progress(resultOf(row)) }}<span v-if="resultOf(row)?.message"> · {{ resultMessage(resultOf(row)) }}</span></span></div></div></div></template>
      <template #plan="{ row }"><ZTag :type="planType(row.planType)" size="small">{{ planLabel(row.planType || 'unknown') }}</ZTag></template>
      <template #groups="{ row }"><div v-if="row.groups.length" class="group-tags"><ZTag v-for="group in row.groups" :key="group.id" size="small" :title="group.name">{{ group.name }}</ZTag></div><span v-else class="muted">未分组</span></template>
      <template #status="{ row }"><span class="status" :class="{ danger: row.status === 'error', muted: !row.enabled, success: row.enabled && row.status === 'normal' }"><i></i>{{ statusText(row) }}</span></template>
      <template #credentials="{ row }"><span :class="row.notesValid ? 'success' : 'danger'">{{ row.notesValid ? '资料齐全' : '备注待检查' }}</span></template>
      <template #proxy="{ row }"><span class="proxy" :title="row.proxy || '未绑定代理'">{{ row.proxy || '未绑定代理' }}</span></template>
      <template #expiry="{ row }"><span class="date">{{ displayTime(row.accessTokenExpiresAt) }}</span></template>
      <template #result="{ row }"><div class="result" :class="{ success: resultOf(row)?.status === 'success', danger: ['failed', 'review', 'interrupted'].includes(resultOf(row)?.status || '') }"><span><RefreshCw v-if="isActive(resultOf(row))" class="spin" :size="13" /><CircleCheck v-else-if="resultOf(row)?.status === 'success'" :size="14" />{{ progress(resultOf(row)) }}</span><small v-if="resultOf(row)?.message" :title="resultMessage(resultOf(row))">{{ resultMessage(resultOf(row)) }}</small><time v-if="resultOf(row)?.finishedAt">{{ displayTime(resultOf(row)?.finishedAt) }}</time></div></template>
      <template #actions="{ row }"><ZButton v-if="canForce(row)" size="small" type="danger" :disabled="busy" @click="openForce(row)">强制写回</ZButton><ZButton v-else-if="canFreeFallback(row)" size="small" type="warning" :disabled="busy" title="退回同一用户的 Free 并停止该账号调度" @click="submitFreeFallback(row)">退回 Free</ZButton><ZIconButton v-else-if="isActive(jobOf(row))" title="取消该账号" :aria-label="`取消 ${row.email || row.name}`" :disabled="busy" @click="cancel(jobOf(row))"><Square :size="15" /></ZIconButton><ZIconButton v-else title="重新授权并写回原账号" :aria-label="`重新授权 ${row.email || row.name}`" :disabled="!ready(row) || busy" @click="confirm([row])"><KeyRound :size="17" /></ZIconButton></template>
    </ZTable>
    <ZPagination v-model:current-page="page" v-model:page-size="pageSize" :total="filtered.length" :page-sizes="[10, 20, 50, 100]" />
    <ZDialog v-model="showConfirm" title="确认重新授权" width="32rem" :show-close="!busy" :close-on-click-modal="!busy" :close-on-press-escape="!busy">
      <p>重新登录以下 {{ targets.length }} 个账号，新授权将写回原账号</p><ul class="targets"><li v-for="a in targets" :key="a.id">{{ a.email || a.name }}<span v-if="!a.enabled">已停用</span></li></ul><div class="muted"><p>保留分组和账号代理，通常保留启用状态</p><p>确认原工作区失效时，切回同一用户的 Free 并停止调度</p><p>密码、2FA 密钥和 RT 不在页面展示</p></div><p v-if="error" class="danger">{{ error }}</p>
      <template #footer><ZButton :disabled="busy" @click="showConfirm = false">取消</ZButton><ZButton type="primary" :loading="busy" @click="submit"><template #icon><KeyRound :size="16" /></template>确认重新授权</ZButton></template>
    </ZDialog>
    <ZDialog v-model="showForce" title="强制写回其他工作区" width="34rem" :show-close="!busy" :close-on-click-modal="!busy" :close-on-press-escape="!busy">
      <p>{{ forceTarget?.email || forceTarget?.name }}</p>
      <template v-if="forceSource?.workspaceChoices?.length">
        <p>请选择要写入原账号的其他工作区</p>
        <ZSelect v-model="forceWorkspace" :options="forceSource.workspaceChoices.map(w => ({ value: w.id, label: w.id }))" aria-label="目标工作区" />
        <p class="danger">将重新登录并替换原账号的工作区及授权，套餐以新授权为准，写回前会停止该账号调度</p>
        <p class="muted">仍需验证同一邮箱和用户，保留分组、代理、备注及其他配置，不显示 RT</p>
        <ZCheckbox v-model="forceConfirmed" class="force-confirm" :disabled="busy" label="我确认使用所选工作区的 RT 替换原授权，并停止该账号调度" />
      </template>
      <p v-else class="muted">旧任务未记录可用工作区，请先重新检测，取得工作区列表后再选择并确认强制写回</p>
      <p v-if="error" class="danger" role="alert">{{ error }}</p>
      <template #footer><ZButton :disabled="busy" @click="showForce = false">取消</ZButton><ZButton v-if="!forceSource?.workspaceChoices?.length" :disabled="busy || !forceTarget" @click="showForce = false; forceTarget && confirm([forceTarget])">重新检测工作区</ZButton><ZButton v-else type="danger" :loading="busy" :disabled="busy || !forceConfirmed || !forceWorkspace" @click="submitForce">确认替换并停止调度</ZButton></template>
    </ZDialog>
  </main>
</template>
