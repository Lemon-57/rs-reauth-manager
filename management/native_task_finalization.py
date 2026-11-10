"""补齐原生导入任务与固定 IPv6 归属的收尾，不重放令牌交换"""
import base64
import copy
import datetime
import hashlib
import json
import threading
import time
import urllib.parse
import uuid

from prolite_policy_service import unique_entry


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def import_details(account, started_at):
    """导入时间来自原流程回执，恢复不能重新起算有效期"""
    start = datetime.datetime.fromisoformat(started_at.replace('Z', '+00:00'))
    if start.tzinfo is None:
        raise ValueError('import_start_timezone')
    fields = {key: account[key] for key in ('notes', 'enabled', 'concurrencyLimit', 'weight', 'modelAccess')}
    fields.update(accountId=account['id'], name=account['email'], enabled=False,
                  groupIds=[g['id'] for g in account['groups']],
                  manualStartsAt=start.isoformat(),
                  manualExpiresAt=(start + datetime.timedelta(days=30)).isoformat())
    if account['planType'].strip().lower() in ('team', 'business', 'self_serve_business_prolite') and not (account.get('supplier') or '').strip():
        fields['supplier'] = 'AI_change_future'
    return fields


def token_fields(value):
    fields, pending = {}, [value]
    aliases = {'access_token': 'accessToken', 'refresh_token': 'refreshToken', 'id_token': 'idToken'}
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, entry in item.items():
                key = aliases.get(key, key)
                if key in ('accessToken', 'refreshToken', 'idToken') and isinstance(entry, str):
                    fields[key] = entry
                elif isinstance(entry, (dict, list)):
                    pending.append(entry)
        elif isinstance(item, list):
            pending.extend(item)
    return fields


def saved_identity(account, document):
    """只读取原生保存的凭据，套餐不能由分组推断"""
    facts = []
    for key in ('accessToken', 'idToken'):
        if key == 'idToken' and not document.get(key):
            continue
        part = document[key].split('.')[1]
        claim = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
        auth = claim['https://api.openai.com/auth']
        email = claim.get('email') or claim.get('https://api.openai.com/profile', {}).get('email')
        if ((key == 'accessToken' and claim['exp'] <= time.time() + 60)
                or not email or email.casefold() != account['email'].casefold()):
            raise ValueError('saved_token_email_or_expiry')
        facts.append((auth.get('chatgpt_user_id') or auth.get('user_id'),
                      auth.get('chatgpt_account_id'), auth['chatgpt_plan_type'].lower(), claim['sub']))
    if any(fact != facts[0] for fact in facts) or facts[0][:3] != (
            account['userId'], account['accountId'], account['planType'].lower()):
        raise ValueError('saved_token_identity_or_plan')
    return facts[0][2]


def install(service, daily_weights=None):
    """在校验过摘要的现行管理实现上复用分配、鉴权和原生 API"""
    OriginalPolicy = service.NativePolicy
    OriginalApplication = service.Application
    Error = service.PolicyError
    oauth_candidate = getattr(service, 'oauth_candidate', None) or __import__(
        OriginalPolicy.__module__, fromlist=['oauth_candidate']).oauth_candidate

    class Policy(OriginalPolicy):
        def preflight_imports(self, items):
            existing = self.inventory()
            fresh, seen = [], set()
            for item in items:
                if item.get('provider') != 'openai':
                    raise Error('此固定 IPv6 管理入口只接受 OpenAI OAuth 账号', 422)
                for row in service.candidates(item['data']):
                    if not oauth_candidate(row):
                        raise Error('此固定 IPv6 管理入口只接受 OAuth 账号', 422)
                    match = self.match(row, provider=item.get('provider'), existing=existing)
                    key = ('account', match['id']) if match else str(row.get('email') or '').casefold()
                    if key and key in seen:
                        raise Error('同一批次包含重复账号', 422)
                    seen.add(key)
                    if match:
                        if match['enabled'] or (match.get('capacity') or {}).get('usedSlots') != 0:
                            raise Error('已有账号须先暂停并等待请求自然完成，再更新导入凭据', 409)
                        self.entry_for(match)
                    else:
                        fresh.append({**item, 'data': row})
            if fresh:
                super().preflight_imports(fresh)

        def import_item(self, body, reservation_prefix):
            prepared = copy.deepcopy(body)
            rows = service.candidates(prepared['data'])
            if len(rows) != 1:
                raise Error('原生导入条目须包含一个账号', 422)
            match = self.match(rows[0], provider=body.get('provider'))
            settings = prepared.setdefault('settings', {})
            requested_enable = settings.get('enabled', True)
            if match:
                self.preflight_imports([body])
                incoming = token_fields(rows[0])
                if incoming.get('accessToken'):
                    saved = self.backend('/api/admin/accounts/export?' + urllib.parse.urlencode({
                        'accountIds': match['id'], 'confirm': 'export_sensitive_accounts'}))[
                            'documents'][0]['document']['accounts'][0]
                    def issued(token):
                        part = token.split('.')[1]
                        return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))['iat']
                    incoming_at, saved_at = issued(incoming['accessToken']), issued(saved['accessToken'])
                    if (incoming_at < saved_at or (incoming_at == saved_at and saved.get('refreshToken')
                            and incoming.get('refreshToken') and incoming['refreshToken'] != saved['refreshToken'])):
                        raise Error('导入凭据早于当前已保存版本，不会覆盖有效凭据', 409)
                # 原生 API 按上游身份更新同一记录；固定出口及存量调度设置不能被表单默认值覆盖
                settings.update(concurrencyLimit=match['concurrencyLimit'], weight=match['weight'],
                    groupIds=[group['id'] for group in match['groups']], modelAccess=match['modelAccess'])
                if settings.get('notes') is None:
                    settings['notes'] = match.get('notes')
            # 只作用于已通过原有去重前置的新账号，不修改全局继承值
            settings.setdefault('enabled', True)
            if not match and settings.get('concurrencyLimit') is None:
                settings['concurrencyLimit'] = 3
            settings.setdefault('weight', 1)
            settings.setdefault('groupIds', [])
            settings.setdefault('notes', None)
            transformed, allocations = super().import_item(prepared, reservation_prefix)
            if not hasattr(self, 'new_identities'):
                self.new_identities = {}
            if not hasattr(self, 'import_controls'):
                self.import_controls = {}
            for _, identity, _ in allocations:
                self.new_identities[identity] = match is None
                self.import_controls[identity] = {
                    'importStartedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'notesHash': digest(transformed['settings'].get('notes')),
                    'expectsRT': bool(token_fields(transformed['data']).get('refreshToken'))}
            return transformed, [(entry, identity, requested_enable if match else desired)
                                 for entry, identity, desired in allocations]

        def finish(self, account_ids, allocations):
            # 上次启用响应可能丢失；不能为重做收尾暂停已在处理请求的账号
            if any(self.detail(account_id)['enabled'] for account_id in account_ids):
                raise Error('导入账号已启用，请先核对原任务结果', 409)
            # 先完成原分配器的永久归属和预算登记，始终保持暂停
            super().finish(account_ids, [(entry, identity, False)
                                        for entry, identity, _ in allocations])
            desired = {identity: enabled for _, identity, enabled in allocations}
            for account_id in account_ids:
                account = self.detail(account_id)
                document = self.backend('/api/admin/accounts/export?' + urllib.parse.urlencode({
                    'accountIds': account_id, 'confirm': 'export_sensitive_accounts'}))
                documents = document['documents']
                if len(documents) != 1 or len(documents[0]['document']['accounts']) != 1:
                    raise Error('原生凭据读回不完整，账号保持暂停', 502)
                saved = documents[0]['document']['accounts'][0]
                if saved['id'] != account_id:
                    raise Error('原生凭据归属不一致，账号保持暂停', 502)
                try:
                    plan = saved_identity(account, saved)
                except (KeyError, ValueError, IndexError, TypeError):
                    raise Error('原生凭据身份或套餐不一致，账号保持暂停', 502) from None
                identity = (account['userId'], account['accountId'])
                controls = getattr(self, 'import_controls', {}).get(identity, {})
                if controls.get('expectsRT') and not saved.get('refreshToken'):
                    raise Error('原生 RT 尚未保存，账号保持暂停', 502)
                if 'notesHash' in controls and digest(account.get('notes')) != controls['notesHash']:
                    raise Error('导入备注读回不一致，账号保持暂停', 502)
                try:
                    entry = unique_entry(self.allocator, saved['outboundProxyUrl'], account_id)
                    self.allocator.verify(entry)
                except Exception:
                    raise Error('独立固定 IPv6 验证失败，账号保持暂停', 409) from None
                if controls.get('importStartedAt'):
                    try:
                        details = import_details(account, controls['importStartedAt'])
                    except (KeyError, ValueError, TypeError, OverflowError):
                        raise Error('导入开始时间未确认，账号保持暂停', 409) from None
                    self.backend('/api/admin/accounts/update', details)
                    configured = self.detail(account_id)
                    for key, value in details.items():
                        if key in ('accountId', 'groupIds'):
                            continue
                        actual = configured.get(key)
                        if key in ('manualStartsAt', 'manualExpiresAt'):
                            actual = datetime.datetime.fromisoformat((actual or '').replace('Z', '+00:00'))
                            value = datetime.datetime.fromisoformat(value)
                        if actual != value:
                            raise Error('导入邮箱、供应商或起止时间读回不一致，账号保持暂停', 502)
                    account = configured
                preserved = {key: account.get(key) for key in (
                    'userId', 'accountId', 'name', 'email', 'notes', 'modelAccess', 'outboundProxyEndpoint')}
                fields = {'accountIds': [account_id], 'enabled': desired[
                    (account['userId'], account['accountId'])]}
                if plan in ('pro', 'prolite', 'self_serve_business_prolite'):
                    groups = []
                    for page in range(1, 1001):
                        batch = self.backend('/api/admin/account-groups/options?page=' + str(page)
                                             + '&pageSize=100')['items']
                        groups.extend(g for g in batch if g['name'] == 'GPT Pro' and g['enabled'])
                        if len(batch) < 100:
                            break
                    if len(groups) != 1:
                        raise Error('需要唯一启用的 GPT Pro 分组，账号保持暂停', 409)
                    if daily_weights is None:
                        raise Error('Shared daily weight ledger unavailable; account remains paused', 503)
                    concurrency, weight = 50, daily_weights.reserve(account_id, entry['port'], plan)['weight']
                    fields.update(concurrencyLimit=concurrency, weight=weight,
                                  groupIds=[groups[0]['id']])
                    # 启用前先保存并回读配置，不能把一次写入成功当作验收
                    self.backend('/api/admin/accounts/batch-update', {**fields, 'enabled': False})
                    configured = self.detail(account_id)
                    if (configured['enabled'] or configured['concurrencyLimit'] != concurrency
                            or configured['weight'] != weight
                            or [g['id'] for g in configured['groups']] != fields['groupIds']):
                        raise Error('Pro 账号配置读回不一致，账号保持暂停', 502)
                self.backend('/api/admin/accounts/batch-update', fields)
                after = self.detail(account_id)
                if after['enabled'] != fields['enabled']:
                    raise Error('账号启停状态读回不一致，请核对结果', 502)
                if any(after.get(key) != value for key, value in preserved.items()):
                    raise Error('账号身份或固定配置读回不一致，请核对结果', 502)
                for key in ('concurrencyLimit', 'weight'):
                    if key in fields and after.get(key) != fields[key]:
                        raise Error('账号调度配置读回不一致，请核对结果', 502)
                if 'groupIds' in fields and [g['id'] for g in after['groups']] != fields['groupIds']:
                    raise Error('账号分组读回不一致，请核对结果', 502)

    class Application(OriginalApplication):
        def finish_task(self, path, record, backend, policy):
            record = json.loads(path.read_text())
            task = backend('/api/admin/accounts/import-tasks/detail?taskId=' + urllib.parse.quote(
                record['result']['taskId'], safe=''))
            finished = set(record.get('finished', []))
            for item in task['items']:
                # RS 公开合同从 1 开始；旧保护层回执从 0 开始，恢复时只换算索引
                index = item['index'] if record.get('version') == 2 else item['index'] - 1
                if item['status'] != 'succeeded' or index in finished:
                    continue
                bindings = []
                for binding in record['bindings']:
                    if binding['index'] != index:
                        continue
                    entry = next((row for row in self.allocator.all_rows()
                                  if row['port'] == binding['port']), None)
                    if not entry:
                        raise Error('原导入代理预留缺失，账号保持暂停', 503)
                    for account_id in item['accountIds']:
                        account = policy.detail(account_id)
                        if (account['userId'], account['accountId']) != tuple(binding['identity']):
                            raise Error('导入结果与原预留身份不一致，账号保持暂停', 502)
                    bindings.append((entry, tuple(binding['identity']), binding['desired']))
                    if not hasattr(policy, 'new_identities'):
                        policy.new_identities = {}
                    policy.new_identities[tuple(binding['identity'])] = binding.get('newAccount', True)
                    if not hasattr(policy, 'import_controls'):
                        policy.import_controls = {}
                    policy.import_controls[tuple(binding['identity'])] = {
                        key: binding[key] for key in ('notesHash', 'expectsRT', 'importStartedAt') if key in binding}
                if not bindings:
                    raise Error('导入条目没有对应的原代理预留，账号保持暂停', 502)
                policy.finish(item['accountIds'], bindings)
                finished.add(index)
                record['finished'] = sorted(finished)
                service.atomic(path, record)
            return task

        def submit_task(self, body, backend, policy):
            sid, items = body.get('submissionId'), body.get('items')
            try:
                if not isinstance(items, list) or not 0 < len(items) <= 200 or uuid.UUID(sid).int == 0:
                    raise ValueError()
            except (ValueError, TypeError, AttributeError):
                raise Error('导入任务参数不正确', 400) from None
            fingerprint = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
            path = self.record_path(sid)
            if path.exists():
                prior = json.loads(path.read_text())
                if prior['digest'] != fingerprint:
                    raise Error('提交标识已用于其他导入内容', 409)
                if prior.get('result'):
                    # 用原生详情核验当前调用者权限，不能只凭提交标识返回其他管理员的任务
                    backend('/api/admin/accounts/import-tasks/detail?taskId=' +
                            urllib.parse.quote(prior['result']['taskId'], safe=''))
                    return prior['result']
                raise Error('上次原生提交结果待核对，不会重复交换 RT', 409)
            policy.preflight_imports(items)
            prepared = copy.deepcopy(body)
            prepared['items'] = []
            record = {'version': 2, 'digest': fingerprint, 'bindings': [], 'finished': []}
            # 在可能消耗 RT 前写入意图；取消或进程退出后不自动重放
            service.atomic(path, record)
            for item in items:
                for row in service.candidates(item['data']):
                    one = copy.deepcopy(item)
                    one['data'] = row
                    if row.get('notes') is not None:
                        one.setdefault('settings', {})['notes'] = row['notes']
                    index = len(prepared['items']) + 1
                    transformed, allocations = policy.import_item(one, 'task:' + sid + ':' + str(index))
                    for entry, identity, desired in allocations:
                        record['bindings'].append({'index': index, 'port': entry['port'],
                            'identity': list(identity), 'desired': desired,
                            'newAccount': getattr(policy, 'new_identities', {}).get(identity, True),
                            'importStartedAt': policy.import_controls[identity]['importStartedAt'],
                            'expectsRT': bool(token_fields(transformed['data']).get('refreshToken')),
                            'notesHash': digest(transformed['settings'].get('notes'))})
                    prepared['items'].append(transformed)
                    service.atomic(path, record)
            result = backend('/api/admin/accounts/import-tasks', prepared)
            record['result'] = result
            service.atomic(path, record)

            def follow():
                try:
                    deadline = time.monotonic() + 1800
                    while time.monotonic() < deadline:
                        with service.MUTATION:
                            task = self.finish_task(path, record, backend, policy)
                        if task.get('finishedAt'):
                            break
                        time.sleep(2)
                except Exception:
                    # 仅允许客户端以新鉴权轮询原任务收尾，不重放导入或交换
                    pass
                finally:
                    with service.MUTATION:
                        self.workers.discard(result['taskId'])

            self.workers.add(result['taskId'])
            threading.Thread(target=follow, daemon=True).start()
            return result

    service.NativePolicy = Policy
    service.Application = Application
