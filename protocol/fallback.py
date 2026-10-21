"""Workspace selection on the original RS-owned authorization flow."""
import base64
import json
import re
import time
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit


class WorkspaceUnavailable(ValueError):
    def __init__(self, personal_id):
        super().__init__("workspace")
        self.personal_id = personal_id


class WorkspaceUpgrade(ValueError):
    def __init__(self, workspace_id):
        super().__init__('workspace')
        self.workspace_id = workspace_id


def team_candidate(session, original, *, allow_original=False):
    if not isinstance(session, dict):
        return None
    workspaces = session.get('workspaces')
    if not isinstance(workspaces, list):
        return None
    if len(workspaces) > 30 or any(not isinstance(w, dict) or not isinstance(w.get('id'), str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', w['id']) for w in workspaces):
        raise ValueError('workspace_evidence_invalid')
    if len({w['id'] for w in workspaces}) != len(workspaces):
        raise ValueError('workspace_evidence_invalid')
    candidates = []
    for workspace in workspaces:
        if workspace['id'] == original and not allow_original:
            continue
        kinds = {str(workspace.get(k) or '').strip().lower() for k in ['type', 'account_type', 'kind']}
        plan = str(workspace.get('plan_type') or '').strip().lower()
        # Current consent pages identify team memberships as kind=organization.
        # This is only a candidate: recover_team still requires both exchanged
        # tokens to prove the same user, workspace and actual Team/Business plan.
        if (kinds & {'team', 'business', 'organization'} or plan in {'team', 'business'}) and not (workspace.get('is_personal') is True or kinds & {'personal', 'individual'} or plan not in {'', 'team', 'business'}):
            candidates.append(workspace['id'])
    if len(candidates) > 1:
        raise ValueError('workspace')
    return candidates[0] if candidates else None


def merge_workspace_evidence(*sources):
    merged = {}
    for source in sources:
        if not isinstance(source, dict):
            continue
        entries = source.get('workspaces', [])
        if not isinstance(entries, list):
            continue
        if any(not isinstance(w, dict) or not isinstance(w.get('id'), str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', w['id']) for w in entries):
            raise ValueError('workspace_evidence_invalid')
        if len({w['id'] for w in entries}) != len(entries):
            raise ValueError('workspace_evidence_invalid')
        for entry in entries:
            record = merged.setdefault(entry['id'], {'id': entry['id']})
            for key in ['type', 'account_type', 'kind', 'plan_type', 'is_personal']:
                value = entry.get(key)
                if value is None or value == '':
                    continue
                if key in record and record[key] != value:
                    raise ValueError('workspace_evidence_invalid')
                record[key] = value
        if len(merged) > 30:
            raise ValueError('workspace_evidence_invalid')
    return {'workspaces': list(merged.values())}


def free_workspace_candidate(session, original, *, allow_original=False):
    """Choose only an unambiguous candidate; issued tokens must still prove Free."""
    if not isinstance(session, dict):
        raise ValueError('free_workspace_missing')
    workspaces = session.get('workspaces', [])
    if not isinstance(workspaces, list) or any(not isinstance(w, dict) for w in workspaces):
        raise ValueError('free_workspace_missing')
    if len(workspaces) > 30:
        raise ValueError('free_workspace_ambiguous')
    if not workspaces and session.get('workspace_id'):
        workspaces = [{'id': session['workspace_id']}]
    seen, personal, unknown = set(), [], []
    for workspace in workspaces:
        wid = workspace.get('id')
        if not isinstance(wid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', wid):
            raise ValueError('free_workspace_missing')
        if wid in seen:
            raise ValueError('free_workspace_ambiguous')
        seen.add(wid)
        if wid == original and not allow_original:
            continue
        kinds = [str(workspace.get(key) or '').strip().lower() for key in ['type', 'account_type', 'kind']]
        plan = str(workspace.get('plan_type') or '').strip().lower()
        if plan not in {'', 'free'} or workspace.get('is_personal') is False:
            continue
        if any(kind and kind not in {'personal', 'individual'} for kind in kinds):
            continue
        if workspace.get('is_personal') is True or any(kinds) or plan == 'free':
            personal.append(wid)
        else:
            unknown.append(wid)
    if len(personal) == 1:
        return personal[0]
    if len(personal) > 1 or len(unknown) > 1:
        raise ValueError('free_workspace_ambiguous')
    if len(unknown) == 1 and len(workspaces) == 1:
        return unknown[0]
    raise ValueError('free_workspace_missing')


def personal_candidate(session, original):
    if not isinstance(session, dict) or not original:
        raise ValueError("workspace")
    workspaces = session.get("workspaces")
    if not isinstance(workspaces, list) or not workspaces or any(not isinstance(w, dict) or not isinstance(w.get("id"), str) or not w["id"] for w in workspaces):
        raise ValueError("workspace")
    if any(w["id"] == original for w in workspaces) or session.get("workspace_id") == original:
        raise ValueError("workspace")
    candidates = []
    for workspace in workspaces:
        kind = str(workspace.get("type") or workspace.get("account_type") or workspace.get("kind") or "").lower()
        plan = str(workspace.get("plan_type") or "").strip().lower()
        if (workspace.get("is_personal") is True or kind in {"personal", "individual"}) and plan in {"", "free"}:
            candidates.append(workspace["id"])
    if len({w["id"] for w in workspaces}) != len(workspaces) or len(candidates) != 1:
        raise ValueError("workspace")
    return candidates[0]


def automatic_free_candidate(session, original):
    personal = personal_candidate(session, original)
    if len(session['workspaces']) != 1:
        raise ValueError('workspace')
    return personal


def claims(token):
    if not isinstance(token, str) or len(token) > 32768:
        raise ValueError("fallback_identity")
    try:
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise ValueError()
        value = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("fallback_identity") from None


def verify_free_tokens(tokens, email, user_id, workspace, *, force=False):
    verified, _, _ = verify_tokens(tokens, email, user_id, workspace, force=force)
    return verified


def verify_tokens(tokens, email, user_id, workspace=None, *, force=False, require_refresh=True):
    keys = ["access_token", "id_token"] + (["refresh_token"] if require_refresh else [])
    if not isinstance(tokens, dict) or any(not isinstance(tokens.get(key), str) or not tokens[key] or len(tokens[key]) > 32768 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in tokens[key]) for key in keys):
        raise ValueError("fallback_identity")
    identity = claims(tokens.get("id_token"))
    access = claims(tokens.get("access_token"))
    identity_auth = identity.get("https://api.openai.com/auth") or {}
    access_auth = access.get("https://api.openai.com/auth") or {}
    profile = identity.get("https://api.openai.com/profile")
    actual_email = identity.get("email") or (profile.get("email") if isinstance(profile, dict) else None)
    if not isinstance(user_id, str) or not user_id or not isinstance(email, str) or not isinstance(actual_email, str) or actual_email.casefold() != email.casefold() or not isinstance(identity.get("sub"), str) or not identity["sub"]:
        raise ValueError("fallback_identity")
    for token in [identity, access]:
        if type(token.get("exp")) is not int or not time.time() + 30 < token["exp"] < 253402300799:
            raise ValueError("fallback_identity")
    plans = []
    for auth in [identity_auth, access_auth]:
        if not isinstance(auth, dict) or (workspace is not None and auth.get("chatgpt_account_id") != workspace) or (auth.get("chatgpt_user_id") or auth.get("user_id")) != user_id:
            raise ValueError("fallback_identity")
        plan = auth.get("chatgpt_plan_type")
        if not isinstance(plan, str) or not plan.strip() or (not force and plan.lower() != "free"):
            raise ValueError("fallback_identity")
        plans.append(plan.strip().lower())
    if len(set(plans)) != 1 or identity.get("sub") != access.get("sub"):
        raise ValueError("fallback_identity")
    workspace_ids = {auth.get("chatgpt_account_id") for auth in [identity_auth, access_auth]}
    if len(workspace_ids) != 1 or None in workspace_ids:
        raise ValueError("fallback_identity")
    return ({key: tokens[key] for key in keys}, workspace_ids.pop(), plans[0])


def recover_free(oauth, chat, authorize_url, data, personal_id, authorize, *, force=False):
    parsed = urlsplit(authorize_url)
    params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
    state = params['state']
    oauth.selected_workspace = personal_id
    result = authorize(authorize_url, state)
    if not isinstance(result, dict) or result.get("ok") is not True or result.get("state") != state or not isinstance(result.get("code"), str) or not result["code"] or not oauth.workspace_matches():
        raise ValueError("fallback_identity")
    return result


def recover_team(oauth, chat, authorize_url, data, workspace, authorize):
    oauth.selecting_team = True
    return recover_free(oauth, chat, authorize_url, data, workspace, authorize, force=True)


def recover_unbound_free(oauth, chat, authorize_url, data, authorize):
    if not data.get('userId'):
        raise ValueError('fallback_identity')
    parsed = urlsplit(authorize_url)
    params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
    state = params['state']
    oauth.unbound_workspace = True
    oauth.selected_workspace = ""
    result = authorize(authorize_url, state)
    if not isinstance(result, dict) or result.get("ok") is not True or result.get("state") != state or not isinstance(result.get("code"), str) or not result["code"]:
        raise ValueError("fallback_identity")
    workspace = oauth.selected_workspace
    if workspace == data.get("accountId") and str(data.get('planType') or '').strip().lower() != 'free':
        raise ValueError("fallback_identity")
    return result, workspace


def workspace_choices(session, original):
    if not isinstance(session, dict):
        return []
    workspaces = session.get("workspaces", [])
    if not isinstance(workspaces, list):
        return []
    result = []
    for item in workspaces:
        if not isinstance(item, dict):
            return []
        value = item.get("id")
        if not isinstance(value, str) or not 0 < len(value) <= 128 or not all(c.isascii() and (c.isalnum() or c in "_-") for c in value):
            return []
        if value != original:
            result.append({"id": value})
    if len({item["id"] for item in result}) != len(result) or len(result) > 30:
        return []
    selected = session.get("workspace_id")
    if selected and selected != original and selected not in {item["id"] for item in result}:
        if not isinstance(selected, str) or not 0 < len(selected) <= 128 or not all(c.isascii() and (c.isalnum() or c in "_-") for c in selected) or len(result) >= 30:
            return []
        result.append({"id": selected})
    return result
