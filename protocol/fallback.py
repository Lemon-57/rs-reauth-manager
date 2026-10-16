"""Verified personal-Free recovery, using the upstream PKCE and token exchange protocol."""
import base64
import json
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit


class WorkspaceUnavailable(ValueError):
    def __init__(self, personal_id):
        super().__init__("workspace")
        self.personal_id = personal_id


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


def verify_tokens(tokens, email, user_id, workspace=None, *, force=False):
    if not isinstance(tokens, dict) or any(not isinstance(tokens.get(key), str) or not tokens[key] or len(tokens[key]) > 32768 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in tokens[key]) for key in ["access_token", "refresh_token", "id_token"]):
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
    return ({key: tokens[key] for key in ["access_token", "refresh_token", "id_token"]}, workspace_ids.pop(), plans[0])


def recover_free(oauth, chat, authorize_url, data, personal_id, authorize, *, force=False):
    from vendor.lib.utils import generate_pkce

    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(32)
    parsed = urlsplit(authorize_url)
    params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
    params.update(state=state, code_challenge=challenge, code_challenge_method="S256")
    # The RS pending verifier stays private to RS; never exchange its code with another verifier.
    oauth.oauth_client_id = params["client_id"]
    oauth.oauth_redirect_uri = params["redirect_uri"]
    oauth.selected_workspace = personal_id
    result = authorize(urlunsplit(parsed._replace(query=urlencode(params))), state)
    if not isinstance(result, dict) or result.get("ok") is not True or result.get("state") != state or not isinstance(result.get("code"), str) or not result["code"] or not oauth.workspace_matches():
        raise ValueError("fallback_identity")
    tokens = oauth._exchange_code_for_tokens(result["code"], verifier, chat.ua, chat.impersonate)
    return verify_free_tokens(tokens, data["email"], data.get("userId"), personal_id, force=force)


def recover_unbound_free(oauth, chat, authorize_url, data, authorize):
    from vendor.lib.utils import generate_pkce

    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(32)
    parsed = urlsplit(authorize_url)
    params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
    params.update(state=state, code_challenge=challenge, code_challenge_method="S256")
    oauth.oauth_client_id = params["client_id"]
    oauth.oauth_redirect_uri = params["redirect_uri"]
    oauth.unbound_workspace = True
    oauth.selected_workspace = ""
    result = authorize(urlunsplit(parsed._replace(query=urlencode(params))), state)
    if not isinstance(result, dict) or result.get("ok") is not True or result.get("state") != state or not isinstance(result.get("code"), str) or not result["code"]:
        raise ValueError("fallback_identity")
    tokens = oauth._exchange_code_for_tokens(result["code"], verifier, chat.ua, chat.impersonate)
    verified, workspace, plan = verify_tokens(tokens, data["email"], data.get("userId"), None, force=False)
    if workspace == data.get("accountId") or plan != "free":
        raise ValueError("fallback_identity")
    return verified, workspace


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
