"""Offline runtime and RS desktop authorization contract checks, with public fixtures only."""
from urllib.parse import urlencode


def check_runtime():
    import ssl
    import curl_cffi
    from vendor.lib.oauth_client import OAuthClient
    from vendor.lib.chatgpt_client import ChatGPTClient
    from runner import authorization
    from totp import totp_code

    assert totp_code('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', at_time=59, digits=8)[0] == '94287082'
    inner = 'https://auth.openai.com/oauth/authorize?' + urlencode({
        'response_type': 'code', 'client_id': 'fixture',
        'redirect_uri': 'http://127.0.0.1:1455/auth/callback',
        'state': 'runtime-fixture', 'code_challenge': 'a' * 43,
        'code_challenge_method': 'S256',
    })
    outer = 'https://chatgpt.com/codex/desktop-auth?' + urlencode({
        'authorize_url': inner, 'codex_streamlined_login': 'true', 'no_universal_links': '1',
    })
    resolved, state, redirect = authorization(outer)
    assert resolved == inner and state == 'runtime-fixture'
    assert redirect.geturl() == 'http://127.0.0.1:1455/auth/callback'
    assert authorization(inner) == authorization(outer)
