"""Small, authenticated web entry for the installed reauthorization plugin.

No OAuth implementation or account database lives here. An independent portal
administrator session gates the narrow calls to the installed RS plugin.
"""
import argparse
import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import threading
import time
from urllib.parse import urlsplit
from auth import Auth

INSTANCE = "907a9dfa-5ae5-827b-89e4-31011f60ddbf"
MAX_BODY = 520 * 1024
MAX_REPLY = 2 * 1024 * 1024
WEB = Path(__file__).resolve().parent / "web"


class Rejected(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def envelope(raw):
    value = json.loads(raw)
    if isinstance(value, dict) and "code" in value:
        if value["code"] not in (0, 200):
            raise Rejected(502, "RS 未接受请求，请核对任务状态")
        return value["data"]
    return value


def import_payload(value):
    if not isinstance(value, dict) or set(value) != {"line", "requestId"}:
        raise Rejected(400, "导入参数无效")
    import uuid
    try:
        if str(uuid.UUID(value["requestId"])) != value["requestId"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Rejected(400, "提交标识无效") from None
    text = value["line"]
    if not isinstance(text, str) or len(text.encode()) > 500 * 1024:
        raise Rejected(400, "导入内容过长")
    seen = set()
    lines = [(i, s.strip()) for i, s in enumerate(text.splitlines(), 1) if s.strip()]
    if not lines or len(lines) > 200:
        raise Rejected(400, "每批请输入 1 至 200 行账号")
    for number, line in lines:
        fields = line.split("----")
        if (len(fields) not in (3, 4) or any(not f for f in fields)
                or any(ord(c) < 32 or ord(c) == 127 for c in line)
                or len(fields[0].strip().encode()) > 254
                or re.search(r"\s", fields[0].strip())
                or fields[0].count("@") != 1
                or "." not in fields[0].split("@", 1)[1]
                or len("----".join(fields[:3]).encode()) > 2000
                or not valid_secret(fields[2])
                or len(fields) == 4 and (len(fields[3].encode()) > 32768 or re.search(r"\s", fields[3]))):
            raise Rejected(400, f"第 {number} 行格式无效，请核对 邮箱----密码----2FA 或 邮箱----密码----2FA----RT；2FA 需为有效 Base32 密钥")
        email = fields[0].casefold()
        if email in seen:
            raise Rejected(400, f"第 {number} 行邮箱重复，本批未提交")
        seen.add(email)
    # The plugin owns subscription policy, deduplication, proxy allocation and OAuth.
    return {"line": text, "requestId": value["requestId"]}


def valid_secret(value):
    secret = value.strip().replace(" ", "")
    if re.fullmatch(r"[A-Za-z2-7=]+", secret) is None:
        return False
    secret = secret.upper()
    core = secret.rstrip("=")
    return (len(core) >= 16 and len(core) % 8 in (0, 2, 4, 5, 7)
            and re.fullmatch(r"[A-Z2-7]+", core) is not None
            and ("=" not in secret or len(secret) % 8 == 0))


def public_jobs(value):
    if not isinstance(value, dict) or not isinstance(value.get("jobs"), list):
        raise Rejected(502, "插件任务列表未确认，请刷新核对")
    fields = ("requestId", "accountId", "status", "step", "message", "startedAt", "finishedAt")
    result = []
    for job in value["jobs"]:
        info = job.get("importInfo")
        if not isinstance(info, dict):
            continue
        item = {k: job.get(k) for k in fields}
        item["importInfo"] = {k: info.get(k) for k in ("line", "email")}
        result.append(item)
    return {"jobs": result}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, upstream, origin, credentials, previous_auth_port=None):
        self.upstream, self.origin = urlsplit(upstream), origin.rstrip("/")
        if self.upstream.scheme != "http" or self.upstream.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError("Upstream must be the local protected RS listener")
        parsed = urlsplit(self.origin)
        if parsed.scheme not in ("https", "http") or parsed.path or parsed.query or parsed.fragment:
            raise ValueError("Invalid public origin")
        if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError("Public origins require HTTPS")
        self.host = parsed.netloc
        self.auth = Auth(credentials)
        if previous_auth_port is not None and (not 1024 <= previous_auth_port <= 65535 or previous_auth_port == address[1]):
            raise ValueError('Invalid previous authentication listener')
        self.previous_auth_port = previous_auth_port
        self.previous_auth_until = time.monotonic() + 8 * 3600
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def previous_auth(self, cookie, logout=False):
        if (self.previous_auth_port is None or time.monotonic() >= self.previous_auth_until
                or not self.auth.token_id(cookie)):
            return False
        conn = http.client.HTTPConnection('127.0.0.1', self.previous_auth_port, timeout=3)
        try:
            headers = {'Host': self.host, 'Cookie': cookie}
            if logout:
                headers.update({'Origin': self.origin, 'Content-Type': 'application/json'})
            conn.request('POST' if logout else 'GET', '/api/logout' if logout else '/api/session',
                         body=b'{}' if logout else None, headers=headers)
            response = conn.getresponse()
            raw = response.read(1025)
            if response.status != 200 or len(raw) > 1024:
                return False
            result = json.loads(raw)
            return result.get('ok' if logout else 'authenticated') is True
        except (OSError, http.client.HTTPException, ValueError, AttributeError):
            return False
        finally:
            conn.close()

    def authenticated(self, cookie):
        return self.auth.authenticated(cookie) or self.previous_auth(cookie)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        # Never print request bodies, headers, cookies or upstream exceptions.
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "ImportPortal"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(12)

    def log_message(self, *args):
        pass

    def reply(self, status, raw, content_type="application/json; charset=utf-8", cookies=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def json_reply(self, value, status=200, cookies=()):
        self.reply(status, json.dumps(value, ensure_ascii=False).encode(), cookies=cookies)

    def read_json(self):
        if self.headers.get_content_type() != "application/json" or self.headers.get("Transfer-Encoding"):
            raise Rejected(415, "请使用 JSON 请求")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isdigit():
            raise Rejected(400, "请求长度无效")
        length = int(lengths[0])
        if length > MAX_BODY:
            raise Rejected(413, "导入内容过长，请拆分提交")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise Rejected(400, "请求不完整")
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError):
            raise Rejected(400, "请求格式无效") from None

    def upstream(self, method, path, value=None):
        headers = {"Host": self.server.host, "Accept": "application/json"}
        headers["X-API-Key"] = self.server.auth.upstream_key
        if method == "POST":
            # Browser Origin is validated at this portal's boundary. This is a
            # server-to-server API-key call; forwarding the portal Origin would
            # make the plugin's protected native-OAuth entry reject it.
            headers["Content-Type"] = "application/json"
        body = None if value is None else json.dumps(value).encode()
        conn = http.client.HTTPConnection(self.server.upstream.hostname, self.server.upstream.port, timeout=50)
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read(MAX_REPLY + 1)
            if len(raw) > MAX_REPLY:
                raise Rejected(502, "插件响应过长，请到 RS 核对任务")
            if response.status == 401 or response.status == 403 and '/api/api/' not in path:
                raise Rejected(503, "LAC-03 插件管理鉴权未确认，请联系管理员")
            if response.status >= 400:
                # Plugin faults are intentionally public and already sanitized by RS.
                try:
                    failure = json.loads(raw)
                    message = failure.get("error", {}).get("message") or failure.get('message')
                except (ValueError, AttributeError):
                    message = None
                raise Rejected(400 if response.status == 403 else response.status,
                               message if isinstance(message, str) else "RS 未接受请求，请先核对任务，勿重复提交")
            return envelope(raw)
        except (OSError, http.client.HTTPException, ValueError, KeyError):
            raise Rejected(502, "暂时无法确认 RS 响应，请刷新任务状态，勿重复提交") from None
        finally:
            conn.close()

    def plugin(self, method, route, value=None):
        self.require_auth()
        views = self.upstream("GET", "/api/admin/plugins/extensions")
        view = next((v for v in views if v["target"]["instanceId"] == INSTANCE), None)
        if view is None:
            raise Rejected(503, "LAC-03 导入插件暂不可用")
        target = view["target"]
        if (not re.fullmatch(r"[a-f0-9]{64}", target["artifactSha256"])
                or not isinstance(target["revision"], int) or target["revision"] < 0):
            raise Rejected(502, "插件版本未确认")
        path = f'/api/admin/plugins/extensions/{INSTANCE}/{target["artifactSha256"]}/{target["revision"]}/api/api/{route}'
        return self.upstream(method, path, value)

    def require_auth(self):
        if not self.server.authenticated(self.headers.get('Cookie', '')):
            raise Rejected(401, '请先登录导入网页')

    def dispatch(self):
        try:
            if self.headers.get_all("Host", []) != [self.server.host]:
                raise Rejected(400, "请求站点无效")
            if self.command == "POST" and self.headers.get_all("Origin", []) != [self.server.origin]:
                raise Rejected(403, "请求来源无效，请从本站提交")
            if self.command in ("GET", "HEAD") and self.path in ("/", "/app.js", "/style.css"):
                name, mime = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}[self.path]
                return self.reply(200, (WEB / name).read_bytes(), mime)
            if self.command == "GET" and self.path == "/healthz":
                return self.json_reply({"ok": True})
            if self.command == "GET" and self.path == "/api/session":
                return self.json_reply({"authenticated": self.server.authenticated(self.headers.get('Cookie', ''))})
            if self.command == "POST" and self.path == "/api/login":
                value = self.read_json()
                if (not isinstance(value, dict) or set(value) != {"username", "password"}
                        or not all(isinstance(v, str) and 0 < len(v) <= 1024 for v in value.values())):
                    raise Rejected(400, "请输入管理员用户名和密码")
                token, status = self.server.auth.login(value['username'], value['password'], self.headers.get('X-Real-IP', self.client_address[0]), self.headers.get('Cookie', ''))
                if status != 200:
                    raise Rejected(status, '尝试过于频繁，请稍后再试' if status == 429 else '用户名或密码不正确')
                self.server.previous_auth(self.headers.get('Cookie', ''), logout=True)
                cookie = self.server.auth.cookie(token, self.server.origin.startswith('https:'))
                return self.json_reply({"authenticated": True}, cookies=[cookie])
            if self.command == "POST" and self.path == "/api/logout":
                if self.read_json() != {}:
                    raise Rejected(400, "请求格式无效")
                old_cookie = self.headers.get('Cookie', '')
                if self.server.previous_auth(old_cookie) and not self.server.previous_auth(old_cookie, logout=True):
                    raise Rejected(503, '退出状态未确认，请稍后重试')
                self.server.auth.logout(self.headers.get('Cookie', ''))
                return self.json_reply({"ok": True}, cookies=[self.server.auth.cookie('', self.server.origin.startswith('https:'))])
            if self.command == "GET" and self.path == "/api/jobs":
                return self.json_reply(public_jobs(self.plugin("GET", "jobs")))
            if self.command == "POST" and self.path == "/api/import":
                self.require_auth()
                value = import_payload(self.read_json())
                value['groupIds'] = []
                return self.json_reply(public_jobs(self.plugin("POST", "import-line", value)))
            raise Rejected(404, "页面不存在")
        except Rejected as exc:
            self.json_reply({"error": exc.message}, exc.status)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass
        except Exception:
            self.json_reply({"error": "请求未确认，请刷新任务，勿重复提交"}, 502)

    do_GET = dispatch
    do_POST = dispatch
    do_HEAD = dispatch


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18884)
    parser.add_argument("--upstream", default="http://127.0.0.1:18118")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--previous-auth-port", type=int)
    args = parser.parse_args()
    credentials = json.loads(args.credentials.read_text())
    Server(("127.0.0.1", args.port), args.upstream, args.origin, credentials, args.previous_auth_port).serve_forever()
