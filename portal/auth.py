"""Independent portal administrator authentication; no account credentials."""
from collections import deque
import hashlib
import hmac
from http.cookies import SimpleCookie
import secrets
import threading
import time

ROUNDS = 600_000


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), ROUNDS).hex()


class Auth:
    def __init__(self, configuration):
        self.username = configuration['username']
        self.salt = configuration['salt']
        self.digest = configuration['passwordHash']
        self.upstream_key = configuration['upstreamKey']
        if (not isinstance(self.username, str) or not self.username
                or len(bytes.fromhex(self.salt)) != 32 or len(bytes.fromhex(self.digest)) != 32
                or not isinstance(self.upstream_key, str) or not self.upstream_key):
            raise ValueError('Invalid portal authentication configuration')
        self.lock = threading.Lock()
        self.hash_slot = threading.BoundedSemaphore(1)
        self.sessions = {}
        self.attempts = {}
        self.global_attempts = deque()

    def token_id(self, cookie):
        jar = SimpleCookie()
        try:
            jar.load(cookie)
            raw = jar['import_session'].value if 'import_session' in jar else ''
        except Exception:
            return ''
        return hashlib.sha256(raw.encode()).hexdigest() if 20 <= len(raw) <= 100 else ''

    def _prune(self, now):
        self.sessions = {k: v for k, v in self.sessions.items() if v > now}
        self.attempts = {k: q for k, q in self.attempts.items() if q and q[-1] > now - 600}
        for queue in [self.global_attempts, *self.attempts.values()]:
            while queue and queue[0] <= now - 600:
                queue.popleft()

    def authenticated(self, cookie):
        with self.lock:
            token = self.token_id(cookie)
            return bool(token and self.sessions.get(token, 0) > time.monotonic())

    def login(self, username, password, source, old_cookie=''):
        source = hashlib.sha256(source.encode()).hexdigest()
        with self.lock:
            now = time.monotonic()
            self._prune(now)
            attempts = self.attempts.setdefault(source, deque())
            if len(attempts) >= 10 or len(self.global_attempts) >= 100 or len(self.attempts) > 2048:
                return None, 429
            attempts.append(now)
            self.global_attempts.append(now)
        if not self.hash_slot.acquire(blocking=False):
            return None, 429
        try:
            valid_password = hmac.compare_digest(password_hash(password, self.salt), self.digest)
            valid_user = hmac.compare_digest(username.encode(), self.username.encode())
        finally:
            self.hash_slot.release()
        if not valid_password or not valid_user:
            return None, 401
        raw = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions.pop(self.token_id(old_cookie), None)
            if len(self.sessions) >= 128:
                return None, 429
            self.sessions[hashlib.sha256(raw.encode()).hexdigest()] = time.monotonic() + 8 * 3600
        return raw, 200

    def logout(self, cookie):
        with self.lock:
            self.sessions.pop(self.token_id(cookie), None)

    @staticmethod
    def cookie(token, secure=True):
        return ('import_session=' + token + '; Path=/; HttpOnly; SameSite=Strict; Max-Age='
                + ('28800' if token else '0') + ('; Secure' if secure else ''))
