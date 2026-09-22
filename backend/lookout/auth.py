"""Portal accounts and sessions.

Three kinds of account: the twelve Meridian Bank employees (each mapped to
their roster identity, so what they do in the portal is scored against their
real baseline -- the two managers among them also get a team view), the SOC
analyst who watches the console, and the Super Admin who manages policy and
accounts.

Passwords are demo credentials, published in the README and on the sign-in
page on purpose -- this is a demonstration bank. They are still stored as
salted PBKDF2 hashes and compared in constant time, because the pattern is the
point: a security product that stores plaintext passwords would undercut its
own argument.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import jwt

from .generator import BY_ACTOR

log = logging.getLogger("lookout.auth")

PBKDF2_ROUNDS = 200_000
SESSION_HOURS = int(os.getenv("JWT_EXPIRES_HOURS", "8"))
JWT_ALGORITHM = "HS256"


def _jwt_secret() -> str:
    """From the environment in any real deployment. A random per-process
    secret keeps a bare ``uvicorn`` run working, at the cost of signing
    everyone out on restart -- which is said out loud rather than hidden."""
    secret = os.getenv("JWT_SECRET", "")
    if len(secret) >= 32:
        return secret
    if secret:
        log.warning("JWT_SECRET is shorter than 32 characters; using a random one instead")
    else:
        log.warning("JWT_SECRET not set; using a random per-process secret (sessions end on restart)")
    return secrets.token_urlsafe(48)

#: (username, password, kind). Employees use their roster name as username.
DEMO_ACCOUNTS: tuple[tuple[str, str, str], ...] = (
    ("r.krishnan", "Teller@Krishnan1", "employee"),
    ("s.iyer", "Teller@Iyer2", "employee"),
    ("a.fernandes", "Teller@Fernandes3", "employee"),
    ("p.nair", "Officer@Nair4", "employee"),
    ("m.d'souza", "Officer@Dsouza5", "employee"),
    ("k.venkatesh", "Analyst@Venkatesh6", "employee"),
    ("d.sharma", "Analyst@Sharma7", "employee"),
    ("l.mathew", "Manager@Mathew8", "employee"),
    ("v.rao", "Manager@Rao9", "employee"),
    ("t.banerjee", "Dba@Banerjee10", "employee"),
    ("h.qureshi", "Sysadmin@Qureshi11", "employee"),
    ("n.pillai", "Admin@Pillai12", "employee"),
    ("soc.analyst", "SocWatch@2026", "soc"),
    ("super.admin", "SuperAdmin@2026", "superadmin"),
)


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)


@dataclass
class Account:
    username: str
    kind: str  # "employee" | "soc" | "superadmin"
    salt: bytes
    digest: bytes

    def check(self, password: str) -> bool:
        return hmac.compare_digest(_hash(password, self.salt), self.digest)


@dataclass
class Session:
    token: str
    username: str
    kind: str
    session_id: str
    expires: datetime
    #: Name, role and branch, for the portal header.
    profile: dict = field(default_factory=dict)

    @property
    def expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires


class AuthStore:
    """Accounts plus live sessions. Sessions survive a demo reset so the SOC
    analyst is not signed out by pressing Reset."""

    def __init__(self, accounts=DEMO_ACCOUNTS, secret: str | None = None) -> None:
        self._secret = secret or _jwt_secret()
        self._accounts: dict[str, Account] = {}
        for username, password, kind in accounts:
            salt = os.urandom(16)
            self._accounts[username] = Account(username, kind, salt, _hash(password, salt))
        self._sessions: dict[str, Session] = {}
        #: username -> (who disabled it, why)
        self.disabled: dict[str, tuple[str, str]] = {}
        self._lock = threading.Lock()

    def stored_hash(self, username: str) -> str:
        """The stored credential in a portable form, for the users table."""
        a = self._accounts[username]
        return f"pbkdf2_sha256${PBKDF2_ROUNDS}${a.salt.hex()}${a.digest.hex()}"

    def exists(self, username: str) -> bool:
        return username in self._accounts

    def kind_of(self, username: str) -> str | None:
        acct = self._accounts.get(username)
        return acct.kind if acct else None

    def verify(self, username: str, password: str) -> bool:
        acct = self._accounts.get(username)
        if acct is None:
            # Burn the same time as a real check so response timing does not
            # reveal which usernames exist.
            _hash(password, b"\0" * 16)
            return False
        return acct.check(password)

    def open_session(self, username: str) -> Session:
        """Issue a signed JWT. The server also keeps the session, so revoking
        it or disabling the account takes effect before the token expires."""
        kind = self._accounts[username].kind
        session_id = f"portal-{secrets.token_hex(4)}"
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=SESSION_HOURS)
        token = jwt.encode(
            {"sub": username, "kind": kind, "sid": session_id, "iat": now, "exp": expires, "jti": secrets.token_hex(8)},
            self._secret,
            algorithm=JWT_ALGORITHM,
        )
        profile: dict = {"username": username, "kind": kind}
        staff = BY_ACTOR.get(username)
        if staff:
            profile.update(role=staff.role.value, city=staff.city, device=staff.device)
        elif kind == "superadmin":
            profile.update(role="super_admin", city="Head office")
        else:
            profile.update(role="soc_analyst", city="Chennai SOC")
        session = Session(
            token=token,
            username=username,
            kind=kind,
            session_id=session_id,
            expires=expires,
            profile=profile,
        )
        with self._lock:
            self._sessions[token] = session
        return session

    def get(self, token: str | None) -> Session | None:
        """Valid only if the signature checks, it has not expired, and the
        server has not ended the session since it was issued."""
        if not token:
            return None
        try:
            claims = jwt.decode(token, self._secret, algorithms=[JWT_ALGORITHM], options={"require": ["exp", "sub", "sid"]})
        except jwt.PyJWTError:
            return None
        s = self._sessions.get(token)
        if s is None or s.expired or s.username != claims["sub"] or s.session_id != claims["sid"]:
            return None
        return s

    def close(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    # -- administration ---------------------------------------------------- #

    def accounts(self) -> list[dict]:
        active: dict[str, int] = {}
        for sess in self._sessions.values():
            if not sess.expired:
                active[sess.username] = active.get(sess.username, 0) + 1
        return [
            {
                "username": a.username,
                "kind": a.kind,
                "disabled": a.username in self.disabled,
                "disabled_by": self.disabled.get(a.username, (None, None))[0],
                "disabled_reason": self.disabled.get(a.username, (None, None))[1],
                "active_sessions": active.get(a.username, 0),
            }
            for a in self._accounts.values()
        ]

    def sessions(self) -> list[Session]:
        return [s for s in self._sessions.values() if not s.expired]

    def is_disabled(self, username: str) -> bool:
        return username in self.disabled

    def disable(self, username: str, by: str, reason: str) -> int:
        """Lock the account and sign out every session it holds."""
        with self._lock:
            self.disabled[username] = (by, reason)
            doomed = [t for t, s in self._sessions.items() if s.username == username]
            for t in doomed:
                del self._sessions[t]
        return len(doomed)

    def enable(self, username: str) -> bool:
        with self._lock:
            return self.disabled.pop(username, None) is not None

    def revoke(self, session_id: str) -> Session | None:
        """End one portal session by its session ID (not its secret token)."""
        with self._lock:
            for token, sess in list(self._sessions.items()):
                if sess.session_id == session_id:
                    del self._sessions[token]
                    return sess
        return None


class LoginLimiter:
    """Brute-force brake on sign-in.

    Failed attempts per account in a sliding window, and all attempts per
    client address. Crossing either returns 429 until the window moves on.
    The engine still sees every failure it was allowed to see, so password
    guessing is both slowed down and detected.
    """

    def __init__(self, max_failures: int = 10, failure_window: int = 300, max_per_ip: int = 60, ip_window: int = 60) -> None:
        self.max_failures, self.failure_window = max_failures, failure_window
        self.max_per_ip, self.ip_window = max_per_ip, ip_window
        self._failures: dict[str, deque] = defaultdict(deque)
        self._by_ip: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    @staticmethod
    def _trim(q: deque, window: int, now: float) -> None:
        while q and now - q[0] > window:
            q.popleft()

    def check(self, username: str, ip: str) -> int | None:
        """Seconds to wait if this attempt must be refused, else None."""
        now = time.monotonic()
        with self._lock:
            f, a = self._failures[username], self._by_ip[ip]
            self._trim(f, self.failure_window, now)
            self._trim(a, self.ip_window, now)
            if len(f) >= self.max_failures:
                return int(self.failure_window - (now - f[0])) + 1
            if len(a) >= self.max_per_ip:
                return int(self.ip_window - (now - a[0])) + 1
            a.append(now)
            return None

    def failed(self, username: str) -> None:
        with self._lock:
            self._failures[username].append(time.monotonic())

    def succeeded(self, username: str) -> None:
        with self._lock:
            self._failures.pop(username, None)
