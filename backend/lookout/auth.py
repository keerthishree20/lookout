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
import os
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .generator import BY_ACTOR

PBKDF2_ROUNDS = 200_000
SESSION_HOURS = 8

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

    def __init__(self, accounts=DEMO_ACCOUNTS) -> None:
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
        kind = self._accounts[username].kind
        token = secrets.token_urlsafe(32)
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
            session_id=f"portal-{secrets.token_hex(4)}",
            expires=datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS),
            profile=profile,
        )
        with self._lock:
            self._sessions[token] = session
        return session

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        s = self._sessions.get(token)
        if s is None or s.expired:
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
