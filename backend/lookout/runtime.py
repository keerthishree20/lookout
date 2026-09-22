"""System configuration the Super Admin can change without a restart.

Initial values come from the environment; after that the Super Admin's
``PUT /api/admin/config`` is the source of truth until the process restarts.
Security thresholds live in :mod:`lookout.policy`; this is the operational side.
"""

from __future__ import annotations

import os
import threading
from typing import Any

from .models import Role

_lock = threading.Lock()

CONFIG: dict[str, Any] = {
    #: Background benign activity for the demo.
    "live_traffic": os.getenv("LOOKOUT_LIVE_TRAFFIC", "1") != "0",
    #: Seconds between background events.
    "traffic_interval": float(os.getenv("LOOKOUT_TRAFFIC_INTERVAL", "1.5")),
    #: List the demo credentials on the sign-in page.
    "show_demo_accounts": os.getenv("LOOKOUT_SHOW_DEMO_ACCOUNTS", "1") == "1",
    #: Allow the audit-forgery and artefact-tamper demo buttons.
    "allow_tamper_demo": os.getenv("LOOKOUT_ALLOW_TAMPER", "1") == "1",
    #: Ask for a one-time code when a sign-in scores MEDIUM.
    "login_mfa": True,
}

_VALIDATORS = {
    "live_traffic": bool,
    "traffic_interval": lambda v: max(0.3, min(30.0, float(v))),
    "show_demo_accounts": bool,
    "allow_tamper_demo": bool,
    "login_mfa": bool,
}


def update(changes: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    unknown = set(changes) - set(CONFIG)
    if unknown:
        raise ValueError(f"unknown settings: {sorted(unknown)}")
    with _lock:
        before = dict(CONFIG)
        for k, v in changes.items():
            CONFIG[k] = _VALIDATORS[k](v)
        return before, dict(CONFIG)


#: Role changes made by a privileged administrator in the portal: the access
#: layer uses these instead of the roster role. Keyed by username.
ROLE_OVERRIDES: dict[str, Role] = {}
