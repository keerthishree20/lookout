"""Security policy the Super Admin can change at runtime.

Scoring reads these values on every decision rather than baking them in as
constants, so a threshold change takes effect on the very next event. Every
change is validated here and audited by the API.
"""

from __future__ import annotations

import os
import threading
from dataclasses import asdict, dataclass, field
from typing import Any

from .models import BULK_COMMS_ROLES, CUSTOMER_COMMS_ROLES, TRANSFER_LIMITS, Role

DEFAULT_TRANSFER_LIMITS: dict[Role, int] = dict(TRANSFER_LIMITS)
DEFAULT_CUSTOMER_COMMS_ROLES: frozenset[Role] = frozenset(CUSTOMER_COMMS_ROLES)
DEFAULT_BULK_COMMS_ROLES: frozenset[Role] = frozenset(BULK_COMMS_ROLES)


@dataclass
class Policy:
    #: Lower bound of each risk band on the 0-100 score. The spec's bands:
    #: 0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL.
    medium: float = 30.0
    high: float = 60.0
    critical: float = 80.0
    #: Customer exports at or above this many records get the decoy PDF.
    honeypot_export_threshold: int = int(os.getenv("LOOKOUT_HONEYPOT_THRESHOLD", "100"))
    #: Largest single transfer per role, in rupees. Roles absent here may not
    #: move customer money at all.
    transfer_limits: dict[str, int] = field(
        default_factory=lambda: {r.value: v for r, v in DEFAULT_TRANSFER_LIMITS.items()}
    )
    # -- communication policy ------------------------------------------------ #
    #: Roles that may send customer-facing messages at all.
    customer_comms_roles: list[str] = field(
        default_factory=lambda: sorted(r.value for r in DEFAULT_CUSTOMER_COMMS_ROLES)
    )
    #: Roles that may send bulk (campaign) customer messages.
    bulk_comms_roles: list[str] = field(
        default_factory=lambda: sorted(r.value for r in DEFAULT_BULK_COMMS_ROLES)
    )
    #: Recipients above which a send counts as bulk.
    bulk_threshold: int = 50
    #: Privileged administrators (privilege level 4+) need a second factor for
    #: any customer-facing message, however low its score.
    privileged_comms_step_up: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class PolicyError(ValueError):
    pass


class PolicyStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.current = Policy()

    def update(self, changes: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Apply a partial update. Returns (before, after). Rejects anything
        that would leave the policy incoherent."""
        with self._lock:
            before = self.current.as_dict()
            merged = {**before, **{k: v for k, v in changes.items() if v is not None}}
            unknown = set(changes) - set(before)
            if unknown:
                raise PolicyError(f"unknown policy fields: {sorted(unknown)}")
            if not 0 < merged["medium"] < merged["high"] < merged["critical"] <= 100:
                raise PolicyError("thresholds must satisfy 0 < medium < high < critical <= 100")
            if not 1 <= int(merged["honeypot_export_threshold"]) <= 500:
                raise PolicyError("honeypot export threshold must be between 1 and 500")
            valid_roles = {r.value for r in Role}
            limits = {str(k): int(v) for k, v in merged["transfer_limits"].items()}
            if set(limits) - valid_roles or any(v <= 0 for v in limits.values()):
                raise PolicyError("transfer limits need known roles and positive amounts")
            merged["transfer_limits"] = limits
            for key in ("customer_comms_roles", "bulk_comms_roles"):
                roles = sorted({str(r) for r in merged[key]})
                if set(roles) - valid_roles:
                    raise PolicyError(f"{key} contains unknown roles")
                merged[key] = roles
            if set(merged["bulk_comms_roles"]) - set(merged["customer_comms_roles"]):
                raise PolicyError("every bulk-messaging role must also be allowed customer messaging")
            if not 2 <= int(merged["bulk_threshold"]) <= 100_000:
                raise PolicyError("bulk threshold must be between 2 and 100000 recipients")
            merged["bulk_threshold"] = int(merged["bulk_threshold"])
            merged["privileged_comms_step_up"] = bool(merged["privileged_comms_step_up"])
            self.current = Policy(**merged)
            _apply(self.current)
            return before, self.current.as_dict()

    def reset(self) -> None:
        with self._lock:
            self.current = Policy()
            _apply(self.current)


def _apply(policy: Policy) -> None:
    """TRANSFER_LIMITS and the comms role sets are shared by the detectors, the
    policy floors and the generator; mutate them in place so every reader sees
    the change."""
    TRANSFER_LIMITS.clear()
    TRANSFER_LIMITS.update({Role(k): v for k, v in policy.transfer_limits.items()})
    CUSTOMER_COMMS_ROLES.clear()
    CUSTOMER_COMMS_ROLES.update(Role(r) for r in policy.customer_comms_roles)
    BULK_COMMS_ROLES.clear()
    BULK_COMMS_ROLES.update(Role(r) for r in policy.bulk_comms_roles)


POLICY = PolicyStore()
