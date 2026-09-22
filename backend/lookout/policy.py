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

from .models import TRANSFER_LIMITS, Role

DEFAULT_TRANSFER_LIMITS: dict[Role, int] = dict(TRANSFER_LIMITS)


@dataclass
class Policy:
    #: Lower bound of each risk band on the 0-100 score.
    medium: float = 30.0
    high: float = 60.0
    critical: float = 85.0
    #: Customer exports at or above this many records get the decoy PDF.
    honeypot_export_threshold: int = int(os.getenv("LOOKOUT_HONEYPOT_THRESHOLD", "100"))
    #: Largest single transfer per role, in rupees. Roles absent here may not
    #: move customer money at all.
    transfer_limits: dict[str, int] = field(
        default_factory=lambda: {r.value: v for r, v in DEFAULT_TRANSFER_LIMITS.items()}
    )

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
            limits = {str(k): int(v) for k, v in merged["transfer_limits"].items()}
            valid_roles = {r.value for r in Role}
            if set(limits) - valid_roles or any(v <= 0 for v in limits.values()):
                raise PolicyError("transfer limits need known roles and positive amounts")
            merged["transfer_limits"] = limits
            self.current = Policy(**merged)
            _apply_limits(limits)
            return before, self.current.as_dict()

    def reset(self) -> None:
        with self._lock:
            self.current = Policy()
            _apply_limits(self.current.transfer_limits)


def _apply_limits(limits: dict[str, int]) -> None:
    """TRANSFER_LIMITS is shared by the detector, the policy floor and the
    generator; mutate it in place so every reader sees the change."""
    TRANSFER_LIMITS.clear()
    TRANSFER_LIMITS.update({Role(k): v for k, v in limits.items()})


POLICY = PolicyStore()
