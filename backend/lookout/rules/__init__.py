"""Deterministic detectors.

The machine-learning model in :mod:`lookout.anomaly` is good at "this is
unusual" and bad at saying why. These rules are the opposite: each encodes one
crisp, auditable statement about banking risk, and each returns a
:class:`~lookout.models.Signal` carrying the sentence a SOC analyst will read.
Together they are the explainable half of the score.

A detector is any callable ``(event, baseline, ctx) -> list[Signal]``. Adding
one is a matter of writing the function and listing it in :data:`DETECTORS`.
"""

from __future__ import annotations

from typing import Callable, Sequence

from ..baselines import Baseline
from ..context import DetectionContext
from ..models import Event, Signal

Detector = Callable[[Event, Baseline, DetectionContext], list[Signal]]

from .data import (  # noqa: E402
    bulk_file_write,
    mass_record_access,
    off_hours_data_access,
    vault_hoarding,
)
from .identity import (  # noqa: E402
    abnormal_login_time,
    credential_misuse,
    failed_login_burst,
    impossible_travel,
    new_device_or_network,
    containment_breach,
)
from .messaging import (  # noqa: E402
    bulk_message_blast,
    suspicious_url,
    unauthorized_customer_comms,
)
from .privilege import (  # noqa: E402
    dormant_privileged_account,
    out_of_scope_admin_action,
    privilege_escalation,
)

#: Evaluation order is irrelevant -- every detector sees the same event and the
#: same baseline, and their points sum. Keep them grouped for readability.
DETECTORS: Sequence[Detector] = (
    # identity
    impossible_travel,
    abnormal_login_time,
    new_device_or_network,
    failed_login_burst,
    credential_misuse,
    containment_breach,
    # privilege
    privilege_escalation,
    out_of_scope_admin_action,
    dormant_privileged_account,
    # data
    mass_record_access,
    off_hours_data_access,
    bulk_file_write,
    vault_hoarding,
    # messaging
    suspicious_url,
    bulk_message_blast,
    unauthorized_customer_comms,
)


def run_detectors(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Run every detector and collect whatever fired."""
    signals: list[Signal] = []
    for detector in DETECTORS:
        signals.extend(detector(event, baseline, ctx))
    return signals


__all__ = ["DETECTORS", "Detector", "run_detectors"]
