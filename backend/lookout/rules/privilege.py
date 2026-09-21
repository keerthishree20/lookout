"""Detectors about privileged access -- the PAM half of the brief."""

from __future__ import annotations

from ..baselines import Baseline
from ..context import DetectionContext
from ..models import PRIVILEGE_LEVEL, Action, Event, Role, Signal, ThreatClass

#: Which roles may legitimately perform each sensitive action. Anything else
#: doing them is out of scope, regardless of whether the platform allows it.
ACTION_SCOPE: dict[Action, frozenset[Role]] = {
    Action.CONFIG_CHANGE: frozenset({Role.SYSADMIN, Role.DOMAIN_ADMIN}),
    Action.VAULT_READ: frozenset({Role.SYSADMIN, Role.DOMAIN_ADMIN, Role.DBA}),
    Action.PRIV_ESCALATE: frozenset({Role.SYSADMIN, Role.DOMAIN_ADMIN}),
}

#: Escalation attempts in the window before it stops looking like a mistake.
ESCALATION_BURST = 3

#: Days of silence after which a privileged account waking up is notable.
DORMANT_DAYS = 45


def privilege_escalation(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """An identity reaching for rights above its own.

    Scored on the size of the jump: teller to domain admin is a different event
    from DBA to sysadmin, and a flat "escalation detected" alert loses that.
    """
    if event.action is not Action.PRIV_ESCALATE:
        return []

    target = event.meta.get("target_role")
    try:
        target_role = Role(target) if target else None
    except ValueError:
        target_role = None
    if target_role is None:
        return []

    held = PRIVILEGE_LEVEL[event.actor_role]
    sought = PRIVILEGE_LEVEL[target_role]
    if sought <= held:
        return []

    jump = sought - held
    attempts = ctx.count(event.actor, Action.PRIV_ESCALATE, event.ts, minutes=15) + 1
    points = 20.0 + 10.0 * jump + (10.0 if attempts >= ESCALATION_BURST else 0.0)
    if not event.success:
        points *= 0.8  # a blocked attempt is intent without impact

    outcome = "succeeded" if event.success else "was rejected by the platform"
    burst = (
        f" This is attempt {attempts} in 15 minutes."
        if attempts >= ESCALATION_BURST
        else ""
    )
    return [
        Signal(
            name="privilege_escalation",
            points=points,
            explanation=(
                f"{event.actor} holds {event.actor_role.value} (level {held}) and "
                f"requested {target_role.value} (level {sought}) on {event.resource or 'an internal system'}"
                f" -- a {jump}-level jump that {outcome}.{burst}"
            ),
            detail={
                "held_role": event.actor_role.value,
                "target_role": target_role.value,
                "levels_jumped": jump,
                "attempts_15m": attempts,
                "succeeded": event.success,
            },
            indicates=[ThreatClass.PRIVILEGE_ABUSE, ThreatClass.MALICIOUS],
        )
    ]


def out_of_scope_admin_action(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """A sensitive action performed by a role that has no business doing it."""
    allowed = ACTION_SCOPE.get(event.action)
    if allowed is None or event.actor_role in allowed:
        return []
    return [
        Signal(
            name="out_of_scope_admin_action",
            points=22.0,
            explanation=(
                f"{event.action.value.replace('_', ' ')} on {event.resource or 'an internal system'} "
                f"is restricted to {', '.join(sorted(r.value for r in allowed))}, but "
                f"{event.actor} is a {event.actor_role.value}."
            ),
            detail={
                "action": event.action.value,
                "actor_role": event.actor_role.value,
                "permitted_roles": sorted(r.value for r in allowed),
            },
            indicates=[ThreatClass.PRIVILEGE_ABUSE],
        )
    ]


def dormant_privileged_account(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """A high-privilege account that has been silent for weeks suddenly acting.

    Dormant admin and service accounts are a favourite foothold precisely
    because nobody is watching them.
    """
    if PRIVILEGE_LEVEL[event.actor_role] < 4 or baseline.last_login_ts is None:
        return []
    idle_days = (event.ts - baseline.last_login_ts).total_seconds() / 86400.0
    if idle_days < DORMANT_DAYS:
        return []
    return [
        Signal(
            name="dormant_privileged_account",
            points=18.0,
            explanation=(
                f"{event.actor} ({event.actor_role.value}) had been inactive for "
                f"{idle_days:.0f} days before this {event.action.value.replace('_', ' ')}."
            ),
            detail={"idle_days": round(idle_days, 1)},
            indicates=[ThreatClass.COMPROMISED, ThreatClass.PRIVILEGE_ABUSE],
        )
    ]
