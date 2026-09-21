"""Core domain types for Lookout.

Everything that flows through the pipeline is an :class:`Event`. Everything that
comes out is a :class:`Decision`. The types in between (:class:`Signal`,
:class:`RiskScore`) exist so that every number on the dashboard can be traced
back to the rule or model that produced it -- that is the whole point of the
explainability requirement.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Role(str, enum.Enum):
    """Job roles, ordered by how much damage the holder can do."""

    TELLER = "teller"
    OFFICER = "officer"
    ANALYST = "analyst"
    MANAGER = "manager"
    DBA = "dba"
    SYSADMIN = "sysadmin"
    DOMAIN_ADMIN = "domain_admin"


#: Privilege level per role, 1 (lowest) .. 6 (highest). Used both as a risk
#: multiplier and to decide whether an action is in scope for the actor.
PRIVILEGE_LEVEL: dict[Role, int] = {
    Role.TELLER: 1,
    Role.OFFICER: 2,
    Role.ANALYST: 2,
    Role.MANAGER: 3,
    Role.DBA: 4,
    Role.SYSADMIN: 5,
    Role.DOMAIN_ADMIN: 6,
}

#: Roles permitted to send customer-facing communication at all.
CUSTOMER_COMMS_ROLES: frozenset[Role] = frozenset(
    {Role.OFFICER, Role.MANAGER, Role.DOMAIN_ADMIN}
)

#: Roles permitted to send *bulk* customer communication (campaigns).
BULK_COMMS_ROLES: frozenset[Role] = frozenset({Role.MANAGER, Role.DOMAIN_ADMIN})


class Action(str, enum.Enum):
    """The verbs Lookout understands."""

    LOGIN = "login"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PRIV_ESCALATE = "priv_escalate"
    DB_QUERY = "db_query"
    FILE_ACCESS = "file_access"
    CONFIG_CHANGE = "config_change"
    SEND_MESSAGE = "send_message"
    VAULT_READ = "vault_read"


class ThreatClass(str, enum.Enum):
    """CERT-style insider taxonomy, plus a benign bucket."""

    BENIGN = "benign"
    NEGLIGENT = "negligent"
    MALICIOUS = "malicious"
    COMPROMISED = "compromised"
    PRIVILEGE_ABUSE = "privilege_abuse"


class ActionTaken(str, enum.Enum):
    """Graded response. Ordered from least to most disruptive."""

    ALLOW = "allow"
    STEP_UP = "step_up"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    BLOCK_AND_ALERT = "block_and_alert"


class Band(str, enum.Enum):
    """Traffic-light band the risk score falls into."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Geo(BaseModel):
    """Where an event came from. Coordinates are what impossible-travel uses."""

    city: str
    country: str
    lat: float
    lon: float


class MessagePayload(BaseModel):
    """Attached to :attr:`Action.SEND_MESSAGE` events."""

    channel: str = "sms"
    recipient_count: int = 1
    audience: str = "internal"  # internal | customer
    subject: str = ""
    body: str = ""
    urls: list[str] = Field(default_factory=list)


class Event(BaseModel):
    """One observed action by one identity."""

    event_id: str
    ts: datetime
    actor: str
    actor_role: Role
    action: Action
    resource: str = ""
    source_ip: str = "0.0.0.0"
    device_id: str = "unknown"
    geo: Geo
    success: bool = True
    message: MessagePayload | None = None
    #: Free-form extras: ``record_count``, ``target_role``, ``session_id`` ...
    meta: dict[str, Any] = Field(default_factory=dict)
    #: Ground-truth label, present only on generated data. Never read by the
    #: detectors -- it exists so :mod:`lookout.evaluate` can score them.
    label: ThreatClass | None = None
    scenario: str | None = None

    @property
    def privilege(self) -> int:
        return PRIVILEGE_LEVEL[self.actor_role]


class Signal(BaseModel):
    """One detector firing on one event.

    ``points`` is the detector's own contribution to the risk score before the
    privilege multiplier is applied. ``explanation`` is a complete sentence,
    because it is rendered verbatim in the SOC console.
    """

    name: str
    points: float
    explanation: str
    detail: dict[str, Any] = Field(default_factory=dict)
    #: Which threat classes this signal is evidence for.
    indicates: list[ThreatClass] = Field(default_factory=list)


class RiskScore(BaseModel):
    """The fused score and the arithmetic that produced it."""

    total: float
    band: Band
    rule_points: float
    model_points: float
    privilege_multiplier: float
    signals: list[Signal] = Field(default_factory=list)


class Decision(BaseModel):
    """What Lookout did about an event, and why."""

    event: Event
    risk: RiskScore
    action_taken: ActionTaken
    threat_class: ThreatClass
    narrative: str = ""
    audit_seq: int | None = None
    #: Only set for message events that were held rather than delivered.
    quarantine_id: str | None = None
    #: Set when a hard policy raised the response above what the score alone
    #: would have produced. The wording is shown to the analyst verbatim.
    policy: str | None = None
