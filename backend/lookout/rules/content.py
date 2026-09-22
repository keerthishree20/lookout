"""Detectors that read what an outbound message *says* and *carries*.

:mod:`lookout.rules.messaging` judges links, volume and who may send what.
These judge the content itself:

* ``phishing_language`` -- the NLP model (:mod:`lookout.nlp`) thinks the text
  reads like a scam, with or without a link;
* ``sensitive_data_leak`` -- account, card, Aadhaar or PAN numbers, IFSC codes
  or credentials in the body, worse when going to a personal mailbox;
* ``risky_attachment`` -- executables, macro documents, HTML attachments,
  double extensions, and large data files leaving the bank;
* ``repeated_message`` -- the same suspicious text sent again and again, the
  shape of a fraud campaign split into small batches to stay under the bulk
  threshold.

Nothing here echoes the sensitive values themselves into an explanation or
the audit log: the explanation names what kind of data it was and how many.
"""

from __future__ import annotations

import hashlib
import re

from ..baselines import Baseline
from ..context import DetectionContext
from ..models import Action, Event, Signal, ThreatClass
from ..nlp import content_model
from ..urlcheck import inspect_all

#: Probability above which the text itself counts as evidence.
PHISHING_PROBABILITY = 0.7

#: Personal mailboxes: bank data sent here has left the bank's control.
PERSONAL_MAIL_DOMAINS = (
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me",
    "protonmail.com", "rediffmail.com", "icloud.com",
)


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_AADHAAR = re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b")
_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
_ACCOUNT = re.compile(r"\b(?:a/?c|acct|account)(?:\s*(?:no\.?|number|#))?\s*[:\-]?\s*(\d{9,18})\b", re.IGNORECASE)
_CREDENTIAL = re.compile(
    r"\b(password|passwd|pwd|pin|cvv|user\s?id)\s*(?:is|:|=|-)\s*\S+", re.IGNORECASE
)


def find_sensitive(text: str) -> dict[str, int]:
    """Counts of each kind of sensitive value in ``text``. Values are never
    returned, only how many of each kind."""
    found: dict[str, int] = {}
    card_runs = list(_CARD.finditer(text))
    card_count = sum(1 for m in card_runs if _luhn(re.sub(r"\D", "", m.group(0))))
    if card_count:
        found["card number"] = card_count
    # Twelve digits inside a longer card-shaped run, or an account number, are
    # not also an Aadhaar number.
    accounts = [m.span(1) for m in _ACCOUNT.finditer(text)] + [m.span() for m in card_runs]
    aadhaar = [
        m
        for m in _AADHAAR.finditer(text)
        if len(re.sub(r"\D", "", m.group(0))) == 12
        and not any(a <= m.start() < b for a, b in accounts)
    ]
    if aadhaar:
        found["Aadhaar number"] = len(aadhaar)
    for label, pattern in (("PAN", _PAN), ("IFSC code", _IFSC), ("account number", _ACCOUNT), ("credential", _CREDENTIAL)):
        n = len(pattern.findall(text))
        if n:
            found[label] = n
    return found


def _personal_mailbox(recipient: str) -> bool:
    r = recipient.lower().strip()
    return any(r.endswith("@" + d) for d in PERSONAL_MAIL_DOMAINS)


def phishing_language(event: Event, baseline: Baseline, ctx: DetectionContext) -> list[Signal]:
    if event.action is not Action.SEND_MESSAGE or not event.message:
        return []
    text = f"{event.message.subject}\n{event.message.body}".strip()
    verdict = content_model().score(text)
    if verdict.probability < PHISHING_PROBABILITY:
        return []
    points = 10.0 + 14.0 * (verdict.probability - PHISHING_PROBABILITY) / (1 - PHISHING_PROBABILITY)
    phrases = ", ".join(f'"{p}"' for p in verdict.phrases) or "its overall wording"
    return [
        Signal(
            name="phishing_language",
            points=round(points, 1),
            explanation=(
                f"The message reads like a scam ({verdict.probability:.0%} by the content model), "
                f"driven by {phrases}."
            ),
            detail=verdict.as_dict(),
            indicates=[ThreatClass.MALICIOUS, ThreatClass.COMPROMISED],
        )
    ]


def sensitive_data_leak(event: Event, baseline: Baseline, ctx: DetectionContext) -> list[Signal]:
    if event.action is not Action.SEND_MESSAGE or not event.message:
        return []
    m = event.message
    found = find_sensitive(f"{m.subject}\n{m.body}")
    if not found:
        return []
    kinds = len(found)
    items = sum(found.values())
    points = 14.0 + 6.0 * (kinds - 1) + min(12.0, 2.0 * (items - 1))
    personal = _personal_mailbox(m.recipient)
    if personal:
        points += 14.0
    if m.recipient_count > 1:
        points += 6.0
    what = ", ".join(f"{n} {k}{'s' if n > 1 else ''}" for k, n in found.items())
    where = (
        f"to a personal mailbox ({m.recipient.split('@')[-1]})"
        if personal
        else f"to {m.recipient_count:,} recipient{'s' if m.recipient_count != 1 else ''}"
    )
    return [
        Signal(
            name="sensitive_data_leak",
            points=round(points, 1),
            explanation=f"The message contains {what}, sent {where}. The values are not repeated here.",
            detail={"found": found, "personal_mailbox": personal, "recipient_count": m.recipient_count},
            indicates=(
                [ThreatClass.MALICIOUS, ThreatClass.NEGLIGENT]
                if personal
                else [ThreatClass.NEGLIGENT, ThreatClass.MALICIOUS]
            ),
        )
    ]


_EXECUTABLE = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".apk", ".jar", ".msi", ".ps1", ".hta", ".lnk")
_MACRO = (".docm", ".xlsm", ".pptm")
_HTML = (".html", ".htm", ".svg")
_ARCHIVE = (".zip", ".rar", ".7z", ".iso")
_DATA = (".csv", ".xlsx", ".xls", ".sql", ".bak", ".db", ".json")

#: A data file above this size leaving the bank is an export, not a note.
LARGE_DATA_KB = 5_000


def _attachment_findings(name: str, size_kb: float) -> list[tuple[str, float]]:
    n = name.lower().strip()
    out: list[tuple[str, float]] = []
    parts = n.split(".")
    if len(parts) >= 3 and "." + parts[-1] in _EXECUTABLE + _HTML:
        out.append((f"{name} hides its real type behind a double extension", 30.0))
    elif n.endswith(_EXECUTABLE):
        out.append((f"{name} is an executable or script", 28.0))
    if n.endswith(_MACRO):
        out.append((f"{name} is a macro-enabled document", 18.0))
    if n.endswith(_HTML):
        out.append((f"{name} is an HTML file, a common way to deliver a fake login page", 20.0))
    if n.endswith(_ARCHIVE):
        out.append((f"{name} is an archive, which hides its contents from scanning", 8.0))
    if n.endswith(_DATA) and size_kb >= LARGE_DATA_KB:
        out.append((f"{name} is a {size_kb / 1024:.1f} MB data file", 16.0))
    return out


def risky_attachment(event: Event, baseline: Baseline, ctx: DetectionContext) -> list[Signal]:
    if event.action is not Action.SEND_MESSAGE or not event.message or not event.message.attachments:
        return []
    findings: list[tuple[str, float]] = []
    for a in event.message.attachments:
        findings.extend(_attachment_findings(a.name, a.size_kb))
    if not findings:
        return []
    points = min(40.0, sum(p for _, p in findings))
    personal = _personal_mailbox(event.message.recipient)
    if personal:
        points += 10.0
    exfil = all("data file" in f for f, _ in findings)
    return [
        Signal(
            name="risky_attachment",
            points=round(points, 1),
            explanation="; ".join(f for f, _ in findings)
            + (f"; going to a personal mailbox ({event.message.recipient.split('@')[-1]})" if personal else "")
            + ".",
            detail={
                "attachments": [a.model_dump() for a in event.message.attachments],
                "findings": [f for f, _ in findings],
                "personal_mailbox": personal,
            },
            indicates=(
                [ThreatClass.MALICIOUS, ThreatClass.NEGLIGENT]
                if exfil
                else [ThreatClass.MALICIOUS, ThreatClass.COMPROMISED]
            ),
        )
    ]


def _fingerprint(body: str) -> str:
    """Same message modulo whitespace, case and numbers (which vary per batch)."""
    norm = re.sub(r"\d+", "#", re.sub(r"\s+", " ", body.lower())).strip()
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


#: Sends of the same suspicious text within an hour that make a campaign.
REPEAT_THRESHOLD = 3


def repeated_message(event: Event, baseline: Baseline, ctx: DetectionContext) -> list[Signal]:
    """The same suspicious text sent over and over.

    Ordinary notices repeat all day ("your statement is ready"), so repetition
    alone means nothing. It counts only when the text carries a suspicious
    link or reads like a scam.
    """
    if event.action is not Action.SEND_MESSAGE or not event.message or not event.message.body:
        return []
    m = event.message
    suspicious = any(v.suspicious for v in inspect_all(m.urls)) or (
        content_model().score(m.body).probability >= PHISHING_PROBABILITY
    )
    if not suspicious:
        return []
    fp = _fingerprint(m.body)
    earlier = [
        e
        for e in ctx.recent(event.actor, event.ts, minutes=60)
        if e.action is Action.SEND_MESSAGE and e.message and _fingerprint(e.message.body) == fp
    ]
    sends = len(earlier) + 1
    if sends < REPEAT_THRESHOLD:
        return []
    reach = sum(e.message.recipient_count for e in earlier if e.message) + m.recipient_count
    return [
        Signal(
            name="repeated_message",
            points=round(12.0 + min(18.0, 3.0 * (sends - REPEAT_THRESHOLD)), 1),
            explanation=(
                f"The same suspicious message has now been sent {sends} times in an hour, "
                f"reaching {reach:,} recipients in total: a campaign split into batches."
            ),
            detail={"sends_60m": sends, "recipients_60m": reach, "fingerprint": fp},
            indicates=[ThreatClass.MALICIOUS, ThreatClass.COMPROMISED],
        )
    ]
