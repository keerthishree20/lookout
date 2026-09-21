"""Employee customer-data export, with a honeypot for suspicious requests.

When an employee exports customer records, Lookout decides *before* rendering
the file whether the request is suspicious. If it is, the employee receives a
decoy: the same rows they saw on screen, but with every unmasked field --
full account number, phone, email, balance -- fabricated. The download looks
identical: same filename pattern, same layout, same row count, a document
reference in the footer just like a genuine export. Nothing on screen changes.

Why deceive rather than block? A block tells an insider they have been noticed,
and they try another route. A decoy lets them believe they succeeded, gives the
SOC time, and turns the stolen file into evidence: every fabricated account
number is recorded against this export, so if one ever surfaces, it names the
person who took it.

A request is suspicious if it reaches :data:`HONEYPOT_THRESHOLD` records, or if
the risk engine would not simply allow it -- a 60-row export at 02:00 from an
unfamiliar device is as much a problem as a 500-row one at noon.
"""

from __future__ import annotations

import os
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fpdf import FPDF

from .customers import Customer, decoy_of

#: Exports at or above this many records always get the decoy.
HONEYPOT_THRESHOLD = int(os.getenv("LOOKOUT_HONEYPOT_THRESHOLD", "100"))

#: Most records one export may request.
MAX_EXPORT = 500


@dataclass
class ExportRecord:
    """One export, genuine or decoy. The ledger holds both, so a leaked file
    can be traced whichever it was."""

    doc_ref: str
    actor: str
    role: str
    requested: int
    decoy: bool
    reason: str
    ts: datetime
    risk_total: float
    action_taken: str
    audit_seq: int | None
    filename: str
    #: Canary account numbers planted in a decoy (empty for genuine exports).
    canaries: list[str] = field(default_factory=list)
    customer_ids: list[str] = field(default_factory=list)

    def as_dict(self, include_canaries: bool = True) -> dict[str, Any]:
        d = {
            "doc_ref": self.doc_ref,
            "actor": self.actor,
            "role": self.role,
            "requested": self.requested,
            "decoy": self.decoy,
            "reason": self.reason,
            "ts": self.ts.isoformat(),
            "risk_total": self.risk_total,
            "action_taken": self.action_taken,
            "audit_seq": self.audit_seq,
            "filename": self.filename,
            "canary_count": len(self.canaries),
        }
        if include_canaries:
            d["canaries"] = self.canaries
        return d


class ExportLedger:
    def __init__(self) -> None:
        self.records: list[ExportRecord] = []
        self._by_ref: dict[str, ExportRecord] = {}
        self._by_canary: dict[str, ExportRecord] = {}
        #: Employees who have been served a decoy. Once fed one, they only ever
        #: get decoys -- across sign-outs and new sessions -- until the SOC
        #: clears them: a genuine file next to a fake one is exactly the
        #: comparison that would expose the trap.
        self._caught: set[str] = set()
        self._lock = threading.Lock()

    def add(self, rec: ExportRecord) -> None:
        with self._lock:
            self.records.append(rec)
            self._by_ref[rec.doc_ref] = rec
            for acct in rec.canaries:
                self._by_canary[acct] = rec
            if rec.decoy:
                self._caught.add(rec.actor)

    def caught(self, actor: str) -> bool:
        return actor in self._caught

    def watchlist(self) -> list[str]:
        return sorted(self._caught)

    def clear(self, actor: str) -> bool:
        with self._lock:
            if actor in self._caught:
                self._caught.discard(actor)
                return True
            return False

    def honeypots(self) -> list[ExportRecord]:
        return [r for r in reversed(self.records) if r.decoy]

    def trace(self, needle: str) -> tuple[str, ExportRecord] | None:
        """Find the export behind a document reference or a leaked account number."""
        key = needle.strip().upper().replace(" ", "")
        if key in self._by_ref:
            return "doc_ref", self._by_ref[key]
        digits = "".join(ch for ch in needle if ch.isdigit())
        if digits in self._by_canary:
            return "canary_account", self._by_canary[digits]
        return None


def new_doc_ref() -> str:
    """Printed in every export's footer, genuine or decoy, so its presence is
    never a tell."""
    return f"MB-DOC-{secrets.token_hex(4).upper()}"


def is_suspicious(requested: int, action_taken: str, caught: bool = False) -> tuple[bool, str]:
    if caught:
        return True, "employee already served a decoy; on the honeypot watchlist until the SOC clears them"
    if requested >= HONEYPOT_THRESHOLD:
        return True, (
            f"bulk export of {requested} customer records "
            f"(policy threshold {HONEYPOT_THRESHOLD})"
        )
    if action_taken != "allow":
        return True, f"risk engine returned {action_taken.replace('_', ' ')} for this export"
    return False, "within policy"


def choose_rows(book: list[Customer], customer_ids: list[str] | None, count: int) -> list[Customer]:
    if customer_ids:
        wanted = set(customer_ids)
        rows = [c for c in book if c.customer_id in wanted]
    else:
        rows = book[:count]
    return rows[:MAX_EXPORT]


def poison(rows: list[Customer], book: list[Customer]) -> list[Customer]:
    return decoy_of(rows, seed=secrets.randbits(32), real=book)


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #


COLUMNS: tuple[tuple[str, float], ...] = (
    ("Customer ID", 24), ("Name", 44), ("Account no.", 32), ("Product", 28),
    ("City", 26), ("Phone", 32), ("Email", 53), ("Balance (INR)", 28), ("KYC", 10),
)  # 277 mm: the printable width of landscape A4 with 10 mm margins


class _ExportPDF(FPDF):
    """fpdf2 calls header() and footer() on every page break, which keeps the
    table header and document reference on every page without fighting the
    automatic page-break logic."""

    def __init__(self, actor: str, doc_ref: str, generated: datetime, n: int) -> None:
        super().__init__(orientation="L", unit="mm", format="A4")
        self.actor, self.doc_ref, self.generated, self.n = actor, doc_ref, generated, n

    def header(self) -> None:
        self.set_font("Helvetica", "B", 13)
        self.cell(0, 8, "Meridian Bank - Customer Export", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", size=8)
        self.set_text_color(90, 90, 90)
        self.cell(
            0, 5,
            f"Generated {self.generated:%d %b %Y %H:%M} UTC for {self.actor} - {self.n} records - "
            "CONFIDENTIAL: customer personal data",
            new_x="LMARGIN", new_y="NEXT",
        )
        self.set_text_color(0, 0, 0)
        self.ln(2)
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(230, 234, 240)
        for title, width in COLUMNS:
            self.cell(width, 6, title, border=1, fill=True)
        self.ln()
        self.set_font("Helvetica", size=7.5)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", size=7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 5, f"Ref {self.doc_ref}  -  page {self.page_no()}/{{nb}}", align="R")
        self.set_text_color(0, 0, 0)


def render_pdf(rows: list[Customer], *, actor: str, doc_ref: str, generated: datetime) -> bytes:
    """One renderer for both genuine and decoy files -- a second code path is
    exactly where a tell would creep in."""
    pdf = _ExportPDF(actor, doc_ref, generated, len(rows))
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.set_title("Meridian Bank - Customer Export")
    pdf.set_author(actor)
    pdf.set_creator("Meridian Bank Core Portal")
    # Pin the creation date to the export time, so metadata carries nothing
    # that differs between a genuine and a decoy file generated together.
    pdf.set_creation_date(generated)
    pdf.alias_nb_pages()
    pdf.add_page()
    for c in rows:
        values = (
            c.customer_id, c.name, c.account_no, c.product, c.city, c.phone,
            c.email, f"{c.balance_inr:,}", "OK" if c.kyc == "Verified" else "DUE",
        )
        for (_, width), value in zip(COLUMNS, values):
            pdf.cell(width, 5.5, value, border=1)
        pdf.ln()
    return bytes(pdf.output())


def export_filename(actor: str, generated: datetime) -> str:
    safe = "".join(ch for ch in actor if ch.isalnum() or ch in "._-")
    return f"customers_{safe}_{generated:%Y%m%d_%H%M%S}.pdf"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
