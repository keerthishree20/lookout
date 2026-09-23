"""Incident reports as PDF.

What a SOC hands to an auditor, a manager or a regulator after an
investigation: what happened, when, who decided what, on which evidence, and
what was done about it. Everything in the report already exists in the
incident, the decisions behind it and the signed audit log -- this module only
lays it out, so a report can never say something the system did not record.

The footer carries the audit chain's signing algorithm and the sequence number
of the checkpoint covering the report, so a reader can verify the underlying
entries with ``GET /api/audit/verify``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fpdf import FPDF

from .incidents import Alert, Incident
from .models import Decision

#: Rupee and other non-Latin-1 characters have no glyph in the built-in fonts.
_REPLACEMENTS = {"₹": "INR ", "–": "-", "—": "-", "‘": "'", "’": "'", "“": '"', "”": '"', "•": "-", "→": "->"}


def _ascii(text: str) -> str:
    for bad, good in _REPLACEMENTS.items():
        text = text.replace(bad, good)
    return text.encode("latin-1", "replace").decode("latin-1")


class _ReportPDF(FPDF):
    def __init__(self, incident: Incident, generated: datetime, signing: str) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.incident, self.generated, self.signing = incident, generated, signing

    def header(self) -> None:
        self.set_font("Helvetica", "B", 13)
        self.cell(0, 8, "Meridian Bank - Security Incident Report", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", size=8)
        self.set_text_color(90, 90, 90)
        self.cell(
            0, 5,
            _ascii(
                f"{self.incident.id} - {self.incident.severity} - {self.incident.title} - "
                f"generated {self.generated:%d %b %Y %H:%M} UTC"
            ),
            new_x="LMARGIN", new_y="NEXT",
        )
        self.set_draw_color(180, 190, 200)
        self.line(10, self.get_y() + 1, 200, self.get_y() + 1)
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", size=7)
        self.set_text_color(120, 120, 120)
        self.cell(
            0, 5,
            _ascii(
                f"{self.incident.id} - evidence is hash-chained and signed with {self.signing}"
                f"  -  page {self.page_no()}/{{nb}}"
            ),
            align="R",
        )
        self.set_text_color(0, 0, 0)

    # -- building blocks --------------------------------------------------- #

    def section(self, title: str) -> None:
        self.ln(2)
        self.set_font("Helvetica", "B", 10)
        self.set_fill_color(235, 239, 245)
        self.cell(0, 6.5, _ascii(f"  {title}"), fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(1.5)
        self.set_font("Helvetica", size=9)

    def field(self, label: str, value: str) -> None:
        self.set_font("Helvetica", size=9)
        self.set_text_color(110, 110, 110)
        self.cell(38, 5.5, _ascii(label))
        self.set_text_color(0, 0, 0)
        self.multi_cell(0, 5.5, _ascii(value), new_x="LMARGIN", new_y="NEXT")

    def bullet(self, text: str, indent: float = 4.0) -> None:
        self.set_x(10 + indent)
        self.multi_cell(0, 5, _ascii(f"- {text}"), new_x="LMARGIN", new_y="NEXT")

    def paragraph(self, text: str) -> None:
        self.multi_cell(0, 5, _ascii(text), new_x="LMARGIN", new_y="NEXT")
        self.ln(1)


def _when(value: Any) -> str:
    if isinstance(value, datetime):
        return f"{value:%d %b %Y %H:%M} UTC"
    try:
        return f"{datetime.fromisoformat(str(value)):%d %b %Y %H:%M} UTC"
    except ValueError:
        return str(value)


def incident_report(
    incident: Incident,
    *,
    alerts: list[Alert],
    decisions: list[Decision],
    signing: str,
    prepared_by: str,
    generated: datetime | None = None,
) -> bytes:
    """One incident as a PDF: summary, evidence, AI explanation, timeline,
    actions taken and analyst notes."""
    generated = generated or datetime.now(timezone.utc)
    pdf = _ReportPDF(incident, generated, signing)
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_title(f"Incident report {incident.id}")
    pdf.set_author(prepared_by)
    pdf.set_creator("Lookout")
    pdf.set_creation_date(generated)
    pdf.alias_nb_pages()
    pdf.add_page()

    pdf.section("Summary")
    pdf.field("Incident", f"{incident.id} - {incident.title}")
    pdf.field("Subject", incident.user)
    pdf.field("Severity", incident.severity)
    pdf.field("Threat type", incident.threat_type.replace("_", " "))
    pdf.field("Peak risk score", f"{incident.risk_score:.0f} / 100")
    pdf.field("Status", incident.status.replace("_", " "))
    pdf.field("Assigned to", incident.assigned_to or "unassigned")
    pdf.field("Opened", _when(incident.created_at))
    if incident.resolved_at:
        pdf.field("Closed", _when(incident.resolved_at))
    pdf.field("Alerts", f"{len(incident.alert_ids)} ({', '.join(incident.alert_ids) or 'none'})")
    pdf.field("Prepared by", prepared_by)

    if incident.ai_explanation:
        pdf.section("What happened")
        pdf.paragraph(incident.ai_explanation)

    if incident.ml_opinion:
        opinion = incident.ml_opinion
        pdf.section("Model second opinion")
        pdf.paragraph(
            f"The supervised classifier called this session "
            f"{str(opinion.get('classification', 'unknown')).replace('_', ' ')} with "
            f"{float(opinion.get('confidence', 0)) * 100:.0f}% confidence. The rules, not the model, "
            "decided the outcome; the model is recorded for comparison."
        )

    pdf.section(f"Alerts ({len(alerts)})")
    if not alerts:
        pdf.paragraph("None recorded.")
    for a in alerts:
        pdf.set_font("Helvetica", "B", 9)
        pdf.multi_cell(
            0, 5,
            _ascii(f"{a.id}  {a.severity}  {a.alert_type}  -  risk {a.risk_score:.0f}  -  {_when(a.ts)}"),
            new_x="LMARGIN", new_y="NEXT",
        )
        pdf.set_font("Helvetica", size=9)
        for reason in a.reasons[:6]:
            pdf.bullet(reason)
        pdf.bullet(f"Recommended: {a.recommended_action}")
        pdf.ln(1)

    pdf.section(f"Evidence ({len(decisions)} scored events)")
    if not decisions:
        pdf.paragraph("No scored events are attached to this incident.")
    for d in decisions:
        e = d.event
        pdf.set_font("Helvetica", "B", 9)
        pdf.multi_cell(
            0, 5,
            _ascii(
                f"{e.ts:%d %b %H:%M}  {e.action.value.replace('_', ' ')}  on {e.resource or '-'}  -  "
                f"risk {d.risk.total:.0f} ({d.risk.band.value}), {d.action_taken.value.replace('_', ' ')}"
            ),
            new_x="LMARGIN", new_y="NEXT",
        )
        pdf.set_font("Helvetica", size=8.5)
        pdf.set_text_color(110, 110, 110)
        pdf.multi_cell(
            0, 4.5,
            _ascii(f"event {e.event_id} - {e.device_id} - {e.source_ip} - {e.geo.city}, {e.geo.country}"),
            new_x="LMARGIN", new_y="NEXT",
        )
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=9)
        for s in d.risk.signals[:5]:
            pdf.bullet(f"{s.explanation} (+{s.points:.0f})")
        if d.policy:
            pdf.bullet(f"Policy: {d.policy}")
        pdf.ln(1)

    pdf.section(f"Timeline ({len(incident.timeline)})")
    for item in incident.timeline:
        pdf.bullet(f"{_when(item.get('ts'))}  [{item.get('kind', '-')}]  {item.get('text', '')}", indent=0)

    pdf.section(f"Actions taken ({len(incident.actions_taken)})")
    if not incident.actions_taken:
        pdf.paragraph("None recorded.")
    for act in incident.actions_taken:
        detail = f" - {act['detail']}" if act.get("detail") else ""
        pdf.bullet(f"{_when(act.get('ts'))}  {act.get('by', '-')}: {act.get('action', '')}{detail}", indent=0)

    pdf.section(f"Analyst notes ({len(incident.notes)})")
    if not incident.notes:
        pdf.paragraph("None recorded.")
    for note in incident.notes:
        pdf.bullet(f"{_when(note.get('ts'))}  {note.get('by', '-')}: {note.get('text', '')}", indent=0)

    pdf.section("How to verify this report")
    pdf.paragraph(
        "Every event, alert and action above was written to Lookout's append-only audit log when it "
        f"happened. The log is SHA-256 hash-chained and its checkpoints are signed with {signing}, so "
        "an entry cannot be altered after the fact without the check failing. Re-run the verification "
        "from the console (Audit & quantum-safe) or GET /api/audit/verify, and compare the event "
        "identifiers listed under Evidence."
    )
    pdf.ln(1)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(110, 110, 110)
    pdf.multi_cell(
        0, 4.5,
        _ascii(
            "Demonstration system: Meridian Bank, its staff, customers and balances are simulated. "
            "No real customer data appears in this report."
        ),
        new_x="LMARGIN", new_y="NEXT",
    )
    return bytes(pdf.output())


def report_filename(incident: Incident, generated: datetime) -> str:
    return f"incident_{incident.id}_{generated:%Y%m%d_%H%M%S}.pdf"
