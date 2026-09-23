"""Sending critical alerts out of Lookout: webhook and email.

An alert nobody sees is not a control. This delivers CRITICAL alerts to a chat
webhook (Slack, Discord, Google Chat, Teams or a Telegram bot) and/or to an
email address through Brevo's HTTP API, so an analyst gets them on a phone
rather than only in an open browser tab.

Three rules, because a notifier sits on the hot path of the detection engine:

* **Never block.** Sending happens on a worker thread; the engine returns at once.
* **Never crash.** A refused webhook or an expired API key is logged and counted,
  never raised into the pipeline.
* **Never flood.** At most ``max_per_hour`` messages, and the same alert type for
  the same person is not repeated within ``cooldown_seconds``.

Configuration comes from the environment and can be changed at runtime by the
Super Admin. With nothing configured, it is simply off, and the console says so.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

log = logging.getLogger("lookout.notify")

BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class NotifySettings:
    """Where alerts go. ``webhook_url`` accepts any endpoint that takes a JSON
    POST; Telegram bot URLs are detected and given their own payload shape."""

    enabled: bool = True
    webhook_url: str = ""
    #: Telegram only: the chat to post to (the bot token is in the URL).
    telegram_chat_id: str = ""
    email_to: str = ""
    email_from: str = ""
    brevo_api_key: str = ""
    #: Only alerts at or above this severity are sent.
    min_severity: str = "CRITICAL"
    max_per_hour: int = 20
    cooldown_seconds: int = 300

    @classmethod
    def from_env(cls) -> "NotifySettings":
        return cls(
            enabled=os.getenv("LOOKOUT_NOTIFY", "1") != "0",
            webhook_url=os.getenv("ALERT_WEBHOOK_URL", "").strip(),
            telegram_chat_id=os.getenv("ALERT_TELEGRAM_CHAT_ID", "").strip(),
            email_to=os.getenv("ALERT_EMAIL_TO", "").strip(),
            email_from=os.getenv("ALERT_EMAIL_FROM", "").strip() or os.getenv("BREVO_SENDER", "").strip(),
            brevo_api_key=os.getenv("BREVO_API_KEY", "").strip(),
            min_severity=os.getenv("ALERT_MIN_SEVERITY", "CRITICAL").upper(),
            max_per_hour=int(os.getenv("ALERT_MAX_PER_HOUR", "20")),
            cooldown_seconds=int(os.getenv("ALERT_COOLDOWN_SECONDS", "300")),
        )

    def as_dict(self, *, redact: bool = True) -> dict[str, Any]:
        d = {
            "enabled": self.enabled,
            "webhook_url": _redact_url(self.webhook_url) if redact else self.webhook_url,
            "telegram_chat_id": self.telegram_chat_id,
            "email_to": self.email_to,
            "email_from": self.email_from,
            "brevo_api_key": ("set" if self.brevo_api_key else "") if redact else self.brevo_api_key,
            "min_severity": self.min_severity,
            "max_per_hour": self.max_per_hour,
            "cooldown_seconds": self.cooldown_seconds,
        }
        d["channels"] = self.channels()
        return d

    def channels(self) -> list[str]:
        out = []
        if self.webhook_url:
            out.append("telegram" if "api.telegram.org" in self.webhook_url else "webhook")
        if self.email_to and self.brevo_api_key and self.email_from:
            out.append("email")
        return out


def _redact_url(url: str) -> str:
    """Webhook URLs are secrets: Slack, Discord and Telegram all carry the
    token in the path, often in its last segment. Show the host and nothing
    else, so the console can say where alerts go without leaking the key."""
    if not url:
        return ""
    host = url.partition("?")[0].split("/")
    return "/".join(host[:3]) + "/..." if len(host) > 3 else url


SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


@dataclass
class Delivery:
    ts: datetime
    channel: str
    alert_id: str
    ok: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts.isoformat(), "channel": self.channel,
            "alert_id": self.alert_id, "ok": self.ok, "detail": self.detail,
        }


class Notifier:
    """Queues alerts and delivers them on one background thread."""

    def __init__(self, settings: NotifySettings | None = None, transport: Any | None = None) -> None:
        self.settings = settings or NotifySettings.from_env()
        #: Injected in tests; otherwise httpx.
        self._post = transport or _http_post
        self._queue: queue.Queue = queue.Queue(maxsize=200)
        self._lock = threading.Lock()
        self._sent_times: list[datetime] = []
        self._last_by_key: dict[str, datetime] = {}
        self.deliveries: list[Delivery] = []
        self.skipped = 0
        self._worker = threading.Thread(target=self._run, name="lookout-notify", daemon=True)
        self._worker.start()

    # -- intake ------------------------------------------------------------ #

    def on_alert(self, alert: Any) -> None:
        """Engine-side entry point: decide quickly, queue, return."""
        s = self.settings
        if not s.enabled or not s.channels():
            return
        severity = getattr(alert, "severity", "HIGH")
        if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(s.min_severity, 3):
            return
        key = f"{getattr(alert, 'user', '?')}|{getattr(alert, 'alert_type', '?')}"
        now = _now()
        with self._lock:
            self._sent_times = [t for t in self._sent_times if now - t < timedelta(hours=1)]
            last = self._last_by_key.get(key)
            if last and (now - last).total_seconds() < s.cooldown_seconds:
                self.skipped += 1
                return
            if len(self._sent_times) >= s.max_per_hour:
                self.skipped += 1
                return
            self._sent_times.append(now)
            self._last_by_key[key] = now
        try:
            self._queue.put_nowait(_message_for(alert))
        except queue.Full:  # pragma: no cover -- only under a flood
            self.skipped += 1

    def send_test(self) -> list[Delivery]:
        """Deliver a test message now and report what happened, so the Super
        Admin can check the configuration without waiting for a real attack."""
        msg = {
            "alert_id": "TEST",
            "title": "Lookout test alert",
            "severity": "CRITICAL",
            "lines": [
                "This is a test from the Lookout console.",
                f"Sent {_now():%d %b %Y %H:%M} UTC.",
            ],
        }
        return self._deliver(msg)

    # -- worker ------------------------------------------------------------ #

    def _run(self) -> None:  # pragma: no cover -- exercised through the queue
        while True:
            msg = self._queue.get()
            try:
                self._deliver(msg)
            except Exception as e:  # noqa: BLE001 -- a notifier must not die
                log.error("notification failed: %s", e)
            finally:
                self._queue.task_done()

    def _deliver(self, msg: dict[str, Any]) -> list[Delivery]:
        out: list[Delivery] = []
        s = self.settings
        text = f"{msg['severity']} - {msg['title']}\n" + "\n".join(msg["lines"])
        if s.webhook_url:
            out.append(self._send(_webhook_channel(s.webhook_url), msg["alert_id"], lambda: self._post(
                s.webhook_url, _webhook_payload(s, text, msg), None)))
        if "email" in s.channels():
            out.append(self._send("email", msg["alert_id"], lambda: self._post(
                BREVO_ENDPOINT,
                {
                    "sender": {"email": s.email_from, "name": "Lookout SOC"},
                    "to": [{"email": s.email_to}],
                    "subject": f"[{msg['severity']}] {msg['title']}",
                    "textContent": text,
                },
                {"api-key": s.brevo_api_key, "accept": "application/json"},
            )))
        with self._lock:
            self.deliveries = (self.deliveries + out)[-50:]
        return out

    def _send(self, channel: str, alert_id: str, call) -> Delivery:
        try:
            status = call()
            ok = 200 <= int(status) < 300
            return Delivery(_now(), channel, alert_id, ok, "" if ok else f"HTTP {status}")
        except Exception as e:  # noqa: BLE001 -- report, never raise
            log.warning("%s delivery failed: %s", channel, e)
            return Delivery(_now(), channel, alert_id, False, f"{type(e).__name__}: {e}")

    # -- views -------------------------------------------------------------- #

    def status(self) -> dict[str, Any]:
        with self._lock:
            recent = [d.as_dict() for d in self.deliveries[-10:]][::-1]
            sent_hour = len([t for t in self._sent_times if _now() - t < timedelta(hours=1)])
        return {
            "settings": self.settings.as_dict(),
            "active": bool(self.settings.enabled and self.settings.channels()),
            "sent_last_hour": sent_hour,
            "skipped": self.skipped,
            "recent": recent,
        }


def _webhook_channel(url: str) -> str:
    return "telegram" if "api.telegram.org" in url else "webhook"


def _webhook_payload(s: NotifySettings, text: str, msg: dict[str, Any]) -> dict[str, Any]:
    """Slack, Discord, Google Chat and Teams all accept a plain body field;
    Telegram needs the chat id and its own key."""
    if "api.telegram.org" in s.webhook_url:
        return {"chat_id": s.telegram_chat_id, "text": text, "disable_web_page_preview": True}
    return {"text": text, "content": text}


def _message_for(alert: Any) -> dict[str, Any]:
    reasons = list(getattr(alert, "reasons", []))[:3]
    return {
        "alert_id": getattr(alert, "id", "?"),
        "severity": getattr(alert, "severity", "HIGH"),
        "title": f"{getattr(alert, 'alert_type', 'Security alert')}: {getattr(alert, 'user', 'unknown')}",
        "lines": [
            f"Risk {getattr(alert, 'risk_score', 0):.0f}/100 on "
            f"{str(getattr(alert, 'event', '')).replace('_', ' ')}",
            *[f"- {r}" for r in reasons],
            f"Recommended: {getattr(alert, 'recommended_action', '')}",
            f"Incident {getattr(alert, 'incident_id', '-')} - alert {getattr(alert, 'id', '-')}",
        ],
    }


def _http_post(url: str, payload: dict[str, Any], headers: dict[str, str] | None) -> int:
    response = httpx.post(url, json=payload, headers=headers or {}, timeout=8.0)
    return response.status_code
