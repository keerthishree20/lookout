"""URL reputation, computed rather than looked up.

Lookout has no threat-intel subscription, so it cannot ask "has anyone seen
this domain before?". It can ask the question that actually catches internal
phishing: **does this link claim to be us when it is not?** That is decidable
offline from the string itself, and it is the check that matters when the
sender is a bank employee whose messages customers already trust.

Six findings, each independently justifiable in a review:

* the host is a lookalike of a corporate domain (edit distance, after
  homoglyph folding)
* the host is a known URL shortener, which hides the real destination
* the host is a bare IP address
* the host uses punycode, the classic homograph attack
* the path or query carries credential-harvest bait
* the scheme is plain HTTP for something asking the reader to act
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

#: Domains the bank actually owns. Anything close to these but not equal is the
#: single strongest phishing tell available offline.
CORPORATE_DOMAINS: tuple[str, ...] = (
    "meridianbank.com",
    "meridianbank.in",
    "secure.meridianbank.com",
)

SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
    }
)

#: TLDs that are cheap, bulk-registrable and wildly over-represented in abuse
#: feeds. Not proof of anything -- worth a point, not a block.
RISKY_TLDS: frozenset[str] = frozenset(
    {"zip", "mov", "top", "xyz", "gq", "cf", "tk", "ml", "click", "country", "rest"}
)

CREDENTIAL_BAIT: tuple[str, ...] = (
    "verify", "kyc", "reactivate", "suspend", "unlock", "netbanking", "otp",
    "update-account", "secure-login", "refund", "blocked", "re-kyc",
)

#: Confusable characters, folded before the edit-distance comparison so that
#: ``rneridian-bank`` and ``meridianbank`` sit one cheap edit apart.
HOMOGLYPHS: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "$": "s", "@": "a", "|": "l", "!": "l",
}


@dataclass
class UrlVerdict:
    """What the checker concluded about one URL."""

    url: str
    host: str
    score: float = 0.0  # 0..1, where 1 is "certainly hostile"
    findings: list[str] = field(default_factory=list)
    impersonates: str | None = None

    @property
    def suspicious(self) -> bool:
        return self.score >= 0.35

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "host": self.host,
            "score": round(self.score, 2),
            "suspicious": self.suspicious,
            "findings": self.findings,
            "impersonates": self.impersonates,
        }


def inspect_url(url: str, corporate: tuple[str, ...] = CORPORATE_DOMAINS) -> UrlVerdict:
    """Score one URL. Pure function, no network."""
    parts = urlsplit(url if "://" in url else f"http://{url}")
    host = (parts.hostname or "").lower().strip(".")
    verdict = UrlVerdict(url=url, host=host)
    if not host:
        verdict.findings.append("URL has no resolvable host")
        verdict.score = 0.5
        return verdict

    registrable = _registrable(host)

    if host in {d.lower() for d in corporate} or registrable in {
        _registrable(d) for d in corporate
    }:
        verdict.findings.append("host is a verified corporate domain")
        return verdict  # score stays 0

    if _is_ip(host):
        verdict.findings.append("host is a bare IP address, not a domain name")
        verdict.score += 0.45

    if host.startswith("xn--") or ".xn--" in host:
        verdict.findings.append("host uses punycode, the classic homograph attack")
        verdict.score += 0.40

    if registrable in SHORTENERS:
        verdict.findings.append(
            f"{registrable} is a URL shortener, so the real destination is hidden"
        )
        verdict.score += 0.35

    twin, distance = _closest_corporate(host, corporate)
    if twin and distance <= 2:
        verdict.impersonates = twin
        verdict.findings.append(
            f"host resembles the corporate domain {twin} "
            f"({distance} character{'s' if distance != 1 else ''} different after "
            f"folding lookalike characters)"
        )
        verdict.score += 0.55 if distance == 1 else 0.45
    elif twin and _contains_brand(host, twin):
        verdict.impersonates = twin
        verdict.findings.append(
            f"host embeds the corporate name '{_brand(twin)}' but is registered "
            f"under {registrable}, which the bank does not own"
        )
        verdict.score += 0.45

    tld = registrable.rsplit(".", 1)[-1] if "." in registrable else ""
    if tld in RISKY_TLDS:
        verdict.findings.append(f".{tld} is a bulk-registration TLD common in abuse")
        verdict.score += 0.12

    haystack = f"{parts.path}?{parts.query}".lower()
    bait = sorted({w for w in CREDENTIAL_BAIT if w in haystack or w in host})
    if bait:
        verdict.findings.append(
            "path or host contains credential-harvest bait: " + ", ".join(bait)
        )
        verdict.score += min(0.30, 0.12 * len(bait))

    if parts.scheme == "http" and verdict.score > 0:
        verdict.findings.append("link is plain HTTP, so anything entered is in the clear")
        verdict.score += 0.08

    if host.count(".") >= 4:
        verdict.findings.append(
            "host has an unusually deep subdomain chain, often used to push the "
            "real domain out of view on mobile"
        )
        verdict.score += 0.10

    verdict.score = min(1.0, round(verdict.score, 3))
    return verdict


def inspect_all(urls: list[str]) -> list[UrlVerdict]:
    return [inspect_url(u) for u in urls]


def worst(verdicts: list[UrlVerdict]) -> UrlVerdict | None:
    return max(verdicts, key=lambda v: v.score) if verdicts else None


# --------------------------------------------------------------------------- #


def _fold(text: str) -> str:
    """Normalise confusables so visual twins become string twins."""
    folded = "".join(HOMOGLYPHS.get(c, c) for c in text.lower())
    return folded.replace("rn", "m").replace("vv", "w").replace("-", "").replace("_", "")


def _registrable(host: str) -> str:
    """Last two labels. Good enough without a public-suffix list, and the
    corporate domains here are all two-label."""
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _brand(domain: str) -> str:
    return _registrable(domain).rsplit(".", 1)[0]


def _is_ip(host: str) -> bool:
    labels = host.split(".")
    return len(labels) == 4 and all(l.isdigit() and 0 <= int(l) <= 255 for l in labels)


def _contains_brand(host: str, corporate: str) -> bool:
    """The brand name appears somewhere in the host, but not as the registrable
    domain -- ``meridianbank.secure-verify.top``."""
    brand = _fold(_brand(corporate))
    return brand in _fold(host) and _fold(_brand(_registrable(host))) != brand


def _closest_corporate(
    host: str, corporate: tuple[str, ...]
) -> tuple[str | None, int]:
    best: tuple[str | None, int] = (None, 99)
    folded_host = _fold(_registrable(host))
    for domain in corporate:
        d = levenshtein(folded_host, _fold(_registrable(domain)))
        if d < best[1]:
            best = (domain, d)
    return best


def levenshtein(a: str, b: str) -> int:
    """Edit distance. Short strings only, so the simple DP row is plenty."""
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
