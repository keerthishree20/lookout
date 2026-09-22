"""Customer accounts, the genuine ledger, and the shadow ledgers.

The genuine ledger is where real (simulated) money moves. A shadow ledger is a
per-employee copy-on-write view that looks exactly like it: same accounts, same
balances, same transaction history -- until the moment that employee is caught.
From then on every transfer they make is applied to their shadow only. Their
screen shows the debit, the receipt, the reference, the updated balance and the
new line in their history. The real account is never touched, and no other
employee's screen ever shows the fake transaction.

That consistency is what makes the honeypot hold. A decoy receipt with an
unchanged balance on refresh, or a history that forgets the transfer, would tell
a careful insider in seconds.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .customers import Customer

#: Opening balance floor, so the savings accounts in the book have something to move.
MIN_OPENING = 25_000


@dataclass
class Transaction:
    reference: str
    utr: str
    ts: datetime
    actor: str
    from_account: str
    from_name: str
    to_account: str
    to_name: str
    to_ifsc: str
    external: bool
    amount: float
    remarks: str
    balance_after: float
    status: str = "SUCCESS"

    def as_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        return d


def opening_balance(c: Customer) -> float:
    """Loans carry negative book balances; give every account a spendable one."""
    return float(max(MIN_OPENING, c.balance_inr))


def new_reference() -> str:
    """Same format for genuine and shadow transactions."""
    return f"MBTXN{secrets.randbelow(10**10):010d}"


def new_utr() -> str:
    return f"MERB{datetime.now(timezone.utc):%y%j}{secrets.randbelow(10**8):08d}"


@dataclass
class _Shadow:
    """One caught employee's private view of the bank."""

    balances: dict[str, float] = field(default_factory=dict)
    transactions: list[Transaction] = field(default_factory=list)


class Bank:
    def __init__(self, book: list[Customer]) -> None:
        self.customers: dict[str, Customer] = {c.account_no: c for c in book}
        self.balances: dict[str, float] = {c.account_no: opening_balance(c) for c in book}
        self.transactions: list[Transaction] = []
        self._shadows: dict[str, _Shadow] = {}
        self._lock = threading.Lock()

    # -- reading, as a given employee sees it ------------------------------ #

    def balance(self, account: str, actor: str) -> float:
        shadow = self._shadows.get(actor)
        if shadow and account in shadow.balances:
            return shadow.balances[account]
        return self.balances[account]

    def history(self, actor: str) -> list[Transaction]:
        """This employee's transfers: genuine ones plus, if they are in a
        shadow, the fake ones -- merged in time order so nothing looks spliced."""
        mine = [t for t in self.transactions if t.actor == actor]
        shadow = self._shadows.get(actor)
        if shadow:
            mine = mine + shadow.transactions
        return sorted(mine, key=lambda t: t.ts, reverse=True)

    def in_shadow(self, actor: str) -> bool:
        return actor in self._shadows

    # -- writing ----------------------------------------------------------- #

    def transfer(
        self,
        *,
        actor: str,
        from_account: str,
        to_account: str,
        to_name: str,
        to_ifsc: str,
        amount: float,
        remarks: str,
        shadow: bool,
    ) -> Transaction:
        """Move money for real, or only in ``actor``'s shadow. Same code path
        and same receipt either way; only where the numbers land differs."""
        with self._lock:
            src = self.customers[from_account]
            external = to_account not in self.customers
            if shadow:
                view = self._shadows.setdefault(actor, _Shadow())
                balances = view.balances
                current = view.balances.get(from_account, self.balances[from_account])
                balances[from_account] = current - amount
                if not external:
                    dest_now = view.balances.get(to_account, self.balances[to_account])
                    balances[to_account] = dest_now + amount
                after = balances[from_account]
            else:
                self.balances[from_account] -= amount
                if not external:
                    self.balances[to_account] += amount
                after = self.balances[from_account]

            txn = Transaction(
                reference=new_reference(),
                utr=new_utr(),
                ts=datetime.now(timezone.utc),
                actor=actor,
                from_account=from_account,
                from_name=src.name,
                to_account=to_account,
                to_name=to_name or (self.customers[to_account].name if not external else ""),
                to_ifsc=to_ifsc.upper(),
                external=external,
                amount=amount,
                remarks=remarks,
                balance_after=after,
            )
            if shadow:
                self._shadows[actor].transactions.append(txn)
            else:
                self.transactions.append(txn)
            return txn

    def leave_shadow(self, actor: str) -> list[Transaction]:
        """The SOC cleared them. Their fake transactions vanish from their view
        -- the investigation keeps its own copy in the honeypot ledger."""
        with self._lock:
            shadow = self._shadows.pop(actor, None)
        return shadow.transactions if shadow else []
