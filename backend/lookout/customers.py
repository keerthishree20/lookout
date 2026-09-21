"""Meridian Bank's customer book -- and its decoy twin.

Both are synthetic. The "real" book is a fixed, seeded set of 500 customers the
employee portal shows and exports. The decoy book is generated fresh for every
honeypot export, in exactly the same format, so a person holding one cannot
tell which they received. The only difference is that every decoy account
number is recorded against the export that issued it: if one ever turns up in a
transaction, a paste site or a competitor's hands, it names the leaker.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass

FIRST = (
    "Aarav", "Aditi", "Akash", "Ananya", "Arjun", "Bhavna", "Deepak", "Divya",
    "Farhan", "Gayathri", "Harish", "Isha", "Jayanth", "Kavya", "Karthik",
    "Lakshmi", "Manoj", "Meera", "Naveen", "Nisha", "Pooja", "Pranav", "Priya",
    "Rahul", "Revathi", "Rohan", "Sanjay", "Shreya", "Suresh", "Tanvi", "Uma",
    "Varun", "Vidya", "Vikram", "Yamini", "Zoya", "Anil", "Saranya", "Gokul",
    "Hema",
)
LAST = (
    "Iyer", "Nair", "Menon", "Reddy", "Sharma", "Rao", "Pillai", "Krishnan",
    "Subramanian", "Das", "Bose", "Kulkarni", "Joshi", "Patel", "Gupta",
    "Fernandes", "Mathew", "Khan", "Varghese", "Chandran", "Raman", "Hegde",
    "Srinivasan", "Naidu", "Balan",
)
CITIES = ("Chennai", "Bengaluru", "Mumbai", "Coimbatore", "Hyderabad", "Kochi", "Pune", "Madurai")
PRODUCTS = ("Savings", "Savings", "Current", "Salary", "Fixed deposit", "Home loan")
KYC = ("Verified", "Verified", "Verified", "Verified", "Re-KYC due")

BOOK_SIZE = 500


@dataclass(frozen=True)
class Customer:
    customer_id: str
    name: str
    account_no: str
    product: str
    city: str
    phone: str
    email: str
    balance_inr: int
    kyc: str

    def as_dict(self) -> dict:
        return asdict(self)


def _customer(rng: random.Random, idx: int, prefix: str) -> Customer:
    first, last = rng.choice(FIRST), rng.choice(LAST)
    account = f"{prefix}{rng.randrange(10**8):08d}"
    product = rng.choice(PRODUCTS)
    balance = int(rng.lognormvariate(11.5, 1.1))
    if product == "Home loan":
        balance = -int(rng.uniform(800_000, 6_500_000))
    return Customer(
        customer_id=f"C{idx:06d}",
        name=f"{first} {last}",
        account_no=account,
        product=product,
        city=rng.choice(CITIES),
        phone=f"+91 9{rng.randrange(10**9):09d}",
        email=f"{first.lower()}.{last.lower()}{rng.randrange(100)}@example.in",
        balance_inr=balance,
        kyc=rng.choice(KYC),
    )


def customer_book(seed: int = 7) -> list[Customer]:
    """The bank's (synthetic) customers. Same seed, same book, every run."""
    rng = random.Random(seed)
    return [_customer(rng, 100001 + i, "5021") for i in range(BOOK_SIZE)]


def masked(c: Customer) -> dict:
    """What the portal shows on screen. Banking UIs mask PII by default; only
    an export reveals the full values -- which is what makes exports the thing
    worth watching, and what lets a decoy match the screen exactly."""
    return {
        "customer_id": c.customer_id,
        "name": c.name,
        "account_no": f"•••• {c.account_no[-4:]}",
        "product": c.product,
        "city": c.city,
        "phone": f"+91 •••••• {c.phone[-4:]}",
        "email": f"{c.email[0]}•••@{c.email.split('@')[1]}",
        "kyc": c.kyc,
    }


def decoy_of(rows: list[Customer], seed: int, real: list[Customer]) -> list[Customer]:
    """Poisoned copies of exactly the rows the employee asked for.

    Everything visible on screen -- ID, name, product, city, KYC, the last four
    digits of the account and phone, the first letter and domain of the email --
    is kept, so the file matches what they just saw. Everything the mask hid is
    fabricated: the full account number, the rest of the phone, the email, the
    balance. Those fabricated account numbers are the canaries. None collides
    with a real account, so a sighting of one is unambiguous.
    """
    rng = random.Random(seed)
    taken = {c.account_no for c in real}
    out: list[Customer] = []
    for c in rows:
        while True:
            account = f"5021{rng.randrange(10**4):04d}{c.account_no[-4:]}"
            if account not in taken and account != c.account_no:
                break
        taken.add(account)
        # Same first.last<n> pattern as a genuine address -- only the number
        # differs, which is invisible behind the screen's mask.
        real_local = c.email.split("@")[0]
        while True:
            local = f"{c.name.split()[0].lower()}.{c.name.split()[-1].lower()}{rng.randrange(100)}"
            if local != real_local:
                break
        balance = int(rng.lognormvariate(11.5, 1.1))
        if c.product == "Home loan":
            balance = -int(rng.uniform(800_000, 6_500_000))
        out.append(
            Customer(
                customer_id=c.customer_id,
                name=c.name,
                account_no=account,
                product=c.product,
                city=c.city,
                phone=f"+91 9{rng.randrange(10**5):05d}{c.phone[-4:]}",
                email=f"{local}@{c.email.split('@')[1]}",
                balance_inr=balance,
                kyc=c.kyc,
            )
        )
    return out
