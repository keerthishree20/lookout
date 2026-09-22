"""Message-content model: does this text read like a phishing / fraud message?

The URL checker judges links and the detectors judge volume and privilege.
This model judges the *words*, so a scam without a link ("reply with your OTP
to avoid suspension") is still caught, and so detection doesn't come down to a
fixed keyword list: the model weighs word pairs such as "verify now" or
"account suspended" against the ordinary language of bank notices.

It is a TF-IDF (word 1-2 grams) + logistic regression classifier trained on a
**synthetic** corpus built from templates below. That makes it a demonstration:
the templates are Lookout's idea of what bank phishing and bank notices look
like, not a sample of real traffic. Replace the corpus with labelled real
messages before relying on it.

It is trained once, on first use, and cached; never per request.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from functools import lru_cache

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

# --------------------------------------------------------------------------- #
# Synthetic corpus
# --------------------------------------------------------------------------- #

_BRAND = ["Meridian Bank", "Meridian", "MB", "Meridian Bank Ltd", "Dear customer"]
_LINK = ["{link}", "the link below", "this link", "{link} now", "our secure page {link}"]

_PHISH = [
    "{b}: your account will be suspended in 24 hours. Re-verify your KYC at {l}.",
    "{b} alert: unusual login detected. Confirm your identity immediately at {l} or your card will be blocked.",
    "Your net banking access is locked. Update your PAN and Aadhaar details via {l} to unlock.",
    "Dear customer, your KYC has expired. Your account will be frozen today. Verify now: {l}",
    "{b}: you have won a cashback reward of Rs {n}. Claim it before midnight at {l}.",
    "Your debit card is blocked due to suspicious activity. Reply with your card number and OTP to reactivate.",
    "Urgent: please share the OTP you just received to cancel the unauthorised transaction of Rs {n}.",
    "{b} refund of Rs {n} is pending. Enter your net banking password at {l} to receive it.",
    "Final warning: your account is under review. Login at {l} within 2 hours to avoid permanent closure.",
    "{b}: your reward points of Rs {n} expire today. Redeem immediately using {l}.",
    "Security notice: verify your account details and password at {l} to prevent suspension.",
    "Your loan of Rs {n} is pre-approved. Pay a processing fee to {l} to release the funds today.",
    "Income tax refund of Rs {n} approved. Submit your bank login details at {l} to receive it.",
    "Your SIM will be deactivated and your bank account blocked. Call now and share your UPI PIN to continue.",
    "{b}: we could not verify your last transaction. Confirm your card CVV at {l} immediately.",
    "Your account has been compromised. Change your password now by logging in at {l}.",
    "Please reply with the OTP you received so we can stop the fraudulent debit of Rs {n}.",
    "This is the {b} fraud team. Share the 6 digit code sent to your phone to secure your account.",
    "Your account will be blocked tonight. Send your net banking user ID and password to this number.",
    "Kindly confirm your card number, expiry and CVV by reply to avoid blocking of your card.",
    "Act now: your KYC is incomplete and your account will be suspended. Tap {l}",
    "We noticed a login from a new device. If this was not you, verify your password at {l}.",
]

_LEGIT = [
    "{b}: your statement for {m} is ready in net banking.",
    "Your EMI of Rs {n} is due on {d}. Please keep sufficient balance. Ignore if already paid.",
    "Rs {n} has been credited to your account ending {k} on {d}.",
    "Rs {n} was debited from your account ending {k} on {d}. Not you? Call the number on the back of your card.",
    "{b} will never ask for your OTP, PIN or password. Do not share them with anyone.",
    "Your cheque book request has been received and will be dispatched within 5 working days.",
    "Branch timings for the festival week: open 10 am to 2 pm on {d}.",
    "Your fixed deposit of Rs {n} matures on {d}. Visit net banking to renew or close it.",
    "Thank you for visiting the {c} branch today. We hope your query was resolved.",
    "Your home loan application is approved. Your relationship manager will call you to schedule the signing.",
    "Scheduled maintenance: net banking will be unavailable from 1 am to 3 am on {d}.",
    "Your new debit card has been dispatched and should reach you within a week.",
    "Interest rates on savings accounts are revised from {d}. Details are on our website.",
    "Reminder: team meeting at 3 pm today in the {c} conference room.",
    "Please review the attached audit checklist before Friday.",
    "The core banking patch window is confirmed for Saturday night. Change ticket CHG-{k}.",
    "Customer complaint {k} has been resolved and the customer informed.",
    "Your account statement request for {m} has been processed.",
    "Your OTP for the transaction of Rs {n} is {k}. It is valid for 5 minutes. Do not share it with anyone.",
    "Welcome to {b}. Your account ending {k} is now active.",
    "Hi team, lunch at 1?",
    "Running 10 minutes late for the stand-up.",
    "Can you send me the updated branch roster by today?",
    "Thanks, noted.",
    "Please call me when you are free.",
    "The printer on the second floor is fixed.",
    "Approved. Go ahead with the change at 6 pm.",
    "Your service request {k} is closed. Rate us at the end of the call.",
    "Happy Diwali from all of us at {b}.",
    "Your credit card bill of Rs {n} is generated. Pay by {d} to avoid late fees.",
]

_MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September"]
_CITIES = ["Chennai", "Bengaluru", "Mumbai", "Coimbatore"]
_LINKS = [
    "http://meridian-bank.secure-verify.top/kyc", "bit.ly/3xKyc9", "meridianbank-help.xyz/login",
    "http://203.0.113.9/verify", "tinyurl.com/mb-refund", "https://meridian-rewards.click/claim",
]


def _fill(template: str, rng: random.Random) -> str:
    return template.format(
        b=rng.choice(_BRAND),
        l=rng.choice(_LINK).format(link=rng.choice(_LINKS)),
        n=f"{rng.randint(500, 499_999):,}",
        m=rng.choice(_MONTHS),
        d=f"{rng.randint(1, 28)} {rng.choice(_MONTHS)}",
        k=rng.randint(1000, 9999),
        c=rng.choice(_CITIES),
    )


def _vary(text: str, rng: random.Random) -> str:
    """Small surface changes, so the model can't memorise exact strings."""
    if rng.random() < 0.3:
        text = text.upper() if rng.random() < 0.2 else text.lower()
    if rng.random() < 0.3:
        text = text.replace(". ", "! ", 1)
    if rng.random() < 0.2:
        text = text.rstrip(".") + " - " + rng.choice(["Team MB", "Customer care", "Regards"])
    return text


def synthetic_corpus(n: int = 3000, seed: int = 7) -> tuple[list[str], list[int]]:
    """``n`` messages, about 30% phishing (label 1)."""
    rng = random.Random(seed)
    texts, labels = [], []
    for _ in range(n):
        phishing = rng.random() < 0.3
        texts.append(_vary(_fill(rng.choice(_PHISH if phishing else _LEGIT), rng), rng))
        labels.append(int(phishing))
    return texts, labels


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #


@dataclass
class ContentVerdict:
    probability: float
    phrases: list[str]

    def as_dict(self) -> dict:
        return {"phishing_probability": round(self.probability, 3), "phrases": self.phrases}


class ContentModel:
    def __init__(self, seed: int = 7) -> None:
        texts, labels = synthetic_corpus(seed=seed)
        x_train, x_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.25, stratify=labels, random_state=seed
        )
        self.pipeline = Pipeline(
            [
                ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2, lowercase=True)),
                ("clf", LogisticRegression(class_weight="balanced", max_iter=1000, C=2.0)),
            ]
        )
        self.pipeline.fit(x_train, y_train)
        predicted = self.pipeline.predict(x_test)
        self.metrics = {
            "synthetic": True,
            "train_messages": len(x_train),
            "test_messages": len(x_test),
            "precision": round(float(precision_score(y_test, predicted)), 3),
            "recall": round(float(recall_score(y_test, predicted)), 3),
            "f1": round(float(f1_score(y_test, predicted)), 3),
            "note": "Measured on held-out messages from the same templates, so it shows the "
            "pipeline works, not how it would do on real messages.",
        }
        tfidf: TfidfVectorizer = self.pipeline.named_steps["tfidf"]
        self._vocab = np.array(tfidf.get_feature_names_out())
        self._coef = self.pipeline.named_steps["clf"].coef_[0]
        #: The top quarter of fraud-leaning weights: what counts as a telling phrase.
        self._strong = float(np.percentile(self._coef[self._coef > 0], 75))

    def score(self, text: str, top: int = 4) -> ContentVerdict:
        """Probability the text is phishing, and the phrases that pushed it up
        (TF-IDF weight x coefficient, positive contributions only)."""
        if not text.strip():
            return ContentVerdict(0.0, [])
        probability = float(self.pipeline.predict_proba([text])[0][1])
        row = self.pipeline.named_steps["tfidf"].transform([text])
        contributions = row.multiply(self._coef).tocsr()
        idx = contributions.indices[np.argsort(contributions.data)[::-1]]
        # Only phrases the model genuinely associates with fraud, not ones that
        # merely nudge the score (the bank's own name appears in both classes).
        phrases = [self._vocab[i] for i in idx if self._coef[i] >= self._strong][:top]
        return ContentVerdict(probability, phrases)


@lru_cache(maxsize=1)
def content_model() -> ContentModel:
    return ContentModel()
