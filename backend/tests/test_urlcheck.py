import pytest

from lookout.urlcheck import inspect_url, levenshtein


@pytest.mark.parametrize(
    "url",
    [
        "https://meridianbank.com/login",
        "https://secure.meridianbank.com/statements",
        "https://www.meridianbank.in/support",
    ],
)
def test_corporate_domains_are_clean(url):
    v = inspect_url(url)
    assert v.score == 0
    assert not v.suspicious


@pytest.mark.parametrize(
    "url, twin",
    [
        ("https://meridianbamk.com/login", "meridianbank.com"),  # one letter off
        ("https://merid1anbank.com/", "meridianbank.com"),  # 1 -> i
        ("https://rneridianbank.com/", "meridianbank.com"),  # rn -> m
        ("https://meridian-bank.com/", "meridianbank.com"),  # hyphenated
    ],
)
def test_lookalikes_are_caught_and_named(url, twin):
    v = inspect_url(url)
    assert v.suspicious, v.findings
    assert v.impersonates == twin


def test_brand_embedded_under_foreign_domain():
    v = inspect_url("http://meridianbank.secure-verify.top/re-kyc")
    assert v.suspicious
    assert v.impersonates is not None
    joined = " ".join(v.findings)
    assert "does not own" in joined
    assert ".top" in joined
    assert "re-kyc" in joined
    assert "HTTP" in joined


def test_scenario_phishing_link_scores_high():
    v = inspect_url("http://meridian-bank.secure-verify.top/re-kyc")
    assert v.score >= 0.7


def test_shortener_hides_destination():
    v = inspect_url("https://bit.ly/3xYz")
    assert v.suspicious
    assert any("shortener" in f for f in v.findings)


def test_bare_ip():
    v = inspect_url("http://185.220.101.44/login")
    assert v.suspicious
    assert any("IP address" in f for f in v.findings)


def test_punycode_homograph():
    assert inspect_url("https://xn--meridinbank-9za.com/").suspicious


def test_unrelated_ordinary_site_is_not_flagged():
    v = inspect_url("https://www.rbi.org.in/Scripts/NotificationUser.aspx")
    assert not v.suspicious


def test_bait_words_alone_on_unrelated_https_site_are_weak():
    v = inspect_url("https://example.org/verify")
    assert 0 < v.score < 0.35


def test_score_is_capped_at_one():
    v = inspect_url("http://xn--meridianbnk-x.secure.verify.kyc.top/otp/verify/unlock")
    assert v.score <= 1.0


def test_missing_host():
    assert inspect_url("http://").score > 0


def test_levenshtein():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "abc") == 3
    assert levenshtein("same", "same") == 0
