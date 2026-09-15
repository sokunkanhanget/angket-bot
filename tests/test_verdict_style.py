"""
tests/test_verdict_style.py
=============================
verdict_style() and risk_style() are FIXED labels (not model-generated),
translated via bot/response/translate/ - covers the lang parameter added when private-DM/
business-chat verdict content became translatable.
"""

from bot.response.verdict_style import DISCLAIMER_SPACER, defang_domains, risk_style, trusted_link_notice, verdict_style


def test_disclaimer_spacer_is_empty():
    assert DISCLAIMER_SPACER == ""


def test_verdict_style_defaults_to_english():
    icon, label = verdict_style("Scam")
    assert icon == "⚠️"
    assert label == "LIKELY A SCAM"


def test_verdict_style_translates_to_khmer():
    icon, label = verdict_style("Scam", "km")
    assert icon == "⚠️"
    assert label == "ទំនងជាការឆបោក"


def test_verdict_style_unknown_verdict_falls_back_per_language():
    _icon, en_label = verdict_style("something-unexpected", "en")
    _icon, km_label = verdict_style("something-unexpected", "km")
    assert en_label == "UNABLE TO VERIFY"
    assert km_label == "មិនអាចផ្ទៀងផ្ទាត់បាន"


def test_risk_style_translates_all_buckets_to_khmer():
    assert risk_style(None, "km")[1] == "ហានិភ័យមិនស្គាល់"
    assert risk_style(10, "km")[1] == "ហានិភ័យទាប"
    assert risk_style(45, "km")[1] == "ហានិភ័យមធ្យម"
    assert risk_style(90, "km")[1] == "ហានិភ័យខ្ពស់"


def test_risk_style_defaults_to_english():
    assert risk_style(90)[1] == "High Risk"


def test_defang_domains_wraps_html_style():
    # Direct user spec (2026-09-11): a reply warning about a link
    # shouldn't hand the reader a one-tap way to open it.
    text = defang_domains("bit.ly: Shortened link")
    assert text == "<code>bit.ly</code>: Shortened link"


def test_defang_domains_wraps_markdown_style():
    text = defang_domains("bit.ly: Shortened link", style="markdown")
    assert text == "`bit.ly`: Shortened link"


def test_defang_domains_wraps_multiple_domains_in_one_string():
    text = defang_domains("redirects from evil.tk to kimtech-portfolio.vercel.app")
    assert text == "redirects from <code>evil.tk</code> to <code>kimtech-portfolio.vercel.app</code>"


def test_defang_domains_leaves_plain_text_untouched():
    text = defang_domains("No strong scam signals were found here.")
    assert text == "No strong scam signals were found here."


def test_defang_domains_works_after_html_escape():
    # The real call order this is always used in - html.escape() first,
    # then defang_domains() on the already-escaped text (see the
    # function's own docstring for why that order is required).
    from html import escape
    text = defang_domains(escape("<script>evil.tk</script>"))
    assert "<script>" not in text  # still safely escaped
    assert "<code>evil.tk</code>" in text  # domain still wrapped


# --- trusted_link_notice (2026-09-16 direct user spec) ------------------
# A bare trusted-brand link gets this one-line notice instead of the
# full VERDICT/KEY REASONS/WHAT TO DO template - quota or no quota.

def test_trusted_link_notice_has_no_verdict_or_reasons_sections():
    notice = trusted_link_notice("facebook.com", "en")

    assert "facebook.com" in notice
    assert "VERDICT" not in notice
    assert "KEY REASONS" not in notice
    assert "WHAT YOU SHOULD DO" not in notice
    assert "%" not in notice  # no risk percentage either


def test_trusted_link_notice_uses_the_not_a_scam_icon():
    notice = trusted_link_notice("facebook.com", "en")

    assert notice.startswith("✅")


def test_trusted_link_notice_includes_the_real_disclaimer():
    notice = trusted_link_notice("facebook.com", "en")

    assert "may occasionally make mistakes" in notice


def test_trusted_link_notice_translates_to_khmer():
    notice = trusted_link_notice("facebook.com", "km")

    assert "facebook.com" in notice
    assert any(0x1780 <= ord(ch) <= 0x17FF for ch in notice)
    assert "VERDICT" not in notice


def test_trusted_link_notice_defangs_the_domain_html_style():
    notice = trusted_link_notice("facebook.com", "en", style="html")

    assert "<code>facebook.com</code>" in notice


def test_trusted_link_notice_defangs_the_domain_markdown_style():
    notice = trusted_link_notice("facebook.com", "en", style="markdown")

    assert "`facebook.com`" in notice


def test_trusted_link_notice_placeholder_parity_between_languages():
    import string

    from bot.response.buttons import t

    def placeholders(text):
        return {name for _lit, name, _spec, _conv in string.Formatter().parse(text) if name}

    assert placeholders(t("en", "trusted_link_notice")) == placeholders(t("km", "trusted_link_notice"))


def test_trusted_link_notice_html_escapes_before_defanging():
    # Real bug, found by code review (2026-09-16): every other
    # style="html" call site in this codebase does html.escape() before
    # defang_domains() (see defang_domains' own docstring for why the
    # order matters) - trusted_link_notice skipped that step. Currently
    # harmless (host is always a hand-verified PROTECTED_BRANDS domain,
    # the fixed notice text has no metacharacters) but the contract
    # violation is real; this pins the fix down directly by forcing a
    # value that WOULD break parse_mode="HTML" if unescaped.
    from bot.response.translate import TEXT

    old = TEXT["en"]["trusted_link_notice"]
    TEXT["en"]["trusted_link_notice"] = "{host} <b>should not render as bold</b> & neither this"
    try:
        notice = trusted_link_notice("evil.example", "en", style="html")
    finally:
        TEXT["en"]["trusted_link_notice"] = old

    assert "<b>" not in notice
    assert "&lt;b&gt;" in notice
    assert "&amp;" in notice


# --- format_local_datetime (2026-09-16, extracted, found by code review) --
# The same "%d %b %Y, %I:%M %p (UTC+n)" format used to be built by hand
# in three places (url_handler.py's business header, health_alerts.py's
# admin alert, subscription.py's reset-time notice) - a drift risk the
# original code review flagged since a future format tweak applied to
# only some sites would leave surfaces inconsistent.

def test_format_local_datetime_applies_the_configured_offset(monkeypatch):
    import datetime as dt

    import bot.response.verdict_style as vs
    monkeypatch.setattr(vs, "DISPLAY_TIMEZONE_OFFSET_HOURS", 7)

    utc_dt = dt.datetime(2026, 1, 1, 17, 0, tzinfo=dt.timezone.utc)
    result = vs.format_local_datetime(utc_dt)

    assert "02 Jan 2026, 12:00 AM" in result
    assert "(UTC+7)" in result


def test_format_local_datetime_negative_offset(monkeypatch):
    import datetime as dt

    import bot.response.verdict_style as vs
    monkeypatch.setattr(vs, "DISPLAY_TIMEZONE_OFFSET_HOURS", -5)

    utc_dt = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.timezone.utc)
    result = vs.format_local_datetime(utc_dt)

    assert "01 Jan 2026, 07:00 AM" in result
    assert "(UTC-5)" in result
