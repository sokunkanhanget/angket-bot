"""
tests/test_verdict_style.py
=============================
verdict_style() and risk_style() are FIXED labels (not model-generated),
translated via bot/response/translate/ - covers the lang parameter added when private-DM/
business-chat verdict content became translatable.
"""

from bot.response.verdict_style import DISCLAIMER_SPACER, defang_domains, risk_style, verdict_style


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
