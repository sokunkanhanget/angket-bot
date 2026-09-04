"""
tests/test_verdict_style.py
=============================
verdict_style() and risk_style() are FIXED labels (not model-generated),
translated via i18n.py - covers the lang parameter added when private-DM/
business-chat verdict content became translatable.
"""

from bot.verdict_style import risk_style, verdict_style


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
