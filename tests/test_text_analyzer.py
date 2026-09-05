from bot.detectors.text.offline.keyword import analyze_text


def test_analyze_text_finds_suspicious_keyword():
    result = analyze_text("Please claim reward now")

    assert result == {"suspicious": True, "matches": ["claim reward"]}


def test_analyze_text_accepts_clean_text():
    assert analyze_text("Hello from Veridex") == {
        "suspicious": False,
        "matches": [],
    }