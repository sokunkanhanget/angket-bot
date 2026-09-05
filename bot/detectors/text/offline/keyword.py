from bot.config import SUSPICIOUS_KEYWORDS


def analyze_text(text: str) -> dict:
    normalized_text = text.casefold()
    matches = [
        keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in normalized_text
    ]
    return {
        "suspicious": bool(matches),
        "matches": matches,
    }