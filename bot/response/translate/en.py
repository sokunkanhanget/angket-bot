"""
bot/response/translate/en.py
=============================
English CONTENT strings - see this package's __init__.py for how this
combines with km.py into the same TEXT dict shape every caller already
uses. One language per file so adding/editing a language never touches
another's text.
"""

TEXT = {
    "switch_language": "🌐 <b>Switch Language</b>",
    "language_set": "Language set to English.",
    "menu_title": "📋 <b>Menu</b>\n\nChoose an action below.",
    "how_to_use": (
        "📖 <b>How to Use Angket Bot</b>\n\n"
        "Angket helps you check suspicious content and understand the security risk.\n\n"
        "<b>1. Send the content you want to check</b>\n\n"
        "• 📝 Send a suspicious text message\n"
        "• 📄 Upload a suspicious file\n"
        "• 🔗 Send a URL or link\n\n"
        "<b>2. Let Angket analyze it</b>\n\n"
        "Angket will scan the content and identify potential security threats.\n\n"
        "<b>3. Get your result</b>\n\n"
        "You’ll receive:\n\n"
        "• 📊 <b>Risk Level:</b> How risky the content may be.\n"
        "• 🔍 <b>Key Reasons:</b> Why it was flagged.\n"
        "• 💡 <b>What To Do:</b> What you should do next.\n\n"
        "<b>Risk Levels</b>\n"
        "🟢 <b>Low Risk:</b> No significant threat detected.\n"
        "🟡 <b>Medium Risk:</b> Some suspicious signs detected. Be cautious.\n"
        "🔴 <b>High Risk:</b> Strong signs of a potential threat. Avoid interacting with it."
    ),
    "usage": (
        "📈 <b>Daily Usage</b>\n\n"
        "📄 Files scanned: <b>{files_used}/{files_limit}</b>\n"
        "🔗 Links & messages scanned: <b>{links_used}/{links_limit}</b>\n"
        "🤖 AI usage: <b>{tokens_used}/{tokens_limit:,} tokens</b>\n\n"
        "🔄 <b>Want more scans?</b>\n"
        "Upgrade to Premium for higher limits.\n"
        "👉 <b>[ Upgrade to Premium ]</b>"
    ),
    "policy": (
        "📋 <b>Angket Bot Policy</b>\n\n"
        "Please read our policies to understand how Angket handles your information and how you should use the service.\n\n"
        "🔐 <b>Privacy</b>\n"
        "• Information needed to provide and improve the scanning service.\n"
        "• Messages, files, and URLs you submit are processed to analyze potential security risks.\n"
        "• We only keep submitted data for as long as necessary according to our data-retention policy.\n"
        "• Your information is not shared with third parties except where necessary to provide the service or when required by law.\n\n"
        "📄 <b>Terms of Use</b>\n"
        "• <b>What Angket is for:</b> Angket helps users identify potentially suspicious messages, files, and links.\n"
        "• <b>Security analysis has limitations:</b> Angket's results are an assessment, not a guarantee. A message marked as safe may still be harmful, and a suspicious result does not necessarily mean something is a scam.\n"
        "• <b>Your responsibility:</b> Always verify important information yourself before clicking links, sharing information, or sending money.\n\n"
        "⚠️ <b>Important</b>\n"
        "Angket is a security-assistance tool. It does not guarantee that every threat or scam will be detected."
    ),
    "help": (
        "❓ <b>Help</b>\n\n"
        "Here are the available commands:\n\n"
        "🌐 <b>/language</b> — Switch between English and Khmer.\n"
        "📖 <b>/howtouse</b> — Learn how to use Angket to check suspicious content.\n"
        "📈 <b>/usage</b> — Check your daily scan.\n"
        "🔒 <b>/policy</b> — View Angket’s Privacy Policy and Terms of Use.\n"
        "⭐️ <b>/subscription</b> — View Premium plans and upgrade for higher limits."
    ),
    "subscription": (
        "⭐️ <b>Subscription</b>\n\n"
        "Want to get more out of Angket? Upgrade to Premium for higher daily scan limits and more access to our security features.\n\n"
        "Choose a plan that fits your needs and continue checking suspicious links, messages, and files with fewer limitations.\n\n"
        "👉 <b>[ View Premium Plans ]</b>"
    ),
    "file_scan_failed": (
        "⚠️ We couldn't finish scanning this file right now. "
        "Please try again in a moment."
    ),

    "scan_failed": (
        "⚠️ We couldn't finish checking this right now. "
        "Please try again in a moment."
    ),

    "daily_file_limit_reached": (
        "🚫 You've reached today's free file-scan limit ({limit} files/day).\n\n"
        "Your limit will reset tomorrow. Want to scan more files today? "
        "Check our subscription plans for higher daily limits."
        "👉 <b>[ View Premium Plans ]</b>"
    ),

    "daily_scan_limit_reached": (
        "🚫 You've reached today's free link/message-scan limit ({limit}/day).\n\n"
        "Your limit will reset tomorrow. Want to keep scanning today? "
        "Check our subscription plans for higher daily limits."
        "👉 <b>[ View Premium Plans ]</b>"
    ),

    "live_detect_trial_ended": (
        "⏰ Your 7-day free trial of Live Detect has ended.\n\n"
        "Live Detect automatically scans messages in your business chats. "
        "Subscribe to keep Live Detect active and continue protecting your chats."
        "👉 <b>[ View Premium Plans ]</b>"
    ),
    "checking_status": "🔍 Checking",
    # Multi-stage status animation (bot/response/status_animation.py) -
    # a timed fake sequence, not synced to real internal steps. Used by
    # text/link/file scans; group chat only ever shows these (never
    # translated content) too, per bot.py's TEXT_FILTER scope.
    "status_checking": "🔍 Checking",
    "status_searching": "🔎 Searching",
    "status_constructing": "⚙️ Constructing",
    "status_formatting": "🗂️ Formatting",
    "status_generating": "✨ Generating",
    "verdict_label": "VERDICT",
    "type_label": "TYPE",
    "key_reasons_header": "KEY REASONS",
    "what_to_do_header": "WHAT YOU SHOULD DO",
    "keyword_match_label": "KEYWORD MATCH",
    "none_provided": "None provided",
    "ai_unavailable_notice": (
        "AI reasoning was unavailable for this check - this result uses "
        "offline pattern matching only and may be less accurate than usual."
    ),
    "evidence_degraded_notice": (
        "The server has experienced some difficulties and will be back "
        "shortly - this result may be less complete than usual."
    ),
    "summary_warning_signs": "This message has warning signs. Verify it before taking action.",
    "summary_strong_unsafe": "This message shows strong signs of being unsafe.",
    "summary_no_indicators": "No strong scam indicators were detected in this message.",
    "summary_uncertain_no_signal": "There isn't enough information here to give a confident verdict.",
    "verdict_disclaimer": (
        "ⓘ Angket Bot may occasionally make mistakes.\n"
        "Double-check important information before taking action."
    ),
    "business_new_activity": "👀 New Activity Detected",
    "business_what_they_can_do_header": "What They Can Do",
    "verdict_scam": "LIKELY A SCAM",
    "verdict_not_a_scam": "SAFE / LEGITIMATE",
    "verdict_uncertain": "SUSPICIOUS",
    "verdict_unknown": "UNABLE TO VERIFY",
    "risk_low": "Low Risk",
    "risk_medium": "Medium Risk",
    "risk_high": "High Risk",
    "risk_unknown": "Unknown Risk",
}
