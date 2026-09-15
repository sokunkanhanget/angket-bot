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
        "📖 <b>/howto</b> — Learn how to use Angket to check suspicious content.\n"
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
        "Check our subscription plans for higher daily limits.\n\n"
        "👉 <b>[ View Premium Plans ]</b>"
    ),

    "daily_scan_limit_reached": (
        "🚫 You've reached today's free link/message-scan limit ({limit}/day).\n\n"
        "Your limit will reset tomorrow. Want to keep scanning today? "
        "Check our subscription plans for higher daily limits.\n\n"
        "👉 <b>[ View Premium Plans ]</b>"
    ),

    "live_detect_trial_ended": (
        "⏰ Your 7-day free trial of Live Detect has ended.\n\n"
        "Live Detect automatically scans messages in your business chats. "
        "Subscribe to keep Live Detect active and continue protecting your chats.\n\n"
        "👉 <b>[ View Premium Plans ]</b>"
    ),
    "checking_status": "🔍 Checking",
    "check_usage_hint": "Usage: reply to a message with /check, or /check <url or text>.",
    "check_nothing_to_check": (
        "Nothing to check there - reply to a message with text or a link, "
        "or use /check <url or text>."
    ),
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

    # --- Reasons and recommendations written WITHOUT Gemini ------------
    # Gemini normally writes key_reasons/recommendations directly in the
    # user's language (see context_engine.py's _system_prompt), so those
    # needed no table entries. Every path that bypasses Gemini was
    # therefore emitting raw English into an otherwise fully-translated
    # Khmer reply: the offline fallback, both deterministic
    # short-circuits, the evidence-reconciliation overrides, and the
    # group-chat link reply. These keys close that.
    #
    # {placeholders} are filled by the caller and deliberately left
    # untranslated: scam-script category slugs, hostnames, engine counts.
    "reason_keyword_match": "Matched suspicious keywords: {matches}.",
    "reason_scam_script": "Message text closely matches a known '{category}' scam script.",
    "reason_link_flagged": "{host}: {detail}",
    "reason_file_malicious": "VirusTotal: {count} engine(s) flag the attached file as malicious.",
    "reason_override_file": (
        "Overridden: the attached file was independently confirmed malicious "
        "by VirusTotal, regardless of the message text."
    ),
    "reason_override_link": (
        "Overridden: at least one link in this message was independently "
        "flagged suspicious or dangerous, regardless of the message text."
    ),
    # No similarity score here on purpose - internal detection-method and
    # confidence details must never reach the user.
    "reason_override_scam_script": (
        "Overridden: message text closely matches a known '{category}' scam "
        "script, regardless of the model's own reading of it."
    ),
    "reason_dead_link": (
        "This link could not be verified: its address does not resolve or the "
        "server can't be reached, and the message has no other text to judge it "
        "by. That is a weak caution, not proof of a scam - dead links, typos and "
        "temporarily offline pages look the same from here."
    ),
    "reason_trusted_brand": (
        "{host} is a verified official domain, and following the link's own "
        "redirects/network trace found nothing suspicious."
    ),

    "rec_scam_no_interaction": (
        "Do not click any links, open any files, or share personal or financial details."
    ),
    "rec_scam_block_report": "Block and report the sender - this pattern matches known scam tactics.",
    "rec_uncertain_hold_off": (
        "Don't share personal details, click links, or send money until you're sure "
        "this is legitimate."
    ),
    "rec_uncertain_verify_sender": "Verify with the sender through a separate channel before acting.",
    "rec_safe_stay_cautious": (
        "No strong scam signals were found, but stay cautious with anything unexpected."
    ),
    "rec_dead_link_no_credentials": (
        "Don't enter any login or payment details on this link until you have "
        "confirmed it is genuine."
    ),
    "rec_dead_link_check_sender": (
        "If someone sent it to you, check through a channel you trust that they "
        "really meant to."
    ),

    # Link-checker (group-chat) recommendations - pipeline.py's own
    # _RECOMMENDATIONS, moved here so the group path can be translated
    # the same way every other surface already is.
    "rec_link_dangerous_no_entry": (
        "Do not open this link, log in, or enter any codes, passwords, or card details."
    ),
    "rec_link_dangerous_already_entered": (
        "If you already entered anything, change that password now and contact "
        "your bank or provider."
    ),
    "rec_link_dangerous_block": (
        "Block and report the sender — this pattern matches known scam tactics."
    ),
    "rec_link_suspicious_hold_off": (
        "Don't log in, pay, or enter personal details until you confirm this is legitimate."
    ),
    "rec_link_suspicious_go_direct": (
        "Go to the official site or app directly instead of clicking this link."
    ),
    "rec_link_suspicious_verify_sender": (
        "If someone sent this to you, verify with them through a separate channel first."
    ),
    "rec_link_safe_double_check": (
        "No strong scam signals were found, but always double-check before entering "
        "sensitive info."
    ),
    "rec_link_safe_match_address": (
        "Make sure the address matches the official site exactly before logging in."
    ),

    # --- File scanning -------------------------------------------------
    # The file checker never involves Gemini at all, so every reason and
    # recommendation it shows was fixed English - the last surface still
    # rendering English inside an otherwise Khmer reply. File extensions
    # and engine counts are real evidence and stay verbatim.
    "filename_warning_double_extension_executable": (
        "File name disguises an executable ('.{outer_ext}') behind a '.{inner_ext}' "
        "extension — a classic malware trick (e.g. 'invoice.pdf.exe')."
    ),
    "filename_warning_double_extension_archive": (
        "File name hides a '.{inner_ext}' file inside a '.{outer_ext}' archive — "
        "this bot cannot see inside archives, so the real content is unverified."
    ),
    "filename_warning_lone_executable": (
        "This is a '.{ext}' executable/script file — a common malware vector, "
        "especially when unsolicited."
    ),

    "reason_file_engines_flag": (
        "{malicious} of {total} security engines on VirusTotal flag this file as "
        "malicious (e.g. Microsoft: {top_engine})."
    ),
    "reason_file_clean_but_name_suspect": (
        "VirusTotal found no threats in this exact file ({total} engines checked), "
        "but its name is still worth a second look."
    ),
    "reason_file_no_engine_flags": "No security engine out of {total} on VirusTotal flags this file.",
    # Deliberately does not name the unavailable backend - state the real
    # limitation without the "why" (9th-session decision).
    "reason_file_name_only": "This result is based on the file name only, not a full antivirus scan.",
    "reason_file_never_seen": (
        "This file's signature has never been seen by VirusTotal before — no track "
        "record either way."
    ),
    "reason_file_no_name_flags": "No filename red flags were found either.",

    "rec_file_dangerous_do_not_open": "Do not open this file, run it, or extract its contents.",
    "rec_file_dangerous_already_opened": (
        "If you already opened it, disconnect from the internet and run a full "
        "antivirus scan."
    ),
    "rec_file_dangerous_delete_block": "Delete the file and block/report whoever sent it.",
    "rec_file_suspicious_verify_sender": (
        "Don't open this file until you've verified it with the sender through "
        "another channel."
    ),
    "rec_file_suspicious_scan_first": (
        "If you must open it, scan it with your own antivirus software first."
    ),
    "rec_file_safe_no_signals": (
        "No strong threat signals were found, but stay cautious with any unexpected "
        "attachment."
    ),
    "rec_file_safe_trusted_senders": "Only open files from senders you actually trust.",
    "rec_file_uncertain_caution": (
        "Treat this file with caution until it can be properly checked."
    ),
    "rec_file_uncertain_verify_sender": (
        "Verify the sender through another channel before opening it."
    ),
}
