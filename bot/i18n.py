DEFAULT_LANG = "en"

BUTTONS = {
    "en": {
        "menu": "MENU",
        "switch_language": "🌐 Switch Language",
        "lang_en": "English",
        "lang_km": "ខ្មែរ",
        "back": "↩️ Back",
        "how_to_use": "📖 How to Use",
        "safety_tips": "🛡️ Safety Tips",
        "live_scan": "🔎 Live Message Scan",
        "policy": "📜 Policy",
        "help": "❓ Help",
        "subscription": "⭐ Subscription",
        "delete": "🗑️ Delete",
        "ignore": "🙈 Ignore",
        "view_on_virustotal": "📊 View on VirusTotal",
    },
    "km": {
        "menu": "ម៉ឺនុយ",
        "switch_language": "🌐 ផ្លាស់ប្តូរភាសា",
        "lang_en": "English",
        "lang_km": "ខ្មែរ",
        "back": "↩️ ត្រឡប់ក្រោយ",
        "how_to_use": "📖 របៀបប្រើប្រាស់",
        "safety_tips": "🛡️ គន្លឹះសុវត្ថិភាព",
        "live_scan": "🔎 ការពិនិត្យដោយស្វ័យប្រវត្តិ",
        "policy": "📜 គោលការណ៍",
        "help": "❓ ជំនួយ",
        "subscription": "⭐ ការជាវ",
        "delete": "🗑️ លុប",
        "ignore": "🙈 មិនអើពើ",
        "view_on_virustotal": "📊 មើលនៅលើ VirusTotal",
    },
}

TEXT = {
    "en": {
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
        "safety_tips": (
            "🛡️ <b>Safety Tips</b>\n\n"
            "Stay safe online with these simple rules:\n\n"
            "🛑 <b>1. STOP</b>\n"
            "• Don't rush when someone asks for money or personal information.\n"
            "• Take a moment before clicking, replying, or paying.\n\n"
            "🔎 <b>2. CHECK</b>\n"
            "• Check who sent the message.\n"
            "• Be careful with unexpected links and offers.\n"
            "• Verify the information through a trusted or official source.\n\n"
            "🔐 <b>3. PROTECT</b>\n"
            "• Never share your password or security codes.\n"
            "• Protect your personal and financial information.\n"
            "• Keep your accounts and devices secure.\n\n"
            "<b>Remember</b>\n"
            "A message can look real and still be a scam.\n"
            "Stop. Check. Protect.\n\n"
            "🤔 <b>Not sure about something?</b>\n\n"
            "Send it to Angket Bot and let us help you check it:\n\n"
            "📝 Suspicious message\n"
            "📄 Suspicious file\n"
            "🔗 Suspicious URL"
        ),
        "live_scan": "🔎 <b>Live Message Scan</b>\n\nSend me any message and I’ll scan it in real time.",
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
        "help": "❓ <b>Help</b>\n\nNeed assistance? Just send your question and we'll do our best to help.",
        "subscription": "⭐ <b>Subscription</b>\n\nSubscription plans are coming soon.",
        "file_deleted": "🗑️ Message deleted.",
        "file_scan_ignored": "🙈 Ignored. No action taken.",
        "file_scan_failed": (
            "⚠️ Could not finish scanning this file right now (the download or "
            "the virus-check service failed). Please try again in a moment."
        ),
        # --- Verdict reply content (private DM / business chat only -
        # group chat stays English, see bot/route.py's TEXT_FILTER scope
        # notes) - the FIXED labels/headers around Gemini's own dynamic
        # key_reasons/recommendations text. Gemini generates those in the
        # target language directly (see context_engine.py's lang param);
        # these are the surrounding static strings, translated once here
        # instead of round-tripping through the model for a handful of
        # fixed words every single call. -----------------------------
        "checking_status": "🔍 Checking...",
        "verdict_label": "VERDICT",
        "key_reasons_header": "KEY REASONS",
        "what_to_do_header": "WHAT YOU SHOULD DO",
        "keyword_match_label": "KEYWORD MATCH",
        "none_provided": "None provided",
        "ai_unavailable_notice": (
            "AI reasoning was unavailable for this check - this result uses "
            "offline pattern matching only and may be less accurate than usual."
        ),
        "summary_warning_signs": "This message has warning signs. Verify it before taking action.",
        "summary_strong_unsafe": "This message shows strong signs of being unsafe.",
        "summary_no_indicators": "No strong scam indicators were detected in this message.",
        "verdict_disclaimer": (
            "ⓘ Angket Bot may occasionally make mistakes.\n"
            "Double-check important information before taking action."
        ),
        "business_new_activity": "👀 New activity in your business chat",
        "business_disclaimer": "ⓘ Bot can make mistakes. Please check carefully.",
        "business_what_they_can_do_header": "What They Can Do",
        "verdict_scam": "LIKELY A SCAM",
        "verdict_not_a_scam": "SAFE / LEGITIMATE",
        "verdict_uncertain": "SUSPICIOUS",
        "verdict_unknown": "UNABLE TO VERIFY",
        "risk_low": "Low Risk",
        "risk_medium": "Medium Risk",
        "risk_high": "High Risk",
        "risk_unknown": "Unknown Risk",
    },
    "km": {
        "switch_language": "🌐 <b>ផ្លាស់ប្តូរភាសា</b>",
        "language_set": "ភាសាត្រូវបានកំណត់ជា ខ្មែរ។",
        "menu_title": "📋 <b>ម៉ឺនុយ</b>\n\nសូមជ្រើសរើសសកម្មភាពខាងក្រោម។",
        "how_to_use": (
            "📖 <b>របៀបប្រើប្រាស់ Angket Bot</b>\n\n"
            "Angket ជួយអ្នកពិនិត្យមាតិកាដែលគួរឱ្យសង្ស័យនិងស្វែងយល់អំពីកម្រិត ហានិភ័យនៃមាតិកាទាំងនោះ។\n\n"
            "<b>1. ផ្ញើរមាតិកាដែលអ្នកចង់ពិនិត្យ</b>\n\n"
            "• 📝 ផ្ញើសារដែលគួរឱ្យសង្ស័យ\n"
            "• 📄 បង្ហោះឯកសារដែលគួរឱ្យសង្ស័យ\n"
            "• 🔗 ផ្ញើ URL ឬតំណភ្ជាប់\n\n"
            "<b>2. អនុញ្ញាតឱ្យ Angket វិភាគ</b>\n\n"
            "Angket"" នឹងស្កេននិងវិភាគមាតិកាដើម្បីស្វែងរកសញ្ញាឬការគំរាមកំហែងណាមួយ ដែលអាចកើតមានឡើង។\n\n"
            "<b>3. លទ្ធផលទទួលបាន</b>\n\n"
            "អ្នកនឹងទទួលបាន៖\n\n"
            "• 📊 <b>កម្រិតហានិភ័យ៖</b> បង្ហាញថាមាតិកានោះអាចមានហានិភ័យកម្រិតណា។\n"
            "• 🔍 <b>មូលហេតុសំខាន់ៗ៖</b> បង្ហាញពីមូលហេតុដែលមាតិកានោះត្រូវបាន​សម្គាល់ ថាគួរឱ្យសង្ស័យ។\n"
            "• 💡 <b>អ្វីដែលគួរធ្វើ៖</b> ផ្តល់ការណែនាំដែលអ្នកគួរធ្វើបន្ទាប់។\n\n"
            "<b>កម្រិតហានិភ័យ</b>\n"
            "🟢 <b>ហានិភ័យទាប៖</b> មិនបានរកឃើញការគំរាមកំហែងសំខាន់ៗទេ។\n"
            "🟡 <b>ហានិភ័យមធ្យម៖</b> រកឃើញសញ្ញាមួយចំនួនដែលគួរឱ្យសង្ស័យ។ សូមប្រុងប្រយ័ត្ន។\n"
            "🔴 <b>ហានិភ័យខ្ពស់៖</b> រកឃើញសញ្ញាហានិភ័យខ្លាំងដែលអាចបង្ហាញពីការគំរាម កំហែង។ សូមជៀសវាង ការចុច ឬធ្វើសកម្មភាពណាមួយជាមួយមាតិកានោះ។"
        ),
        "safety_tips": (
            "🛡️ <b>គន្លឹះសុវត្ថិភាព</b>\n\n"
            "រក្សាសុវត្ថិភាពរបស់អ្នកនៅលើអ៊ីនធឺណិត ដោយអនុវត្តតាមគោលការណ៍សាមញ្ញៗទាំងនេះ៖\n\n"
            "🛑 <b>1. បញ្ឈប់</b>\n"
            "• សូមកុំប្រញាប់ នៅពេលមានអ្នកស្នើសុំលុយ ឬព័ត៌មានផ្ទាល់ខ្លួន។\n"
            "• សូមចំណាយពេលបន្តិច មុនពេលចុចតំណ ឆ្លើយតប ឬធ្វើការទូទាត់។\n\n"
            "🔎 <b>2. ពិនិត្យឱ្យបានច្បាស់</b>\n"
            "• ពិនិត្យថា អ្នកណាជាអ្នកផ្ញើសារ។\n"
            "• ប្រុងប្រយ័ត្នចំពោះតំណភ្ជាប់ ឬការផ្តល់ជូនដែលអ្នកមិនបានរំពឹងទុក។\n"
            "• ផ្ទៀងផ្ទាត់ព័ត៌មានតាមរយៈប្រភពដែលអាចទុកចិត្តបាន ឬប្រភពផ្លូវការ។\n\n"
            "🔐 <b>3. ការពារខ្លួន</b>\n"
            "• កុំចែករំលែកពាក្យសម្ងាត់ ឬលេខកូដសុវត្ថិភាពរបស់អ្នក។\n"
            "• ការពារព័ត៌មានផ្ទាល់ខ្លួន និងព័ត៌មានហិរញ្ញវត្ថុរបស់អ្នក។\n"
            "• រក្សាគណនី និងឧបករណ៍របស់អ្នកឱ្យមានសុវត្ថិភាពជានិច្ច។\n\n"
            "📱 <b>សូមចងចាំ</b>\n\n"
            "សារមួយចំនួនអាចមើលទៅដូចជាពិតមិនមានហានិភ័យ ប៉ុន្តែវាអាចជាការឆបោកបាន។\n\n"
            "បញ្ឈប់ ពិនិត្យ ការពារ\n\n"
            "🤔 <b>មិនប្រាកដចំពោះអ្វីមួយមែនទេ?</b>\n\n"
            "សូមធ្វើការផ្ញើទៅ Angket Bot ដើម្បីជួយពិនិត្យ៖\n\n"
            "📝 សារដែលគួរឱ្យសង្ស័យ\n"
            "📄 ឯកសារដែលគួរឱ្យសង្ស័យ\n"
            "🔗 URL ឬតំណភ្ជាប់ដែលគួរឱ្យសង្ស័យ"
        ),
        "live_scan": "🔎 <b>ការពិនិត្យដោយស្វ័យប្រវត្តិ</b>\n\nផ្ញើសារណាមួយមកកាន់ Angket Bot ដើម្បីស្កេនវាភ្លាមៗ។",
        "policy": (
            "📋 <b>គោលការណ៍ប្រើប្រាស់ Angket Bot</b>\n\n"
            "សូមអានគោលការណ៍របស់យើង ដើម្បីយល់ពីរបៀបដែល Angket គ្រប់គ្រងព័ត៌មានរបស់អ្នក និងរបៀបប្រើប្រាស់សេវាកម្មឱ្យបានត្រឹមត្រូវ។\n\n"
            "🔐 <b>ឯកជនភាព</b>\n\n"
            "• យើងអាចប្រមូលព័ត៌មានដែលចាំបាច់ ដើម្បីកែលម្អសេវាកម្មពិនិត្យសុវត្ថិភាព។\n"
            "• សារ ឯកសារ និង URL ដែលអ្នកផ្ញើ ត្រូវបានដំណើរការ ដើម្បីវិភាគហានិភ័យផ្នែកសុវត្ថិភាព។\n"
            "• យើងរក្សាទុកទិន្នន័យដែលអ្នកបានផ្ញើ ត្រឹមរយៈពេលដែលចាំបាច់ ស្របតាមគោលការណ៍រក្សាទុកទិន្នន័យរបស់យើង។\n"
            "• យើងមិនចែករំលែកព័ត៌មានរបស់អ្នកទៅភាគីទីបីឡើយ លើកលែងតែចាំបាច់សម្រាប់ការផ្តល់សេវាកម្ម ឬតម្រូវដោយច្បាប់។\n\n"
            "📄 <b>លក្ខខណ្ឌប្រើប្រាស់</b>\n\n"
            "• <b>គោលបំណងរបស់ Angket:</b> Angket ជួយអ្នកកំណត់អត្តសញ្ញាណសារ ឯកសារ និង តំណភ្ជាប់ ដែលអាចមានភាពគួរឱ្យសង្ស័យ។\n\n"
            "• <b>ការវិភាគមានកម្រិត:</b> លទ្ធផលពី Angket គឺជាការវាយតម្លៃ មិនមែនជាការធានាថាមាតិកានោះមានសុវត្ថិភាព ឬជាការឆបោកជាក់លាក់ឡើយ។ សារដែលត្រូវបានសម្គាល់ថាមានសុវត្ថិភាព ក៏អាចមានគ្រោះថ្នាក់បាន ហើយលទ្ធផលដែលគួរឱ្យសង្ស័យ ក៏មិនមានន័យថាវាជាការឆបោកជានិច្ចនោះទេ។\n\n"
            "• <b>ការទទួលខុសត្រូវរបស់អ្នក:</b> តែងតែផ្ទៀងផ្ទាត់ព័ត៌មានសំខាន់ៗដោយខ្លួនឯង មុនពេលចុចតំណភ្ជាប់ ចែករំលែកព័ត៌មាន ឬផ្ញើប្រាក់។\n\n"
            "⚠️ <b>ព័ត៌មានសំខាន់</b>\n\n"
            "Angket គឺជាឧបករណ៍ជំនួយផ្នែកសុវត្ថិភាព។ វាមិនអាចធានាថានឹងរកឃើញការគំរាមកំហែង ឬការឆបោកគ្រប់ប្រភេទបានទាំងអស់នោះទេ។"
        ),
        "help": "❓ <b>ជំនួយ</b>\n\nត្រូវការជំនួយ? គ្រាន់តែផ្ញើសំណួររបស់អ្នក ហើយយើងនឹងខិតខំជួយអ្នកឱ្យបានល្អបំផុត។",
        "subscription": "⭐ <b>ការជាវ</b>\n\nគម្រោងជាវនឹងមកដល់ឆាប់ៗនេះ។",
        "file_deleted": "🗑️ សារត្រូវបានលុប។",
        "file_scan_ignored": "🙈 មិនអើពើ។ គ្មានសកម្មភាពត្រូវបានធ្វើឡើយ។",
        "file_scan_failed": (
            "⚠️ មិនអាចបញ្ចប់ការពិនិត្យឯកសារនេះបានទេនាពេលនេះ "
            "(ការទាញយក ឬសេវាកម្មពិនិត្យមេរោគបានបរាជ័យ)។ សូមព្យាយាមម្តងទៀតក្នុងពេលបន្តិចទៀត។"
        ),
        # NOTE: translated by Claude, not yet reviewed by a native Khmer
        # speaker on the team - flag any wording that reads oddly before
        # this goes live for real users, same caveat as this session's
        # other new Khmer text (see the bge-m3 sandbox test messages).
        "checking_status": "🔍 កំពុងពិនិត្យ...",
        "verdict_label": "លទ្ធផល",
        "key_reasons_header": "មូលហេតុសំខាន់ៗ",
        "what_to_do_header": "អ្វីដែលគួរធ្វើ",
        "keyword_match_label": "ពាក្យគន្លឹះដែលត្រូវគ្នា",
        "none_provided": "មិនមានទិន្នន័យ",
        "ai_unavailable_notice": (
            "ការវិភាគ AI មិនអាចប្រើប្រាស់បានទេសម្រាប់ការត្រួតពិនិត្យនេះ — "
            "លទ្ធផលនេះផ្អែកលើការផ្គូផ្គងលំនាំក្រៅបណ្តាញប៉ុណ្ណោះ "
            "ហើយអាចមានភាពត្រឹមត្រូវតិចជាងធម្មតា។"
        ),
        "summary_warning_signs": "សារនេះមានសញ្ញាគួរឱ្យប្រុងប្រយ័ត្ន។ សូមផ្ទៀងផ្ទាត់មុននឹងធ្វើសកម្មភាព។",
        "summary_strong_unsafe": "សារនេះបង្ហាញសញ្ញាខ្លាំងថាមិនមានសុវត្ថិភាព។",
        "summary_no_indicators": "រកមិនឃើញសញ្ញាការឆបោកខ្លាំងក្នុងសារនេះទេ។",
        "verdict_disclaimer": (
            "ⓘ Angket Bot អាចមានកំហុសខ្លះជួនកាល។\n"
            "សូមផ្ទៀងផ្ទាត់ព័ត៌មានសំខាន់ៗម្តងទៀត មុននឹងធ្វើសកម្មភាព។"
        ),
        "business_new_activity": "👀 សកម្មភាពថ្មីនៅក្នុងជជែកអាជីវកម្មរបស់អ្នក",
        "business_disclaimer": "ⓘ Bot អាចមានកំហុសខ្លះ។ សូមពិនិត្យដោយប្រុងប្រយ័ត្ន។",
        "business_what_they_can_do_header": "អ្វីដែលពួកគេអាចធ្វើបាន",
        "verdict_scam": "ទំនងជាការឆបោក",
        "verdict_not_a_scam": "សុវត្ថិភាព / ត្រឹមត្រូវ",
        "verdict_uncertain": "គួរឱ្យសង្ស័យ",
        "verdict_unknown": "មិនអាចផ្ទៀងផ្ទាត់បាន",
        "risk_low": "ហានិភ័យទាប",
        "risk_medium": "ហានិភ័យមធ្យម",
        "risk_high": "ហានិភ័យខ្ពស់",
        "risk_unknown": "ហានិភ័យមិនស្គាល់",
    },
}


def _normalize_lang(lang: str | None) -> str:
    return lang if lang in BUTTONS else DEFAULT_LANG


def t(lang: str | None, key: str) -> str:
    locale = _normalize_lang(lang)
    return TEXT.get(locale, {}).get(key) or TEXT.get(DEFAULT_LANG, {}).get(key) or key


def label(lang: str | None, key: str) -> str:
    locale = _normalize_lang(lang)
    return BUTTONS.get(locale, {}).get(key) or BUTTONS.get(DEFAULT_LANG, {}).get(key) or key


def key_for_label(text: str) -> str | None:
    normalized = (text or "").strip()
    if not normalized:
        return None

    for lang, labels in BUTTONS.items():
        for key, label_text in labels.items():
            if normalized == label_text:
                return key
    return None
