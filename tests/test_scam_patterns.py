"""
tests/test_scam_patterns.py
=============================
nearest_scam_pattern() is a local, in-memory search (no DB, no mocking
needed) - see scam_patterns.py's own docstring for why: the whole
SCAM_MESSAGE_PATTERNS corpus is ~30 static rows, too small to justify a
Supabase round trip every time it's consulted.
"""

import pytest

from bot.config.config import SCAM_PATTERN_THRESHOLD
from bot.detectors.text.offline.scam_patterns import (
    SCAM_MESSAGE_PATTERNS,
    nearest_scam_pattern,
)
from bot.detectors.url.offline.vectors import embed


def test_nearest_scam_pattern_matches_a_near_exact_scam_script():
    text = ("Mom, this is urgent, I lost my phone and I'm texting from a friend's. "
            "I need you to send $800 right now to help me, don't call, just trust me "
            "on this one time.")

    hits = nearest_scam_pattern(text, k=1)

    assert hits[0][1] == "scam_pattern"
    assert hits[0][3] == "family_emergency"
    assert hits[0][0] >= 0.5


def test_nearest_scam_pattern_scores_benign_text_low():
    hits = nearest_scam_pattern("hey, are we still on for lunch tomorrow?", k=1)

    assert hits[0][0] < 0.3


def test_nearest_scam_pattern_returns_empty_for_empty_text():
    assert nearest_scam_pattern("", k=1) == []
    assert nearest_scam_pattern("!!!???...", k=1) == []


def test_nearest_scam_pattern_covers_every_seeded_category():
    # The local index must actually contain every category
    # SCAM_MESSAGE_PATTERNS defines, not a stale/partial copy.
    hits = nearest_scam_pattern(
        "This is the tax department, you owe unpaid taxes, pay immediately "
        "or a warrant will be issued for your arrest.", k=1,
    )
    assert hits[0][3] == "authority_impersonation"
    assert set(SCAM_MESSAGE_PATTERNS.keys()) == {
        "family_emergency", "lottery_prize", "account_verification",
        "romance", "investment_crypto", "job_offer", "authority_impersonation",
    }


def test_nearest_scam_pattern_respects_k():
    hits = nearest_scam_pattern("send money now urgent", k=3)
    assert len(hits) == 3
    # best-first
    assert hits[0][0] >= hits[1][0] >= hits[2][0]


def test_embed_produces_real_signal_for_khmer_only_text():
    # Regression: _TOKEN_RE used to be r"[a-z0-9]+" (ASCII-only), so a
    # pure-Khmer message tokenized to nothing and embed() returned {} -
    # not "low similarity", literally zero signal, for a Khmer-first
    # bot. This test only proves the embedding itself is no longer
    # degenerately empty for Khmer input; whether Khmer text actually
    # MATCHES the corpus is covered by the Khmer coverage tests below,
    # which exist because that needed Khmer seed scripts too, not just a
    # working tokenizer.
    khmer_scam = "សូមផ្ញើលុយ ១០០ដុល្លារ ឥឡូវនេះ បន្ទាន់ណាស់"  # "please send $100 now, urgent"
    vec = embed(khmer_scam)
    assert vec != {}

    # Two different Khmer messages must produce different embeddings,
    # not the same degenerate fallback - proves this is real per-message
    # signal, not a constant.
    other_khmer = "អរគុណច្រើន សូមអញ្ជើញមកលេងផ្ទះខ្ញុំនៅចុងសប្តាហ៍នេះ"  # unrelated benign text
    assert embed(other_khmer) != vec


def test_nearest_scam_pattern_does_not_silently_short_circuit_on_khmer_text():
    # End-to-end: nearest_scam_pattern has an explicit `if not q: return []`
    # short-circuit for a genuinely empty query (e.g. "!!!???..." - see
    # test_nearest_scam_pattern_returns_empty_for_empty_text above). Before
    # the embed() fix, EVERY pure-Khmer message hit that same short-circuit
    # too - indistinguishable from actually-empty input. Now it must return
    # a real (possibly low-similarity, given the cross-lingual gap noted
    # above) scored result instead.
    hits = nearest_scam_pattern("សូមផ្ញើលុយ ១០០ដុល្លារ ឥឡូវនេះ បន្ទាន់ណាស់", k=1)
    assert len(hits) == 1
    assert 0.0 <= hits[0][0] <= 1.0


# --- Khmer coverage ----------------------------------------------------
# SCAM_MESSAGE_PATTERNS used to hold English scripts only, so a scam
# written in Khmer scored 0.0556-0.1663 here (measured) - far under
# SCAM_PATTERN_THRESHOLD, meaning it contributed nothing at all to the
# offline signal on a bot built for a Khmer-first audience. Khmer
# scripts were added per category to close that.
#
# Every message below is HELD OUT: a paraphrase, never a copy of a seed
# string, so these measure real generalisation rather than an identity
# match against the corpus.

KHMER_SCAM_MESSAGES = [
    # Mom, I lost my phone, this is a new number, send $300 to this account now.
    ("family_emergency",
     "ម៉ាក់ ទូរស័ព្ទកូនបាត់ នេះលេខថ្មី។ កូនត្រូវការលុយឥឡូវនេះ សូមផ្ញើ ៣០០ដុល្លារ មកគណនីនេះ។"),
    # Congratulations, you won $5,000, click this link and enter your bank details.
    ("lottery_prize",
     "សូមអបអរសាទរ! អ្នកបានឈ្នះរង្វាន់ ៥,០០០ដុល្លារ។ ចុចលីងនេះ ហើយបញ្ចូលព័ត៌មានធនាគាររបស់អ្នក។"),
    # Your account will be closed in 24 hours, verify via this link now.
    ("account_verification",
     "គណនីរបស់អ្នកនឹងត្រូវបិទក្នុងរយៈពេល ២៤ម៉ោង។ សូមផ្ទៀងផ្ទាត់ព័ត៌មានតាមតំណភ្ជាប់នេះឥឡូវនេះ។"),
    # Unusual activity on your account, send us your OTP code now.
    ("account_verification",
     "មានសកម្មភាពមិនប្រក្រតីក្នុងគណនីរបស់អ្នក។ សូមផ្ញើលេខកូដ OTP មកឲ្យយើងឥឡូវនេះ។"),
    # Work from home, $80 a day, just click Like, inbox us if interested.
    ("job_offer",
     "ការងារធ្វើនៅផ្ទះ ចំណូល ៨០ដុល្លារមួយថ្ងៃ គ្រាន់តែចុច Like។ ចាប់អារម្មណ៍សូម inbox មក។"),
    # You passed the interview, salary $1,000, pay a $50 registration fee first.
    ("job_offer",
     "អ្នកជាប់ការសម្ភាសន៍ហើយ ប្រាក់ខែ ១,០០០ដុល្លារ។ សូមបង់ថ្លៃចុះឈ្មោះ ៥០ដុល្លារជាមុន។"),
    # Police: you are involved in money laundering, transfer funds or be arrested.
    ("authority_impersonation",
     "នគរបាល៖ អ្នកជាប់ពាក់ព័ន្ធនឹងរឿងសម្អាតប្រាក់។ សូមផ្ទេរប្រាក់ទៅគណនីរបស់រដ្ឋ បើមិនដូច្នេះទេអ្នកនឹងត្រូវចាប់ខ្លួន។"),
    # Your package is held at customs, pay the fine immediately to avoid arrest.
    ("authority_impersonation",
     "កញ្ចប់របស់អ្នកត្រូវបានឃុំនៅពន្ធគយ។ សូមបង់ប្រាក់ពិន័យភ្លាមៗ ដើម្បីជៀសវាងការចាប់ខ្លួន។"),
    # Invest $200, get $2,000 in 7 days, 100% guaranteed.
    ("investment_crypto",
     "វិនិយោគ ២០០ដុល្លារ ទទួលបាន ២,០០០ដុល្លារ ក្នុងរយៈពេល ៧ថ្ងៃ ធានា ១០០%។"),
    # Our trading group guarantees 20% profit daily, join our Telegram now.
    ("investment_crypto",
     "ក្រុមជួញដូររបស់យើងធានាចំណេញ ២០% រាល់ថ្ងៃ។ ចូលរួមក្រុមតេលេក្រាមឥឡូវនេះ។"),
    # My love, I sent you a gift package but you must pay the customs fee first.
    ("romance",
     "ស្នេហាខ្ញុំ ខ្ញុំផ្ញើកញ្ចប់អំណោយមកឲ្យអ្នក ប៉ុន្តែអ្នកត្រូវបង់ថ្លៃពន្ធគយសិន។"),
]

# Ordinary Khmer messages. The ones marked HARD deliberately talk about
# money, banks, accounts, transfers, salaries, jobs, investment and
# urgency WITHOUT being scams - the exact material that would produce
# false positives if the Khmer patterns were matching on "is this Khmer
# and about money" rather than on the scam script itself.
KHMER_BENIGN_MESSAGES = [
    "សុខសប្បាយទេ? ថ្ងៃនេះខ្ញុំទៅផ្សារ។",
    "បងអើយ ខ្ញុំមកដល់ហើយ រង់ចាំនៅមុខផ្ទះ។",
    "ម៉ាក់ ថ្ងៃនេះកូនមកផ្ទះយឺតបន្តិច។",
    "អរគុណច្រើនសម្រាប់ជំនួយរបស់បង។",
    "ប្រជុំនៅម៉ោង ៣ រសៀលនេះ សូមកុំមកយឺត។",
    "ថ្ងៃស្អែកយើងទៅលេងសៀមរាបជាមួយគ្នា។",
    "តើអ្នកមានពេលទំនេរនៅល្ងាចនេះទេ?",
    "កូនប្រលងជាប់ហើយម៉ាក់ អរគុណម៉ាក់ច្រើន។",
    "ថ្ងៃនេះញ៉ាំបាយជាមួយគ្នានៅភោជនីយដ្ឋានដើមទេ?",
    # HARD: "I already transferred the money to your account, please check."
    "ខ្ញុំបានផ្ទេរលុយទៅគណនីរបស់បងហើយ សូមពិនិត្យមើល។",
    # HARD: a real bank notification about a salary payment.
    "ធនាគារបានផ្ញើសារបញ្ជាក់ការទូទាត់ប្រាក់ខែរបស់អ្នក។",
    # HARD: a real urgent request from a colleague.
    "បង ជួយផ្ញើឯកសារមកឲ្យខ្ញុំបន្ទាន់ផង ខ្ញុំត្រូវការវាថ្ងៃនេះ។",
    # HARD: "this month's salary is in the account, check at the bank."
    "ប្រាក់ខែខែនេះចូលគណនីហើយ សូមពិនិត្យមើលនៅធនាគារ។",
    # HARD: a genuine question about investing in Cambodia.
    "ខ្ញុំចង់សួរបងអំពីការវិនិយោគនៅក្នុងប្រទេសកម្ពុជា តើបងមានចំណេះដឹងទេ?",
    # HARD: a real company recruitment message.
    "ក្រុមហ៊ុនយើងកំពុងជ្រើសរើសបុគ្គលិកថ្មី សូមផ្ញើប្រវត្តិរូបមកតាមអ៊ីមែល។",
]


@pytest.mark.parametrize("expected_category, message", KHMER_SCAM_MESSAGES)
def test_khmer_scam_messages_clear_the_threshold(expected_category, message):
    hits = nearest_scam_pattern(message, k=1)

    assert hits, "Khmer message produced no scored result at all"
    similarity, kind, _key, category = hits[0]
    assert kind == "scam_pattern"
    assert similarity >= SCAM_PATTERN_THRESHOLD, (
        f"{similarity:.4f} is below SCAM_PATTERN_THRESHOLD "
        f"{SCAM_PATTERN_THRESHOLD} - measured range for these was 0.5575-0.7134"
    )
    assert category == expected_category


@pytest.mark.parametrize("message", KHMER_BENIGN_MESSAGES)
def test_benign_khmer_messages_stay_below_the_threshold(message):
    # The whole risk of adding Khmer seeds: the tokenizer treats Khmer
    # script as long pseudo-tokens and takes character n-grams over them,
    # so patterns could in principle match any Khmer text just for being
    # Khmer. Measured benign range after the addition: 0.0938-0.2379,
    # comfortably under the 0.5 threshold.
    hits = nearest_scam_pattern(message, k=1)

    assert hits
    assert hits[0][0] < SCAM_PATTERN_THRESHOLD, (
        f"benign Khmer message scored {hits[0][0]:.4f}, at or above "
        f"SCAM_PATTERN_THRESHOLD {SCAM_PATTERN_THRESHOLD}"
    )


def test_khmer_scam_and_benign_ranges_stay_separated():
    # A single margin check over the whole set, so a future seed edit
    # that narrows the gap fails here rather than silently eroding it.
    scam_scores = [nearest_scam_pattern(m, k=1)[0][0] for _cat, m in KHMER_SCAM_MESSAGES]
    benign_scores = [nearest_scam_pattern(m, k=1)[0][0] for m in KHMER_BENIGN_MESSAGES]

    assert min(scam_scores) > max(benign_scores)
    # Measured gap at the time of writing: +0.3196. Asserting a much
    # looser 0.15 so ordinary re-tuning doesn't trip it, while a real
    # collapse of the separation still does.
    assert min(scam_scores) - max(benign_scores) > 0.15


def test_every_category_has_both_english_and_khmer_examples():
    # A category left English-only would be a silent Khmer blind spot
    # for that whole scam type.
    khmer_range = range(0x1780, 0x1800)

    for category, examples in SCAM_MESSAGE_PATTERNS.items():
        has_khmer = any(any(ord(ch) in khmer_range for ch in text) for text in examples)
        has_english = any(not any(ord(ch) in khmer_range for ch in text) for text in examples)
        assert has_khmer, f"{category} has no Khmer example"
        assert has_english, f"{category} has no English example"
