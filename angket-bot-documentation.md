# Angket Bot — Project Documentation

**What it is:** a Telegram bot that reads messages, links, and files, and tells
the user whether something looks like a scam or phishing attempt.
**Who it's for:** anyone chatting with the bot directly, in a group, or a
business owner who connects it to their business account.
**Branch:** `BolBol`.

> **How to read this document:** it explains *what* each part does and *why*
> it exists, without needing to read the code first. File names in this doc
> match the real folder names in the repo.

## 1. The big picture

When someone sends the bot a message, one of three things can be inside it:
plain text, a link, or a file. The bot checks all three, then replies with a
verdict — how risky it looks, why, and what to do about it.

```
                 Telegram message
                        |
        +---------------+---------------+
        |               |               |
     plain text       a link         a file
        |               |               |
   text scanner    link checker    file scanner
        |               |               |
        +-------- combined into --------+
              ONE reply to the user
```

The three checks used to be separate and could disagree with each other. They
are now combined by one shared piece called the **Context Engine** (see
Section 4) so the bot gives one consistent answer instead of two
contradicting ones.

### Verdict levels

| Level | Meaning |
|---|---|
| 🟢 Safe / Not a Scam | No real warning signs found |
| 🟠 Suspicious / Uncertain | Some warning signs — be careful |
| 🔴 Dangerous / Scam | Strong evidence of a scam or phishing attempt |

## 2. The bot behaves differently depending on where you talk to it

This is one of the more important design decisions in the project, so it's
worth explaining clearly:

| Where | What happens |
|---|---|
| **Private chat with the bot** | The bot reads your text AND any link (and any attached file — see the update below) together, in one combined check, and replies with one full answer directly in the chat. |
| **Group / supergroup chat** | Text and links are still checked separately (this hasn't changed). A link gets a short preview reply with a button to see the full details in a private message with the bot. |
| **Business chat** (via Telegram's Business feature) | A business owner can connect Angket to their own business account. Every customer message — text, link, and/or file, all together — is checked once and reported privately to the OWNER only. The customer never sees the bot at all, and nothing is ever posted in the business chat itself. |

> **Why business chat is private-only:** anything the bot sends through a
> business connection would actually be sent AS the business account, so both
> the owner and the customer would see it. There's no way to reply "just to
> the owner" inside that chat — so instead the bot DMs the owner separately,
> in their own private chat with the bot, which the customer can't see.

## 3. Link Checker

Every link the bot finds gets checked from several different angles at once,
and every one of them can add "risk points" with a plain-language reason
attached. The points get added up into a final score (0–100+), which decides
the verdict level from the table above.

**What it looks at:**

- **The link's text itself** — is it a raw IP address? Does it try to trick
  you with an `@` symbol? Is it a lookalike of a real brand (e.g.
  `faceb00k.com`)? Does it use a known link-shortener or a suspicious domain
  ending? Is the link written in a broken way that a browser wouldn't
  normally accept?
- **Where the link actually goes** — the bot follows redirects and checks if
  it ends up somewhere completely different from what was shown.
- **How old the domain and its security certificate are** — a domain
  registered yesterday is a lot more suspicious than one that's been around
  for years.
- **The destination page itself** — does it have a login form that secretly
  sends your password somewhere else? Does it claim to be a bank or
  well-known brand while living on a completely different domain?
- **VirusTotal** — a well-known antivirus/threat-intelligence service is
  checked too, but only when the bot's own checks already found something
  suspicious, to avoid wasting the free daily quota on obviously clean links.
- **Past experience** — every link the bot has ever checked is remembered. If
  a new link closely resembles one that was flagged before, that counts as
  evidence too. The bot effectively gets smarter over time as more people use
  it.

> **Speed trick:** if the exact same link gets sent again within an hour, the
> bot reuses its last answer instead of re-checking everything from scratch.
> This matters a lot in group chats where the same link gets forwarded by
> many people — a check that used to take ~24 seconds now takes a fraction of
> a second on a repeat.

## 4. The Context Engine — combining everything into one answer

This is the part that ties text, links, and files together. Instead of the
text scanner and the link checker each giving their own separate opinion,
one combined check (powered by Google's Gemini AI) looks at everything at
once: the message wording, every link's findings, any file's scan result,
and how closely the message resembles known scam scripts — and produces a
single verdict.

> **Why this matters — a real example:** a scam message like *"Mom, I lost
> my phone, send $800 right now, don't call me"* is obviously a scam from
> the wording alone. But if the message also happened to include a
> harmless, dead link, the old system used to throw away the text analysis
> entirely and only look at the link — which came back clean. The same
> message went from 95% "definitely a scam" down to 40% "maybe fine",
> purely because of an unrelated link. The Context Engine fixes this by
> always looking at everything together.

If the AI service is unavailable (no internet, no API key, or a temporary
failure), the bot doesn't just give up — it falls back to checking the
message against a list of known scam-message patterns (family emergencies,
fake lottery wins, fake account warnings, romance scams, investment scams,
fake job offers, and people pretending to be authorities). This fallback is
deliberately cautious: it can only ever raise suspicion, never lower it.

> **Real bug fixed:** this pattern-matching (and the link checker's "past
> experience" memory in Section 3) both work by turning text into a list of
> numbers the computer can compare mathematically. The code that did this
> conversion only understood English letters and digits — a message written
> **entirely in Khmer script** produced a completely blank/empty result, not
> just a weak one, so both systems were silently unable to compare it against
> anything at all. Confirmed and fixed: Khmer text now converts properly.
> Worth knowing this doesn't (yet) mean a Khmer scam message reliably matches
> an English-written scam script — the known scam scripts themselves are
> still written in English — just that the underlying comparison itself no
> longer breaks on Khmer input.

**Recent improvements to this fallback/safety-net behavior:**

1. **The scam-script check now also helps the live AI, not just the
   fallback.** Previously, comparing a message against those known scam
   scripts only happened when the AI was unavailable. Now the AI sees that
   comparison too, as one more piece of evidence — and since the list of
   scripts is small and fixed, checking it is done instantly, from memory,
   with no real slowdown.
2. **A safety net now double-checks the AI's own answer.** The AI is told,
   in plain English, not to contradict evidence that already looks
   dangerous — but nothing used to actually enforce that. Now, if the AI
   ever says "safe" while a link, a file, or a scam-script match already
   says otherwise, the bot automatically corrects the verdict upward and
   logs the disagreement, so it can never quietly slip through.
3. **Private-chat file scanning is now part of the combined check too.** A
   file attached to a private message with a suspicious caption used to be
   scanned completely separately, with the combined check having no idea a
   file was even there. It's now included, the same way it already worked
   for business chat.
4. **When the AI is down, the reply no longer mixes in raw English.** The
   offline fallback used to append two hardcoded English sentences ("LLM
   analysis failed..." / "Full AI reasoning was unavailable...") straight
   into the reply body — so a Khmer user seeing the AI-down fallback got a
   reply that was part-Khmer, part-untranslated-English, with an empty
   "What You Should Do" section underneath. It's now a single, properly
   translated notice line in the user's own language, with the verdict and
   risk percentage still fully reflecting whatever real offline evidence
   was found (nothing about the actual detection changed, just how the
   "AI is unavailable" state gets communicated).

## 5. File Scanning

Any file sent to the bot gets hashed and checked against VirusTotal. If it's
found to be malicious, the bot shows a clear warning with buttons to delete
the message or dismiss the warning. In a business chat, files are checked as
part of the same combined check described in Section 4, instead of a
separate reply.

## 6. Two Languages: English and Khmer

The bot's menus and buttons are available in both English and Khmer.

**Scan results are now translated too — for private chat and business chat.**
When the AI (Gemini) generates a verdict's reasons and recommendations, it's
now asked to write them directly in the user's chosen language instead of
always English — live AI translation, exactly as the team agreed, rather than
pre-written fixed translations. The verdict/risk labels around that text
(e.g. "LIKELY A SCAM", "High Risk") are small and fixed, so those are
translated the same simple way the menus already are, not through the AI.

A few details worth knowing:
- **Translation only affects new replies, going forward** — a message already
  sent stays as it was; switching language never rewrites anything already
  sent.
- **Business chat translates based on the OWNER's language, not the
  customer's** — the owner is the only one who reads that notification, so
  it looks up whatever language the owner has set for themselves (if they've
  ever used the bot directly), not the customer sending the message.
- **Group chat is not covered yet.** Group-chat link replies don't go through
  the AI at all today — they're built from fixed English text baked directly
  into the code — so translating them is a separate, bigger piece of work,
  intentionally left for later.
- **The offline fallback** (when the AI is unavailable) still replies in
  English only, even if the user has switched to Khmer — it's already the
  degraded, less-accurate path, so this was left as a deliberate boundary
  rather than adding more translated text to a path that's meant to be a
  rare, temporary stand-in.

## 7. Where things live in the code

The code was reorganized around **what kind of content is being checked**
first (text / file / URL), and **what role a file plays** second (detection
logic vs. Telegram wiring vs. shared storage) — one consistent rule instead
of the previous mix, where e.g. the URL checker's own package held a
text-pattern file, and the link-checker's Telegram-wiring file was named and
placed differently than the other two handler files.

```
bot/
├── bot.py                 - entry point: builds the bot, registers every
│                             handler, decides which check runs where
├── config.py               - all the settings (API keys, thresholds, etc.)
├── context_engine.py        - the combined text+link+file AI reasoning (Section 4)
├── i18n.py                  - English / Khmer text
│
├── detectors/                - "what checks the content" - no Telegram code at all
│   ├── text/
│   │   ├── keyword.py           - simple keyword/phrase matching
│   │   ├── llm.py                - Gemini-based text analysis (group chat only)
│   │   └── scam_patterns.py       - the known scam-script list (Section 4)
│   ├── file/
│   │   └── scanner.py             - hashes a file and checks it against VirusTotal
│   └── url/                     - the link checker (Section 3)
│       ├── pipeline.py            - combines all the link signals into one verdict
│       ├── offline/                - checks that don't need the internet
│       └── online/                 - checks that do (domain age, VirusTotal, etc.)
│
├── handlers/                 - "how the bot replies" - all Telegram wiring, one place
│   ├── text_handler.py
│   ├── file_handler.py
│   └── url_handler.py            - link replies (private chat / group / business)
│
└── storage/                  - shared logging helpers every detector uses
    └── scan_log.py
```

## 8. Testing

The project has 191 automated tests covering all of the above, and they run
in a few seconds without needing real internet access or a real database.
To run them:

```
python -m pytest -q
```

A recent pass specifically added harder, edge-case tests that were missing
before — not just more "does the happy path work" checks:
- The Khmer-blindness bug above, so it can never silently come back.
- Every English menu/button text has a matching Khmer one, and vice versa —
  catches a future update that adds one language's wording but forgets the
  other.
- The safety-net in Section 4 correctly handles a link that's merely
  "suspicious" (not just the most severe "dangerous" level), and correctly
  leaves an already-correct AI answer alone instead of pushing it further.
- The "page claims to be a real bank/brand but lives elsewhere" detector,
  which had zero tests before despite being one of the harder checks to
  fool with simple tricks.
- Exact scoring-boundary numbers for domain age and certificate age (e.g.
  the score really does change at day 29 vs. day 30), instead of only ever
  being tested through a stand-in that skipped the real math.
- A caching bug in the certificate-age check: a "this site has no
  certificate info" result wasn't being remembered, so the bot was
  needlessly re-checking the same dead end on every scan of that site.
  Fixed and now covered by a test.

## 9. Startup & Performance

There are two genuinely different kinds of "how long does it take to start"
worth knowing about — they used to not be measured at all, and are easy to
mix up:

**1. Real startup** — happens once, when the bot process itself launches,
before it's ready to receive any Telegram messages. Measured live on a real
run:

| Phase | Time |
|---|---|
| Loading all the Python code (including setting up the connection to Gemini) | 1.899s |
| Setting up the local database tables | 0.001s |
| Building the Telegram connection | 0.326s |
| **Total time to start polling** | **~2.23s** |

**2. First-message cost** — a separate, smaller delay that happens once
per bot restart, but only when the *first* real Telegram message arrives,
not during startup itself. This is when the bot opens its connection to the
Supabase database and loads the known brand/scam-pattern reference data —
work that's deliberately deferred until it's actually needed, rather than
slowing down every single startup whether or not the vector-similarity
features end up being used. This is logged separately (search the bot's
logs for `[first-message]`) so it's never confused with the real startup
time above.

## 10. Built but not turned on yet

A few features have already been built and tested separately, but are
waiting on a decision before going live in the real bot:

| Idea | Status |
|---|---|
| Smarter AI-based text matching (better at catching paraphrased or Khmer-language scams) | Tested and working, waiting on hosting to be arranged |
| Matching scam websites by their icon (favicon) | Tested and working, no decision made yet |
| Letting users vote a verdict as "wrong" | Tested and working, waiting on a decision about who's allowed to submit corrections |
| A nicer, tabbed reply layout | Tested and working, just a design choice that hasn't been made yet |
| Paid subscription via QR payment | Built and tested — including fixing the generated QR code to actually match the real national KHQR bank-payment standard, which it didn't before — on hold while the team decides on a payment provider |
| Paid subscription via Telegram's own built-in payments ("Stars") | Built and tested; sending the actual payment request works live, completing a real payment wasn't tested (would cost real money) |
| Daily free-scan limit tied to a subscription | Tested and working as a standalone idea, not connected to anything real yet |
| Website purchase unlocking the Telegram subscription | Proven possible in a sandbox test using Telegram's official "Log in with Telegram" website button — but the real team website doesn't have any of this wired up yet (confirmed by reading its current code directly) |
| "Ephemeral" group replies — the full verdict breakdown in a group chat, visible only to whoever asked for it | Tested and working, no decision made yet |
| Richer, structured reply formatting (replaces hand-built text formatting, sidesteps a known formatting-escaping gap) | Tested and working, no decision made yet |
| Reply buttons that show which action was taken (Delete/Ignore) instead of swapping out the whole message | Tested and working, no decision made yet |
| "Guest mode" — the bot can reply to an @-mention in a group without the user ever having started a private chat with it first | Built, but needs a setting turned on in BotFather before it can even be tested live |
| Typing `@AngketBot <link>` in any chat's message box for an instant preview | Built, but needs a setting turned on in BotFather before it can even be tested live |
| Verdict Mini App: vibration feedback and remembering a user's collapsed/expanded preference between visits | The "remembering a preference" part is confirmed working; the vibration part only works on an actual phone, not in a browser, so it hasn't been tested there yet |

> **Also on the radar, not started:** Telegram's newer "Managed Bots" feature
> would let the bot read and act on *any* user's personal chats, not just
> business accounts connected on purpose. That's a bigger step than anything
> above, so no prototype has been built — it needs a team conversation first.

## 11. Sandbox: everything tested outside the real bot

Before an idea goes into the real bot, it usually gets built and tested on
its own first, in a separate sandbox folder (`next-gen-test/concepts/`,
outside this repository entirely) — so a rough idea can be proven or
disproven with real, working code before touching anything live. This is
the current, complete list of what's in there.

**Detection ideas already proven, listed in Section 10's table above (not
repeated here):** smarter AI-based text matching for paraphrased/Khmer
scams (`bge-m3-embedding`), matching scam sites by favicon
(`favicon-hashing-py`), letting users vote a verdict wrong
(`feedback-loop-py`), a tabbed reply layout (`multi-view-buttons-py`), and
every subscription/payment piece (`qr-subscription-py`, `scan-limit-py`,
`website-subscription-py`).

**Telegram feature prototypes (Bot API 10.x), all live-tested against the
real bot account, none turned on in the real bot yet:**
| Folder | What it proves |
|---|---|
| `ephemeral-verdict-py` | A full verdict breakdown posted in a group chat, but visible only to the one person who asked for it — everyone else in the group sees nothing. |
| `rich-verdict-py` | Replies built from Telegram's newer structured message format instead of hand-typed text formatting — sidesteps a known text-formatting bug class entirely. |
| `reply-markup-py` | Buttons that visibly show which choice was made (e.g. "Deleted ✓") instead of the whole message disappearing/changing abruptly. |
| `guest-mode-py` | Answering someone who @-mentions the bot in a group even if they've never messaged the bot privately before. Needs a bot-settings toggle turned on before it can be tested live. |
| `inline-mode-py` | Typing `@AngketBot <link>` in any chat's message box, anywhere in Telegram, for an instant preview. Also needs a bot-settings toggle first. |
| `verdict-mini-app` | A richer, app-like popup window (instead of a plain text message) for showing a verdict, with device features like vibration and remembering the user's preferences. |

**Detection ideas that were tried and then explicitly rejected by the team
(kept for reference, not because they might still ship):**
| Folder | Why it was rejected |
|---|---|
| `qr-link-detection-py` | Reading QR codes found inside photos — the team decided image-content scanning of any kind is out of scope. |
| `image-detection-py` | Using AI to read scam screenshots directly — same reason, out of scope. |

**Older prototypes, now superseded by what actually shipped in the real
bot (kept as historical reference — safe to delete if the folder is ever
cleaned up, since everything they proved now exists for real, and better,
in `bot/`):**
| Folder | Superseded by |
|---|---|
| `context-engineering` | `bot/context_engine.py` (Section 4) |
| `cert-age-py` | `bot/detectors/url/online/cert_info.py` (Section 3) |
| `message-checker-bot-py` | `bot/detectors/text/keyword.py` and the real business-chat flow (Section 2) |
| `vector-search-py`'s `vector-search.py` and `vector-search-postgres.py` files | `bot/detectors/url/offline/vectors.py`, now backed by a real hosted database — this folder's third file, `vector-search-gemini.py`, is NOT superseded and is what Section 10's "smarter AI-based text matching" row refers to |

---

*This document describes the project as of the current state of the
`BolBol` branch. Questions or corrections — just ask.*
