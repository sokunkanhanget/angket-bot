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

**Updated this session — three real improvements:**

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

```
bot/
├── bot.py                 - starts the bot, decides which check runs where
├── config.py               - all the settings (API keys, thresholds, etc.)
├── context_engine.py        - the combined text+link+file AI reasoning (Section 4)
├── i18n.py                  - English / Khmer text
│
├── analysis/                - text scanning and file scanning
│   ├── text_analyzer.py
│   ├── llm_analyzer.py
│   └── file_scanner.py
│
├── handlers/                 - what the bot actually replies with
│   ├── text_handler.py
│   └── file_handler.py
│
└── url_checker/               - the link checker (Section 3)
    ├── pipeline.py             - combines all the link signals into one verdict
    ├── message/handler.py       - how link replies are sent (chat / group / business)
    └── features/
        ├── offline/              - checks that don't need the internet
        │   └── scam_patterns.py   - the known scam-script list (Section 4)
        └── online/                - checks that do (domain age, VirusTotal, etc.)
```

## 8. Testing

The project has 142 automated tests covering all of the above, and they run
in a few seconds without needing real internet access or a real database.
To run them:

```
python -m pytest -q
```

## 9. Built but not turned on yet

A few features have already been built and tested separately, but are
waiting on a decision before going live in the real bot:

| Idea | Status |
|---|---|
| Smarter AI-based text matching (better at catching paraphrased or Khmer-language scams) | Tested and working, waiting on hosting to be arranged |
| Matching scam websites by their icon (favicon) | Tested and working, no decision made yet |
| Letting users vote a verdict as "wrong" | Tested and working, waiting on a decision about who's allowed to submit corrections |
| A nicer, tabbed reply layout | Tested and working, just a design choice that hasn't been made yet |
| Paid subscription via QR payment | Built and tested, on hold while the team decides on a payment provider |

---

*This document describes the project as of the current state of the
`BolBol` branch. Questions or corrections — just ask.*
