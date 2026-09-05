# Onboarding — angket-bot

For picking this project back up after a break, or for a teammate joining `BolBol`'s work specifically. This is a pointer document, not a replacement for what already exists:

- **`angket-bot-documentation.md`** — the real reference: what each feature does, the startup/performance numbers, the full sandbox catalog. Read that for *what the bot does*.
- **`.claude/skills/run-angket-bot/`** — how to actually run/drive the bot locally.
- **`.claude/skills/verify/`** — how to runtime-verify a change (added this session; points back to the driver).
- **`session-summary/*.md`** — a running, dated log of what happened each session. Not committed to git (gitignored) — local-only history.

This document covers what those don't: the shape of the codebase, where the real logic lives, and the specific things that trip people up given this project's actual history.

## What this is

A Telegram bot that scans text, links, and files for scam/phishing signals, focused on Cambodian banks/telecoms (ABA, ACLEDA, Wing, TrueMoney, Cellcard, Smart Axiata, Metfone, and others) plus major global brands, in English and Khmer. Python 3.13, `python-telegram-bot`, Gemini for reasoning, VirusTotal for file/link reputation, Supabase+pgvector for similarity search.

## Getting oriented: the directory shape

```
bot/
  bot.py              - entry point, handler registration, startup
  config.py           - env vars (.env at repo root, NOT bot/.env)
  context_engine.py   - THE unified reasoning call (see below)
  i18n.py             - en/km translation
  verdict_style.py    - shared verdict formatting helpers
  detectors/          - detection LOGIC, no Telegram code at all
    text/{offline,online}/   - keyword.py, scam_patterns.py (offline); llm.py (online, real Gemini call)
    file/{offline,online}/   - filename_check.py (offline); virustotal.py (online, real VT call)
    url/                     - pipeline.py (orchestrator) + offline/ (lexical.py, vectors.py, reference_data.py) + online/ (network.py, domain_info.py, cert_info.py, threat_intel.py)
  handlers/           - Telegram WIRING only: text_handler.py, url_handler.py, file_handler.py
  storage/            - scan_log.py, the shared SQLite helpers
```

**The organizing idea, once you see it, makes everything else make sense:** domain first (what's being checked — text/file/url), then layer (detection logic vs. Telegram wiring vs. storage), then — inside each detector — offline (no third-party API call) vs. online (a real external API call: Gemini, VirusTotal, DNS/RDAP, TLS). This is a recent reorg (this session); older code you might remember as `bot/url_checker/` or a flat `bot/detectors/text/keyword.py` no longer exists at those paths.

**"Offline" is not literally "no network" everywhere** — `vectors.py` lives under `url/offline/` but makes real Supabase network calls (it moved off SQLite a few sessions back and was never relabeled until this session's docstring fix). The real distinction that's held up: does this call a *third-party reputation/threat-intel API* (online) or not (offline), not "does this ever touch a network."

## Where the actual money paths are

- **`context_engine.py`** — every private-DM and Business-chat message goes through here. ONE Gemini call reasons over the text + link verdicts + file verdict together, with a hard-coded reconciliation safety net (`_reconcile_with_evidence`) that can only ever *escalate* a too-lenient Gemini verdict, never downgrade one — and, since this session, a symmetric prompt instruction stopping Gemini from *over*-escalating a link the deterministic pipeline already scored safe. If you're debugging "why did the bot say X," this file is almost always where the real verdict got decided, not the individual detectors.
- **`bot/detectors/url/pipeline.py::analyze_url()`** — the link-checking cascade: lexical checks (instant) → network/DNS/domain-age/TLS-cert (concurrent) → vector similarity vs. known brand/phishing patterns → an exact-match verdict cache (checked *first*, short-circuits everything else for a URL seen in the last hour). This is the most complex single function in the codebase (114 lines, real domain branching) — don't be alarmed by that, it's been reviewed multiple times and the complexity is genuine, not accidental.
- **`bot/storage/scan_log.py`** — the shared `scan_logs.db` SQLite file. As of this session, WAL mode is enabled here (and defensively in every other module that touches the same file), because five-plus unrelated caches/logs all share one physical file.

## Running and testing it

Don't duplicate what `run-angket-bot`'s SKILL.md already documents in full — the short version:

```bash
# from the repo root
.venv/Scripts/python -m pytest -q                      # unit suite, ~5s, no network
PYTHONPATH=. .venv/Scripts/python .claude/skills/run-angket-bot/driver.py <command>
```

`driver.py` calls the REAL handlers against REAL backends (Gemini, VirusTotal, live DNS) with a faked Telegram envelope — it's the only real way to exercise this bot's logic end-to-end, since a long-running Telegram poller has no other local surface. See its SKILL.md for the full command table, or `.claude/skills/verify/SKILL.md` for the verification-specific angle (which commands prove what).

## What will most likely trip you up

1. **The repo used to be nested (`angket-bot/angket-bot/`).** It was flattened a few sessions ago. If you find an old note, script, or your own memory referencing `../` paths or a double `angket-bot` in a path, that's stale — everything is one level now.
2. **`next-gen-test/concepts/` is a SIBLING directory, not a subfolder of this repo.** It lives at `Project/next-gen-test/concepts/`, next to `Project/angket-bot/`, not inside it. It's also **not** git-tracked at all — it can and does vanish between environments. If you're looking for a prototype mentioned in a session summary and can't find it inside `angket-bot/`, look one level up. (A stray `next-gen-test/` folder appearing *inside* this repo has happened before by mistake — that's a bug to fix, not a second real sandbox.)
3. **SQLite vs. Supabase isn't split how you'd guess.** Only the `url_vectors` similarity table (brand/phishing/scam-pattern embeddings) is in Supabase+pgvector. Everything else — scan logs, the RDAP/TLS/VirusTotal caches, the exact-match link-verdict cache, MinHash page-dedup — is still plain local SQLite, sharing one file (`scan_logs.db`). This is a deliberate scope decision (Supabase is only needed where similarity search matters), not an incomplete migration.
4. **`.env` lives at the repo root**, not inside `bot/`. (`config.py` calls a bare `load_dotenv()`, which resolves relative to wherever the process actually runs from — the repo root, in every real invocation.)
5. **Two different i18n systems exist in this codebase's history** — a teammate's static `locales.json` (rejected, superseded) and the real one, `bot/i18n.py`, which only translates fixed UI strings; the actual scan-verdict *content* is translated live by asking Gemini to write in the target language directly (`context_engine.py`'s `lang` param), not round-tripped through a translation file.
6. **The two `.doc` files at the repo root are gitignored, intentionally.** They're personal/local reference copies. `angket-bot-documentation.md` is the one that's actually committed and meant for the team to read.

## Team structure (as of this session)

Development happens on the `BolBol` branch. There's a mentor who signs off on architecture-level decisions (Supabase migration, translation approach) and reviews things like the link-checking cascade design. Teammates have worked on separate branches (`panha`'s file-scan UI, `NgetSokunkanha`'s earlier restructuring, `feature/text-analysis`) that get merged in periodically — check `git log --all --oneline` if you need the history of who did what.
