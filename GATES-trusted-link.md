# Gates: bare trusted-brand links should not cost a full network scan every time

OWNS: bot/detectors/url/pipeline.py, bot/handlers/text_handler.py, tools/gate_trusted_link_speed.py, tests/test_trusted_link_redirect.py, GATES-trusted-link.md

Scope: Make a repeat check of a message that is nothing but a bare PROTECTED_BRANDS link return without re-paying the full network pipeline, without losing the redirect signal that can legitimately turn a trusted-domain link suspicious.

Measured problem (real production log, 2026-09-24): `https://facebook.com` took 25.0s end to end - update received 15:35:38.863, verdict 15:36:03.826. All of it was spent inside `check_message_full` -> `analyze_url`; `context_engine`'s `_trusted_bare_link_verdict` short-circuit fired 1ms AFTER that work completed, so it saved a Gemini call and nothing else. `pipeline.py:369` additionally makes official-brand domains skip the verdict cache in BOTH directions, so this cost repeats on every single check forever - which makes trusted links the slowest repeat case in the bot, not the fastest.

Design constraint, deliberately NOT pre-decided (see T5): `bare_trusted_link`'s own docstring states it is a SHAPE filter only, and that the caller must still run `check_message_full()` because a redirect can turn a trusted-domain link suspicious. Anchor-mismatch is already excluded by the shape filter (it rejects any hidden TEXT_LINK entity), but redirects are not. So:

- Skipping the scan outright is fastest and trades that redirect signal away permanently.
- Caching only `safe` verdicts for brand domains keeps the poison-resistance the current bypass was written for - a mislabelled entry can never push a brand to suspicious, because only safe results are ever stored - and bounds the exposure to the cache TTL rather than making it permanent. The first check stays slow; repeats get fast.

T5 records which was chosen and why. Do not treat the faster option as obviously correct.

Toolchain: Windows, Git Bash, `.venv/Scripts/python` (3.13), `PYTHONPATH=.` and `PYTHONIOENCODING=utf-8`, matching every other verification in this repo.

- [ ] T1: A repeat bare trusted-brand link is materially faster than its first check
  CHECK: PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python tools/gate_trusted_link_speed.py
  EXPECT: TRUSTED_LINK_REPEAT_FAST_OK
  EVIDENCE: pending

- [ ] T2: A trusted-brand link that redirects off-brand is still not reported safe
  CHECK: PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python -c "import subprocess,sys; r=subprocess.run([sys.executable,'-m','pytest','-q','tests/test_trusted_link_redirect.py'],text=True); sys.exit('REDIRECT SAFETY TESTS FAILED rc=%d'%r.returncode) if r.returncode else print('REDIRECT_SIGNAL_INTACT_OK')"
  EXPECT: REDIRECT_SIGNAL_INTACT_OK
  EVIDENCE: pending

- [ ] T3: The whole test suite still passes
  CHECK: PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python -c "import subprocess,sys; r=subprocess.run([sys.executable,'-m','pytest','-q'],text=True); sys.exit('PYTEST FAILED rc=%d'%r.returncode) if r.returncode else print('PYTEST_ALL_GREEN')"
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: pending

- [ ] T4: The redirect safety test fails when the redirect signal is removed (positive control)
  EVIDENCE: pending

- [ ] T5: Chosen approach recorded with its safety argument, and reviewed by the user
  EVIDENCE: pending

<!--
T2 and T3 wrap pytest in a small runner that prints a success-only token
rather than matching on pytest's own output, because a bare EXPECT of
"passed" also appears in "1 failed, 12 passed" - the linter flagged exactly
that. The token is printed only after a zero return code.

T4 is manual and exists because T2 is the safety half of this work. A test
that asserts "still not safe" is worthless until it has been shown to fail
when the protection is actually removed. Record that control run as evidence.

T5 is manual because it is a judgement about acceptable risk, not something a
command can decide. It is also the gate that must not be quietly dropped: the
whole point of this ledger is that the fast option and the safe option are
different, and somebody has to choose on the record.
-->
