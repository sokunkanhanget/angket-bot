# Gates: security + concurrency audit fixes (2026-10-05)

OWNS: bot/detectors/file/offline/content_check.py, bot/handlers/file_handler.py, bot/handlers/text_handler.py, bot/context_engine/context_engine.py, bot/storage/subscription.py, bot/detectors/url/offline/vectors.py, bot/bot.py, bot/response/translate/en.py, bot/response/translate/km.py, py-requirement.txt, tools/**, tests/**, GATES-audit-2026-10-05.md

Scope: Close every defect two audits reproduced in this codebase on 2026-10-05: archive-parsing memory/CPU exhaustion, attacker-written archive entry names reaching replies and Gemini, a file verdict that could fail to send, the daily-quota race at concurrent_updates(10), a language-cache race, a serial seed-retry pile-up, and full user messages written to Render logs.

Toolchain: Windows, `.venv\Scripts\python`. Run with `gate-check.mjs --timeout 600` - the full suite takes ~150-215s and the checker default is 120s.

- [x] A1: Hostile ZIP/RAR archives are bounded, entry names are sanitized, padded archives report a partial check
  CHECK: .venv\Scripts\python tools/gate_pytest.py tests/test_content_check.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=25e3f4719232684067c8cf2590ef506ab9f1b1bb36f4e3b6537c86de13875694; exit=0; EXPECT=matched; output-sha256=7c56a4a3b284d2a85faa75ea34942584e97ff9d579155c4eecb0ec3ed9445a71; output-bytes=119; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [x] A2: RAR listing still works on real WinRAR archives with no external binary
  CHECK: .venv\Scripts\python tools/gate_rar_no_binary.py
  EXPECT: RAR_LISTING_WITHOUT_BINARY_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=0d0e6d77944ea976bb75d604d6f54a7470ee74ea9e2ee0d055def74bfe838cbd; exit=0; EXPECT=matched; output-sha256=b29ba095d32c784646c7de495727b4e3b392590df06c75588d2b931c0026d0d3; output-bytes=31; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [x] A3: The real quota-reservation SQL is atomic against Postgres (rolled-back transaction)
  CHECK: .venv\Scripts\python tools/gate_quota_sql.py
  EXPECT: QUOTA_SQL_ATOMIC_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=349ba13e25b19fdae5242ce814464743f1d73445e4553fc7181513538005cbf6; exit=0; EXPECT=matched; output-sha256=79f9400fc596c3ed505ff67d3c80e1438a5e91451215709f86a1abd1c8900acf; output-bytes=21; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [x] A4: Update logs carry no message text, names or usernames
  CHECK: .venv\Scripts\python tools/gate_pytest.py tests/test_update_logging.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=58c7732dd8c3e81a1d90b7c1a5630bf2e7c117f2044fe115f4c7c08e5e52494c; exit=0; EXPECT=matched; output-sha256=281ee93680c7924beddb48e9d9657a1daa8f43757f57ed0a6c081621aa5c4691; output-bytes=118; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [x] A5: The whole suite passes
  CHECK: .venv\Scripts\python tools/gate_pytest.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=0e67e15414711ac822a30a415351dda0c6e6552fc080b8384a9ba9f63ac8ddf6; exit=0; EXPECT=matched; output-sha256=925e28ae17535433e4ba1c8e47211b6e740fce505bac79c38dba8c0054cb7d5f; output-bytes=1645; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [x] A6: No new pyflakes findings
  CHECK: .venv\Scripts\python tools/gate_pyflakes.py
  EXPECT: PYFLAKES_BASELINE_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=635ef0054ec5a91f7d790526a727d70903e21178574b50fe7073e233b8e536a9; exit=0; EXPECT=matched; output-sha256=c5d4c7ce8f168d355a7101c6f43f3f5aaa102b8de6dd621daf18c1fcb6a3c6c7; output-bytes=22; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [x] A7: Each race/DoS regression test fails against the pre-fix code (positive controls)
  EVIDENCE: Measured before writing each fix, same machine. RAR header bomb (1.5M valid 14-byte RAR5 headers, 20MB): 62.6s and 488MB peak with rarfile -> 56ms and 0.02MB with the walker. ZIP with entry count forged to 1 (190k entries): fully parsed by zipfile -> 38ms and 0.35MB. Quota burst test against the old text_handler: 10 of 10 messages passed the gate at 7/8 ("assert 10 == 1") -> exactly 1 with reservation. Language-cache race test against the old get_user_lang: "assert 'en' == 'km'" -> 'km'. Seed-retry test against the old ensure_seeded: seed() ran once per waiting handler -> once. Option-B notice: 3 of 4 tests failed against the old pipeline.

- [ ] A8: Khmer string for content_archive_too_many_entries reviewed by a native speaker
  EVIDENCE: pending

<!--
A8 is a handoff to the user. Deliberately not fixed in this batch, decided
with the user: per-user token-budget overshoot under concurrency (bounded by
~10 concurrent Gemini calls; reserving an estimate up front was judged not
worth it), and the rare leak of a reserved quota slot if the Telegram status
send itself fails between the gate and the scan.
-->
