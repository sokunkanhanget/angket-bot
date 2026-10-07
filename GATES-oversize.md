# Gates: oversized-file handling, decision-court option B (2026-10-07)

OWNS: bot/detectors/file/file_risk.py, bot/detectors/file/scanner.py, bot/handlers/file_handler.py, bot/handlers/text_handler.py, bot/handlers/url_handler.py, bot/context_engine/context_engine.py, bot/response/translate/en.py, bot/response/translate/km.py, tests/**, GATES-oversize.md

Scope: A live malware file (a 21.2MB `.xlsx.z`) was too large for the Telegram Bot API to hand over, so the only signal left was its name: score 30, an orange "Uncertain". Make a deliberately disguised name on a file that could not be scanned read as high risk, bounded by the three conditions the court attached, and make the oversize case measurable.

Court conditions (decision court, summary mode, B scored 74 vs A 60 / C 57 / N 57 / D 53):
1. Apply only to files that could not be scanned, never to scanned ones.
2. Log oversize events by size bucket only, so the false-positive rate and volume become measurable.
3. Word it as "cannot verify, plus a warning sign", not "scam".
Plus a Khmer review by a native speaker.

Toolchain: Windows, `.venv\Scripts\python`. Run with `gate-check.mjs --timeout 600` (the full suite exceeds the 120s default).

- [x] B1: The reported file is high risk, and conditions 1-3 each hold (scanned files unaffected, bare executables not alarmed, wording, private log line)
  CHECK: .venv\Scripts\python tools/gate_pytest.py tests/test_unscannable_file.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=29934bf0dd51bae839930e95fe846824ae34d6d93fe9b301767e7b0ecde674ff; exit=0; EXPECT=matched; output-sha256=61327f41a3240653b77248d96201894431a272f2d2811d66aba69427f68b4ed3; output-bytes=119; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [x] B2: Verdict and risk badge still never contradict on any surface
  CHECK: .venv\Scripts\python tools/gate_pytest.py tests/test_risk_scale.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=027dfeb2bfedd2f666b916f73c4098a78c7739a6cffa73559e083d77960260c6; exit=0; EXPECT=matched; output-sha256=439db6d10ca214cfc2f447d67e143adc11bfbc5b451c2514410307aa0ecafa05; output-bytes=119; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [x] B3: The whole suite passes
  CHECK: .venv\Scripts\python tools/gate_pytest.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=0e67e15414711ac822a30a415351dda0c6e6552fc080b8384a9ba9f63ac8ddf6; exit=0; EXPECT=matched; output-sha256=a4a20d7a108dc0fd2e782d90ce12bc7af39e824e18678476901da1f6471fac00; output-bytes=1726; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [x] B4: No new pyflakes findings
  CHECK: .venv\Scripts\python tools/gate_pyflakes.py
  EXPECT: PYFLAKES_BASELINE_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=635ef0054ec5a91f7d790526a727d70903e21178574b50fe7073e233b8e536a9; exit=0; EXPECT=matched; output-sha256=c5d4c7ce8f168d355a7101c6f43f3f5aaa102b8de6dd621daf18c1fcb6a3c6c7; output-bytes=22; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [x] B5: The B tests fail when the combination rule is switched off (positive control)
  EVIDENCE: Ran on 2026-10-07 with file_risk.is_unscannable_disguise forced to False in-process and everything else unchanged. The reported file came back ('suspicious', 30), the exact orange from the live report. 6 of the 7 selected B tests failed (the reported file, three deceptive double extensions, the wording condition, and the unified override; this control predates the review refinement in B8); the one that passed is invoice.pdf.exe, which was already 60 (high) before B. With the rule on, all 26 tests in the file pass. It also surfaced a gap fixed in the same change: the unified Scam override named no reason for a file without an antivirus verdict.

- [x] B8: An independent pre-push review's findings are addressed (rule narrowed, "failed" not boosted, no exact sizes or file names in logs, size bucket fixed)
  EVIDENCE: A fresh-eyes reviewer found four real defects; each was reproduced here before fixing. (1) Exact byte counts reached the logs: the FileTooLargeError text ("file is 22234567 bytes ..."), a file_handler info line, a text_handler warning, and a file name in "File download failed for %s". All removed, with a test that the exception text carries no size. (2) The first version of the rule returned ('dangerous', 60), i.e. "LIKELY A SCAM", for all 8 of data.csv.gz, export.csv.xz, syslog.txt.gz, Photos.jpg.zip, video.mp4.zip, book.pdf.tar, scan.pdf.7z and report.xlsx.zip. gzip, xz, bzip2 and tar append their extension by design, and csv/txt/jpg/mp4 inside an archive is ordinary data. The boost now needs an executable outer extension, or an Office/PDF inner extension with a zip/rar/7z/z outer. The reported malware (.xlsx.z) is still ('dangerous', 60); data.csv.gz, Photos.jpg.zip, video.mp4.zip and book.pdf.tar now return ('suspicious', 30). (3) A transient "failed" scan of a small photos.jpg.zip was also boosted; the boost is now only for scan_error == "too_large". (4) _size_bucket labelled a 5MB file "20-50MB"; it now returns "under-20MB". Accepted, not fixed: a genuine over-20MB scan.pdf.7z or report.xlsx.zip still triggers the rule, and B7 exists to measure how often. Note on B3: it failed once under the checker while a direct run of the same suite passed (985), and passed on re-run; the failing test was not captured, consistent with the known load-sensitive tests but not proven.

- [x] B9: The B7 log summariser works and notices a privacy regression in the log line
  CHECK: .venv\Scripts\python tools/gate_pytest.py tests/test_oversize_log_report.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=803bd57812e91b7ae8c7cb162125c4ef2ec35943aaa942d4f1548d9b14cf7ce6; exit=0; EXPECT=matched; output-sha256=297a727a7ad68f2f044cd3821c08998dbca3dd6e515dffeb29e574885328c5c2; output-bytes=118; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=112566ce41d7/41 entries

- [ ] B6: New Khmer strings (reason_file_unscannable_disguised, reason_override_file_local) reviewed by a native speaker
  EVIDENCE: pending

- [ ] B7: After real traffic, the `[oversize-file]` log lines are reviewed: how often the rule fires, and that no legitimate file was flagged
  EVIDENCE: pending

<!--
B6 and B7 are handoffs: no command here can judge Khmer phrasing, and the
false-positive rate is unknowable until the logs have data (there is no
labeled file corpus). B7 is the court's measurability condition. Search the
Render log for "[oversize-file]"; each line carries only a size bucket, the
reason, and a disguised=True/False flag - no file name, user id or hash.
Raise the question again if disguised=True lines turn out to be legitimate
files such as report.xlsx.zip.

Deliberately NOT done, per the court: option A (/hash) waits for the
decisive test - the user's SHA-256 of the real file, looked up on
VirusTotal. Option C (local Bot API server) is remanded until hosting
budget exists; it is the dissent's pick if hosting is sponsored.
-->
