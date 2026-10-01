# Gates: one coherent risk scale, honest "unverified", local file inspection

OWNS: bot/response/risk_scale.py, bot/response/verdict_style.py, bot/response/translate/en.py, bot/response/translate/km.py, bot/detectors/url/offline/lexical.py, bot/detectors/url/pipeline.py, bot/detectors/text/online/llm.py, bot/detectors/file/**, bot/handlers/file_handler.py, bot/handlers/text_handler.py, bot/handlers/url_handler.py, bot/context_engine/context_engine.py, py-requirement.txt, tools/**, tests/**, GATES-risk-scoring.md

Scope: Every surface (file, link, text, business) derives its verdict and its risk badge from ONE scale so they can never contradict; a file with no antivirus signal is reported "unverified" instead of "safe"; and file bytes are inspected locally so detection no longer depends on VirusTotal knowing the hash.

Origin: a live `.pdf.rar` flagged by 14/75 VirusTotal engines rendered "LIKELY A SCAM" over a green "19% LOW RISK" (2026-10-01). Follow-up measurement found the same contradiction class on the link side (score 25-30 "Uncertain" over green, score 60 "Scam" over orange), the low/medium/high cut-offs copied in four places, and that any file VirusTotal cannot vouch for with an innocuous name was reported "Not a Scam, 0%".

Toolchain: Windows, `.venv\Scripts\python` (3.13). WinRAR's `Rar.exe` is used only to BUILD test fixtures; the bot itself must list RAR archives without any external binary, because Render has none.

- [x] R1: Verdict and risk badge never contradict on any surface, across the whole score range
  CHECK: .venv\Scripts\python tools/gate_pytest.py tests/test_risk_scale.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=027dfeb2bfedd2f666b916f73c4098a78c7739a6cffa73559e083d77960260c6; exit=0; EXPECT=matched; output-sha256=6cef1f65dc46859336452661ee2b06a70b5818ea64b66f55931b2a782fec4ce2; output-bytes=119; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=a123e80b0bc2/40 entries

- [x] R2: A file with no antivirus signal and no local finding is never reported safe
  CHECK: .venv\Scripts\python tools/gate_pytest.py tests/test_file_unverified.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=492059ef065924e1037d945b3c29323140b304ed2eecaf3081661fd07e975dcb; exit=0; EXPECT=matched; output-sha256=763525288549103aa0f944eab583dcfd01da198578ee610c6b5b2b8d51f58b73; output-bytes=118; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=a123e80b0bc2/40 entries

- [x] R3: Local inspection catches disguised executables, archive payloads, encrypted archives, macros and PDF active content on real fixture files
  CHECK: .venv\Scripts\python tools/gate_pytest.py tests/test_content_check.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=25e3f4719232684067c8cf2590ef506ab9f1b1bb36f4e3b6537c86de13875694; exit=0; EXPECT=matched; output-sha256=508efe469f845dfeabc7614ebd3d6c5273cdf254e411ebcfd699dfe6e2388381; output-bytes=119; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=a123e80b0bc2/40 entries

- [x] R4: RAR listing works with no unrar/7z binary available
  CHECK: .venv\Scripts\python tools/gate_rar_no_binary.py
  EXPECT: RAR_LISTING_WITHOUT_BINARY_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=0d0e6d77944ea976bb75d604d6f54a7470ee74ea9e2ee0d055def74bfe838cbd; exit=0; EXPECT=matched; output-sha256=b29ba095d32c784646c7de495727b4e3b392590df06c75588d2b931c0026d0d3; output-bytes=31; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=a123e80b0bc2/40 entries

- [x] R5: The whole suite passes
  CHECK: .venv\Scripts\python tools/gate_pytest.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: automatic-evidence=v1; definition-sha256=0e67e15414711ac822a30a415351dda0c6e6552fc080b8384a9ba9f63ac8ddf6; exit=0; EXPECT=matched; output-sha256=402845fb5d062597388fb6dbefc72726d027706f9846eb4f910ed6978490c941; output-bytes=1645; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=a123e80b0bc2/40 entries

- [x] R6: No new pyflakes findings
  CHECK: .venv\Scripts\python tools/gate_pyflakes.py
  EXPECT: PYFLAKES_BASELINE_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=635ef0054ec5a91f7d790526a727d70903e21178574b50fe7073e233b8e536a9; exit=0; EXPECT=matched; output-sha256=c5d4c7ce8f168d355a7101c6f43f3f5aaa102b8de6dd621daf18c1fcb6a3c6c7; output-bytes=22; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=a123e80b0bc2/40 entries

- [x] R7: The invariant tests fail against the pre-change scoring (positive control)
  EVIDENCE: Ran tests/test_risk_scale.py against the UNCHANGED scoring on 2026-10-01, before any fix was written. 15 real assertion failures (not import errors), reproducing every documented defect: 'link score 25: verdict Uncertain rendered over a green badge at 25%'; 'file no-VT + .pdf.exe: verdict Scam rendered over an orange badge at 50%'; 'file no-VT + .pdf.rar: verdict Uncertain rendered over a green badge at 20%'; the four hard-coded cut-off copies; and the 100% certainty claim. It also caught a defect in the previous turn's own file fix: 1 engine + a .apk name scored 62% (red badge) while the level stayed 'suspicious'. After the change the same file passes 55/55.

- [ ] R8: New Khmer strings reviewed by a native speaker
  EVIDENCE: pending

- [ ] R9: The original `.pdf.rar` re-sent through the deployed bot renders red / Scam
  EVIDENCE: pending

<!--
R8 and R9 are deliberate handoffs: no command here can judge Khmer phrasing,
and nothing local can prove behavior on the deployed Render instance. They
stay unmet until the user records evidence; this ledger must not be reported
complete while they are open.

Deliberately OUT of scope, decided with the user 2026-10-01:
- Own hash blocklist from user reports: blocked on the paused feedback-loop
  abuse-resistance decision (mentor).
- Uploading unseen files to VirusTotal: hands users' private files to a third
  party and is incompatible with commercial use under VirusTotal's terms.
-->
