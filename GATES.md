# Gates: move blocking sqlite3 off the event loop

OWNS: bot/detectors/url/pipeline.py, bot/detectors/url/online/cert_info.py, bot/detectors/url/online/domain_info.py, bot/detectors/url/online/threat_intel.py, bot/detectors/file/online/virustotal.py, tests/**, GATES.md

Scope: Route every remaining raw `sqlite3.connect` cache in the five detector modules through `bot/storage/sqlite_pool.py` and run each call off the event loop via `asyncio.to_thread`, without changing cache semantics or breaking first-run table creation.

Toolchain: Windows, Git Bash, `.venv/Scripts/python` (3.13). Commands assume `PYTHONPATH=.` and `PYTHONIOENCODING=utf-8` as every other verification in this repo does. Node is not used; this is a Python project and its own interpreter is the portable choice here.

- [x] G1: No detector module opens its own sqlite connection any more
  CHECK: .venv\Scripts\python tools/gate_no_raw_sqlite.py
  EXPECT: SQLITE_POOL_MIGRATION_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=74e596a19767154839d7844fa012c3c922d86aa28473904423f10a04f69acb46; exit=0; EXPECT=matched; output-sha256=043c4585fd775b7885236f5e745d01adcf06d1fd084321aaf445eb204ffbe77d; output-bytes=26; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=18e6b6e52134/53 entries

- [x] G2: Every one of those modules actually routes through sqlite_pool
  CHECK: .venv\Scripts\python tools/gate_sqlite_pool_wired.py
  EXPECT: SQLITE_POOL_WIRED_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=f185ca6a6c56d008d5a450d0aa262f8d3a391e0288129b52a6938decf23288ad; exit=0; EXPECT=matched; output-sha256=73e827906f2b1ec0f5ed9908c5d1a9bf924257e625a748dba136af89bbce3ac5; output-bytes=22; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=18e6b6e52134/53 entries

- [x] G3: A fresh, empty database still bootstraps its tables
  CHECK: .venv\Scripts\python tools/gate_fresh_db.py
  EXPECT: FRESH_DB_BOOTSTRAP_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=4bdd9f28efac77527af03dbaa1e5d6d86e3301fc7a847c67bb4febc21e3dfdb2; exit=0; EXPECT=matched; output-sha256=45b66d448a5cc6bfbbd7a1556bfbb7ca15b0e1d5b1143624fff5ad88b23f07f5; output-bytes=23; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=18e6b6e52134/53 entries

- [x] G4: Cache reads no longer stall the event loop
  CHECK: .venv\Scripts\python tools/gate_loop_stall.py
  EXPECT: EVENT_LOOP_UNBLOCKED_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=d71377c32f23ca74713c2e525d9f8b99a772d10b68bf281b75d9cd2517199c6c; exit=0; EXPECT=matched; output-sha256=4d3e0241ff8e9828cbb79b86729b7835ceb633548b45b662dc12b76480aa8ccd; output-bytes=141; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=18e6b6e52134/53 entries

- [ ] G5: The whole test suite still passes
  CHECK: .venv\Scripts\python tools/gate_pytest.py
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: pending

- [x] G6: Static analysis finds nothing beyond the one known pre-existing flag
  CHECK: .venv\Scripts\python tools/gate_pyflakes.py
  EXPECT: PYFLAKES_BASELINE_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=635ef0054ec5a91f7d790526a727d70903e21178574b50fe7073e233b8e536a9; exit=0; EXPECT=matched; output-sha256=c5d4c7ce8f168d355a7101c6f43f3f5aaa102b8de6dd621daf18c1fcb6a3c6c7; output-bytes=22; shell=C:\WINDOWS\system32\cmd.exe; cwd=C:\Users\USER\OneDrive\Desktop\Project\angket-bot; path=18e6b6e52134/53 entries

- [x] G7: The stall checker reports a stall against the current blocking code (positive control)
  EVIDENCE: Ran `PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python tools/gate_loop_stall.py` against the UNCHANGED blocking implementation on 2026-09-24. It exited 1 and printed "FAIL: the event loop was blocked for 90.11 ms, over the 50.00 ms budget" (40 cache calls, 86.7 ms total wall time). The absence assertion in G4 is therefore known to be capable of failing, rather than passing vacuously. tools/gate_fresh_db.py was run in the same state and printed FRESH_DB_BOOTSTRAP_OK (exit 0), confirming G3 measures a condition that currently holds and so can detect its loss.

- [x] G8: Measured before/after event-loop blocking recorded honestly, not copied
  EVIDENCE: Measured twice on the same machine with the same script, not copied from planning notes. BEFORE (unchanged blocking code, recorded as G7's positive control): worst loop stall 90.11 ms, 40 cache calls in 86.7 ms total wall time, checker exit 1. AFTER (this refactor): worst loop stall 9.94 ms, 40 calls in 4.6 ms, checker exit 0. That is a 9.1x reduction in worst-case event-loop blocking and 18.8x in wall time. Both figures come from tools/gate_loop_stall.py's own output rather than a separate estimate. Caveat kept deliberately: 9.94 ms is not zero - asyncio.to_thread has real scheduling cost - and all figures are from a dev machine, so Render's 0.1 CPU will scale them up.

<!--
G7 exists because G4 is an absence assertion ("no stall"). Per the skill's own
rule, an absence check is untrustworthy until it has been shown to fail against
a known positive control - here, the CURRENT blocking code, which must make
tools/gate_loop_stall.py report a stall before the refactor lands. Record that
control run as G7's manual evidence.

G8 is manual because the honest comparison is a measurement taken twice (before
and after) on the same machine under the same conditions. The pre-refactor
figure measured during planning was 3.10 ms per _verdict_cache_get on this
machine, ~8 such cycles per link scan. Re-measure rather than reusing that
number as its own proof.

G5's EXPECT is deliberately the weak token "passed" because the gate also
requires process exit 0, and pytest exits non-zero on any failure - so
"1 failed, 759 passed" cannot satisfy both conditions.
-->
