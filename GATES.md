# Gates: move blocking sqlite3 off the event loop

OWNS: bot/detectors/url/pipeline.py, bot/detectors/url/online/cert_info.py, bot/detectors/url/online/domain_info.py, bot/detectors/url/online/threat_intel.py, bot/detectors/file/online/virustotal.py, tests/**, GATES.md

Scope: Route every remaining raw `sqlite3.connect` cache in the five detector modules through `bot/storage/sqlite_pool.py` and run each call off the event loop via `asyncio.to_thread`, without changing cache semantics or breaking first-run table creation.

Toolchain: Windows, Git Bash, `.venv/Scripts/python` (3.13). Commands assume `PYTHONPATH=.` and `PYTHONIOENCODING=utf-8` as every other verification in this repo does. Node is not used; this is a Python project and its own interpreter is the portable choice here.

- [ ] G1: No detector module opens its own sqlite connection any more
  CHECK: PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python -c "import ast,sys; files=['bot/detectors/url/pipeline.py','bot/detectors/url/online/cert_info.py','bot/detectors/url/online/domain_info.py','bot/detectors/url/online/threat_intel.py','bot/detectors/file/online/virustotal.py']; bad=[]; [bad.append((f,n.lineno)) for f in files for n in ast.walk(ast.parse(open(f,encoding='utf-8').read())) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='connect' and isinstance(n.func.value,ast.Name) and n.func.value.id=='sqlite3']; sys.exit('RAW sqlite3.connect REMAINS: %r'%bad) if bad else print('SQLITE_POOL_MIGRATION_OK')"
  EXPECT: SQLITE_POOL_MIGRATION_OK
  EVIDENCE: pending

- [ ] G2: Every one of those modules actually routes through sqlite_pool
  CHECK: PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python -c "import sys; files=['bot/detectors/url/pipeline.py','bot/detectors/url/online/cert_info.py','bot/detectors/url/online/domain_info.py','bot/detectors/url/online/threat_intel.py','bot/detectors/file/online/virustotal.py']; missing=[f for f in files if 'sqlite_pool' not in open(f,encoding='utf-8').read()]; sys.exit('NO sqlite_pool USE IN: %r'%missing) if missing else print('SQLITE_POOL_WIRED_OK')"
  EXPECT: SQLITE_POOL_WIRED_OK
  EVIDENCE: pending

- [ ] G3: A fresh, empty database still bootstraps its tables
  CHECK: PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python tools/gate_fresh_db.py
  EXPECT: FRESH_DB_BOOTSTRAP_OK
  EVIDENCE: pending

- [ ] G4: Cache reads no longer stall the event loop
  CHECK: PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python tools/gate_loop_stall.py
  EXPECT: EVENT_LOOP_UNBLOCKED_OK
  EVIDENCE: pending

- [ ] G5: The whole test suite still passes
  CHECK: PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python -c "import subprocess,sys; r=subprocess.run([sys.executable,'-m','pytest','-q'],text=True); sys.exit('PYTEST FAILED rc=%d'%r.returncode) if r.returncode else print('PYTEST_ALL_GREEN')"
  EXPECT: PYTEST_ALL_GREEN
  EVIDENCE: pending

- [ ] G6: Static analysis finds nothing beyond the one known pre-existing flag
  CHECK: PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python -c "import subprocess,sys; out=subprocess.run([sys.executable,'-m','pyflakes','bot/'],capture_output=True,text=True).stdout.strip().splitlines(); extra=[l for l in out if 'virustotal.cached_result' not in l]; sys.exit('NEW PYFLAKES FINDINGS: %r'%extra) if extra else print('PYFLAKES_BASELINE_OK')"
  EXPECT: PYFLAKES_BASELINE_OK
  EVIDENCE: pending

- [x] G7: The stall checker reports a stall against the current blocking code (positive control)
  EVIDENCE: Ran `PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python tools/gate_loop_stall.py` against the UNCHANGED blocking implementation on 2026-09-24. It exited 1 and printed "FAIL: the event loop was blocked for 90.11 ms, over the 50.00 ms budget" (40 cache calls, 86.7 ms total wall time). The absence assertion in G4 is therefore known to be capable of failing, rather than passing vacuously. tools/gate_fresh_db.py was run in the same state and printed FRESH_DB_BOOTSTRAP_OK (exit 0), confirming G3 measures a condition that currently holds and so can detect its loss.

- [ ] G8: Measured before/after event-loop blocking recorded honestly, not copied
  EVIDENCE: pending

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
