"""
bot/linkchecker/
================
The complete Link Checker feature, owned by BB — one self-contained
package so it never conflicts with teammates' text/file branches:

    lexical.py        Flow 1: pure-stdlib URL text analysis (scoring)
    network.py        Flow 2a: async redirect/TLS/page fetching
    domain_info.py    Flow 2a: DNS resolution + RDAP domain age
    vectors.py        Flow 2b: embeddings, cosine k-NN, MinHash LSH
    threat_intel.py   Flow 3:  VirusTotal lookups (+cache)
    pipeline.py       Orchestrator: merges all signals into a verdict
    handler.py        Telegram wiring for the whole feature

Shared infrastructure (SCAN_LOG_DB helpers) intentionally stays in
bot/analysis/utils.py so both features log to the same database.
"""
