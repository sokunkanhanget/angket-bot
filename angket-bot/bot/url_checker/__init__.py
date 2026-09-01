"""
bot/url_checker/
================
The complete URL Checker feature, owned by BB — one self-contained
package so it never conflicts with teammates' text/file branches:

    pipeline.py              Orchestrator: merges all signals into a verdict
    message/
        handler.py            Telegram wiring for the whole feature
    features/
        offline/               No network access - deterministic, instant
            lexical.py            Flow 1: pure-stdlib URL text analysis (scoring)
            vectors.py             Flow 2b: embeddings, cosine k-NN, MinHash LSH
            scam_patterns.py        Offline scam-message pattern similarity -
                                     the Gemini-unavailable fallback signal
        online/                 Real network calls - slower, can fail/degrade
            network.py             Flow 2a: async redirect/TLS/page fetching
            domain_info.py         Flow 2a: DNS resolution + RDAP domain age
            cert_info.py            TLS certificate issuance age
            threat_intel.py         Flow 3:  VirusTotal lookups (+cache)

Shared infrastructure (SCAN_LOG_DB helpers) intentionally stays in
bot/analysis/utils.py so both features log to the same database.
"""
