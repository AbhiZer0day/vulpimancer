# 🦊 Vulpimancer v1.0.0

> Production-grade Async Reconnaissance Engine — Authorised Security Assessments Only

**Author:** Abhishek Zalavadiya

> ⚠️ **Disclaimer:** This tool is intended for legal and ethical security testing purposes only. The developer is not responsible for any unauthorized or illegal usage.

⚠️ **AUTHORISED USE ONLY** — Only run against systems you own or have explicit written permission to test.

---

## What's New in v1.0.0

| Module | Feature | Detail |
|--------|---------|--------|
| **MOD-1** | Robust HTTP Engine | `max_retries=3`, `timeout=15s`, HTTPS→HTTP auto-fallback on SSL error, live status/retry feedback via Rich |
| **MOD-2** | Port Scanner + Nmap | `top1000` port group; `--nmap` flag runs `nmap -sV -Pn`, parses XML into Vulpimancer table |
| **MOD-3** | TLS/SSL Handler | SSLError → SNI retry; `--tls-legacy` enables TLS 1.0/1.1 for older servers |
| **MOD-4** | CVE Discovery (Nuclei) | `--nuclei` runs Nuclei via subprocess, filters Critical + High from JSONL, zero crash policy |
| **MOD-5** | Recon Module | `--recon` launches subfinder + amass in parallel daemon threads, merges + deduplicates, saves `.txt` |

---

## 📦 Installation

```bash
cd vulpimancer_v1
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .

# External tools (optional but recommended)
# nmap:       https://nmap.org/download.html
# nuclei:     go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# subfinder:  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# amass:      go install github.com/owasp-amass/amass/v4/...@master
```

---

## 🚀 Usage

```bash
# Basic scan
vulpimancer --target example.com

# Full v5 scan — all 5 modules
vulpimancer --target example.com \
      --subdomains \
      --recon \
      --nmap \
      --nuclei \
      --ports top1000

# Top-1000 ports (MOD-2)
vulpimancer --target example.com --ports top1000

# With Nmap version detection (MOD-2)
vulpimancer --target example.com --nmap

# Legacy TLS support (MOD-3)
vulpimancer --target example.com --tls-legacy

# With Nuclei CVE discovery (MOD-4) 
vulpimancer --target example.com --nuclei --nuclei-timeout 180

# Threaded amass + subfinder recon (MOD-5)
vulpimancer --target example.com --subdomains --recon

# Multi-target from file
vulpimancer --hosts targets/hosts.txt --subdomains --recon --nmap

# Skip CVE + paths (faster)
vulpimancer --target example.com --no-cve --no-paths

# Debug log
vulpimancer --target example.com --log-file logs/scan.log --debug
```

---

## 📊 Scan Phases

| Phase | Description |
|-------|-------------|
| 0 | Subdomain enum — crt.sh + DNS brute-force + **amass/subfinder (MOD-5)** |
| 1 | DNS resolution — aiodns + stdlib fallback, CNAME extraction, takeover hints |
| 2 | Port scan — async TCP double-verify + **nmap -sV -Pn (MOD-2)** |
| 4 | HTTP probe — **MOD-1 retry engine**, live feedback, HTTPS→HTTP fallback |
| 5 | TLS analysis — **MOD-3 SNI retry**, legacy TLS compat, expiry + cipher |
| 6 | Tech fingerprinting — 60+ signatures, headers + body |
| 7 | Sensitive path probe — baseline comparison, confidence scoring |
| 8 | CVE — NIST NVD API v2 + **Nuclei Critical/High (MOD-4)** |
| 9 | Reports — SQLite + HTML + JSON |

---

## 🏗️ Architecture (v1 modules)

```
vulpimancer_v1/
├── vulpimancer/
│   ├── __init__.py
│   ├── __main__.py
│   └── core.py                    ← All 5 modules integrated
│        ├── robust_get()          MOD-1: retry + HTTPS→HTTP fallback
│        ├── run_nmap()            MOD-2: nmap -sV -Pn XML parser
│        ├── analyse_tls()         MOD-3: SNI retry + legacy TLS
│        ├── run_nuclei()          MOD-4: subprocess + Critical/High JSONL filter
│        ├── threaded_recon()      MOD-5: parallel subfinder+amass threads
│        ├── _merge_dedup_subdomains() MOD-5: dedup helper
│        └── enumerate_subdomains()   integrates all recon sources
├── targets/hosts.txt
├── reports/                       ← HTML/JSON outputs
├── logs/                          ← Silent JSON rotating logs
├── requirements.txt
├── setup.py
└── README.md
```

---

## 🔧 New CLI Flags

| Flag | Module | Description |
|------|--------|-------------|
| `--ports top1000` | MOD-2 | Scan nmap's top-1000 default port list |
| `--nmap` | MOD-2 | Run `nmap -sV -Pn` after TCP scan, enrich results |
| `--tls-legacy` | MOD-3 | Allow TLS 1.0/1.1 for older servers |
| `--recon` | MOD-5 | Launch subfinder + amass in parallel threads |
| `--nuclei` | MOD-4 | Run Nuclei, show only Critical + High |
| `--nuclei-timeout N` | MOD-4 | Nuclei subprocess timeout (default: 120s) |

---

## 📤 Output

| File | Description |
|------|-------------|
| `vulpimancer_results.db` | SQLite — all raw data incl. nuclei_results table |
| `vulpimancer_results_report.html` | Dark-theme HTML report with Nuclei section |
| `vulpimancer_results_report.json` | JSON summary with v1 metadata |
| `vulpimancer_recon_<domain>_<ts>.txt` | MOD-5: merged subfinder+amass subdomain list |
| `logs/scan.log` | Silent JSON rotating log (errors, debug) |

---

## 🧪 Silent Error Policy

All errors are logged to the JSON log file. The CLI never crashes on:
- Missing tools (nmap/nuclei/subfinder/amass) — warns and continues
- SSL errors — retries with SNI, then falls back to HTTP
- Subprocess timeouts — logged, tool skipped gracefully
- Network errors — retried up to `--retries` times
