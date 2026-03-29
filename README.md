# Vulpimancer

Vulpimancer is a security reconnaissance tool that automates the most time-consuming parts of an initial assessment. Instead of running five different tools separately and combining the results yourself, Vulpimancer does it in a single command.

It handles subdomain discovery, port scanning, TLS inspection, technology fingerprinting, sensitive path detection, and CVE lookup — all in one run. It is built on Python's async engine, so it handles large scopes without slowing down.

> ⚠️ **For authorised use only.** Only run this tool against systems you own or have written permission to test. Unauthorised scanning is illegal in most countries. The author, Abhishek Zalavadiya, is not responsible for any misuse.

---

## 🔍 What Vulpimancer Does

When you point it at a target, it works through the following stages automatically:

- 🌐 Finds subdomains using crt.sh, DNS brute-force, Subfinder, and Amass
- 🔗 Resolves each subdomain and checks for potential takeover opportunities
- 🔌 Scans ports using async TCP and optionally enriches results with Nmap version detection
- 📡 Probes HTTP and HTTPS endpoints with automatic retry and fallback logic
- 🔒 Analyses TLS certificates — expiry dates, cipher suites, legacy protocol support
- 🧬 Fingerprints the technology stack using 60+ header and response body signatures
- 📂 Checks for exposed sensitive paths using baseline comparison
- 🛡️ Looks up known CVEs via the NIST NVD API and runs Nuclei for Critical and High severity findings
- 📊 Saves everything to SQLite, JSON, and a dark-theme HTML report

---

## ⚙️ Installation

**Step 1 — Get the code**

```bash
git clone https://github.com/abhishekzalavadiya/vulpimancer.git
cd vulpimancer
```

**Step 2 — Create a virtual environment**

This keeps Vulpimancer's dependencies separate from your system Python. It is good practice and avoids version conflicts.

```bash
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate
```

**Step 3 — Install dependencies**

```bash
pip install -r requirements.txt
pip install -e .
```

Once this is done, the `vulpimancer` command will be available in your terminal.

**Step 4 — Install external tools (optional)**

These tools are not required to run Vulpimancer, but they unlock additional modules. If any of them are missing, Vulpimancer will print a warning and continue without them.

| Tool | Used for | How to install |
|------|----------|----------------|
| Nmap | Port version detection (MOD-2) | [nmap.org/download.html](https://nmap.org/download.html) |
| Nuclei | CVE discovery (MOD-4) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| Subfinder | Subdomain enumeration (MOD-5) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| Amass | Subdomain enumeration (MOD-5) | `go install github.com/owasp-amass/amass/v4/...@master` |

> 💡 Nuclei, Subfinder, and Amass require Go to be installed. You can get it from [go.dev/dl](https://go.dev/dl).

---

## 🚀 Usage

**Basic scan — good starting point**

```bash
vulpimancer --target example.com
```

This runs all the core phases: subdomain discovery, DNS resolution, port scanning, HTTP probing, TLS analysis, tech fingerprinting, path detection, and CVE lookup.

---

**Full scan — all five modules enabled**

```bash
vulpimancer --target example.com \
    --subdomains \
    --recon \
    --nmap \
    --nuclei \
    --ports top1000
```

This is the most complete scan. It adds Nmap version detection, Nuclei CVE scanning, and parallel Subfinder/Amass recon on top of the core phases.

---

**Common scan types**

Scan the top 1000 ports with Nmap version detection:
```bash
vulpimancer --target example.com --ports top1000 --nmap
```

Test a server that uses old TLS versions:
```bash
vulpimancer --target example.com --tls-legacy
```

Run Nuclei with a longer timeout (useful for large targets):
```bash
vulpimancer --target example.com --nuclei --nuclei-timeout 180
```

Enumerate subdomains using Subfinder and Amass:
```bash
vulpimancer --target example.com --subdomains --recon
```

Scan multiple targets from a file:
```bash
vulpimancer --hosts targets/hosts.txt --subdomains --recon --nmap
```

Faster scan — skip CVE lookup and path probing:
```bash
vulpimancer --target example.com --no-cve --no-paths
```

Save a debug log for troubleshooting:
```bash
vulpimancer --target example.com --log-file logs/scan.log --debug
```

---

## 🏳️ All CLI Flags

| Flag | Description |
|------|-------------|
| `--target <domain>` | Single target domain |
| `--hosts <file>` | Read multiple targets from a file |
| `--subdomains` | Enable subdomain enumeration |
| `--recon` | Run Subfinder and Amass in parallel threads |
| `--ports top1000` | Scan Nmap's top 1000 ports |
| `--nmap` | Run `nmap -sV -Pn` and merge results |
| `--tls-legacy` | Allow TLS 1.0 and 1.1 connections |
| `--nuclei` | Run Nuclei and show Critical and High findings only |
| `--nuclei-timeout N` | Set Nuclei timeout in seconds (default: 120) |
| `--no-cve` | Skip the CVE discovery phase |
| `--no-paths` | Skip the sensitive path probe |
| `--log-file <path>` | Path to write the log file |
| `--debug` | Enable verbose debug output |

---

## 📤 Output Files

After a scan, you will find these files in your working directory:

| File | What it contains |
|------|-----------------|
| `vulpimancer_results.db` | SQLite database with all raw scan data |
| `vulpimancer_results_report.html` | Dark-theme HTML report — open in any browser |
| `vulpimancer_results_report.json` | Full JSON output for scripting or further analysis |
| `vulpimancer_recon_<domain>_<timestamp>.txt` | Subdomain list from Subfinder and Amass |
| `logs/scan.log` | Rotating JSON log with errors and debug events |

> 💡 The HTML report is the easiest way to review results. Open it in your browser after the scan completes.

---

## 🛡️ Error Handling

Vulpimancer is designed to never crash mid-scan. Every error is caught, logged, and the scan continues. Specifically:

- If Nmap, Nuclei, Subfinder, or Amass is not installed — it prints a warning and skips that module
- If an SSL handshake fails — it retries with SNI, then falls back to HTTP
- If a subprocess times out — it is logged and skipped
- If a network request fails — it retries up to the `--retries` limit

All errors are written to `logs/scan.log` in JSON format so you can review them after the scan.

---

## 🗂️ Project Structure

```
vulpimancer/
├── vulpimancer/
│   ├── __init__.py
│   ├── __main__.py
│   └── core.py          # All logic lives here
├── targets/
│   └── hosts.txt        # Example multi-target file
├── reports/             # HTML and JSON output
├── logs/                # Log files
├── tests/
├── requirements.txt
├── setup.py
└── README.md
```

---

## 👤 Author

Built by **Abhishek Zalavadiya**.

---

## ⚖️ Legal

This tool is for authorised security assessments only. Do not run it against systems without explicit written permission. Unauthorised use is illegal under the CFAA, Computer Misuse Act, India's IT Act, and similar laws in most countries.
