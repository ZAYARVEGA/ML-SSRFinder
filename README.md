# ML-SSRFinder

**ML-Powered SSRF Detection Framework**

ML-SSRFinder is a command-line tool for detecting Server-Side Request Forgery (SSRF) vulnerabilities. It extends a core HTTP injection engine with two machine learning layers:

- **Passive mode** (`-i`): analyses the HTTP request structure with a rule-based scorer and a trained XGBoost classifier to rank injection candidates — no traffic is sent to the target.
- **Active mode** (`-p`): injects payloads via the built-in injection engine, then runs an ensemble of three ML models (SVM, XGBoost, Random Forest) on every HTTP response to confirm exploitation.

---

## Requirements

- Python 3.8+
- pip dependencies:

```
colorama>=0.4.6
numpy>=1.20.0
pandas>=1.3.0
requests>=2.25.0
scikit-learn>=1.8.0
xgboost>=3.2.0
```

---

## Installation

```bash
git clone https://github.com/ZAYARVEGA/ML-SSRFinder.git
cd ML-SSRFinder
pip install -r requirements.txt
```

The trained model files (`svm_rbf_response.pkl`, `xgboost_response.pkl`, `random_forest_response.pkl`, `xgboost_request.pkl`) are included in the repository and must stay in the same directory as `mlssrfinder-main.py`.

---

## Quick Start

### Step 1 — Capture a raw HTTP request

Save a request from Burp Suite, your browser proxy, or write it manually. Place one of the injection markers (`SSRF`, `***`, `INJECT`, `FUZZ`) where you want payloads inserted:

```
GET /api/fetch?url=SSRF&format=json HTTP/1.1
Host: target.example.com
Authorization: Bearer eyJhbGci...
User-Agent: Mozilla/5.0
Accept: application/json
```

Save it as `request.txt`.

### Step 2 — Passive analysis (no traffic sent)

Identify the most likely vulnerable parameters before touching the target:

```bash
python3 mlssrfinder-main.py -r request.txt -i
```

Example output:

```
Vulnerability Probability: 95%
Risk Level: CRITICAL

SUSPICIOUS PARAMETERS IDENTIFIED:
  Parameter: url     Confidence: 95%   Reason: Parameter name is 'url' (primary SSRF indicator)
  Parameter: format  Confidence: 42%   Reason: Moderate indicator

RECOMMENDED PAYLOADS (by dataset success rate):
  1. http://169.254.169.254/latest/meta-data/   Priority: CRITICAL | Success Rate: 27%
  2. http://localhost/admin                      Priority: HIGH     | Success Rate: 37%
```

### Step 3 — Active injection

Inject payloads into the `url` parameter using ML-ranked payloads:

```bash
python3 mlssrfinder-main.py -r request.txt -p url
```

### Step 4 — Active injection with response ML

Run the full pipeline: injection + 3-model ensemble analysis on every response:

```bash
python3 mlssrfinder-main.py -r request.txt -p url --response-ml
```

---

## Usage Reference

```
python3 mlssrfinder-main.py [options]
```

### Input

| Flag | Description |
|------|-------------|
| `-r FILE` / `--request FILE` | Raw HTTP request file |
| `-u URL` / `--url URL` | Direct URL with injection marker (e.g. `http://target.com/api?url=SSRF`) |

### Operation Modes

| Flag | Description |
|------|-------------|
| `-i` / `--inspect` | Passive ML analysis — no injection, no traffic sent |
| `-p NAME` / `--parameter NAME` | Inject payloads into the named parameter |

### Payload Options

| Flag | Description |
|------|-------------|
| `--payload-strategy STRATEGY` | `ml-recommended` (default), `all`, `ml-only`, `custom` |
| `-w FILE` / `--wordlist FILE` | Custom payload list (required for `--payload-strategy custom`) |
| `--ip-range RANGE` | Test an IP range, e.g. `192.168.1.1-254` |
| `--ip ADDRESS` | Test one IP across all default ports |
| `--single-url URL` | Test a single specific URL as payload |
| `-P PORTS` / `--port PORTS` | Ports to test, e.g. `80,443,8080` or `8000-9000` |
| `--path PATH` | Path appended to generated payloads, e.g. `/admin` |
| `--encode TYPE` | URL-encode payloads: `none` (default), `single`, `double` |

### ML & Analysis Options

| Flag | Description |
|------|-------------|
| `--response-ml` | Enable 3-model response ensemble after injection |
| `--confidence-threshold N` | Minimum ML confidence % to proceed with injection (default: `70`) |

### Network Options

| Flag | Description |
|------|-------------|
| `-t SECONDS` / `--timeout SECONDS` | Request timeout (default: `5`) |
| `--threads N` | Concurrent injection threads (default: `1`) |
| `--proxy URL` | HTTP/HTTPS proxy, e.g. `http://127.0.0.1:8080` |

### Output Options

| Flag | Description |
|------|-------------|
| `-v` / `--verbose` | Show ML reasoning and full response details |
| `-q` / `--quiet` | Results only, minimal output |
| `-o FILE` / `--output FILE` | Save results to a file |
| `--format FORMAT` | Output format: `text` (default), `json`, `xml` |
| `-s` / `--show-response` | Print response body for high-confidence findings |
| `-m` / `--manual` | Show the built-in detailed manual |

---

## Injection Markers

Place one of these markers in the request file where payloads should be injected:

| Marker | Example |
|--------|---------|
| `SSRF` | `?url=SSRF` |
| `***` | `?callback=***` |
| `INJECT` | `?redirect=INJECT` |
| `FUZZ` | `?webhook=FUZZ` |

---

## Examples

```bash
# Passive recon — inspect only, no traffic
python3 mlssrfinder-main.py -r request.txt -i

# Verbose passive analysis with ML reasoning
python3 mlssrfinder-main.py -r request.txt -i -v

# Inject into 'url' with default ML-recommended payloads
python3 mlssrfinder-main.py -r request.txt -p url

# Full active scan: injection + response ML confirmation
python3 mlssrfinder-main.py -r request.txt -p url --response-ml

# Save results as JSON
python3 mlssrfinder-main.py -r request.txt -p url --format json -o results.json

# Use all payloads in the database (no ML filtering)
python3 mlssrfinder-main.py -r request.txt -p url --payload-strategy all

# Use only ML-recommended payloads
python3 mlssrfinder-main.py -r request.txt -p url --payload-strategy ml-only

# Test with a custom wordlist
python3 mlssrfinder-main.py -r request.txt -p url --payload-strategy custom -w my_payloads.txt

# Test a single specific payload
python3 mlssrfinder-main.py -r request.txt -p url --single-url "http://169.254.169.254/latest/meta-data/"

# Scan an internal IP range with a path
python3 mlssrfinder-main.py -r request.txt -p url --ip-range 192.168.1.1-254 --path /admin

# Lower the confidence threshold and use double URL encoding
python3 mlssrfinder-main.py -r request.txt -p url --confidence-threshold 50 --encode double

# Route through Burp Suite for manual review
python3 mlssrfinder-main.py -r request.txt -p url --proxy http://127.0.0.1:8080 -v

# Direct URL test (no request file needed)
python3 mlssrfinder-main.py -u "http://target.com/fetch?src=SSRF" -p src

# Quiet output, pipe to jq
python3 mlssrfinder-main.py -r request.txt -p url -q --format json | jq .
```

---

## Confidence Levels

| Level | Range | Meaning |
|-------|-------|---------|
| `CRITICAL` | 90–100% | Exploitation confirmed with high certainty |
| `HIGH` | 75–89% | Strong vulnerability indicators |
| `MEDIUM` | 50–74% | Moderate indicators — manual review advised |
| `LOW` | 25–49% | Weak indicators, likely false positive |
| `INFO` | 0–24% | No significant indicators |

**Passive mode** fuses scores as: `0.70 × injection score + 0.30 × ML score`

**Active mode** (`--response-ml`) shifts weight to favour direct response evidence: `0.60 × response ensemble + 0.30 × injection + 0.10 × ML`

---

## Response ML Models

When `--response-ml` is active, three models analyse each HTTP response:

| Model | LOO Accuracy |
|-------|-------------|
| SVM (RBF kernel) | 82.1% |
| Random Forest | 67.9% |
| XGBoost | 64.3% |

The ensemble decides by **majority vote** (binary verdict) and **accuracy-weighted average** of calibrated probabilities (confidence value).

A deterministic content-analysis module runs in parallel and can override the ensemble when it detects unambiguous indicators:

- Cloud provider metadata (AWS IMDSv1/v2, GCP, Azure)
- Leaked credentials or IAM tokens
- System file content (`/etc/passwd`, `/etc/shadow`)
- Private keys or database connection strings
- WAF block pages (suppresses false positives)

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Completed successfully — no vulnerabilities found |
| `1` | Execution error |
| `2` | Vulnerability confirmed (at least one HIGH confidence result) |

---

## Running the Tests

```bash
python3 mlssrfinder-test.py
```

Expected output: `65/65 passed`.

---

## GUI

A graphical interface is available:

```bash
python3 mlssrfinder-gui.py
```

Requires `tkinter` (included in standard Python on most systems).

---

## Project Structure

```
mlssrfinder-main.py          # Entry point
mlssrfinder-cli.py           # Argument parser
mlssrfinder-ml.py            # Passive request-level ML analyser
mlssrfinder-detector.py      # SSRF detector and scoring logic
mlssrfinder-confidence.py    # Confidence scoring and fusion
mlssrfinder-response-ml.py   # Active response ensemble (SVM + XGBoost + RF)
mlssrfinder-output.py        # Output formatting (text / json / xml)
mlssrfinder-gui.py           # GUI interface
mlssrfinder-config.py        # Configuration constants
mlssrfinder-banner.py        # Banner display
mlssrfinder-test.py          # Integration test suite (65 tests)
ml-ssrfinder                 # Shell launcher

# SSRFinder core (injection engine)
main.py                      # SSRFinder entry point
ssrfinder_class.py           # Core scanner class
request_parser.py            # HTTP request file parser
request_sender.py            # HTTP request sender
payload_generator.py         # Payload generation
injection_handler.py         # Injection point detection and replacement
confidence_calculator.py     # Base confidence calculator
network_parser.py            # IP range and port parsing
url_encoding.py              # URL encoding utilities
summary_printer.py           # Scan summary output
response_formatter.py        # Response formatting

# Data and models
BALANCED_DATASET_40_EXAMPLES.json   # 40-example request-level training corpus
response_dataset_final.json         # Response-level training dataset
payload_database.json               # Payload catalogue
xgboost_request.pkl                 # Trained passive request classifier
svm_rbf_response.pkl                # Trained SVM response model
xgboost_response.pkl                # Trained XGBoost response model
random_forest_response.pkl          # Trained Random Forest response model

# Training scripts
train_response_models.py            # Train the three response ML models
train_request_model.py              # Train the passive request classifier
diagnose_pkl.py                     # Diagnostic script for model loading issues
```

---

## Legal and Ethical Use

This tool is intended for **authorised security testing only**. Only run it against systems you own or have explicit written permission to test. Unauthorised use against third-party systems may violate computer fraud laws in your jurisdiction.
