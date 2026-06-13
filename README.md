# Neural Forger

**ML-Powered SSRF Detection Framework** — extends SSRFinder with machine learning analysis for high-confidence Server-Side Request Forgery detection.

Neural Forger works in two complementary stages:

- **Passive mode** (`-i`): analyses HTTP request structure with a rule-based scorer and a trained XGBoost classifier to rank injection candidates — no traffic sent.
- **Active mode** (`-p`): injects payloads via SSRFinder's engine, then runs an ensemble of three ML models (SVM, XGBoost, Random Forest) on every HTTP response to confirm exploitation.

---

## Requirements

- Python 3.8+
- Dependencies (install via pip):

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
git clone https://github.com/your-username/NeuralForger.git
cd NeuralForger
pip install -r requirements.txt
```

> The trained model files (`svm_rbf_response.pkl`, `xgboost_response.pkl`, `random_forest_response.pkl`) must be in the **same directory** as `neuralforger-main.py`. They are included in the repository.

---

## Quick Start

### 1. Capture a raw HTTP request

Save the request from Burp Suite, your browser proxy, or write it manually. Place the injection marker `SSRF` (or `***`, `INJECT`, `FUZZ`) where you want payloads to be inserted:

```
GET /api/fetch?url=SSRF&format=json HTTP/1.1
Host: target.example.com
Authorization: Bearer eyJhbGci...
User-Agent: Mozilla/5.0
Accept: application/json
```

Save it as `request.txt`.

### 2. Passive analysis (no traffic sent)

Identify which parameters are most likely vulnerable before touching the target:

```bash
python neuralforger-main.py -r request.txt -i
```

Output example:
```
Vulnerability Probability: 95%
Risk Level: CRITICAL

SUSPICIOUS PARAMETERS IDENTIFIED:
  Parameter: url     Confidence: 95%   Reason: Parameter name is 'url' (primary SSRF indicator)
  Parameter: format  Confidence: 42%   Reason: Moderate indicator

RECOMMENDED PAYLOADS (by dataset success rate):
  1. http://169.254.169.254/latest/meta-data/   Priority: CRITICAL | Success Rate: 27%
  2. http://localhost/admin                      Priority: HIGH     | Success Rate: 37%
  ...
```

### 3. Active injection testing

Test the `url` parameter with ML-recommended payloads:

```bash
python neuralforger-main.py -r request.txt -p url
```

### 4. Full active scan with response ML

Run all three response-analysis models on every injected payload to confirm exploitation:

```bash
python neuralforger-main.py -r request.txt -p url --response-ml
```

---

## Usage Reference

```
python neuralforger-main.py [options]
```

### Input

| Flag | Description |
|------|-------------|
| `-r FILE` / `--request FILE` | Raw HTTP request file (required unless using `-u`) |
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
| `--response-ml` | Enable 3-model response ensemble after injection (active scan) |
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

Place one of these markers in the request file wherever you want payloads injected:

| Marker | Example |
|--------|---------|
| `SSRF` | `?url=SSRF` |
| `***` | `?callback=***` |
| `INJECT` | `?redirect=INJECT` |
| `FUZZ` | `?webhook=FUZZ` |

---

## Examples

```bash
# Passive recon — no traffic
python neuralforger-main.py -r request.txt -i

# Inject into 'url' param with default ML-recommended payloads
python neuralforger-main.py -r request.txt -p url

# Full active scan: injection + response ML confirmation
python neuralforger-main.py -r request.txt -p url --response-ml

# Test all payloads (not just ML-ranked), save JSON report
python neuralforger-main.py -r request.txt -p url --payload-strategy all --format json -o results.json

# Test with a custom wordlist
python neuralforger-main.py -r request.txt -p url --payload-strategy custom -w my_payloads.txt

# Scan internal IP range
python neuralforger-main.py -r request.txt -p url --ip-range 10.0.0.1-254 --path /admin

# Route through Burp Suite proxy (for manual review)
python neuralforger-main.py -r request.txt -p url --proxy http://127.0.0.1:8080 -v

# Direct URL test (no request file needed)
python neuralforger-main.py -u "http://target.com/fetch?src=SSRF" -p src

# Lower the confidence threshold and test with double URL encoding
python neuralforger-main.py -r request.txt -p url --confidence-threshold 50 --encode double

# Quiet output, pipe results elsewhere
python neuralforger-main.py -r request.txt -p url -q --format json | jq .
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

In **passive mode** the confidence is fused as: `0.70 × injection score + 0.30 × ML score`.  
In **active mode** (`--response-ml`) the weights shift to favour direct response evidence: `0.60 × response ensemble + 0.30 × injection + 0.10 × ML`.

---

## Response ML Models

When `--response-ml` is active, three models analyse each HTTP response:

| Model | LOO Accuracy |
|-------|-------------|
| SVM (RBF kernel) | 82.1% |
| Random Forest | 67.9% |
| XGBoost | 64.3% |

The ensemble decides by **majority vote** (binary verdict) and **accuracy-weighted average** of calibrated probabilities (confidence value). A deterministic content-analysis module runs in parallel and can override the ensemble when it detects unambiguous indicators such as:

- Cloud provider metadata (AWS IMDSv1/v2, GCP, Azure)
- Leaked credentials or IAM tokens
- System files (`/etc/passwd`, `/proc/self/`)
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

## Payload Strategies

| Strategy | Description |
|----------|-------------|
| `ml-recommended` | ML-ranked payloads first, then standard payloads (default) |
| `ml-only` | Only the payloads the ML model recommends |
| `all` | All payloads in the database, no filtering |
| `custom` | Only payloads from your `--wordlist` file |

---

## GUI

A graphical interface is also available:

```bash
python neuralforger-gui.py
```

Requires `tkinter` (included in standard Python on most systems).

---

## Running the Tests

```bash
python neuralforger-test.py
```

Expected output: `65/65 passed`.

---

## Project Structure

```
neuralforger-main.py          # Main entry point
neuralforger-cli.py           # Argument parser
neuralforger-ml.py            # Passive request-level ML analyzer
neuralforger-detector.py      # SSRF detector logic
neuralforger-confidence.py    # Confidence scoring and fusion
neuralforger-response-ml.py   # Active response ensemble (3 models)
neuralforger-output.py        # Output formatting (text/json/xml)
neuralforger-gui.py           # GUI interface
neuralforger-config.py        # Configuration constants
neuralforger-banner.py        # Banner display
neuralforger-test.py          # Integration test suite

# SSRFinder core (injection engine)
main.py / ssrfinder_class.py
request_parser.py / request_sender.py
payload_generator.py / injection_handler.py
confidence_calculator.py / network_parser.py
url_encoding.py / summary_printer.py

# Data & models
BALANCED_DATASET_40_EXAMPLES.json   # 40-example training corpus
ssrf_model.json                     # Rule-based model definition
payload_database.json               # Payload catalog
svm_rbf_response.pkl                # Trained SVM
xgboost_response.pkl                # Trained XGBoost
random_forest_response.pkl          # Trained Random Forest

# Training scripts (for retraining models)
train_response_models.py
retrain_response_models.py
```

---

## Legal & Ethical Use

This tool is intended for **authorised security testing only**. Only run it against systems you own or have explicit written permission to test. Unauthorised use against third-party systems may violate computer fraud laws in your jurisdiction.

