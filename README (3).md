# 🛡️ Automated Web Security Scanner

**Passive audit tool for HTTP security headers, cookies, CORS misconfigurations and transport issues.**

IBM SkillsBuild Cybersecurity Bootcamp – Individual Project (Topic 2)

> ⚠️ **Ethical use only**  
> Scan **only** websites you own or have written permission to test.  
> This tool sends **only passive** GET and OPTIONS requests. It never attempts exploitation, payload injection or authentication bypass.

---

## ✨ Features

- **Security headers** (presence + value validation):
  - Strict-Transport-Security (HSTS max-age check)
  - Content-Security-Policy (unsafe-inline / unsafe-eval / wildcards / frame-ancestors)
  - X-Frame-Options (accepts CSP frame-ancestors as equivalent)
  - X-Content-Type-Options, Referrer-Policy, Permissions-Policy
  - Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, Cross-Origin-Embedder-Policy
- **Cookie audit**: Secure, HttpOnly, SameSite (including SameSite=None without Secure)
- **CORS tests**:
  - Arbitrary origin reflection
  - Null origin
  - Prefix / suffix origin-validation bypass
  - Wildcard + credentials
  - Permissive preflight (dangerous methods)
- **Transport**: HTTPS enforcement + HTTP→HTTPS redirect check
- **Information disclosure**: Server, X-Powered-By and related headers
- **Safety controls**: Authorization consent checkbox + private/loopback address blocking
- **Scoring**: 0–100 security score with severity breakdown
- **Export**: JSON and Markdown reports
- **Interfaces**: Interactive Streamlit dashboard + command-line mode

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

### 2. Create and activate a virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the dashboard (recommended)
```bash
streamlit run web_scanner.py
```
- Enter the target URL in the sidebar
- Tick the authorization checkbox
- Click **Run scan**

### 5. Or run from the command line
```bash
# Basic scan
python web_scanner.py https://example.com

# Save JSON report
python web_scanner.py https://example.com --json report.json

# Scan your own local lab server
python web_scanner.py http://127.0.0.1:8000 --allow-private
```

---

## 📁 Project Structure

```
.
├── web_scanner.py          # Main scanner engine + CLI + Streamlit dashboard
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── Project_Report.docx     # Full project report (required deliverable)
```

---

## 🔧 How It Works

1. Normalises the URL and blocks private/loopback addresses unless `--allow-private` is set.
2. Issues a GET request and analyses the response (headers, cookies, final URL, status code).
3. Runs independent checks: transport, security headers (with value validation), cookies, information disclosure.
4. Performs CORS tests with crafted `Origin` headers and one OPTIONS preflight.
5. Assigns severities, calculates a 0–100 score, and displays results.
6. Supports JSON / Markdown export.

---

## 🧪 Testing

The scanner was validated against a deliberately misconfigured local server that:
- Reflected any Origin (including null and prefix/suffix variants) with credentials
- Omitted security headers
- Served content over plain HTTP
- Set weak cookies

All planted weaknesses were correctly detected with appropriate severity and remediation advice.

---

## 🔮 Future Scope

- Passive TLS version / cipher-suite checks and certificate expiry alerts
- Limited multi-page crawling with per-endpoint CORS testing
- HTML / PDF report generation
- CI/CD pipeline integration as a security gate
- Optional deeper analysis with OWASP ZAP

---

## 📚 References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- OWASP Top 10 – A05:2021 Security Misconfiguration
- MDN Web Docs – HTTP security headers & CORS
- PortSwigger Web Security Academy – CORS vulnerabilities

---

## 📄 License

Educational / personal use for the IBM SkillsBuild Cybersecurity Bootcamp.  
Use responsibly and only on authorised targets.
