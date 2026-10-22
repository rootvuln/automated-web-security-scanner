"""
Automated Web Security Scanner
==============================
Audits websites for missing/weak HTTP security headers, insecure cookies,
CORS misconfigurations, information disclosure, and basic transport issues.

Only passive, non-destructive requests are sent (GET / OPTIONS).
USE ONLY ON SITES YOU OWN OR HAVE WRITTEN PERMISSION TO TEST.

Run dashboard:  streamlit run web_scanner.py
Run CLI:        python web_scanner.py https://example.com [--json report.json]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT = 12
USER_AGENT = "WebSecScanner/1.1 (IBM SkillsBuild educational project; passive checks only)"

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3, "Pass": 4}

# Extended security headers with severity, rationale and recommendation
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "High",
        "Missing HSTS allows SSL-stripping attacks and forces browsers to try HTTP first.",
        "max-age=31536000; includeSubDomains; preload",
    ),
    "Content-Security-Policy": (
        "High",
        "No CSP significantly increases XSS impact. Browsers cannot restrict script, style and object sources.",
        "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
    ),
    "X-Frame-Options": (
        "Medium",
        "Allows the page to be framed by other origins (clickjacking).",
        "DENY or SAMEORIGIN (or use CSP frame-ancestors)",
    ),
    "X-Content-Type-Options": (
        "Medium",
        "Enables MIME sniffing which can lead to content-type confusion attacks.",
        "nosniff",
    ),
    "Referrer-Policy": (
        "Low",
        "Full URLs (including query strings with tokens) may leak to third parties.",
        "strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        "Low",
        "Powerful browser features (camera, microphone, geolocation, payment) are not restricted.",
        "geolocation=(), camera=(), microphone=(), payment=()",
    ),
    "Cross-Origin-Opener-Policy": (
        "Low",
        "Missing COOP can allow cross-origin windows to access the opener via window.opener.",
        "same-origin",
    ),
    "Cross-Origin-Resource-Policy": (
        "Low",
        "Missing CORP may allow cross-origin embedding of resources.",
        "same-origin",
    ),
    "Cross-Origin-Embedder-Policy": (
        "Info",
        "COEP is required for SharedArrayBuffer and some modern isolation features.",
        "require-corp",
    ),
}

INFO_LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "Via", "X-Backend-Server",
]


@dataclass
class Finding:
    category: str
    check: str
    severity: str
    detail: str
    remediation: str = ""


@dataclass
class ScanResult:
    target: str
    scanned_at: str
    status_code: int | None = None
    final_url: str | None = None
    findings: list[Finding] = None
    error: str | None = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []

    @property
    def score(self) -> int:
        penalties = {"High": 15, "Medium": 8, "Low": 3, "Info": 0, "Pass": 0}
        total = sum(penalties.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - total)

    def summary(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = self.score
        d["summary"] = self.summary()
        return d


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("URL is empty")
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only valid http:// or https:// URLs are supported")
    return url


def is_private_target(url: str) -> bool:
    host = urlparse(url).hostname
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
        except ValueError:
            continue
    return False


def _get(url: str, headers: dict | None = None, method: str = "GET") -> requests.Response:
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        h.update(headers)
    return requests.request(
        method, url, headers=h, timeout=REQUEST_TIMEOUT,
        allow_redirects=True, verify=True,
    )


def check_security_headers(resp: requests.Response, is_https: bool) -> list[Finding]:
    findings: list[Finding] = []
    for name, (sev, why, rec) in SECURITY_HEADERS.items():
        value = resp.headers.get(name)
        if name == "Strict-Transport-Security" and not is_https:
            findings.append(Finding("Security Header", name, "Info",
                                    "Not applicable: target reached over HTTP.", rec))
            continue
        if value is None:
            if name == "X-Frame-Options":
                csp = resp.headers.get("Content-Security-Policy", "").lower()
                if "frame-ancestors" in csp:
                    findings.append(Finding("Security Header", name, "Pass",
                                            "Not set, but CSP frame-ancestors provides equivalent protection."))
                    continue
            findings.append(Finding("Security Header", name, sev, f"Header missing. {why}", f"Add: {name}: {rec}"))
            continue

        v = value.lower().strip()
        if name == "Strict-Transport-Security":
            try:
                max_age = int(next(p.split("=")[1] for p in v.replace(" ", "").split(";")
                                   if p.startswith("max-age=")))
            except (StopIteration, ValueError, IndexError):
                max_age = 0
            if max_age < 15552000:  # 180 days
                findings.append(Finding("Security Header", name, "Medium",
                                        f"HSTS max-age is only {max_age}s (< 180 days).", f"Use: {rec}"))
                continue
        elif name == "Content-Security-Policy":
            weak = []
            if "'unsafe-inline'" in v or "'unsafe-eval'" in v:
                weak.append("unsafe-inline/eval")
            if "default-src *" in v or "script-src *" in v or "object-src *" in v:
                weak.append("wildcard sources")
            if "frame-ancestors" not in v and "X-Frame-Options" not in resp.headers:
                weak.append("no frame-ancestors")
            if weak:
                findings.append(Finding("Security Header", name, "Medium",
                                        f"CSP present but weak: {', '.join(weak)}.",
                                        "Remove unsafe directives; prefer nonces/hashes; add frame-ancestors."))
                continue
        elif name == "X-Content-Type-Options" and v != "nosniff":
            findings.append(Finding("Security Header", name, "Low", f"Unexpected value '{value}'.", f"Use: {rec}"))
            continue
        elif name == "X-Frame-Options" and v not in ("deny", "sameorigin"):
            findings.append(Finding("Security Header", name, "Low", f"Unexpected value '{value}'.", f"Use: {rec}"))
            continue
        findings.append(Finding("Security Header", name, "Pass", f"Present and acceptable: {value[:140]}"))
    return findings


def check_info_disclosure(resp: requests.Response) -> list[Finding]:
    findings = []
    for h in INFO_LEAK_HEADERS:
        val = resp.headers.get(h)
        if val:
            findings.append(Finding(
                "Information Disclosure", h, "Low",
                f"Technology/version disclosure: '{val}'.",
                f"Remove or genericise the {h} header in the web server/application config.",
            ))
    if not findings:
        findings.append(Finding("Information Disclosure", "Technology headers", "Pass",
                                "No common Server / X-Powered-By version leakage detected."))
    return findings


def check_cookies(resp: requests.Response, is_https: bool) -> list[Finding]:
    findings = []
    try:
        raw_cookies = resp.raw.headers.getlist("Set-Cookie")
    except Exception:
        sc = resp.headers.get("Set-Cookie")
        raw_cookies = [sc] if sc else []
    if not raw_cookies:
        return [Finding("Cookie", "Set-Cookie", "Info", "No cookies set on this response.")]
    for c in raw_cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        problems = []
        if is_https and "secure" not in low:
            problems.append("missing Secure")
        if "httponly" not in low:
            problems.append("missing HttpOnly")
        if "samesite" not in low:
            problems.append("missing SameSite")
        elif "samesite=none" in low and "secure" not in low:
            problems.append("SameSite=None without Secure")
        if problems:
            sev = "Medium" if any(p in problems for p in ("missing Secure", "missing HttpOnly")) else "Low"
            findings.append(Finding(
                "Cookie", name, sev,
                "Issues: " + ", ".join(problems) + ".",
                "Set Secure; HttpOnly; SameSite=Lax (or Strict). Never use SameSite=None without Secure.",
            ))
        else:
            findings.append(Finding("Cookie", name, "Pass", "Secure, HttpOnly and SameSite are all present."))
    return findings


def check_transport(url: str, final_url: str) -> list[Finding]:
    findings = []
    if urlparse(final_url).scheme != "https":
        findings.append(Finding("Transport", "HTTPS", "High",
                                "Site is served over plain HTTP.", "Redirect all traffic to HTTPS and enable HSTS."))
        return findings
    findings.append(Finding("Transport", "HTTPS", "Pass", "Site is served over HTTPS."))
    parsed = urlparse(url)
    if parsed.scheme == "https":
        http_url = "http://" + parsed.netloc + (parsed.path or "/")
        try:
            r = requests.get(http_url, headers={"User-Agent": USER_AGENT},
                             timeout=REQUEST_TIMEOUT, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
                findings.append(Finding("Transport", "HTTP->HTTPS redirect", "Pass",
                                        f"HTTP redirects to HTTPS ({r.status_code})."))
            else:
                findings.append(Finding("Transport", "HTTP->HTTPS redirect", "Medium",
                                        "Plain HTTP does not redirect to HTTPS.",
                                        "Configure a permanent (301) redirect from HTTP to HTTPS."))
        except requests.RequestException:
            findings.append(Finding("Transport", "HTTP->HTTPS redirect", "Info",
                                    "Port 80 not reachable (acceptable for HTTPS-only deployments)."))
    return findings


def check_cors(url: str) -> list[Finding]:
    findings: list[Finding] = []
    host = urlparse(url).hostname or ""
    tests = {
        "arbitrary origin": "https://evil-attacker.example",
        "null origin": "null",
        "suffix bypass": f"https://{host}.evil-attacker.example",
        "prefix bypass": f"https://evil-{host}",
    }
    reflected_any = False
    for label, origin in tests.items():
        try:
            r = _get(url, {"Origin": origin})
        except requests.RequestException as e:
            findings.append(Finding("CORS", label, "Info", f"Request failed: {e}"))
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao is None:
            continue
        if acao == "*":
            reflected_any = True
            if acac:
                findings.append(Finding("CORS", "Wildcard + credentials", "High",
                                        "ACAO '*' with Allow-Credentials: true (invalid combination that still signals broken policy).",
                                        "Never use '*' with credentials. Use an explicit allow-list."))
            else:
                findings.append(Finding("CORS", "Wildcard origin", "Low",
                                        "Access-Control-Allow-Origin is '*'. Safe only for public, non-authenticated resources.",
                                        "Restrict to trusted origins if the endpoint returns private data."))
        elif acao == origin or acao.lower() == origin.lower():
            reflected_any = True
            sev = "High" if acac else "Medium"
            extra = " with Allow-Credentials: true" if acac else ""
            findings.append(Finding(
                "CORS", f"Reflected origin ({label})", sev,
                f"Server reflected untrusted Origin '{origin}'{extra}.",
                "Validate Origin against a strict exact-match allow-list. Never reflect blindly.",
            ))
    # Preflight
    try:
        r = _get(url, {
            "Origin": "https://evil-attacker.example",
            "Access-Control-Request-Method": "DELETE",
        }, method="OPTIONS")
        methods = r.headers.get("Access-Control-Allow-Methods", "")
        acao = r.headers.get("Access-Control-Allow-Origin")
        if methods and any(m in methods.upper() for m in ("DELETE", "PUT", "PATCH")) \
                and acao in ("*", "https://evil-attacker.example"):
            findings.append(Finding("CORS", "Permissive preflight", "Medium",
                                    f"Preflight from untrusted origin allows dangerous methods: {methods}.",
                                    "Restrict Access-Control-Allow-Methods and origins on OPTIONS responses."))
    except requests.RequestException:
        pass
    if not reflected_any and not any(f.category == "CORS" and f.severity != "Pass" for f in findings):
        findings.append(Finding("CORS", "Origin validation", "Pass",
                                "No CORS headers granted to untrusted origins."))
    return findings


def scan(url: str, allow_private: bool = False) -> ScanResult:
    url = normalize_url(url)
    result = ScanResult(target=url, scanned_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    if not allow_private and is_private_target(url):
        result.error = ("Target resolves to a private/loopback address. "
                        "Enable 'allow private targets' only for your own lab systems.")
        return result
    try:
        resp = _get(url)
    except requests.exceptions.SSLError as e:
        result.error = f"TLS/SSL error: {e}"
        result.findings.append(Finding("Transport", "TLS certificate", "High",
                                       "TLS handshake or certificate validation failed.",
                                       "Install a valid certificate from a trusted CA and ensure proper chain."))
        return result
    except requests.RequestException as e:
        result.error = f"Could not reach target: {e}"
        return result

    result.status_code = resp.status_code
    result.final_url = resp.url
    is_https = urlparse(resp.url).scheme == "https"

    result.findings += check_transport(url, resp.url)
    result.findings += check_security_headers(resp, is_https)
    result.findings += check_cookies(resp, is_https)
    result.findings += check_info_disclosure(resp)
    result.findings += check_cors(resp.url)
    result.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.category, f.check))
    return result


def to_markdown(result: ScanResult) -> str:
    lines = [
        "# Web Security Scan Report",
        f"- **Target:** {result.target}",
        f"- **Scanned at:** {result.scanned_at}",
        f"- **Final URL:** {result.final_url}",
        f"- **HTTP status:** {result.status_code}",
        f"- **Security score:** {result.score}/100",
        "",
        "| Severity | Category | Check | Detail | Remediation |",
        "|---|---|---|---|---|",
    ]
    for f in result.findings:
        rem = (f.remediation or "").replace("|", "/")
        det = (f.detail or "").replace("|", "/")
        lines.append(f"| {f.severity} | {f.category} | {f.check} | {det} | {rem} |")
    return "\n".join(lines)


def run_dashboard() -> None:
    import pandas as pd
    import streamlit as st

    st.set_page_config(page_title="Web Security Scanner", page_icon="🛡️", layout="wide")
    st.title("🛡️ Automated Web Security Scanner")
    st.caption("Passive audit of HTTP security headers, cookies, CORS and transport configuration.")

    with st.sidebar:
        st.header("Scan settings")
        url = st.text_input("Target URL", placeholder="https://example.com")
        allow_private = st.checkbox("Allow private / localhost targets (own lab only)")
        consent = st.checkbox("I own this site or have written permission to test it")
        run = st.button("Run scan", type="primary", disabled=not consent)
        st.info("Only passive GET / OPTIONS requests are sent. No exploitation is attempted.")

    if run:
        if not url:
            st.warning("Enter a URL first.")
            return
        try:
            with st.spinner("Scanning…"):
                result = scan(url, allow_private=allow_private)
        except ValueError as e:
            st.error(str(e))
            return
        if result.error and not result.findings:
            st.error(result.error)
            return

        s = result.summary()
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Security score", f"{result.score}/100")
        c2.metric("High", s.get("High", 0))
        c3.metric("Medium", s.get("Medium", 0))
        c4.metric("Low", s.get("Low", 0))
        c5.metric("Pass", s.get("Pass", 0))

        st.write(f"**HTTP status:** {result.status_code}  |  **Final URL:** `{result.final_url}`")

        df = pd.DataFrame([asdict(f) for f in result.findings])
        if not df.empty:
            tab_all, tab_hdr, tab_cors, tab_cookie, tab_other = st.tabs(
                ["All findings", "Headers", "CORS", "Cookies", "Other"]
            )
            with tab_all:
                st.dataframe(df, use_container_width=True, hide_index=True)
            with tab_hdr:
                st.dataframe(df[df.category == "Security Header"], use_container_width=True, hide_index=True)
            with tab_cors:
                st.dataframe(df[df.category == "CORS"], use_container_width=True, hide_index=True)
            with tab_cookie:
                st.dataframe(df[df.category == "Cookie"], use_container_width=True, hide_index=True)
            with tab_other:
                other = df[~df.category.isin(["Security Header", "CORS", "Cookie"])]
                st.dataframe(other, use_container_width=True, hide_index=True)

            st.subheader("Severity distribution")
            chart_data = pd.Series({k: v for k, v in s.items() if k != "Pass" and v > 0})
            if not chart_data.empty:
                st.bar_chart(chart_data)

        d1, d2 = st.columns(2)
        d1.download_button(
            "Download JSON report",
            json.dumps(result.to_dict(), indent=2),
            file_name="scan_report.json",
            mime="application/json",
        )
        d2.download_button(
            "Download Markdown report",
            to_markdown(result),
            file_name="scan_report.md",
            mime="text/markdown",
        )
    else:
        st.write("Enter a target in the sidebar, tick the authorization box and click **Run scan**.")


def _running_in_streamlit() -> bool:
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        return get_script_run_ctx() is not None
    except Exception:
        return False


def main_cli() -> int:
    ap = argparse.ArgumentParser(description="Passive web security header / CORS scanner")
    ap.add_argument("url")
    ap.add_argument("--allow-private", action="store_true", help="allow localhost/private targets (own lab)")
    ap.add_argument("--json", metavar="FILE", help="write JSON report to FILE")
    args = ap.parse_args()
    try:
        res = scan(args.url, allow_private=args.allow_private)
    except ValueError as e:
        print(f"Error: {e}")
        return 2
    if res.error:
        print(f"[!] {res.error}")
    if not res.findings:
        return 1
    print(f"\nTarget: {res.target}")
    print(f"Score: {res.score}/100   Summary: {res.summary()}\n")
    for f in res.findings:
        if f.severity != "Pass":
            print(f"[{f.severity:<6}] {f.category:<22} {f.check}: {f.detail}")
            if f.remediation:
                print(f"         Remediation: {f.remediation}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res.to_dict(), fh, indent=2)
        print(f"\nJSON report saved to {args.json}")
    return 0


if _running_in_streamlit():
    run_dashboard()
elif __name__ == "__main__":
    sys.exit(main_cli())
