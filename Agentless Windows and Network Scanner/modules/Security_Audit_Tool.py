import requests
import socket
import ssl
import datetime
import hashlib
import random
import string
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import re
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional

# ---- PDF
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# --------------- Safety Note ---------------
# Use this tool ONLY on targets you own or have explicit permission to test.
# It performs non-destructive checks (no data modification), but still counts as active testing.
# -------------------------------------------


# =========================
# Utility & Data Structures
# =========================

@dataclass
class Finding:
    category: str
    title: str
    severity: str
    affected_url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    description: str = ""
    evidence: str = ""
    impact: str = ""
    likelihood: str = "Medium"
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    def to_rows(self) -> List[List[str]]:
        rows = [
            ["Category", self.category],
            ["Title", self.title],
            ["Severity", self.severity],
            ["Affected URL", self.affected_url],
        ]
        if self.parameter: rows.append(["Parameter", self.parameter])
        if self.payload: rows.append(["Payload", self.payload])
        rows.extend([
            ["Description", self.description],
            ["Evidence (excerpt)", self.evidence[:1000]],
            ["Impact", self.impact],
            ["Likelihood", self.likelihood],
            ["Recommendation", self.recommendation],
        ])
        if self.references:
            rows.append(["References", " | ".join(self.references)])
        return rows


def _safe_get(url: str, params: Dict[str, Any] = None, headers: Dict[str, str] = None, timeout: int = 12):
    try:
        return requests.get(url, params=params or {}, headers=headers or {}, timeout=timeout, allow_redirects=True)
    except Exception as e:
        class Dummy:
            def __init__(self, url, error):
                self.status_code = 0
                self.text = str(error)
                self.headers = {}
                self.url = url
        return Dummy(url, e)



def _similarity(a: str, b: str) -> float:
    # Jaccard on shingles (rough & fast)
    def shingles(s, k=5):
        s = s or ""
        return set(s[i:i+k] for i in range(max(len(s)-k+1, 1)))
    A, B = shingles(a), shingles(b)
    if not A and not B: return 1.0
    return len(A & B) / max(len(A | B), 1)


def _norm_target(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    parsed = urlparse(target)
    # Remove fragments; keep query
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def _domain_from_target(target: str) -> str:
    parsed = urlparse(target)
    return parsed.netloc or parsed.path


# ==================
# Header & TLS checks
# ==================

def check_http_headers(url):
    report = {}
    try:
        r = _safe_get(url)
        headers = r.headers or {}
        must = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        for h in must:
            report[h] = headers.get(h, "❌ Missing")
        # Cookie flags (basic)
        cookies = headers.get("Set-Cookie", "")
        if cookies:
            report["Cookies Secure/HttpOnly"] = ("Secure" in cookies and "HttpOnly" in cookies) and "✅ Present" or "⚠️ Missing flags"
        else:
            report["Cookies Secure/HttpOnly"] = "ℹ️ No Set-Cookie observed"
    except Exception as e:
        report["error"] = str(e)
    return report


def check_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(6.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            remaining = expiry - datetime.datetime.utcnow()
            issuer = ", ".join([f"{k}={v}" for tup in cert['issuer'] for (k, v) in tup])
            subject = ", ".join([f"{k}={v}" for tup in cert['subject'] for (k, v) in tup])
            return {
                "Subject": subject,
                "Issuer": issuer,
                "Valid Until": expiry.strftime("%Y-%m-%d"),
                "Days Remaining": remaining.days
            }
    except Exception as e:
        return {"error": str(e)}


# =======================
# Content/Param-based Tests
# =======================

SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql_fetch_array()",
    "pg_query():",
    "sqlstate",
    "odbc sql",
    "sqlite error",
    "ora-00933", "ora-01756", "ora-00936",
]

SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1' OR 1=1 -- -",
    "' OR '1'='1' -- -",
    "1') OR ('1'='1",
    "1 AND SLEEP(1)",           # time-ish (naive)
    "'; WAITFOR DELAY '0:0:1'--",
    "\" OR \"1\"=\"1",
]

SQLI_CONTRAST = [("1' OR '1'='1", "1' AND '1'='2")]

XSS_PAYLOADS = [
    "<script>alert(1337)</script>",
    "\"'><svg/onload=alert(1337)>",
    "<img src=x onerror=alert(1337)>",
    "<b>XXS_MARKER_@@@</b>",  # HTML injection detectable
]

HTML_INJECTION_MARKER = "XXS_MARKER_@@@"

# parameters we’ll try to probe if not present
COMMON_PARAMS = ["q", "search", "s", "id", "page", "cat", "name", "ref", "redirect", "next", "return", "url"]

DEBUG_PARAMS = {
    "debug": ["1", "true", "on"],
    "test": ["1", "true"],
    "admin": ["1", "true"],
    "preview": ["1"],
}

def _evidence_excerpt(text: str, needle: str, radius: int = 160) -> str:
    text_low = text.lower()
    idx = text_low.find(needle.lower())
    if idx == -1:
        return text[:radius*2] if text else ""
    start = max(idx - radius, 0)
    end = min(idx + radius, len(text))
    return text[start:end].replace("\n", " ")[:1200]


def _try_param_payloads(base_url: str, param: str, payloads: List[str]) -> List[Dict[str, Any]]:
    """Return list of matches with evidence for a specific parameter."""
    matches = []
    for pl in payloads:
        r = _safe_get(base_url, params={param: pl})
        body = r.text or ""
        url_used = r.url if hasattr(r, "url") else base_url
        # Record raw result for later logic
        matches.append({
            "payload": pl,
            "status": r.status_code,
            "body": body,
            "url": url_used,
            "headers": dict(getattr(r, "headers", {})),
        })
    return matches


def check_sqli(url: str, params_to_try: List[str]) -> List[Finding]:
    findings = []

    # Baseline
    base_r = _safe_get(url)
    base_body = base_r.text or ""
    base_len = len(base_body)

    for p in params_to_try:
        results = _try_param_payloads(url, p, SQLI_PAYLOADS)
        # Error-based and reflection differences
        for res in results:
            body_low = (res["body"] or "").lower()
            if any(sig in body_low for sig in SQL_ERROR_SIGNS):
                findings.append(Finding(
                    category="Injection",
                    title="SQL Injection (Error-based) – possible",
                    severity="High",
                    affected_url=res["url"],
                    parameter=p,
                    payload=res["payload"],
                    description="Error-based SQL injection signatures appeared in the response.",
                    evidence=_evidence_excerpt(res["body"], "sql"),
                    impact="Attackers could extract or manipulate database contents.",
                    recommendation="Use parameterized queries (prepared statements), input validation, and generic error messages.",
                    references=[
                        "https://owasp.org/Top10/A03_2021-Injection/"
                    ]
                ))
        # Boolean-ish length contrast
        for true_pl, false_pl in SQLI_CONTRAST:
            r_true = _safe_get(url, params={p: true_pl})
            r_false = _safe_get(url, params={p: false_pl})
            if r_true.status_code and r_false.status_code:
                sim = _similarity(r_true.text or "", r_false.text or "")
                # If pages differ a lot, it may indicate boolean condition changes
                if sim < 0.75 and abs((len(r_true.text or "") - len(r_false.text or ""))) > 100:
                    findings.append(Finding(
                        category="Injection",
                        title="SQL Injection (Boolean-based difference) – possible",
                        severity="High",
                        affected_url=url,
                        parameter=p,
                        payload=f"TRUE: {true_pl} | FALSE: {false_pl}",
                        description="Significant content difference between boolean TRUE/FALSE payloads.",
                        evidence=f"Similarity: {sim:.2f}; len(TRUE)={len(r_true.text or '')}, len(FALSE)={len(r_false.text or '')}",
                        impact="Attackers may extract data by inferring conditions.",
                        recommendation="Use parameterized queries and server-side validation. Avoid building SQL from user input.",
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection"
                        ]
                    ))
    return findings


def check_xss_html_injection(url: str, params_to_try: List[str]) -> List[Finding]:
    findings = []
    for p in params_to_try:
        results = _try_param_payloads(url, p, XSS_PAYLOADS)
        for res in results:
            body = res["body"] or ""
            # reflected token detection (loose)
            if HTML_INJECTION_MARKER in body:
                findings.append(Finding(
                    category="HTML Injection",
                    title="HTML Injection / Reflected content unescaped",
                    severity="Medium",
                    affected_url=res["url"],
                    parameter=p,
                    payload=res["payload"],
                    description="HTML content is reflected back unescaped, enabling markup injection.",
                    evidence=_evidence_excerpt(body, HTML_INJECTION_MARKER),
                    impact="UI redress, phishing overlays, or prep for stored XSS chains.",
                    recommendation="Properly HTML-encode user input before rendering. Use templating auto-escape.",
                    references=["https://owasp.org/www-community/attacks/HTML_Injection"]
                ))
            # crude reflected-XSS hint: payload appears verbatim
            # (NOTE: Not executing JS here; only reflection detection)
            if any(sig in body for sig in ["<script>alert(1337)</script>", "onerror=alert(1337)", "onload=alert(1337)"]):
                findings.append(Finding(
                    category="XSS",
                    title="Reflected XSS – potential (payload mirrored)",
                    severity="High",
                    affected_url=res["url"],
                    parameter=p,
                    payload=res["payload"],
                    description="Script-like payload reflected; may execute depending on context.",
                    evidence=_evidence_excerpt(body, "alert(1337)"),
                    impact="Session hijacking, CSRF bypass, defacement.",
                    recommendation="Apply output encoding by context (HTML, attribute, JS). Enable CSP with nonces.",
                    references=["https://owasp.org/Top10/A03_2021-Injection/"]
                ))
    return findings


def check_unnecessary_hidden_params(url: str) -> List[Finding]:
    """
    - Try adding benign random param (noise) to see if the app echoes it back (leak of unnecessary param handling).
    - Probe common debug/admin flags. If body shows stack traces, debug banners or extra info -> finding.
    """
    findings = []

    # Random noise parameter
    noise_key = "zzz" + "".join(random.choices(string.ascii_lowercase, k=6))
    noise_val = "n0is3_" + "".join(random.choices(string.ascii_lowercase, k=6))

    base = _safe_get(url)
    base_body = base.text or ""
    base_len = len(base_body)
    base_sig = hashlib.sha256(base_body.encode("utf-8", errors="ignore")).hexdigest()

    with_noise = _safe_get(url, params={noise_key: noise_val})
    noise_body = with_noise.text or ""
    sim = _similarity(base_body, noise_body)

    # If the app reflects unknown params or surfaces them in response (e.g., search results without a form)
    if noise_val in noise_body:
        findings.append(Finding(
            category="Unnecessary Parameter",
            title="Unnecessary parameter reflected",
            severity="Low",
            affected_url=with_noise.url,
            parameter=noise_key,
            payload=noise_val,
            description="An unrecognized parameter value was reflected in the response.",
            evidence=_evidence_excerpt(noise_body, noise_val),
            impact="May facilitate UI tampering or pave way for injection if not sanitized.",
            recommendation="Ignore unknown parameters server-side; validate and whitelist accepted parameters.",
            references=["https://owasp.org/www-community/vulnerabilities/Unvalidated_Redirects_and_Forwards"]
        ))
    else:
        # If identical response (very high similarity), we note the parameter is likely ignored (informational)
        if sim > 0.98:
            findings.append(Finding(
                category="Unnecessary Parameter",
                title="Unknown parameter accepted but ignored",
                severity="Info",
                affected_url=with_noise.url,
                parameter=noise_key,
                payload=noise_val,
                description="Adding an unrecognized parameter did not change the response (likely ignored).",
                evidence=f"Similarity with baseline: {sim:.3f}",
                impact="Generally safe, but indicates no strict server-side parameter validation.",
                recommendation="Implement parameter whitelisting; drop unknown parameters early.",
                references=[]
            ))

    # Debug/admin flags
    debug_signatures = [
        "stack trace", "traceback", "notice:", "warning:", "fatal error", "undefined index",
        "x-debug", "debug mode", "development server", "flask debug", "django debug"
    ]
    for k, vals in DEBUG_PARAMS.items():
        for v in vals:
            r = _safe_get(url, params={k: v})
            body = r.text or ""
            if any(sig in body.lower() for sig in debug_signatures) or any(h for h in r.headers if str(h).lower().startswith("x-debug")):
                findings.append(Finding(
                    category="Misconfiguration",
                    title=f"Debug/Preview parameter exposed: {k}={v}",
                    severity="Medium",
                    affected_url=r.url,
                    parameter=k,
                    payload=v,
                    description="Enabling a debug/preview/admin parameter revealed extra information.",
                    evidence=_evidence_excerpt(body, "debug"),
                    impact="Information disclosure may aid exploitation.",
                    recommendation="Disable debug features in production; gate with auth/roles and remove dead feature flags.",
                    references=["https://owasp.org/www-project-cheat-sheets/cheatsheets/Error_Handling_Cheat_Sheet.html"]
                ))
    return findings


def check_outdated_software(url: str) -> Dict[str, Any]:
    report = {}
    try:
        resp = _safe_get(url)
        soup = BeautifulSoup(resp.text or "", "html.parser")

        txt_low = (resp.text or "").lower()
        if "wordpress" in txt_low:
            report["WordPress"] = "⚠️ Fingerprint suggests WordPress (check version & plugins)."
        if "joomla" in txt_low:
            report["Joomla"] = "⚠️ Fingerprint suggests Joomla."
        if "drupal" in txt_low:
            report["Drupal"] = "⚠️ Fingerprint suggests Drupal."

        gens = soup.find_all("meta", {"name": "generator"})
        for g in gens:
            val = (g.get("content") or "").strip()
            if val:
                report["Generator Meta"] = val

        if not report:
            report["Status"] = "✅ No obvious CMS fingerprints found"
    except Exception as e:
        report["error"] = str(e)
    return report


# =================
# Top-level Orchestrator
# =================

def audit(target: Optional[str] = None) -> Dict[str, Any]:
    if not target:
        return {"error": "No target provided"}

    target = _norm_target(target)
    domain = _domain_from_target(target)

    # Determine params to try (prefer existing query keys, else COMMON_PARAMS)
    parsed = urlparse(target)
    existing_params = list(parse_qs(parsed.query).keys())
    params_to_try = existing_params or COMMON_PARAMS

    results: Dict[str, Any] = {}
    results["Target"] = target
    results["HTTP Headers"] = check_http_headers(target)
    results["SSL Certificate"] = check_ssl_certificate(domain)
    results["Outdated Software"] = check_outdated_software(target)

    # Deep checks producing detailed Findings
    findings: List[Finding] = []
    findings.extend(check_sqli(target, params_to_try))
    findings.extend(check_xss_html_injection(target, params_to_try))
    findings.extend(check_unnecessary_hidden_params(target))

    # Build summary
    sev_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f.severity in sev_count:
            sev_count[f.severity] += 1
        else:
            sev_count["Info"] += 1
    results["Summary"] = {
        "Total Findings": len(findings),
        **sev_count
    }

    # Serialize findings for template (dicts)
    results["Findings"] = [asdict(f) for f in findings]

    # Matrix: which payloads matched per category
    results["Test Matrix"] = {
        "Params Tested": params_to_try,
        "SQLi Payloads Tried": SQLI_PAYLOADS,
        "XSS/HTML Payloads Tried": XSS_PAYLOADS,
    }

    return results

# =================
# PDF Report (Detailed)
# =================

from xml.sax.saxutils import escape

def generate_pdf(results: Dict[str, Any], filename: str = "Security_Audit_Report.pdf"):
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    h2 = styles['Heading2']
    h3 = styles['Heading3']
    normal = styles['Normal']

    # ✅ Change Heading2 text color to white
    h2.textColor = colors.white
    h3.textColor = colors.white

    doc = SimpleDocTemplate(filename, pagesize=A4, leftMargin=32, rightMargin=32, topMargin=36, bottomMargin=36)
    story = []

    # Cover
    story.append(Paragraph("🔍 Website Security Audit Report", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Target: {escape(results.get('Target',''))}", normal))
    story.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal))
    story.append(Spacer(1, 16))

    # Executive Summary
    story.append(Paragraph("Executive Summary", h2))
    summary = results.get("Summary", {})
    if summary:
        tdata = [[escape(str(k)), escape(str(v))] for k, v in summary.items()]
        table = Table([["Metric", "Value"]] + tdata, colWidths=[180, 320])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a1a")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#f9f9f9")),
            ("TEXTCOLOR", (0,1), (-1,-1), colors.black),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        story.append(table)
    story.append(Spacer(1, 10))

    # Security Headers
    story.append(Paragraph("Security Headers", h2))
    headers = results.get("HTTP Headers", {})
    if headers:
        tdata = [["Header", "Status"]] + [[escape(str(k)), escape(str(v))] for k, v in headers.items()]
        table = Table(tdata, colWidths=[220, 280])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a1a")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#f0f7ff")),
            ("TEXTCOLOR", (0,1), (-1,-1), colors.black),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        story.append(table)
        story.append(Spacer(1, 10))

    # TLS/Certificate
    story.append(Paragraph("TLS/Certificate", h2))
    tls = results.get("SSL Certificate", {})
    if tls:
        tdata = [["Key", "Value"]] + [[escape(str(k)), escape(str(v))] for k, v in tls.items()]
        table = Table(tdata, colWidths=[160, 340])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a1a")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#f9f9f9")),
            ("TEXTCOLOR", (0,1), (-1,-1), colors.black),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        story.append(table)
        story.append(Spacer(1, 16))

    # Findings
    story.append(Paragraph("Detailed Findings", h2))
    f_list: List[Dict[str, Any]] = results.get("Findings", [])
    if not f_list:
        story.append(Paragraph("No findings detected by the current checks.", normal))
    for i, fdict in enumerate(f_list, 1):
        f = Finding(**fdict)
        story.append(Paragraph(f"{i}. {escape(f.title)} [{escape(f.severity)}]", h3))
        safe_rows = [[escape(str(k)), escape(str(v))] for k, v in f.to_rows()]
        table = Table(safe_rows, colWidths=[140, 360])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#e6f7ff")),
            ("TEXTCOLOR", (0,0), (0,-1), colors.black),
            ("TEXTCOLOR", (1,0), (1,-1), colors.black),  # ensure second column visible
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        story.append(table)
        story.append(Spacer(1, 12))
        if i % 3 == 0:
            story.append(PageBreak())

    # Test Matrix
    story.append(Paragraph("Test Matrix", h2))
    matrix = results.get("Test Matrix", {})
    if matrix:
        for k, v in matrix.items():
            safe_val = ", ".join([escape(str(x)) for x in v]) if isinstance(v, list) else escape(str(v))
            story.append(Paragraph(f"<b>{escape(str(k))}</b>: {safe_val}", normal))
        story.append(Spacer(1, 8))

    doc.build(story)
    return filename
