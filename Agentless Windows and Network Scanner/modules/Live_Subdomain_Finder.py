from flask import Flask, render_template, request, flash, redirect, url_for, send_file
from werkzeug.utils import secure_filename
import asyncio
import aiohttp
import aiodns
import pandas as pd
import fitz  # PyMuPDF
import os
import re
import socket

# -----------------------------
# Flask app config
# -----------------------------
app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config['UPLOAD_FOLDER'] = "uploads"
ALLOWED_EXTENSIONS = {'txt', 'csv', 'xls', 'xlsx', 'pdf'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs("reports", exist_ok=True)

# -----------------------------
# Domain validation
# -----------------------------
DOMAIN_REGEX = re.compile(r"^(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

def is_valid_domain(domain):
    return bool(DOMAIN_REGEX.match(domain.strip().lower()))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -----------------------------
# Extract domains from files
# -----------------------------
def extract_from_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    lines = []

    try:
        if ext == ".txt":
            with open(file_path, "r") as f:
                lines = [line.strip() for line in f if line.strip()]
        elif ext == ".csv":
            df = pd.read_csv(file_path, header=None)
            lines = df[0].dropna().astype(str).tolist()
        elif ext in [".xls", ".xlsx"]:
            df = pd.read_excel(file_path, header=None)
            lines = df[0].dropna().astype(str).tolist()
        elif ext == ".pdf":
            doc = fitz.open(file_path)
            for page in doc:
                text = page.get_text()
                lines.extend([line.strip() for line in text.splitlines() if line.strip()])
        else:
            raise ValueError("Unsupported file type.")
    except Exception as e:
        raise ValueError(f"Error reading file: {e}")

    # Keep only valid domains
    valid_domains = [d.lower() for d in lines if is_valid_domain(d)]
    return list(set(valid_domains))

# -----------------------------
# Async domain checker
# -----------------------------
async def check_domain(session, resolver, domain):
    result = {"domain": domain, "ip": None, "url": None, "status_code": None, "type": None}
    try:
        ip = await resolver.gethostbyname(domain, socket.AF_INET)
        result["ip"] = ip.addresses[0]

        for url in [f"http://{domain}", f"https://{domain}"]:
            try:
                async with session.get(url, timeout=5) as resp:
                    result["url"] = url
                    result["status_code"] = resp.status
                    result["type"] = "live"
                    return result
            except:
                continue

        result["type"] = "dead"
        result["status_code"] = "No response"

    except aiodns.error.DNSError:
        result["type"] = "dead"
        result["status_code"] = "DNS Fail"
        result["ip"] = "Not resolved"
    except Exception as e:
        result["type"] = "dead"
        result["status_code"] = f"Error: {e}"
    return result

async def check_domains_async(domains, concurrency=100):
    live, dead = [], []
    resolver = aiodns.DNSResolver()
    connector = aiohttp.TCPConnector(limit=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_domain(session, resolver, d) for d in domains]
        for fut in asyncio.as_completed(tasks):
            res = await fut
            if res["type"] == "live":
                live.append(res)
            else:
                dead.append(res)
    return live, dead

# -----------------------------
# Export reports
# -----------------------------
def export_reports(live, dead, output_dir="reports"):
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet

    os.makedirs(output_dir, exist_ok=True)

    live_df = pd.DataFrame(live)
    dead_df = pd.DataFrame(dead)

    # CSV
    live_df.to_csv(f"{output_dir}/live.csv", index=False)
    dead_df.to_csv(f"{output_dir}/dead.csv", index=False)

    # Excel
    with pd.ExcelWriter(f"{output_dir}/report.xlsx") as writer:
        live_df.to_excel(writer, sheet_name="Live", index=False)
        dead_df.to_excel(writer, sheet_name="Dead", index=False)

    # TXT
    with open(f"{output_dir}/live.txt", "w") as f:
        for row in live:
            f.write(f"{row}\n")
    with open(f"{output_dir}/dead.txt", "w") as f:
        for row in dead:
            f.write(f"{row}\n")

    # PDF
    doc = SimpleDocTemplate(f"{output_dir}/report.pdf", pagesize=A4)
    story = []
    styles = getSampleStyleSheet()
    story.append(Paragraph("Domain & Subdomain Report", styles["Heading1"]))
    story.append(Spacer(1, 12))

    # Live table
    story.append(Paragraph(f"Live Domains/Subdomains ({len(live)})", styles["Heading2"]))
    if not live_df.empty:
        table = Table([live_df.columns.tolist()] + live_df.values.tolist())
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.green),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.5, colors.black)
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No live domains found", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Dead table
    story.append(Paragraph(f"Dead Domains/Subdomains ({len(dead)})", styles["Heading2"]))
    if not dead_df.empty:
        table = Table([dead_df.columns.tolist()] + dead_df.values.tolist())
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.red),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.5, colors.black)
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No dead domains found", styles["Normal"]))

    doc.build(story)

    # Return absolute paths for Flask
    return {
        "csv": [os.path.abspath("reports/live.csv"), os.path.abspath("reports/dead.csv")],
        "excel": os.path.abspath("reports/report.xlsx"),
        "txt": [os.path.abspath("reports/live.txt"), os.path.abspath("reports/dead.txt")],
        "pdf": os.path.abspath("reports/report.pdf")
    }

# -----------------------------
# Main scanner handler
# -----------------------------
def process_input(domain_text=None, file_path=None):
    domains = []

    if domain_text and domain_text.strip():
        lines = re.split(r"[,\n]+", domain_text)
        valid_text_domains = [d.strip().lower() for d in lines if is_valid_domain(d.strip())]
        domains.extend(valid_text_domains)

    if file_path:
        file_domains = extract_from_file(file_path)
        domains.extend(file_domains)

    domains = list(set(domains))

    if not domains:
        raise ValueError("❌ No valid domain found. Please enter a domain or upload a proper file.")

    # Run async scanner
    live, dead = asyncio.run(check_domains_async(domains, concurrency=100))
    reports = export_reports(live, dead)
    return live, dead, reports

