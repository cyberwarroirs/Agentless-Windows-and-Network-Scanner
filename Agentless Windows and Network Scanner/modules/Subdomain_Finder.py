import requests
import dns.resolver
import itertools
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# Pre-built wordlist for bruteforce/permutations
COMMON_SUBDOMAINS = ["www", "mail", "ftp", "dev", "test", "portal", "admin", "beta", "shop", "api"]
NUM_PERMUTATIONS = [1, 2, 3, 10, 20]  # dev1, api2, etc.

# -------------------------------
# Passive OSINT Methods
# -------------------------------
def query_ctlogs(domain):
    """Query Certificate Transparency logs via crt.sh"""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=10)
        subdomains = set()
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if "*" not in sub:
                        subdomains.add(sub)
        return subdomains
    except Exception as e:
        print("CT log error:", e)
        return set()

def search_engines(domain):
    """Placeholder for search engine indexing / passive OSINT"""
    # Optional: integrate Bing Search API, Google Custom Search, SecurityTrails API
    return set()

# -------------------------------
# Bruteforce & Permutations
# -------------------------------
def generate_permutations(wordlist):
    """Create subdomain permutations like dev1, api2"""
    perms = set()
    for word in wordlist:
        for num in NUM_PERMUTATIONS:
            perms.add(f"{word}{num}")
    return perms

def brute_force(domain, wordlist=COMMON_SUBDOMAINS):
    """Bruteforce common subdomains including permutations"""
    found = set()
    subdomain_candidates = wordlist + list(generate_permutations(wordlist))
    for sub in subdomain_candidates:
        for scheme in ["http://", "https://"]:
            url = f"{scheme}{sub}.{domain}"
            try:
                r = requests.get(url, timeout=3)
                if r.status_code < 400:
                    found.add(f"{sub}.{domain}")
                    break
            except:
                continue
    return found

# -------------------------------
# Active DNS Checks
# -------------------------------
def dns_probe(subdomains):
    """Check if subdomain exists via DNS"""
    live = set()
    for sub in subdomains:
        try:
            for record_type in ["A", "AAAA", "CNAME"]:
                answers = dns.resolver.resolve(sub, record_type, lifetime=3)
                if answers:
                    live.add(sub)
                    break
        except:
            continue
    return live

# -------------------------------
# Main Function
# -------------------------------
def find_subdomains(domain):
    domain = domain.lower()
    all_subdomains = set()

    # Passive OSINT
    all_subdomains.update(query_ctlogs(domain))
    all_subdomains.update(search_engines(domain))

    # Bruteforce
    all_subdomains.update(brute_force(domain))

    # Active DNS check (optional, just for confirmation)
    dns_probe(all_subdomains)

    # Remove duplicates and sort
    return sorted(all_subdomains)

# -------------------------------
# PDF Report Generation
# -------------------------------
def generate_pdf(subdomains, domain):
    filename = f"subdomains_report_{domain.replace('.', '_')}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    styleN = styles["Normal"]
    styleH = styles["Heading2"]

    story.append(Paragraph(f"Subdomain Report for {domain}", styleH))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styleN))
    story.append(Paragraph(" ", styleN))

    data = [["#", "Subdomain"]]
    for i, sub in enumerate(subdomains, 1):
        data.append([i, sub])

    table = Table(data, colWidths=[50, 400])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('ALIGN',(0,0),(-1,-1),'LEFT'),
        ('GRID', (0,0), (-1,-1), 1, colors.white),
        ('BACKGROUND',(0,1),(-1,-1),colors.darkgrey)
    ]))
    story.append(table)
    doc.build(story)
    return filename
