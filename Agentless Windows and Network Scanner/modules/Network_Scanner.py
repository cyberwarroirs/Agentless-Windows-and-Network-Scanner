import nmap
import matplotlib.pyplot as plt
from io import BytesIO
import base64
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, Image, TableStyle, Preformatted
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors

# ----------------- CUSTOM EXCEPTION -----------------
class ScanError(Exception):
    """Custom exception to show friendly scan errors to users."""
    pass


# ----------------- NMAP SCAN -----------------
def scan(target, scan_types):
    nm = nmap.PortScanner()

    scan_modes = {
        "basic": "-sn",           # Ping scan
        "service": "-sV",         # Service/version detection
        "os": "-sS -O",           # OS detection
        "aggressive": "-A",       # Aggressive scan
        "full": "-p- -sV -O",     # Full port scan
        "vuln": "--script vuln",  # Vulnerability scan
        "dns": "-sU -p 53",       # DNS scan
        "udp": "-sU"              # UDP scan
    }

    # Validation
    if "os" in scan_types and "basic" in scan_types:
        raise ScanError("OS detection cannot be combined with basic ping scan.")
    if "os" in scan_types and not any(s in scan_types for s in ["service", "full", "aggressive"]):
        raise ScanError("OS detection requires a port scan. Select Service, Full, or Aggressive.")

    combined_args = " ".join([scan_modes[s] for s in scan_types if s in scan_modes]) or "-sn"

    try:
        nm.scan(hosts=target, arguments=combined_args)
    except nmap.PortScannerError as e:
        raise ScanError("Scan failed. Check target IP or scan type.") from e
    except Exception:
        raise ScanError("Unexpected error occurred during scanning.")

    results = {}
    for host in nm.all_hosts():
        host_info = {
            "state": nm[host].state(),
            "hostnames": nm[host].hostnames(),
            "osmatch": nm[host].get("osmatch", []),
            "ports": []
        }
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                p_info = nm[host][proto][port]
                host_info["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": p_info.get("state", ""),
                    "service": p_info.get("name", ""),
                    "product": p_info.get("product", ""),
                    "version": p_info.get("version", ""),
                    "extrainfo": p_info.get("extrainfo", "")
                })
        results[host] = host_info

    if not results:
        raise ScanError("No hosts found. Target may be down or unreachable.")

    raw_output = nm.get_nmap_last_output().decode() if hasattr(nm, "get_nmap_last_output") else nm.csv()

    return {
        "results": results,
        "raw_output": raw_output
    }


# ----------------- GRAPH GENERATOR -----------------
def generate_graphs(scan_results):
    graphs = {}
    ports, services = [], []

    for _, data in scan_results.items():
        for p in data["ports"]:
            ports.append(p["port"])
            services.append(p["service"] if p["service"] else "unknown")

    # Pie chart for service distribution
    if services:
        plt.figure(figsize=(6, 6))
        service_counts = {s: services.count(s) for s in set(services)}
        plt.pie(service_counts.values(), labels=service_counts.keys(),
                autopct='%1.1f%%', startangle=140)
        plt.title("Service Distribution")
        img = BytesIO()
        plt.savefig(img, format="png", bbox_inches="tight")
        img.seek(0)
        graphs["services"] = base64.b64encode(img.getvalue()).decode()
        plt.close()

    # Histogram for ports
    if ports:
        plt.figure(figsize=(8, 4))
        plt.hist(ports, bins=min(len(set(ports)), 20), color="steelblue", edgecolor="black")
        plt.title("Open Port Distribution")
        plt.xlabel("Port Numbers")
        plt.ylabel("Frequency")
        img = BytesIO()
        plt.savefig(img, format="png")
        img.seek(0)
        graphs["ports"] = base64.b64encode(img.getvalue()).decode()
        plt.close()

    return graphs


# ----------------- PDF REPORT -----------------
def generate_report(scan_results, scan_types, raw_output, buffer):
    """Generate PDF report directly into a BytesIO buffer (no file saving)."""
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []

    # Title
    elements.append(Paragraph("<b>Network Scan Report</b>", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Scan Types: {', '.join(scan_types)}", styles['Heading2']))
    elements.append(Spacer(1, 12))

    # Hosts & Ports
    for host, data in scan_results.items():
        elements.append(Paragraph(f"<b>Host:</b> {host}", styles['Heading3']))
        elements.append(Paragraph(f"State: {data['state']}", styles['Normal']))

        if data.get("hostnames"):
            hostnames = ", ".join([h["name"] for h in data["hostnames"] if h["name"]])
            elements.append(Paragraph(f"Hostnames: {hostnames}", styles['Normal']))

        if data.get("osmatch"):
            oslist = ", ".join([f"{os['name']} ({os['accuracy']}%)" for os in data["osmatch"]])
            elements.append(Paragraph(f"OS Detection: {oslist}", styles['Normal']))

        elements.append(Spacer(1, 12))

        if data.get("ports"):
            table_data = [["Port", "Protocol", "State", "Service", "Product", "Version", "Extra Info"]]
            for p in data["ports"]:
                table_data.append([
                    str(p.get("port", "")),
                    p.get("protocol", ""),
                    p.get("state", ""),
                    p.get("service", ""),
                    p.get("product", ""),
                    p.get("version", ""),
                    p.get("extrainfo", "")
                ])
            table = Table(table_data, repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey])
            ]))
            elements.append(table)
            elements.append(Spacer(1, 12))

    # Graphs
    graphs = generate_graphs(scan_results)
    for name, img_data in graphs.items():
        img = BytesIO(base64.b64decode(img_data))
        elements.append(Paragraph(f"<b>{name.capitalize()} Graph</b>", styles['Heading3']))
        elements.append(Image(img, width=400, height=250))
        elements.append(Spacer(1, 12))

    # Raw Output
    elements.append(Paragraph("<b>Raw Nmap Output</b>", styles["Heading2"]))
    elements.append(Preformatted(raw_output, styles["Code"]))
    elements.append(Spacer(1, 12))

    doc.build(elements)
