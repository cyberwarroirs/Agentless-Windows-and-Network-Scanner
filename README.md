

# 🔐 Agentless Windows & Network Scanner

The **Agentless Windows & Network Scanner** is a **web-based cybersecurity toolkit** built using **Flask (Python)**.
It integrates multiple security modules into a single platform to simplify scanning, auditing, and vulnerability analysis.

This toolkit is designed for:

* 🔍 **Security Researchers** → To analyze systems & networks.
* 🛡 **Penetration Testers** → To find weaknesses and create reports.
* 🖥 **System Administrators** → To monitor, audit, and secure infrastructure.

---

## ✨ Key Features

### 🌐 Network Scanner

* Perform different types of **Nmap scans**:

  * Basic Scan (host discovery)
  * Service Scan (detect running services & versions)
  * OS Detection Scan (identify target OS)
  * Full Scan (combination of above + detailed enumeration)
* Display **hostnames, IPs, ports, services, versions, and CPE data**.
* Visualize results using **graphs & tables**.
* Export **scan results as PDF** with raw Nmap output included.

---

### 💻 Local System Vulnerability Scanner (Agentless)

* Scan your **own Windows system** directly from the web app (no agent needed).
* Detect:

  * Suspicious software/processes
  * System open ports
  * Firewall status
  * Unused software
  * Network connections (IPs, MAC addresses)
  * Disk usage (visualized with charts)
* Generates **PDF vulnerability reports** with detailed system findings.

---

### 🛡 Website Security Audit Tool

* Perform quick **web security audits**.
* Check for missing/weak **HTTP security headers**:

  * Content-Security-Policy
  * X-Frame-Options
  * Strict-Transport-Security
  * X-Content-Type-Options
  * Referrer-Policy
* Detect potential misconfigurations.
* Detect SQl Injection, HTML Injection, XSS Vulnerability
* Export results into a structured **audit report (PDF)**.

---

### 🔎 Subdomain Finder

* Discover subdomains for any given domain.
* Supports **background scanning** with caching for faster results.
* Export findings as **downloadable PDF reports**.

---

### 🌍 Live Subdomain Finder

* Identify **live vs. dead subdomains**.
* Accepts domain input as:

  * Manual text
  * File upload (`.txt`, `.csv`, `.xls`, `.xlsx`, `.pdf`)
* Generates a **live/dead domain classification report in PDF**.

---

## 📊 Reports & Visualization

Every module supports **automated PDF report generation**.
Reports include:

* Structured results
* Graphs & charts (via Matplotlib)
* Tabular scan output
* Raw scan results (for transparency)

Example report sections:

* “The End is Beginning!” (report header)
* Scan Type + Target details
* Graphical visualizations
* Raw output for validation

---

## 🛠️ Tech Stack

* **Backend**: Python (Flask)
* **Scanning Tools**:

  * Nmap (network scanning)
  * psutil (system scanning)
* **Reporting**: ReportLab (PDF generation), Matplotlib (graphs)
* **Frontend**: HTML, Bootstrap, Jinja2 templates
* **File Handling**: Secure file uploads for domain lists

---

## ⚡ Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/agentless-scanner.git
cd agentless-scanner
```

### 2. Setup Virtual Environment

```bash
python -m venv venv
# Activate
source venv/bin/activate     # Linux / Mac
venv\Scripts\activate        # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run Application

```bash
python app.py
```

### 5. Access Web App

Visit in browser:
👉 **[http://127.0.0.1:5000/](http://127.0.0.1:5000/)**

---

## 📂 Project Structure

```
Agentless Windows and Network Scanner
├── app.py                        # Main Flask application
├── modules/                      # Security modules
│   ├── Network_Scanner.py        # Network scanning (Nmap integration)
│   ├── Local_System_Vulnerability_Scanner.py   # Agentless system scan
│   ├── Security_Audit_Tool.py    # Website header audit
│   ├── Subdomain_Finder.py       # Subdomain enumeration
│   ├── Live_Subdomain_Finder.py  # Live/dead subdomain check
├── templates/                    # HTML frontend templates
│   ├── base.html                
│   ├── dashboard.html
│   ├── Network_Scanner.html
│   ├── Local_System_Vulnerability_Scanner.html
│   ├── Security_Audit_Tool.html
│   ├── Subdomain_Finder.html
│   ├── Live_Subdomain_Finder.html
├── static/                       # CSS, JS, assets
│   ├── Screenshots                       
├── reports/                      # Generated PDF reports
├── uploads/                      # Uploaded domain files
├── requirements.txt              # Python dependencies
└── README.md                     # Documentation
```

---

## 📸 Screenshots

* **Dashboard**
  ![Dashboard](static/Screenshots/Dashboard.png)
  ![Dashboard](static/Screenshots/Dashboard1.png)
  
* **Network Scanner**
  ![Network Scanner](static/Screenshots/Network_Scanner.png)

* **Local System Vulnerability Scanner**
  ![Local System Vulnerability Scanner](static/Screenshots/Local_System_Vulnerability_Scanner.png)

* **Local System Vulnerability Scanner Result**
  ![Local System Vulnerability Scanner Result](static/Screenshots/Local_System_Vulnerability_Scanner_Result.png)

* **Website Security Audit**
  ![Website Security Audit](static/Screenshots/Security_Audit_Tool.png)

* **Website Security Audit Result**
  ![Website Security Audit Result](static/Screenshots/Security_Audit_Tool_Result.png)
  ![Website Security Audit Result](static/Screenshots/Security_Audit_Tool_Result1.png)
  ![Website Security Audit Result](static/Screenshots/Security_Audit_Tool_Result2.png)

* **Advanced Subdomain Finder**
  ![Advanced Subdomain Finder](static/Screenshots/Subdomain_Finder.png)

* **Live Subdomain Finder**
  ![Live Subdomain Finder](static/Screenshots/Live_Subdomain_Finder.png)
  
* **PDF Report Example**
  ![Websecurity_Report](screenshots/Websecurity_Report.png)
  ![Subdomain_Finder_Report](screenshots/Subdomain_Finder_Report.png)
  
  

---

## 🔒 Disclaimer

This tool is intended **for educational and research purposes only**.

* ✅ Use it on systems **you own** or **have explicit permission** to test.
* ❌ Unauthorized scanning or auditing of third-party systems may be illegal.

> ⚠️ The author is **not responsible** for any misuse or damage caused.

---

## ⭐ Contributing

Contributions are welcome!

1. Fork the repo
2. Create a new branch (`feature-newscan`)
3. Commit your changes
4. Submit a Pull Request 🚀

---

## 📬 Contact

For queries or collaborations:
📧 **[your.email@example.com](mailto:vijaywagh7391@gmail.com)**
🌐 [LinkedIn](https://linkedin.com/in/vijaywagh4454) | [GitHub](https://github.com/cyberwarroirs)

---

## ⚖️ License  
⚔️  © 2025 Cyberwarriors. | All Rights Reserved — Cyberwarriors

