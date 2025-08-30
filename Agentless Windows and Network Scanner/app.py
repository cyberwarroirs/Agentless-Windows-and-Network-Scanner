from flask import Flask, render_template, request, send_file, redirect, url_for, flash, jsonify, session
import logging, os, io, threading
from werkzeug.utils import secure_filename

# ----------------- Import Modules -----------------
from modules import Network_Scanner, Local_System_Vulnerability_Scanner, Security_Audit_Tool, Subdomain_Finder, Live_Subdomain_Finder
from modules.Network_Scanner import scan, generate_report, generate_graphs, ScanError
from modules.Local_System_Vulnerability_Scanner import PDF_REPORT, generate_pdf
from modules.Live_Subdomain_Finder import process_input

# ----------------- App Setup -----------------
app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['UPLOAD_FOLDER'] = "uploads"
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'csv', 'xls', 'xlsx', 'pdf'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

logging.basicConfig(level=logging.INFO)


# ----------------- Dashboard -----------------
@app.route('/')
def dashboard():
    return render_template('dashboard.html')


# ----------------- Network Scanner -----------------
@app.route("/network_scanner", methods=["GET", "POST"])
def network_scanner():
    if request.method == "POST":
        target = request.form["target"]
        scan_types = request.form.getlist("scan_types")
        try:
            data = scan(target, scan_types)
            results, raw_output = data["results"], data["raw_output"]
            graphs = generate_graphs(results)

            return render_template("Network_Scanner.html",
                                   target=target,
                                   scan_types=scan_types,
                                   results=results,
                                   graphs=graphs,
                                   raw_output=raw_output)
        except ScanError as e:
            return render_template("Network_Scanner.html", error=str(e))

    return render_template("Network_Scanner.html")


@app.route("/download_network_report", methods=["POST"])
def download_network_report():
    target = request.form.get("target")
    scan_types = request.form.getlist("scan_types")

    data = scan(target, scan_types)
    results, raw_output = data["results"], data["raw_output"]

    buffer = io.BytesIO()
    generate_report(results, scan_types, raw_output, buffer)
    buffer.seek(0)

    return send_file(buffer,
                     as_attachment=True,
                     download_name=f"scan_report_{target}.pdf",
                     mimetype="application/pdf")


# ----------------- Local System Vulnerability Scanner -----------------
@app.route("/local_scan", methods=["GET", "POST"])
def local_scan():
    if request.method == "POST":
        results = Local_System_Vulnerability_Scanner.scan()
        session["scan_results"] = results
        generate_pdf(results)

        return render_template("Local_System_Vulnerability_Scanner.html",
                               results=results,
                               show_download=True)

    return render_template("Local_System_Vulnerability_Scanner.html",
                           results=None,
                           show_download=False)


@app.route("/download_report", methods=["GET"])
def download_report():
    if os.path.exists(PDF_REPORT):
        return send_file(PDF_REPORT, as_attachment=True)
    else:
        flash("Report not found. Please run a scan first.", "danger")
        return redirect(url_for("local_scan"))


# ----------------- Security Audit -----------------
@app.route('/security_audit', methods=['GET', 'POST'])
def security_audit():
    results = None
    if request.method == 'POST':
        target = request.form.get('target')
        results = Security_Audit_Tool.audit(target)
    return render_template('Security_Audit_Tool.html', results=results)


@app.route('/download_audit_report', methods=['POST'])
def download_audit_report():
    target = request.form.get('target')
    if not target:
        return "No target provided", 400
    
    results = Security_Audit_Tool.audit(target)
    filename = Security_Audit_Tool.generate_pdf(results)
    return send_file(filename, as_attachment=True, download_name="audit_report.pdf")


# ----------------- Subdomain Finder -----------------
results_cache = {}

def run_subdomain_scan(domain):
    results_cache[domain] = Subdomain_Finder.find(domain)

@app.route('/subdomain_finder', methods=['GET', 'POST'])
def subdomain_finder():
    results, target_submitted = None, False
    if request.method == 'POST':
        domain = request.form['domain']
        target_submitted = True
        if domain not in results_cache:
            thread = threading.Thread(target=run_subdomain_scan, args=(domain,))
            thread.start()
        results = results_cache.get(domain)
    return render_template('Subdomain_Finder.html', results=results, target_submitted=target_submitted)


@app.route('/download_subdomains', methods=['POST'])
def download_subdomains():
    domain = request.form.get('domain')
    if not domain:
        return "No domain provided", 400
    subdomains = Subdomain_Finder.find_subdomains(domain)
    filename = Subdomain_Finder.generate_pdf(subdomains, domain)
    return send_file(filename, as_attachment=True, download_name=f"{domain}_subdomains.pdf")


# ----------------- Live Subdomain Finder -----------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/live_subdomain', methods=['GET', 'POST'])
def live_subdomain_finder():
    live, dead, pdf_file = [], [], None

    if request.method == 'POST':
        domain_text = request.form.get('domain', '').strip()
        file = request.files.get('domain_file')
        file_path = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

        try:
            live, dead, reports = process_input(domain_text=domain_text or None,
                                                file_path=file_path or None)
            session['last_pdf'] = reports['pdf']
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(request.url)
        finally:
            if file_path and os.path.exists(file_path):
                os.remove(file_path)

        pdf_file = session.get('last_pdf')

    return render_template('Live_Subdomain_Finder.html', live=live, dead=dead, pdf_file=pdf_file)


@app.route('/download/pdf', methods=['GET'])
def download_pdf_report():
    file_path = os.path.abspath("reports/report.pdf")
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True, download_name="domain_report.pdf")
    else:
        return "PDF report not found", 404


# ----------------- Run App -----------------
if __name__ == '__main__':
    app.run(debug=True)
