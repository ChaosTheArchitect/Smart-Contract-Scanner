import os
import re

import pdfkit
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, make_response
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash

app = Flask(__name__)


# Set up configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/generate-report')
@login_required
def generate_report():
    rendered = render_template('report_template.html')
    pdf = pdfkit.from_string(rendered, False)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=report.pdf'
    return response


@app.route('/', methods=['GET', 'POST'])
def index():
    findings = {}
    contract_code = ""
    if request.method == 'POST':
        contract_code = request.form.get('contract_code', '').strip()
        if 0 < len(contract_code) <= 5000:
            findings = scan_contract(contract_code)
            advanced_findings = advanced_audit(contract_code)
            findings.update(advanced_findings)
        else:
            findings = {"Error": ["Invalid input length."]}
    return render_template('index.html', findings=findings, contract_code=contract_code)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    scans = db.relationship('ScanHistory', backref='user', lazy=True)


class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_data = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))

        # Log the user in
        login_user(user, remember=remember)
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    scans = current_user.scans
    return render_template('profile.html', scans=scans)


@app.route('/generate_report')
@login_required
def generate_pdf_report(html_content):
    config = pdfkit.configuration(wkhtmltopdf='C:\Program Files\wkhtmltopdf')
    pdfkit.from_string(html_content, 'reports/report.pdf', configuration=config)
    latest_scan = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.id.desc()).first()

    if not latest_scan:
        flash("No scans found for the user!")
        return redirect(url_for('index'))

    findings = eval(latest_scan.scan_data)  # Assuming you stored findings as a string representation of a dictionary
    html_content = render_template('report_template.html', findings=findings)

    generate_pdf_report(html_content)
    return send_from_directory(directory=os.path.join(app.root_path, 'reports'), filename='report.pdf')


def scan_contract(contract_code):
    vulnerabilities = {

        "Unchecked Call Return Value": re.compile(r'\.call\('),
        "Delegatecall Usage": re.compile(r'\.delegatecall\('),
        "Reentrancy Attack": re.compile(r'call\.value\('),
        "Unprotected SELFDESTRUCT Instruction": re.compile(r'selfdestruct\('),
        "Unprotected Change of Ownership": re.compile(r'owner\s*=\s*'),
        "Unprotected Ether Withdrawal": re.compile(r'\.transfer\('),
        "Block Timestamp Manipulation": re.compile(r'block\.timestamp'),
        "Unchecked Send Return Value": re.compile(r'\.send\('),
        "Array Length Manipulation": re.compile(r'\.length\s*=\s*'),
        "tx.origin Authentication": re.compile(r'tx\.origin'),
        "Public Data or Functions": re.compile(r'\bpublic\b|\bexternal\b'),
        "Short Address Attack": re.compile(r'msg\.data\.length')
    }

    findings = {}
    lines = contract_code.split('\n')
    for vuln, pattern in vulnerabilities.items():
        matched_lines = []
        for i, line in enumerate(lines):
            if pattern.search(line):
                matched_lines.append(i + 1)

        if matched_lines:
            findings[vuln] = f"Potential vulnerability detected on line(s) {', '.join(map(str, matched_lines))}"
        else:
            findings[vuln] = "No obvious pattern detected"

    return findings


def advanced_audit(contract_code):
    # For demonstration purposes, this function identifies a few additional patterns.
    advanced_patterns = {
        "Use of call(": re.compile(r'\.call\('),
        "Use of delegatecall(": re.compile(r'\.delegatecall\('),
        "Use of call.value(": re.compile(r'call\.value\('),
        "Low-level calls are potentially unsafe. Consider using higher-level alternatives.": re.compile(
            r'\.call\(|\.delegatecall\(|\.callcode\('),
        "block.timestamp can be manipulated by miners. Consider its implications.": re.compile(r'block\.timestamp'),
        "Loops can be gas-intensive. Ensure they have a clear exit condition.": re.compile(r'for\(|while\('),
        "Consider using named constants instead of magic numbers.": re.compile(r'\d{3,}'),
        # any number 3 digits or longer
        "For full ERC-20 compliance, this function should be implemented.": re.compile(r'function totalSupply\('),
        "Ensure that the fallback function is safe and has necessary checks.": re.compile(
            r'function \(\) external payable')
    }

    findings = {}
    lines = contract_code.split('\n')
    for vuln, pattern in advanced_patterns.items():
        matched_lines = []
        for i, line in enumerate(lines):
            if pattern.search(line):
                matched_lines.append(i + 1)

        if matched_lines:
            findings[vuln] = f"Potential vulnerability detected on line(s) {', '.join(map(str, matched_lines))}"
        else:
            findings[vuln] = "No obvious pattern detected"

    return findings


if __name__ == '__main__':
    app.run(debug=False)
