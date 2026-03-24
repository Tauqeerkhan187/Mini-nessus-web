Here’s a clean, professional README you can drop straight into your repo. No fluff, but strong enough to impress recruiters and actually explain what you built.

---

# 🛡️ Mini Nessus Web Scanner

A lightweight, web-based vulnerability scanner inspired by tools like Nessus and Nmap.
Built to identify exposed services, detect common security misconfigurations, and generate actionable reports.

---

## 🚀 Overview

Mini Nessus is a Python-based vulnerability scanner with a web interface that allows users to:

* Scan a target host for open ports
* Identify running services (SSH, HTTP, FTP, MySQL, Redis, etc.)
* Detect security issues and misconfigurations
* Assign severity levels to findings
* Generate structured PDF reports
* View results in a clean dashboard

This project demonstrates core cybersecurity concepts including **reconnaissance, service enumeration, vulnerability mapping, and risk assessment**.

---

## ⚙️ Features

### 🔍 Scanning Engine

* TCP port scanning (custom, quick, and full profiles)
* Banner grabbing for service identification
* Port-based fallback detection for silent services (e.g., MySQL, Redis)

### 🧠 Vulnerability Detection

* Rule-based vulnerability mapping
* Detection examples:

  * Open SSH service
  * Weak SSH configurations
  * FTP exposure (plaintext protocol)
  * Redis exposure (no authentication)
  * MySQL exposure
  * Missing firewall rules
  * Pending security updates

### 📊 Risk Classification

* Severity levels:

  * **CRITICAL**
  * **HIGH**
  * **MEDIUM**
  * **LOW**
  * **INFO**

### 📄 Reporting

* Auto-generated PDF reports
* Executive summary with severity breakdown
* Detailed findings with recommendations

### 🌐 Web Dashboard

* Scan management interface
* Detailed findings table
* Downloadable reports
* Clean UI built with Flask templates

---

## 🧱 Architecture

```
User (Browser)
     ↓
Flask Web App
     ↓
Scan Engine (Python)
     ↓
Service Detection
     ↓
Vulnerability Rules Engine
     ↓
Database (SQLite)
     ↓
Dashboard + PDF Report
```

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask
* **Database:** SQLite (SQLAlchemy ORM)
* **Scanning:** Custom socket-based engine
* **Frontend:** HTML, CSS (Jinja templates)
* **Reporting:** PDF generation (ReportLab / similar)

---

## 📂 Project Structure

```
mini_nessus_web/
│
├── app/
│   ├── routes.py          # Flask routes
│   ├── models.py          # Database models
│   ├── tasks.py           # Scan execution logic
│
├── scanner/
│   ├── engine.py          # Port scanning + detection
│   ├── vulns.py           # Vulnerability rules
│
├── templates/             # HTML templates
├── static/                # CSS / assets
├── reports/               # Generated PDFs
├── instance/              # Database files
│
├── main.py                 # App entry point
├── requirements.txt
└── README.md
```

---

## ⚡ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/mini-nessus-web.git
cd mini-nessus-web
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python main.py
```

### 5. Open in browser

```
http://127.0.0.1:5000
```

---

## 🧪 Example Scan

```bash
Target: 192.168.56.110
Open Ports:
- 22 (SSH)
- 80 (HTTP)
- 3306 (MySQL)
- 6379 (Redis)
```

### Example Findings:

* 🔴 Redis exposed to network
* 🔴 SSH vulnerable (CVE-2024-6387)
* 🟠 MySQL exposed
* 🟡 SSH password authentication enabled

---

## 📌 How It Works

1. **Port Scan**
   Uses TCP socket connections to identify open ports.

2. **Service Detection**

   * Banner grabbing (if available)
   * Port-based fallback (for silent services like Redis/MySQL)

3. **Vulnerability Mapping**
   Matches detected services against predefined rules.

4. **Severity Assignment**
   Each issue is classified based on impact.

5. **Report Generation**
   Results are stored and exported into a structured PDF.

---

## ⚠️ Limitations

* Not a replacement for enterprise tools like Nessus
* No authenticated scanning (yet)
* Limited CVE database (rule-based only)
* No UDP scanning

---

## 🧭 Future Improvements

* ✅ Risk scoring system (CVSS-style)
* 📊 Dashboard charts (severity distribution)
* 🔐 Credentialed scanning (SSH-based checks)
* 🌍 Multi-target scanning
* ⚡ Async scanning for performance
* 🧠 CVE API integration

---

## 🎯 Learning Outcomes

This project demonstrates:

* Network scanning fundamentals
* Service enumeration techniques
* Vulnerability assessment logic
* Secure coding practices
* Web app integration with security tooling

---

## 📸 Screenshots

> Add screenshots of:

* Dashboard
* Scan results
* PDF report

---

## 📜 License

MIT License

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first.

---

## 👤 Author

**TK**
Cybersecurity Student | Aspiring Security Engineer

---

## ⭐ Final Note

This project was built to bridge the gap between **theory and practical security tooling**, showcasing how vulnerability scanners work under the hood.
