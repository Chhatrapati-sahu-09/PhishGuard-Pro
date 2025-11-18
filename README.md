🛡️ PhishGuard Pro – AI Powered Phishing URL Detector

A modern, dark-themed desktop application for real-time phishing URL detection.

📌 Overview

PhishGuard Pro is an intelligent phishing detection tool that analyzes suspicious URLs using a powerful combination of:

✔ Heuristic rules
✔ Machine Learning (ML)
✔ Threat-Intelligence APIs (VirusTotal + Google Safe Browsing)
✔ SSL + WHOIS checks
✔ Real-time analytics visualization

It features a modern dark-themed UI built using PyQt5, complete with a dual analytics dashboard (Histogram + Pie Chart), session history tracking, and exportable reports.

🚀 Features
🔍 URL Analysis Engine

✔ Detects phishing URLs using ML (TF-IDF + Logistic Regression)

✔ Heuristic checks (IP, @ symbol, long URL, suspicious TLDs, tokens, SSL, domain age)

✔ VirusTotal & Google Safe Browsing API integration

📊 Analytics Dashboard

✔ Live histogram of risk scores

✔ Pie chart of risk distribution

✔ Mean score indicator

🖥️ Modern PyQt5 UI

✔ Dark theme

✔ Smooth gradients

✔ Professional card layout

✔ Animated progress bar

✔ Color-coded risk score

📝 Reports & History

✔ Detailed scan report

✔ Session history table

✔ Export report as HTML

✔ Export session as CSV

🎯 Demo Mode

✔ Auto-generate demo dataset

✔ Train offline demo model

✔ Useful for hackathon demonstrations

🛠️ Tech Stack
Component	Technology
UI Framework	PyQt5
Machine Learning	Scikit-Learn (TF-IDF + Logistic Regression)
Data Processing	Pandas
WHOIS Lookup	python-whois
Domain Parsing	tldextract
Visualization	Matplotlib
HTTP Requests	Requests
Model Saving	Joblib
📦 Installation
1️⃣ Clone the repository
git clone https://github.com/Chhatrapati-sahu-09/PhishGuard-Pro.git
cd PhishGuard-Pro

2️⃣ Create a virtual environment
python -m venv .venv

3️⃣ Activate environment

Windows:

.venv\Scripts\activate

4️⃣ Install dependencies
pip install -r requirements.txt

▶️ Run the Application
python phishguard_pro.py


Or (if filename renamed):

python phishguard_modern.py

🧠 How Detection Works

PhishGuard Pro uses a 3-layer security model:

1️⃣ Heuristic Analysis (Rule-based)

Checks:

IP present

“@” symbol

Long URL

Suspicious tokens

Multiple subdomains

Least-safe TLDs

Missing HTTPS

SSL invalid

Domain age

2️⃣ Machine Learning Detection

URL → Character-level TF-IDF features

Logistic Regression predicts phishing probability

Lightweight + fast model

3️⃣ Threat Intelligence

VirusTotal

Google Safe Browsing
