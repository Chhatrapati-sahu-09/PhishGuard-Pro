# PhishGuard Pro – AI-Powered Phishing URL Detector

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![PyQt5](https://img.shields.io/badge/UI-PyQt5-green)
![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn-orange)
![Security](https://img.shields.io/badge/Cybersecurity-Phishing%20Detection-red)
![Status](https://img.shields.io/badge/Status-Completed-success)
![License](https://img.shields.io/badge/License-MIT-blue)

A **modern dark-themed desktop application** for **real-time phishing URL detection** that combines **Machine Learning, heuristic analysis, and threat-intelligence APIs** with professional analytics and reporting.

---

# Overview

**PhishGuard Pro** is an intelligent phishing detection tool designed to analyze suspicious URLs using a **multi-layered security approach**.

### Detection Layers
- **Machine Learning** (TF-IDF + Logistic Regression)
- **Heuristic Rule-Based Analysis**
- **Threat Intelligence APIs**
- **SSL and WHOIS Domain Validation**
- **Real-Time Analytics Dashboard**

The application includes a **modern PyQt5 desktop interface**, interactive visualizations, scan history tracking, and exportable reports.

It is suitable for **cybersecurity learning, demonstrations, and hackathons**.

---

# Key Features

## URL Analysis Engine

The core analysis engine evaluates URLs using multiple techniques.

### Machine Learning
- Character-level **TF-IDF feature extraction**
- **Logistic Regression classifier**
- Fast and lightweight prediction model

### Heuristic Security Checks

The system performs rule-based checks such as:

- IP address usage inside URL  
- Presence of `@` symbol  
- Excessive URL length  
- Suspicious tokens  
- Multiple subdomains  
- Unsafe TLD detection  
- Missing HTTPS protocol  
- Invalid SSL certificate  
- Domain age verification using WHOIS  

### Threat Intelligence Integration

External threat intelligence sources improve detection reliability:

- **VirusTotal API** for URL reputation
- **Google Safe Browsing API** for threat verification

---

# Analytics Dashboard

The application includes a real-time analytics panel that provides visual insights into scan results.

Features include:

- Histogram showing risk score distribution
- Pie chart displaying phishing vs safe URL ratio
- Mean risk score indicator
- Color-coded phishing severity levels

---

# PyQt5 Desktop Interface

The application features a **professional dark-themed GUI** built using **PyQt5**.

UI Features:

- Clean and modern layout
- Card-based interface design
- Smooth gradient styling
- Animated progress bar
- Real-time scan status updates
- User-friendly interaction flow

---

# Reports and History

PhishGuard Pro stores scan results and allows exporting data for analysis.

Capabilities include:

- Detailed phishing scan reports
- Session history table
- Export reports as **HTML**
- Export session history as **CSV**

---

# Demo Mode (Hackathon Friendly)

The tool includes a built-in **demo mode** designed for presentations and offline usage.

Features of demo mode:

- Auto-generated phishing dataset
- Offline machine learning training
- No external API dependency required
- Ideal for hackathons and cybersecurity demos

---

# Detection Architecture

PhishGuard Pro follows a **three-layer security architecture**.

## Layer 1 – Heuristic Analysis

Rule-based checks analyze structural properties of URLs.

Checks include:

- IP address detection
- `@` symbol presence
- Long URLs
- Suspicious tokens
- Multiple subdomains
- Unsafe TLDs
- Missing HTTPS
- SSL certificate validity
- Domain age verification

---

## Layer 2 – Machine Learning Detection

1. URLs are converted into **character-level TF-IDF vectors**.  
2. The feature vectors are passed into a **Logistic Regression classifier**.  
3. The model predicts a **phishing probability score**.

This layer enables **fast and scalable detection**.

---

## Layer 3 – Threat Intelligence

To strengthen results, external threat intelligence services are used.

- **VirusTotal** provides reputation analysis from multiple security vendors.
- **Google Safe Browsing** detects known malicious or phishing domains.

This layer increases **accuracy and credibility of results**.

---

# Technology Stack

| Component | Technology |
|----------|------------|
| Programming Language | Python |
| Desktop UI | PyQt5 |
| Machine Learning | Scikit-Learn |
| Feature Extraction | TF-IDF |
| Data Processing | Pandas |
| Visualization | Matplotlib |
| Domain Lookup | python-whois |
| Domain Parsing | tldextract |
| HTTP Requests | Requests |
| Model Storage | Joblib |

---

# Installation

## 1. Clone the Repository

```bash
git clone https://github.com/Chhatrapati-sahu-09/PhishGuard-Pro.git
cd PhishGuard-Pro
```

---

## 2. Create Virtual Environment (Recommended)

```bash
python -m venv venv
```

Activate environment

### Windows

```bash
venv\Scripts\activate
```

### Mac / Linux

```bash
source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Running the Application

```bash
python main.py
```

The application will launch the **PhishGuard Pro desktop interface**.

---

# Project Structure

```
PhishGuard-Pro
│
├── main.py
├── model
│   ├── phishing_model.pkl
│   └── vectorizer.pkl
│
├── analysis
│   ├── heuristic_checker.py
│   ├── ml_detector.py
│   └── threat_intel.py
│
├── ui
│   ├── dashboard.py
│   └── theme.py
│
├── reports
│   └── report_generator.py
│
├── data
│   └── demo_dataset.csv
│
└── requirements.txt
```

---

# Use Cases

PhishGuard Pro can be used for:

- Cybersecurity project demonstrations
- Hackathons and research prototypes
- Phishing detection experiments
- Security awareness presentations
- Machine learning security projects

---

# License

This project is licensed under the **MIT License**.

---

# Author

**Chhatrapati Sahu**

Portfolio: https://www.chhatrapatisahu.me  
GitHub: https://github.com/Chhatrapati-sahu-09  
LinkedIn: https://www.linkedin.com/in/chhatrpati-sahu-4b803130a/
