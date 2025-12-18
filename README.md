# 🛡️ PhishGuard Pro – AI-Powered Phishing URL Detector

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![PyQt5](https://img.shields.io/badge/UI-PyQt5-green)
![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn-orange)
![Security](https://img.shields.io/badge/Cybersecurity-Phishing%20Detection-red)
![Status](https://img.shields.io/badge/Status-Completed-success)
![License](https://img.shields.io/badge/License-MIT-blue)

A **modern, dark-themed desktop application** for **real-time phishing URL detection**, combining **Machine Learning**, **heuristic analysis**, and **threat-intelligence APIs** with professional-grade analytics and reporting.

---

## 📌 Overview

**PhishGuard Pro** is an intelligent phishing detection tool designed to analyze suspicious URLs using a **multi-layered security approach**:

- 🧠 **Machine Learning** (TF-IDF + Logistic Regression)
- 🔍 **Heuristic Rule-Based Analysis**
- 🌐 **Threat-Intelligence APIs** (VirusTotal & Google Safe Browsing)
- 🔐 **SSL & WHOIS Domain Validation**
- 📊 **Real-Time Analytics Dashboard**

The application features a **modern dark-themed UI built with PyQt5**, including **interactive visualizations**, **session history tracking**, and **exportable reports**, making it ideal for **cybersecurity learning, demonstrations, and hackathons**.

---

## ✨ Key Features

### 🔍 URL Analysis Engine
- Detects phishing URLs using **Machine Learning**
- Character-level **TF-IDF feature extraction**
- **Logistic Regression** classifier for fast predictions
- Heuristic checks:
  - IP-based URLs  
  - `@` symbol usage  
  - Long URLs  
  - Suspicious tokens  
  - Multiple subdomains  
  - Unsafe TLDs  
  - Missing HTTPS  
  - Invalid SSL certificate  
  - Domain age (WHOIS)

- Integration with:
  - **VirusTotal API**
  - **Google Safe Browsing API**

---

### 📊 Analytics Dashboard
- Live **histogram** of risk scores
- **Pie chart** showing risk distribution
- Mean risk score indicator
- Color-coded phishing severity levels

---

### 🖥️ Modern PyQt5 UI
- Dark professional theme
- Smooth gradients & card-based layout
- Animated progress bar
- Real-time status updates
- Intuitive, user-friendly design

---

### 📝 Reports & History
- Detailed phishing scan reports
- Session history table
- Export reports as **HTML**
- Export session history as **CSV**

---

### 🎯 Demo Mode (Hackathon-Friendly)
- Auto-generated demo dataset
- Offline ML model training
- No API dependency required
- Ideal for presentations & evaluations

---

## 🧠 How Detection Works

PhishGuard Pro follows a **3-Layer Security Model**:

### 1️⃣ Heuristic Analysis (Rule-Based)
Checks for:
- IP addresses in URL
- `@` symbol presence
- Excessive URL length
- Suspicious tokens & subdomains
- Unsafe TLDs
- Missing HTTPS
- SSL certificate validity
- Domain age via WHOIS

---

### 2️⃣ Machine Learning Detection
- URL transformed into **character-level TF-IDF features**
- **Logistic Regression** predicts phishing probability
- Lightweight, fast, and efficient model

---

### 3️⃣ Threat Intelligence
- **VirusTotal** URL reputation check
- **Google Safe Browsing** threat verification
- Enhances detection accuracy and trustworthiness

---

## 🛠️ Tech Stack

| Component | Technology |
|---------|------------|
| Language | Python |
| UI Framework | PyQt5 |
| Machine Learning | Scikit-Learn |
| Feature Extraction | TF-IDF |
| Data Processing | Pandas |
| Visualization | Matplotlib |
| WHOIS Lookup | python-whois |
| Domain Parsing | tldextract |
| HTTP Requests | Requests |
| Model Persistence | Joblib |

---

## 📦 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Chhatrapati-sahu-09/PhishGuard-Pro.git
cd PhishGuard-Pro
