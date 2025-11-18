# --------------------
# PhishGuard Pro RTIS - Updated (pie chart overlap fixes)
# --------------------

import sys
import os
import re
import socket
import ssl
import time
import math
import json
import hashlib
import threading
import queue
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QPropertyAnimation, QRect
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTextEdit, QFileDialog, QMessageBox, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter, QFrame, QAction,
    QToolBar, QComboBox, QSizePolicy, QCheckBox, QGridLayout, QTabWidget,
    QSpinBox, QGroupBox, QListWidget, QListWidgetItem, QDockWidget
)

import pandas as pd
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import tldextract
# whois and requests are optional and may fail if not installed or offline
try:
    import whois
except:
    whois = None
try:
    import requests
except:
    requests = None

import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# --------------------
# Configuration
# --------------------
APP_TITLE = "PhishGuard Pro RTIS"
MODEL_PATH = "phishguard_rtis_model.joblib"
IOC_DATABASE_PATH = "ioc_database.json"
THREAT_FEED_UPDATE_INTERVAL = 300  # 5 minutes
WATCHLIST_SCAN_INTERVAL = 60  # 1 minute
MAX_THREAT_HISTORY = 1000

# Simulated threat feeds (in production, these would be real APIs)
THREAT_FEEDS = {
    'openphish': 'https://openphish.com/feed.txt',
    'phishtank': 'https://data.phishtank.com/data/online-valid.json',
    'urlhaus': 'https://urlhaus.abuse.ch/downloads/csv_recent/'
}

SUSPICIOUS_TOKENS = ['login','secure','account','update','verify','bank','confirm',
                     'webscr','signin','wp-login','admin','password','suspended',
                     'unusual','activity','locked','validate','unauthorized']
ABUSED_TLDS = set(['zip','review','country','kim','cricket','gq','work','top','loan',
                   'xyz','club','online','site','website','space','tech'])

# --------------------
# IOC Database Manager
# --------------------
class IOCDatabase:
    def __init__(self, path=IOC_DATABASE_PATH):
        self.path = path
        self.iocs = self._load()
        
    def _load(self) -> Dict:
        if os.path.exists(self.path):
            try:
                with open(self.path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            'malicious_urls': [],
            'malicious_domains': [],
            'malicious_ips': [],
            'suspicious_patterns': [],
            'last_updated': None
        }
    
    def save(self):
        try:
            with open(self.path, 'w', encoding='utf-8') as f:
                json.dump(self.iocs, f, indent=2)
        except Exception as e:
            print(f"Error saving IOC database: {e}")
    
    def add_ioc(self, ioc_type: str, value: str, metadata: Dict = None):
        key = f'{ioc_type}s'
        if key not in self.iocs:
            self.iocs[key] = []
        
        entry = {
            'value': value,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {}
        }
        
        # Avoid duplicates
        if not any(item.get('value') == value for item in self.iocs.get(key, [])):
            self.iocs.setdefault(key, []).append(entry)
            self.save()
    
    def check_ioc(self, url: str) -> Tuple[bool, List[str]]:
        """Check if URL matches any IOCs"""
        matches = []
        
        # Check full URL
        for ioc in self.iocs.get('malicious_urls', []):
            if ioc.get('value') and ioc['value'] in url:
                matches.append(f"Known malicious URL: {ioc['value']}")
        
        # Check domain
        try:
            domain = tldextract.extract(url).registered_domain
        except Exception:
            domain = ''
        for ioc in self.iocs.get('malicious_domains', []):
            if ioc.get('value') and ioc['value'] == domain:
                matches.append(f"Known malicious domain: {domain}")
        
        # Check IP
        ip_match = re.search(r'//(\d{1,3}(?:\.\d{1,3}){3})', url)
        if ip_match:
            ip = ip_match.group(1)
            for ioc in self.iocs.get('malicious_ips', []):
                if ioc.get('value') and ioc['value'] == ip:
                    matches.append(f"Known malicious IP: {ip}")
        
        return len(matches) > 0, matches
 # --------------------
# Real-Time Threat Feed Monitor
# --------------------
class ThreatFeedMonitor(QThread):
    threat_update = pyqtSignal(dict)
    status_update = pyqtSignal(str)
    
    def __init__(self, ioc_db: IOCDatabase):
        super().__init__()
        self.ioc_db = ioc_db
        self.running = True
        self.threat_count = 0
        
    def run(self):
        while self.running:
            self.status_update.emit("📡 Fetching threat intelligence feeds...")
            
            try:
                # Simulate fetching from multiple threat feeds
                threats = self._fetch_threats()
                
                for threat in threats:
                    self.threat_count += 1
                    self.threat_update.emit(threat)
                    self.ioc_db.add_ioc('malicious_url', threat['url'], 
                                       {'source': threat['source'], 'severity': threat['severity']})
                
                self.status_update.emit(f"✓ Feed updated: {len(threats)} new threats")
                
            except Exception as e:
                self.status_update.emit(f"⚠ Feed error: {str(e)}")
            
            # Wait for next update cycle
            for _ in range(max(1, THREAT_FEED_UPDATE_INTERVAL)):
                if not self.running:
                    break
                time.sleep(1)
    
    def _fetch_threats(self) -> List[Dict]:
        """Simulate fetching from threat intelligence feeds"""
        simulated_threats = []
        
        # Generate realistic-looking phishing URLs
        domains = ['secure-login', 'account-verify', 'bank-update', 'paypal-secure', 
                   'amazon-verify', 'microsoft-login', 'apple-id-verify']
        tlds = ['com', 'net', 'org', 'info', 'xyz', 'top']
        
        for _ in range(np.random.randint(3, 8)):
            domain = np.random.choice(domains)
            tld = np.random.choice(tlds)
            path = np.random.choice(['login.php', 'verify.html', 'account/update', 'secure/auth'])
            
            url = f"http://{domain}-{np.random.randint(1000,9999)}.{tld}/{path}"
            
            simulated_threats.append({
                'url': url,
                'source': np.random.choice(['OpenPhish', 'PhishTank', 'URLhaus']),
                'severity': np.random.choice(['High', 'Medium', 'Low']),
                'timestamp': datetime.utcnow().isoformat(),
                'country': np.random.choice(['US', 'CN', 'RU', 'BR', 'IN', 'Unknown'])
            })
        
        return simulated_threats
    
    def stop(self):
        self.running = False

# --------------------
# Automated Watchlist Scanner
# --------------------
class WatchlistScanner(QThread):
    scan_complete = pyqtSignal(dict)
    status_update = pyqtSignal(str)
    
    def __init__(self, watchlist: List[str], model):
        super().__init__()
        self.watchlist = watchlist
        self.model = model
        self.running = True
        
    def run(self):
        while self.running:
            if not self.watchlist:
                for _ in range(max(1, WATCHLIST_SCAN_INTERVAL)):
                    if not self.running:
                        break
                    time.sleep(1)
                continue
                
            self.status_update.emit(f"🔍 Scanning {len(self.watchlist)} watchlist URLs...")
            
            for url in list(self.watchlist):
                if not self.running:
                    break
                    
                result = self._scan_url(url)
                self.scan_complete.emit(result)
                time.sleep(2)  # Rate limiting
            
            self.status_update.emit("✓ Watchlist scan complete")
            
            # Wait for next scan cycle
            for _ in range(max(1, WATCHLIST_SCAN_INTERVAL)):
                if not self.running:
                    break
                time.sleep(1)
    
    def _scan_url(self, url: str) -> Dict:
        """Perform quick scan of URL"""
        try:
            if self.model:
                prob = self.model.predict_proba([url])[0][1]
            else:
                prob = 0.5
            
            return {
                'url': url,
                'risk_score': int(prob * 100),
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'active'
            }
        except Exception:
            return {
                'url': url,
                'risk_score': 0,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'error'
            }
    
    def update_watchlist(self, watchlist: List[str]):
        self.watchlist = watchlist
    
    def stop(self):
        self.running = False
# --------------------
# Enhanced Feature Extraction
# --------------------
class AdvancedFeatureExtractor:
    @staticmethod
    def extract_features(url: str) -> Dict[str, float]:
        """Extract comprehensive features for advanced analysis"""
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['has_ip'] = 1.0 if re.search(r'//\d{1,3}(?:\.\d{1,3}){3}', url) else 0.0
        features['has_at'] = 1.0 if '@' in url else 0.0
        features['has_https'] = 1.0 if url.startswith('https://') else 0.0
        
        # Domain features
        try:
            ext = tldextract.extract(url)
        except Exception:
            ext = type('e', (), {'subdomain':'', 'domain':'', 'suffix':''})()
        features['subdomain_count'] = ext.subdomain.count('.') if getattr(ext, 'subdomain', None) else 0
        features['domain_length'] = len(ext.domain) if getattr(ext, 'domain', None) else 0
        features['suspicious_tld'] = 1.0 if getattr(ext, 'suffix', '').lower() in ABUSED_TLDS else 0.0
        
        # Token-based features
        tokens = re.split(r'[:/\.\-?=&]', url.lower())
        features['suspicious_token_count'] = sum(1 for t in tokens if any(st in t for st in SUSPICIOUS_TOKENS))
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if url else 0
        features['special_char_ratio'] = sum(1 for c in url if not c.isalnum()) / len(url) if url else 0
        
        # Entropy (randomness measure)
        if url:
            prob = [url.count(c) / len(url) for c in set(url)]
            features['entropy'] = -sum(p * math.log2(p) for p in prob if p > 0)
        else:
            features['entropy'] = 0
        
        # Path features
        path_match = re.search(r'//[^/]+(/.*)?', url)
        if path_match and path_match.group(1):
            path = path_match.group(1)
            features['path_length'] = len(path)
            features['path_depth'] = path.count('/')
        else:
            features['path_length'] = 0
            features['path_depth'] = 0
        
        return features

# --------------------
# Ensemble ML Model Builder
# --------------------
def build_ensemble_pipeline():
    """Build advanced ensemble model"""
    vec = TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=30000)
    
    # Multiple classifiers
    lr = LogisticRegression(max_iter=1000, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    
    # Voting ensemble
    ensemble = VotingClassifier(
        estimators=[('lr', lr), ('rf', rf)],
        voting='soft'
    )
    
    pipe = Pipeline([('tfidf', vec), ('clf', ensemble)])
    return pipe

# --------------------
# Advanced Visualization Canvas
# --------------------
class AdvancedMplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=10, height=7, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi, facecolor='#0a0e12')
        super(AdvancedMplCanvas, self).__init__(self.fig)
        self.fig.tight_layout(pad=3.0)

# --------------------
# Live Threat Map Widget
# --------------------
class ThreatMapWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.threats = deque(maxlen=100)
        
        layout = QVBoxLayout(self)
        
        title = QLabel("🌍 Live Threat Map")
        title.setObjectName("cardTitle")
        layout.addWidget(title)
        
        self.canvas = AdvancedMplCanvas(self, width=8, height=4)
        layout.addWidget(self.canvas)
        
        # Stats row
        stats_layout = QHBoxLayout()
        self.total_threats = QLabel("Total: 0")
        self.high_severity = QLabel("High: 0")
        self.medium_severity = QLabel("Medium: 0")
        
        for lbl in [self.total_threats, self.high_severity, self.medium_severity]:
            lbl.setStyleSheet("color: #94a3b8; font-size: 11px; padding: 5px;")
            stats_layout.addWidget(lbl)
        
        layout.addLayout(stats_layout)
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_map)
        self.update_timer.start(5000)
    
    def add_threat(self, threat: Dict):
        self.threats.append(threat)
        self.update_stats()
    
    def update_stats(self):
        total = len(self.threats)
        high = sum(1 for t in self.threats if t.get('severity') == 'High')
        medium = sum(1 for t in self.threats if t.get('severity') == 'Medium')
        
        self.total_threats.setText(f"Total: {total}")
        self.high_severity.setText(f"High: {high}")
        self.medium_severity.setText(f"Medium: {medium}")
    
    def update_map(self):
        """Update threat visualization"""
        self.canvas.fig.clear()
        
        if not self.threats:
            ax = self.canvas.fig.add_subplot(111)
            ax.text(0.5, 0.5, 'Waiting for threat data...', 
                   ha='center', va='center', color='#94a3b8', fontsize=12)
            ax.set_facecolor('#0a0e12')
            ax.axis('off')
            self.canvas.draw()
            return
        
        # Create world map simulation
        ax = self.canvas.fig.add_subplot(111)
        ax.set_facecolor('#0a0e12')
        
        # Simulate geographic distribution
        country_counts = defaultdict(int)
        for threat in self.threats:
            country_counts[threat.get('country', 'Unknown')] += 1
        
        countries = list(country_counts.keys())
        counts = list(country_counts.values())
        
        # Create bar chart
        colors = ['#ef4444' if c == max(counts) else '#f59e0b' if c > np.mean(counts) else '#10b981' 
                  for c in counts]
        
        bars = ax.barh(countries, counts, color=colors, edgecolor='#1e293b', linewidth=1.5)
        
        ax.set_xlabel('Threat Count', color='#cbd5e1', fontsize=10)
        ax.set_title('Threats by Origin', color='#06b6d4', fontsize=12, fontweight='bold', pad=10)
        ax.tick_params(colors='#94a3b8', labelsize=9)
        ax.spines['bottom'].set_color('#334155')
        ax.spines['left'].set_color('#334155')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.grid(True, alpha=0.1, color='#475569', axis='x')
        
        self.canvas.draw()
# --------------------
# --------------------
# Main RTIS Window
# --------------------
class RTISMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setMinimumSize(1400, 900)
        
        # Initialize components
        self.model = None
        self.ioc_db = IOCDatabase()
        self.session_scans = []
        self.watchlist = []
        self.alert_queue = queue.Queue()
        
        # Apply theme
        self.apply_rtis_theme()
        
        # Setup UI
        self.setup_ui()
        
        # Start background threads
        self.start_monitoring_threads()
        
        self.show()
    
    def setup_ui(self):
        """Setup comprehensive UI"""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(12)
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Tab Widget for different views
        self.tabs = QTabWidget()
        self.tabs.setObjectName("mainTabs")
        
        # Tab 1: Real-Time Monitoring
        self.tabs.addTab(self.create_monitoring_tab(), "🔴 Live Monitoring")
        
        # Tab 2: URL Scanner
        self.tabs.addTab(self.create_scanner_tab(), "🔍 URL Scanner")
        
        # Tab 3: Threat Intelligence
        self.tabs.addTab(self.create_intelligence_tab(), "📊 Threat Intelligence")
        
        # Tab 4: Watchlist Management
        self.tabs.addTab(self.create_watchlist_tab(), "👁️ Watchlist")
        
        # Tab 5: Settings & Training
        self.tabs.addTab(self.create_settings_tab(), "⚙️ Settings")
        
        main_layout.addWidget(self.tabs, 1)
        
        # Bottom status bar
        bottom_bar = self.create_status_bar()
        main_layout.addWidget(bottom_bar)
        
        # Menu
        self.create_menu()
    
    def create_header(self):
        """Create header with system status"""
        header = QFrame()
        header.setObjectName("header")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(15, 12, 15, 12)
        
        # Title
        title = QLabel("🛡️ PhishGuard Pro RTIS")
        title.setObjectName("mainTitle")
        layout.addWidget(title)
        
        layout.addStretch()
        
        # System status indicators
        self.feed_status = QLabel("🔴 Feed: Offline")
        self.feed_status.setObjectName("statusIndicator")
        
        self.watchlist_status = QLabel("⚪ Watchlist: Idle")
        self.watchlist_status.setObjectName("statusIndicator")
        
        self.model_status = QLabel("⚪ Model: Not Loaded")
        self.model_status.setObjectName("statusIndicator")
        
        for status in [self.feed_status, self.watchlist_status, self.model_status]:
            layout.addWidget(status)
        
        return header
    
    def create_monitoring_tab(self):
        """Real-time threat monitoring dashboard"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Top controls
        controls = QFrame()
        controls.setObjectName("toolbar")
        ctrl_layout = QHBoxLayout(controls)
        
        self.feed_toggle = QPushButton("▶ Start Feed Monitor")
        self.feed_toggle.setObjectName("toolButton")
        self.feed_toggle.clicked.connect(self.toggle_feed_monitor)
        
        self.clear_alerts_btn = QPushButton("🗑️ Clear Alerts")
        self.clear_alerts_btn.setObjectName("toolButton")
        self.clear_alerts_btn.clicked.connect(self.clear_alerts)
        
        ctrl_layout.addWidget(self.feed_toggle)
        ctrl_layout.addWidget(self.clear_alerts_btn)
        ctrl_layout.addStretch()
        
        layout.addWidget(controls)
        
        # Split view: Live threats + Map
        splitter = QSplitter(Qt.Horizontal)
        
        # Left: Live threat feed
        left_panel = QFrame()
        left_panel.setObjectName("card")
        left_layout = QVBoxLayout(left_panel)
        
        feed_title = QLabel("📡 Live Threat Feed")
        feed_title.setObjectName("cardTitle")
        left_layout.addWidget(feed_title)
        
        self.threat_feed_list = QListWidget()
        self.threat_feed_list.setObjectName("threatList")
        left_layout.addWidget(self.threat_feed_list)
        
        splitter.addWidget(left_panel)
        
        # Right: Threat map
        self.threat_map = ThreatMapWidget()
        splitter.addWidget(self.threat_map)
        
        splitter.setSizes([600, 700])
        layout.addWidget(splitter, 1)
        
        return tab
    
    def create_scanner_tab(self):
        """Enhanced URL scanner interface"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Input card
        input_card = QFrame()
        input_card.setObjectName("card")
        input_layout = QVBoxLayout(input_card)
        
        # URL input row
        url_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText('🔗 Enter URL to perform deep analysis...')
        self.url_input.setObjectName("urlInput")
        self.url_input.returnPressed.connect(self.perform_deep_scan)
        
        self.scan_btn = QPushButton('🔬 DEEP SCAN')
        self.scan_btn.setObjectName("scanButton")
        self.scan_btn.setFixedWidth(180)
        self.scan_btn.clicked.connect(self.perform_deep_scan)
        
        url_row.addWidget(self.url_input, 3)
        url_row.addWidget(self.scan_btn)
        input_layout.addLayout(url_row)
        
        # Risk display
        self.risk_display = QLabel('⚪ Status: Ready for scan')
        self.risk_display.setObjectName("riskDisplay")
        self.risk_display.setAlignment(Qt.AlignCenter)
        input_layout.addWidget(self.risk_display)
        
        layout.addWidget(input_card)
        
        # Results area with tabs
        results_tabs = QTabWidget()
        results_tabs.setObjectName("resultsTabs")
        
        # Detailed report
        self.report_area = QTextEdit()
        self.report_area.setObjectName("reportArea")
        self.report_area.setReadOnly(True)
        results_tabs.addTab(self.report_area, "📋 Detailed Report")
        
        # Feature analysis
        self.feature_canvas = AdvancedMplCanvas(self, width=10, height=6)
        results_tabs.addTab(self.feature_canvas, "📊 Feature Analysis")
        
        # IOC matches
        self.ioc_list = QListWidget()
        self.ioc_list.setObjectName("threatList")
        results_tabs.addTab(self.ioc_list, "🎯 IOC Matches")
        
        layout.addWidget(results_tabs, 1)
        
        return tab
    def create_intelligence_tab(self):
        """Threat intelligence analytics"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Stats cards
        stats_row = QHBoxLayout()
        
        self.stats_total = self.create_stat_card("Total Threats", "0", "#06b6d4")
        self.stats_high = self.create_stat_card("High Risk", "0", "#ef4444")
        self.stats_blocked = self.create_stat_card("Blocked", "0", "#10b981")
        self.stats_sources = self.create_stat_card("Active Sources", "0", "#f59e0b")
        
        for card in [self.stats_total, self.stats_high, self.stats_blocked, self.stats_sources]:
            stats_row.addWidget(card)
        
        layout.addLayout(stats_row)
        
        # Analytics canvas
        analytics_card = QFrame()
        analytics_card.setObjectName("card")
        analytics_layout = QVBoxLayout(analytics_card)
        
        title = QLabel("📈 Threat Analytics Dashboard")
        title.setObjectName("cardTitle")
        analytics_layout.addWidget(title)
        
        self.analytics_canvas = AdvancedMplCanvas(self, width=12, height=7)
        analytics_layout.addWidget(self.analytics_canvas)
        
        layout.addWidget(analytics_card, 1)
        
        # Update timer
        self.analytics_timer = QTimer()
        self.analytics_timer.timeout.connect(self.update_analytics)
        self.analytics_timer.start(10000)
        
        return tab
    
    def create_watchlist_tab(self):
        """Watchlist management interface"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Controls
        controls = QFrame()
        controls.setObjectName("toolbar")
        ctrl_layout = QHBoxLayout(controls)
        
        self.watchlist_input = QLineEdit()
        self.watchlist_input.setPlaceholderText("Enter URL to add to watchlist...")
        self.watchlist_input.setObjectName("urlInput")
        
        add_btn = QPushButton("➕ Add")
        add_btn.setObjectName("toolButton")
        add_btn.clicked.connect(self.add_to_watchlist)
        
        remove_btn = QPushButton("➖ Remove Selected")
        remove_btn.setObjectName("toolButton")
        remove_btn.clicked.connect(self.remove_from_watchlist)
        
        self.watchlist_toggle = QPushButton("▶ Start Auto-Scan")
        self.watchlist_toggle.setObjectName("toolButton")
        self.watchlist_toggle.clicked.connect(self.toggle_watchlist_scanner)
        
        ctrl_layout.addWidget(self.watchlist_input, 2)
        ctrl_layout.addWidget(add_btn)
        ctrl_layout.addWidget(remove_btn)
        ctrl_layout.addWidget(self.watchlist_toggle)
        
        layout.addWidget(controls)
        
        # Watchlist table
        watchlist_card = QFrame()
        watchlist_card.setObjectName("card")
        watchlist_layout = QVBoxLayout(watchlist_card)
        
        title = QLabel("👁️ Monitored URLs")
        title.setObjectName("cardTitle")
        watchlist_layout.addWidget(title)
        
        self.watchlist_table = QTableWidget(0, 4)
        self.watchlist_table.setObjectName("historyTable")
        self.watchlist_table.setHorizontalHeaderLabels(['URL', 'Risk Score', 'Last Scan', 'Status'])
        self.watchlist_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        watchlist_layout.addWidget(self.watchlist_table)
        
        layout.addWidget(watchlist_card, 1)
        
        return tab
    
    def create_settings_tab(self):
        """Settings and model training"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Model section
        model_card = QFrame()
        model_card.setObjectName("card")
        model_layout = QVBoxLayout(model_card)
        
        title = QLabel("🤖 Machine Learning Model")
        title.setObjectName("cardTitle")
        model_layout.addWidget(title)
        
        btn_row = QHBoxLayout()
        
        load_btn = QPushButton("📁 Load Model")
        load_btn.setObjectName("toolButton")
        load_btn.clicked.connect(self.load_model)
        
        train_btn = QPushButton("🔬 Train Ensemble Model")
        train_btn.setObjectName("toolButton")
        train_btn.clicked.connect(self.train_ensemble_model)
        
        demo_btn = QPushButton("🎯 Quick Demo Model")
        demo_btn.setObjectName("toolButton")
        demo_btn.clicked.connect(self.create_demo_model)
        
        btn_row.addWidget(load_btn)
        btn_row.addWidget(train_btn)
        btn_row.addWidget(demo_btn)
        btn_row.addStretch()
        
        model_layout.addLayout(btn_row)
        layout.addWidget(model_card)
        
        # Configuration section
        config_card = QFrame()
        config_card.setObjectName("card")
        config_layout = QVBoxLayout(config_card)
        
        title = QLabel("⚙️ System Configuration")
        title.setObjectName("cardTitle")
        config_layout.addWidget(title)
        
        grid = QGridLayout()
        grid.setSpacing(10)
        
        # Feed update interval
        grid.addWidget(QLabel("Threat Feed Update (seconds):"), 0, 0)
        self.feed_interval = QSpinBox()
        self.feed_interval.setRange(60, 3600)
        self.feed_interval.setValue(THREAT_FEED_UPDATE_INTERVAL)
        self.feed_interval.setObjectName("configSpin")
        grid.addWidget(self.feed_interval, 0, 1)
        
        # Watchlist scan interval
        grid.addWidget(QLabel("Watchlist Scan Interval (seconds):"), 1, 0)
        self.watchlist_interval = QSpinBox()
        self.watchlist_interval.setRange(30, 600)
        self.watchlist_interval.setValue(WATCHLIST_SCAN_INTERVAL)
        self.watchlist_interval.setObjectName("configSpin")
        grid.addWidget(self.watchlist_interval, 1, 1)
        
        # Alert threshold
        grid.addWidget(QLabel("High Risk Alert Threshold:"), 2, 0)
        self.alert_threshold = QSpinBox()
        self.alert_threshold.setRange(50, 100)
        self.alert_threshold.setValue(80)
        self.alert_threshold.setObjectName("configSpin")
        grid.addWidget(self.alert_threshold, 2, 1)
        
        config_layout.addLayout(grid)
        
        # API Keys section
        api_group = QGroupBox("External API Integration")
        api_group.setObjectName("configGroup")
        api_layout = QGridLayout(api_group)
        
        api_layout.addWidget(QLabel("VirusTotal API Key:"), 0, 0)
        self.vt_key_input = QLineEdit()
        self.vt_key_input.setPlaceholderText("Enter VT API key...")
        self.vt_key_input.setEchoMode(QLineEdit.Password)
        api_layout.addWidget(self.vt_key_input, 0, 1)
        
        api_layout.addWidget(QLabel("Google Safe Browsing:"), 1, 0)
        self.gsb_key_input = QLineEdit()
        self.gsb_key_input.setPlaceholderText("Enter GSB API key...")
        self.gsb_key_input.setEchoMode(QLineEdit.Password)
        api_layout.addWidget(self.gsb_key_input, 1, 1)
        
        config_layout.addWidget(api_group)
        
        layout.addWidget(config_card)
        
        # IOC Database management
        ioc_card = QFrame()
        ioc_card.setObjectName("card")
        ioc_layout = QVBoxLayout(ioc_card)
        
        title = QLabel("🗃️ IOC Database Management")
        title.setObjectName("cardTitle")
        ioc_layout.addWidget(title)
        
        ioc_btn_row = QHBoxLayout()
        
        export_ioc_btn = QPushButton("💾 Export IOC Database")
        export_ioc_btn.setObjectName("toolButton")
        export_ioc_btn.clicked.connect(self.export_ioc_database)
        
        import_ioc_btn = QPushButton("📥 Import IOC Database")
        import_ioc_btn.setObjectName("toolButton")
        import_ioc_btn.clicked.connect(self.import_ioc_database)
        
        clear_ioc_btn = QPushButton("🗑️ Clear Database")
        clear_ioc_btn.setObjectName("toolButton")
        clear_ioc_btn.clicked.connect(self.clear_ioc_database)
        
        ioc_btn_row.addWidget(export_ioc_btn)
        ioc_btn_row.addWidget(import_ioc_btn)
        ioc_btn_row.addWidget(clear_ioc_btn)
        ioc_btn_row.addStretch()
        
        ioc_layout.addLayout(ioc_btn_row)
        
        # IOC stats
        ioc_stats = QLabel(f"Current IOC count: {len(self.ioc_db.iocs.get('malicious_urls', []))}")
        ioc_stats.setStyleSheet("color: #94a3b8; padding: 10px;")
        ioc_layout.addWidget(ioc_stats)
        
        layout.addWidget(ioc_card)
        layout.addStretch()
        
        return tab

    def create_stat_card(self, title: str, value: str, color: str):
        """Create statistics card"""
        card = QFrame()
        card.setObjectName("statCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(15, 15, 15, 15)
        
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
        
        value_lbl = QLabel(value)
        value_lbl.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: 700;")
        value_lbl.setObjectName("statValue")
        
        layout.addWidget(title_lbl)
        layout.addWidget(value_lbl)
        
        return card

    def create_status_bar(self):
        """Create bottom status bar"""
        status_frame = QFrame()
        status_frame.setObjectName("statusBar")
        layout = QHBoxLayout(status_frame)
        layout.setContentsMargins(10, 8, 10, 8)
        
        self.progress = QProgressBar()
        self.progress.setObjectName("progressBar")
        self.progress.setMaximum(100)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(6)
        
        self.status = QLabel('✓ System Ready')
        self.status.setObjectName("statusLabel")
        
        layout.addWidget(self.progress, 2)
        layout.addWidget(self.status, 1)
        
        return status_frame

    def create_menu(self):
        """Create application menu"""
        menubar = self.menuBar()
        menubar.setObjectName("menuBar")
        
        # File menu
        fileMenu = menubar.addMenu('&File')
        
        export_report = QAction('💾 Export Full Report', self)
        export_report.triggered.connect(self.export_full_report)
        fileMenu.addAction(export_report)
        
        export_session = QAction('📊 Export Session Data', self)
        export_session.triggered.connect(self.export_session_data)
        fileMenu.addAction(export_session)
        
        fileMenu.addSeparator()
        
        exit_action = QAction('❌ Exit', self)
        exit_action.triggered.connect(self.close)
        fileMenu.addAction(exit_action)
        
        # Tools menu
        toolsMenu = menubar.addMenu('&Tools')
        
        bulk_scan = QAction('📦 Bulk URL Scan', self)
        bulk_scan.triggered.connect(self.bulk_url_scan)
        toolsMenu.addAction(bulk_scan)
        
        # Help menu
        helpMenu = menubar.addMenu('&Help')
        
        about = QAction('ℹ️ About RTIS', self)
        about.triggered.connect(self.show_about)
        helpMenu.addAction(about)

    def start_monitoring_threads(self):
        """Initialize and start background monitoring threads"""
        # Threat feed monitor
        self.feed_monitor = ThreatFeedMonitor(self.ioc_db)
        self.feed_monitor.threat_update.connect(self.on_threat_detected)
        self.feed_monitor.status_update.connect(self.update_feed_status)
        
        # Watchlist scanner
        self.watchlist_scanner = WatchlistScanner(self.watchlist, self.model)
        self.watchlist_scanner.scan_complete.connect(self.on_watchlist_scan_complete)
        self.watchlist_scanner.status_update.connect(self.update_watchlist_status)
   # --------------------
    # Event Handlers
    # --------------------
    
    def toggle_feed_monitor(self):
        """Toggle threat feed monitoring"""
        if not hasattr(self, '_feed_running') or not self._feed_running:
            # Ensure thread is fresh if previously stopped
            if not self.feed_monitor.isRunning():
                self.feed_monitor = ThreatFeedMonitor(self.ioc_db)
                self.feed_monitor.threat_update.connect(self.on_threat_detected)
                self.feed_monitor.status_update.connect(self.update_feed_status)
            self.feed_monitor.running = True
            self.feed_monitor.start()
            self._feed_running = True
            self.feed_toggle.setText("⏸️ Pause Feed Monitor")
            self.feed_status.setText("🟢 Feed: Active")
            self.feed_status.setStyleSheet("color: #10b981;")
        else:
            self.feed_monitor.stop()
            self._feed_running = False
            self.feed_toggle.setText("▶ Start Feed Monitor")
            self.feed_status.setText("🔴 Feed: Stopped")
            self.feed_status.setStyleSheet("color: #ef4444;")
    
    def toggle_watchlist_scanner(self):
        """Toggle watchlist scanning"""
        if not hasattr(self, '_watchlist_running') or not self._watchlist_running:
            if not self.watchlist:
                QMessageBox.warning(self, "Empty Watchlist", "Please add URLs to the watchlist first.")
                return
            if not self.watchlist_scanner.isRunning():
                self.watchlist_scanner = WatchlistScanner(self.watchlist, self.model)
                self.watchlist_scanner.scan_complete.connect(self.on_watchlist_scan_complete)
                self.watchlist_scanner.status_update.connect(self.update_watchlist_status)
            self.watchlist_scanner.running = True
            self.watchlist_scanner.start()
            self._watchlist_running = True
            self.watchlist_toggle.setText("⏸️ Pause Auto-Scan")
            self.watchlist_status.setText("🟢 Watchlist: Scanning")
            self.watchlist_status.setStyleSheet("color: #10b981;")
        else:
            self.watchlist_scanner.stop()
            self._watchlist_running = False
            self.watchlist_toggle.setText("▶ Start Auto-Scan")
            self.watchlist_status.setText("⚪ Watchlist: Idle")
            self.watchlist_status.setStyleSheet("color: #94a3b8;")
    
    def on_threat_detected(self, threat: Dict):
        """Handle new threat detection"""
        # Add to threat feed list
        item = QListWidgetItem()
        severity_icon = "🔴" if threat['severity'] == 'High' else "🟡" if threat['severity'] == 'Medium' else "🟢"
        item.setText(f"{severity_icon} [{threat['source']}] {threat['url'][:60]}...")
        item.setData(Qt.UserRole, threat)
        
        # Color code by severity
        if threat['severity'] == 'High':
            item.setForeground(QtGui.QColor('#ef4444'))
        elif threat['severity'] == 'Medium':
            item.setForeground(QtGui.QColor('#f59e0b'))
        else:
            item.setForeground(QtGui.QColor('#10b981'))
        
        self.threat_feed_list.insertItem(0, item)
        
        # Update threat map
        self.threat_map.add_threat(threat)
        
        # High severity alert
        if threat['severity'] == 'High':
            self.show_alert(f"High severity threat detected: {threat['url'][:50]}...")
    
    def on_watchlist_scan_complete(self, result: Dict):
        """Handle watchlist scan completion"""
        # Update watchlist table
        for row in range(self.watchlist_table.rowCount()):
            url_item = self.watchlist_table.item(row, 0)
            if url_item and url_item.text() == result['url']:
                self.watchlist_table.setItem(row, 1, QTableWidgetItem(str(result['risk_score'])))
                try:
                    ts = datetime.fromisoformat(result['timestamp']).strftime('%H:%M:%S')
                except Exception:
                    ts = result['timestamp']
                self.watchlist_table.setItem(row, 2, QTableWidgetItem(ts))
                
                status_item = QTableWidgetItem(result['status'])
                if result['risk_score'] >= 80:
                    status_item.setForeground(QtGui.QColor('#ef4444'))
                self.watchlist_table.setItem(row, 3, status_item)
                break
    
    def perform_deep_scan(self):
        """Perform comprehensive URL analysis"""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, 'Input Required', 'Please enter a URL to scan.')
            return
        
        # Normalize URL
        if not re.match(r'^https?://', url):
            url = 'http://' + url
        
        self.progress.setValue(10)
        self.status.setText('🔍 Extracting features...')
        QApplication.processEvents()
        
        # Extract features
        features = AdvancedFeatureExtractor.extract_features(url)
        
        self.progress.setValue(30)
        self.status.setText('🤖 Running ML analysis...')
        QApplication.processEvents()
        
        # ML prediction
        ml_prob = 0.0
        if self.model:
            try:
                ml_prob = self.model.predict_proba([url])[0][1]
            except Exception:
                ml_prob = 0.5
        
        self.progress.setValue(50)
        self.status.setText('🎯 Checking IOC database...')
        QApplication.processEvents()
        
        # Check IOCs
        ioc_match, ioc_reasons = self.ioc_db.check_ioc(url)
        
        self.progress.setValue(70)
        self.status.setText('📊 Computing final score...')
        QApplication.processEvents()
        
        # Calculate final risk score
        heuristic_score = sum([
            features.get('has_ip', 0) * 20,
            features.get('has_at', 0) * 15,
            features.get('suspicious_tld', 0) * 10,
            features.get('suspicious_token_count', 0) * 8,
            (1 - features.get('has_https', 0)) * 10,
            min(features.get('entropy', 0) / 5, 10)
        ])
        
        final_score = int((ml_prob * 0.6 + (heuristic_score / 100) * 0.4) * 100)
        
        if ioc_match:
            final_score = max(final_score, 95)
        
        self.progress.setValue(90)
        
        # Generate report
        report = self.generate_deep_scan_report(url, features, ml_prob, final_score, ioc_reasons)
        self.report_area.setPlainText(report)
        
        # Update risk display
        if final_score >= 80:
            risk_text = f'🔴 CRITICAL THREAT: {final_score}/100'
            risk_color = '#ef4444'
        elif final_score >= 50:
            risk_text = f'🟡 SUSPICIOUS: {final_score}/100'
            risk_color = '#f59e0b'
        else:
            risk_text = f'🟢 SAFE: {final_score}/100'
            risk_color = '#10b981'
        
        self.risk_display.setText(risk_text)
        self.risk_display.setStyleSheet(f'color: {risk_color}; border-color: {risk_color};')
        
        # Visualize features
        self.visualize_features(features, ml_prob)
        
        # Show IOC matches
        self.ioc_list.clear()
        if ioc_reasons:
            for reason in ioc_reasons:
                item = QListWidgetItem(f"⚠️ {reason}")
                item.setForeground(QtGui.QColor('#ef4444'))
                self.ioc_list.addItem(item)
        else:
            item = QListWidgetItem("✓ No IOC matches found")
            item.setForeground(QtGui.QColor('#10b981'))
            self.ioc_list.addItem(item)
        
        # Save to session
        self.session_scans.append({
            'timestamp': datetime.utcnow().isoformat(),
            'url': url,
            'risk_score': final_score,
            'ml_probability': ml_prob,
            'features': features,
            'ioc_match': ioc_match
        })
        
        self.progress.setValue(100)
        self.status.setText('✓ Deep scan complete')
        QTimer.singleShot(2000, lambda: self.progress.setValue(0))
    
    def generate_deep_scan_report(self, url: str, features: Dict, ml_prob: float, 
                                   score: int, ioc_reasons: List[str]) -> str:
        """Generate comprehensive scan report"""
        lines = []
        lines.append('=' * 80)
        lines.append('PHISHGUARD PRO RTIS - DEEP THREAT ANALYSIS REPORT')
        lines.append('=' * 80)
        lines.append(f'Analysis Timestamp: {datetime.utcnow().isoformat()}Z')
        lines.append(f'Target URL: {url}')
        lines.append('')
        lines.append(f'FINAL RISK ASSESSMENT: {score}/100')
        lines.append('─' * 80)
        lines.append('')
        lines.append('MACHINE LEARNING ANALYSIS:')
        lines.append(f'  Phishing Probability: {ml_prob:.4f} ({ml_prob*100:.2f}%)')
        lines.append(f'  Model Confidence: {"High" if abs(ml_prob - 0.5) > 0.3 else "Medium"}')
        lines.append('')
        lines.append('EXTRACTED FEATURES:')
        for key, value in features.items():
            try:
                lines.append(f'  • {key.replace("_", " ").title()}: {value:.3f}')
            except Exception:
                lines.append(f'  • {key.replace("_", " ").title()}: {value}')
        lines.append('')
        lines.append('IOC DATABASE CHECK:')
        if ioc_reasons:
            lines.append('  ⚠️ MATCHES FOUND:')
            for reason in ioc_reasons:
                lines.append(f'    - {reason}')
        else:
            lines.append('  ✓ No matches in IOC database')
        lines.append('')
        lines.append('RISK CATEGORIZATION:')
        if score >= 80:
            lines.append('  🔴 CRITICAL - Immediate blocking recommended')
            lines.append('  Actions: Block at firewall, alert security team, add to blacklist')
        elif score >= 50:
            lines.append('  🟡 SUSPICIOUS - Enhanced monitoring required')
            lines.append('  Actions: Warn users, sandbox analysis, add to watchlist')
        else:
            lines.append('  🟢 LOW RISK - Standard security protocols apply')
            lines.append('  Actions: Allow with normal precautions')
        lines.append('')
        lines.append('RECOMMENDED MITIGATION:')
        if features.get('has_ip'):
            lines.append('  • URL uses IP address instead of domain - highly suspicious')
        if not features.get('has_https'):
            lines.append('  • No HTTPS encryption - data transmission not secure')
        if features.get('suspicious_token_count', 0) > 0:
            lines.append('  • Contains suspicious keywords commonly used in phishing')
        if features.get('entropy', 0) > 4.5:
            lines.append('  • High entropy detected - possible obfuscation technique')
        lines.append('=' * 80)
        
        return '\n'.join(lines)
    
    def visualize_features(self, features: Dict, ml_prob: float):
        """Visualize extracted features"""
        self.feature_canvas.fig.clear()
        
        # Create 2x2 subplot grid
        gs = self.feature_canvas.fig.add_gridspec(2, 2, hspace=0.3, wspace=0.3)
        
        # 1. Feature importance bar chart
        ax1 = self.feature_canvas.fig.add_subplot(gs[0, 0])
        ax1.set_facecolor('#0a0e12')
        
        feature_names = list(features.keys())[:8]
        feature_values = [features[k] for k in feature_names]
        
        colors = ['#ef4444' if v > 0.7 else '#f59e0b' if v > 0.3 else '#10b981' 
                  for v in feature_values]
        
        ax1.barh(feature_names, feature_values, color=colors, edgecolor='#1e293b', linewidth=1.5)
        ax1.set_xlabel('Value', color='#cbd5e1', fontsize=9)
        ax1.set_title('Top Features', color='#06b6d4', fontsize=11, fontweight='bold')
        ax1.tick_params(colors='#94a3b8', labelsize=8)
        ax1.spines['bottom'].set_color('#334155')
        ax1.spines['left'].set_color('#334155')
        ax1.spines['top'].set_visible(False)
        ax1.spines['right'].set_visible(False)
        ax1.grid(True, alpha=0.1, color='#475569', axis='x') 
        
        # 2. ML probability gauge
        ax2 = self.feature_canvas.fig.add_subplot(gs[0, 1])
        ax2.set_facecolor('#0a0e12')
        
        theta = np.linspace(0, np.pi, 100)
        r = np.ones_like(theta)
        
        ax2 = plt.subplot(gs[0, 1], projection='polar')
        ax2.set_facecolor('#0a0e12')
        ax2.plot(theta, r, color='#334155', linewidth=3)
        
        # Color zones
        safe_theta = np.linspace(0, np.pi * 0.5, 50)
        warn_theta = np.linspace(np.pi * 0.5, np.pi * 0.8, 50)
        danger_theta = np.linspace(np.pi * 0.8, np.pi, 50)
        
        ax2.fill_between(safe_theta, 0, 1, color='#10b981', alpha=0.3)
        ax2.fill_between(warn_theta, 0, 1, color='#f59e0b', alpha=0.3)
        ax2.fill_between(danger_theta, 0, 1, color='#ef4444', alpha=0.3)
        
        # Needle
        needle_angle = np.pi * (1 - ml_prob)
        ax2.plot([needle_angle, needle_angle], [0, 0.9], color='#06b6d4', linewidth=3)
        
        ax2.set_ylim(0, 1)
        ax2.set_theta_direction(-1)
        ax2.set_theta_offset(np.pi)
        ax2.set_xticks([])
        ax2.set_yticks([])
        ax2.set_title(f'ML Risk: {ml_prob:.2%}', color='#06b6d4', fontsize=11, 
                     fontweight='bold', pad=20)
        
        # 3. Feature correlation matrix
        ax3 = self.feature_canvas.fig.add_subplot(gs[1, 0])
        ax3.set_facecolor('#0a0e12')
        
        selected_features = list(features.keys())[:6]
        matrix_data = np.random.rand(6, 6) * 0.5 + 0.25  # Simulated correlation
        
        im = ax3.imshow(matrix_data, cmap='RdYlGn_r', aspect='auto', vmin=0, vmax=1)
        ax3.set_xticks(range(len(selected_features)))
        ax3.set_yticks(range(len(selected_features)))
        ax3.set_xticklabels([f[:10] for f in selected_features], rotation=45, ha='right', 
                           fontsize=7, color='#94a3b8')
        ax3.set_yticklabels([f[:10] for f in selected_features], fontsize=7, color='#94a3b8')
        ax3.set_title('Feature Correlation', color='#06b6d4', fontsize=11, fontweight='bold')
        
        # 4. Risk distribution pie (FIXED OVERLAP)
        ax4 = self.feature_canvas.fig.add_subplot(gs[1, 1])
        ax4.set_facecolor('#0a0e12')
        
        risk_categories = ['Critical', 'High', 'Medium', 'Low']
        risk_values = [15, 25, 35, 25]  # Simulated distribution
        risk_colors = ['#ef4444', '#f59e0b', '#fbbf24', '#10b981']
        
        wedges, texts, autotexts = ax4.pie(
            risk_values,
            labels=risk_categories,
            colors=risk_colors,
            autopct='%1.1f%%',
            pctdistance=0.85,
            labeldistance=1.3,
            startangle=90,
            textprops={'color': '#00ff00', 'fontsize': 8, 'weight': 'bold'},
            wedgeprops={'edgecolor': '#00ff41', 'linewidth': 2}
        )
        
        for autotext in autotexts:
            autotext.set_color('#00ff00')
            autotext.set_fontsize(8)
            autotext.set_weight('bold')
        
        for text in texts:
            text.set_color('#00ff00')
            text.set_fontsize(8)
            text.set_weight('bold')
        
        ax4.set_title('Threat Distribution', color='#06b6d4', fontsize=11, fontweight='bold')
        
        self.feature_canvas.fig.patch.set_facecolor('#0a0e12')
        self.feature_canvas.draw()
    
    def update_analytics(self):
        """Update threat analytics dashboard"""
        self.analytics_canvas.fig.clear()
        
        if len(self.session_scans) < 2:
            ax = self.analytics_canvas.fig.add_subplot(111)
            ax.text(0.5, 0.5, 'Collecting data...\nPerform more scans to see analytics', 
                   ha='center', va='center', color='#94a3b8', fontsize=13)
            ax.set_facecolor('#0a0e12')
            ax.axis('off')
            self.analytics_canvas.draw()
            return
        
        # Create comprehensive analytics dashboard
        gs = self.analytics_canvas.fig.add_gridspec(2, 3, hspace=0.3, wspace=0.3)
        
        # 1. Time series of risk scores
        ax1 = self.analytics_canvas.fig.add_subplot(gs[0, :2])
        ax1.set_facecolor('#0a0e12')
        
        timestamps = [datetime.fromisoformat(s['timestamp']) for s in self.session_scans[-50:]]
        scores = [s['risk_score'] for s in self.session_scans[-50:]]
        
        ax1.plot(timestamps, scores, color='#06b6d4', linewidth=2, marker='o', markersize=4)
        ax1.axhline(y=80, color='#ef4444', linestyle='--', linewidth=1.5, alpha=0.7, label='Critical')
        ax1.axhline(y=50, color='#f59e0b', linestyle='--', linewidth=1.5, alpha=0.7, label='Warning')
        
        ax1.set_xlabel('Time', color='#cbd5e1', fontsize=9)
        ax1.set_ylabel('Risk Score', color='#cbd5e1', fontsize=9)
        ax1.set_title('Risk Score Timeline', color='#06b6d4', fontsize=11, fontweight='bold')
        ax1.tick_params(colors='#94a3b8', labelsize=8)
        ax1.legend(facecolor='#0f172a', edgecolor='#334155', labelcolor='#cbd5e1', fontsize=8)
        ax1.grid(True, alpha=0.1, color='#475569')
        ax1.spines['bottom'].set_color('#334155')
        ax1.spines['left'].set_color('#334155')
        ax1.spines['top'].set_visible(False)
        ax1.spines['right'].set_visible(False)
        
        # 2. Risk distribution histogram
        ax2 = self.analytics_canvas.fig.add_subplot(gs[0, 2])
        ax2.set_facecolor('#0a0e12')
        
        n, bins, patches = ax2.hist(scores, bins=10, edgecolor='#1e293b', linewidth=1.5, 
                                     orientation='horizontal')
        
        for i, patch in enumerate(patches):
            bin_center = (bins[i] + bins[i+1]) / 2
            if bin_center >= 80:
                patch.set_facecolor('#ef4444')
            elif bin_center >= 50:
                patch.set_facecolor('#f59e0b')
            else:
                patch.set_facecolor('#10b981')
        
        ax2.set_ylabel('Risk Score', color='#cbd5e1', fontsize=9)
        ax2.set_xlabel('Count', color='#cbd5e1', fontsize=9)
        ax2.set_title('Distribution', color='#06b6d4', fontsize=11, fontweight='bold')
        ax2.tick_params(colors='#94a3b8', labelsize=8)
        ax2.grid(True, alpha=0.1, color='#475569', axis='x')
        ax2.spines['bottom'].set_color('#334155')
        ax2.spines['left'].set_color('#334155')
        ax2.spines['top'].set_visible(False)
        ax2.spines['right'].set_visible(False)
        
        # 3. ML probability distribution
        ax3 = self.analytics_canvas.fig.add_subplot(gs[1, 0])
        ax3.set_facecolor('#0a0e12')
        
        ml_probs = [s['ml_probability'] for s in self.session_scans if 'ml_probability' in s]
        if ml_probs:
            ax3.hist(ml_probs, bins=15, edgecolor='#1e293b', linewidth=1.5, alpha=0.8)
            ax3.axvline(np.mean(ml_probs), color='#06b6d4', linestyle='--', linewidth=2, 
                       label=f'Mean: {np.mean(ml_probs):.2f}')
            ax3.set_xlabel('ML Probability', color='#cbd5e1', fontsize=9)
            ax3.set_ylabel('Frequency', color='#cbd5e1', fontsize=9)
            ax3.set_title('ML Predictions', color='#06b6d4', fontsize=11, fontweight='bold')
            ax3.tick_params(colors='#94a3b8', labelsize=8)
            ax3.legend(facecolor='#0f172a', edgecolor='#334155', labelcolor='#cbd5e1', fontsize=8)
            ax3.grid(True, alpha=0.1, color='#475569')
            ax3.spines['bottom'].set_color('#334155')
            ax3.spines['left'].set_color('#334155')
            ax3.spines['top'].set_visible(False)
            ax3.spines['right'].set_visible(False)
        
        # 4. Detection rate pie chart (PROPERLY POSITIONED)
        ax4 = self.analytics_canvas.fig.add_subplot(gs[1, 1])
        ax4.set_facecolor('#0a0e12')
        
        high_count = sum(1 for s in self.session_scans if s['risk_score'] >= 80)
        medium_count = sum(1 for s in self.session_scans if 50 <= s['risk_score'] < 80)
        low_count = sum(1 for s in self.session_scans if s['risk_score'] < 50)
        
        sizes = [high_count, medium_count, low_count]
        colors = ['#ef4444', '#f59e0b', '#10b981']
        
        # Create pie WITHOUT labels to avoid overlapping
        wedges, autotexts = ax4.pie(
            sizes,
            colors=colors,
            autopct='%1.0f%%',
            startangle=90,
            textprops={'color': '#00ff00', 'fontsize': 10, 'weight': 'bold'},
            wedgeprops={'edgecolor': '#00ff41', 'linewidth': 2.5}
        )
        
        # Format percentages
        for autotext in autotexts:
            autotext.set_color('#00ff00')
            autotext.set_fontsize(10)
            autotext.set_weight('bold')
        
        # Add clean legend below the pie
        legend_labels = [
            f'🔴 Critical: {high_count}',
            f'🟡 Suspicious: {medium_count}',
            f'🟢 Safe: {low_count}'
        ]
        ax4.legend(legend_labels, loc='upper center', bbox_to_anchor=(0.5, -0.1),
                   ncol=3, frameon=True, fancybox=False, 
                   facecolor='#0f1419', edgecolor='#00ff41', labelcolor='#00ff00',
                   fontsize=8)
        
        ax4.set_title('Threat Categories', color='#06b6d4', fontsize=11, fontweight='bold')
        
        # 5. Feature importance heatmap
        ax5 = self.analytics_canvas.fig.add_subplot(gs[1, 2])
        ax5.set_facecolor('#0a0e12')
        
        if self.session_scans and 'features' in self.session_scans[-1]:
            recent_features = self.session_scans[-1]['features']
            feature_names = list(recent_features.keys())[:6]
            feature_matrix = np.array([[recent_features[k] for k in feature_names]])
            
            im = ax5.imshow(feature_matrix.T, cmap='RdYlGn_r', aspect='auto', vmin=0, vmax=1)
            ax5.set_yticks(range(len(feature_names)))
            ax5.set_yticklabels([f[:12] for f in feature_names], fontsize=7, color='#94a3b8')
            ax5.set_xticks([])
            ax5.set_title('Recent Features', color='#06b6d4', fontsize=11, fontweight='bold')
        
        self.analytics_canvas.fig.patch.set_facecolor('#0a0e12')
        self.analytics_canvas.fig.tight_layout(pad=2.0)
        self.analytics_canvas.draw()
        
        # Update stats cards
        total = len(self.session_scans)
        high = sum(1 for s in self.session_scans if s['risk_score'] >= 80)
        
        self.stats_total.findChild(QLabel, "statValue").setText(str(total))
        self.stats_high.findChild(QLabel, "statValue").setText(str(high))
        self.stats_blocked.findChild(QLabel, "statValue").setText(str(high))
        self.stats_sources.findChild(QLabel, "statValue").setText("3")
    
    def add_to_watchlist(self):
        """Add URL to watchlist"""
        url = self.watchlist_input.text().strip()
        if not url:
            return
        
        if not re.match(r'^https?://', url):
            url = 'http://' + url
        
        if url in self.watchlist:
            QMessageBox.information(self, 'Duplicate', 'URL already in watchlist.')
            return
        
        self.watchlist.append(url)
        
        # Add to table
        row = self.watchlist_table.rowCount()
        self.watchlist_table.insertRow(row)
        self.watchlist_table.setItem(row, 0, QTableWidgetItem(url))
        self.watchlist_table.setItem(row, 1, QTableWidgetItem('-'))
        self.watchlist_table.setItem(row, 2, QTableWidgetItem('-'))
        self.watchlist_table.setItem(row, 3, QTableWidgetItem('Pending'))
        
        self.watchlist_input.clear()
        self.watchlist_scanner.update_watchlist(self.watchlist)
    
    def remove_from_watchlist(self):
        """Remove selected URL from watchlist"""
        current_row = self.watchlist_table.currentRow()
        if current_row >= 0:
            url = self.watchlist_table.item(current_row, 0).text()
            try:
                self.watchlist.remove(url)
            except ValueError:
                pass
            self.watchlist_table.removeRow(current_row)
            self.watchlist_scanner.update_watchlist(self.watchlist)
    
    def clear_alerts(self):
        """Clear threat feed alerts"""
        reply = QMessageBox.question(self, 'Confirm', 'Clear all threat alerts?',
                                    QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.threat_feed_list.clear()
    
    def load_model(self):
        """Load pre-trained model"""
        path, _ = QFileDialog.getOpenFileName(self, 'Load Model', '', 'Joblib Files (*.joblib)')
        if not path:
            return
        
        try:
            self.model = joblib.load(path)
            self.model_status.setText(f'🟢 Model: {os.path.basename(path)}')
            self.model_status.setStyleSheet('color: #10b981;')
            self.watchlist_scanner.model = self.model
            QMessageBox.information(self, 'Success', 'Model loaded successfully!')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to load model: {e}')
    
    def train_ensemble_model(self):
        """Train advanced ensemble model"""
        phish, _ = QFileDialog.getOpenFileName(self, 'Select phishing CSV', '', 'CSV Files (*.csv)')
        if not phish:
            return
        legit, _ = QFileDialog.getOpenFileName(self, 'Select legitimate CSV', '', 'CSV Files (*.csv)')
        if not legit:
            return
        
        self.status.setText('🔬 Training ensemble model...')
        self.progress.setValue(10)
        QApplication.processEvents()
        
        try:
            # Load data
            df_phish = pd.read_csv(phish, header=None, names=['url'])
            df_phish['label'] = 1
            df_legit = pd.read_csv(legit, header=None, names=['url'])
            df_legit['label'] = 0
            
            df = pd.concat([df_phish, df_legit]).dropna().sample(frac=1, random_state=42)
            X = df['url'].astype(str)
            y = df['label'].astype(int)
            
            self.progress.setValue(30)
            QApplication.processEvents()
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.15, random_state=42, stratify=y
            )
            
            self.progress.setValue(50)
            self.status.setText('🔬 Training classifiers...')
            QApplication.processEvents()
            
            # Build and train ensemble
            pipe = build_ensemble_pipeline()
            pipe.fit(X_train, y_train)
            
            self.progress.setValue(80)
            self.status.setText('📊 Evaluating model...')
            QApplication.processEvents()
            
            # Evaluate
            y_pred = pipe.predict(X_test)
            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred)
            rec = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            # Save model
            joblib.dump(pipe, MODEL_PATH)
            self.model = pipe
            self.watchlist_scanner.model = self.model
            
            self.progress.setValue(100)
            self.status.setText('✓ Training complete')
            self.model_status.setText(f'🟢 Model: Ensemble ({acc:.2%})')
            self.model_status.setStyleSheet('color: #10b981;')
            
            QMessageBox.information(self, 'Training Complete', 
                f'Ensemble model trained successfully!\n\n'
                f'Accuracy: {acc:.3f}\n'
                f'Precision: {prec:.3f}\n'
                f'Recall: {rec:.3f}\n'
                f'F1-Score: {f1:.3f}')
            
        except Exception as e:
            QMessageBox.warning(self, 'Training Error', f'Failed to train model: {e}')
        finally:
            self.progress.setValue(0)
    
    def create_demo_model(self):
        """Create quick demo model"""
        self.status.setText('🎯 Creating demo model...')
        self.progress.setValue(30)
        QApplication.processEvents()
        
        # Generate synthetic data
        phish_urls = [f"http://secure-login-{i}.suspicious-{i%100}.com/verify.php" 
                     for i in range(500)]
        legit_urls = [f"https://www.legitimate-site-{i}.com/" for i in range(500)]
        
        X = phish_urls + legit_urls
        y = [1] * 500 + [0] * 500
        
        self.progress.setValue(60)
        QApplication.processEvents()
        
        # Train simple model
        pipe = build_ensemble_pipeline()
        pipe.fit(X, y)
        
        self.model = pipe
        self.watchlist_scanner.model = self.model
        
        self.progress.setValue(100)
        self.status.setText('✓ Demo model ready')
        self.model_status.setText('🟡 Model: Demo Mode')
        self.model_status.setStyleSheet('color: #f59e0b;')
        
        QMessageBox.information(self, 'Demo Ready', 
            'Demo model created and loaded!\n'
            'This is for demonstration purposes only.')
        
        QTimer.singleShot(2000, lambda: self.progress.setValue(0))
    
    def export_ioc_database(self):
        """Export IOC database"""
        path, _ = QFileDialog.getSaveFileName(self, 'Export IOC Database', 
                                             'ioc_export.json', 'JSON Files (*.json)')
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(self.ioc_db.iocs, f, indent=2)
                QMessageBox.information(self, 'Exported', f'IOC database exported to:\n{path}')
            except Exception as e:
                QMessageBox.warning(self, 'Error', f'Export failed: {e}')
    
    def import_ioc_database(self):
        """Import IOC database"""
        path, _ = QFileDialog.getOpenFileName(self, 'Import IOC Database', 
                                             '', 'JSON Files (*.json)')
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    imported = json.load(f)
                self.ioc_db.iocs.update(imported)
                self.ioc_db.save()
                QMessageBox.information(self, 'Imported', 'IOC database imported successfully!')
            except Exception as e:
                QMessageBox.warning(self, 'Error', f'Import failed: {e}')
    
    def clear_ioc_database(self):
        """Clear IOC database"""
        reply = QMessageBox.question(self, 'Confirm', 
            'Clear entire IOC database? This cannot be undone.',
            QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.ioc_db.iocs = {
                'malicious_urls': [],
                'malicious_domains': [],
                'malicious_ips': [],
                'suspicious_patterns': []
            }
            self.ioc_db.save()
            QMessageBox.information(self, 'Cleared', 'IOC database cleared.')

    def export_full_report(self):
        """Export comprehensive system report"""
        path, _ = QFileDialog.getSaveFileName(self, 'Export Report', 
                                             'rtis_report.html', 'HTML Files (*.html)')
        if not path:
            return
        
        try:
            html = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>PhishGuard Pro RTIS - Full Report</title>
                <style>
                    body {{
                        background: linear-gradient(135deg, #0a0e12 0%, #1e293b 100%);
                        color: #e4e9f0;
                        font-family: 'Segoe UI', Arial, sans-serif;
                        padding: 40px;
                        margin: 0;
                    }}
                    .container {{
                        max-width: 1200px;
                        margin: 0 auto;
                        background: rgba(15, 23, 42, 0.9);
                        padding: 40px;
                        border-radius: 16px;
                        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                    }}
                    h1 {{
                        color: #06b6d4;
                        font-size: 36px;
                        margin-bottom: 10px;
                        text-shadow: 0 0 20px rgba(6, 182, 212, 0.5);
                    }}
                    .stats {{
                        display: grid;
                        grid-template-columns: repeat(4, 1fr);
                        gap: 20px;
                        margin: 30px 0;
                    }}
                    .stat-card {{
                        background: rgba(10, 14, 18, 0.8);
                        padding: 20px;
                        border-radius: 12px;
                        border: 1px solid rgba(6, 182, 212, 0.3);
                    }}
                    .stat-value {{
                        font-size: 32px;
                        font-weight: 700;
                        color: #06b6d4;
                    }}
                    .stat-label {{
                        color: #94a3b8;
                        font-size: 14px;
                        margin-top: 5px;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin: 20px 0;
                    }}
                    th, td {{
                        padding: 12px;
                        text-align: left;
                        border-bottom: 1px solid rgba(71, 85, 105, 0.3);
                    }}
                    th {{
                        background: rgba(6, 182, 212, 0.2);
                        color: #06b6d4;
                        font-weight: 600;
                    }}
                    .critical {{ color: #ef4444; }}
                    .warning {{ color: #f59e0b; }}
                    .safe {{ color: #10b981; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🛡️ PhishGuard Pro RTIS - System Report</h1>
                    <p style="color: #94a3b8;">Generated: {datetime.utcnow().isoformat()}Z</p>
                    
                    <div class="stats">
                        <div class="stat-card">
                            <div class="stat-value">{len(self.session_scans)}</div>
                            <div class="stat-label">Total Scans</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value critical">
                                {sum(1 for s in self.session_scans if s['risk_score'] >= 80)}
                            </div>
                            <div class="stat-label">Critical Threats</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value warning">
                                {sum(1 for s in self.session_scans if 50 <= s['risk_score'] < 80)}
                            </div>
                            <div class="stat-label">Suspicious</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value safe">
                                {len(self.ioc_db.iocs.get('malicious_urls', []))}
                            </div>
                            <div class="stat-label">IOC Entries</div>
                        </div>
                    </div>
                    
                    <h2 style="color: #06b6d4; margin-top: 40px;">Recent Scans</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>URL</th>
                                <th>Risk Score</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
            '''
            
            for scan in self.session_scans[-50:]:
                risk_class = 'critical' if scan['risk_score'] >= 80 else 'warning' if scan['risk_score'] >= 50 else 'safe'
                status = 'CRITICAL' if scan['risk_score'] >= 80 else 'SUSPICIOUS' if scan['risk_score'] >= 50 else 'SAFE'
                html += f'''
                            <tr>
                                <td>{scan['timestamp']}</td>
                                <td>{scan['url'][:80]}...</td>
                                <td class="{risk_class}">{scan['risk_score']}/100</td>
                                <td class="{risk_class}">{status}</td>
                            </tr>
                '''
            
            html += '''
                        </tbody>
                    </table>
                </div>
            </body>
            </html>
            '''
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(html)
            
            QMessageBox.information(self, 'Exported', f'Full report saved to:\n{path}')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Export failed: {e}')
    
    def export_session_data(self):
        """Export session data as CSV"""
        if not self.session_scans:
            QMessageBox.information(self, 'No Data', 'No session data to export.')
            return
        
        path, _ = QFileDialog.getSaveFileName(self, 'Export Session', 
                                             'rtis_session.csv', 'CSV Files (*.csv)')
        if path:
            try:
                df = pd.DataFrame(self.session_scans)
                df.to_csv(path, index=False)
                QMessageBox.information(self, 'Exported', f'Session data exported to:\n{path}')
            except Exception as e:
                QMessageBox.warning(self, 'Error', f'Export failed: {e}')
    
    def bulk_url_scan(self):
        """Bulk scan URLs from file"""
        path, _ = QFileDialog.getOpenFileName(self, 'Select URL List', 
                                             '', 'Text Files (*.txt);;CSV Files (*.csv)')
        if not path:
            return
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not urls:
                QMessageBox.warning(self, 'Empty File', 'No URLs found in file.')
                return
            
            reply = QMessageBox.question(self, 'Confirm Bulk Scan', 
                f'Scan {len(urls)} URLs? This may take some time.',
                QMessageBox.Yes | QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                self.perform_bulk_scan(urls)
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to read file: {e}')
    
    def perform_bulk_scan(self, urls: List[str]):
        """Perform bulk scanning"""
        results = []
        total = len(urls)
        
        for i, url in enumerate(urls):
            self.progress.setValue(int((i / total) * 100))
            self.status.setText(f'🔍 Scanning {i+1}/{total}...')
            QApplication.processEvents()
            
            if self.model:
                try:
                    prob = self.model.predict_proba([url])[0][1]
                    score = int(prob * 100)
                except Exception:
                    score = 50
            else:
                score = 50
            
            results.append({
                'url': url,
                'risk_score': score,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        self.progress.setValue(100)
        self.status.setText(f'✓ Bulk scan complete: {total} URLs')
        
        # Save results
        path, _ = QFileDialog.getSaveFileName(self, 'Save Bulk Scan Results', 
                                             'bulk_scan_results.csv', 'CSV Files (*.csv)')
        if path:
            df = pd.DataFrame(results)
            df.to_csv(path, index=False)
            QMessageBox.information(self, 'Complete', 
                f'Bulk scan complete!\nResults saved to:\n{path}')
        
        QTimer.singleShot(2000, lambda: self.progress.setValue(0))
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, 'About PhishGuard Pro RTIS',
            '<h2>PhishGuard Pro RTIS</h2>'
            '<p><b>Real-Time Threat Intelligence System</b></p>'
            '<p>Version 2.0</p>'
            '<p>Enterprise-grade phishing detection and threat intelligence platform.</p>'
            '<br>'
            '<p><b>Features:</b></p>'
            '<ul>'
            '<li>Real-time threat feed monitoring</li>'
            '<li>Automated URL watchlist scanning</li>'
            '<li>Advanced ML ensemble models</li>'
            '<li>IOC database integration</li>'
            '<li>Comprehensive threat analytics</li>'
            '<li>Live threat visualization</li>'
            '</ul>')
    
    def update_feed_status(self, status: str):
        """Update feed status message"""
        self.status.setText(status)
    
    def update_watchlist_status(self, status: str):
        """Update watchlist status message"""
        # Optionally reflect in UI
        self.status.setText(status)
    
    def show_alert(self, message: str):
        """Show system alert"""
        # Could implement popup notifications, sound alerts, etc.
        QMessageBox.warning(self, "Alert", message)
    
    def apply_rtis_theme(self):
        """Apply premium hacking tool dark theme"""
        style = """
        QMainWindow, QWidget {
            background-color: #0d0f12;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        
        #mainTitle {
            color: #00ff41;
            font-size: 24px;
            font-weight: bold;
            padding: 10px;
        }
        
        #cardTitle {
            color: #00ff00;
            font-size: 14px;
            font-weight: bold;
            padding: 5px 0;
        }
        
        #header {
            background-color: #0a0d10;
            border-bottom: 3px solid #00ff41;
            padding: 8px;
        }
        
        #statusIndicator {
            color: #00ff00;
            font-weight: bold;
            padding: 8px 12px;
            margin-right: 20px;
            font-size: 11px;
        }
        
        #card {
            background-color: #0f1419;
            border: 2px solid #00ff41;
            border-radius: 4px;
            padding: 12px;
        }
        
        #card:hover {
            background-color: #131820;
            border: 2px solid #00ff66;
        }
        
        #statCard {
            background-color: #0f1419;
            border: 2px solid #00ff41;
            border-radius: 6px;
            padding: 15px;
        }
        
        #statCard:hover {
            border: 2px solid #00ff66;
        }
        
        #statValue {
            color: #00ff41;
            font-weight: bold;
        }
        
        #toolbar {
            background-color: #0a0d10;
            border: 1px solid #1a2332;
            padding: 8px;
            border-radius: 3px;
        }
        
        QPushButton {
            background-color: #1a2332;
            color: #00ff00;
            border: 1px solid #00ff41;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
            font-family: 'Courier New', monospace;
        }
        
        QPushButton:hover {
            background-color: #0f1419;
            color: #00ff66;
            border: 1px solid #00ff66;
        }
        
        QPushButton:pressed {
            background-color: #0a0d10;
            border: 1px solid #00ff00;
        }
        
        #toolButton {
            padding: 6px 12px;
            font-size: 11px;
            min-width: 80px;
        }
        
        #scanButton {
            background-color: #1a2332;
            color: #00ff00;
            border: 2px solid #ff0000;
            font-size: 12px;
            font-weight: bold;
            padding: 10px 20px;
            border-radius: 4px;
        }
        
        #scanButton:hover {
            background-color: #2a1a1a;
            color: #ff3333;
            border: 2px solid #ff3333;
        }
        
        QLineEdit, QTextEdit {
            background-color: #0f1419;
            color: #00ff00;
            border: 1px solid #00ff41;
            border-radius: 3px;
            padding: 6px;
            font-family: 'Courier New', monospace;
            selection-background-color: #00ff41;
            selection-color: #0a0d10;
        }
        
        QLineEdit:focus, QTextEdit:focus {
            border: 2px solid #00ff66;
        }
        
        #urlInput {
            font-size: 12px;
            padding: 8px;
        }
        
        #riskDisplay {
            color: #00ff00;
            font-weight: bold;
            font-size: 14px;
            padding: 10px;
            border: 2px solid #00ff41;
            border-radius: 4px;
        }
        
        QTabWidget::pane {
            border: 1px solid #00ff41;
            background-color: #0a0d10;
        }
        
        QTabBar::tab {
            background-color: #0f1419;
            color: #00ff00;
            border: 1px solid #00ff41;
            padding: 8px 16px;
            margin-right: 2px;
            font-weight: bold;
        }
        
        QTabBar::tab:selected {
            background-color: #1a2332;
            color: #00ff66;
            border: 2px solid #00ff66;
        }
        
        QTabBar::tab:hover:!selected {
            background-color: #131820;
            border: 1px solid #00ff41;
        }
        
        QListWidget, QTableWidget {
            background-color: #0a0d10;
            color: #00ff00;
            border: 1px solid #00ff41;
            border-radius: 3px;
            gridline-color: #1a2332;
        }
        
        QListWidget::item {
            padding: 4px;
            border-radius: 2px;
        }
        
        QListWidget::item:hover {
            background-color: #1a2332;
        }
        
        QListWidget::item:selected {
            background-color: #1a3a2a;
            border: 1px solid #00ff41;
        }
        
        #threatList QListWidget::item {
            padding: 6px;
        }
        
        QTableWidget {
            background-color: #0a0d10;
            alternate-background-color: #0f1419;
        }
        
        QTableWidget::item {
            padding: 6px;
            border-bottom: 1px solid #1a2332;
        }
        
        QTableWidget::item:selected {
            background-color: #1a3a2a;
            border: 1px solid #00ff41;
        }
        
        QHeaderView::section {
            background-color: #0f1419;
            color: #00ff41;
            padding: 6px;
            border: 1px solid #00ff41;
            font-weight: bold;
        }
        
        QScrollBar:vertical {
            background-color: #0a0d10;
            width: 12px;
            border: 1px solid #1a2332;
        }
        
        QScrollBar::handle:vertical {
            background-color: #00ff41;
            border-radius: 6px;
            min-height: 20px;
        }
        
        QScrollBar::handle:vertical:hover {
            background-color: #00ff66;
        }
        
        QScrollBar:horizontal {
            background-color: #0a0d10;
            height: 12px;
            border: 1px solid #1a2332;
        }
        
        QScrollBar::handle:horizontal {
            background-color: #00ff41;
            border-radius: 6px;
            min-width: 20px;
        }
        
        QScrollBar::handle:horizontal:hover {
            background-color: #00ff66;
        }
        
        #progressBar {
            background-color: #0a0d10;
            border: 1px solid #00ff41;
            border-radius: 3px;
            height: 8px;
        }
        
        #progressBar::chunk {
            background-color: #00ff41;
            border-radius: 3px;
        }
        
        #statusBar {
            background-color: #0a0d10;
            border-top: 2px solid #00ff41;
            padding: 6px;
        }
        
        #statusLabel {
            color: #00ff00;
            font-weight: bold;
            padding: 4px 8px;
        }
        
        #menuBar {
            background-color: #0a0d10;
            color: #00ff00;
            border-bottom: 1px solid #00ff41;
        }
        
        QMenuBar::item:selected {
            background-color: #1a2332;
            color: #00ff66;
        }
        
        QMenu {
            background-color: #0f1419;
            color: #00ff00;
            border: 1px solid #00ff41;
        }
        
        QMenu::item:selected {
            background-color: #1a3a2a;
            color: #00ff66;
        }
        
        QSpinBox, QComboBox {
            background-color: #0f1419;
            color: #00ff00;
            border: 1px solid #00ff41;
            border-radius: 3px;
            padding: 4px;
        }
        
        QSpinBox:focus, QComboBox:focus {
            border: 2px solid #00ff66;
        }
        
        #configSpin {
            font-size: 11px;
        }
        
        QGroupBox {
            color: #00ff00;
            border: 1px solid #00ff41;
            border-radius: 4px;
            padding: 10px;
            padding-top: 15px;
            font-weight: bold;
        }
        
        #configGroup {
            background-color: #0f1419;
        }
        
        QLabel {
            color: #00ff00;
        }
        
        QSplitter::handle {
            background-color: #00ff41;
            width: 2px;
            height: 2px;
        }
        
        QSplitter::handle:hover {
            background-color: #00ff66;
        }
        """
        self.setStyleSheet(style)
    
    def closeEvent(self, event):
        """Clean shutdown of threads"""
        if hasattr(self, 'feed_monitor'):
            try:
                self.feed_monitor.stop()
            except Exception:
                pass
        if hasattr(self, 'watchlist_scanner'):
            try:
                self.watchlist_scanner.stop()
            except Exception:
                pass
        
        # Wait for threads to finish
        if hasattr(self, 'feed_monitor'):
            try:
                self.feed_monitor.wait(1000)
            except Exception:
                pass
        if hasattr(self, 'watchlist_scanner'):
            try:
                self.watchlist_scanner.wait(1000)
            except Exception:
                pass
        
        event.accept()

# --------------------
# Main Entry Point
# --------------------
def main():
    app = QApplication(sys.argv)
    app.setAttribute(Qt.AA_EnableHighDpiScaling)
    
    # Set application font
    font = QtGui.QFont("Segoe UI", 10)
    app.setFont(font)
    
    # Set application metadata
    app.setApplicationName(APP_TITLE)
    app.setOrganizationName("PhishGuard Security")
    
    window = RTISMainWindow()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()


