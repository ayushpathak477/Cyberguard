from flask import Flask, render_template, request, jsonify, redirect, url_for
import torch
import torch.nn as nn
import numpy as np
import re
import math
import hashlib
import requests
import threading
import time
import socket
import ssl
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
import json
import sqlite3
from collections import Counter
import subprocess
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
from urllib.request import urlopen
import urllib.error

# TensorFlow/Keras imports for password enhancement model
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras.models import load_model
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    TENSORFLOW_AVAILABLE = True
    print("✅ TensorFlow loaded successfully")
except ImportError as e:
    print(f"⚠️ TensorFlow not available: {e}")
    print("Install with: pip install tensorflow")
    TENSORFLOW_AVAILABLE = False


# Your existing PasswordRNN class
class PasswordRNN(nn.Module):
    def __init__(self, vocab_size, hidden_size, num_layers):
        super(PasswordRNN, self).__init__()
        self.embedding = nn.Embedding(vocab_size, hidden_size)
        self.rnn = nn.LSTM(hidden_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, vocab_size)

    def forward(self, x, hidden=None):
        x = self.embedding(x)
        out, hidden = self.rnn(x, hidden)
        out = self.fc(out)
        return out, hidden


class PasswordEnhancer:
    def __init__(self, model_path="password_strength_model.h5"):
        """Initialize the password enhancer with the trained LSTM model"""
        self.model = None
        self.model_path = model_path
        self.char_to_int = {}
        self.int_to_char = {}
        self.max_length = 50  # Adjust based on your model's training
        self.is_loaded = False
        
        # Common character mappings for password enhancement
        self.enhancement_map = {
            'a': ['@', '4', 'A'],
            'e': ['3', 'E'],
            'i': ['1', '!', 'I'],
            'o': ['0', 'O'],
            's': ['$', '5', 'S'],
            't': ['7', 'T'],
            'l': ['1', 'L'],
            'g': ['9', 'G'],
            'b': ['6', 'B'],
            'z': ['2', 'Z']
        }
        
        self.special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', '|', '\\', ':', ';', '"', "'", '<', '>', ',', '.', '?', '/']
        self.numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        
        self.load_model()
    
    def load_model(self):
        """Load the pre-trained LSTM model"""
        if not TENSORFLOW_AVAILABLE:
            print("⚠️ TensorFlow not available. Password enhancement will use fallback method.")
            return False
            
        try:
            if os.path.exists(self.model_path):
                # Define custom objects for model loading
                custom_objects = {
                    'NotEqual': tf.keras.utils.get_custom_objects().get('NotEqual', lambda x, y: tf.not_equal(x, y))
                }
                
                # Try loading with custom objects
                try:
                    self.model = load_model(self.model_path, custom_objects=custom_objects)
                except Exception as custom_error:
                    print(f"⚠️ Error loading model with custom objects: {custom_error}")
                    # Try loading without custom objects (this might work for simpler models)
                    try:
                        self.model = load_model(self.model_path, compile=False)
                        print("✅ Model loaded without compilation (some features may be limited)")
                    except Exception as fallback_error:
                        print(f"⚠️ Complete model loading failed: {fallback_error}")
                        return False
                
                print(f"✅ Password enhancement model loaded from {self.model_path}")
                self.is_loaded = True
                self._setup_char_mappings()
                return True
            else:
                print(f"⚠️ Model file {self.model_path} not found. Using fallback enhancement method.")
                return False
        except Exception as e:
            print(f"⚠️ Error loading model: {e}. Using fallback enhancement method.")
            return False
    
    def _setup_char_mappings(self):
        """Setup character to integer mappings"""
        # Create a comprehensive character set
        chars = set()
        
        # Add alphabets (both cases)
        for i in range(26):
            chars.add(chr(ord('a') + i))
            chars.add(chr(ord('A') + i))
        
        # Add numbers
        chars.update(self.numbers)
        
        # Add special characters
        chars.update(self.special_chars)
        
        # Add space and common punctuation
        chars.update([' ', '.', ',', '!', '?'])
        
        # Create mappings
        chars = sorted(list(chars))
        self.char_to_int = {char: i for i, char in enumerate(chars)}
        self.int_to_char = {i: char for i, char in enumerate(chars)}
    
    def enhance_password_with_model(self, password):
        """Enhance password using the trained LSTM model"""
        if not self.is_loaded or self.model is None:
            return self.enhance_password_fallback(password)
        
        try:
            # Convert password to sequence
            sequence = []
            for char in password:
                if char in self.char_to_int:
                    sequence.append(self.char_to_int[char])
                else:
                    # Handle unknown characters
                    sequence.append(0)  # Use 0 for unknown chars
            
            # Pad sequence
            padded_sequence = pad_sequences([sequence], maxlen=self.max_length, padding='post')
            
            # Predict enhanced version
            prediction = self.model.predict(padded_sequence, verbose=0)
            
            # Convert prediction back to characters
            enhanced_password = ""
            for pred_vector in prediction[0]:
                predicted_int = np.argmax(pred_vector)
                if predicted_int in self.int_to_char:
                    enhanced_password += self.int_to_char[predicted_int]
            
            # Clean up and ensure minimum requirements
            enhanced_password = enhanced_password.strip()
            if len(enhanced_password) < len(password):
                enhanced_password = self.enhance_password_fallback(password)
            
            return self._ensure_complexity(enhanced_password)
            
        except Exception as e:
            print(f"Error during model prediction: {e}")
            return self.enhance_password_fallback(password)
    
    def enhance_password_fallback(self, password):
        """Fallback method to enhance password without ML model"""
        if not password:
            return "SecureP@ssw0rd123!"
        
        enhanced = ""
        original_chars = list(password.lower())
        
        # First pass: enhance existing characters
        for i, char in enumerate(original_chars):
            if char in self.enhancement_map and np.random.random() < 0.6:
                # 60% chance to enhance character
                enhanced += np.random.choice(self.enhancement_map[char])
            elif char.isalpha() and np.random.random() < 0.3:
                # 30% chance to uppercase
                enhanced += char.upper()
            else:
                enhanced += char
            
            # Add random special chars and numbers between characters
            if np.random.random() < 0.4:  # 40% chance
                enhanced += np.random.choice(self.special_chars + self.numbers)
        
        # Second pass: ensure minimum length and complexity
        enhanced = self._ensure_complexity(enhanced)
        
        # Third pass: extend to reasonable length (12-16 characters minimum)
        target_length = max(12, len(password) * 2)
        while len(enhanced) < target_length:
            # Add more complexity
            if np.random.random() < 0.5:
                enhanced += np.random.choice(self.special_chars)
            else:
                enhanced += str(np.random.randint(0, 9))
        
        return enhanced[:20]  # Cap at 20 characters to avoid overly long passwords
    
    def _ensure_complexity(self, password):
        """Ensure the password meets complexity requirements"""
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in self.special_chars for c in password)
        
        # Add missing character types
        if not has_upper and password:
            # Convert first character to uppercase if it's a letter
            if password[0].isalpha():
                password = password[0].upper() + password[1:]
            else:
                password += 'A'
        
        if not has_digit:
            password += str(np.random.randint(0, 9))
        
        if not has_special:
            password += np.random.choice(self.special_chars)
        
        if not has_lower:
            password += 'x'
        
        return password
    
    def enhance_password(self, password):
        """Main method to enhance a password"""
        if self.is_loaded:
            return self.enhance_password_with_model(password)
        else:
            return self.enhance_password_fallback(password)


class ThreatIntelligence:
    def __init__(self):
        self.malicious_domains = set()
        self.phishing_patterns = []
        self.malware_urls = set()
        self.safe_domains = set()
        self.threat_categories = {
            'phishing': set(),
            'malware': set(),
            'scam': set(),
            'adult': set(),
            'gambling': set(),
            'social_engineering': set()
        }
        self.load_threat_feeds()

    def load_threat_feeds(self):
        """Load threat intelligence from various sources"""
        # Load from local databases or APIs
        self.malicious_domains.update([
            'malicious-site.com',
            'phishing-bank.fake',
            'download-virus.net',
            'free-money-scam.org',
            'fake-antivirus.com'
        ])

        # Phishing patterns (suspicious URL patterns)
        self.phishing_patterns = [
            r'.*-secure.*\.com',
            r'.*paypal-.*\.com',
            r'.*amazon-.*\.tk',
            r'.*bank.*-verify.*',
            r'.*microsoft-.*\.ml',
            r'.*google-.*\.cf'
        ]

        print(f"Loaded {len(self.malicious_domains)} malicious domains")

    def check_url_safety(self, url):
        """Comprehensive URL safety check"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()

            threat_analysis = {
                'url': url,
                'domain': domain,
                'is_safe': True,
                'threat_type': None,
                'risk_score': 0,
                'reasons': [],
                'timestamp': datetime.now().isoformat()
            }

            # Check against known malicious domains
            if domain in self.malicious_domains:
                threat_analysis.update({
                    'is_safe': False,
                    'threat_type': 'malicious_domain',
                    'risk_score': 10,
                    'reasons': ['Domain found in malicious database']
                })
                return threat_analysis

            # Check phishing patterns
            for pattern in self.phishing_patterns:
                if re.match(pattern, domain):
                    threat_analysis.update({
                        'is_safe': False,
                        'threat_type': 'phishing_pattern',
                        'risk_score': 8,
                        'reasons': [f'Suspicious domain pattern: {pattern}']
                    })
                    return threat_analysis

            # Check for suspicious URL characteristics
            risk_factors = self.analyze_url_characteristics(url)
            threat_analysis['risk_score'] = risk_factors['score']
            threat_analysis['reasons'].extend(risk_factors['reasons'])

            if risk_factors['score'] >= 7:
                threat_analysis['is_safe'] = False
                threat_analysis['threat_type'] = 'suspicious_characteristics'

            # Check with external APIs (VirusTotal, Google Safe Browsing, etc.)
            external_check = self.check_external_apis(url)
            if not external_check['is_safe']:
                threat_analysis.update(external_check)

            return threat_analysis

        except Exception as e:
            return {
                'url': url,
                'is_safe': True,  # Default to safe if check fails
                'error': str(e),
                'risk_score': 0
            }

    def analyze_url_characteristics(self, url):
        """Analyze URL for suspicious characteristics"""
        score = 0
        reasons = []

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        # Long domain names (often used in phishing)
        if len(domain) > 50:
            score += 2
            reasons.append("Unusually long domain name")

        # Multiple subdomains
        if domain.count('.') > 3:
            score += 1
            reasons.append("Multiple subdomains detected")

        # Suspicious keywords in domain
        suspicious_keywords = ['secure', 'verify', 'update', 'suspended', 'limited', 'alert']
        for keyword in suspicious_keywords:
            if keyword in domain:
                score += 2
                reasons.append(f"Suspicious keyword in domain: {keyword}")

        # IP address instead of domain
        try:
            socket.inet_aton(domain.split(':')[0])
            score += 5
            reasons.append("Using IP address instead of domain name")
        except socket.error:
            pass

        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                score += 3
                reasons.append(f"Suspicious TLD: {tld}")

        # URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        if any(shortener in domain for shortener in shorteners):
            score += 2
            reasons.append("URL shortener detected")

        return {'score': score, 'reasons': reasons}

    def check_external_apis(self, url):
        """Check URL against external threat APIs"""
        # Simulate external API checks
        # In real implementation, integrate with:
        # - Google Safe Browsing API
        # - VirusTotal API
        # - PhishTank API

        # For demo, simulate some checks
        domain = urlparse(url).netloc.lower()

        # Simulate Google Safe Browsing check
        if 'malware' in domain or 'phishing' in domain:
            return {
                'is_safe': False,
                'threat_type': 'external_blacklist',
                'risk_score': 10,
                'reasons': ['Flagged by external security API'],
                'source': 'Google Safe Browsing (simulated)'
            }

        return {'is_safe': True}


class BreachChecker:
    def __init__(self):
        self.hibp_api_url = "https://haveibeenpwned.com/api/v3"
        self.api_key = None  # Set your HaveIBeenPwned API key here

    def check_email_breaches(self, email):
        """Check if email appears in known data breaches"""
        try:
            # Try XposedOrNot first (open/free API) - breach analytics endpoint
            try:
                api_url = f"https://api.xposedornot.com/v1/breach-analytics?email={email}"
                headers = {"User-Agent": "CyberGuardPro"}
                resp = requests.get(api_url, headers=headers, timeout=10)
                breaches = []

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        data = {}

                    # Preferred: detailed analytics with ExposedBreaches -> breaches_details
                    exposed = data.get('ExposedBreaches') if isinstance(data, dict) else None

                    breaches_details = []
                    if isinstance(exposed, dict):
                        breaches_details = exposed.get('breaches_details', [])
                    elif isinstance(exposed, list):
                        breaches_details = exposed

                    if breaches_details:
                        for bd in breaches_details:
                            # Map XposedOrNot fields to our expected breach dict format
                            name = bd.get('breach') or bd.get('name') or ''
                            domain = bd.get('domain') or ''
                            xposed_date = bd.get('xposed_date') or bd.get('breached_date') or ''
                            breach_date = ''
                            if xposed_date:
                                # If xposed_date is a year like '2015', convert to YYYY-01-01
                                try:
                                    year = int(str(xposed_date)[:4])
                                    breach_date = f"{year}-01-01"
                                except Exception:
                                    breach_date = str(xposed_date)

                            xposed_data = bd.get('xposed_data') or ''
                            if isinstance(xposed_data, str):
                                data_classes = [s.strip() for s in xposed_data.split(';') if s.strip()]
                            elif isinstance(xposed_data, list):
                                data_classes = xposed_data
                            else:
                                data_classes = []

                            breaches.append({
                                'Name': name,
                                'Title': name,
                                'Domain': domain,
                                'BreachDate': breach_date,
                                'AddedDate': '',
                                'DataClasses': data_classes
                            })

                    else:
                        # Fallback: some endpoints return a simple 'breaches' list or nested list
                        simple = data.get('breaches') if isinstance(data, dict) else None
                        if simple:
                            # In docs, sample was: {"breaches": [["Tesco", "KiwiFarms", ...]]}
                            simple_list = []
                            if isinstance(simple, list) and len(simple) > 0 and isinstance(simple[0], list):
                                simple_list = simple[0]
                            elif isinstance(simple, list):
                                simple_list = simple

                            for item in simple_list:
                                breaches.append({
                                    'Name': item,
                                    'Title': item,
                                    'Domain': '',
                                    'BreachDate': '',
                                    'AddedDate': '',
                                    'DataClasses': []
                                })

                elif resp.status_code == 404:
                    breaches = []
                else:
                    # On unexpected response, fall back to demo data below
                    breaches = []

                # If XposedOrNot returned nothing, fall back to demo dataset
                if not breaches:
                    demo_breaches = {
                        'test@gmail.com': [
                            {
                                'Name': 'Adobe',
                                'Title': 'Adobe',
                                'Domain': 'adobe.com',
                                'BreachDate': '2013-10-04',
                                'AddedDate': '2013-12-04T00:00:00Z',
                                'DataClasses': ['Email addresses', 'Password hints', 'Passwords', 'Usernames']
                            }
                        ],
                        'demo@example.com': [
                            {
                                'Name': 'Collection1',
                                'Title': 'Collection #1',
                                'Domain': '',
                                'BreachDate': '2019-01-07',
                                'AddedDate': '2019-01-16T21:46:07Z',
                                'DataClasses': ['Email addresses', 'Passwords']
                            }
                        ]
                    }

                    breaches = demo_breaches.get(email.lower(), [])

                return {
                    'email': email,
                    'is_breached': len(breaches) > 0,
                    'breach_count': len(breaches),
                    'breaches': breaches,
                    'risk_assessment': self.assess_breach_risk(breaches),
                    'recommendations': self.get_breach_recommendations(breaches)
                }

            except requests.RequestException:
                # Network error when contacting XposedOrNot, fallback to demo data
                demo_breaches = {
                    'test@gmail.com': [
                        {
                            'Name': 'Adobe',
                            'Title': 'Adobe',
                            'Domain': 'adobe.com',
                            'BreachDate': '2013-10-04',
                            'AddedDate': '2013-12-04T00:00:00Z',
                            'DataClasses': ['Email addresses', 'Password hints', 'Passwords', 'Usernames']
                        }
                    ],
                    'demo@example.com': [
                        {
                            'Name': 'Collection1',
                            'Title': 'Collection #1',
                            'Domain': '',
                            'BreachDate': '2019-01-07',
                            'AddedDate': '2019-01-16T21:46:07Z',
                            'DataClasses': ['Email addresses', 'Passwords']
                        }
                    ]
                }

                breaches = demo_breaches.get(email.lower(), [])

                return {
                    'email': email,
                    'is_breached': len(breaches) > 0,
                    'breach_count': len(breaches),
                    'breaches': breaches,
                    'risk_assessment': self.assess_breach_risk(breaches),
                    'recommendations': self.get_breach_recommendations(breaches)
                }

        except Exception as e:
            return {
                'email': email,
                'error': str(e),
                'is_breached': False,
                'breach_count': 0
            }

    def assess_breach_risk(self, breaches):
        """Assess the risk level based on breach data"""
        if not breaches:
            return {'level': 'LOW', 'score': 0}

        risk_score = 0
        sensitive_data_types = ['passwords', 'social security numbers', 'credit cards', 'phone numbers']

        for breach in breaches:
            # Recent breaches are more concerning
            breach_date = datetime.strptime(breach['BreachDate'], '%Y-%m-%d')
            days_old = (datetime.now() - breach_date).days

            if days_old < 365:  # Within last year
                risk_score += 3
            elif days_old < 365 * 3:  # Within last 3 years
                risk_score += 2
            else:
                risk_score += 1

            # Check for sensitive data types
            data_classes = [dc.lower() for dc in breach.get('DataClasses', [])]
            for sensitive in sensitive_data_types:
                if any(sensitive in dc for dc in data_classes):
                    risk_score += 2

        if risk_score >= 8:
            return {'level': 'CRITICAL', 'score': risk_score}
        elif risk_score >= 5:
            return {'level': 'HIGH', 'score': risk_score}
        elif risk_score >= 2:
            return {'level': 'MEDIUM', 'score': risk_score}
        else:
            return {'level': 'LOW', 'score': risk_score}

    def get_breach_recommendations(self, breaches):
        """Provide security recommendations based on breaches"""
        if not breaches:
            return ["No breaches found! Keep using unique passwords for each account."]

        recommendations = [
            "Change passwords immediately for all affected accounts",
            "Enable two-factor authentication where possible",
            "Monitor your accounts for suspicious activity",
            "Use a password manager to create unique passwords",
            "Consider freezing your credit if sensitive data was exposed"
        ]

        # Add specific recommendations based on data types
        all_data_classes = []
        for breach in breaches:
            all_data_classes.extend(breach.get('DataClasses', []))

        if any('credit' in dc.lower() for dc in all_data_classes):
            recommendations.append("Monitor credit reports and consider credit monitoring services")

        if any('social' in dc.lower() for dc in all_data_classes):
            recommendations.append("File a report with identity theft protection services")

        return recommendations


class WebFirewall:
    def __init__(self, threat_intel, port=8888):
        self.threat_intel = threat_intel
        self.port = port
        self.blocked_count = 0
        self.allowed_count = 0
        self.threat_log = []
        self.server = None
        self.is_running = False

    def start_proxy(self):
        """Start the web filtering proxy server"""
        try:
            self.server = HTTPServer(('localhost', self.port), ProxyHandler)
            self.server.threat_intel = self.threat_intel
            self.server.firewall = self
            self.is_running = True

            print(f"🔒 Web Firewall started on http://localhost:{self.port}")
            print("Configure your browser to use this proxy:")
            print(f"   HTTP Proxy: localhost:{self.port}")
            print(f"   HTTPS Proxy: localhost:{self.port}")

            # Start server in a separate thread
            server_thread = threading.Thread(target=self.server.serve_forever)
            server_thread.daemon = True
            server_thread.start()

            return True

        except Exception as e:
            print(f"Failed to start proxy server: {e}")
            return False

    def stop_proxy(self):
        """Stop the web filtering proxy server"""
        if self.server:
            self.server.shutdown()
            self.is_running = False
            print("🔓 Web Firewall stopped")

    def log_threat(self, threat_info):
        """Log blocked threats"""
        self.threat_log.append(threat_info)
        self.blocked_count += 1

        print(f"🚫 BLOCKED: {threat_info['url']} - {threat_info['threat_type']}")

    def log_allowed(self, url):
        """Log allowed requests"""
        self.allowed_count += 1
        # Don't print every allowed request to avoid spam


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        """Handle incoming web requests"""
        try:
            url = self.path if self.path.startswith('http') else f"http://{self.headers.get('Host', '')}{self.path}"

            # Check URL safety
            threat_analysis = self.server.threat_intel.check_url_safety(url)

            if not threat_analysis['is_safe']:
                # Block the request and show warning page
                self.server.firewall.log_threat(threat_analysis)
                self.send_block_page(threat_analysis)
                return

            # Allow the request (in a real implementation, you'd proxy it)
            self.server.firewall.log_allowed(url)
            self.send_allowed_response(url)

        except Exception as e:
            self.send_error(500, f"Proxy error: {str(e)}")

    def send_block_page(self, threat_analysis):
        """Send a custom block page"""
        block_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>🚫 CyberGuard Pro - Threat Blocked</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    background: linear-gradient(135deg, #1a1a1a, #2d2d2d); 
                    color: #fff; 
                    padding: 50px; 
                    text-align: center; 
                }}
                .warning {{ 
                    background: #ff3333; 
                    padding: 20px; 
                    border-radius: 10px; 
                    margin: 20px 0; 
                }}
                .details {{ 
                    background: rgba(255,255,255,0.1); 
                    padding: 15px; 
                    border-radius: 8px; 
                    margin: 15px 0; 
                    text-align: left; 
                }}
            </style>
        </head>
        <body>
            <h1>🛡️ CyberGuard Pro</h1>
            <div class="warning">
                <h2>🚫 THREAT BLOCKED</h2>
                <p>This website has been blocked for your security!</p>
            </div>

            <div class="details">
                <h3>Threat Details:</h3>
                <p><strong>URL:</strong> {threat_analysis['url']}</p>
                <p><strong>Threat Type:</strong> {threat_analysis['threat_type']}</p>
                <p><strong>Risk Score:</strong> {threat_analysis['risk_score']}/10</p>
                <p><strong>Reasons:</strong></p>
                <ul>
                    {''.join(f'<li>{reason}</li>' for reason in threat_analysis.get('reasons', []))}
                </ul>
                <p><strong>Blocked at:</strong> {threat_analysis['timestamp']}</p>
            </div>

            <div style="margin-top: 30px;">
                <button onclick="history.back()">← Go Back</button>
                <a href="http://localhost:5000" style="margin-left: 20px;">
                    <button>🏠 CyberGuard Dashboard</button>
                </a>
            </div>
        </body>
        </html>
        """

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(block_html.encode())

    def send_allowed_response(self, url):
        """Send response for allowed URLs (simplified)"""
        allowed_html = f"""
        <html>
        <head><title>Request Processed</title></head>
        <body>
            <h2>✅ URL Allowed by CyberGuard Pro</h2>
            <p>The requested URL has been analyzed and deemed safe:</p>
            <p><strong>{url}</strong></p>
            <p><em>In a full implementation, this would proxy the actual website content.</em></p>
            <a href="{url}" target="_blank">Continue to website →</a>
        </body>
        </html>
        """

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(allowed_html.encode())


# Initialize components
app = Flask(__name__)
threat_intel = ThreatIntelligence()
breach_checker = BreachChecker()
web_firewall = WebFirewall(threat_intel)
password_enhancer = PasswordEnhancer()  # Initialize the password enhancer


# Your existing password analysis functions here
def calculate_entropy(password):
    if not password:
        return 0
    char_counts = Counter(password)
    length = len(password)
    entropy = 0
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def check_password_strength(password):
    # Your existing password strength function
    analysis = {
        'length': len(password),
        'entropy': calculate_entropy(password),
        'has_uppercase': bool(re.search(r'[A-Z]', password)),
        'has_lowercase': bool(re.search(r'[a-z]', password)),
        'has_numbers': bool(re.search(r'[0-9]', password)),
        'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        'has_common_patterns': bool(re.search(r'(.)\1{2,}', password)),
        'score': 0,
        'strength': '',
        'feedback': []
    }

    # Calculate score (your existing logic)
    if analysis['length'] >= 12:
        analysis['score'] += 2
    elif analysis['length'] >= 8:
        analysis['score'] += 1
    if analysis['entropy'] >= 3.5:
        analysis['score'] += 2
    elif analysis['entropy'] >= 2.5:
        analysis['score'] += 1
    if analysis['has_uppercase']: analysis['score'] += 1
    if analysis['has_lowercase']: analysis['score'] += 1
    if analysis['has_numbers']: analysis['score'] += 1
    if analysis['has_special']: analysis['score'] += 1
    if analysis['has_common_patterns']: analysis['score'] -= 1

    # Determine strength
    if analysis['score'] >= 7:
        analysis['strength'] = 'Strong'
    elif analysis['score'] >= 4:
        analysis['strength'] = 'Medium'
    else:
        analysis['strength'] = 'Weak'

    return analysis


@app.route('/')
def home():
    return render_template('cyberguard_dashboard.html')


@app.route('/analyze_password', methods=['POST'])
def analyze_password():
    password = request.json.get('password', '')
    analysis = check_password_strength(password)
    return jsonify(analysis)


@app.route('/enhance_password', methods=['POST'])
def enhance_password():
    """Enhance a weak password using the LSTM model"""
    password = request.json.get('password', '')
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    try:
        # Get original analysis
        original_analysis = check_password_strength(password)
        
        # Enhance the password
        enhanced_password = password_enhancer.enhance_password(password)
        
        # Analyze enhanced password
        enhanced_analysis = check_password_strength(enhanced_password)
        
        # Return both original and enhanced results
        result = {
            'original': {
                'password': password,
                'analysis': original_analysis
            },
            'enhanced': {
                'password': enhanced_password,
                'analysis': enhanced_analysis
            },
            'improvement': {
                'score_increase': enhanced_analysis['score'] - original_analysis['score'],
                'strength_change': f"{original_analysis['strength']} → {enhanced_analysis['strength']}"
            },
            'model_used': password_enhancer.is_loaded
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/check_breach', methods=['POST'])
def check_breach():
    email = request.json.get('email', '')
    result = breach_checker.check_email_breaches(email)
    return jsonify(result)


@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.json.get('url', '')
    result = threat_intel.check_url_safety(url)
    return jsonify(result)


@app.route('/firewall/start', methods=['POST'])
def start_firewall():
    success = web_firewall.start_proxy()
    return jsonify({
        'success': success,
        'port': web_firewall.port,
        'message': f'Firewall {"started" if success else "failed to start"}'
    })


@app.route('/firewall/stop', methods=['POST'])
def stop_firewall():
    web_firewall.stop_proxy()
    return jsonify({'success': True, 'message': 'Firewall stopped'})


@app.route('/firewall/status')
def firewall_status():
    return jsonify({
        'is_running': web_firewall.is_running,
        'blocked_count': web_firewall.blocked_count,
        'allowed_count': web_firewall.allowed_count,
        'recent_threats': web_firewall.threat_log[-10:]  # Last 10 threats
    })


if __name__ == '__main__':
    print("🚀 Starting CyberGuard Pro...")
    print("🔐 Password Analyzer: Ready")
    print("🌐 Web Firewall: Ready to start")
    print("📧 Breach Checker: Ready")

    app.run(debug=True, host='0.0.0.0', port=5000)
