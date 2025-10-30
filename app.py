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
import platform
import urllib.parse as urlparse_mod
import logging
import random
try:
    import geoip2.database
except Exception:
    geoip2 = None

# Setup logging for honeypot
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# TensorFlow/Keras imports for password enhancement model
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras.models import load_model
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    TENSORFLOW_AVAILABLE = True
    print("✅ TensorFlow loaded successfully")
except Exception as e:
    print(f"⚠️ TensorFlow not available or failed to load: {e}")
    print("Tip: You can run CyberGuard without TensorFlow; password enhancement will use a fallback.")
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
        # Visit tracking for dashboard
        self.visit_log = []
        self.daily_stats = {
            'total_visits': 0,
            'unique_domains': set(),
            'threats_blocked': 0,
            'last_reset': datetime.now().date()
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
            'fake-antivirus.com',
            # More realistic-looking test domains
            'secure-paypal-verify.com',
            'amazon-security-alert.org',
            'microsoft-account-suspended.net',
            'google-security-warning.tk',
            'bank-of-america-verify.ml',
            'apple-id-locked.ga',
            'facebook-security-check.cf',
            'netflix-payment-failed.click',
            'steam-account-suspended.download',
            # Known piracy/malware distribution sites
            'fitgirlrepacks.co',
            'thepiratebay.org',
            'kickasstorrents.to',
            '1337x.to',
            'rarbg.to',
            'torrentz2.eu'
        ])

        # Phishing patterns (suspicious URL patterns)
        self.phishing_patterns = [
            r'.*-secure.*\.com',
            r'.*paypal-.*\.com',
            r'.*amazon-.*\.tk',
            r'.*bank.*-verify.*',
            r'.*microsoft-.*\.ml',
            r'.*google-.*\.cf',
            # Piracy and malware distribution patterns
            r'.*repacks.*',
            r'.*torrent.*',
            r'.*pirate.*',
            r'.*crack.*',
            r'.*keygen.*',
            r'.*warez.*'
        ]

        print(f"Loaded {len(self.malicious_domains)} malicious domains")

    def check_url_safety(self, url):
        """Traffic monitoring - analyze but NEVER block anything"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()

            # Categorize the website for monitoring
            category = self.categorize_website(domain)
            
            traffic_analysis = {
                'url': url,
                'domain': domain,
                'is_safe': True,  # ALWAYS SAFE - never block
                'category': category,
                'risk_score': 0,  # No risk scoring needed
                'timestamp': datetime.now().isoformat(),
                'visit_time': datetime.now().strftime("%H:%M:%S"),
                'visit_date': datetime.now().strftime("%Y-%m-%d")
            }

            return traffic_analysis

        except Exception as e:
            return {
                'url': url,
                'domain': urlparse(url).netloc.lower(),
                'is_safe': True,  # Always safe
                'category': 'unknown',
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }
    
    def categorize_website(self, domain):
        """Categorize websites for monitoring"""
        social_media = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'tiktok.com', 'snapchat.com']
        search_engines = ['google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com']
        news_sites = ['cnn.com', 'bbc.com', 'reuters.com', 'news.yahoo.com', 'msn.com']
        shopping = ['amazon.com', 'ebay.com', 'walmart.com', 'target.com', 'alibaba.com']
        entertainment = ['youtube.com', 'netflix.com', 'hulu.com', 'disney.com', 'twitch.tv']
        work_productivity = ['microsoft.com', 'office.com', 'github.com', 'stackoverflow.com', 'gmail.com']
        
        for site in social_media:
            if site in domain:
                return 'Social Media'
        for site in search_engines:
            if site in domain:
                return 'Search Engine'
        for site in news_sites:
            if site in domain:
                return 'News'
        for site in shopping:
            if site in domain:
                return 'Shopping'
        for site in entertainment:
            if site in domain:
                return 'Entertainment'
        for site in work_productivity:
            if site in domain:
                return 'Work/Productivity'
        
        # Check for piracy/illegal content
        piracy_indicators = ['torrent', 'pirate', 'repacks', 'crack', 'keygen', 'warez', 'rarbg', '1337x', 'kickass', 'fitgirl']
        if any(indicator in domain for indicator in piracy_indicators):
            return 'Piracy/Illegal'
        
        return 'Other'

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
            piracy_keywords = ['torrent', 'pirate', 'crack', 'keygen', 'repacks', 'warez', 'download', 'free-games']
            
            for keyword in suspicious_keywords:
                if keyword in domain:
                    score += 2
                    reasons.append(f"Suspicious keyword in domain: {keyword}")
            
            for keyword in piracy_keywords:
                if keyword in domain:
                    score += 4
                    reasons.append(f"Piracy-related keyword detected: {keyword}")        # IP address instead of domain
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

    def analyze_threat(self, url):
        """Comprehensive threat analysis for extension"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Initialize analysis result
            analysis = {
                'url': url,
                'domain': domain,
                'is_safe': True,
                'threat_type': None,
                'risk_score': 0,
                'reasons': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # 1. Check against known malicious domains
            if domain in self.malicious_domains:
                analysis.update({
                    'is_safe': False,
                    'threat_type': 'Known Malicious Domain',
                    'risk_score': 10,
                    'reasons': ['Domain found in malicious domains database']
                })
                return analysis
            
            # 2. Check phishing patterns
            import re
            for pattern in self.phishing_patterns:
                if re.search(pattern, url):
                    analysis.update({
                        'is_safe': False,
                        'threat_type': 'Phishing Pattern Match',
                        'risk_score': 9,
                        'reasons': [f'URL matches known phishing pattern: {pattern}']
                    })
                    return analysis
            
            # 3. Analyze URL characteristics
            url_analysis = self.analyze_url_characteristics(url)
            risk_score = url_analysis['score']
            reasons = url_analysis['reasons']
            
            # 4. Check for malware/phishing keywords in domain
            if 'malware' in domain or 'phishing' in domain:
                risk_score += 10
                reasons.append('Domain contains malware/phishing keywords')
            
            # 5. Determine threat level
            if risk_score >= 8:
                analysis.update({
                    'is_safe': False,
                    'threat_type': 'High Risk Domain',
                    'risk_score': min(risk_score, 10),
                    'reasons': reasons
                })
            elif risk_score >= 5:
                analysis.update({
                    'is_safe': False,
                    'threat_type': 'Suspicious Domain',
                    'risk_score': risk_score,
                    'reasons': reasons
                })
            elif risk_score > 0:
                analysis.update({
                    'is_safe': True,  # Still safe but with warnings
                    'threat_type': 'Low Risk',
                    'risk_score': risk_score,
                    'reasons': reasons
                })
            
            return analysis
            
        except Exception as e:
            return {
                'url': url,
                'domain': 'unknown',
                'is_safe': True,
                'threat_type': 'Analysis Error',
                'risk_score': 0,
                'reasons': [f'Error analyzing URL: {str(e)}'],
                'timestamp': datetime.now().isoformat()
            }

    def track_visit(self, url, threat_analysis):
        """Track a visit for dashboard statistics"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            now = datetime.now()
            
            # Reset daily stats if new day
            if now.date() != self.daily_stats['last_reset']:
                self.daily_stats = {
                    'total_visits': 0,
                    'unique_domains': set(),
                    'threats_blocked': 0,
                    'last_reset': now.date()
                }
                self.visit_log = []
            
            # Add to visit log (keep last 100 visits)
            visit_entry = {
                'url': url,
                'domain': domain,
                'timestamp': now.isoformat(),
                'time': now.strftime("%H:%M:%S"),
                'date': now.strftime("%Y-%m-%d"),
                'is_safe': threat_analysis['is_safe'],
                'threat_type': threat_analysis.get('threat_type'),
                'risk_score': threat_analysis.get('risk_score', 0),
                'category': self.categorize_website(domain)
            }
            
            self.visit_log.insert(0, visit_entry)  # Most recent first
            if len(self.visit_log) > 100:
                self.visit_log = self.visit_log[:100]
            
            # Update daily stats
            self.daily_stats['total_visits'] += 1
            self.daily_stats['unique_domains'].add(domain)
            
            if not threat_analysis['is_safe']:
                self.daily_stats['threats_blocked'] += 1
                
        except Exception as e:
            print(f"Error tracking visit: {e}")

    def get_dashboard_stats(self):
        """Get current statistics for dashboard"""
        # Filter out localhost and specific ignored domains
        ignored_domains = ['127.0.0.1', 'localhost', 'gxcorner.games']
        
        filtered_visits = [
            visit for visit in self.visit_log 
            if not any(ignored in visit['domain'] for ignored in ignored_domains)
        ]
        
        return {
            'visit_count': len(filtered_visits),
            'unique_domains': len(set(v['domain'] for v in filtered_visits)),
            'threats_blocked': self.daily_stats['threats_blocked'],
            'recent_visits': filtered_visits[:20],  # Last 20 visits (filtered)
            'top_domains': self._get_top_domains(filtered_visits),
            'category_breakdown': self._get_category_breakdown(filtered_visits)
        }
    
    def _get_top_domains(self, visits=None):
        """Get most visited domains"""
        visits_to_use = visits if visits is not None else self.visit_log
        domain_counts = {}
        for visit in visits_to_use:
            domain = visit['domain']
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        return sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    def _get_category_breakdown(self, visits=None):
        """Get breakdown of visits by category"""
        visits_to_use = visits if visits is not None else self.visit_log
        category_counts = {}
        for visit in visits_to_use:
            category = visit['category']
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return category_counts


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


# Web Firewall removed - replaced with browser extension


# ===================== Web Protection via Browser Extension =====================
# Proxy-based firewall removed and replaced with browser extension approach


# ===================== HONEYPOT SYSTEM =====================
class HoneypotManager:
    def __init__(self):
        self.init_database()
        self.honeypot_active = False
        self.attack_stats = {'total_attacks': 0, 'countries': {}, 'services': {}}
        
    def init_database(self):
        """Initialize honeypot database"""
        conn = sqlite3.connect('cyberguard.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS honeypot_attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, source_ip TEXT, source_port INTEGER, service TEXT,
                attack_type TEXT, payload TEXT, credentials TEXT, session_id TEXT,
                country TEXT, asn TEXT, user_agent TEXT, fingerprint TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_ip_location(self, ip):
        """Get IP location information"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'XX'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'latitude': data.get('lat', 0),
                    'longitude': data.get('lon', 0),
                    'isp': data.get('isp', 'Unknown'),
                    'as': data.get('as', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown')
                }
        except:
            pass
        return {
            'country': 'Unknown', 'country_code': 'XX', 'city': 'Unknown',
            'region': 'Unknown', 'latitude': 0, 'longitude': 0,
            'isp': 'Unknown', 'as': 'Unknown', 'timezone': 'Unknown'
        }
    
    def log_honeypot_attack(self, source_ip, source_port, service, attack_type, payload="", credentials="", user_agent=""):
        """Log honeypot attack to database"""
        session_id = hashlib.md5(f"{source_ip}{time.time()}".encode()).hexdigest()[:8]
        location = self.get_ip_location(source_ip)
        fingerprint = hashlib.md5(f"{source_ip}{user_agent}{payload}".encode()).hexdigest()[:16]
        
        conn = sqlite3.connect('cyberguard.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO honeypot_attacks 
            (timestamp, source_ip, source_port, service, attack_type, payload, credentials, 
             session_id, country, asn, user_agent, fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), source_ip, source_port, service, attack_type,
              payload, credentials, session_id, location['country'], location['as'],
              user_agent, fingerprint))
        conn.commit()
        conn.close()
        
        # Update attack statistics
        self.attack_stats['total_attacks'] += 1
        self.attack_stats['countries'][location['country']] = self.attack_stats['countries'].get(location['country'], 0) + 1
        self.attack_stats['services'][service] = self.attack_stats['services'].get(service, 0) + 1
        
        logger.warning(f"HONEYPOT ATTACK: {source_ip}:{source_port} -> {service} ({attack_type}) from {location['country']}")


class AdvancedHoneypotHTTPHandler(BaseHTTPRequestHandler):
    """HTTP Honeypot Handler"""
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
        fake_responses = {
            '/admin': self.serve_fake_admin,
            '/login': self.serve_fake_login,
            '/wp-admin': self.serve_fake_wordpress,
            '/phpmyadmin': self.serve_fake_phpmyadmin,
            '/.env': self.serve_fake_env,
            '/config.php': self.serve_fake_config,
            '/': self.serve_fake_index
        }
        
        handler = fake_responses.get(self.path, self.serve_fake_404)
        honeypot_manager.log_honeypot_attack(client_ip, self.client_address[1], "HTTP", "WEB_SCAN", self.path, "", user_agent)
        handler()
    
    def serve_fake_admin(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', 'Apache/2.4.41 (Ubuntu)')
        self.end_headers()
        html = '''<html><head><title>Admin Panel</title></head><body>
        <h2>System Administration</h2>
        <form method="POST" action="/admin">
        <input name="username" placeholder="Username" required><br><br>
        <input name="password" type="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
        </form></body></html>'''
        self.wfile.write(html.encode())
    
    def serve_fake_login(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = '''<html><body><h1>Login Required</h1>
        <form method="POST"><input name="user"><input name="pass" type="password">
        <button>Sign In</button></form></body></html>'''
        self.wfile.write(html.encode())
    
    def serve_fake_wordpress(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = '''<html><head><title>WordPress Admin</title></head><body>
        <h1>WordPress</h1><form method="POST">
        <input name="log" placeholder="Username"><input name="pwd" type="password" placeholder="Password">
        <button>Log In</button></form></body></html>'''
        self.wfile.write(html.encode())
    
    def serve_fake_phpmyadmin(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = '''<html><head><title>phpMyAdmin</title></head><body>
        <h1>phpMyAdmin 4.9.5</h1><form method="POST">
        <input name="pma_username" placeholder="Username">
        <input name="pma_password" type="password" placeholder="Password">
        <button>Go</button></form></body></html>'''
        self.wfile.write(html.encode())
    
    def serve_fake_env(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        content = '''APP_NAME=MyApp
APP_ENV=production
APP_KEY=base64:fake_key_here
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=myapp
DB_USERNAME=root
DB_PASSWORD=secret123'''
        self.wfile.write(content.encode())
    
    def serve_fake_config(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        content = '''<?php
$config = array(
    'db_host' => 'localhost',
    'db_user' => 'admin',
    'db_pass' => 'password123',
    'db_name' => 'website'
);
?>'''
        self.wfile.write(content.encode())
    
    def serve_fake_index(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = '''<html><head><title>Welcome</title></head><body>
        <h1>Server Running</h1><p>Apache/2.4.41 Server</p>
        <a href="/admin">Admin Panel</a> | <a href="/login">Login</a>
        </body></html>'''
        self.wfile.write(html.encode())
    
    def serve_fake_404(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = '''<html><head><title>404 Not Found</title></head><body>
        <h1>Not Found</h1><p>The requested URL was not found on this server.</p>
        <hr><address>Apache/2.4.41 (Ubuntu) Server</address>
        </body></html>'''
        self.wfile.write(html.encode())
    
    def do_POST(self):
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
        try:
            length = int(self.headers.get('content-length', 0))
            post_data = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            
            honeypot_manager.log_honeypot_attack(client_ip, self.client_address[1], "HTTP",
                                        "LOGIN_ATTEMPT", self.path, post_data, user_agent)
        except:
            pass
        
        self.send_response(401)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = '''<html><body><h2>Authentication Failed</h2>
        <p>Invalid credentials. <a href="javascript:history.back()">Try Again</a></p>
        </body></html>'''
        self.wfile.write(html.encode())


def enhanced_ssh_honeypot(port=2222):
    """Enhanced SSH honeypot"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(10)
        logger.info(f"SSH Honeypot listening on port {port}")
        
        while honeypot_manager.honeypot_active:
            try:
                client, addr = sock.accept()
                threading.Thread(target=handle_enhanced_ssh_client, args=(client, addr)).start()
            except:
                break
        sock.close()
    except Exception as e:
        logger.error(f"SSH honeypot error: {e}")


def handle_enhanced_ssh_client(client, addr):
    """Handle SSH client connections"""
    try:
        banners = [
            b"SSH-2.0-OpenSSH_7.4\r\n",
            b"SSH-2.0-OpenSSH_8.0\r\n",
            b"SSH-2.0-OpenSSH_6.6\r\n"
        ]
        client.send(random.choice(banners))
        
        try:
            banner = client.recv(1024).decode().strip()
            honeypot_manager.log_honeypot_attack(addr[0], addr[1], "SSH", "CONNECTION", banner)
        except:
            banner = "Unknown"
        
        time.sleep(random.uniform(0.5, 2.0))
        
        for attempt in range(5):
            try:
                time.sleep(random.uniform(0.2, 0.8))
                client.settimeout(30)
                auth_data = client.recv(1024)
                
                if auth_data:
                    creds = f"attempt_{attempt + 1}_from_{addr[0]}"
                    honeypot_manager.log_honeypot_attack(addr[0], addr[1], "SSH", "BRUTE_FORCE", banner, creds)
                    time.sleep(random.uniform(0.5, 1.5))
                    failure_msg = b"Permission denied, please try again.\r\n"
                    client.send(failure_msg)
                else:
                    break
            except socket.timeout:
                break
            except:
                break
        
        try:
            client.send(b"Too many authentication failures\r\n")
        except:
            pass
    except Exception as e:
        logger.debug(f"SSH client handler error: {e}")
    finally:
        try:
            client.close()
        except:
            pass


def telnet_honeypot(port=2323):
    """Telnet honeypot"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        logger.info(f"Telnet Honeypot listening on port {port}")
        
        while honeypot_manager.honeypot_active:
            try:
                client, addr = sock.accept()
                threading.Thread(target=handle_telnet_client, args=(client, addr)).start()
            except:
                break
        sock.close()
    except Exception as e:
        logger.error(f"Telnet honeypot error: {e}")


def handle_telnet_client(client, addr):
    """Handle telnet connections"""
    try:
        honeypot_manager.log_honeypot_attack(addr[0], addr[1], "TELNET", "CONNECTION")
        
        client.send(b"Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)\r\n")
        client.send(b"\r\nlogin: ")
        
        for attempt in range(3):
            try:
                client.settimeout(30)
                username = client.recv(1024).decode().strip()
                if username:
                    client.send(b"Password: ")
                    password = client.recv(1024).decode().strip()
                    
                    creds = f"{username}:{password}"
                    honeypot_manager.log_honeypot_attack(addr[0], addr[1], "TELNET", "LOGIN_ATTEMPT", creds, creds)
                    
                    client.send(b"Login incorrect\r\n\r\nlogin: ")
                else:
                    break
            except:
                break
        
        client.send(b"Too many authentication failures\r\n")
    except:
        pass
    finally:
        try:
            client.close()
        except:
            pass


def start_enhanced_honeypots():
    """Start all honeypot services"""
    if not honeypot_manager.honeypot_active:
        honeypot_manager.honeypot_active = True
        
        # Start SSH honeypot
        threading.Thread(target=enhanced_ssh_honeypot, daemon=True).start()
        
        # Start Telnet honeypot
        threading.Thread(target=telnet_honeypot, daemon=True).start()
        
        # Start HTTP honeypot
        def run_http_honeypot():
            try:
                server = HTTPServer(('0.0.0.0', 8080), AdvancedHoneypotHTTPHandler)
                logger.info("HTTP Honeypot listening on port 8080")
                while honeypot_manager.honeypot_active:
                    server.handle_request()
            except Exception as e:
                logger.error(f"HTTP honeypot error: {e}")
        
        threading.Thread(target=run_http_honeypot, daemon=True).start()
        logger.info("All honeypots started")


def stop_enhanced_honeypots():
    """Stop all honeypot services"""
    honeypot_manager.honeypot_active = False
    logger.info("All honeypots stopped")


# Initialize components
honeypot_manager = HoneypotManager()
app = Flask(__name__)
threat_intel = ThreatIntelligence()
breach_checker = BreachChecker()
# web_firewall = WebFirewall(threat_intel)  # Removed - replaced with browser extension
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
    result = threat_intel.analyze_threat(url)
    return jsonify(result)


# Firewall endpoints removed - replaced with browser extension API

@app.route('/extension/check_url', methods=['POST'])
def extension_check_url():
    """API endpoint for browser extension to check URL safety"""
    try:
        data = request.get_json()
        url = data.get('url', '') if data else ''
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Use comprehensive threat analysis for extension
        threat_analysis = threat_intel.analyze_threat(url)
        
        # Track the visit for dashboard statistics
        threat_intel.track_visit(url, threat_analysis)
        
        return jsonify(threat_analysis)
        
    except Exception as e:
        return jsonify({'error': f'Error checking URL: {str(e)}'}), 500


@app.route('/extension/stats', methods=['GET'])
def extension_stats():
    """API endpoint to get dashboard statistics from extension visits"""
    try:
        stats = threat_intel.get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': f'Error getting stats: {str(e)}'}), 500


# ===================== Map Trace feature integration =====================
# Minimal integration of mapTrace functionality with namespaced routes
class SimpleGeo:
    @staticmethod
    def get_public_ip():
        try:
            resp = requests.get('https://api.ipify.org', timeout=5)
            return resp.text
        except Exception:
            return '127.0.0.1'

    @staticmethod
    def ip_location(ip: str):
        # Try local MaxMind if available
        try:
            if 'geoip2' in globals() and geoip2 and os.path.exists('GeoLite2-City.mmdb'):
                with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
                    r = reader.city(ip)
                    return {
                        'country': r.country.name or 'Unknown',
                        'city': r.city.name or 'Unknown',
                        'latitude': float(r.location.latitude or 0),
                        'longitude': float(r.location.longitude or 0),
                        'timezone': str(r.location.time_zone or 'Unknown')
                    }
        except Exception:
            pass

        # Fallback to ip-api.com
        try:
            r = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            d = r.json()
            if d.get('status') == 'success':
                return {
                    'country': d.get('country', 'Unknown'),
                    'city': d.get('city', 'Unknown'),
                    'latitude': d.get('lat', 0),
                    'longitude': d.get('lon', 0),
                    'timezone': d.get('timezone', 'Unknown')
                }
        except Exception:
            pass

        return {
            'country': 'Unknown', 'city': 'Unknown',
            'latitude': 0, 'longitude': 0, 'timezone': 'Unknown'
        }


def extract_domain_for_maptrace(u: str) -> str:
    try:
        if not u.startswith(('http://', 'https://')):
            u = 'http://' + u
        parsed = urlparse_mod.urlparse(u)
        return parsed.netloc
    except Exception:
        return u


def resolve_ip_for_maptrace(domain: str):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def ping_host_for_maptrace(host: str):
    try:
        sysname = platform.system().lower()
        if sysname == 'windows':
            cmd = ['ping', '-n', '4', host]
        else:
            cmd = ['ping', '-c', '4', host]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = r.stdout

        # Response times
        times = []
        if sysname == 'windows':
            matches = re.findall(r'time[<=](\d+)ms', out)
            times = [float(t) for t in matches]
            loss_m = re.search(r'\((\d+)% loss\)', out)
        else:
            matches = re.findall(r'time=(\d+\.?\d*)', out)
            times = [float(t) for t in matches]
            loss_m = re.search(r'(\d+)% packet loss', out)

        loss = int(loss_m.group(1)) if loss_m else 0
        avg = sum(times) / len(times) if times else 0.0
        return avg, loss
    except Exception:
        return 0.0, 100


def detect_simple_threats_for_maptrace(ip: str, resp_ms: float, loss_pct: int):
    threats = []
    if resp_ms > 1000:
        threats.append({'type': 'HIGH_LATENCY', 'severity': 2, 'description': f'High response time: {resp_ms:.2f}ms'})
    if loss_pct > 20:
        threats.append({'type': 'PACKET_LOSS', 'severity': 3, 'description': f'High packet loss: {loss_pct}%'})
    if loss_pct > 50 and resp_ms > 2000:
        threats.append({'type': 'POSSIBLE_DDOS', 'severity': 5, 'description': 'Possible DDoS attack detected'})
    return threats


@app.route('/maptrace')
def maptrace_page():
    return render_template('map_trace.html')


@app.route('/maptrace/trace', methods=['POST'])
def maptrace_trace():
    data = request.get_json(force=True, silent=True) or {}
    u = data.get('url', '')
    if not u:
        return jsonify({'error': 'URL is required'}), 400

    domain = extract_domain_for_maptrace(u)
    dest_ip = resolve_ip_for_maptrace(domain)
    if not dest_ip:
        return jsonify({'error': 'Could not resolve domain'}), 400

    src_ip = SimpleGeo.get_public_ip()
    src_loc = SimpleGeo.ip_location(src_ip)
    dst_loc = SimpleGeo.ip_location(dest_ip)

    resp_ms, loss_pct = ping_host_for_maptrace(dest_ip)
    threats = detect_simple_threats_for_maptrace(dest_ip, resp_ms, loss_pct)

    return jsonify({
        'source': {'ip': src_ip, 'location': src_loc},
        'destination': {'ip': dest_ip, 'location': dst_loc, 'domain': domain},
        'network_stats': {'response_time': resp_ms, 'packet_loss': loss_pct},
        'threats': threats,
        'timestamp': datetime.now().isoformat()
    })


# ===================== HONEYPOT API ENDPOINTS =====================
@app.route('/api/honeypot/start', methods=['POST'])
def start_honeypot_api():
    try:
        start_enhanced_honeypots()
        return jsonify({
            'status': 'success',
            'message': 'Honeypots started successfully',
            'services': ['SSH (port 2222)', 'Telnet (port 2323)', 'HTTP (port 8080)']
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/honeypot/stop', methods=['POST'])
def stop_honeypot_api():
    try:
        stop_enhanced_honeypots()
        return jsonify({'status': 'success', 'message': 'All honeypots stopped successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/honeypot/attacks')
def get_honeypot_attacks():
    try:
        conn = sqlite3.connect('cyberguard.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM honeypot_attacks 
            ORDER BY timestamp DESC LIMIT 100
        ''')
        
        attacks = []
        for row in cursor.fetchall():
            attacks.append({
                'id': row[0], 'timestamp': row[1], 'source_ip': row[2], 'source_port': row[3],
                'service': row[4], 'attack_type': row[5], 'payload': row[6], 'credentials': row[7],
                'session_id': row[8], 'country': row[9], 'asn': row[10], 'user_agent': row[11],
                'fingerprint': row[12]
            })
        
        conn.close()
        return jsonify(attacks)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/honeypot/stats')
def get_honeypot_stats():
    try:
        conn = sqlite3.connect('cyberguard.db')
        cursor = conn.cursor()
        
        # Attack statistics by service
        cursor.execute('''
            SELECT service, COUNT(*) as count 
            FROM honeypot_attacks 
            GROUP BY service
        ''')
        service_stats = dict(cursor.fetchall())
        
        # Attack statistics by country
        cursor.execute('''
            SELECT country, COUNT(*) as count 
            FROM honeypot_attacks 
            GROUP BY country 
            ORDER BY count DESC LIMIT 10
        ''')
        country_stats = dict(cursor.fetchall())
        
        # Recent attack trends (last 24 hours)
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        cursor.execute('''
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM honeypot_attacks 
            WHERE timestamp > ?
            GROUP BY hour
            ORDER BY hour
        ''', (yesterday,))
        hourly_stats = dict(cursor.fetchall())
        
        # Top attacking IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count, country
            FROM honeypot_attacks 
            GROUP BY source_ip 
            ORDER BY count DESC LIMIT 10
        ''')
        top_attackers = [{'ip': row[0], 'count': row[1], 'country': row[2]}
                         for row in cursor.fetchall()]
        
        # Total unique IPs
        cursor.execute('''
            SELECT COUNT(DISTINCT source_ip) FROM honeypot_attacks
        ''')
        unique_ips = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_attacks': honeypot_manager.attack_stats['total_attacks'],
            'service_stats': service_stats,
            'country_stats': country_stats,
            'hourly_stats': hourly_stats,
            'top_attackers': top_attackers,
            'unique_ips': unique_ips,
            'active_honeypots': honeypot_manager.honeypot_active
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/honeypot/status')
def get_honeypot_status():
    try:
        return jsonify({
            'active': honeypot_manager.honeypot_active,
            'total_attacks': honeypot_manager.attack_stats['total_attacks']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("🚀 Starting CyberGuard Pro...")
    print("🔐 Password Analyzer: Ready")
    print("🌐 Browser Extension: Ready")
    print("📧 Breach Checker: Ready")
    print("🍯 Honeypot System: Ready to deploy")
    print("�️  Map Trace: Ready")
    print("\n💡 Honeypot ports: SSH (2222), Telnet (2323), HTTP (8080)")
    print("📍 Dashboard: http://localhost:5000")

    app.run(debug=True, host='0.0.0.0', port=5000)
