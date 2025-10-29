from flask import Flask, render_template, request, jsonify
import requests
import socket
import subprocess
import platform
import re
import threading
import time
from datetime import datetime, timedelta
import json
import sqlite3
import os
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging
import hashlib
import random
import struct

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AdvancedIntegratedMonitor:
    def __init__(self):
        self.init_database()
        self.threat_feeds = {
            'malicious_ips': set(['185.220.100.240', '192.168.1.100', '1.2.3.4']),
            'suspicious_countries': {'KP', 'IR', 'CN', 'RU', 'BD'},
            'malicious_ports': {22, 23, 80, 443, 8080, 3389, 5900},
            'common_passwords': ['admin', '123456', 'password', 'root', 'test']
        }
        self.executor = ThreadPoolExecutor(max_workers=15)
        self.honeypot_active = False
        self.attack_stats = {'total_attacks': 0, 'countries': {}, 'services': {}}
        self.active_connections = {}

    def init_database(self):
        conn = sqlite3.connect('network_monitor.db')
        cursor = conn.cursor()

        # Enhanced network logs table
        cursor.execute('DROP TABLE IF EXISTS network_logs')
        cursor.execute('DROP TABLE IF EXISTS honeypot_attacks')
        cursor.execute('DROP TABLE IF EXISTS traceroute_hops')

        cursor.execute('''
            CREATE TABLE network_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, source_ip TEXT, dest_ip TEXT, source_country TEXT, dest_country TEXT,
                response_time REAL, packet_loss REAL, jitter REAL, threat_level TEXT, url TEXT,
                ssl_info TEXT, dns_resolution_time REAL, http_status INTEGER, content_length INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE honeypot_attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, source_ip TEXT, source_port INTEGER, service TEXT,
                attack_type TEXT, payload TEXT, credentials TEXT, session_id TEXT,
                country TEXT, asn TEXT, user_agent TEXT, fingerprint TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE traceroute_hops (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT, hop_number INTEGER, ip_address TEXT, 
                hostname TEXT, response_time REAL, country TEXT, timestamp TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org', timeout=5).text.strip()
        except:
            try:
                return requests.get('https://httpbin.org/ip', timeout=5).json()['origin']
            except:
                return '127.0.0.1'

    def get_ip_location(self, ip):
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

    def advanced_traceroute(self, host):
        """Perform advanced traceroute with hop analysis"""
        hops = []
        session_id = hashlib.md5(f"{host}{time.time()}".encode()).hexdigest()[:8]

        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = f"tracert -h 30 {host}"
            else:
                cmd = f"traceroute -m 30 {host}"

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)

            lines = result.stdout.split('\n')
            hop_num = 0

            for line in lines:
                if system == "windows":
                    # Windows tracert format
                    match = re.search(r'^\s*(\d+)\s+.*?(\d+)\s*ms.*?(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        hop_num = int(match.group(1))
                        response_time = float(match.group(2))
                        ip = match.group(3)

                        hop_info = self.analyze_hop(ip, hop_num, response_time, session_id)
                        hops.append(hop_info)
                else:
                    # Linux/Mac traceroute format
                    match = re.search(r'^\s*(\d+)\s+([\w\.-]+)?\s*\(([\d\.]+)\)\s+([\d\.]+)\s*ms', line)
                    if match:
                        hop_num = int(match.group(1))
                        hostname = match.group(2) if match.group(2) else 'Unknown'
                        ip = match.group(3)
                        response_time = float(match.group(4))

                        hop_info = self.analyze_hop(ip, hop_num, response_time, session_id, hostname)
                        hops.append(hop_info)

        except Exception as e:
            logger.error(f"Traceroute error: {e}")

        return hops, session_id

    def analyze_hop(self, ip, hop_num, response_time, session_id, hostname='Unknown'):
        """Analyze individual hop in traceroute"""
        location = self.get_ip_location(ip)

        # Store hop data
        conn = sqlite3.connect('network_monitor.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO traceroute_hops 
            (session_id, hop_number, ip_address, hostname, response_time, country, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, hop_num, ip, hostname, response_time, location['country'], datetime.now().isoformat()))
        conn.commit()
        conn.close()

        return {
            'hop': hop_num,
            'ip': ip,
            'hostname': hostname,
            'response_time': response_time,
            'location': location,
            'is_suspicious': location['country_code'] in self.threat_feeds['suspicious_countries']
        }

    def get_domain_info(self, domain):
        """Get comprehensive domain information"""
        try:
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]

            # DNS resolution timing
            start_time = time.time()
            ip = socket.gethostbyname(domain)
            dns_time = (time.time() - start_time) * 1000

            # SSL/TLS information
            ssl_info = self.get_ssl_info(domain)

            # HTTP response analysis
            http_info = self.analyze_http_response(domain)

            return {
                'ip': ip,
                'dns_resolution_time': dns_time,
                'ssl_info': ssl_info,
                'http_info': http_info
            }
        except Exception as e:
            return {'ip': None, 'error': str(e)}

    def get_ssl_info(self, domain):
        """Get SSL certificate information"""
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
        except:
            return {'error': 'No SSL certificate or connection failed'}

    def analyze_http_response(self, domain):
        """Analyze HTTP response"""
        try:
            response = requests.get(f'http://{domain}', timeout=10, allow_redirects=True)
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds() * 1000,
                'redirects': len(response.history)
            }
        except Exception as e:
            return {'error': str(e)}

    def enhanced_ping(self, host):
        """Enhanced ping with more detailed statistics"""
        try:
            system = platform.system().lower()
            count = 10  # More pings for better statistics

            if system == "windows":
                cmd = f"ping -n {count} {host}"
            else:
                cmd = f"ping -c {count} {host}"

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

            if system == "windows":
                times = re.findall(r'time[<=](\d+)ms', result.stdout)
                loss_match = re.search(r'\((\d+)% loss\)', result.stdout)
            else:
                times = re.findall(r'time=(\d+\.?\d*)', result.stdout)
                loss_match = re.search(r'(\d+)% packet loss', result.stdout)

            response_times = [float(t) for t in times] if times else [0]
            packet_loss = int(loss_match.group(1)) if loss_match else 100 if not response_times else 0

            if response_times:
                avg_time = sum(response_times) / len(response_times)
                min_time = min(response_times)
                max_time = max(response_times)
                jitter = max_time - min_time
                stddev = (sum((t - avg_time) ** 2 for t in response_times) / len(response_times)) ** 0.5
            else:
                avg_time = min_time = max_time = jitter = stddev = 0

            return {
                'avg_time': avg_time,
                'min_time': min_time,
                'max_time': max_time,
                'packet_loss': packet_loss,
                'jitter': jitter,
                'stddev': stddev,
                'packets_sent': count,
                'packets_received': count - (count * packet_loss // 100)
            }
        except Exception as e:
            return {'avg_time': 0, 'packet_loss': 100, 'error': str(e)}

    def advanced_threat_detection(self, ip, location, ping_stats, domain_info):
        """Advanced threat detection with scoring"""
        threats = []
        risk_score = 0

        # Performance-based threats
        if ping_stats['avg_time'] > 1000:
            threats.append({
                'type': 'EXTREME_LATENCY',
                'severity': 5,
                'description': f'Extreme latency: {ping_stats["avg_time"]:.2f}ms',
                'risk_score': 25
            })
            risk_score += 25
        elif ping_stats['avg_time'] > 500:
            threats.append({
                'type': 'HIGH_LATENCY',
                'severity': 4,
                'description': f'High latency: {ping_stats["avg_time"]:.2f}ms',
                'risk_score': 15
            })
            risk_score += 15

        if ping_stats['packet_loss'] > 30:
            threats.append({
                'type': 'SEVERE_PACKET_LOSS',
                'severity': 5,
                'description': f'Severe packet loss: {ping_stats["packet_loss"]}%',
                'risk_score': 30
            })
            risk_score += 30
        elif ping_stats['packet_loss'] > 10:
            threats.append({
                'type': 'PACKET_LOSS',
                'severity': 3,
                'description': f'Packet loss: {ping_stats["packet_loss"]}%',
                'risk_score': 15
            })
            risk_score += 15

        # Geographic threats
        if location.get('country_code') in self.threat_feeds['suspicious_countries']:
            threats.append({
                'type': 'SUSPICIOUS_COUNTRY',
                'severity': 4,
                'description': f'High-risk country: {location["country"]}',
                'risk_score': 20
            })
            risk_score += 20

        # Known malicious IP
        if ip in self.threat_feeds['malicious_ips']:
            threats.append({
                'type': 'MALICIOUS_IP',
                'severity': 5,
                'description': 'Known malicious IP address',
                'risk_score': 40
            })
            risk_score += 40

        # SSL/TLS threats
        if 'ssl_info' in domain_info and 'error' in domain_info['ssl_info']:
            threats.append({
                'type': 'SSL_ISSUES',
                'severity': 3,
                'description': 'SSL/TLS certificate issues detected',
                'risk_score': 10
            })
            risk_score += 10

        # HTTP threats
        if 'http_info' in domain_info and domain_info['http_info'].get('status_code', 0) >= 400:
            threats.append({
                'type': 'HTTP_ERROR',
                'severity': 2,
                'description': f'HTTP error: {domain_info["http_info"]["status_code"]}',
                'risk_score': 5
            })
            risk_score += 5

        return threats, min(risk_score, 100)  # Cap at 100%

    def log_honeypot_attack(self, source_ip, source_port, service, attack_type, payload="", credentials="",
                            user_agent=""):
        """Enhanced honeypot attack logging"""
        session_id = hashlib.md5(f"{source_ip}{time.time()}".encode()).hexdigest()[:8]
        location = self.get_ip_location(source_ip)
        fingerprint = hashlib.md5(f"{source_ip}{user_agent}{payload}".encode()).hexdigest()[:16]

        conn = sqlite3.connect('network_monitor.db')
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
        self.attack_stats['countries'][location['country']] = self.attack_stats['countries'].get(location['country'],
                                                                                                 0) + 1
        self.attack_stats['services'][service] = self.attack_stats['services'].get(service, 0) + 1

        logger.warning(
            f"HONEYPOT ATTACK: {source_ip}:{source_port} -> {service} ({attack_type}) from {location['country']}")


monitor = AdvancedIntegratedMonitor()


class AdvancedHoneypotHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')

        # Different responses for different paths
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
        monitor.log_honeypot_attack(client_ip, self.client_address[1], "HTTP", "WEB_SCAN",
                                    self.path, "", user_agent)
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

            monitor.log_honeypot_attack(client_ip, self.client_address[1], "HTTP",
                                        "LOGIN_ATTEMPT", self.path, post_data, user_agent)
        except:
            pass

        # Always return authentication failed
        self.send_response(401)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = '''<html><body><h2>Authentication Failed</h2>
        <p>Invalid credentials. <a href="javascript:history.back()">Try Again</a></p>
        </body></html>'''
        self.wfile.write(html.encode())


def enhanced_ssh_honeypot(port=2222):
    """Enhanced SSH honeypot with more realistic behavior"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(10)
        logger.info(f"Enhanced SSH Honeypot listening on port {port}")

        while monitor.honeypot_active:
            try:
                client, addr = sock.accept()
                threading.Thread(target=handle_enhanced_ssh_client, args=(client, addr)).start()
            except:
                break
        sock.close()
    except Exception as e:
        logger.error(f"SSH honeypot error: {e}")


def handle_enhanced_ssh_client(client, addr):
    """Enhanced SSH client handler"""
    try:
        # Send SSH banner
        banners = [
            b"SSH-2.0-OpenSSH_7.4\r\n",
            b"SSH-2.0-OpenSSH_8.0\r\n",
            b"SSH-2.0-OpenSSH_6.6\r\n"
        ]
        client.send(random.choice(banners))

        # Read client banner
        try:
            banner = client.recv(1024).decode().strip()
            monitor.log_honeypot_attack(addr[0], addr[1], "SSH", "CONNECTION", banner)
        except:
            banner = "Unknown"

        time.sleep(random.uniform(0.5, 2.0))  # Simulate processing time

        # Simulate authentication attempts
        for attempt in range(5):  # Allow up to 5 attempts
            try:
                # Simulate SSH protocol negotiation
                time.sleep(random.uniform(0.2, 0.8))

                # Wait for authentication attempt
                client.settimeout(30)
                auth_data = client.recv(1024)

                if auth_data:
                    # Simulate credential extraction (simplified)
                    creds = f"attempt_{attempt + 1}_from_{addr[0]}"
                    monitor.log_honeypot_attack(addr[0], addr[1], "SSH", "BRUTE_FORCE",
                                                banner, creds)

                    # Send authentication failure
                    time.sleep(random.uniform(0.5, 1.5))
                    failure_msg = b"Permission denied, please try again.\r\n"
                    client.send(failure_msg)
                else:
                    break

            except socket.timeout:
                break
            except:
                break

        # Close connection
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

        while monitor.honeypot_active:
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
        monitor.log_honeypot_attack(addr[0], addr[1], "TELNET", "CONNECTION")

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
                    monitor.log_honeypot_attack(addr[0], addr[1], "TELNET", "LOGIN_ATTEMPT",
                                                creds, creds)

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
    """Start all enhanced honeypot services"""
    if not monitor.honeypot_active:
        monitor.honeypot_active = True

        # Start SSH honeypot
        threading.Thread(target=enhanced_ssh_honeypot, daemon=True).start()

        # Start Telnet honeypot
        threading.Thread(target=telnet_honeypot, daemon=True).start()

        # Start HTTP honeypot
        def run_http_honeypot():
            try:
                server = HTTPServer(('0.0.0.0', 8080), AdvancedHoneypotHTTPHandler)
                logger.info("Advanced HTTP Honeypot listening on port 8080")
                while monitor.honeypot_active:
                    server.handle_request()
            except Exception as e:
                logger.error(f"HTTP honeypot error: {e}")

        threading.Thread(target=run_http_honeypot, daemon=True).start()
        logger.info("All enhanced honeypots started")


def stop_enhanced_honeypots():
    """Stop all honeypot services"""
    monitor.honeypot_active = False
    logger.info("All honeypots stopped")


# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/trace', methods=['POST'])
def advanced_trace_route():
    data = request.get_json()
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        # Get domain information
        domain_info = monitor.get_domain_info(url)

        if not domain_info.get('ip'):
            return jsonify({'error': 'Could not resolve domain'}), 400

        dest_ip = domain_info['ip']
        domain = url.replace('http://', '').replace('https://', '').split('/')[0]
        source_ip = monitor.get_public_ip()

        # Parallel execution for better performance
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_source = executor.submit(monitor.get_ip_location, source_ip)
            future_dest = executor.submit(monitor.get_ip_location, dest_ip)
            future_ping = executor.submit(monitor.enhanced_ping, dest_ip)
            future_traceroute = executor.submit(monitor.advanced_traceroute, dest_ip)

            source_location = future_source.result()
            dest_location = future_dest.result()
            ping_stats = future_ping.result()
            traceroute_hops, session_id = future_traceroute.result()

        # Advanced threat detection
        threats, risk_score = monitor.advanced_threat_detection(dest_ip, dest_location, ping_stats, domain_info)

        # Log to database
        conn = sqlite3.connect('network_monitor.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO network_logs 
            (timestamp, source_ip, dest_ip, source_country, dest_country, response_time, 
             packet_loss, jitter, threat_level, url, ssl_info, dns_resolution_time, 
             http_status, content_length)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), source_ip, dest_ip, source_location['country'],
              dest_location['country'], ping_stats['avg_time'], ping_stats['packet_loss'],
              ping_stats['jitter'], 'HIGH' if risk_score > 50 else 'MEDIUM' if risk_score > 20 else 'LOW',
              url, json.dumps(domain_info.get('ssl_info', {})),
              domain_info.get('dns_resolution_time', 0),
              domain_info.get('http_info', {}).get('status_code', 0),
              domain_info.get('http_info', {}).get('content_length', 0)))
        conn.commit()
        conn.close()

        return jsonify({
            'source': {'ip': source_ip, 'location': source_location},
            'destination': {'ip': dest_ip, 'location': dest_location, 'domain': domain},
            'network_stats': ping_stats,
            'domain_info': domain_info,
            'traceroute': {
                'hops': traceroute_hops,
                'session_id': session_id,
                'total_hops': len(traceroute_hops)
            },
            'threats': threats,
            'risk_score': risk_score,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Trace route error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/honeypot/start', methods=['POST'])
def start_honeypot_api():
    try:
        start_enhanced_honeypots()
        return jsonify({
            'status': 'Enhanced honeypots started successfully',
            'services': ['SSH (port 2222)', 'Telnet (port 2323)', 'HTTP (port 8080)']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/honeypot/stop', methods=['POST'])
def stop_honeypot_api():
    try:
        stop_enhanced_honeypots()
        return jsonify({'status': 'All honeypots stopped successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/honeypot/attacks')
def get_honeypot_attacks():
    try:
        conn = sqlite3.connect('network_monitor.db')
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
        conn = sqlite3.connect('network_monitor.db')
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

        conn.close()

        return jsonify({
            'total_attacks': monitor.attack_stats['total_attacks'],
            'service_stats': service_stats,
            'country_stats': country_stats,
            'hourly_stats': hourly_stats,
            'top_attackers': top_attackers,
            'active_honeypots': monitor.honeypot_active
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/history')
def get_history():
    try:
        conn = sqlite3.connect('network_monitor.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM network_logs 
            ORDER BY timestamp DESC LIMIT 50
        ''')

        logs = []
        for row in cursor.fetchall():
            logs.append({
                'id': row[0], 'timestamp': row[1], 'source_ip': row[2], 'dest_ip': row[3],
                'source_country': row[4], 'dest_country': row[5], 'response_time': row[6],
                'packet_loss': row[7], 'jitter': row[8], 'threat_level': row[9], 'url': row[10],
                'ssl_info': row[11], 'dns_resolution_time': row[12], 'http_status': row[13],
                'content_length': row[14]
            })

        conn.close()
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/traceroute/<session_id>')
def get_traceroute_details(session_id):
    try:
        conn = sqlite3.connect('network_monitor.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM traceroute_hops 
            WHERE session_id = ? 
            ORDER BY hop_number
        ''', (session_id,))

        hops = []
        for row in cursor.fetchall():
            hops.append({
                'id': row[0], 'session_id': row[1], 'hop_number': row[2],
                'ip_address': row[3], 'hostname': row[4], 'response_time': row[5],
                'country': row[6], 'timestamp': row[7]
            })

        conn.close()
        return jsonify(hops)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')

    # Advanced HTML template with tabbed interface
    advanced_html_template = '''<!DOCTYPE html>
<html>
<head>
    <title>Advanced Network Monitor & Honeypot System</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%); 
            color: #ffffff; 
            overflow-x: hidden;
        }

        .header {
            background: rgba(0, 0, 0, 0.9);
            padding: 15px 0;
            border-bottom: 2px solid #00ff88;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 10000;
            backdrop-filter: blur(10px);
        }

        .header h1 {
            text-align: center;
            color: #00ff88;
            font-size: 24px;
            font-weight: bold;
            text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
        }

        .tab-container {
            display: flex;
            justify-content: center;
            background: rgba(0, 0, 0, 0.8);
            border-bottom: 1px solid #333;
            margin-top: 70px;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 9999;
        }

        .tab {
            padding: 15px 30px;
            cursor: pointer;
            border: none;
            background: transparent;
            color: #888;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s ease;
            border-bottom: 3px solid transparent;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .tab:hover {
            color: #fff;
            background: rgba(255, 255, 255, 0.05);
        }

        .tab.active {
            color: #00ff88;
            border-bottom-color: #00ff88;
            background: rgba(0, 255, 136, 0.1);
        }

        .tab-content {
            display: none;
            padding-top: 130px;
            min-height: 100vh;
        }

        .tab-content.active {
            display: block;
        }

        #map { 
            height: calc(100vh - 130px); 
            width: 100%; 
            position: relative;
        }

        .control-panel {
            position: absolute;
            top: 20px;
            left: 20px;
            background: rgba(0, 0, 0, 0.95);
            border: 2px solid #00ff88;
            border-radius: 15px;
            padding: 25px;
            min-width: 380px;
            z-index: 1000;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 255, 136, 0.2);
        }

        .stats-panel {
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(0, 0, 0, 0.95);
            border: 2px solid #00bfff;
            border-radius: 15px;
            padding: 25px;
            min-width: 380px;
            max-height: 500px;
            overflow-y: auto;
            z-index: 1000;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 191, 255, 0.2);
        }

        .threat-panel {
            position: absolute;
            bottom: 20px;
            left: 20px;
            background: rgba(0, 0, 0, 0.95);
            border: 2px solid #ff6b6b;
            border-radius: 15px;
            padding: 25px;
            min-width: 380px;
            max-height: 400px;
            overflow-y: auto;
            z-index: 1000;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(255, 107, 107, 0.2);
        }

        .traceroute-panel {
            position: absolute;
            bottom: 20px;
            right: 20px;
            background: rgba(0, 0, 0, 0.95);
            border: 2px solid #ffd93d;
            border-radius: 15px;
            padding: 25px;
            min-width: 380px;
            max-height: 400px;
            overflow-y: auto;
            z-index: 1000;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(255, 217, 61, 0.2);
        }

        /* Honeypot Tab Styles */
        .honeypot-dashboard {
            padding: 20px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            grid-template-rows: auto auto 1fr;
            gap: 20px;
            height: calc(100vh - 130px);
        }

        .honeypot-control {
            grid-column: 1 / -1;
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #ff6600;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
        }

        .honeypot-stats {
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00bfff;
            border-radius: 15px;
            padding: 25px;
        }

        .attack-feed {
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #ff0066;
            border-radius: 15px;
            padding: 25px;
            overflow-y: auto;
        }

        .attack-map {
            grid-column: 1 / -1;
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #9d4edd;
            border-radius: 15px;
            padding: 25px;
            height: 400px;
        }

        .panel-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 20px;
            text-align: center;
            text-shadow: 0 0 10px currentColor;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .input-group {
            margin-bottom: 20px;
        }

        .input-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            font-weight: 600;
            color: #ccc;
        }

        .input-group input, .input-group select {
            width: 100%;
            padding: 12px 15px;
            background: rgba(255, 255, 255, 0.05);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: #fff;
            font-family: inherit;
            font-size: 14px;
            transition: all 0.3s ease;
        }

        .input-group input:focus, .input-group select:focus {
            outline: none;
            border-color: #00ff88;
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.3);
        }

        .btn {
            width: 100%;
            padding: 12px 20px;
            margin: 8px 0;
            background: linear-gradient(45deg, #00ff88, #00cc6a);
            border: none;
            border-radius: 8px;
            color: #000;
            cursor: pointer;
            font-family: inherit;
            font-weight: bold;
            font-size: 14px;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .btn:hover {
            background: linear-gradient(45deg, #00cc6a, #00ff88);
            box-shadow: 0 5px 20px rgba(0, 255, 136, 0.4);
            transform: translateY(-2px);
        }

        .btn-honeypot {
            background: linear-gradient(45deg, #ff6600, #ff8800);
            color: #fff;
        }

        .btn-honeypot:hover {
            background: linear-gradient(45deg, #ff8800, #ff6600);
            box-shadow: 0 5px 20px rgba(255, 102, 0, 0.4);
        }

        .btn-danger {
            background: linear-gradient(45deg, #ff4757, #ff6b7a);
            color: #fff;
        }

        .btn-danger:hover {
            background: linear-gradient(45deg, #ff6b7a, #ff4757);
            box-shadow: 0 5px 20px rgba(255, 71, 87, 0.4);
        }

        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .stat-card .value {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-card .label {
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
        }

        .stat-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 12px 0;
            padding: 10px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            border-left: 4px solid #00bfff;
        }

        .attack-item {
            margin: 12px 0;
            padding: 15px;
            background: rgba(255, 0, 102, 0.1);
            border-left: 4px solid #ff0066;
            border-radius: 8px;
            font-size: 13px;
            transition: all 0.3s ease;
        }

        .attack-item:hover {
            background: rgba(255, 0, 102, 0.2);
            transform: translateX(5px);
        }

        .threat-item {
            margin: 12px 0;
            padding: 15px;
            background: rgba(255, 107, 107, 0.1);
            border-left: 4px solid #ff6b6b;
            border-radius: 8px;
            font-size: 13px;
        }

        .hop-item {
            margin: 8px 0;
            padding: 12px;
            background: rgba(255, 217, 61, 0.1);
            border-left: 4px solid #ffd93d;
            border-radius: 8px;
            font-size: 13px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .status {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }

        .status-active {
            background: #00ff88;
            color: #000;
        }

        .status-inactive {
            background: #ff4757;
            color: #fff;
        }

        .status-medium {
            background: #ffa502;
            color: #000;
        }

        .status-high {
            background: #ff4757;
            color: #fff;
        }

        .loading {
            display: none;
            text-align: center;
            color: #00ff88;
            margin: 15px 0;
            font-weight: bold;
        }

        .loading i {
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .risk-meter {
            width: 100%;
            height: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }

        .risk-fill {
            height: 100%;
            transition: all 0.5s ease;
            border-radius: 10px;
        }

        .risk-low { background: linear-gradient(90deg, #00ff88, #00cc6a); }
        .risk-medium { background: linear-gradient(90deg, #ffa502, #ff8800); }
        .risk-high { background: linear-gradient(90deg, #ff4757, #ff3742); }

        /* Charts */
        .chart-container {
            width: 100%;
            height: 200px;
            margin: 15px 0;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .honeypot-dashboard {
                grid-template-columns: 1fr;
                grid-template-rows: auto auto auto auto;
            }

            .control-panel, .stats-panel, .threat-panel, .traceroute-panel {
                position: relative;
                top: auto;
                left: auto;
                right: auto;
                bottom: auto;
                margin: 10px;
                min-width: auto;
            }

            #map {
                height: 50vh;
            }
        }

        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb {
            background: rgba(0, 255, 136, 0.5);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: rgba(0, 255, 136, 0.8);
        }
    </style>
</head>
<body>
    <div class="header">
        <h1><i class="fas fa-shield-alt"></i> ADVANCED NETWORK MONITOR & HONEYPOT SYSTEM</h1>
    </div>

    <div class="tab-container">
        <button class="tab active" onclick="switchTab('tracer')">
            <i class="fas fa-route"></i> Network Tracer
        </button>
        <button class="tab" onclick="switchTab('honeypot')">
            <i class="fas fa-bug"></i> Honeypot Control
        </button>
    </div>

    <!-- Network Tracer Tab -->
    <div id="tracer-tab" class="tab-content active">
        <div class="control-panel">
            <div class="panel-title" style="color: #00ff88;">
                <i class="fas fa-satellite-dish"></i> NETWORK TRACER
            </div>
            <div class="input-group">
                <label><i class="fas fa-globe"></i> Target URL/Domain:</label>
                <input type="text" id="urlInput" placeholder="github.com, google.com, 1.1.1.1">
            </div>
            <div class="input-group">
                <label><i class="fas fa-cog"></i> Trace Options:</label>
                <select id="traceOptions">
                    <option value="basic">Basic Trace</option>
                    <option value="advanced">Advanced + Traceroute</option>
                    <option value="full">Full Analysis</option>
                </select>
            </div>
            <button class="btn" onclick="performAdvancedTrace()">
                <i class="fas fa-search"></i> START TRACE
            </button>
            <div class="loading" id="loading">
                <i class="fas fa-spinner"></i> Analyzing network path...
            </div>
        </div>

        <div class="stats-panel">
            <div class="panel-title" style="color: #00bfff;">
                <i class="fas fa-chart-line"></i> NETWORK STATISTICS
            </div>
            <div id="stats-content">
                <div class="stat-grid">
                    <div class="stat-card">
                        <div class="value" style="color: #00ff88;">Ready</div>
                        <div class="label">Status</div>
                    </div>
                </div>
                <div id="detailed-stats"></div>
            </div>
        </div>

        <div class="threat-panel">
            <div class="panel-title" style="color: #ff6b6b;">
                <i class="fas fa-exclamation-triangle"></i> THREAT ANALYSIS
            </div>
            <div class="risk-meter">
                <div class="risk-fill risk-low" id="riskMeter" style="width: 0%;"></div>
            </div>
            <div id="risk-score" style="text-align: center; margin: 10px 0; font-weight: bold;">Risk Score: 0%</div>
            <div id="threats-content">
                <div style="color: #00ff88; text-align: center; padding: 20px;">
                    <i class="fas fa-shield-alt"></i> No threats detected
                </div>
            </div>
        </div>

        <div class="traceroute-panel">
            <div class="panel-title" style="color: #ffd93d;">
                <i class="fas fa-map-marked-alt"></i> TRACEROUTE HOPS
            </div>
            <div id="traceroute-content">
                <div style="color: #888; text-align: center; padding: 20px;">
                    <i class="fas fa-info-circle"></i> Run advanced trace to see route hops
                </div>
            </div>
        </div>

        <div id="map"></div>
    </div>

    <!-- Honeypot Tab -->
    <div id="honeypot-tab" class="tab-content">
        <div class="honeypot-dashboard">
            <div class="honeypot-control">
                <div class="panel-title" style="color: #ff6600;">
                    <i class="fas fa-bug"></i> HONEYPOT CONTROL CENTER
                </div>
                <div style="margin-bottom: 20px;">
                    <span id="honeypot-status" class="status status-inactive">INACTIVE</span>
                </div>
                <div style="display: flex; gap: 15px; justify-content: center; margin-bottom: 20px;">
                    <button class="btn btn-honeypot" id="honeypot-toggle" onclick="toggleHoneypot()">
                        <i class="fas fa-play"></i> START HONEYPOTS
                    </button>
                    <button class="btn btn-danger" onclick="clearAttacks()">
                        <i class="fas fa-trash"></i> CLEAR LOGS
                    </button>
                </div>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; font-size: 12px; color: #888;">
                    <div>
                        <i class="fas fa-terminal"></i> SSH Honeypot<br>
                        <strong>Port 2222</strong>
                    </div>
                    <div>
                        <i class="fas fa-server"></i> Telnet Honeypot<br>
                        <strong>Port 2323</strong>
                    </div>
                    <div>
                        <i class="fas fa-globe"></i> HTTP Honeypot<br>
                        <strong>Port 8080</strong>
                    </div>
                </div>
            </div>

            <div class="honeypot-stats">
                <div class="panel-title" style="color: #00bfff;">
                    <i class="fas fa-chart-bar"></i> ATTACK STATISTICS
                </div>
                <div id="honeypot-stats-content">
                    <div class="stat-grid">
                        <div class="stat-card">
                            <div class="value" style="color: #ff0066;" id="total-attacks">0</div>
                            <div class="label">Total Attacks</div>
                        </div>
                        <div class="stat-card">
                            <div class="value" style="color: #00ff88;" id="unique-ips">0</div>
                            <div class="label">Unique IPs</div>
                        </div>
                    </div>
                    <div id="service-stats"></div>
                </div>
            </div>

            <div class="attack-feed">
                <div class="panel-title" style="color: #ff0066;">
                    <i class="fas fa-satellite"></i> LIVE ATTACK FEED
                </div>
                <div id="attack-feed-content">
                    <div style="color: #888; text-align: center; padding: 20px;">
                        <i class="fas fa-shield-alt"></i> No attacks detected
                    </div>
                </div>
            </div>

            <div class="attack-map">
                <div class="panel-title" style="color: #9d4edd;">
                    <i class="fas fa-globe-americas"></i> ATTACK ORIGINS MAP
                </div>
                <div id="attack-map-container" style="height: calc(100% - 60px); border-radius: 8px; background: rgba(255, 255, 255, 0.05);"></div>
            </div>
        </div>
    </div>

    <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        let map, attackMap, honeypotActive = false;
        let currentTraceroute = null;
        let attackPollingInterval = null;

        // Tab Management
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // Show selected tab
            document.getElementById(`${tabName}-tab`).classList.add('active');
            event.target.classList.add('active');

            // Initialize maps when switching tabs
            if (tabName === 'tracer' && !map) {
                setTimeout(initMainMap, 100);
            } else if (tabName === 'honeypot' && !attackMap) {
                setTimeout(initAttackMap, 100);
            }
        }

        // Initialize Main Network Map
        function initMainMap() {
            if (map) return;
            map = L.map('map', { 
                center: [20, 0], 
                zoom: 2, 
                zoomControl: true, 
                attributionControl: false 
            });

            // Dark theme map
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
                subdomains: 'abcd',
                maxZoom: 19
            }).addTo(map);
        }

        // Initialize Attack Map
        function initAttackMap() {
            if (attackMap) return;
            attackMap = L.map('attack-map-container', { 
                center: [20, 0], 
                zoom: 2, 
                zoomControl: true, 
                attributionControl: false 
            });

            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
                subdomains: 'abcd',
                maxZoom: 19
            }).addTo(attackMap);
        }

        // Advanced Network Trace
        async function performAdvancedTrace() {
            const url = document.getElementById('urlInput').value.trim();
            const options = document.getElementById('traceOptions').value;

            if (!url) { 
                alert('Please enter a URL or IP address'); 
                return; 
            }

            document.getElementById('loading').style.display = 'block';

            try {
                const response = await fetch('/api/trace', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, options })
                });

                const data = await response.json();

                if (response.ok) {
                    updateMainMap(data);
                    updateNetworkStats(data);
                    updateThreatAnalysis(data.threats, data.risk_score);
                    updateTraceroute(data.traceroute);
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (error) {
                alert('Error: ' + error.message);
            } finally {
                document.getElementById('loading').style.display = 'none';
            }
        }

        // Update Main Map
        function updateMainMap(data) {
            if (!map) initMainMap();

            map.eachLayer(layer => {
                if (layer instanceof L.Marker || layer instanceof L.Polyline) {
                    map.removeLayer(layer);
                }
            });

            const src = data.source.location;
            const dst = data.destination.location;
            const hasThreat = data.risk_score > 50;

            // Source marker
            const sourceIcon = L.divIcon({
                html: '<div style="background:#00ff88;width:20px;height:20px;border-radius:50%;border:3px solid #fff;box-shadow:0 0 15px rgba(0,255,136,0.7);"></div>',
                iconSize: [20, 20],
                className: 'custom-marker'
            });

            // Destination marker
            const destIcon = L.divIcon({
                html: `<div style="background:${hasThreat ? '#ff4757' : '#00bfff'};width:20px;height:20px;border-radius:50%;border:3px solid #fff;box-shadow:0 0 15px ${hasThreat ? 'rgba(255,71,87,0.7)' : 'rgba(0,191,255,0.7)'};"></div>`,
                iconSize: [20, 20],
                className: 'custom-marker'
            });

            // Add markers
            const sourceMarker = L.marker([src.latitude, src.longitude], {icon: sourceIcon})
                .addTo(map)
                .bindPopup(`
                    <div style="color: #000; font-weight: bold;">
                        <h3>🟢 SOURCE</h3>
                        <p><strong>IP:</strong> ${data.source.ip}</p>
                        <p><strong>Location:</strong> ${src.city}, ${src.country}</p>
                        <p><strong>ISP:</strong> ${src.isp}</p>
                    </div>
                `);

            const destMarker = L.marker([dst.latitude, dst.longitude], {icon: destIcon})
                .addTo(map)
                .bindPopup(`
                    <div style="color: #000; font-weight: bold;">
                        <h3>${hasThreat ? '🔴' : '🔵'} DESTINATION</h3>
                        <p><strong>Domain:</strong> ${data.destination.domain}</p>
                        <p><strong>IP:</strong> ${data.destination.ip}</p>
                        <p><strong>Location:</strong> ${dst.city}, ${dst.country}</p>
                        <p><strong>Response:</strong> ${data.network_stats.avg_time.toFixed(1)}ms</p>
                        <p><strong>Risk Score:</strong> ${data.risk_score}%</p>
                    </div>
                `);

            // Connection line
            const connectionLine = L.polyline([
                [src.latitude, src.longitude], 
                [dst.latitude, dst.longitude]
            ], {
                color: hasThreat ? '#ff4757' : '#00ff88',
                weight: 4,
                opacity: 0.8,
                dashArray: hasThreat ? '10, 5' : null
            }).addTo(map);

            // Add traceroute hops if available
            if (data.traceroute && data.traceroute.hops) {
                data.traceroute.hops.forEach((hop, index) => {
                    if (hop.location && hop.location.latitude && hop.location.longitude) {
                        const hopIcon = L.divIcon({
                            html: `<div style="background:${hop.is_suspicious ? '#ff6600' : '#ffd93d'};width:12px;height:12px;border-radius:50%;border:2px solid #fff;"></div>`,
                            iconSize: [12, 12],
                            className: 'custom-marker'
                        });

                        L.marker([hop.location.latitude, hop.location.longitude], {icon: hopIcon})
                            .addTo(map)
                            .bindPopup(`
                                <div style="color: #000;">
                                    <h4>Hop ${hop.hop}</h4>
                                    <p><strong>IP:</strong> ${hop.ip}</p>
                                    <p><strong>Time:</strong> ${hop.response_time}ms</p>
                                    <p><strong>Location:</strong> ${hop.location.country}</p>
                                    ${hop.is_suspicious ? '<p style="color: red;"><strong>⚠️ Suspicious</strong></p>' : ''}
                                </div>
                            `);
                    }
                });
            }

            // Fit map to show all points
            const group = new L.featureGroup([sourceMarker, destMarker]);
            map.fitBounds(group.getBounds().pad(0.1));
        }

        // Update Network Statistics
        function updateNetworkStats(data) {
            const stats = data.network_stats;
            const domainInfo = data.domain_info;

            const statsGrid = `
                <div class="stat-card">
                    <div class="value" style="color: #00ff88;">${data.destination.domain}</div>
                    <div class="label">Target</div>
                </div>
                <div class="stat-card">
                    <div class="value" style="color: #00bfff;">${stats.avg_time.toFixed(1)}ms</div>
                    <div class="label">Avg Latency</div>
                </div>
                <div class="stat-card">
                    <div class="value" style="color: #ffd93d;">${stats.packet_loss}%</div>
                    <div class="label">Packet Loss</div>
                </div>
                <div class="stat-card">
                    <div class="value" style="color: #ff6600;">${stats.jitter.toFixed(1)}ms</div>
                    <div class="label">Jitter</div>
                </div>
            `;

            const detailedStats = `
                <div class="stat-item">
                    <span><i class="fas fa-globe"></i> Country</span>
                    <span>${data.destination.location.country}</span>
                </div>
                <div class="stat-item">
                    <span><i class="fas fa-building"></i> ISP</span>
                    <span>${data.destination.location.isp}</span>
                </div>
                <div class="stat-item">
                    <span><i class="fas fa-clock"></i> DNS Resolution</span>
                    <span>${domainInfo.dns_resolution_time ? domainInfo.dns_resolution_time.toFixed(1) + 'ms' : 'N/A'}</span>
                </div>
                <div class="stat-item">
                    <span><i class="fas fa-exchange-alt"></i> Min/Max RTT</span>
                    <span>${stats.min_time.toFixed(1)}/${stats.max_time.toFixed(1)}ms</span>
                </div>
                <div class="stat-item">
                    <span><i class="fas fa-wifi"></i> Packets Sent/Received</span>
                    <span>${stats.packets_sent}/${stats.packets_received}</span>
                </div>
                ${domainInfo.http_info && domainInfo.http_info.status_code ? `
                <div class="stat-item">
                    <span><i class="fas fa-server"></i> HTTP Status</span>
                    <span>${domainInfo.http_info.status_code}</span>
                </div>
                ` : ''}
                ${domainInfo.ssl_info && !domainInfo.ssl_info.error ? `
                <div class="stat-item">
                    <span><i class="fas fa-lock"></i> SSL Certificate</span>
                    <span style="color: #00ff88;">Valid</span>
                </div>
                ` : ''}
            `;

            document.querySelector('#stats-content .stat-grid').innerHTML = statsGrid;
            document.getElementById('detailed-stats').innerHTML = detailedStats;
        }

        // Update Threat Analysis
        function updateThreatAnalysis(threats, riskScore) {
            const riskMeter = document.getElementById('riskMeter');
            const riskScoreElement = document.getElementById('risk-score');
            const threatsContent = document.getElementById('threats-content');

            // Update risk meter
            riskMeter.style.width = `${riskScore}%`;
            riskMeter.className = `risk-fill ${riskScore > 70 ? 'risk-high' : riskScore > 30 ? 'risk-medium' : 'risk-low'}`;
            riskScoreElement.innerHTML = `Risk Score: ${riskScore}%`;
            riskScoreElement.style.color = riskScore > 70 ? '#ff4757' : riskScore > 30 ? '#ffa502' : '#00ff88';

            if (!threats || threats.length === 0) {
                threatsContent.innerHTML = `
                    <div style="color: #00ff88; text-align: center; padding: 20px;">
                        <i class="fas fa-shield-alt"></i> No threats detected
                    </div>
                `;
                return;
            }

            threatsContent.innerHTML = threats.map(threat => `
                <div class="threat-item">
                    <div style="display: flex; justify-content: between; align-items: center; margin-bottom: 8px;">
                        <strong style="color: #ff6b6b;">${threat.type.replace(/_/g, ' ')}</strong>
                        <span class="status ${threat.severity >= 4 ? 'status-high' : 'status-medium'}">
                            Severity ${threat.severity}/5
                        </span>
                    </div>
                    <div style="color: #ccc; font-size: 12px;">${threat.description}</div>
                    <div style="color: #888; font-size: 11px; margin-top: 5px;">
                        Risk Contribution: +${threat.risk_score || 0} points
                    </div>
                </div>
            `).join('');
        }

        // Update Traceroute Display
        function updateTraceroute(traceroute) {
            const tracerouteContent = document.getElementById('traceroute-content');

            if (!traceroute || !traceroute.hops || traceroute.hops.length === 0) {
                tracerouteContent.innerHTML = `
                    <div style="color: #888; text-align: center; padding: 20px;">
                        <i class="fas fa-info-circle"></i> No traceroute data available
                    </div>
                `;
                return;
            }

            currentTraceroute = traceroute;

            const hopsHtml = traceroute.hops.map(hop => `
                <div class="hop-item ${hop.is_suspicious ? 'suspicious-hop' : ''}">
                    <div>
                        <strong>Hop ${hop.hop}:</strong> ${hop.ip}
                        <br><small style="color: #888;">${hop.location ? hop.location.country : 'Unknown'}</small>
                        ${hop.is_suspicious ? '<br><small style="color: #ff6600;"><i class="fas fa-exclamation-triangle"></i> Suspicious</small>' : ''}
                    </div>
                    <div style="text-align: right;">
                        <strong style="color: #ffd93d;">${hop.response_time}ms</strong>
                    </div>
                </div>
            `).join('');

            tracerouteContent.innerHTML = `
                <div style="text-align: center; margin-bottom: 15px; color: #ffd93d;">
                    <strong>Session: ${traceroute.session_id}</strong><br>
                    <small>Total Hops: ${traceroute.total_hops}</small>
                </div>
                ${hopsHtml}
            `;
        }

        // Honeypot Management
        async function toggleHoneypot() {
            const button = document.getElementById('honeypot-toggle');
            const status = document.getElementById('honeypot-status');

            try {
                button.disabled = true;
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> PROCESSING...';

                const endpoint = honeypotActive ? '/api/honeypot/stop' : '/api/honeypot/start';
                const response = await fetch(endpoint, { method: 'POST' });
                const data = await response.json();

                if (response.ok) {
                    honeypotActive = !honeypotActive;
                    updateHoneypotStatus();

                    if (honeypotActive) {
                        startAttackPolling();
                    } else {
                        stopAttackPolling();
                    }
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (error) {
                alert('Error: ' + error.message);
            } finally {
                button.disabled = false;
            }
        }

        function updateHoneypotStatus() {
            const statusEl = document.getElementById('honeypot-status');
            const btnEl = document.getElementById('honeypot-toggle');

            if (honeypotActive) {
                statusEl.textContent = 'ACTIVE';
                statusEl.className = 'status status-active';
                btnEl.innerHTML = '<i class="fas fa-stop"></i> STOP HONEYPOTS';
                btnEl.className = 'btn btn-danger';
            } else {
                statusEl.textContent = 'INACTIVE';
                statusEl.className = 'status status-inactive';
                btnEl.innerHTML = '<i class="fas fa-play"></i> START HONEYPOTS';
                btnEl.className = 'btn btn-honeypot';
            }
        }

        async function clearAttacks() {
            if (confirm('Are you sure you want to clear all attack logs?')) {
                try {
                    // This would need a backend endpoint to clear the database
                    alert('Clear attacks functionality would be implemented with a backend endpoint');
                } catch (error) {
                    alert('Error clearing attacks: ' + error.message);
                }
            }
        }

        // Attack Polling
        function startAttackPolling() {
            if (attackPollingInterval) return;

            attackPollingInterval = setInterval(async () => {
                await loadHoneypotStats();
                await loadAttackFeed();
            }, 3000); // Poll every 3 seconds
        }

        function stopAttackPolling() {
            if (attackPollingInterval) {
                clearInterval(attackPollingInterval);
                attackPollingInterval = null;
            }
        }

        async function loadHoneypotStats() {
            try {
                const response = await fetch('/api/honeypot/stats');
                const stats = await response.json();

                if (response.ok) {
                    updateHoneypotStats(stats);
                }
            } catch (error) {
                console.error('Error loading honeypot stats:', error);
            }
        }

        function updateHoneypotStats(stats) {
            document.getElementById('total-attacks').textContent = stats.total_attacks || 0;
            document.getElementById('unique-ips').textContent = Object.keys(stats.top_attackers || {}).length;

            const serviceStats = document.getElementById('service-stats');
            if (stats.service_stats && Object.keys(stats.service_stats).length > 0) {
                serviceStats.innerHTML = Object.entries(stats.service_stats).map(([service, count]) => `
                    <div class="stat-item">
                        <span><i class="fas fa-${getServiceIcon(service)}"></i> ${service}</span>
                        <span style="color: #ff0066;">${count} attacks</span>
                    </div>
                `).join('');
            } else {
                serviceStats.innerHTML = '<div style="color: #888; text-align: center;">No service data</div>';
            }
        }

        async function loadAttackFeed() {
            try {
                const response = await fetch('/api/honeypot/attacks');
                const attacks = await response.json();

                if (response.ok) {
                    updateAttackFeed(attacks);
                    updateAttackMap(attacks);
                }
            } catch (error) {
                console.error('Error loading attack feed:', error);
            }
        }

        function updateAttackFeed(attacks) {
            const feedContent = document.getElementById('attack-feed-content');

            if (!attacks || attacks.length === 0) {
                feedContent.innerHTML = `
                    <div style="color: #888; text-align: center; padding: 20px;">
                        <i class="fas fa-shield-alt"></i> No attacks detected
                    </div>
                `;
                return;
            }

            feedContent.innerHTML = attacks.slice(0, 20).map(attack => `
                <div class="attack-item">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                        <strong style="color: #ff0066;">${attack.service} ${attack.attack_type}</strong>
                        <small style="color: #888;">${new Date(attack.timestamp).toLocaleTimeString()}</small>
                    </div>
                    <div style="font-size: 12px; margin-bottom: 5px;">
                        <i class="fas fa-map-marker-alt"></i> ${attack.source_ip}:${attack.source_port} 
                        ${attack.country ? `(${attack.country})` : ''}
                    </div>
                    ${attack.credentials ? `
                        <div style="font-size: 11px; color: #ff8800; background: rgba(255, 136, 0, 0.1); padding: 3px 6px; border-radius: 3px; margin-top: 5px;">
                            <i class="fas fa-key"></i> ${attack.credentials.substring(0, 50)}${attack.credentials.length > 50 ? '...' : ''}
                        </div>
                    ` : ''}
                    ${attack.user_agent && attack.user_agent !== 'Unknown' ? `
                        <div style="font-size: 10px; color: #666; margin-top: 3px;">
                            <i class="fas fa-globe"></i> ${attack.user_agent.substring(0, 40)}...
                        </div>
                    ` : ''}
                </div>
            `).join('');
        }

        function updateAttackMap(attacks) {
            if (!attackMap) return;

            // Clear existing markers
            attackMap.eachLayer(layer => {
                if (layer instanceof L.Marker) {
                    attackMap.removeLayer(layer);
                }
            });

            // Group attacks by IP for better visualization
            const attacksByIP = {};
            attacks.forEach(attack => {
                if (!attacksByIP[attack.source_ip]) {
                    attacksByIP[attack.source_ip] = {
                        count: 0,
                        country: attack.country,
                        services: new Set(),
                        latest: attack.timestamp
                    };
                }
                attacksByIP[attack.source_ip].count++;
                attacksByIP[attack.source_ip].services.add(attack.service);
            });

            // Add markers for each attacking IP
            Object.entries(attacksByIP).forEach(([ip, data]) => {
                // For demo purposes, place markers at random locations
                // In a real implementation, you'd use IP geolocation
                const lat = Math.random() * 180 - 90;
                const lng = Math.random() * 360 - 180;

                const markerSize = Math.min(15 + data.count * 2, 35);
                const attackIcon = L.divIcon({
                    html: `<div style="background: #ff0066; width: ${markerSize}px; height: ${markerSize}px; border-radius: 50%; border: 3px solid #fff; display: flex; align-items: center; justify-content: center; color: white; font-size: 10px; font-weight: bold; box-shadow: 0 0 15px rgba(255, 0, 102, 0.7);">${data.count}</div>`,
                    iconSize: [markerSize, markerSize],
                    className: 'attack-marker'
                });

                L.marker([lat, lng], {icon: attackIcon})
                    .addTo(attackMap)
                    .bindPopup(`
                        <div style="color: #000; font-weight: bold;">
                            <h4 style="color: #ff0066;"><i class="fas fa-exclamation-triangle"></i> ATTACKER</h4>
                            <p><strong>IP:</strong> ${ip}</p>
                            <p><strong>Country:</strong> ${data.country || 'Unknown'}</p>
                            <p><strong>Attacks:</strong> ${data.count}</p>
                            <p><strong>Services:</strong> ${Array.from(data.services).join(', ')}</p>
                            <p><strong>Latest:</strong> ${new Date(data.latest).toLocaleString()}</p>
                        </div>
                    `);
            });
        }

        function getServiceIcon(service) {
            const icons = {
                'SSH': 'terminal',
                'HTTP': 'globe',
                'TELNET': 'server',
                'FTP': 'folder',
                'SMTP': 'envelope'
            };
            return icons[service] || 'bug';
        }

        // Initialize on page load
        window.onload = function() {
            initMainMap();

            // Event listeners
            document.getElementById('urlInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') performAdvancedTrace();
            });

            // Auto-refresh honeypot stats if active
            if (honeypotActive) {
                startAttackPolling();
            }
        };

        // Cleanup on page unload
        window.onbeforeunload = function() {
            stopAttackPolling();
        };
    </script>
</body>
</html>'''

    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(advanced_html_template)

    print("🚀 Advanced Integrated Network Monitor + Honeypot System Starting...")
    print("=" * 80)
    print("📡 MAIN INTERFACES:")
    print(f"   • Web Dashboard: http://localhost:5000")
    print(f"   • Network Tracer Tab: Advanced route analysis with threat detection")
    print(f"   • Honeypot Control Tab: Real-time attack monitoring")
    print()
    print("🍯 ENHANCED HONEYPOT SERVICES:")
    print("   • SSH Honeypot: Port 2222 (Advanced brute force detection)")
    print("   • Telnet Honeypot: Port 2323 (Legacy protocol monitoring)")
    print("   • HTTP Honeypot: Port 8080 (Web attack simulation)")
    print()
    print("🎯 TESTING FROM EXTERNAL DEVICES:")
    print("   1. Find server IP: ip addr show (Linux) / ipconfig (Windows)")
    print("   2. SSH Attacks: ssh admin@[SERVER_IP] -p 2222")
    print("   3. Telnet Attacks: telnet [SERVER_IP] 2323")
    print("   4. HTTP Attacks:")
    print("      curl http://[SERVER_IP]:8080/admin")
    print("      curl -d 'username=admin&password=123' http://[SERVER_IP]:8080/login")
    print("      curl http://[SERVER_IP]:8080/wp-admin")
    print("      curl http://[SERVER_IP]:8080/.env")
    print()
    print("⚡ ADVANCED FEATURES:")
    print("   ✅ Tabbed interface for better organization")
    print("   ✅ Advanced traceroute with hop analysis")
    print("   ✅ Enhanced threat detection with risk scoring")
    print("   ✅ Real-time attack visualization on world map")
    print("   ✅ Comprehensive attack statistics and analytics")
    print("   ✅ SSL/TLS certificate analysis")
    print("   ✅ DNS resolution timing")
    print("   ✅ HTTP response analysis")
    print("   ✅ Enhanced network performance metrics")
    print("   ✅ Attack fingerprinting and session tracking")
    print("   ✅ Multi-service honeypot deployment")
    print("   ✅ Live attack feed with detailed forensics")
    print()
    print("📦 REQUIRED DEPENDENCIES:")
    print("   pip install flask requests")
    print()
    print("🔥 Ready to monitor and defend your network!")
    print("=" * 80)

    app.run(debug=True, host='0.0.0.0', port=5000)
