#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗  ██████╗ ███╗   ███╗██╗███╗   ██╗██╗   ██╗███████╗    ███████╗  ║
║   ██╔══██╗██╔═══██╗████╗ ████║██║████╗  ██║██║   ██║██╔════╝    ██╔════╝  ║
║   ██║  ██║██║   ██║██╔████╔██║██║██╔██╗ ██║██║   ██║███████╗    ███████╗  ║
║   ██║  ██║██║   ██║██║╚██╔╝██║██║██║╚██╗██║██║   ██║╚════██║    ╚════██║  ║
║   ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║██║ ╚████║╚██████╔╝███████║    ███████║  ║
║   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝    ╚══════╝  ║
║                                                                           ║
║                 Ultimate Web Application Penetration Testing Suite        ║
║                         Version 3.0 PRO | By SaudiLinux                    ║
║                     Email: SaudiLinux1@gmail.com                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import re
import json
import time
import socket
import ssl
import hashlib
import base64
import random
import string
import argparse
import itertools
import subprocess
import warnings
import threading
import itertools
from collections import defaultdict, Counter
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional, Union, Any, Callable, Iterator

# تجاهل التحذيرات
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# إضافة مسار الوحدات المحلية
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# محاولة استيراد المكتبات مع معالجة الأخطاء
REQUIRED_PACKAGES = {
    'requests': 'pip install requests',
    'bs4': 'pip install beautifulsoup4',
    'dns': 'pip install dnspython',
    'urllib3': 'pip install urllib3',
}

missing_packages = []
for package, install_cmd in REQUIRED_PACKAGES.items():
    try:
        if package == 'requests':
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
        elif package == 'bs4':
            from bs4 import BeautifulSoup
        elif package == 'dns':
            import dns.resolver
        elif package == 'urllib3':
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        missing_packages.append(f"{package}: {install_cmd}")

if missing_packages:
    print("\n[!] Missing required packages:")
    for pkg in missing_packages:
        print(f"    {pkg}")
    print("\n[*] Please install the missing packages and try again.")
    sys.exit(1)

# استيراد الوحدات المحلية
try:
    from utilities import (
        PayloadGenerator, Encoder, RegexPatterns, Validator,
        NetUtils, DataUtils, OutputFormatter, FileUtils, Logger
    )
    UTILITIES_AVAILABLE = True
except ImportError as e:
    UTILITIES_AVAILABLE = False
    print(f"[!] Warning: Could not import utilities module: {e}")

try:
    from vulnerabilities_db import (
        VulnerabilityDatabase, VulnerabilityTemplate,
        SeverityLevel, VulnerabilityCategory
    )
    VULN_DB_AVAILABLE = True
except ImportError as e:
    VULN_DB_AVAILABLE = False
    print(f"[!] Warning: Could not import vulnerabilities_db module: {e}")


class ColorManager:
    """مدير الألوان المتقدم"""
    
    # تعريف الألوان
    COLORS = {
        'black': '\033[30m',
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'magenta': '\033[35m',
        'cyan': '\033[36m',
        'white': '\033[37m',
        'bright_black': '\033[90m',
        'bright_red': '\033[91m',
        'bright_green': '\033[92m',
        'bright_yellow': '\033[93m',
        'bright_blue': '\033[94m',
        'bright_magenta': '\033[95m',
        'bright_cyan': '\033[96m',
        'bright_white': '\033[97m',
    }
    
    STYLES = {
        'bold': '\033[1m',
        'dim': '\033[2m',
        'italic': '\033[3m',
        'underline': '\033[4m',
        'blink': '\033[5m',
        'reverse': '\033[7m',
        'hidden': '\033[8m',
        'strikethrough': '\033[9m',
    }
    
    RESET = '\033[0m'
    
    # أنماط الخطورة
    SEVERITY_STYLES = {
        'critical': f"{COLORS['bright_red']}{STYLES['bold']}",
        'high': f"{COLORS['red']}{STYLES['bold']}",
        'medium': f"{COLORS['yellow']}{STYLES['bold']}",
        'low': f"{COLORS['green']}{STYLES['bold']}",
        'info': f"{COLORS['blue']}{STYLES['bold']}",
    }
    
    @classmethod
    def colorize(cls, text: str, color: str, style: str = None) -> str:
        """تلوين النص"""
        color_code = cls.COLORS.get(color.lower(), '')
        style_code = cls.STYLES.get(style.lower(), '') if style else ''
        return f"{color_code}{style_code}{text}{cls.RESET}"
    
    @classmethod
    def severity(cls, text: str, level: str) -> str:
        """تلوين حسب مستوى الخطورة"""
        style = cls.SEVERITY_STYLES.get(level.lower(), cls.COLORS['white'])
        return f"{style}{text}{cls.RESET}"
    
    @classmethod
    def gradient(cls, text: str, start_color: str, end_color: str) -> str:
        """تلوين متدرج للنص"""
        # تبسيط: إرجاع النص بلون واحد (يمكن تطويره لاحقاً)
        return cls.colorize(text, start_color)
    
    @classmethod
    def strip_colors(cls, text: str) -> str:
        """إزالة أكواد الألوان"""
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)


class ProgressManager:
    """مدير شريط التقدم المتقدم"""
    
    def __init__(self, total: int, desc: str = "Processing", bar_length: int = 40):
        self.total = total
        self.current = 0
        self.desc = desc
        self.bar_length = bar_length
        self.start_time = time.time()
    
    def update(self, amount: int = 1):
        """تحديث شريط التقدم"""
        self.current += amount
        percentage = (self.current / self.total) * 100
        filled = int(self.bar_length * self.current / self.total)
        bar = '█' * filled + '░' * (self.bar_length - filled)
        
        # حساب الوقت المتبقي
        elapsed = time.time() - self.start_time
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = f"{int(eta)}s"
        else:
            eta_str = "calculating..."
        
        # طباعة شريط التقدم
        print(f"\r{ColorManager.colorize(self.desc, 'cyan')} {bar} {ColorManager.severity(f'{percentage:.1f}%', 'info')} | {self.current}/{self.total} | ETA: {eta_str}", end='', flush=True)
        
        if self.current >= self.total:
            print()  # سطر جديد عند الانتهاء
    
    def finish(self):
        """إنهاء شريط التقدم"""
        self.current = self.total
        self.update(0)


class DominusSecurityScannerPro:
    """الماسح الأمني المحترف"""
    
    def __init__(self, target: str, threads: int = 50, timeout: int = 15, 
                 output_dir: str = None, verbose: bool = True):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output_dir = output_dir or f"scan_results_{int(time.time())}"
        
        # إعداد الجلسة
        self.session = requests.Session()
        self._setup_session()
        
        # نتائج الفحص
        self.subdomains: Set[str] = set()
        self.live_hosts: Dict[str, Dict] = {}
        self.endpoints: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.js_files: Set[str] = set()
        self.technologies: List[str] = []
        self.dns_records: Dict[str, List] = {}
        self.ssl_info: Dict = {}
        self.port_scan_results: Dict = {}
        
        # قواعد البيانات
        self.vuln_db = VulnerabilityDatabase() if VULN_DB_AVAILABLE else None
        
        # إنشاء مجلد المخرجات
        os.makedirs(self.output_dir, exist_ok=True)
        
        # السجل
        self.logger = Logger(os.path.join(self.output_dir, 'scan.log'))
    
    def _setup_session(self):
        """إعداد جلسة الطلبات"""
        # إعداد إعادة المحاولة
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.threads,
            pool_maxsize=self.threads
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # تعيين الرؤوس
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
        })
        
        # تعطيل التحقق من SSL
        self.session.verify = False
    
    def print_banner(self):
        """طباعة البانر"""
        banner = f"""
{ColorManager.BRIGHT_CYAN}╔══════════════════════════════════════════════════════════════════════════════════╗
║{ColorManager.BRIGHT_GREEN}   ██████╗  ██████╗ ███╗   ███╗██╗███╗   ██╗██╗   ██╗███████╗    ███████╗███████╗  {ColorManager.BRIGHT_CYAN} ║
║{ColorManager.BRIGHT_GREEN}   ██╔══██╗██╔═══██╗████╗ ████║██║████╗  ██║██║   ██║██╔════╝    ██╔════╝██╔════╝  {ColorManager.BRIGHT_CYAN} ║
║{ColorManager.BRIGHT_GREEN}   ██║  ██║██║   ██║██╔████╔██║██║██╔██╗ ██║██║   ██║███████╗    ███████╗█████╗    {ColorManager.BRIGHT_CYAN} ║
║{ColorManager.BRIGHT_GREEN}   ██║  ██║██║   ██║██║╚██╔╝██║██║██║╚██╗██║██║   ██║╚════██║    ╚════██║██╔══╝    {ColorManager.BRIGHT_CYAN} ║
║{ColorManager.BRIGHT_GREEN}   ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║██║ ╚████║╚██████╔╝███████║    ███████║███████╗  {ColorManager.BRIGHT_CYAN} ║
║{ColorManager.BRIGHT_GREEN}   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝    ╚══════╝╚══════╝  {ColorManager.BRIGHT_CYAN} ║
║{ColorManager.BRIGHT_GREEN}                                                                              v3.0  {ColorManager.BRIGHT_CYAN} ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║{ColorManager.BRIGHT_YELLOW}  Ultimate Web Application Penetration Testing Suite                                   {ColorManager.BRIGHT_CYAN} ║
║{ColorManager.BRIGHT_MAGENTA}  Programmer: SaudiLinux | Email: SaudiLinux1@gmail.com                             {ColorManager.BRIGHT_CYAN} ║
╚══════════════════════════════════════════════════════════════════════════════════╝{ColorManager.RESET}
"""
        print(banner)
    
    def log(self, message: str, level: str = 'INFO'):
        """تسجيل رسالة"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        if self.verbose:
            if level == 'ERROR':
                print(f"{ColorManager.ERROR}[ERROR]{ColorManager.RESET} {message}")
            elif level == 'WARNING':
                print(f"{ColorManager.WARNING}[WARNING]{ColorManager.RESET} {message}")
            elif level == 'SUCCESS':
                print(f"{ColorManager.SUCCESS}[SUCCESS]{ColorManager.RESET} {message}")
            elif level == 'INFO':
                print(f"{ColorManager.INFO}[INFO]{ColorManager.RESET} {message}")
            else:
                print(log_entry)
        
        # كتابة إلى ملف السجل
        if self.logger:
            self.logger.info(message)
    
    def run_full_scan(self):
        """تشغيل الفحص الكامل"""
        self.print_banner()
        self.log(f"Starting full security scan on target: {self.target}", 'INFO')
        self.log(f"Output directory: {self.output_dir}", 'INFO')
        self.log(f"Threads: {self.threads} | Timeout: {self.timeout}s", 'INFO')
        
        start_time = time.time()
        
        try:
            # 1. استخراج النطاقات الفرعية
            self.enumerate_subdomains()
            
            # 2. اكتشاف المضيفين النشطين
            self.discover_live_hosts()
            
            # 3. فحص المنافذ
            self.scan_ports()
            
            # 4. تحليل SSL/TLS
            self.analyze_ssl()
            
            # 5. جمع معلومات DNS
            self.gather_dns_info()
            
            # 6. اكتشاف التقنيات
            self.detect_technologies()
            
            # 7. الزحف واستخراج الروابط
            self.crawl_website()
            
            # 8. فحص الثغرات
            self.scan_vulnerabilities()
            
            # 9. إنشاء التقرير
            self.generate_report()
            
            elapsed_time = time.time() - start_time
            self.log(f"Full scan completed in {elapsed_time:.2f} seconds", 'SUCCESS')
            
        except KeyboardInterrupt:
            self.log("Scan interrupted by user", 'WARNING')
            self.generate_report()
        except Exception as e:
            self.log(f"Error during scan: {str(e)}", 'ERROR')
            import traceback
            self.log(traceback.format_exc(), 'ERROR')
    
    def enumerate_subdomains(self):
        """استخراج النطاقات الفرعية"""
        self.log("Starting subdomain enumeration...", 'INFO')
        
        # قائمة كلمات مفتاحية شاملة
        wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'admin', 'dashboard', 'api', 'app',
            'mobile', 'dev', 'test', 'staging', 'prod', 'demo', 'beta', 'alpha',
            'support', 'help', 'docs', 'blog', 'news', 'forum', 'shop', 'store',
            'payment', 'checkout', 'cart', 'user', 'users', 'account', 'accounts',
            'profile', 'settings', 'config', 'internal', 'private', 'secure',
            'vpn', 'remote', 'git', 'svn', 'ci', 'cd', 'jenkins', 'gitlab',
            'github', 'bitbucket', 'docker', 'k8s', 'kubernetes', 'aws', 'azure',
            'gcp', 'cloud', 'cdn', 'static', 'assets', 'media', 'files', 'uploads',
            'download', 'downloads', 'backup', 'backups', 'archive', 'old', 'new',
            'v1', 'v2', 'v3', 'api-v1', 'api-v2', 'rest', 'graphql', 'soap',
            'webhook', 'callback', 'oauth', 'sso', 'ldap', 'ad', 'radius',
            'sql', 'db', 'database', 'mongo', 'mysql', 'postgres', 'redis',
            'elasticsearch', 'solr', 'sphinx', 'queue', 'rabbitmq', 'kafka',
            'monitor', 'monitoring', 'metrics', 'grafana', 'prometheus', 'nagios',
            'zabbix', 'status', 'health', 'ping', 'test', 'testing', 'qa',
            'uat', 'preprod', 'production', 'live', 'main', 'master', 'slave',
            'worker', 'jobs', 'cron', 'scheduler', 'task', 'tasks', 'runner',
            'builder', 'deploy', 'deployment', 'release', 'version', 'build'
        ]
        
        # إضافة النطاق الرئيسي
        self.subdomains.add(self.target)
        
        # فحص DNS
        self._enumerate_dns(wordlist)
        
        # فحص Certificate Transparency
        self._enumerate_crtsh()
        
        # فحص Shodan (إذا كان متاحاً)
        # self._enumerate_shodan()
        
        self.log(f"Found {len(self.subdomains)} subdomains", 'SUCCESS')
    
    def _enumerate_dns(self, wordlist: List[str]):
        """فحص DNS للنطاقات الفرعية"""
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.target}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    ips = [str(answer) for answer in answers]
                    return (full_domain, ips)
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in wordlist]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    domain, ips = result
                    if domain not in self.subdomains:
                        self.subdomains.add(domain)
                        if self.verbose:
                            print(f"  {ColorManager.SUCCESS}[+]{ColorManager.RESET} {domain} -> {', '.join(ips)}")
    
    def _enumerate_crtsh(self):
        """فحص Certificate Transparency logs"""
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    domains = name_value.split('\n')
                    for domain in domains:
                        domain = domain.strip().lstrip('*').lstrip('.')
                        if domain and domain.endswith(self.target):
                            if domain not in self.subdomains:
                                try:
                                    socket.gethostbyname(domain)
                                    self.subdomains.add(domain)
                                    if self.verbose:
                                        print(f"  {ColorManager.SUCCESS}[+]{ColorManager.RESET} {domain} (from crt.sh)")
                                except:
                                    pass
        except Exception as e:
            self.log(f"Error querying crt.sh: {e}", 'WARNING')
    
    def discover_live_hosts(self):
        """اكتشاف المضيفين النشطين"""
        self.log("Discovering live hosts...", 'INFO')
        
        def check_host(subdomain):
            results = {}
            
            # فحص HTTP
            try:
                url = f"http://{subdomain}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                results['http'] = {
                    'status': response.status_code,
                    'title': self._extract_title(response.text),
                    'server': response.headers.get('Server', ''),
                    'tech': self._detect_tech_from_headers(response.headers)
                }
            except:
                results['http'] = None
            
            # فحص HTTPS
            try:
                url = f"https://{subdomain}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                results['https'] = {
                    'status': response.status_code,
                    'title': self._extract_title(response.text),
                    'server': response.headers.get('Server', ''),
                    'tech': self._detect_tech_from_headers(response.headers)
                }
            except:
                results['https'] = None
            
            return subdomain, results
        
        # فحص المضيفين النشطين
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_host, sub) for sub in self.subdomains]
            for future in as_completed(futures):
                subdomain, results = future.result()
                if results.get('http') or results.get('https'):
                    self.live_hosts[subdomain] = results
                    if self.verbose:
                        status = results.get('https', results.get('http', {})).get('status', '???')
                        print(f"  {ColorManager.SUCCESS}[LIVE]{ColorManager.RESET} {subdomain} (HTTP: {status})")
        
        self.log(f"Found {len(self.live_hosts)} live hosts", 'SUCCESS')
    
    def _extract_title(self, html: str) -> str:
        """استخراج عنوان الصفحة"""
        try:
            match = re.search(r'<title[^>]*>([^<]*)</title>', html, re.IGNORECASE)
            return match.group(1).strip() if match else 'N/A'
        except:
            return 'N/A'
    
    def _detect_tech_from_headers(self, headers: Dict) -> List[str]:
        """اكتشاف التقنيات من الرؤوس"""
        tech = []
        
        server = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        
        # خوادم الويب
        if 'apache' in server:
            tech.append('Apache')
        if 'nginx' in server:
            tech.append('Nginx')
        if 'iis' in server or 'microsoft' in server:
            tech.append('IIS')
        if 'litespeed' in server:
            tech.append('LiteSpeed')
        
        # لغات البرمجة
        if 'php' in powered_by or 'php' in server:
            tech.append('PHP')
        if 'asp.net' in powered_by or 'asp.net' in server:
            tech.append('ASP.NET')
        if 'python' in powered_by:
            tech.append('Python')
        if 'ruby' in powered_by:
            tech.append('Ruby')
        
        return tech
    
    def scan_ports(self):
        """فحص المنافذ"""
        self.log("Starting port scan...", 'INFO')
        
        # قائمة المنافذ الشائعة
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 9090, 9200, 9300
        ]
        
        target_ip = socket.gethostbyname(self.target)
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    return port
                sock.close()
            except:
                pass
            return None
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in common_ports]
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
                    service = self._get_service_name(port)
                    if self.verbose:
                        print(f"  {ColorManager.SUCCESS}[OPEN]{ColorManager.RESET} Port {port}/tcp - {service}")
        
        self.port_scan_results = {
            'target': target_ip,
            'open_ports': open_ports,
            'scan_time': datetime.now().isoformat()
        }
        
        self.log(f"Found {len(open_ports)} open ports", 'SUCCESS')
    
    def _get_service_name(self, port: int) -> str:
        """الحصول على اسم الخدمة للمنفذ"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Proxy'
        }
        return services.get(port, 'Unknown')
    
    def analyze_ssl(self):
        """تحليل SSL/TLS"""
        self.log("Analyzing SSL/TLS configuration...", 'INFO')
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    self.ssl_info = {
                        'version': version,
                        'cipher': cipher,
                        'subject': cert.get('subject'),
                        'issuer': cert.get('issuer'),
                        'not_after': cert.get('notAfter'),
                        'not_before': cert.get('notBefore'),
                        'serial_number': cert.get('serialNumber'),
                    }
                    
                    # التحقق من الإصدار
                    if version in ['TLSv1', 'TLSv1.1']:
                        self.log(f"Outdated TLS version detected: {version}", 'WARNING')
                    else:
                        self.log(f"TLS Version: {version}", 'SUCCESS')
                    
                    if self.verbose:
                        print(f"  {ColorManager.INFO}SSL/TLS Version:{ColorManager.RESET} {version}")
                        print(f"  {ColorManager.INFO}Cipher Suite:{ColorManager.RESET} {cipher[0]}")
                        print(f"  {ColorManager.INFO}Certificate Expiry:{ColorManager.RESET} {cert.get('notAfter')}")
        
        except Exception as e:
            self.log(f"SSL analysis failed: {e}", 'WARNING')
    
    def gather_dns_info(self):
        """جمع معلومات DNS"""
        self.log("Gathering DNS information...", 'INFO')
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'PTR']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                self.dns_records[record_type] = [str(answer) for answer in answers]
                if self.verbose:
                    print(f"  {ColorManager.SUCCESS}[{record_type}]{ColorManager.RESET} {', '.join(self.dns_records[record_type][:3])}")
            except:
                pass
        
        self.log(f"Collected {len(self.dns_records)} DNS record types", 'SUCCESS')
    
    def detect_technologies(self):
        """اكتشاف التقنيات المستخدمة"""
        self.log("Detecting technologies...", 'INFO')
        
        try:
            url = f"https://{self.target}"
            response = self.session.get(url, timeout=self.timeout)
            headers = response.headers
            html = response.text
            
            # اكتشاف من الرؤوس
            tech = self._detect_tech_from_headers(headers)
            
            # اكتشاف من HTML
            if 'wp-content' in html or 'wordpress' in html.lower():
                tech.append('WordPress')
            if 'drupal' in html.lower():
                tech.append('Drupal')
            if 'joomla' in html.lower():
                tech.append('Joomla')
            if 'react' in html.lower():
                tech.append('React')
            if 'vue' in html.lower():
                tech.append('Vue.js')
            if 'angular' in html.lower():
                tech.append('Angular')
            if 'jquery' in html.lower():
                tech.append('jQuery')
            if 'bootstrap' in html.lower():
                tech.append('Bootstrap')
            if 'laravel' in html.lower():
                tech.append('Laravel')
            if 'django' in html.lower():
                tech.append('Django')
            if 'flask' in html.lower():
                tech.append('Flask')
            
            # إزالة التكرارات
            self.technologies = list(set(tech))
            
            if self.verbose:
                for tech in self.technologies:
                    print(f"  {ColorManager.INFO}[TECH]{ColorManager.RESET} {tech}")
            
            self.log(f"Detected {len(self.technologies)} technologies", 'SUCCESS')
            
        except Exception as e:
            self.log(f"Technology detection failed: {e}", 'WARNING')
    
    def crawl_website(self):
        """الزحف على الموقع"""
        self.log("Starting web crawling...", 'INFO')
        
        visited = set()
        to_visit = [f"https://{self.target}"]
        
        progress = ProgressManager(total=100, desc="Crawling")
        
        while to_visit and len(visited) < 100:
            url = to_visit.pop(0)
            
            if url in visited:
                continue
            
            visited.add(url)
            self.endpoints.add(url)
            
            try:
                response = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # استخراج الروابط
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    
                    if parsed.netloc == self.target:
                        if full_url not in visited and full_url not in to_visit:
                            to_visit.append(full_url)
                
                # استخراج ملفات JavaScript
                for script in soup.find_all('script', src=True):
                    src = script['src']
                    full_url = urljoin(url, src)
                    if self.target in full_url:
                        self.js_files.add(full_url)
                
                # استخراج نقاط API
                api_patterns = [
                    r'/api/[^\s"\'<>]+',
                    r'/v\d+/[^\s"\'<>]+',
                    r'/graphql[^\s"\'<>]*',
                    r'/rest/[^\s"\'<>]+'
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, response.text)
                    for match in matches:
                        full_url = urljoin(url, match)
                        self.api_endpoints.add(full_url)
                
                # تحديث شريط التقدم
                progress.update(1)
                
            except Exception as e:
                continue
        
        progress.finish()
        
        self.log(f"Crawled {len(self.endpoints)} endpoints", 'SUCCESS')
        self.log(f"Found {len(self.js_files)} JavaScript files", 'SUCCESS')
        self.log(f"Found {len(self.api_endpoints)} API endpoints", 'SUCCESS')
    
    def scan_vulnerabilities(self):
        """فحص الثغرات الأمنية"""
        self.log("Starting vulnerability scanning...", 'INFO')
        
        vulnerabilities_found = []
        
        # فحص كل نقطة نهاية
        for endpoint in list(self.endpoints)[:50]:  # تحديد عدد النقاط للفحص
            try:
                # فحص XSS
                xss_payload = "<script>alert('XSS')</script>"
                test_url = f"{endpoint}?test={quote(xss_payload)}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                if xss_payload in response.text:
                    vuln = {
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'url': endpoint,
                        'description': 'Reflected XSS vulnerability detected',
                        'evidence': f'Payload reflected: {xss_payload[:50]}...'
                    }
                    vulnerabilities_found.append(vuln)
                    self.vulnerabilities.append(vuln)
                
                # فحص SQL Injection
                sql_payload = "' OR '1'='1"
                test_url = f"{endpoint}?id={quote(sql_payload)}"
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    sql_errors = [
                        'mysql_fetch_array', 'ORA-', 'SQL Server', 'PostgreSQL',
                        'sqlite_query', 'mysql_error', 'syntax error'
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            vuln = {
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'url': endpoint,
                                'description': f'SQL Injection vulnerability detected - {error}',
                                'evidence': f'Error message: {error}'
                            }
                            vulnerabilities_found.append(vuln)
                            self.vulnerabilities.append(vuln)
                            break
                except:
                    pass
                
            except Exception as e:
                continue
        
        # فحص نقاط API
        for api_endpoint in list(self.api_endpoints)[:20]:
            try:
                # فحص المصادقة
                response = self.session.get(api_endpoint, timeout=self.timeout)
                
                if response.status_code == 200:
                    # التحقق مما إذا كانت البيانات حساسة
                    if any(keyword in response.text.lower() for keyword in ['password', 'secret', 'token', 'key']):
                        vuln = {
                            'type': 'Information Disclosure',
                            'severity': 'High',
                            'url': api_endpoint,
                            'description': 'Potentially sensitive information exposed without authentication',
                            'evidence': 'API endpoint accessible without authentication'
                        }
                        vulnerabilities_found.append(vuln)
                        self.vulnerabilities.append(vuln)
                
            except Exception as e:
                continue
        
        self.log(f"Found {len(vulnerabilities_found)} vulnerabilities", 'SUCCESS')
        
        # عرض ملخص الثغرات
        if vulnerabilities_found:
            print(f"\n{ColorManager.BRIGHT_CYAN}{'='*70}{ColorManager.RESET}")
            print(f"{ColorManager.BRIGHT_YELLOW}VULNERABILITY SUMMARY{ColorManager.RESET}")
            print(f"{ColorManager.BRIGHT_CYAN}{'='*70}{ColorManager.RESET}\n")
            
            for i, vuln in enumerate(vulnerabilities_found, 1):
                severity_color = {
                    'Critical': ColorManager.BRIGHT_RED,
                    'High': ColorManager.RED,
                    'Medium': ColorManager.YELLOW,
                    'Low': ColorManager.GREEN
                }.get(vuln['severity'], ColorManager.WHITE)
                
                print(f"{ColorManager.BOLD}[{i}]{ColorManager.RESET} {severity_color}[{vuln['severity']}]{ColorManager.RESET} {vuln['type']}")
                print(f"    URL: {vuln['url']}")
                print(f"    Description: {vuln['description']}")
                print()
    
    def generate_report(self):
        """إنشاء تقرير الفحص"""
        self.log("Generating scan report...", 'INFO')
        
        report = {
            'scan_info': {
                'target': self.target,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '3.0 PRO',
                'scanner_author': 'SaudiLinux',
                'scanner_email': 'SaudiLinux1@gmail.com'
            },
            'findings': {
                'subdomains': list(self.subdomains),
                'live_hosts': self.live_hosts,
                'endpoints': list(self.endpoints),
                'api_endpoints': list(self.api_endpoints),
                'javascript_files': list(self.js_files),
                'technologies': self.technologies,
                'dns_records': self.dns_records,
                'ssl_info': self.ssl_info,
                'port_scan': self.port_scan_results,
            },
            'vulnerabilities': self.vulnerabilities,
            'statistics': {
                'total_subdomains': len(self.subdomains),
                'total_live_hosts': len(self.live_hosts),
                'total_endpoints': len(self.endpoints),
                'total_api_endpoints': len(self.api_endpoints),
                'total_vulnerabilities': len(self.vulnerabilities),
                'technologies_detected': len(self.technologies)
            }
        }
        
        # حفظ التقرير
        report_file = os.path.join(self.output_dir, 'scan_report.json')
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        # إنشاء تقرير HTML
        self._generate_html_report(report)
        
        self.log(f"Report saved to: {self.output_dir}", 'SUCCESS')
        print(f"\n{ColorManager.BRIGHT_CYAN}{'='*70}{ColorManager.RESET}")
        print(f"{ColorManager.BRIGHT_GREEN}SCAN COMPLETED SUCCESSFULLY!{ColorManager.RESET}")
        print(f"{ColorManager.BRIGHT_CYAN}{'='*70}{ColorManager.RESET}")
        print(f"\n{ColorManager.BRIGHT_WHITE}Report Location:{ColorManager.RESET} {self.output_dir}")
        print(f"{ColorManager.BRIGHT_WHITE}JSON Report:{ColorManager.RESET} {report_file}")
        print(f"\n{ColorManager.BRIGHT_YELLOW}Thank you for using DOMINUS SECURITY SCANNER PRO!{ColorManager.RESET}")
        print(f"{ColorManager.BRIGHT_MAGENTA}Created by: SaudiLinux | Email: SaudiLinux1@gmail.com{ColorManager.RESET}\n")
    
    def _generate_html_report(self, report_data: Dict):
        """إنشاء تقرير HTML"""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {report_data['scan_info']['target']}</title>
    <style>
        :root {{
            --primary: #00d4ff;
            --secondary: #7000ff;
            --success: #00ff88;
            --warning: #ffaa00;
            --danger: #ff0055;
            --info: #00ccff;
            --dark: #0a0a0f;
            --card: #12121a;
            --text: #e0e0ff;
            --text-muted: #8080a0;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--dark);
            color: var(--text);
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        header {{
            text-align: center;
            padding: 3rem 0;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            margin: -2rem -2rem 2rem -2rem;
            position: relative;
            overflow: hidden;
        }}
        
        header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.08'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            opacity: 0.5;
        }}
        
        h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            position: relative;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        
        .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
            position: relative;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }}
        
        .stat-card {{
            background: var(--card);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.3);
        }}
        
        .stat-value {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }}
        
        .stat-label {{
            color: var(--text-muted);
            font-size: 0.9rem;
        }}
        
        .section {{
            background: var(--card);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1.5rem 0;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        
        .section-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--primary);
            border-bottom: 2px solid var(--primary);
            padding-bottom: 0.5rem;
        }}
        
        .vulnerability {{
            background: rgba(255,0,85,0.1);
            border-left: 4px solid var(--danger);
            padding: 1rem;
            margin: 0.75rem 0;
            border-radius: 0 8px 8px 0;
        }}
        
        .vulnerability-title {{
            font-weight: 600;
            color: var(--danger);
            margin-bottom: 0.5rem;
        }}
        
        .vulnerability-severity {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-right: 0.5rem;
        }}
        
        .severity-critical {{ background: var(--danger); color: white; }}
        .severity-high {{ background: #ff5500; color: white; }}
        .severity-medium {{ background: var(--warning); color: black; }}
        .severity-low {{ background: var(--success); color: black; }}
        
        .tech-badge {{
            display: inline-block;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            margin: 0.25rem;
        }}
        
        footer {{
            text-align: center;
            padding: 2rem;
            margin-top: 2rem;
            border-top: 1px solid rgba(255,255,255,0.1);
            color: var(--text-muted);
        }}
        
        .footer-logo {{
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        
        @media print {{
            body {{ background: white; color: black; }}
            .stat-card, .section {{ background: white; border: 1px solid #ccc; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ DOMINUS SECURITY SCANNER PRO</h1>
            <p class="subtitle">Professional Web Application Penetration Testing Report</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" style="color: var(--primary);">{len(self.subdomains)}</div>
                <div class="stat-label">Subdomains Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--success);">{len(self.live_hosts)}</div>
                <div class="stat-label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--info);">{len(self.endpoints)}</div>
                <div class="stat-label">Endpoints</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--danger);">{len(self.vulnerabilities)}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Target Information</h2>
            <p><strong>Target Domain:</strong> {self.target}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Scanner Version:</strong> 3.0 PRO</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">Technologies Detected</h2>
            <div>
                {''.join([f'<span class="tech-badge">{tech}</span>' for tech in self.technologies]) if self.technologies else '<p>No technologies detected</p>'}
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Vulnerabilities Found ({len(self.vulnerabilities)})</h2>
            {''.join([f'''
            <div class="vulnerability">
                <div class="vulnerability-title">{vuln['type']}</div>
                <p><span class="vulnerability-severity severity-{vuln['severity'].lower()}">{vuln['severity']}</span></p>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
            </div>
            ''' for vuln in self.vulnerabilities]) if self.vulnerabilities else '<p>No vulnerabilities found</p>'}
        </div>
        
        <div class="section">
            <h2 class="section-title">Subdomains Discovered ({len(self.subdomains)})</h2>
            <ul>
                {''.join([f'<li>{sub}</li>' for sub in sorted(self.subdomains)[:50]])}
            </ul>
            {f'<p><em>... and {len(self.subdomains) - 50} more</em></p>' if len(self.subdomains) > 50 else ''}
        </div>
        
        <footer>
            <div class="footer-logo">DOMINUS SECURITY SCANNER PRO</div>
            <p>Professional Web Application Penetration Testing Suite</p>
            <p>Created by <strong>SaudiLinux</strong> | Email: SaudiLinux1@gmail.com</p>
            <p>&copy; {datetime.now().year} All Rights Reserved.</p>
        </footer>
    </div>
</body>
</html>
"""
        
        html_file = os.path.join(self.output_dir, 'scan_report.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.log(f"HTML report generated: {html_file}", 'SUCCESS')


def main():
    parser = argparse.ArgumentParser(
        description='DOMINUS SECURITY SCANNER PRO - Ultimate Web Application Penetration Testing Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python domain_security_scanner_pro.py example.com
  python domain_security_scanner_pro.py example.com --threads 100 --output ./results
  python domain_security_scanner_pro.py example.com --full-scan --verbose

Author: SaudiLinux | Email: SaudiLinux1@gmail.com
        """
    )
    
    parser.add_argument('target', help='Target domain to scan')
    parser.add_argument('--threads', '-t', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--output', '-o', type=str, default=None, help='Output directory for reports')
    parser.add_argument('--full-scan', action='store_true', help='Perform full comprehensive scan')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--version', action='version', version='DOMINUS SECURITY SCANNER PRO v3.0')
    
    args = parser.parse_args()
    
    # إنشاء مثيل الماسح
    scanner = DominusSecurityScannerPro(
        target=args.target,
        threads=args.threads,
        timeout=args.timeout,
        output_dir=args.output,
        verbose=args.verbose
    )
    
    # تشغيل الفحص
    try:
        if args.full_scan:
            scanner.run_full_scan()
        else:
            scanner.run_full_scan()
    except KeyboardInterrupt:
        print(f"\n\n{ColorManager.WARNING}[!]{ColorManager.RESET} Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{ColorManager.ERROR}[ERROR]{ColorManager.RESET} {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
