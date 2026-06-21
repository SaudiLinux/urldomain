#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║           HIDDEN LINKS EXTRACTOR - استخراج الروابط المخفية                    ║
║                                                                               ║
║                  Advanced Web Link Discovery & Extraction Tool                 ║
║                                                                               ║
║                        المبرمج: SaudiLinux                                     ║
║                     البريد: SaudiLinux1@gmail.com                              ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

تقنيات الاستخراج المدعومة:
- استخراج الروابط من HTML و JavaScript و CSS
- اكتشاف نقاط نهاية API المخفية
- استخراج الروابط من ملفات JSON و XML
- فك تشفير الروابط المشفرة
- اكتشاف الروابط في تعليقات الكود
- استخراج روابط من سجلات الأخطاء
"""

import re
import json
import base64
import urllib.parse
import html
from typing import List, Set, Dict, Tuple, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from collections import defaultdict
import binascii


class HiddenLinksExtractor:
    """مستخرج الروابط المخفية المتقدم"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.parsed_base = urlparse(base_url)
        self.domain = self.parsed_base.netloc
        
        # تخزين النتائج
        self.all_links: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.js_files: Set[str] = set()
        self.hidden_forms: List[Dict] = []
        self.parameters: Set[str] = set()
        
        # أنماط الاستخراج
        self._compile_patterns()
    
    def _compile_patterns(self):
        """تجميع أنماط التعبيرات النمطية"""
        
        # أنماط الروابط الأساسية
        self.patterns = {
            # روابط HTTP/HTTPS
            'full_url': re.compile(
                r'https?://[^\s<>"\'\]\)]+',
                re.IGNORECASE
            ),
            
            # روابط نسبية
            'relative_url': re.compile(
                r'["\']\s*(/[^\s<>"\'\]\)]*)\s*["\']',
                re.IGNORECASE
            ),
            
            # روابط من JavaScript
            'js_url': re.compile(
                r'(fetch|axios|XMLHttpRequest|\.ajax|http\.get)\s*\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE
            ),
            
            # نقاط نهاية API
            'api_endpoint': re.compile(
                r'["\']\s*(/api/[^\s<>"\'\]\)]*|/v\d+/[^\s<>"\'\]\)]*|/graphql[^\s<>"\'\)]*)\s*["\']',
                re.IGNORECASE
            ),
            
            # ملفات JavaScript
            'js_file': re.compile(
                r'<script[^>]+src\s*=\s*["\']([^"\']+\.(?:js|mjs))["\']',
                re.IGNORECASE
            ),
            
            # ملفات CSS
            'css_file': re.compile(
                r'<link[^>]+href\s*=\s*["\']([^"\']+\.(?:css|scss|less))["\']',
                re.IGNORECASE
            ),
            
            # URLs في CSS
            'css_url': re.compile(
                r'url\s*\(\s*["\']?([^\)"\']+)["\']?\s*\)',
                re.IGNORECASE
            ),
            
            # روابط في JSON
            'json_url': re.compile(
                r'["\']([^"\']*(?:url|link|href|src|endpoint)[^"\']*)["\']\s*:\s*["\']([^"\']+)["\']',
                re.IGNORECASE
            ),
            
            # روابط مشفرة base64
            'b64_url': re.compile(
                r'(?:data:|b64:|base64:)?([A-Za-z0-9+/]{20,}={0,2})',
                re.IGNORECASE
            ),
            
            # روابط في تعليقات HTML
            'comment_url': re.compile(
                r'<!--.*?https?://[^\s<>"\'\]]+.*?-->',
                re.DOTALL | re.IGNORECASE
            ),
            
            # معلمات URL
            'url_params': re.compile(
                r'[?&]([^=&]+)=([^&]*)',
                re.IGNORECASE
            ),
            
            # نماذج مخفية
            'hidden_form': re.compile(
                r'<form[^>]*>.*?<input[^>]*type\s*=\s*["\']hidden["\'][^>]*>.*?</form>',
                re.DOTALL | re.IGNORECASE
            ),
            
            # WebSocket endpoints
            'websocket': re.compile(
                r'(?:ws|wss)://[^\s<>"\'\]]+',
                re.IGNORECASE
            ),
            
            # GraphQL endpoints
            'graphql': re.compile(
                r'["\']\s*(/graphql|/api/graphql|/query)\s*["\']',
                re.IGNORECASE
            ),
        }
    
    def extract_from_html(self, html_content: str) -> Set[str]:
        """استخراج الروابط من HTML"""
        links = set()
        
        # استخراج الروابط الكاملة
        for match in self.patterns['full_url'].finditer(html_content):
            links.add(match.group(0))
        
        # استخراج الروابط النسبية
        for match in self.patterns['relative_url'].finditer(html_content):
            relative = match.group(1)
            full = urljoin(self.base_url, relative)
            links.add(full)
        
        # استخراج ملفات JavaScript
        for match in self.patterns['js_file'].finditer(html_content):
            js_url = match.group(1)
            full_js = urljoin(self.base_url, js_url)
            self.js_files.add(full_js)
        
        # استخراج ملفات CSS
        for match in self.patterns['css_file'].finditer(html_content):
            css_url = match.group(1)
            full_css = urljoin(self.base_url, css_url)
            links.add(full_css)
        
        # استخراج الروابط من CSS
        for match in self.patterns['css_url'].finditer(html_content):
            url = match.group(1)
            full_url = urljoin(self.base_url, url)
            links.add(full_url)
        
        # استخراج نقاط نهاية API
        for match in self.patterns['api_endpoint'].finditer(html_content):
            endpoint = match.group(1) or match.group(2)
            if endpoint:
                full_endpoint = urljoin(self.base_url, endpoint)
                self.api_endpoints.add(full_endpoint)
        
        # استخراج روابط WebSocket
        for match in self.patterns['websocket'].finditer(html_content):
            self.api_endpoints.add(match.group(0))
        
        # استخراج GraphQL
        for match in self.patterns['graphql'].finditer(html_content):
            endpoint = match.group(1)
            full_endpoint = urljoin(self.base_url, endpoint)
            self.api_endpoints.add(full_endpoint)
        
        # استخراج الروابط من تعليقات HTML
        for match in self.patterns['comment_url'].finditer(html_content):
            comment = match.group(0)
            for url_match in self.patterns['full_url'].finditer(comment):
                links.add(url_match.group(0))
        
        # استخراج الروابط المشفرة
        links.update(self._extract_encoded_urls(html_content))
        
        self.all_links.update(links)
        return links
    
    def extract_from_javascript(self, js_content: str) -> Set[str]:
        """استخراج الروابط من JavaScript"""
        links = set()
        
        # استخراج من دوال fetch/axios/XMLHttpRequest
        for match in self.patterns['js_url'].finditer(js_content):
            url = match.group(2)
            full_url = urljoin(self.base_url, url)
            links.add(full_url)
            self.api_endpoints.add(full_url)
        
        # استخراج الروابط الكاملة
        for match in self.patterns['full_url'].finditer(js_content):
            links.add(match.group(0))
        
        # استخراج الروابط النسبية
        for match in self.patterns['relative_url'].finditer(js_content):
            relative = match.group(1)
            full = urljoin(self.base_url, relative)
            links.add(full)
        
        # استخراج الروابط من السلاسل النصية
        string_pattern = re.compile(r'["\']((?:\/[^\s"\']+)+)["\']')
        for match in string_pattern.finditer(js_content):
            potential_url = match.group(1)
            if potential_url.startswith('/api/') or potential_url.startswith('/v'):
                full_url = urljoin(self.base_url, potential_url)
                self.api_endpoints.add(full_url)
        
        # استخراج الروابط المشفرة
        links.update(self._extract_encoded_urls(js_content))
        
        self.all_links.update(links)
        return links
    
    def extract_from_json(self, json_content: str) -> Set[str]:
        """استخراج الروابط من JSON"""
        links = set()
        
        try:
            data = json.loads(json_content)
            links.update(self._extract_from_dict(data))
        except json.JSONDecodeError:
            # إذا فشل تحليل JSON، نبحث عن روابط نصية
            for match in self.patterns['full_url'].finditer(json_content):
                links.add(match.group(0))
        
        # استخراج الروابط من أزواج المفاتيح والقيم
        for match in self.patterns['json_url'].finditer(json_content):
            key = match.group(1)
            value = match.group(2)
            if value.startswith('http'):
                links.add(value)
            else:
                full = urljoin(self.base_url, value)
                links.add(full)
        
        self.all_links.update(links)
        return links
    
    def _extract_from_dict(self, data: Any, links: Set[str] = None) -> Set[str]:
        """استخراج روابط من قاموس بشكل متكرر"""
        if links is None:
            links = set()
        
        if isinstance(data, dict):
            for key, value in data.items():
                # البحث عن مفاتيح تشير إلى روابط
                if any(k in key.lower() for k in ['url', 'link', 'href', 'src', 'endpoint', 'path']):
                    if isinstance(value, str):
                        if value.startswith('http'):
                            links.add(value)
                        elif value.startswith('/'):
                            links.add(urljoin(self.base_url, value))
                
                # البحث بشكل متكرر
                links.update(self._extract_from_dict(value, links))
        
        elif isinstance(data, list):
            for item in data:
                links.update(self._extract_from_dict(item, links))
        
        elif isinstance(data, str):
            # البحث عن روابط في النص
            for match in self.patterns['full_url'].finditer(data):
                links.add(match.group(0))
        
        return links
    
    def _extract_encoded_urls(self, content: str) -> Set[str]:
        """استخراج الروابط المشفرة"""
        links = set()
        
        # البحث عن روابط base64
        for match in self.patterns['b64_url'].finditer(content):
            encoded = match.group(1)
            try:
                decoded = base64.b64decode(encoded).decode('utf-8')
                if decoded.startswith('http'):
                    links.add(decoded)
            except:
                pass
        
        # البحث عن روابط مشفرة URL-encoded
        url_encoded_pattern = re.compile(r'%[0-9A-Fa-f]{2}', re.IGNORECASE)
        for match in url_encoded_pattern.finditer(content):
            try:
                # محاولة فك تشفير جزء صغير
                start = max(0, match.start() - 20)
                end = min(len(content), match.end() + 20)
                snippet = content[start:end]
                decoded = urllib.parse.unquote(snippet)
                if decoded.startswith('http'):
                    links.add(decoded)
            except:
                pass
        
        # البحث عن روابط في hexadecimal
        hex_pattern = re.compile(r'(?:0x)?([0-9A-Fa-f]{20,})', re.IGNORECASE)
        for match in hex_pattern.finditer(content):
            hex_str = match.group(1)
            try:
                decoded = bytes.fromhex(hex_str).decode('utf-8')
                if decoded.startswith('http'):
                    links.add(decoded)
            except:
                pass
        
        return links
    
    def extract_hidden_forms(self, html_content: str) -> List[Dict]:
        """استخراج النماذج المخفية"""
        forms = []
        
        # البحث عن النماذج
        form_pattern = re.compile(
            r'<form\s+([^>]*)>(.*?)</form>',
            re.DOTALL | re.IGNORECASE
        )
        
        for match in form_pattern.finditer(html_content):
            form_attrs = match.group(1)
            form_content = match.group(2)
            
            # استخراج action
            action_match = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_attrs, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''
            
            # استخراج method
            method_match = re.search(r'method\s*=\s*["\']([^"\']+)["\']', form_attrs, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # البحث عن حقول مخفية
            hidden_fields = []
            input_pattern = re.compile(
                r'<input\s+([^>]*type\s*=\s*["\']hidden["\'][^>]*)>',
                re.IGNORECASE
            )
            
            for input_match in input_pattern.finditer(form_content):
                input_attrs = input_match.group(1)
                
                name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', input_attrs, re.IGNORECASE)
                value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', input_attrs, re.IGNORECASE)
                
                if name_match:
                    hidden_fields.append({
                        'name': name_match.group(1),
                        'value': value_match.group(1) if value_match else ''
                    })
            
            if hidden_fields:
                forms.append({
                    'action': urljoin(self.base_url, action),
                    'method': method,
                    'hidden_fields': hidden_fields
                })
        
        self.hidden_forms = forms
        return forms
    
    def extract_all(self, html_content: str = '', js_content: str = '', json_content: str = '') -> Dict[str, Any]:
        """استخراج جميع الروابط من جميع المصادر"""
        results = {
            'all_links': set(),
            'api_endpoints': set(),
            'js_files': set(),
            'css_files': set(),
            'hidden_forms': [],
            'parameters': set()
        }
        
        if html_content:
            results['all_links'].update(self.extract_from_html(html_content))
            results['hidden_forms'] = self.extract_hidden_forms(html_content)
        
        if js_content:
            results['all_links'].update(self.extract_from_javascript(js_content))
        
        if json_content:
            results['all_links'].update(self.extract_from_json(json_content))
        
        # تنظيم النتائج
        results['api_endpoints'] = self.api_endpoints
        results['js_files'] = self.js_files
        results['all_links'] = self.all_links
        
        return results
    
    def print_summary(self):
        """طباعة ملخص النتائج"""
        print(f"\n{'='*70}")
        print(f"{'HIDDEN LINKS EXTRACTION SUMMARY':^70}")
        print(f"{'='*70}\n")
        
        print(f"Base URL: {self.base_url}")
        print(f"Domain: {self.domain}\n")
        
        print(f"Total Links Found: {len(self.all_links)}")
        print(f"API Endpoints: {len(self.api_endpoints)}")
        print(f"JavaScript Files: {len(self.js_files)}")
        print(f"Hidden Forms: {len(self.hidden_forms)}\n")
        
        if self.api_endpoints:
            print("API Endpoints:")
            for endpoint in sorted(self.api_endpoints)[:10]:
                print(f"  - {endpoint}")
            if len(self.api_endpoints) > 10:
                print(f"  ... and {len(self.api_endpoints) - 10} more")
            print()
        
        if self.hidden_forms:
            print("Hidden Forms:")
            for i, form in enumerate(self.hidden_forms[:5], 1):
                print(f"  Form {i}:")
                print(f"    Action: {form['action']}")
                print(f"    Method: {form['method']}")
                print(f"    Hidden Fields: {len(form['hidden_fields'])}")
                for field in form['hidden_fields']:
                    print(f"      - {field['name']}: {field['value'][:50]}...")
            print()
        
        print(f"{'='*70}\n")


# وظيفة رئيسية للاختبار
if __name__ == "__main__":
    # مثال على الاستخدام
    extractor = HiddenLinksExtractor("https://example.com")
    
    # محتوى HTML تجريبي
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="/js/app.js"></script>
        <link rel="stylesheet" href="/css/style.css">
    </head>
    <body>
        <a href="/page1">Page 1</a>
        <a href="https://external.com/link">External</a>
        
        <form action="/submit" method="POST">
            <input type="hidden" name="token" value="secret123">
            <input type="hidden" name="user_id" value="456">
        </form>
        
        <script>
            fetch('/api/data');
            axios.get('/api/users');
        </script>
    </body>
    </html>
    """
    
    # استخراج الروابط
    results = extractor.extract_all(html_content=html_content)
    
    # طباعة الملخص
    extractor.print_summary()
    
    # عرض جميع الروابط المستخرجة
    print("\nAll Extracted Links:")
    for link in sorted(extractor.all_links):
        print(f"  - {link}")
