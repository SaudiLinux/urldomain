#!/usr/bin/env python3
"""
Advanced Vulnerability Database - قاعدة بيانات الثغرات المتقدمة
المبرمج: SaudiLinux
البريد الإلكتروني: SaudiLinux1@gmail.com
"""

from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import json
import re


class SeverityLevel(Enum):
    """مستويات الخطورة"""
    CRITICAL = "حرجة"
    HIGH = "عالية"
    MEDIUM = "متوسطة"
    LOW = "منخفضة"
    INFO = "معلوماتية"


class VulnerabilityCategory(Enum):
    """فئات الثغرات"""
    INJECTION = "حقن"
    AUTHENTICATION = "مصادقة"
    SESSION_MANAGEMENT = "إدارة الجلسات"
    ACCESS_CONTROL = "التحكم في الوصول"
    CRYPTOGRAPHIC = "تشفير"
    CONFIGURATION = "إعدادات"
    INFORMATION_DISCLOSURE = "كشف المعلومات"
    BUSINESS_LOGIC = "منطق الأعمال"
    API = "API"
    MOBILE = "موبايل"
    CLOUD = "سحابة"
    IOT = "إنترنت الأشياء"


@dataclass
class VulnerabilityTemplate:
    """قالب الثغرة"""
    id: str
    name: str
    description: str
    severity: SeverityLevel
    category: VulnerabilityCategory
    cvss_score: float
    cwe_id: Optional[str]
    owasp_top10: Optional[str]
    payloads: List[str]
    detection_patterns: List[str]
    exploitation_steps: List[str]
    remediation: str
    references: List[str]
    tags: List[str]
    affected_versions: Optional[str] = None


class VulnerabilityDatabase:
    """قاعدة بيانات الثغرات"""
    
    def __init__(self):
        self.vulnerabilities: Dict[str, VulnerabilityTemplate] = {}
        self._initialize_database()
    
    def _initialize_database(self):
        """تهيئة قاعدة البيانات"""
        self._add_injection_vulnerabilities()
        self._add_authentication_vulnerabilities()
        self._add_access_control_vulnerabilities()
        self._add_information_disclosure_vulnerabilities()
        self._add_configuration_vulnerabilities()
        self._add_cryptographic_vulnerabilities()
        self._add_api_vulnerabilities()
    
    def _add_injection_vulnerabilities(self):
        """إضافة ثغرات الحقن"""
        vulns = [
            VulnerabilityTemplate(
                id="SQLI-001",
                name="SQL Injection",
                description="ثغرة تسمح للمهاجم بحقن استعلامات SQL عشوائية في قاعدة البيانات، مما يتيح قراءة البيانات الحساسة أو تعديلها أو حذفها.",
                severity=SeverityLevel.CRITICAL,
                category=VulnerabilityCategory.INJECTION,
                cvss_score=9.8,
                cwe_id="CWE-89",
                owasp_top10="A03:2021 – Injection",
                payloads=[
                    "' OR '1'='1",
                    "' UNION SELECT * FROM users--",
                    "'; DROP TABLE users;--",
                    "' AND SLEEP(5)--",
                    "' UNION SELECT null,@@version,null--",
                    "' OR 1=1 LIMIT 1--"
                ],
                detection_patterns=[
                    r"mysql_fetch_array",
                    r"ORA-[0-9]{4,5}",
                    r"Microsoft SQL Server",
                    r"PostgreSQL query failed",
                    r"unterminated quoted string"
                ],
                exploitation_steps=[
                    "تحديد نقاط الإدخال التي تتصل بقاعدة البيانات",
                    "اختبار استجابة التطبيق لحقن SQL",
                    "تحديد نوع قاعدة البيانات",
                    "استخراج اسم الجداول والأعمدة",
                    "استخراج البيانات الحساسة",
                    "تنفيذ أوامر على النظام إذا كان ممكناً"
                ],
                remediation="""
                1. استخدم الاستعلامات المُحضرة (Prepared Statements) مع الربط التلقائي للمتغيرات
                2. استخدم ORM مع إعدادات الأمان الصحيحة
                3. قم بالتحقق من صحة المدخلات باستخدام القوائم البيضاء
                4. تجنب استخدام مدخلات المستخدم في الاستعلامات الديناميكية
                5. استخدم أقل امتيازات ممكنة لحساب قاعدة البيانات
                """,
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://portswigger.net/web-security/sql-injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                ],
                tags=["sql", "database", "injection", "data-extraction", "authentication-bypass"]
            ),
            VulnerabilityTemplate(
                id="XSS-001",
                name="Cross-Site Scripting (XSS)",
                description="ثغرة تسمح للمهاجم بحقن كود JavaScript ضار في صفحات الويب التي يعرضها المستخدمون الآخرون. يمكن استغلالها لسرقة الجلسات، أو تعديل محتوى الصفحة، أو إعادة توجيه المستخدمين إلى مواقع ضارة.",
                severity=SeverityLevel.HIGH,
                category=VulnerabilityCategory.INJECTION,
                cvss_score=6.1,
                cwe_id="CWE-79",
                owasp_top10="A03:2021 – Injection",
                payloads=[
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
                ],
                detection_patterns=[
                    r"<script[^>]*>",
                    r"onerror\s*=",
                    r"onload\s*=",
                    r"onclick\s*=",
                    r"javascript:",
                    r"<iframe",
                    r"<object",
                    r"<embed"
                ],
                exploitation_steps=[
                    "تحديد نقاط الإدخال التي تعرض البيانات في الصفحة",
                    "اختبار التطبيق بحمولات XSS مختلفة",
                    "تحديد نوع الثغرة (Stored, Reflected, DOM)",
                    "تطوير payload مخصص للاستهداف",
                    "سرقة ملفات تعريف الارتباط أو تنفيذ إجراءات غير مصرح بها"
                ],
                remediation="""
                1. فرض Content Security Policy (CSP) صارم
                2. تشفير جميع البيانات الديناميكية قبل عرضها في HTML
                3. استخدام سياقات الإخراج الصحيحة (HTML, JavaScript, URL, CSS)
                4. تنفيذ SameSite cookies لحماية جلسات المصادقة
                5. استخدام X-XSS-Protection: 1; mode=block
                6. التحقق من صحة المدخلات باستخدام القوائم البيضاء
                7. تجنب استخدام innerHTML واستخدام textContent بدلاً منه
                """,
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://portswigger.net/web-security/cross-site-scripting",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                ],
                tags=["xss", "javascript", "injection", "client-side", "session-hijacking"]
            )
        ]
        
        for vuln in vulns:
            self.vulnerabilities[vuln.id] = vuln


# ... إكمال إضافة الثغرات الأخرى ...

if __name__ == "__main__":
    db = VulnerabilityDatabase()
    print(f"Loaded {len(db.vulnerabilities)} vulnerability templates")
    
    # عرض معلومات ثغرة SQL Injection
    sqli = db.vulnerabilities.get("SQLI-001")
    if sqli:
        print(f"\n{sqli.name}")
        print(f"Severity: {sqli.severity.value}")
        print(f"CVSS Score: {sqli.cvss_score}")
        print(f"Payloads: {len(sqli.payloads)}")
