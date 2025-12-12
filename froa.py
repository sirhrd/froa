# -*- coding: utf-8 -*-
"""

"""

import os
import re
import sys
import time
import html
import ssl
import socket
import traceback
import datetime
import json
import hashlib
import base64
import subprocess
import warnings
import ipaddress
import threading
from urllib.parse import urlparse, urljoin, quote, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict

# إخفاء تحذيرات غير ضرورية
warnings.filterwarnings('ignore')

# مكتبات خارجية أساسية
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except Exception:
    print("مطلوب تثبيت requests: pip install requests")
    raise SystemExit

try:
    import whois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

try:
    from PIL import Image, ImageFile
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as qr_decode
    PYZBAR_AVAILABLE = True
except Exception:
    PYZBAR_AVAILABLE = False

try:
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except Exception:
    BS4_AVAILABLE = False

# ------------------------------------------------------------
# لوقو
LOGO = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⠔⠒⠊⠉⠉⠉⠉⠙⠒⠲⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⠔⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠲⣄⠀⠀⠀⠀⠀
⠀⠀⠀⣠⠞⠁⠀⣀⠀⠀⠀⠀⢀⣀⡀⠀⢀⣀⠀⠀⠀⠀⢀⠀⠈⠱⣄⠀⠀⠀
⠀⠀⡴⠁⡠⣴⠟⠁⢀⠤⠂⡠⠊⡰⠁⠇⢃⠁⠊⠑⠠⡀⠀⢹⣶⢤⡈⢣⡀⠀
⠀⡼⢡⣾⢓⡵⠃⡐⠁⠀⡜⠀⠐⠃⣖⣲⡄⠀⠀⠱⠀⠈⠢⠈⢮⣃⣷⢄⢳⠀
⢰⠃⣿⡹⣫⠃⡌⠀⠄⠈⠀⠀⠀⠀⠀⠋⠀⠀⠀⠀⠣⠀⠀⠱⠈⣯⡻⣼⠈⡇
⡞⢈⢿⡾⡃⠰⠀⠀⠀⠀⠀⠀⠀⠀⣘⣋⠀⠀⠀⠀⠀⠀⠀⠀⠇⢸⢿⣿⢠⢸
⡇⢸⡜⣴⠃⠀⠀⠀⠀⠀⣀⣀⣤⡎⠹⡏⢹⣦⣀⣀⠀⠀⠀⠀⢈⠘⣧⢣⡟⢸
⢧⢊⢳⡏⣤⠸⠀⠀⠀⢸⣿⣿⣿⡇⢰⡇⢠⣿⣿⣿⣷⠀⠀⠀⡆⢸⢹⡼⣱⢸
⢸⡘⢷⣅⣿⢂⢃⠐⠂⣿⣿⣿⣿⣿⣼⣇⣾⣿⣿⣿⣿⠁⠂⡰⡠⣿⢨⡾⠃⡇
⠀⢳⡱⣝⠻⡼⣆⡁⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠐⣰⣇⠿⣋⠝⡼⠀
⠀⠀⢳⡈⢻⠶⣿⣞⢾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⢣⣿⡶⠟⢉⡼⠁⠀
⠀⠀⠀⠙⢦⡑⠲⠶⠾⠿⢟⣿⣿⣿⣿⣿⣿⣿⣿⡛⠿⠷⠶⠶⠊⡡⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠙⠦⣝⠛⠛⠛⣿⣿⣿⣿⣿⣿⣿⣿⡛⠛⠛⣋⠴⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠉⠒⠦⠿⣿⣿⣿⣿⣿⣿⠿⠧⠒⠋⠁⠀⠀⠀⠀⠀⠀⠀
"""
LOGO_FOOTER = "By @HRD"
print(LOGO)
print(LOGO_FOOTER)
print("")

# ------------------------------------------------------------
# إعدادات عامة متطورة
REQUEST_TIMEOUT = 15
MAX_PREVIEW_BYTES = 500000
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

# قواعد بيانات موسعة للفحص
THREAT_DATABASE = {
    'xss_patterns': [
        r'<script[^>]*>.*?</script>',
        r'on\w+\s*=',
        r'javascript:',
        r'vbscript:',
        r'data:text/html',
        r'alert\([^)]*\)',
        r'prompt\([^)]*\)',
        r'confirm\([^)]*\)',
        r'document\.cookie',
        r'window\.location',
        r'document\.write\(',
        r'innerHTML\s*=',
        r'outerHTML\s*=',
        r'eval\(',
        r'setTimeout\(',
        r'setInterval\(',
        r'Function\('
    ],
    'sql_patterns': [
        r'(\%27)|(\')|(\-\-)',
        r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))',
        r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))',
        r'(?i)(union.*select|select.*from|insert.*into|delete.*from|update.*set|drop.*table)',
        r'(?i)(select\s+\*|insert\s+values|delete\s+from|update\s+\w+\s+set)',
        r'(?i)(or\s+\d+=\d+|and\s+\d+=\d+)',
        r'(?i)(sleep\(|benchmark\(|waitfor\s+delay)'
    ],
    'phishing_keywords': [
        'login', 'signin', 'sign-in', 'log-in', 'bank', 'secure', 'confirm',
        'account', 'password', 'verify', 'update', 'paypal', 'ebay', 'amazon',
        'apple', 'microsoft', 'google', 'facebook', 'instagram', 'whatsapp',
        'verification', 'authentication', 'security', 'update', 'billing',
        'payment', 'credit', 'card', 'social', 'security', 'ssn', 'password reset',
        'account recovery', 'verify identity', 'confirm details', 'urgent action required'
    ],
    'suspicious_domains': [
        'free', 'online', 'web', 'site', 'host', 'service', 'cloud', 'server',
        'secure', 'verify', 'account', 'login', 'signin', 'update', 'confirm'
    ],
    'malware_indicators': [
        r'eval\(', r'exec\(', r'system\(', r'popen\(', r'subprocess',
        r'base64_decode', r'gzinflate', r'str_rot13', r'create_function',
        r'assert\(', r'preg_replace.*/e', r'call_user_func',
        r'file_get_contents\s*\([^)]*http', r'curl_exec',
        r'shell_exec', r'passthru', r'proc_open'
    ]
}

# ------------------------------------------------------------
# دوال مساعدة متطورة
def now_str():
    try:
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

def normalize_url(u):
    if not u:
        return None
    u = u.strip()
    u = re.sub(r'[\x00-\x1F\x7F]', '', u)
    
    if not re.match(r'^[a-zA-Z0-9+.-]+://', u):
        return 'http://' + u
    return u

def validate_url(u):
    try:
        p = urlparse(u)
        if not p.scheme in ('http','https'):
            return False
        if not p.netloc:
            return False
        domain_parts = p.netloc.split('.')
        if len(domain_parts) < 2:
            return False
        if len(p.netloc) > 253:
            return False
        return True
    except:
        return False

def sanitize_filename(name):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1F]', '_', name)
    name = re.sub(r'\s+', '_', name)
    return name[:200]

def get_random_user_agent():
    import random
    return random.choice(USER_AGENTS)

def create_session():
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def calculate_hash(data, hash_type='sha256'):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if hash_type == 'md5':
        return hashlib.md5(data).hexdigest()
    elif hash_type == 'sha1':
        return hashlib.sha1(data).hexdigest()
    elif hash_type == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif hash_type == 'sha512':
        return hashlib.sha512(data).hexdigest()
    else:
        return hashlib.sha256(data).hexdigest()

def human_readable_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    
    size_names = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

# ------------------------------------------------------------
# تطوير الخيار 1: فحص رابط سريع متطور
def handle_scan_url_quick_enhanced():
    """فحص رابط سريع متطور مع معلومات موسعة"""
    print("=" * 60)
    print("فحص رابط سريع متطور - استخراج معلومات موسعة")
    print("=" * 60)
    
    u = input("أدخل الرابط: ").strip()
    if not u:
        print("لم تقم بإدخال رابط!")
        return None
    
    u = normalize_url(u)
    
    if not validate_url(u):
        print("الرابط غير صالح!")
        return None
    
    print("\n" + "=" * 60)
    print("جار الفحص المتطور...")
    print("=" * 60)
    
    start_time = time.time()
    report = {'input_url': u, 'scanned_at': now_str()}
    
    # 1. الفحص الأساسي المتطور
    print("1/7 فحص أساسي متطور...")
    report['basic_enhanced'] = scan_basic_enhanced(u)
    
    # 2. فحص SSL/شهادة متطور
    parsed = urlparse(u)
    if parsed.scheme == 'https':
        print("2/7 فحص SSL/شهادة متطور...")
        report['ssl_enhanced'] = scan_ssl_enhanced(u)
    else:
        report['ssl_enhanced'] = {'note': 'لا يستخدم HTTPS'}
    
    # 3. تحليل المحتوى المتطور
    print("3/7 تحليل محتوى متطور...")
    report['content_analysis_enhanced'] = analyze_content_enhanced(u)
    
    # 4. تحليل روابط الوسائط المتطور
    print("4/7 تحليل روابط الوسائط...")
    media_links = report['content_analysis_enhanced'].get('media_links', [])
    report['media_analysis_enhanced'] = analyze_media_links_enhanced(media_links)
    
    # 5. معلومات WHOIS متطورة
    if WHOIS_AVAILABLE:
        print("5/7 معلومات WHOIS متطورة...")
        report['whois_enhanced'] = whois_info_enhanced(parsed.hostname)
    else:
        report['whois_enhanced'] = {'note': 'whois غير متوفر'}
    
    # 6. معلومات الشبكة المتطورة
    print("6/7 معلومات الشبكة متطورة...")
    report['network_enhanced'] = network_info_enhanced(parsed.hostname)
    
    # 7. تحليل حركة المرور المتطور
    print("7/7 تحليل حركة المرور...")
    report['traffic_analysis_enhanced'] = traffic_analysis_enhanced(u)
    
    # تحليل مخاطر التصيد المتطور
    print("\nتحليل مخاطر التصيد...")
    phishing_result = phishing_heuristic_enhanced(report)
    report['phishing_analysis'] = phishing_result
    
    total_time = time.time() - start_time
    
    # عرض النتائج التفصيلية
    print("\n" + "=" * 60)
    print("نتائج الفحص المتطور")
    print("=" * 60)
    
    print(f"\nوقت الفحص: {total_time:.2f} ثانية")
    print(f"الرابط المدخل: {u}")
    print(f"الرابط النهائي: {report['basic_enhanced'].get('final_url', u)}")
    
    # معلومات أساسية موسعة
    basic = report['basic_enhanced']
    print(f"\nمعلومات أساسية:")
    print(f"   رمز الحالة: {basic.get('status_code')}")
    print(f"   وقت الاستجابة: {basic.get('response_time')} ثانية")
    print(f"   نوع المحتوى: {basic.get('content_type')}")
    print(f"   حجم المحتوى: {human_readable_size(basic.get('content_length', 0))}")
    print(f"   عدد التحويلات: {len(basic.get('redirect_chain', []))}")
    
    # معلومات SSL موسعة
    if parsed.scheme == 'https':
        ssl_info = report['ssl_enhanced']
        print(f"\nمعلومات SSL:")
        print(f"   صالح: {'نعم' if ssl_info.get('valid') else 'لا'}")
        if ssl_info.get('valid'):
            print(f"   المتبقي: {ssl_info.get('days_remaining', 'غير معروف')} يوم")
            print(f"   المصدر: {ssl_info.get('issuer', {}).get('organizationName', 'غير معروف')}")
    
    # معلومات الدومين موسعة
    if WHOIS_AVAILABLE:
        whois_info = report['whois_enhanced']
        print(f"\nمعلومات الدومين:")
        if whois_info.get('creation_date'):
            print(f"   تاريخ الإنشاء: {whois_info.get('creation_date')}")
        if whois_info.get('age_days'):
            print(f"   العمر: {whois_info.get('age_days')} يوم")
        if whois_info.get('registrar'):
            print(f"   المسجل: {whois_info.get('registrar')}")
    
    # معلومات الشبكة موسعة
    network = report['network_enhanced']
    print(f"\nمعلومات الشبكة:")
    if network.get('ip_addresses'):
        print(f"   عناوين IP: {', '.join(network['ip_addresses'][:3])}")
        if len(network['ip_addresses']) > 3:
            print(f"   + {len(network['ip_addresses']) - 3} عناوين إضافية")
    
    # تحليل المحتوى موسع
    content = report['content_analysis_enhanced']
    print(f"\nتحليل المحتوى:")
    print(f"   العنوان: {content.get('title', 'غير موجود')[:50]}...")
    print(f"   عدد الروابط: {content.get('num_links', 0)}")
    print(f"   روابط خارجية: {len(content.get('external_links', []))}")
    print(f"   روابط وسائط: {len(content.get('media_links', []))}")
    
    # مؤشرات التهديد
    if content.get('suspicious_patterns'):
        print(f"   أنماط مشبوهة: {len(content['suspicious_patterns'])}")
    
    # تحليل التصيد
    phishing = report['phishing_analysis']
    print(f"\nتحليل مخاطر التصيد:")
    print(f"   مستوى الخطر: {phishing.get('verdict')}")
    print(f"   النقاط: {phishing.get('score')}/20")
    
    if phishing.get('reasons'):
        print(f"   المؤشرات ({len(phishing['reasons'])}):")
        for i, reason in enumerate(phishing['reasons'][:5], 1):
            print(f"     {i}. {reason}")
        if len(phishing['reasons']) > 5:
            print(f"     ... و{len(phishing['reasons']) - 5} مؤشرات أخرى")
    
    # توصيات
    print(f"\nتوصيات:")
    if phishing['score'] >= 15:
        print("   خطر عالي - تجنب هذا الرابط!")
    elif phishing['score'] >= 10:
        print("   خطر متوسط - كن حذراً!")
    elif phishing['score'] >= 5:
        print("   خطر منخفض - لكن تحقق من المصدر")
    else:
        print("   آمن - يبدو الرابط آمناً")
    
    # حفظ التقرير
    print("\n" + "=" * 60)
    save = input("هل تريد حفظ التقرير المفصل؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        timestamp = int(time.time())
        hostname = parsed.hostname or 'report'
        safe_hostname = sanitize_filename(hostname)
        
        base = os.path.join(folder, f"{safe_hostname}_detailed_{timestamp}")
        
        # حفظ تقارير متعددة
        paths = save_report_files_enhanced(base, report, phishing)
        
        print("\nتم حفظ التقارير:")
        for path in paths:
            print(f"   {os.path.basename(path)}")
        
        # حفظ JSON تفصيلي
        json_path = base + "_full.json"
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2, default=str)
            print(f"   {os.path.basename(json_path)} (بيانات كاملة)")
        except Exception as e:
            print(f"   خطأ في حفظ JSON: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى الفحص المتطور")
    print("=" * 60)
    
    return report, phishing

# ------------------------------------------------------------
# تطوير الخيار 2: توسيع روابط مختصرة متطور
def handle_expand_short_url_enhanced():
    """توسيع روابط مختصرة مع تحليل متطور"""
    print("=" * 60)
    print("توسيع وتحليل روابط مختصرة متطور")
    print("=" * 60)
    
    u = input("أدخل الرابط المختصر أو الرابط: ").strip()
    if not u:
        print("لم تقم بإدخال رابط!")
        return None
    
    u = normalize_url(u)
    
    print("\nجار تحليل الرابط...")
    result = expand_url_enhanced(u)
    
    print("\n" + "=" * 60)
    print("نتائج التحليل المتطور")
    print("=" * 60)
    
    print(f"\nالرابط المدخل: {result.get('input', u)}")
    print(f"الرابط النهائي: {result.get('final_url', 'غير متوفر')}")
    
    # معلومات التحويلات
    redirects = result.get('redirect_chain', [])
    print(f"\nسلسلة التحويلات ({len(redirects)}):")
    for i, redirect in enumerate(redirects, 1):
        print(f"   {i}. {redirect}")
    
    # معلومات الاستجابة
    response_info = result.get('response_info', {})
    if response_info:
        print(f"\nمعلومات الاستجابة:")
        print(f"   رمز الحالة: {response_info.get('status_code')}")
        print(f"   نوع المحتوى: {response_info.get('content_type')}")
        print(f"   حجم المحتوى: {human_readable_size(response_info.get('content_length', 0))}")
        print(f"   الخادم: {response_info.get('server', 'غير معروف')}")
    
    # تحليل الدومين
    domain_info = result.get('domain_analysis', {})
    if domain_info:
        print(f"\nتحليل الدومين:")
        print(f"   الدومين النهائي: {domain_info.get('final_domain')}")
        
        redirect_domains = domain_info.get('redirect_domains', [])
        if redirect_domains:
            print(f"   دومينات التحويل ({len(redirect_domains)}):")
            for domain in redirect_domains[:5]:
                print(f"     • {domain}")
            if len(redirect_domains) > 5:
                print(f"     • ... و{len(redirect_domains) - 5} دومينات أخرى")
    
    # تحليل المخاطر
    risk_analysis = result.get('risk_analysis', {})
    if risk_analysis:
        print(f"\nتحليل المخاطر:")
        print(f"   مستوى الخطر: {risk_analysis.get('risk_level', 'غير معروف')}")
        
        indicators = risk_analysis.get('risk_indicators', [])
        if indicators:
            print(f"   مؤشرات الخطر ({len(indicators)}):")
            for indicator in indicators[:3]:
                print(f"     • {indicator}")
            if len(indicators) > 3:
                print(f"     • ... و{len(indicators) - 3} مؤشرات أخرى")
    
    # تحسينات على الخيار الأصلي
    print(f"\nإحصائيات:")
    print(f"   عدد خطوات التحويل: {len(redirects)}")
    print(f"   أقصر رابط: {min([len(r) for r in redirects + [u]], default=0)} حرف")
    print(f"   أطول رابط: {max([len(r) for r in redirects + [u]], default=0)} حرف")
    
    # حفظ التقرير
    print("\n" + "=" * 60)
    save = input("هل تريد حفظ تقرير التحليل؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        timestamp = int(time.time())
        domain = urlparse(result.get('final_url', u)).hostname or 'short_url'
        safe_domain = sanitize_filename(domain)
        
        filename = f"expand_{safe_domain}_{timestamp}.txt"
        filepath = os.path.join(folder, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("تقرير تحليل روابط مختصرة متطور\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"الرابط المدخل: {result.get('input', u)}\n")
                f.write(f"الرابط النهائي: {result.get('final_url', 'غير متوفر')}\n")
                f.write(f"وقت التحليل: {now_str()}\n\n")
                
                f.write(f"عدد التحويلات: {len(redirects)}\n")
                f.write("سلسلة التحويلات:\n")
                for i, redirect in enumerate(redirects, 1):
                    f.write(f"  {i}. {redirect}\n")
                
                f.write("\nتحليل المخاطر:\n")
                if risk_analysis:
                    f.write(f"  مستوى الخطر: {risk_analysis.get('risk_level')}\n")
                    f.write("  مؤشرات:\n")
                    for indicator in risk_analysis.get('risk_indicators', []):
                        f.write(f"    • {indicator}\n")
                
                f.write("\nإحصائيات:\n")
                f.write(f"  أقصر رابط: {min([len(r) for r in redirects + [u]], default=0)} حرف\n")
                f.write(f"  أطول رابط: {max([len(r) for r in redirects + [u]], default=0)} حرف\n")
                
            print(f"تم حفظ التقرير: {filepath}")
        except Exception as e:
            print(f"خطأ في الحفظ: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى تحليل الروابط المختصرة")
    print("=" * 60)
    
    return result

def expand_url_enhanced(url):
    """توسيع رابط مختصر مع تحليل متطور"""
    result = {
        'input': url,
        'final_url': url,
        'redirect_chain': [],
        'response_info': {},
        'domain_analysis': {},
        'risk_analysis': {},
        'metadata': {}
    }
    
    try:
        session = create_session()
        session.max_redirects = 10
        
        # تتبع التحويلات بالتفصيل
        history = []
        final_url = url
        
        # طلب HEAD مع تتبع التحويلات
        response = session.head(
            url,
            allow_redirects=True,
            timeout=15,
            headers={'User-Agent': get_random_user_agent()}
        )
        
        # جمع معلومات التحويلات
        if response.history:
            for resp in response.history:
                history.append(resp.url)
                result['redirect_chain'].append(resp.url)
            
            result['final_url'] = response.url
        
        # معلومات الاستجابة التفصيلية
        result['response_info'] = {
            'status_code': response.status_code,
            'content_type': response.headers.get('Content-Type', ''),
            'content_length': response.headers.get('Content-Length'),
            'server': response.headers.get('Server', ''),
            'date': response.headers.get('Date', ''),
            'last_modified': response.headers.get('Last-Modified', '')
        }
        
        # تحليل الدومينات
        domains = []
        all_urls = [url] + result['redirect_chain'] + [result['final_url']]
        
        for u in all_urls:
            try:
                domain = urlparse(u).hostname
                if domain and domain not in domains:
                    domains.append(domain)
            except:
                continue
        
        result['domain_analysis'] = {
            'original_domain': urlparse(url).hostname,
            'final_domain': urlparse(result['final_url']).hostname,
            'redirect_domains': domains,
            'domain_changes': len(set(domains)) > 1
        }
        
        # تحليل المخاطر
        risk_indicators = []
        risk_score = 0
        
        # 1. كثرة التحويلات
        if len(result['redirect_chain']) > 5:
            risk_score += 3
            risk_indicators.append(f'تحويلات كثيرة ({len(result["redirect_chain"])})')
        elif len(result['redirect_chain']) > 2:
            risk_score += 1
            risk_indicators.append(f'تحويلات متعددة ({len(result["redirect_chain"])})')
        
        # 2. تغيير الدومين
        original_domain = urlparse(url).hostname
        final_domain = urlparse(result['final_url']).hostname
        
        if original_domain != final_domain:
            risk_score += 2
            risk_indicators.append(f'تغيير الدومين من {original_domain} إلى {final_domain}')
        
        # 3. دومينات مشبوهة
        suspicious_keywords = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        for domain in domains:
            if any(keyword in domain.lower() for keyword in suspicious_keywords):
                risk_score += 1
                risk_indicators.append(f'خدمة تقصير روابط: {domain}')
        
        # 4. أطوال روابط
        url_length = len(url)
        if url_length < 20:
            risk_score += 1
            risk_indicators.append(f'رابط قصير جداً ({url_length} حرف)')
        
        # تحديد مستوى الخطر
        if risk_score >= 5:
            risk_level = 'مرتفع'
        elif risk_score >= 3:
            risk_level = 'متوسط'
        elif risk_score >= 1:
            risk_level = 'منخفض'
        else:
            risk_level = 'آمن'
        
        result['risk_analysis'] = {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_indicators': risk_indicators
        }
        
        # معلومات إضافية
        result['metadata'] = {
            'total_redirects': len(result['redirect_chain']),
            'analysis_time': now_str(),
            'url_length': len(url),
            'final_url_length': len(result['final_url'])
        }
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

# ------------------------------------------------------------
# تطوير الخيار 3: فحص بريد إلكتروني متطور
def handle_scan_email_enhanced():
    """فحص بريد إلكتروني متطور مع معلومات موسعة"""
    print("=" * 60)
    print("فحص بريد إلكتروني متطور")
    print("=" * 60)
    
    email = input("أدخل عنوان البريد الإلكتروني: ").strip()
    if not email:
        print("لم تقم بإدخال بريد إلكتروني!")
        return None
    
    print("\nجار فحص البريد الإلكتروني...")
    report = analyze_email_enhanced(email)
    
    print("\n" + "=" * 60)
    print("نتائج الفحص المتطور")
    print("=" * 60)
    
    print(f"\nالبريد المدخل: {report.get('email')}")
    print(f"وقت الفحص: {report.get('scanned_at')}")
    
    # معلومات الصحة
    validation = report.get('validation', {})
    print(f"\nالتحقق من الصحة:")
    print(f"   التنسيق صحيح: {'نعم' if validation.get('format_valid') else 'لا'}")
    print(f"   الدومين موجود: {'نعم' if validation.get('domain_exists') else 'لا'}")
    print(f"   لديه سجلات MX: {'نعم' if validation.get('has_mx_records') else 'لا'}")
    
    # معلومات الدومين
    domain_info = report.get('domain_info', {})
    if domain_info:
        print(f"\nمعلومات الدومين:")
        print(f"   الدومين: {domain_info.get('domain')}")
        
        if domain_info.get('mx_records'):
            print(f"   سيرفرات البريد ({len(domain_info['mx_records'])}):")
            for mx in domain_info['mx_records'][:3]:
                print(f"     • {mx.get('exchange')} (أولوية: {mx.get('preference')})")
        
        if domain_info.get('ip_address'):
            print(f"   عنوان IP: {domain_info.get('ip_address')}")
    
    # تحليل المخاطر
    risk_analysis = report.get('risk_analysis', {})
    if risk_analysis:
        print(f"\nتحليل المخاطر:")
        print(f"   النقاط: {risk_analysis.get('risk_score', 0)}/10")
        print(f"   المستوى: {risk_analysis.get('risk_level', 'غير معروف')}")
        
        indicators = risk_analysis.get('risk_indicators', [])
        if indicators:
            print(f"   المؤشرات ({len(indicators)}):")
            for indicator in indicators[:5]:
                print(f"     • {indicator}")
    
    # تحسينات على الخيار الأصلي
    print(f"\nإحصائيات:")
    
    # الوقت المنقضي منذ إنشاء الدومين
    if domain_info.get('domain_age_days'):
        age = domain_info['domain_age_days']
        if age < 30:
            print(f"   الدومين جديد جداً ({age} يوم)")
        elif age < 365:
            print(f"   الدومين عمره {age} يوم")
        else:
            years = age // 365
            print(f"   الدومين عمره {years} سنة")
    
    # عدد سيرفرات البريد
    if domain_info.get('mx_records'):
        print(f"   عدد سيرفرات البريد: {len(domain_info['mx_records'])}")
    
    # التوصيات
    print(f"\nالتوصيات:")
    risk_score = risk_analysis.get('risk_score', 0)
    
    if risk_score >= 8:
        print("   تجنب هذا البريد - خطر عالي")
    elif risk_score >= 5:
        print("   كن حذراً - تأكد من مصدر البريد")
    elif risk_score >= 2:
        print("   البريد مقبول لكن تحقق من الرسائل")
    else:
        print("   البريد يبدو آمناً")
    
    # التحقق الإضافي
    print(f"\nفحوصات إضافية:")
    if validation.get('format_valid') and validation.get('domain_exists'):
        print("   التنسيق والدومين صحيحان")
    else:
        print("   هناك مشكلة في التنسيق أو الدومين")
    
    if validation.get('has_mx_records'):
        print("   الدومين يستقبل بريداً إلكترونياً")
    else:
        print("   الدومين لا يستقبل بريداً إلكترونياً")
    
    # حفظ التقرير
    print("\n" + "=" * 60)
    save = input("هل تريد حفظ تقرير الفحص؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        timestamp = int(time.time())
        safe_email = sanitize_filename(email.replace('@', '_at_'))
        
        filename = f"email_{safe_email}_{timestamp}.txt"
        filepath = os.path.join(folder, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("تقرير فحص بريد إلكتروني متطور\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"البريد الإلكتروني: {email}\n")
                f.write(f"وقت الفحص: {report.get('scanned_at')}\n\n")
                
                f.write("التحقق من الصحة:\n")
                f.write(f"  التنسيق صحيح: {validation.get('format_valid', False)}\n")
                f.write(f"  الدومين موجود: {validation.get('domain_exists', False)}\n")
                f.write(f"  لديه سجلات MX: {validation.get('has_mx_records', False)}\n\n")
                
                f.write("معلومات الدومين:\n")
                f.write(f"  الدومين: {domain_info.get('domain', 'غير معروف')}\n")
                f.write(f"  عنوان IP: {domain_info.get('ip_address', 'غير معروف')}\n")
                
                if domain_info.get('mx_records'):
                    f.write(f"  سيرفرات البريد ({len(domain_info['mx_records'])}):\n")
                    for mx in domain_info['mx_records']:
                        f.write(f"    • {mx.get('exchange')} (أولوية: {mx.get('preference')})\n")
                
                f.write("\nتحليل المخاطر:\n")
                f.write(f"  النقاط: {risk_analysis.get('risk_score', 0)}/10\n")
                f.write(f"  المستوى: {risk_analysis.get('risk_level', 'غير معروف')}\n")
                
                if risk_analysis.get('risk_indicators'):
                    f.write("  المؤشرات:\n")
                    for indicator in risk_analysis['risk_indicators']:
                        f.write(f"    • {indicator}\n")
                
                f.write("\nالتوصيات:\n")
                if risk_score >= 8:
                    f.write("  تجنب هذا البريد - خطر عالي\n")
                elif risk_score >= 5:
                    f.write("  كن حذراً - تأكد من مصدر البريد\n")
                elif risk_score >= 2:
                    f.write("  البريد مقبول لكن تحقق من الرسائل\n")
                else:
                    f.write("  البريد يبدو آمناً\n")
            
            print(f"تم حفظ التقرير: {filepath}")
        except Exception as e:
            print(f"خطأ في الحفظ: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى فحص البريد الإلكتروني")
    print("=" * 60)
    
    return report

def analyze_email_enhanced(email):
    """تحليل بريد إلكتروني متطور"""
    report = {
        'email': email,
        'scanned_at': now_str(),
        'validation': {},
        'domain_info': {},
        'risk_analysis': {},
        'technical_details': {}
    }
    
    try:
        # التحقق من التنسيق
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        format_valid = bool(re.match(email_pattern, email))
        report['validation']['format_valid'] = format_valid
        
        if not format_valid:
            report['validation']['error'] = 'تنسيق البريد غير صحيح'
            return report
        
        # استخراج الدومين
        domain = email.split('@')[1]
        report['domain_info']['domain'] = domain
        
        # التحقق من وجود الدومين
        try:
            ip_address = socket.gethostbyname(domain)
            report['domain_info']['ip_address'] = ip_address
            report['validation']['domain_exists'] = True
        except socket.gaierror:
            report['validation']['domain_exists'] = False
            report['validation']['error'] = 'الدومين غير موجود'
            return report
        
        # التحقق من سجلات MX
        try:
            mx_records = socket.getaddrinfo(domain, None, socket.AF_INET)
            if mx_records:
                report['validation']['has_mx_records'] = True
                
                # محاولة جلب سجلات MX بشكل أفضل
                try:
                    import dns.resolver
                    answers = dns.resolver.resolve(domain, 'MX')
                    mx_list = []
                    for rdata in answers:
                        mx_list.append({
                            'preference': rdata.preference,
                            'exchange': str(rdata.exchange)
                        })
                    report['domain_info']['mx_records'] = mx_list
                except:
                    # طريقة بديلة
                    report['domain_info']['mx_records'] = [{'exchange': str(mx[4][0]), 'preference': 10} 
                                                          for mx in mx_records[:5]]
            else:
                report['validation']['has_mx_records'] = False
        except:
            report['validation']['has_mx_records'] = False
        
        # معلومات WHOIS (إذا كانت متاحة)
        if WHOIS_AVAILABLE and report['validation']['domain_exists']:
            try:
                who = whois.whois(domain)
                
                # عمر الدومين
                if who.creation_date:
                    if isinstance(who.creation_date, list):
                        creation_date = who.creation_date[0]
                    else:
                        creation_date = who.creation_date
                    
                    if creation_date:
                        now = datetime.datetime.now(datetime.timezone.utc)
                        if isinstance(creation_date, str):
                            from dateutil import parser
                            creation_date = parser.parse(creation_date)
                        
                        age_days = (now - creation_date).days
                        report['domain_info']['domain_age_days'] = age_days
                
                report['domain_info']['whois_info'] = {
                    'registrar': str(who.registrar) if who.registrar else None,
                    'creation_date': str(who.creation_date) if who.creation_date else None,
                    'expiration_date': str(who.expiration_date) if who.expiration_date else None
                }
            except Exception as e:
                report['domain_info']['whois_error'] = str(e)
        
        # تحليل المخاطر
        risk_score = 0
        risk_indicators = []
        
        # 1. دومينات مجانية
        free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                       'aol.com', 'protonmail.com', 'zoho.com']
        
        if domain.lower() in free_domains:
            risk_score += 1
            risk_indicators.append('بريد مجاني')
        
        # 2. دومينات مشبوهة
        suspicious_patterns = [
            r'.*\.ru$', r'.*\.cn$', r'.*\.tk$', r'.*\.ml$', r'.*\.ga$',
            r'.*\.cf$', r'.*\.gq$', r'.*\.xyz$', r'.*\.top$', r'.*\.win$'
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, domain.lower()):
                risk_score += 2
                risk_indicators.append(f'دومين مشبوه: {domain}')
                break
        
        # 3. دومينات قصيرة جداً
        if len(domain.split('.')[0]) < 3:
            risk_score += 1
            risk_indicators.append('اسم دومين قصير جداً')
        
        # 4. عمر الدومين
        if report['domain_info'].get('domain_age_days'):
            age = report['domain_info']['domain_age_days']
            if age < 30:
                risk_score += 3
                risk_indicators.append(f'دومين جديد جداً ({age} يوم)')
            elif age < 365:
                risk_score += 1
                risk_indicators.append(f'دومين جديد ({age} يوم)')
        
        # 5. عدم وجود سجلات MX
        if not report['validation'].get('has_mx_records'):
            risk_score += 2
            risk_indicators.append('لا توجد سجلات MX (لا يستقبل بريداً)')
        
        # تحديد مستوى الخطر
        if risk_score >= 8:
            risk_level = 'مرتفع جداً'
        elif risk_score >= 5:
            risk_level = 'مرتفع'
        elif risk_score >= 3:
            risk_level = 'متوسط'
        elif risk_score >= 1:
            risk_level = 'منخفض'
        else:
            risk_level = 'آمن'
        
        report['risk_analysis'] = {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_indicators': risk_indicators
        }
        
        # تفاصيل تقنية
        report['technical_details'] = {
            'email_length': len(email),
            'username_length': len(email.split('@')[0]),
            'domain_length': len(domain),
            'tld': domain.split('.')[-1] if '.' in domain else None,
            'subdomain_count': len(domain.split('.')) - 2
        }
        
    except Exception as e:
        report['error'] = str(e)
    
    return report

# ------------------------------------------------------------
# تطوير الخيار 4: فحص كلمة مرور متطور
def handle_check_password_enhanced():
    """فحص كلمة مرور متطور مع تحليل مفصل"""
    print("=" * 60)
    print("فحص قوة كلمة المرور متطور")
    print("=" * 60)
    
    password = input("أدخل كلمة المرور للتحقق: ").strip()
    if not password:
        print("لم تقم بإدخال كلمة مرور!")
        return None
    
    print("\nجار تحليل كلمة المرور...")
    report = analyze_password_enhanced(password)
    
    print("\n" + "=" * 60)
    print("نتائج التحليل المتطور")
    print("=" * 60)
    
    print(f"\nكلمة المرور: {'*' * min(len(password), 10)}{'...' if len(password) > 10 else ''}")
    print(f"الطول: {len(password)} حرف")
    print(f"وقت الفحص: {report.get('checked_at')}")
    
    # قوة كلمة المرور
    strength = report.get('strength_analysis', {})
    print(f"\nقوة كلمة المرور:")
    print(f"   المستوى: {strength.get('strength_level', 'غير معروف')}")
    print(f"   النقاط: {strength.get('score', 0)}/20")
    print(f"   التصنيف: {strength.get('category', 'غير معروف')}")
    
    # المعايير المفحوصة
    criteria = report.get('criteria_check', {})
    print(f"\nالمعايير المفحوصة:")
    
    checks = [
        ('has_length_8', '8 أحرف على الأقل'),
        ('has_length_12', '12 أحرف على الأقل'),
        ('has_uppercase', 'حرف كبير'),
        ('has_lowercase', 'حرف صغير'),
        ('has_digits', 'رقم'),
        ('has_special', 'رمز خاص'),
        ('has_no_spaces', 'بدون مسافات'),
        ('has_no_common', 'ليست كلمة شائعة'),
        ('has_no_sequential', 'بدون تسلسل'),
        ('has_no_repeating', 'بدون تكرار')
    ]
    
    for key, description in checks:
        if key in criteria:
            status = '✓' if criteria[key] else '✗'
            print(f"   {status} {description}")
    
    # نقاط القوة والضعف
    print(f"\nنقاط القوة:")
    strengths = report.get('strengths', [])
    if strengths:
        for strength in strengths[:5]:
            print(f"   ✓ {strength}")
    
    print(f"\nنقاط الضعف:")
    weaknesses = report.get('weaknesses', [])
    if weaknesses:
        for weakness in weaknesses[:5]:
            print(f"   ✗ {weakness}")
    
    # تحليل التعقيد
    complexity = report.get('complexity_analysis', {})
    if complexity:
        print(f"\nتحليل التعقيد:")
        print(f"   مجموعة الأحرف: {complexity.get('character_set_size', 0)}")
        print(f"   الإنتروبيا: {complexity.get('entropy', 0):.2f} بت")
        print(f"   مساحة البحث: 10^{complexity.get('search_space_log10', 0):.1f}")
    
    # الإحصائيات
    print(f"\nإحصائيات:")
    stats = report.get('statistics', {})
    if stats:
        print(f"   وقت التخمين (10 محاولات/ثانية): {stats.get('time_to_crack_10', 'غير معروف')}")
        print(f"   وقت التخمين (1000 محاولات/ثانية): {stats.get('time_to_crack_1000', 'غير معروف')}")
        print(f"   وقت التخمين (1M محاولات/ثانية): {stats.get('time_to_crack_1M', 'غير معروف')}")
    
    # التوصيات
    print(f"\nالتوصيات:")
    recommendations = report.get('recommendations', [])
    if recommendations:
        for i, rec in enumerate(recommendations[:5], 1):
            print(f"   {i}. {rec}")
    
    # نصائح أمنية
    print(f"\nنصائح أمنية:")
    tips = [
        "استخدم 12 حرفاً على الأقل",
        "امزج بين أحرف كبيرة وصغيرة وأرقام ورموز",
        "تجنب الكلمات الشائعة والمعلومات الشخصية",
        "لا تستخدم نفس كلمة المرور لأكثر من حساب",
        "فكر في استخدام مدير كلمات المرور"
    ]
    
    for tip in tips:
        print(f"   • {tip}")
    
    # حفظ التقرير
    print("\n" + "=" * 60)
    save = input("هل تريد حفظ تقرير التحليل؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        timestamp = int(time.time())
        # لا نحفظ كلمة المرور الفعلية
        filename = f"password_analysis_{timestamp}.txt"
        filepath = os.path.join(folder, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("تقرير تحليل قوة كلمة المرور\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"وقت الفحص: {report.get('checked_at')}\n")
                f.write(f"طول كلمة المرور: {len(password)} حرف\n\n")
                
                f.write(f"مستوى القوة: {strength.get('strength_level', 'غير معروف')}\n")
                f.write(f"النقاط: {strength.get('score', 0)}/20\n\n")
                
                f.write("المعايير المفحوصة:\n")
                for key, description in checks:
                    if key in criteria:
                        status = 'متحقق' if criteria[key] else 'غير متحقق'
                        f.write(f"  {description}: {status}\n")
                
                f.write("\nنقاط القوة:\n")
                for s in strengths:
                    f.write(f"  ✓ {s}\n")
                
                f.write("\nنقاط الضعف:\n")
                for w in weaknesses:
                    f.write(f"  ✗ {w}\n")
                
                f.write("\nالتوصيات:\n")
                for rec in recommendations:
                    f.write(f"  • {rec}\n")
                
                f.write("\nملاحظة: لم يتم حفظ كلمة المرور الفعلية.\n")
            
            print(f"تم حفظ التقرير: {filepath}")
        except Exception as e:
            print(f"خطأ في الحفظ: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى تحليل كلمة المرور")
    print("=" * 60)
    
    return report

def analyze_password_enhanced(password):
    """تحليل كلمة مرور متطور"""
    report = {
        'checked_at': now_str(),
        'password_length': len(password),
        'criteria_check': {},
        'strength_analysis': {},
        'strengths': [],
        'weaknesses': [],
        'complexity_analysis': {},
        'statistics': {},
        'recommendations': []
    }
    
    try:
        # التحقق من المعايير الأساسية
        criteria = report['criteria_check']
        
        # الطول
        criteria['has_length_8'] = len(password) >= 8
        criteria['has_length_12'] = len(password) >= 12
        criteria['has_length_16'] = len(password) >= 16
        
        # الأنواع المختلفة من الأحرف
        criteria['has_uppercase'] = bool(re.search(r'[A-Z]', password))
        criteria['has_lowercase'] = bool(re.search(r'[a-z]', password))
        criteria['has_digits'] = bool(re.search(r'[0-9]', password))
        criteria['has_special'] = bool(re.search(r'[^A-Za-z0-9]', password))
        
        # التحقق من المشاكل
        criteria['has_no_spaces'] = ' ' not in password
        criteria['has_no_common'] = password.lower() not in COMMON_PASSWORDS
        criteria['has_no_sequential'] = not has_sequential_chars(password)
        criteria['has_no_repeating'] = not has_repeating_chars(password)
        
        # حساب النقاط
        score = 0
        
        # نقاط الطول
        if criteria['has_length_8']:
            score += 1
        if criteria['has_length_12']:
            score += 2
        if criteria['has_length_16']:
            score += 3
        
        # نقاط أنواع الأحرف
        if criteria['has_uppercase']:
            score += 1
            report['strengths'].append('تحتوي على أحرف كبيرة')
        else:
            report['weaknesses'].append('لا تحتوي على أحرف كبيرة')
        
        if criteria['has_lowercase']:
            score += 1
            report['strengths'].append('تحتوي على أحرف صغيرة')
        else:
            report['weaknesses'].append('لا تحتوي على أحرف صغيرة')
        
        if criteria['has_digits']:
            score += 1
            report['strengths'].append('تحتوي على أرقام')
        else:
            report['weaknesses'].append('لا تحتوي على أرقام')
        
        if criteria['has_special']:
            score += 2
            report['strengths'].append('تحتوي على رموز خاصة')
        else:
            report['weaknesses'].append('لا تحتوي على رموز خاصة')
        
        # نقاط إضافية للتنوع
        char_types = sum([criteria['has_uppercase'], criteria['has_lowercase'], 
                         criteria['has_digits'], criteria['has_special']])
        
        if char_types >= 4:
            score += 3
            report['strengths'].append('تحتوي على 4 أنواع مختلفة من الأحرف')
        elif charTypes >= 3:
            score += 2
            report['strengths'].append('تحتوي على 3 أنواع مختلفة من الأحرف')
        elif charTypes >= 2:
            score += 1
            report['strengths'].append('تحتوي على نوعين مختلفين من الأحرف')
        
        # خصم النقاط للمشاكل
        if not criteria['has_no_common']:
            score -= 5
            report['weaknesses'].append('كلمة مرور شائعة')
        
        if not criteria['has_no_spaces']:
            score -= 1
            report['weaknesses'].append('تحتوي على مسافات')
        
        if not criteria['has_no_sequential']:
            score -= 2
            report['weaknesses'].append('تحتوي على تسلسل أحرف')
        
        if not criteria['has_no_repeating']:
            score -= 2
            report['weaknesses'].append('تحتوي على أحرف مكررة')
        
        # التأكد من أن النقاط لا تكون سالبة
        score = max(score, 0)
        
        # تحديد مستوى القوة
        if score >= 16:
            strength_level = 'قوي جداً'
            category = 'ممتاز'
        elif score >= 12:
            strength_level = 'قوي'
            category = 'جيد جداً'
        elif score >= 8:
            strength_level = 'متوسط'
            category = 'مقبول'
        elif score >= 4:
            strength_level = 'ضعيف'
            category = 'ضعيف'
        else:
            strength_level = 'ضعيف جداً'
            category = 'خطر'
        
        report['strength_analysis'] = {
            'score': score,
            'strength_level': strength_level,
            'category': category
        }
        
        # تحليل التعقيد
        character_set = 0
        if criteria['has_lowercase']:
            character_set += 26
        if criteria['has_uppercase']:
            character_set += 26
        if criteria['has_digits']:
            character_set += 10
        if criteria['has_special']:
            # تقدير الرموز الخاصة
            character_set += 32
        
        entropy = len(password) * (character_set.bit_length() if character_set > 0 else 1)
        search_space = character_set ** len(password) if character_set > 0 else 0
        
        report['complexity_analysis'] = {
            'character_set_size': character_set,
            'entropy': entropy,
            'search_space': search_space,
            'search_space_log10': math.log10(search_space) if search_space > 0 else 0
        }
        
        # إحصائيات وقت التخمين
        if search_space > 0:
            attempts_10 = search_space / 10
            attempts_1000 = search_space / 1000
            attempts_1M = search_space / 1000000
            
            report['statistics'] = {
                'time_to_crack_10': format_time(attempts_10),
                'time_to_crack_1000': format_time(attempts_1000),
                'time_to_crack_1M': format_time(attempts_1M)
            }
        
        # التوصيات
        recommendations = report['recommendations']
        
        if not criteria['has_length_12']:
            recommendations.append('اجعل كلمة المرور أطول (12 حرفاً على الأقل)')
        
        if not criteria['has_special']:
            recommendations.append('أضف رموزاً خاصة مثل !@#$%^&*')
        
        if not criteria['has_no_common']:
            recommendations.append('تجنب كلمات المرور الشائعة')
        
        if not criteria['has_uppercase'] or not criteria['has_lowercase']:
            recommendations.append('امزج بين الأحرف الكبيرة والصغيرة')
        
        if not criteria['has_digits']:
            recommendations.append('أضف أرقاماً إلى كلمة المرور')
        
        # نصائح عامة
        recommendations.append('لا تستخدم المعلومات الشخصية في كلمة المرور')
        recommendations.append('استخدم كلمة مرور مختلفة لكل حساب مهم')
        recommendations.append('فكر في استخدام مدير كلمات المرور')
        
    except Exception as e:
        report['error'] = str(e)
    
    return report

def has_sequential_chars(password):
    """الكشف عن التسلسلات"""
    sequential_patterns = [
        '123', '234', '345', '456', '567', '678', '789',
        'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
        'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio', 'iop', 'op[',
        'asd', 'sdf', 'dfg', 'fgh', 'ghj', 'hjk', 'jkl',
        'zxc', 'xcv', 'cvb', 'vbn', 'bnm'
    ]
    
    password_lower = password.lower()
    for pattern in sequential_patterns:
        if pattern in password_lower:
            return True
    
    return False

def has_repeating_chars(password):
    """الكشف عن التكرارات"""
    # بحث عن 3 أحرف متتالية مكررة
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return True
    
    return False

def format_time(seconds):
    """تنسيق الوقت"""
    if seconds < 60:
        return f"{seconds:.1f} ثانية"
    elif seconds < 3600:
        return f"{seconds/60:.1f} دقيقة"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} ساعة"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} يوم"
    else:
        return f"{seconds/31536000:.1f} سنة"

# قائمة كلمات المرور الشائعة
COMMON_PASSWORDS = [
    '123456', 'password', '12345678', 'qwerty', '123456789',
    '12345', '1234', '111111', '1234567', 'dragon',
    '123123', 'baseball', 'abc123', 'football', 'monkey',
    'letmein', '696969', 'shadow', 'master', '666666',
    'qwertyuiop', '123321', 'mustang', '1234567890',
    'michael', '654321', 'superman', '1qaz2wsx', '7777777',
    '121212', '000000', 'qazwsx', '123qwe', 'killer',
    'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh',
    'hunter', 'buster', 'soccer', 'harley', 'batman',
    'andrew', 'tigger', 'sunshine', 'iloveyou', '2000',
    'charlie', 'robert', 'thomas', 'hockey', 'ranger',
    'daniel', 'starwars', 'klaster', '112233', 'george',
    'computer', 'michelle', 'jessica', 'pepper', '1111',
    'zxcvbn', '555555', '11111111', '131313', 'freedom',
    '777777', 'pass', 'maggie', '159753', 'aaaaaa',
    'ginger', 'princess', 'joshua', 'cheese', 'amanda',
    'summer', 'love', 'ashley', 'nicole', 'chelsea',
    'biteme', 'matthew', 'access', 'yankees', '987654321',
    'dallas', 'austin', 'thunder', 'taylor', 'matrix',
    'mobilemail', 'mom', 'monitor', 'monitoring', 'montana',
    'moon', 'moscow'
]

# ------------------------------------------------------------
# تطوير الخيار 5: فحص ملف برمجي متطور
def handle_scan_code_file_enhanced():
    """فحص ملف برمجي متطور مع تحليل مفصل"""
    print("=" * 60)
    print("فحص ملف برمجي متطور")
    print("=" * 60)
    
    path = input("أدخل مسار الملف البرمجي: ").strip()
    
    if not os.path.isfile(path):
        print("الملف غير موجود!")
        return None
    
    print(f"\nجار فحص الملف: {os.path.basename(path)}")
    report = scan_code_file_enhanced(path)
    
    print("\n" + "=" * 60)
    print("نتائج الفحص المتطور")
    print("=" * 60)
    
    print(f"\nمعلومات الملف:")
    print(f"   الاسم: {report.get('filename')}")
    print(f"   المسار: {report.get('path')}")
    print(f"   الحجم: {report.get('size_human')}")
    print(f"   الامتداد: {report.get('extension')}")
    print(f"   نوع الملف: {report.get('file_type', 'غير معروف')}")
    
    # الهاشات
    hashes = report.get('hashes', {})
    if hashes:
        print(f"\nالهاشات:")
        print(f"   MD5: {hashes.get('md5', 'غير متوفر')}")
        print(f"   SHA1: {hashes.get('sha1', 'غير متوفر')}")
        print(f"   SHA256: {hashes.get('sha256', 'غير متوفر')}")
    
    # تحليل المحتوى
    content_analysis = report.get('content_analysis', {})
    if content_analysis:
        print(f"\nتحليل المحتوى:")
        print(f"   عدد الأسطر: {content_analysis.get('line_count', 0)}")
        print(f"   عدد الأحرف: {content_analysis.get('char_count', 0)}")
        print(f"   عدد الكلمات: {content_analysis.get('word_count', 0)}")
        
        language = content_analysis.get('detected_language')
        if language:
            print(f"   لغة البرمجة: {language}")
    
    # تحليل المخاطر
    threat_analysis = report.get('threat_analysis', {})
    if threat_analysis:
        print(f"\nتحليل المخاطر:")
        print(f"   مستوى التهديد: {threat_analysis.get('threat_level', 'غير معروف')}")
        print(f"   النقاط: {threat_analysis.get('threat_score', 0)}/20")
        
        indicators = threat_analysis.get('threat_indicators', [])
        if indicators:
            print(f"   مؤشرات التهديد ({len(indicators)}):")
            for i, indicator in enumerate(indicators[:5], 1):
                print(f"     {i}. {indicator}")
            if len(indicators) > 5:
                print(f"     ... و{len(indicators) - 5} مؤشرات أخرى")
    
    # الأنماط الخطرة المكتشفة
    patterns_found = report.get('dangerous_patterns', {})
    if patterns_found:
        print(f"\nالأنماط الخطرة المكتشفة:")
        for pattern_type, patterns in patterns_found.items():
            if patterns:
                print(f"   {pattern_type}: {len(patterns)}")
                for pattern in patterns[:3]:
                    print(f"     • {pattern[:50]}...")
                if len(patterns) > 3:
                    print(f"     • ... و{len(patterns) - 3} أنماط أخرى")
    
    # تحليل الاستيرادات
    imports_analysis = report.get('imports_analysis', {})
    if imports_analysis:
        suspicious_imports = imports_analysis.get('suspicious_imports', [])
        if suspicious_imports:
            print(f"\nاستيرادات مشبوهة ({len(suspicious_imports)}):")
            for imp in suspicious_imports[:5]:
                print(f"   • {imp}")
            if len(suspicious_imports) > 5:
                print(f"   • ... و{len(suspicious_imports) - 5} استيرادات أخرى")
    
    # الروابط المكتشفة
    links_found = report.get('links_found', [])
    if links_found:
        print(f"\nالروابط المكتشفة ({len(links_found)}):")
        for link in links_found[:5]:
            domain = urlparse(link).netloc
            print(f"   • {domain}")
        if len(links_found) > 5:
            print(f"   • ... و{len(links_found) - 5} روابط أخرى")
    
    # التحليل الإحصائي
    statistics = report.get('statistics', {})
    if statistics:
        print(f"\nإحصائيات:")
        print(f"   كثافة التعليقات: {statistics.get('comment_density', 0):.1f}%")
        print(f"   متوسط طول السطر: {statistics.get('avg_line_length', 0):.1f} حرف")
    
    # التوصيات
    recommendations = report.get('recommendations', [])
    if recommendations:
        print(f"\nالتوصيات:")
        for i, rec in enumerate(recommendations[:5], 1):
            print(f"   {i}. {rec}")
    
    # تقدير المخاطر
    threat_score = threat_analysis.get('threat_score', 0) if threat_analysis else 0
    print(f"\nتقدير المخاطر:")
    
    if threat_score >= 15:
        print("   خطر عالي - تجنب تشغيل هذا الملف!")
    elif threat_score >= 10:
        print("   خطر متوسط - كن حذراً عند التشغيل")
    elif threat_score >= 5:
        print("   خطر منخفض - تحقق من مصدر الملف")
    elif threat_score > 0:
        print("   خطر طفيف - قد يحتوي على كود مشبوه")
    else:
        print("   يبدو الملف آمناً")
    
    # حفظ التقرير
    print("\n" + "=" * 60)
    save = input("هل تريد حفظ تقرير الفحص؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        timestamp = int(time.time())
        safe_filename = sanitize_filename(report.get('filename', 'file'))
        
        filename = f"code_scan_{safe_filename}_{timestamp}.txt"
        filepath = os.path.join(folder, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("تقرير فحص ملف برمجي متطور\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"اسم الملف: {report.get('filename')}\n")
                f.write(f"المسار: {report.get('path')}\n")
                f.write(f"الحجم: {report.get('size_human')}\n")
                f.write(f"الامتداد: {report.get('extension')}\n")
                f.write(f"نوع الملف: {report.get('file_type', 'غير معروف')}\n\n")
                
                f.write("الهاشات:\n")
                for hash_name, hash_value in hashes.items():
                    f.write(f"  {hash_name.upper()}: {hash_value}\n")
                
                f.write("\nتحليل المحتوى:\n")
                if content_analysis:
                    f.write(f"  عدد الأسطر: {content_analysis.get('line_count', 0)}\n")
                    f.write(f"  عدد الأحرف: {content_analysis.get('char_count', 0)}\n")
                    f.write(f"  عدد الكلمات: {content_analysis.get('word_count', 0)}\n")
                    if content_analysis.get('detected_language'):
                        f.write(f"  لغة البرمجة: {content_analysis['detected_language']}\n")
                
                f.write("\nتحليل المخاطر:\n")
                if threat_analysis:
                    f.write(f"  مستوى التهديد: {threat_analysis.get('threat_level')}\n")
                    f.write(f"  النقاط: {threat_analysis.get('threat_score', 0)}/20\n")
                    
                    if threat_analysis.get('threat_indicators'):
                        f.write("  مؤشرات التهديد:\n")
                        for indicator in threat_analysis['threat_indicators']:
                            f.write(f"    • {indicator}\n")
                
                f.write("\nالأنماط الخطرة:\n")
                if patterns_found:
                    for pattern_type, patterns in patterns_found.items():
                        if patterns:
                            f.write(f"  {pattern_type} ({len(patterns)}):\n")
                            for pattern in patterns[:10]:
                                f.write(f"    • {pattern[:100]}\n")
                
                f.write("\nالتوصيات:\n")
                for rec in recommendations:
                    f.write(f"  • {rec}\n")
                
                f.write("\nملاحظة: تم تحليل {report.get('percentage_analyzed', 100)}% من الملف\n")
            
            print(f"تم حفظ التقرير: {filepath}")
        except Exception as e:
            print(f"خطأ في الحفظ: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى فحص الملف البرمجي")
    print("=" * 60)
    
    return report

def scan_code_file_enhanced(path):
    """فحص ملف برمجي متطور"""
    report = {
        'path': path,
        'filename': os.path.basename(path),
        'size_bytes': 0,
        'size_human': '',
        'extension': '',
        'file_type': 'غير معروف',
        'hashes': {},
        'content_analysis': {},
        'threat_analysis': {},
        'dangerous_patterns': {},
        'imports_analysis': {},
        'links_found': [],
        'statistics': {},
        'recommendations': []
    }
    
    try:
        # معلومات الملف الأساسية
        size = os.path.getsize(path)
        report['size_bytes'] = size
        report['size_human'] = human_readable_size(size)
        
        ext = os.path.splitext(path)[1].lower()
        report['extension'] = ext
        
        # حساب الهاشات
        with open(path, 'rb') as f:
            content = f.read()
            report['hashes'] = {
                'md5': hashlib.md5(content).hexdigest(),
                'sha1': hashlib.sha1(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest()
            }
        
        # محاولة تحديد نوع الملف من المحتوى
        try:
            # قراءة أول 1000 بايت للتحليل
            with open(path, 'rb') as f:
                header = f.read(1000)
                
                if header.startswith(b'#!'):  # سكربت Unix
                    report['file_type'] = 'سكربت Unix'
                elif b'<?php' in header[:100]:
                    report['file_type'] = 'PHP'
                elif b'#!/usr/bin/env python' in header[:100] or b'#!/usr/bin/python' in header[:100]:
                    report['file_type'] = 'Python سكربت'
                elif b'function' in header[:500] and b'var ' in header[:500]:
                    report['file_type'] = 'JavaScript'
                elif b'import ' in header[:500] and (b'java.' in header[:500] or b'public class' in header[:500]):
                    report['file_type'] = 'Java'
                elif b'#include' in header[:500]:
                    report['file_type'] = 'C/C++'
                else:
                    # محاولة من الامتداد
                    ext_map = {
                        '.py': 'Python',
                        '.js': 'JavaScript',
                        '.php': 'PHP',
                        '.java': 'Java',
                        '.cpp': 'C++',
                        '.c': 'C',
                        '.cs': 'C#',
                        '.rb': 'Ruby',
                        '.go': 'Go',
                        '.rs': 'Rust',
                        '.sh': 'Shell Script',
                        '.bat': 'Batch File',
                        '.ps1': 'PowerShell'
                    }
                    report['file_type'] = ext_map.get(ext, 'نصي')
        except:
            pass
        
        # تحليل المحتوى النصي
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                text_content = f.read(500000)  # قراءة حتى 500KB
                
                report['percentage_analyzed'] = min(100, (len(text_content) / max(size, 1)) * 100)
                
                # إحصائيات المحتوى
                lines = text_content.splitlines()
                words = text_content.split()
                
                report['content_analysis'] = {
                    'line_count': len(lines),
                    'char_count': len(text_content),
                    'word_count': len(words),
                    'detected_language': report['file_type']
                }
                
                # تحليل المخاطر
                threat_score = 0
                threat_indicators = []
                dangerous_patterns = {
                    'execution': [],
                    'network': [],
                    'file_operations': [],
                    'obfuscation': [],
                    'suspicious': []
                }
                
                # أنماط التنفيذ الخطرة
                execution_patterns = [
                    (r'eval\s*\(', 'eval'),
                    (r'exec\s*\(', 'exec'),
                    (r'system\s*\(', 'system'),
                    (r'popen\s*\(', 'popen'),
                    (r'subprocess\.', 'subprocess'),
                    (r'os\.system', 'os.system'),
                    (r'Process\.Start', 'Process.Start'),
                    (r'Runtime\.exec', 'Runtime.exec'),
                    (r'ShellExecute', 'ShellExecute'),
                    (r'CreateProcess', 'CreateProcess')
                ]
                
                for pattern, name in execution_patterns:
                    matches = re.findall(pattern, text_content, re.IGNORECASE)
                    if matches:
                        threat_score += 2
                        threat_indicators.append(f'يحتوي على {name}')
                        dangerous_patterns['execution'].extend(matches[:5])
                
                # أنماط الشبكة الخطرة
                network_patterns = [
                    (r'curl_exec\s*\(', 'curl_exec'),
                    (r'file_get_contents\s*\([^)]*http', 'file_get_contents to URL'),
                    (r'wget\s+', 'wget'),
                    (r'curl\s+', 'curl'),
                    (r'socket\.', 'socket'),
                    (r'HttpClient', 'HttpClient'),
                    (r'WebClient', 'WebClient'),
                    (r'WebRequest', 'WebRequest')
                ]
                
                for pattern, name in network_patterns:
                    matches = re.findall(pattern, text_content, re.IGNORECASE)
                    if matches:
                        threat_score += 1
                        threat_indicators.append(f'اتصال شبكة: {name}')
                        dangerous_patterns['network'].extend(matches[:5])
                
                # أنماط ملفات خطرة
                file_patterns = [
                    (r'fopen\s*\([^)]*w[^)]*\)', 'fopen للكتابة'),
                    (r'file_put_contents', 'file_put_contents'),
                    (r'File\.Write', 'File.Write'),
                    (r'File\.Create', 'File.Create'),
                    (r'open\s*\([^)]*["\']w["\']', 'open للكتابة')
                ]
                
                for pattern, name in file_patterns:
                    matches = re.findall(pattern, text_content, re.IGNORECASE)
                    if matches:
                        threat_score += 1
                        threat_indicators.append(f'عمليات ملفات: {name}')
                        dangerous_patterns['file_operations'].extend(matches[:5])
                
                # أنماط تعتيم
                obfuscation_patterns = [
                    (r'base64_decode\s*\(', 'base64_decode'),
                    (r'gzinflate\s*\(', 'gzinflate'),
                    (r'str_rot13\s*\(', 'str_rot13'),
                    (r'chr\s*\(.*\)\.chr\s*\(.*\)', 'chr concatenation'),
                    (r'fromCharCode', 'fromCharCode'),
                    (r'unescape\s*\(', 'unescape'),
                    (r'atob\s*\(', 'atob')
                ]
                
                for pattern, name in obfuscation_patterns:
                    matches = re.findall(pattern, text_content, re.IGNORECASE)
                    if matches:
                        threat_score += 2
                        threat_indicators.append(f'تعتيم كود: {name}')
                        dangerous_patterns['obfuscation'].extend(matches[:5])
                
                # أنماط مشبوهة أخرى
                suspicious_patterns = [
                    (r'password\s*=\s*["\'][^"\']+["\']', 'كلمة مرور داخل الكود'),
                    (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'مفتاح API'),
                    (r'secret[_-]?key\s*=\s*["\'][^"\']+["\']', 'مفتاح سري'),
                    (r'token\s*=\s*["\'][^"\']+["\']', 'توكن'),
                    (r'admin\s*=\s*["\'][^"\']+["\']', 'معلومات مدير')
                ]
                
                for pattern, name in suspicious_patterns:
                    matches = re.findall(pattern, text_content, re.IGNORECASE)
                    if matches:
                        threat_score += 1
                        threat_indicators.append(f'معلومات حساسة: {name}')
                        dangerous_patterns['suspicious'].extend(matches[:5])
                
                # استخراج الروابط
                url_pattern = r'https?://[^\s<>"\']+'
                links = re.findall(url_pattern, text_content)
                report['links_found'] = list(set(links))[:20]  # أول 20 رابط فريد
                
                if links:
                    threat_score += 1
                    threat_indicators.append(f'يحتوي على {len(links)} رابط')
                
                # تحليل الاستيرادات
                if report['file_type'] in ['Python', 'Python سكربت']:
                    imports = re.findall(r'^import\s+(\w+)', text_content, re.MULTILINE)
                    imports += re.findall(r'^from\s+(\w+)', text_content, re.MULTILINE)
                    
                    suspicious_modules = ['os', 'sys', 'subprocess', 'socket', 'urllib', 
                                         'requests', 'ftplib', 'smtplib', 'telnetlib']
                    
                    found_suspicious = [imp for imp in imports if imp in suspicious_modules]
                    
                    report['imports_analysis'] = {
                        'imports_found': list(set(imports))[:20],
                        'suspicious_imports': found_suspicious
                    }
                    
                    if found_suspicious:
                        threat_score += len(found_suspicious)
                        threat_indicators.append(f'استيرادات مشبوهة: {", ".join(found_suspicious[:3])}')
                
                # تحليل إحصائي
                if lines:
                    # حساب متوسط طول السطر
                    avg_line_length = sum(len(line) for line in lines) / len(lines)
                    
                    # حساب كثافة التعليقات (تقريبي)
                    comment_lines = sum(1 for line in lines if line.strip().startswith('#') or 
                                       line.strip().startswith('//') or 
                                       line.strip().startswith('/*'))
                    
                    comment_density = (comment_lines / len(lines)) * 100 if lines else 0
                    
                    report['statistics'] = {
                        'avg_line_length': avg_line_length,
                        'comment_density': comment_density,
                        'empty_lines': sum(1 for line in lines if not line.strip())
                    }
                
                # تصفية الأنماط الفارغة
                for key in list(dangerous_patterns.keys()):
                    if not dangerous_patterns[key]:
                        del dangerous_patterns[key]
                
                report['dangerous_patterns'] = dangerous_patterns
                
                # تحديد مستوى التهديد
                if threat_score >= 15:
                    threat_level = 'مرتفع جداً'
                elif threat_score >= 10:
                    threat_level = 'مرتفع'
                elif threat_score >= 5:
                    threat_level = 'متوسط'
                elif threat_score >= 2:
                    threat_level = 'منخفض'
                elif threat_score > 0:
                    threat_level = 'طفيف'
                else:
                    threat_level = 'آمن'
                
                report['threat_analysis'] = {
                    'threat_score': threat_score,
                    'threat_level': threat_level,
                    'threat_indicators': threat_indicators
                }
                
                # التوصيات
                recommendations = report['recommendations']
                
                if threat_score >= 10:
                    recommendations.append('خطر عالي - تجنب تشغيل هذا الملف')
                elif threat_score >= 5:
                    recommendations.append('خطر متوسط - تحقق من مصدر الملف قبل التشغيل')
                
                if dangerous_patterns.get('execution'):
                    recommendations.append('يحتوي على أوامر تنفيذ خطيرة')
                
                if dangerous_patterns.get('obfuscation'):
                    recommendations.append('يحتوي على كود معتم')
                
                if report['links_found']:
                    recommendations.append('يتصل بمواقع خارجية')
                
                if not recommendations:
                    recommendations.append('يبدو الملف آمناً، لكن تحقق دائماً من مصدر الملف')
                
        except UnicodeDecodeError:
            report['error'] = 'لا يمكن قراءة الملف كنص (قد يكون ثنائي)'
        except Exception as e:
            report['error'] = str(e)
    
    except Exception as e:
        report['error'] = str(e)
    
    return report

# ------------------------------------------------------------
# تطوير الخيار 6: فحص QR من صورة متطور
def handle_scan_qr_enhanced():
    """فحص QR من صورة متطور"""
    print("=" * 60)
    print("فحص QR من صورة متطور")
    print("=" * 60)
    
    path = input("أدخل مسار صورة QR: ").strip()
    
    if not os.path.isfile(path):
        print("الملف غير موجود!")
        return None
    
    if not PYZBAR_AVAILABLE or not PIL_AVAILABLE:
        print("المكتبات المطلوبة غير مثبتة!")
        print("قم بتثبيت: pip install pyzbar pillow")
        return None
    
    print(f"\nجار تحليل الصورة: {os.path.basename(path)}")
    result = scan_qr_enhanced(path)
    
    print("\n" + "=" * 60)
    print("نتائج التحليل المتطور")
    print("=" * 60)
    
    if not result.get('qr_found'):
        print("\nلم يتم العثور على QR code في الصورة")
        return result
    
    print(f"\nتم العثور على {result.get('qr_count', 0)} QR code في الصورة")
    
    for i, qr_data in enumerate(result.get('qr_codes', []), 1):
        print(f"\nQR #{i}:")
        print(f"   النوع: {qr_data.get('type', 'غير معروف')}")
        
        data = qr_data.get('data', '')
        print(f"   البيانات: {data[:100]}{'...' if len(data) > 100 else ''}")
        
        # تحليل نوع البيانات
        data_analysis = qr_data.get('data_analysis', {})
        if data_analysis:
            data_type = data_analysis.get('data_type', 'غير معروف')
            print(f"   نوع البيانات: {data_type}")
            
            if data_type == 'URL':
                print(f"   الرابط: {data}")
                
                # تحليل الرابط إذا كان URL
                if data.startswith(('http://', 'https://')):
                    print(f"\n   تحليل الرابط:")
                    parsed = urlparse(data)
                    print(f"      الدومين: {parsed.netloc}")
                    print(f"      المسار: {parsed.path[:50]}")
                    
                    # تحليل المخاطر الأولي
                    risk_indicators = []
                    risk_score = 0
                    
                    # دومينات مختصرة
                    short_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd']
                    if any(domain in parsed.netloc for domain in short_domains):
                        risk_score += 1
                        risk_indicators.append('رابط مختصر')
                    
                    # دومينات مشبوهة
                    suspicious_keywords = ['login', 'signin', 'verify', 'account', 'bank']
                    if any(keyword in parsed.netloc.lower() for keyword in suspicious_keywords):
                        risk_score += 1
                        risk_indicators.append('دومين مشبوه')
                    
                    # معلمات URL
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        param_count = len(params)
                        print(f"      المعلمات: {param_count}")
                        
                        if param_count > 5:
                            risk_score += 1
                            risk_indicators.append('معلمات كثيرة')
                        
                        # معلمات حساسة
                        sensitive_params = ['password', 'token', 'key', 'secret']
                        found_sensitive = [p for p in params.keys() if any(sp in p.lower() for sp in sensitive_params)]
                        if found_sensitive:
                            risk_score += 2
                            risk_indicators.append(f'معلمات حساسة: {", ".join(found_sensitive)}')
                    
                    # تحديد مستوى الخطر
                    if risk_score >= 3:
                        risk_level = 'مرتفع'
                    elif risk_score >= 1:
                        risk_level = 'متوسط'
                    else:
                        risk_level = 'منخفض'
                    
                    print(f"      مستوى الخطر: {risk_level}")
                    if risk_indicators:
                        print(f"      المؤشرات: {', '.join(risk_indicators)}")
        
        # معلومات الصورة
        image_info = qr_data.get('image_info', {})
        if image_info:
            print(f"   أبعاد الصورة: {image_info.get('width')}x{image_info.get('height')}")
            print(f"   تنسيق الصورة: {image_info.get('format', 'غير معروف')}")
    
    # معلومات الصورة الأصلية
    image_analysis = result.get('image_analysis', {})
    if image_analysis:
        print(f"\nمعلومات الصورة:")
        print(f"   الحجم: {image_analysis.get('size_human')}")
        print(f"   الأبعاد: {image_analysis.get('width')}x{image_analysis.get('height')}")
        print(f"   التنسيق: {image_analysis.get('format')}")
        print(f"   الوضع: {image_analysis.get('mode')}")
    
    # التوصيات
    print(f"\nالتوصيات:")
    
    for i, qr_data in enumerate(result.get('qr_codes', []), 1):
        data = qr_data.get('data', '')
        data_analysis = qr_data.get('data_analysis', {})
        
        if data_analysis.get('data_type') == 'URL':
            print(f"   {i}. تحقق من الرابط قبل فتحه: {data[:50]}...")
            
            # تحليل إضافي للرابط
            parsed = urlparse(data)
            if parsed.scheme not in ['http', 'https']:
                print(f"     مبدأ غير آمن: {parsed.scheme}")
            
            # فحص الدومين
            domain = parsed.netloc
            if not domain:
                print(f"     لا يوجد دومين")
            elif '.' not in domain:
                print(f"     دومين غير صالح: {domain}")
        else:
            print(f"   {i}. البيانات: {data[:100]}{'...' if len(data) > 100 else ''}")
    
    # فحص الروابط تلقائياً
    print("\n" + "=" * 60)
    auto_scan = input("هل تريد فحص الروابط الموجودة في QR تلقائياً؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if auto_scan:
        for qr_data in result.get('qr_codes', []):
            data = qr_data.get('data', '')
            if data.startswith(('http://', 'https://')):
                print(f"\nفحص الرابط: {data[:50]}...")
                
                try:
                    # فحص سريع
                    quick_report = scan_basic_enhanced(data)
                    
                    if quick_report.get('status_code'):
                        print(f"   رمز الحالة: {quick_report['status_code']}")
                        print(f"   الرابط النهائي: {quick_report['final_url']}")
                        
                        if quick_report['final_url'] != data:
                            print(f"   تحويل إلى: {quick_report['final_url']}")
                    
                except Exception as e:
                    print(f"   خطأ في الفحص: {e}")
    
    # حفظ التقرير
    print("\n" + "=" * 60)
    save = input("هل تريد حفظ تقرير التحليل؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        timestamp = int(time.time())
        safe_filename = sanitize_filename(os.path.basename(path))
        
        filename = f"qr_scan_{safe_filename}_{timestamp}.txt"
        filepath = os.path.join(folder, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("تقرير فحص QR متطور\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"مسار الصورة: {path}\n")
                f.write(f"اسم الملف: {os.path.basename(path)}\n")
                f.write(f"وقت الفحص: {now_str()}\n\n")
                
                if not result.get('qr_found'):
                    f.write("لم يتم العثور على QR code في الصورة\n")
                else:
                    f.write(f"تم العثور على {result.get('qr_count', 0)} QR code\n\n")
                    
                    for i, qr_data in enumerate(result['qr_codes'], 1):
                        f.write(f"QR #{i}:\n")
                        f.write(f"  النوع: {qr_data.get('type', 'غير معروف')}\n")
                        f.write(f"  البيانات: {qr_data.get('data', '')}\n")
                        
                        data_analysis = qr_data.get('data_analysis', {})
                        if data_analysis:
                            f.write(f"  نوع البيانات: {data_analysis.get('data_type')}\n")
                        
                        f.write("\n")
                
                if image_analysis:
                    f.write("معلومات الصورة:\n")
                    f.write(f"  الحجم: {image_analysis.get('size_human')}\n")
                    f.write(f"  الأبعاد: {image_analysis.get('width')}x{image_analysis.get('height')}\n")
                    f.write(f"  التنسيق: {image_analysis.get('format')}\n")
            
            print(f"تم حفظ التقرير: {filepath}")
        except Exception as e:
            print(f"خطأ في الحفظ: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى فحص QR")
    print("=" * 60)
    
    return result

def scan_qr_enhanced(path):
    """فحص QR من صورة متطور"""
    result = {
        'image_path': path,
        'filename': os.path.basename(path),
        'qr_found': False,
        'qr_count': 0,
        'qr_codes': [],
        'image_analysis': {},
        'scan_time': now_str()
    }
    
    try:
        # تحليل معلومات الصورة
        try:
            img = Image.open(path)
            
            result['image_analysis'] = {
                'format': img.format,
                'size': img.size,
                'width': img.width,
                'height': img.height,
                'mode': img.mode,
                'size_bytes': os.path.getsize(path),
                'size_human': human_readable_size(os.path.getsize(path))
            }
            
            # فك QR codes
            decoded_objects = qr_decode(img)
            
            if decoded_objects:
                result['qr_found'] = True
                result['qr_count'] = len(decoded_objects)
                
                for obj in decoded_objects:
                    qr_data = {
                        'type': obj.type,
                        'data': obj.data.decode('utf-8', errors='ignore'),
                        'data_analysis': {},
                        'image_info': {
                            'width': img.width,
                            'height': img.height,
                            'format': img.format
                        }
                    }
                    
                    # تحليل نوع البيانات
                    data = qr_data['data']
                    data_analysis = {'data_type': 'نص'}
                    
                    # URL
                    if data.startswith(('http://', 'https://')):
                        data_analysis['data_type'] = 'URL'
                        data_analysis['url'] = data
                        
                        parsed = urlparse(data)
                        data_analysis['domain'] = parsed.netloc
                        data_analysis['path'] = parsed.path
                        data_analysis['params_count'] = len(parse_qs(parsed.query))
                    
                    # بريد إلكتروني
                    elif '@' in data and '.' in data.split('@')[-1]:
                        email_match = re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data)
                        if email_match:
                            data_analysis['data_type'] = 'البريد الإلكتروني'
                            data_analysis['email'] = data
                    
                    # رقم هاتف
                    elif re.match(r'^\+?[\d\s\-\(\)]+$', data.replace(' ', '')):
                        data_analysis['data_type'] = 'رقم الهاتف'
                        data_analysis['phone'] = data
                    
                    # موقع جغرافي
                    elif 'geo:' in data.lower():
                        data_analysis['data_type'] = 'موقع جغرافي'
                    
                    # Wi-Fi
                    elif 'WIFI:' in data.upper():
                        data_analysis['data_type'] = 'إعدادات Wi-Fi'
                    
                    # vCard
                    elif 'BEGIN:VCARD' in data.upper():
                        data_analysis['data_type'] = 'vCard (بطاقة اتصال)'
                    
                    # تطبيق
                    elif data.startswith(('market://', 'itms://', 'itms-apps://')):
                        data_analysis['data_type'] = 'رابط تطبيق'
                    
                    qr_data['data_analysis'] = data_analysis
                    result['qr_codes'].append(qr_data)
        
        except Exception as e:
            result['error'] = f'خطأ في فك QR: {str(e)}'
    
    except Exception as e:
        result['error'] = f'خطأ في فتح الصورة: {str(e)}'
    
    return result

# ------------------------------------------------------------
# تطوير الخيار 7: فحص روابط تحميل متطور
def handle_scan_download_links_enhanced():
    """فحص روابط تحميل متطور"""
    print("=" * 60)
    print("فحص روابط تحميل متطور")
    print("=" * 60)
    
    links_input = input("أدخل رابط التحميل أو روابط مفصولة بفواصل: ").strip()
    
    if not links_input:
        print("لم تقم بإدخال أي روابط!")
        return None
    
    # تقسيم الروابط
    raw_links = [link.strip() for link in links_input.split(",") if link.strip()]
    
    if not raw_links:
        print("لم تقم بإدخال أي روابط صالحة!")
        return None
    
    print(f"\nجار فحص {len(raw_links)} رابط...")
    
    # تطبيع الروابط
    links = []
    for link in raw_links:
        try:
            normalized = normalize_url(link)
            if validate_url(normalized):
                links.append(normalized)
            else:
                print(f"رابط غير صالح تم تخطيه: {link}")
        except:
            print(f"رابط غير صالح تم تخطيه: {link}")
    
    if not links:
        print("لا توجد روابط صالحة للفحص!")
        return None
    
    print(f"\nسيتم فحص {len(links)} رابط صالح")
    
    results = []
    
    # فحص كل رابط
    for i, link in enumerate(links, 1):
        print(f"\n[{i}/{len(links)}] فحص الرابط: {link[:50]}...")
        
        try:
            # فحص سريع مع معلومات موسعة
            report = scan_download_link_enhanced(link)
            results.append(report)
            
            # عرض ملخص سريع
            print(f"   رمز الحالة: {report.get('status_code', 'غير معروف')}")
            print(f"   نوع الملف: {report.get('content_type', 'غير معروف')}")
            
            size = report.get('content_length', 0)
            if size:
                print(f"   حجم الملف: {human_readable_size(size)}")
            
            # تحليل المخاطر
            risk = report.get('risk_analysis', {})
            if risk:
                print(f"   مستوى الخطر: {risk.get('risk_level', 'غير معروف')}")
            
        except Exception as e:
            print(f"   خطأ في فحص الرابط: {e}")
            results.append({'url': link, 'error': str(e)})
    
    # عرض النتائج الإجمالية
    print("\n" + "=" * 60)
    print("النتائج الإجمالية")
    print("=" * 60)
    
    # إحصائيات
    successful = sum(1 for r in results if not r.get('error'))
    errors = len(results) - successful
    
    high_risk = sum(1 for r in results if r.get('risk_analysis', {}).get('risk_level') == 'مرتفع')
    medium_risk = sum(1 for r in results if r.get('risk_analysis', {}).get('risk_level') == 'متوسط')
    low_risk = sum(1 for r in results if r.get('risk_analysis', {}).get('risk_level') == 'منخفض')
    safe = sum(1 for r in results if r.get('risk_analysis', {}).get('risk_level') == 'آمن')
    
    print(f"\nإحصائيات:")
    print(f"   إجمالي الروابط: {len(results)}")
    print(f"   فحص ناجح: {successful}")
    print(f"   أخطاء: {errors}")
    print(f"\n   خطر مرتفع: {high_risk}")
    print(f"   خطر متوسط: {medium_risk}")
    print(f"   خطر منخفض: {low_risk}")
    print(f"   آمن: {safe}")
    
    # عرض الروابط الخطرة
    dangerous_links = []
    for report in results:
        risk = report.get('risk_analysis', {})
        if risk and risk.get('risk_level') in ['مرتفع', 'متوسط']:
            dangerous_links.append({
                'url': report.get('url', 'غير معروف'),
                'risk': risk.get('risk_level'),
                'indicators': risk.get('risk_indicators', [])[:2]
            })
    
    if dangerous_links:
        print(f"\nالروابط الخطرة ({len(dangerous_links)}):")
        for link_info in dangerous_links[:5]:
            print(f"   • {link_info['url'][:50]}... ({link_info['risk']})")
            if link_info['indicators']:
                print(f"     مؤشرات: {', '.join(link_info['indicators'])}")
        
        if len(dangerous_links) > 5:
            print(f"   • ... و{len(dangerous_links) - 5} روابط خطرة أخرى")
    
    # عرض الملفات الكبيرة
    large_files = []
    for report in results:
        size = report.get('content_length', 0)
        if size > 100 * 1024 * 1024:  # أكبر من 100MB
            large_files.append({
                'url': report.get('url', 'غير معروف'),
                'size': human_readable_size(size)
            })
    
    if large_files:
        print(f"\nالملفات الكبيرة ({len(large_files)}):")
        for file_info in large_files[:3]:
            print(f"   • {file_info['url'][:40]}... ({file_info['size']})")
        
        if len(large_files) > 3:
            print(f"   • ... و{len(large_files) - 3} ملفات كبيرة أخرى")
    
    # التوصيات
    print(f"\nالتوصيات:")
    
    if high_risk > 0:
        print("   هناك روابط عالية الخطورة - تجنب تحميلها")
    
    if medium_risk > 0:
        print("   هناك روابط متوسطة الخطورة - كن حذراً عند التحميل")
    
    if large_files:
        print("   هناك ملفات كبيرة - تأكد من مساحة التخزين")
    
    if errors > 0:
        print("   بعض الروابط فشل فحصها - تحقق من اتصال الإنترنت")
    
    # حفظ التقارير
    print("\n" + "=" * 60)
    save = input("هل تريد حفظ تقارير الفحص؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        timestamp = int(time.time())
        
        # حفظ تقرير إجمالي
        summary_file = os.path.join(folder, f"download_links_summary_{timestamp}.txt")
        
        try:
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("تقرير فحص روابط تحميل متطور\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"وقت الفحص: {now_str()}\n")
                f.write(f"عدد الروابط المدخلة: {len(raw_links)}\n")
                f.write(f"عدد الروابط المفحوصة: {len(links)}\n\n")
                
                f.write("الإحصائيات:\n")
                f.write(f"  فحص ناجح: {successful}\n")
                f.write(f"  أخطاء: {errors}\n")
                f.write(f"  خطر مرتفع: {high_risk}\n")
                f.write(f"  خطر متوسط: {medium_risk}\n")
                f.write(f"  خطر منخفض: {low_risk}\n")
                f.write(f"  آمن: {safe}\n\n")
                
                f.write("النتائج التفصيلية:\n")
                for i, report in enumerate(results, 1):
                    f.write(f"\n[{i}] {report.get('url', 'غير معروف')}\n")
                    
                    if report.get('error'):
                        f.write(f"  خطأ: {report['error']}\n")
                        continue
                    
                    f.write(f"  رمز الحالة: {report.get('status_code', 'غير معروف')}\n")
                    f.write(f"  نوع الملف: {report.get('content_type', 'غير معروف')}\n")
                    
                    size = report.get('content_length', 0)
                    if size:
                        f.write(f"  حجم الملف: {human_readable_size(size)}\n")
                    
                    risk = report.get('risk_analysis', {})
                    if risk:
                        f.write(f"  مستوى الخطر: {risk.get('risk_level', 'غير معروف')}\n")
                        
                        if risk.get('risk_indicators'):
                            f.write(f"  مؤشرات الخطر:\n")
                            for indicator in risk['risk_indicators'][:3]:
                                f.write(f"    • {indicator}\n")
            
            print(f"تم حفظ التقرير الإجمالي: {summary_file}")
            
            # حفظ تقارير فردية
            save_individual = input("هل تريد حفظ تقرير منفصل لكل رابط؟ (نعم/لا): ").strip().lower() == "نعم"
            
            if save_individual:
                for i, report in enumerate(results):
                    if not report.get('error'):
                        domain = urlparse(report.get('url', '')).hostname or f"link_{i}"
                        safe_domain = sanitize_filename(domain)
                        
                        individual_file = os.path.join(folder, f"download_{safe_domain}_{timestamp}_{i}.txt")
                        
                        try:
                            with open(individual_file, 'w', encoding='utf-8') as f:
                                f.write("=" * 60 + "\n")
                                f.write(f"تقرير فحص رابط تحميل\n")
                                f.write("=" * 60 + "\n\n")
                                
                                f.write(f"الرابط: {report.get('url', 'غير معروف')}\n")
                                f.write(f"وقت الفحص: {now_str()}\n\n")
                                
                                f.write("معلومات الرابط:\n")
                                f.write(f"  رمز الحالة: {report.get('status_code', 'غير معروف')}\n")
                                f.write(f"  نوع المحتوى: {report.get('content_type', 'غير معروف')}\n")
                                
                                size = report.get('content_length', 0)
                                if size:
                                    f.write(f"  حجم الملف: {human_readable_size(size)}\n")
                                
                                f.write(f"  الخادم: {report.get('server', 'غير معروف')}\n\n")
                                
                                risk = report.get('risk_analysis', {})
                                if risk:
                                    f.write("تحليل المخاطر:\n")
                                    f.write(f"  مستوى الخطر: {risk.get('risk_level', 'غير معروف')}\n")
                                    f.write(f"  النقاط: {risk.get('risk_score', 0)}\n")
                                    
                                    if risk.get('risk_indicators'):
                                        f.write("  مؤشرات:\n")
                                        for indicator in risk['risk_indicators']:
                                            f.write(f"    • {indicator}\n")
                                    
                                    f.write("\n")
                                
                                f.write("التوصيات:\n")
                                risk_level = risk.get('risk_level', 'آمن') if risk else 'آمن'
                                
                                if risk_level == 'مرتفع':
                                    f.write("  تجنب تحميل هذا الملف\n")
                                elif risk_level == 'متوسط':
                                    f.write("  كن حذراً عند التحميل\n")
                                elif risk_level == 'منخفض':
                                    f.write("  الملف مقبول لكن تحقق من مصدره\n")
                                else:
                                    f.write("  الملف يبدو آمناً\n")
                            
                            print(f"  تم حفظ: {os.path.basename(individual_file)}")
                        except Exception as e:
                            print(f"  خطأ في حفظ التقرير الفردي: {e}")
        
        except Exception as e:
            print(f"خطأ في حفظ التقرير: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى فحص روابط التحميل")
    print("=" * 60)
    
    return results

def scan_download_link_enhanced(url):
    """فحص رابط تحميل متطور"""
    report = {
        'url': url,
        'scanned_at': now_str(),
        'status_code': None,
        'content_type': '',
        'content_length': 0,
        'server': '',
        'headers': {},
        'risk_analysis': {},
        'file_info': {},
        'download_info': {}
    }
    
    try:
        session = create_session()
        
        # طلب HEAD أولاً
        head_response = session.head(
            url,
            allow_redirects=True,
            timeout=15,
            headers={'User-Agent': get_random_user_agent()}
        )
        
        report['status_code'] = head_response.status_code
        report['content_type'] = head_response.headers.get('Content-Type', '')
        report['server'] = head_response.headers.get('Server', '')
        
        # جمع الهيدرات المهمة
        important_headers = [
            'Content-Length', 'Content-Type', 'Server', 'Date',
            'Last-Modified', 'ETag', 'Accept-Ranges', 'Content-Disposition'
        ]
        
        headers_dict = {}
        for header in important_headers:
            if header in head_response.headers:
                headers_dict[header] = head_response.headers[header]
        
        report['headers'] = headers_dict
        
        # حجم المحتوى
        content_length = head_response.headers.get('Content-Length')
        if content_length:
            try:
                report['content_length'] = int(content_length)
            except:
                pass
        
        # معلومات الملف
        file_info = {}
        
        # استخراج اسم الملف من Content-Disposition
        content_disposition = head_response.headers.get('Content-Disposition', '')
        if 'filename=' in content_disposition:
            import re
            match = re.search(r'filename=["\']?([^"\']+)["\']?', content_disposition)
            if match:
                file_info['suggested_name'] = match.group(1)
        
        # استخراج اسم الملف من URL
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        if path_parts and path_parts[-1]:
            file_info['url_filename'] = path_parts[-1]
        
        # تحديد نوع الملف من Content-Type
        content_type = report['content_type'].lower()
        file_type = 'غير معروف'
        
        if 'application/pdf' in content_type:
            file_type = 'PDF'
        elif 'application/zip' in content_type or 'application/x-zip' in content_type:
            file_type = 'ZIP'
        elif 'application/x-rar' in content_type:
            file_type = 'RAR'
        elif 'application/x-7z' in content_type:
            file_type = '7Z'
        elif 'application/x-tar' in content_type:
            file_type = 'TAR'
        elif 'application/gzip' in content_type:
            file_type = 'GZIP'
        elif 'application/x-msdownload' in content_type or 'application/octet-stream' in content_type:
            file_type = 'تنفيذي'
        elif 'text/' in content_type:
            file_type = 'نصي'
        elif 'image/' in content_type:
            file_type = 'صورة'
        elif 'audio/' in content_type:
            file_type = 'صوت'
        elif 'video/' in content_type:
            file_type = 'فيديو'
        
        file_info['file_type'] = file_type
        
        report['file_info'] = file_info
        
        # تحليل المخاطر
        risk_score = 0
        risk_indicators = []
        
        # 1. رمز الحالة
        status = report['status_code']
        if status and status >= 400:
            if status == 403:
                risk_score += 1
                risk_indicators.append('ممنوع الوصول (403)')
            elif status == 404:
                risk_score += 1
                risk_indicators.append('غير موجود (404)')
            elif status >= 500:
                risk_score += 1
                risk_indicators.append(f'خطأ في الخادم ({status})')
        
        # 2. نوع الملف الخطير
        dangerous_types = [
            'application/x-msdownload',
            'application/octet-stream',
            'application/x-msdos-program',
            'application/x-executable'
        ]
        
        if any(dangerous in content_type for dangerous in dangerous_types):
            risk_score += 3
            risk_indicators.append('ملف تنفيذي')
        
        # 3. حجم الملف الكبير جداً
        if report['content_length'] > 500 * 1024 * 1024:  # أكبر من 500MB
            risk_score += 2
            risk_indicators.append('حجم كبير جداً')
        elif report['content_length'] > 100 * 1024 * 1024:  # أكبر من 100MB
            risk_score += 1
            risk_indicators.append('حجم كبير')
        
        # 4. دومين مشبوه
        domain = parsed.netloc.lower()
        suspicious_keywords = ['download', 'free', 'file', 'get', 'upload', 'share']
        if any(keyword in domain for keyword in suspicious_keywords):
            risk_score += 1
            risk_indicators.append('دومين مشبوه')
        
        # 5. عدم وجود Content-Type
        if not report['content_type']:
            risk_score += 2
            risk_indicators.append('نوع الملف غير معروف')
        
        # 6. امتدادات خطرة
        if file_info.get('url_filename'):
            filename = file_info['url_filename'].lower()
            dangerous_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.sh', '.jar', '.apk', '.ipa']
            
            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    risk_score += 3
                    risk_indicators.append(f'امتداد خطير: {ext}')
                    break
        
        # تحديد مستوى الخطر
        if risk_score >= 8:
            risk_level = 'مرتفع جداً'
        elif risk_score >= 5:
            risk_level = 'مرتفع'
        elif risk_score >= 3:
            risk_level = 'متوسط'
        elif risk_score >= 1:
            risk_level = 'منخفض'
        else:
            risk_level = 'آمن'
        
        report['risk_analysis'] = {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_indicators': risk_indicators
        }
        
        # معلومات التحميل
        report['download_info'] = {
            'is_downloadable': 200 <= status < 300 if status else False,
            'supports_resume': 'Accept-Ranges' in head_response.headers,
            'has_last_modified': 'Last-Modified' in head_response.headers,
            'estimated_download_time': estimate_download_time(report['content_length']) if report['content_length'] else 'غير معروف'
        }
    
    except Exception as e:
        report['error'] = str(e)
    
    return report

def estimate_download_time(size_bytes):
    """تقدير وقت التحميل"""
    if not size_bytes:
        return "غير معروف"
    
    # افتراض سرعة تحميل 1 ميجابت/ثانية (0.125 ميجابايت/ثانية)
    speed_mbps = 1
    speed_bytes_per_sec = speed_mbps * 125000
    
    seconds = size_bytes / speed_bytes_per_sec
    
    if seconds < 60:
        return f"{seconds:.0f} ثانية"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} دقيقة"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} ساعة"

# ------------------------------------------------------------
# تطوير الخيار 8: فحص ملف عام متطور
def handle_scan_generic_file_enhanced():
    """فحص ملف عام متطور"""
    print("=" * 60)
    print("فحص ملف عام متطور")
    print("=" * 60)
    
    path = input("أدخل مسار الملف لفحصه (أي صيغة): ").strip()
    
    if not os.path.isfile(path):
        print("الملف غير موجود!")
        return None
    
    print(f"\nجار فحص الملف: {os.path.basename(path)}")
    report = scan_generic_file_enhanced(path)
    
    print("\n" + "=" * 60)
    print("نتائج الفحص المتطور")
    print("=" * 60)
    
    print(f"\nمعلومات الملف الأساسية:")
    print(f"   الاسم: {report.get('filename')}")
    print(f"   المسار: {report.get('path')}")
    print(f"   الحجم: {report.get('size_human')}")
    print(f"   الامتداد: {report.get('extension')}")
    print(f"   نوع الملف: {report.get('file_type', 'غير معروف')}")
    
    # الهاشات
    hashes = report.get('hashes', {})
    if hashes:
        print(f"\nالهاشات:")
        print(f"   MD5: {hashes.get('md5', 'غير متوفر')}")
        print(f"   SHA1: {hashes.get('sha1', 'غير متوفر')}")
        print(f"   SHA256: {hashes.get('sha256', 'غير متوفر')}")
    
    # تحليل الملف
    file_analysis = report.get('file_analysis', {})
    if file_analysis:
        print(f"\nتحليل الملف:")
        
        magic_info = file_analysis.get('magic_info')
        if magic_info:
            print(f"   التحديد السحري: {magic_info[:100]}...")
        
        is_text = file_analysis.get('is_text_file', False)
        print(f"   ملف نصي: {'نعم' if is_text else 'لا'}")
        
        if is_text:
            encoding = file_analysis.get('detected_encoding', 'غير معروف')
            print(f"   الترميز: {encoding}")
    
    # تحليل المخاطر
    threat_analysis = report.get('threat_analysis', {})
    if threat_analysis:
        print(f"\nتحليل المخاطر:")
        print(f"   مستوى التهديد: {threat_analysis.get('threat_level', 'غير معروف')}")
        print(f"   النقاط: {threat_analysis.get('threat_score', 0)}/20")
        
        indicators = threat_analysis.get('threat_indicators', [])
        if indicators:
            print(f"   مؤشرات التهديد ({len(indicators)}):")
            for i, indicator in enumerate(indicators[:5], 1):
                print(f"     {i}. {indicator}")
            if len(indicators) > 5:
                print(f"     ... و{len(indicators) - 5} مؤشرات أخرى")
    
    # الأنماط المشبوهة
    patterns_found = report.get('suspicious_patterns', {})
    if patterns_found:
        print(f"\nالأنماط المشبوهة المكتشفة:")
        for pattern_type, patterns in patterns_found.items():
            if patterns:
                print(f"   {pattern_type}: {len(patterns)}")
                for pattern in patterns[:2]:
                    print(f"     • {pattern[:50]}...")
                if len(patterns) > 2:
                    print(f"     • ... و{len(patterns) - 2} أنماط أخرى")
    
    # تحليل المحتوى
    content_analysis = report.get('content_analysis', {})
    if content_analysis:
        print(f"\nتحليل المحتوى:")
        
        strings = content_analysis.get('strings_found', [])
        if strings:
            print(f"   سلاسل نصية مكتشفة: {len(strings)}")
            for string in strings[:3]:
                print(f"     • {string[:50]}...")
            if len(strings) > 3:
                print(f"     • ... و{len(strings) - 3} سلاسل أخرى")
        
        urls = content_analysis.get('urls_found', [])
        if urls:
            print(f"   روابط مكتشفة: {len(urls)}")
            for url in urls[:3]:
                print(f"     • {url[:50]}...")
        
        emails = content_analysis.get('emails_found', [])
        if emails:
            print(f"   عناوين بريد مكتشفة: {len(emails)}")
            for email in emails[:3]:
                print(f"     • {email}")
    
    # المعلومات الثنائية
    binary_info = report.get('binary_analysis', {})
    if binary_info:
        print(f"\nتحليل ثنائي:")
        
        sections = binary_info.get('pe_sections', [])
        if sections:
            print(f"   أقسام PE: {len(sections)}")
            for section in sections[:3]:
                print(f"     • {section}")
        
        imports = binary_info.get('imports', [])
        if imports:
            print(f"   استيرادات: {len(imports)}")
            for imp in imports[:3]:
                print(f"     • {imp}")
    
    # المعلومات الأرشيفية
    archive_info = report.get('archive_analysis', {})
    if archive_info:
        print(f"\nتحليل الأرشيف:")
        print(f"   نوع الأرشيف: {archive_info.get('archive_type', 'غير معروف')}")
        print(f"   عدد الملفات: {archive_info.get('file_count', 0)}")
        
        files = archive_info.get('files', [])
        if files:
            print(f"   الملفات ({len(files)}):")
            for file in files[:3]:
                print(f"     • {file[:50]}...")
            if len(files) > 3:
                print(f"     • ... و{len(files) - 3} ملفات أخرى")
    
    # التوصيات
    recommendations = report.get('recommendations', [])
    if recommendations:
        print(f"\nالتوصيات:")
        for i, rec in enumerate(recommendations[:5], 1):
            print(f"   {i}. {rec}")
    
    # تقدير المخاطر
    threat_score = threat_analysis.get('threat_score', 0) if threat_analysis else 0
    print(f"\nتقدير المخاطر:")
    
    if threat_score >= 15:
        print("   خطر عالي جداً - تجنب فتح هذا الملف!")
    elif threat_score >= 10:
        print("   خطر عالي - كن حذراً جداً!")
    elif threat_score >= 5:
        print("   خطر متوسط - تحقق من مصدر الملف")
    elif threat_score > 0:
        print("   خطر منخفض - قد يحتوي على محتوى مشبوه")
    else:
        print("   يبدو الملف آمناً")
    
    # حفظ التقرير
    print("\n" + "=" * 60)
    save = input("هل تريد حفظ تقرير الفحص؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        timestamp = int(time.time())
        safe_filename = sanitize_filename(report.get('filename', 'file'))
        
        filename = f"generic_scan_{safe_filename}_{timestamp}.txt"
        filepath = os.path.join(folder, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("تقرير فحص ملف عام متطور\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"اسم الملف: {report.get('filename')}\n")
                f.write(f"المسار: {report.get('path')}\n")
                f.write(f"الحجم: {report.get('size_human')}\n")
                f.write(f"الامتداد: {report.get('extension')}\n")
                f.write(f"نوع الملف: {report.get('file_type', 'غير معروف')}\n\n")
                
                f.write("الهاشات:\n")
                for hash_name, hash_value in hashes.items():
                    f.write(f"  {hash_name.upper()}: {hash_value}\n")
                
                f.write("\nتحليل المخاطر:\n")
                if threat_analysis:
                    f.write(f"  مستوى التهديد: {threat_analysis.get('threat_level')}\n")
                    f.write(f"  النقاط: {threat_analysis.get('threat_score', 0)}/20\n")
                    
                    if threat_analysis.get('threat_indicators'):
                        f.write("  مؤشرات التهديد:\n")
                        for indicator in threat_analysis['threat_indicators']:
                            f.write(f"    • {indicator}\n")
                
                f.write("\nالأنماط المشبوهة:\n")
                if patterns_found:
                    for pattern_type, patterns in patterns_found.items():
                        if patterns:
                            f.write(f"  {pattern_type} ({len(patterns)}):\n")
                            for pattern in patterns[:5]:
                                f.write(f"    • {pattern[:100]}\n")
                
                f.write("\nتحليل المحتوى:\n")
                if content_analysis:
                    strings = content_analysis.get('strings_found', [])
                    if strings:
                        f.write(f"  سلاسل نصية: {len(strings)}\n")
                    
                    urls = content_analysis.get('urls_found', [])
                    if urls:
                        f.write(f"  روابط: {len(urls)}\n")
                        for url in urls[:5]:
                            f.write(f"    • {url}\n")
                    
                    emails = content_analysis.get('emails_found', [])
                    if emails:
                        f.write(f"  عناوين بريد: {len(emails)}\n")
                        for email in emails[:5]:
                            f.write(f"    • {email}\n")
                
                f.write("\nالتوصيات:\n")
                for rec in recommendations:
                    f.write(f"  • {rec}\n")
            
            print(f"تم حفظ التقرير: {filepath}")
            
            # حفظ JSON مفصل
            json_file = filepath.replace('.txt', '.json')
            try:
                with open(json_file, 'w', encoding='utf-8') as f:
                    import json
                    json.dump(report, f, ensure_ascii=False, indent=2, default=str)
                print(f"تم حفظ البيانات الكاملة: {os.path.basename(json_file)}")
            except Exception as e:
                print(f"خطأ في حفظ JSON: {e}")
        
        except Exception as e:
            print(f"خطأ في الحفظ: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى فحص الملف العام")
    print("=" * 60)
    
    return report

def scan_generic_file_enhanced(path):
    """فحص ملف عام متطور"""
    report = {
        'path': path,
        'filename': os.path.basename(path),
        'size_bytes': 0,
        'size_human': '',
        'extension': '',
        'file_type': 'غير معروف',
        'hashes': {},
        'file_analysis': {},
        'threat_analysis': {},
        'suspicious_patterns': {},
        'content_analysis': {},
        'binary_analysis': {},
        'archive_analysis': {},
        'recommendations': []
    }
    
    try:
        # معلومات الملف الأساسية
        size = os.path.getsize(path)
        report['size_bytes'] = size
        report['size_human'] = human_readable_size(size)
        
        ext = os.path.splitext(path)[1].lower()
        report['extension'] = ext
        
        # حساب الهاشات
        with open(path, 'rb') as f:
            content = f.read()
            report['hashes'] = {
                'md5': hashlib.md5(content).hexdigest(),
                'sha1': hashlib.sha1(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest()
            }
        
        # تحاول تحديد نوع الملف
        file_analysis = report['file_analysis']
        
        # استخدام python-magic إذا كان متاحاً
        try:
            import magic
            mime = magic.Magic(mime=True)
            file_analysis['magic_info'] = mime.from_file(path)
            
            # تحديد نوع الملف من MIME type
            mime_type = file_analysis['magic_info']
            if 'text/' in mime_type:
                file_analysis['is_text_file'] = True
            elif 'application/' in mime_type:
                file_analysis['is_binary'] = True
        except:
            file_analysis['magic_info'] = 'غير متوفر (تثبيت python-magic لمزيد من الدقة)'
        
        # تحليل أولي
        try:
            with open(path, 'rb') as f:
                header = f.read(1024)  # قراءة أول 1KB
                
                # التحقق من توقيعات الملفات المعروفة
                signatures = {
                    b'\x25\x50\x44\x46': 'PDF',
                    b'\x50\x4B\x03\x04': 'ZIP',
                    b'\x52\x61\x72\x21\x1A\x07': 'RAR',
                    b'\x37\x7A\xBC\xAF\x27\x1C': '7Z',
                    b'\x1F\x8B\x08': 'GZIP',
                    b'\x4D\x5A': 'PE (تنفيذي Windows)',
                    b'\x7F\x45\x4C\x46': 'ELF (تنفيذي Linux)',
                    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'PNG',
                    b'\xFF\xD8\xFF': 'JPEG',
                    b'\x47\x49\x46\x38': 'GIF',
                    b'\x42\x4D': 'BMP',
                    b'\x49\x44\x33': 'MP3',
                    b'\x00\x00\x00\x20\x66\x74\x79\x70': 'MP4',
                    b'\x52\x49\x46\x46': 'AVI/WAV'
                }
                
                for signature, file_type in signatures.items():
                    if header.startswith(signature):
                        file_analysis['detected_signature'] = file_type
                        report['file_type'] = file_type
                        break
                
                # تحديد الترميز للملفات النصية
                try:
                    with open(path, 'r', encoding='utf-8') as text_file:
                        text_file.read(1000)
                        file_analysis['detected_encoding'] = 'UTF-8'
                        file_analysis['is_text_file'] = True
                except UnicodeDecodeError:
                    try:
                        with open(path, 'r', encoding='cp1256') as text_file:
                            text_file.read(1000)
                            file_analysis['detected_encoding'] = 'Windows-1256'
                            file_analysis['is_text_file'] = True
                    except:
                        file_analysis['is_text_file'] = False
        
        except Exception as e:
            file_analysis['header_analysis_error'] = str(e)
        
        # تحليل المخاطر
        threat_score = 0
        threat_indicators = []
        suspicious_patterns = {
            'execution': [],
            'network': [],
            'obfuscation': [],
            'suspicious_strings': []
        }
        
        # قراءة محتوى الملف للتحليل (أول 1MB)
        try:
            with open(path, 'rb') as f:
                file_content = f.read(min(size, 1048576))  # 1MB كحد أقصى
                
                # تحليل الأنماط المشبوهة
                patterns_to_check = [
                    (rb'eval\s*\(', 'eval', 'execution'),
                    (rb'exec\s*\(', 'exec', 'execution'),
                    (rb'system\s*\(', 'system', 'execution'),
                    (rb'popen\s*\(', 'popen', 'execution'),
                    (rb'http://', 'http://', 'network'),
                    (rb'https://', 'https://', 'network'),
                    (rb'base64_decode', 'base64_decode', 'obfuscation'),
                    (rb'gzinflate', 'gzinflate', 'obfuscation'),
                    (rb'str_rot13', 'str_rot13', 'obfuscation'),
                    (rb'cmd\.exe', 'cmd.exe', 'execution'),
                    (rb'powershell', 'powershell', 'execution'),
                    (rb'/bin/bash', '/bin/bash', 'execution'),
                    (rb'/bin/sh', '/bin/sh', 'execution'),
                    (rb'CreateProcess', 'CreateProcess', 'execution'),
                    (rb'ShellExecute', 'ShellExecute', 'execution')
                ]
                
                for pattern, name, category in patterns_to_check:
                    import re
                    matches = re.findall(pattern, file_content, re.IGNORECASE)
                    if matches:
                        threat_score += 1
                        threat_indicators.append(f'يحتوي على {name}')
                        unique_matches = list(set(matches))[:5]
                        suspicious_patterns[category].extend([m.decode('utf-8', errors='ignore')[:100] for m in unique_matches])
                
                # استخراج السلاسل النصية
                try:
                    # استخراج سلاسل ASCII القابلة للطباعة
                    import string
                    printable = set(string.printable)
                    
                    strings = []
                    current_string = []
                    
                    for byte in file_content:
                        char = chr(byte) if 32 <= byte < 127 else ''
                        if char:
                            current_string.append(char)
                        else:
                            if len(current_string) >= 4:
                                strings.append(''.join(current_string))
                            current_string = []
                    
                    if len(current_string) >= 4:
                        strings.append(''.join(current_string))
                    
                    # حفظ السلاسل المثيرة للاهتمام
                    interesting_strings = []
                    for s in strings:
                        if len(s) >= 8:  # سلاسل طويلة نسبياً
                            interesting_strings.append(s)
                    
                    suspicious_patterns['suspicious_strings'] = interesting_strings[:50]
                    
                except:
                    pass
                
                # استخراج الروابط
                try:
                    text_content = file_content.decode('utf-8', errors='ignore')[:100000]
                    
                    url_pattern = r'https?://[^\s<>"\']+'
                    urls = re.findall(url_pattern, text_content)
                    
                    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                    emails = re.findall(email_pattern, text_content)
                    
                    report['content_analysis'] = {
                        'strings_found': interesting_strings[:100] if 'interesting_strings' in locals() else [],
                        'urls_found': list(set(urls))[:20],
                        'emails_found': list(set(emails))[:10]
                    }
                    
                except:
                    pass
        
        except Exception as e:
            report['content_analysis_error'] = str(e)
        
        # تحليل ثنائي للملفات التنفيذية
        if ext in ['.exe', '.dll', '.sys', '.so', '.bin']:
            try:
                with open(path, 'rb') as f:
                    header = f.read(64)
                    
                    binary_info = {}
                    
                    # PE files
                    if header[0:2] == b'MZ':
                        binary_info['is_pe'] = True
                        
                        # قراءة معلومات PE الأساسية
                        if len(header) > 60:
                            pe_offset = int.from_bytes(header[60:64], 'little')
                            f.seek(pe_offset)
                            pe_header = f.read(4)
                            
                            if pe_header == b'PE\x00\x00':
                                binary_info['has_pe_header'] = True
                                
                                # قراءة عدد الأقسام
                                f.seek(pe_offset + 6)
                                num_sections = int.from_bytes(f.read(2), 'little')
                                binary_info['pe_sections_count'] = num_sections
                                
                                # قراءة تاريخ الإنشاء
                                f.seek(pe_offset + 8)
                                timestamp = int.from_bytes(f.read(4), 'little')
                                if timestamp > 0:
                                    import datetime
                                    dt = datetime.datetime.fromtimestamp(timestamp)
                                    binary_info['compile_time'] = dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    report['binary_analysis'] = binary_info
                    
                    # زيادة نقاط المخاطر للملفات التنفيذية
                    threat_score += 3
                    threat_indicators.append('ملف تنفيذي')
            
            except Exception as e:
                report['binary_analysis_error'] = str(e)
        
        # تحليل الأرشيفات
        elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            try:
                import zipfile
                
                archive_info = {}
                
                if ext == '.zip':
                    with zipfile.ZipFile(path, 'r') as z:
                        file_list = z.namelist()
                        archive_info = {
                            'archive_type': 'ZIP',
                            'file_count': len(file_list),
                            'files': file_list[:20]
                        }
                
                report['archive_analysis'] = archive_info
                
                # زيادة نقاط المخاطر للأرشيفات
                threat_score += 1
                threat_indicators.append('ملف أرشيف')
                
            except Exception as e:
                report['archive_analysis_error'] = str(e)
        
        # تحليل المستندات
        elif ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            threat_score += 1
            threat_indicators.append('ملف مستند')
        
        # تنظيف الأنماط الفارغة
        for key in list(suspicious_patterns.keys()):
            if not suspicious_patterns[key]:
                del suspicious_patterns[key]
        
        report['suspicious_patterns'] = suspicious_patterns
        
        # تحديد مستوى التهديد
        if threat_score >= 15:
            threat_level = 'مرتفع جداً'
        elif threat_score >= 10:
            threat_level = 'مرتفع'
        elif threat_score >= 5:
            threat_level = 'متوسط'
        elif threat_score >= 2:
            threat_level = 'منخفض'
        elif threat_score > 0:
            threat_level = 'طفيف'
        else:
            threat_level = 'آمن'
        
        report['threat_analysis'] = {
            'threat_score': threat_score,
            'threat_level': threat_level,
            'threat_indicators': threat_indicators
        }
        
        # التوصيات
        recommendations = report['recommendations']
        
        if threat_level in ['مرتفع جداً', 'مرتفع']:
            recommendations.append('خطر عالي - تجنب فتح هذا الملف')
        elif threat_level == 'متوسط':
            recommendations.append('خطر متوسط - تحقق من مصدر الملف قبل الفتح')
        
        if suspicious_patterns.get('execution'):
            recommendations.append('يحتوي على أوامر تنفيذية')
        
        if suspicious_patterns.get('network'):
            recommendations.append('يتصل بالشبكة')
        
        if ext in ['.exe', '.dll', '.sys']:
            recommendations.append('ملف تنفيذي - قم بفحصه بمضاد فيروسات')
        
        if not recommendations:
            recommendations.append('يبدو الملف آمناً، لكن تحقق دائماً من مصدر الملف')
    
    except Exception as e:
        report['error'] = str(e)
    
    return report

# ------------------------------------------------------------
# تطوير الخيار 9: فحص APK/IPA مخصص متطور
def handle_scan_apk_ipa_enhanced():
    """فحص APK/IPA مخصص متطور"""
    print("=" * 60)
    print("فحص تطبيقات الجوال (APK/IPA) متطور")
    print("=" * 60)
    
    path = input("أدخل مسار ملف APK أو IPA: ").strip()
    
    if not os.path.isfile(path):
        print("الملف غير موجود!")
        return None
    
    filename = os.path.basename(path)
    ext = os.path.splitext(path)[1].lower()
    
    if ext not in ['.apk', '.ipa']:
        print(f"الملف ليس APK أو IPA! الامتداد: {ext}")
        return None
    
    print(f"\nجار فحص تطبيق الجوال: {filename}")
    report = scan_mobile_app_enhanced(path)
    
    print("\n" + "=" * 60)
    print("نتائج الفحص المتطور")
    print("=" * 60)
    
    print(f"\nمعلومات التطبيق:")
    print(f"   الاسم: {report.get('filename')}")
    print(f"   المسار: {report.get('path')}")
    print(f"   الحجم: {report.get('size_human')}")
    print(f"   الامتداد: {ext}")
    print(f"   نوع التطبيق: {report.get('app_type', 'غير معروف')}")
    
    # الهاشات
    hashes = report.get('hashes', {})
    if hashes:
        print(f"\nالهاشات:")
        print(f"   MD5: {hashes.get('md5', 'غير متوفر')}")
        print(f"   SHA1: {hashes.get('sha1', 'غير متوفر')}")
        print(f"   SHA256: {hashes.get('sha256', 'غير متوفر')}")
    
    # معلومات الأرشيف
    archive_info = report.get('archive_info', {})
    if archive_info:
        print(f"\nمعلومات الأرشيف:")
        print(f"   عدد الملفات: {archive_info.get('file_count', 0)}")
        print(f"   حجم مضغوط: {human_readable_size(archive_info.get('compressed_size', 0))}")
        print(f"   حجم غير مضغوط: {human_readable_size(archive_info.get('uncompressed_size', 0))}")
    
    # الملفات المهمة
    important_files = report.get('important_files', {})
    if important_files:
        print(f"\nالملفات المهمة:")
        
        for file_type, files in important_files.items():
            if files:
                print(f"   {file_type}: {len(files)}")
                for file in files[:2]:
                    print(f"     • {file[:50]}...")
                if len(files) > 2:
                    print(f"     • ... و{len(files) - 2} ملفات أخرى")
    
    # تحليل المخاطر
    threat_analysis = report.get('threat_analysis', {})
    if threat_analysis:
        print(f"\nتحليل المخاطر:")
        print(f"   مستوى التهديد: {threat_analysis.get('threat_level', 'غير معروف')}")
        print(f"   النقاط: {threat_analysis.get('threat_score', 0)}/20")
        
        indicators = threat_analysis.get('threat_indicators', [])
        if indicators:
            print(f"   مؤشرات التهديد ({len(indicators)}):")
            for i, indicator in enumerate(indicators[:5], 1):
                print(f"     {i}. {indicator}")
            if len(indicators) > 5:
                print(f"     ... و{len(indicators) - 5} مؤشرات أخرى")
    
    # الأنماط المشبوهة
    suspicious_patterns = report.get('suspicious_patterns', {})
    if suspicious_patterns:
        print(f"\nالأنماط المشبوهة المكتشفة:")
        for pattern_type, patterns in suspicious_patterns.items():
            if patterns:
                print(f"   {pattern_type}: {len(patterns)}")
                for pattern in patterns[:2]:
                    print(f"     • {pattern[:50]}...")
    
    # الأذونات
    permissions = report.get('permissions', [])
    if permissions:
        print(f"\nالأذونات ({len(permissions)}):")
        dangerous_perms = []
        normal_perms = []
        
        # قائمة الأذونات الخطرة
        dangerous_permission_list = [
            'INTERNET', 'ACCESS_NETWORK_STATE', 'READ_PHONE_STATE',
            'READ_CONTACTS', 'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'CAMERA', 'RECORD_AUDIO', 'WRITE_EXTERNAL_STORAGE',
            'READ_EXTERNAL_STORAGE', 'CALL_PHONE'
        ]
        
        for perm in permissions:
            if any(dangerous in perm for dangerous in dangerous_permission_list):
                dangerous_perms.append(perm)
            else:
                normal_perms.append(perm)
        
        if dangerous_perms:
            print(f"   أذونات خطرة ({len(dangerous_perms)}):")
            for perm in dangerous_perms[:5]:
                print(f"     • {perm}")
            if len(dangerous_perms) > 5:
                print(f"     • ... و{len(dangerous_perms) - 5} أذونات خطرة أخرى")
        
        if normal_perms:
            print(f"   أذونات عادية ({len(normal_perms)}):")
            for perm in normal_perms[:3]:
                print(f"     • {perm}")
            if len(normal_perms) > 3:
                print(f"     • ... و{len(normal_perms) - 3} أذونات عادية أخرى")
    
    # التحليل الثنائي
    binary_analysis = report.get('binary_analysis', {})
    if binary_analysis:
        print(f"\nالتحليل الثنائي:")
        
        if binary_analysis.get('has_native_code'):
            print(f"   يحتوي على كود أصلي (native)")
        
        if binary_analysis.get('has_dynamic_loading'):
            print(f"   يحمل مكتبات ديناميكياً")
    
    # التوصيات
    recommendations = report.get('recommendations', [])
    if recommendations:
        print(f"\nالتوصيات:")
        for i, rec in enumerate(recommendations[:5], 1):
            print(f"   {i}. {rec}")
    
    # تقدير المخاطر
    threat_score = threat_analysis.get('threat_score', 0) if threat_analysis else 0
    print(f"\nتقدير المخاطر:")
    
    if threat_score >= 15:
        print("   خطر عالي جداً - تجنب تثبيت هذا التطبيق!")
    elif threat_score >= 10:
        print("   خطر عالي - كن حذراً جداً!")
    elif threat_score >= 5:
        print("   خطر متوسط - تحقق من مصدر التطبيق")
    elif threat_score > 0:
        print("   خطر منخفض - قد يطلب أذونات كثيرة")
    else:
        print("   يبدو التطبيق آمناً")
    
    # فحص إضافي
    print(f"\nفحوصات إضافية:")
    
    if report.get('app_type') == 'Android APK':
        print("   تم فحص هيكل APK")
        
        if important_files.get('dex_files'):
            print(f"   يحتوي على {len(important_files['dex_files'])} ملف DEX")
        
        if important_files.get('so_files'):
            print(f"   يحتوي على {len(important_files['so_files'])} مكتبة أصلية")
    
    elif report.get('app_type') == 'iOS IPA':
        print("   تم فحص هيكل IPA")
        
        if important_files.get('executable_files'):
            print(f"   يحتوي على ملف تنفيذي")
    
    # حفظ التقرير
    print("\n" + "=" * 60)
    save = input("هل تريد حفظ تقرير الفحص؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        timestamp = int(time.time())
        safe_filename = sanitize_filename(report.get('filename', 'app'))
        
        filename = f"mobile_scan_{safe_filename}_{timestamp}.txt"
        filepath = os.path.join(folder, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("تقرير فحص تطبيق جوال متطور\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"اسم الملف: {report.get('filename')}\n")
                f.write(f"المسار: {report.get('path')}\n")
                f.write(f"الحجم: {report.get('size_human')}\n")
                f.write(f"الامتداد: {ext}\n")
                f.write(f"نوع التطبيق: {report.get('app_type', 'غير معروف')}\n\n")
                
                f.write("الهاشات:\n")
                for hash_name, hash_value in hashes.items():
                    f.write(f"  {hash_name.upper()}: {hash_value}\n")
                
                f.write("\nتحليل المخاطر:\n")
                if threat_analysis:
                    f.write(f"  مستوى التهديد: {threat_analysis.get('threat_level')}\n")
                    f.write(f"  النقاط: {threat_analysis.get('threat_score', 0)}/20\n")
                    
                    if threat_analysis.get('threat_indicators'):
                        f.write("  مؤشرات التهديد:\n")
                        for indicator in threat_analysis['threat_indicators']:
                            f.write(f"    • {indicator}\n")
                
                f.write("\nالأذونات:\n")
                if permissions:
                    f.write(f"  إجمالي الأذونات: {len(permissions)}\n")
                    
                    dangerous_count = sum(1 for p in permissions if any(dangerous in p for dangerous in [
                        'INTERNET', 'ACCESS_NETWORK_STATE', 'READ_PHONE_STATE',
                        'READ_CONTACTS', 'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
                        'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
                        'CAMERA', 'RECORD_AUDIO', 'WRITE_EXTERNAL_STORAGE',
                        'READ_EXTERNAL_STORAGE', 'CALL_PHONE'
                    ]))
                    
                    f.write(f"  أذونات خطرة: {dangerous_count}\n\n")
                    
                    f.write("  قائمة الأذونات:\n")
                    for perm in permissions[:20]:
                        f.write(f"    • {perm}\n")
                    
                    if len(permissions) > 20:
                        f.write(f"    • ... و{len(permissions) - 20} أذونات أخرى\n")
                
                f.write("\nالتوصيات:\n")
                for rec in recommendations:
                    f.write(f"  • {rec}\n")
            
            print(f"تم حفظ التقرير: {filepath}")
        except Exception as e:
            print(f"خطأ في الحفظ: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى فحص تطبيق الجوال")
    print("=" * 60)
    
    return report

def scan_mobile_app_enhanced(path):
    """فحص تطبيق جوال متطور"""
    report = {
        'path': path,
        'filename': os.path.basename(path),
        'size_bytes': 0,
        'size_human': '',
        'app_type': 'غير معروف',
        'hashes': {},
        'archive_info': {},
        'important_files': {},
        'threat_analysis': {},
        'suspicious_patterns': {},
        'permissions': [],
        'binary_analysis': {},
        'recommendations': []
    }
    
    try:
        # معلومات الملف الأساسية
        size = os.path.getsize(path)
        report['size_bytes'] = size
        report['size_human'] = human_readable_size(size)
        
        ext = os.path.splitext(path)[1].lower()
        
        # حساب الهاشات
        with open(path, 'rb') as f:
            content = f.read()
            report['hashes'] = {
                'md5': hashlib.md5(content).hexdigest(),
                'sha1': hashlib.sha1(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest()
            }
        
        # فحص الأرشيف
        try:
            import zipfile
            
            with zipfile.ZipFile(path, 'r') as z:
                file_list = z.namelist()
                
                report['archive_info'] = {
                    'file_count': len(file_list),
                    'files': file_list[:50],  # أول 50 ملف فقط
                    'compressed_size': sum(zinfo.compress_size for zinfo in z.infolist()),
                    'uncompressed_size': sum(zinfo.file_size for zinfo in z.infolist())
                }
                
                # تحديد نوع التطبيق
                if any(n.endswith('.dex') for n in file_list):
                    report['app_type'] = 'Android APK'
                    app_platform = 'android'
                elif any('Payload/' in n for n in file_list):
                    report['app_type'] = 'iOS IPA'
                    app_platform = 'ios'
                else:
                    report['app_type'] = 'أرشيف غير معروف'
                    app_platform = 'unknown'
                
                # تصنيف الملفات المهمة
                important_files = {
                    'manifest_files': [],
                    'dex_files': [],
                    'so_files': [],
                    'xml_files': [],
                    'plist_files': [],
                    'executable_files': [],
                    'certificate_files': [],
                    'resource_files': [],
                    'asset_files': [],
                    'library_files': []
                }
                
                for filename in file_list:
                    filename_lower = filename.lower()
                    
                    # Android Manifest
                    if 'androidmanifest.xml' in filename_lower:
                        important_files['manifest_files'].append(filename)
                    
                    # DEX files
                    elif filename_lower.endswith('.dex'):
                        important_files['dex_files'].append(filename)
                    
                    # Native libraries
                    elif filename_lower.endswith('.so'):
                        important_files['so_files'].append(filename)
                    
                    # XML files
                    elif filename_lower.endswith('.xml'):
                        important_files['xml_files'].append(filename)
                    
                    # iOS plist files
                    elif 'info.plist' in filename_lower:
                        important_files['plist_files'].append(filename)
                    
                    # Executable files
                    elif any(ext in filename_lower for ext in ['.exe', '.dll', '.bin']):
                        important_files['executable_files'].append(filename)
                    
                    # Certificate files
                    elif any(ext in filename_lower for ext in ['.cer', '.crt', '.pem', '.der', '.p12', '.pfx']):
                        important_files['certificate_files'].append(filename)
                    
                    # Resource files
                    elif any(ext in filename_lower for ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp']):
                        important_files['resource_files'].append(filename)
                    
                    # Asset files
                    elif 'assets/' in filename_lower:
                        important_files['asset_files'].append(filename)
                    
                    # Library files
                    elif any(ext in filename_lower for ext in ['.jar', '.aar']):
                        important_files['library_files'].append(filename)
                
                # إزالة الفئات الفارغة
                for key in list(important_files.keys()):
                    if not important_files[key]:
                        del important_files[key]
                
                report['important_files'] = important_files
                
                # تحليل المخاطر
                threat_score = 0
                threat_indicators = []
                suspicious_patterns = {
                    'urls': [],
                    'ips': [],
                    'domains': [],
                    'suspicious_strings': []
                }
                
                # استخراج النصوص من الملفات المهمة
                files_to_analyze = []
                
                # إضافة الملفات المهمة للتحليل
                if important_files.get('manifest_files'):
                    files_to_analyze.extend(important_files['manifest_files'][:2])
                
                if important_files.get('xml_files'):
                    files_to_analyze.extend(important_files['xml_files'][:3])
                
                if app_platform == 'android' and important_files.get('dex_files'):
                    files_to_analyze.extend(important_files['dex_files'][:1])
                
                # تحليل الملفات النصية
                for filename in files_to_analyze:
                    try:
                        with z.open(filename) as file:
                            content = file.read(50000)  # قراءة أول 50KB
                            
                            try:
                                text_content = content.decode('utf-8', errors='ignore')
                                
                                # استخراج الأذونات (Android)
                                if 'androidmanifest.xml' in filename.lower():
                                    permission_pattern = r'android\.permission\.([A-Z_]+)'
                                    permissions = re.findall(permission_pattern, text_content)
                                    report['permissions'] = list(set(permissions))
                                    
                                    # زيادة نقاط المخاطر للأذونات الخطرة
                                    dangerous_permissions = [
                                        'INTERNET', 'ACCESS_NETWORK_STATE', 'READ_PHONE_STATE',
                                        'READ_CONTACTS', 'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
                                        'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
                                        'CAMERA', 'RECORD_AUDIO', 'WRITE_EXTERNAL_STORAGE',
                                        'READ_EXTERNAL_STORAGE', 'CALL_PHONE'
                                    ]
                                    
                                    dangerous_found = [p for p in report['permissions'] if p in dangerous_permissions]
                                    if dangerous_found:
                                        threat_score += len(dangerous_found)
                                        threat_indicators.append(f'{len(dangerous_found)} أذونات خطرة')
                                
                                # استخراج الروابط والمجالات
                                url_pattern = r'https?://[^\s<>"\']+'
                                urls = re.findall(url_pattern, text_content)
                                if urls:
                                    suspicious_patterns['urls'].extend(urls[:10])
                                
                                ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                                ips = re.findall(ip_pattern, text_content)
                                if ips:
                                    suspicious_patterns['ips'].extend(ips[:10])
                                
                                domain_pattern = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                                domains = re.findall(domain_pattern, text_content)
                                if domains:
                                    suspicious_patterns['domains'].extend(domains[:20])
                                
                                # البحث عن سلاسل مشبوهة
                                suspicious_strings = [
                                    'eval', 'exec', 'system', 'runtime',
                                    'base64', 'decode', 'encrypt', 'decrypt',
                                    'shell', 'command', 'su ', 'root',
                                    'debug', 'test', 'admin', 'password',
                                    'key', 'secret', 'token', 'api'
                                ]
                                
                                found_strings = []
                                for s in suspicious_strings:
                                    if s in text_content.lower():
                                        found_strings.append(s)
                                
                                if found_strings:
                                    suspicious_patterns['suspicious_strings'].extend(found_strings)
                                    threat_score += len(found_strings)
                                    threat_indicators.append(f'سلاسل مشبوهة: {", ".join(found_strings[:3])}')
                            
                            except UnicodeDecodeError:
                                pass
                    
                    except Exception as e:
                        continue
                
                # تحليل إضافي للملفات التنفيذية
                binary_analysis = {}
                
                if important_files.get('so_files'):
                    binary_analysis['has_native_code'] = True
                    threat_score += 2
                    threat_indicators.append('يحتوي على كود أصلي')
                
                if important_files.get('dex_files') and len(important_files['dex_files']) > 1:
                    binary_analysis['multiple_dex'] = True
                    threat_score += 1
                    threat_indicators.append('ملفات DEX متعددة')
                
                report['binary_analysis'] = binary_analysis
                
                # تنظيف الأنماط الفارغة
                for key in list(suspicious_patterns.keys()):
                    if not suspicious_patterns[key]:
                        del suspicious_patterns[key]
                    else:
                        # إزالة التكرارات
                        suspicious_patterns[key] = list(set(suspicious_patterns[key]))
                
                report['suspicious_patterns'] = suspicious_patterns
                
                # نقاط إضافية حسب نوع التطبيق
                if app_platform == 'android':
                    threat_score += 1  # APK بشكل عام أكثر خطورة للفحص
                elif app_platform == 'ios':
                    threat_score += 2  # IPA أصعب في الفحص
                
                # تحديد مستوى التهديد
                if threat_score >= 15:
                    threat_level = 'مرتفع جداً'
                elif threat_score >= 10:
                    threat_level = 'مرتفع'
                elif threat_score >= 5:
                    threat_level = 'متوسط'
                elif threat_score >= 2:
                    threat_level = 'منخفض'
                elif threat_score > 0:
                    threat_level = 'طفيف'
                else:
                    threat_level = 'آمن'
                
                report['threat_analysis'] = {
                    'threat_score': threat_score,
                    'threat_level': threat_level,
                    'threat_indicators': threat_indicators
                }
                
                # التوصيات
                recommendations = report['recommendations']
                
                if threat_level in ['مرتفع جداً', 'مرتفع']:
                    recommendations.append('خطر عالي - تجنب تثبيت هذا التطبيق')
                elif threat_level == 'متوسط':
                    recommendations.append('خطر متوسط - تحقق من مصدر التطبيق قبل التثبيت')
                
                if report['permissions'] and len(report['permissions']) > 10:
                    recommendations.append('يطلب العديد من الأذونات')
                
                if suspicious_patterns.get('urls'):
                    recommendations.append('يتصل بمواقع خارجية')
                
                if important_files.get('so_files'):
                    recommendations.append('يحتوي على مكتبات أصلية')
                
                if not recommendations:
                    recommendations.append('يبدو التطبيق آمناً، لكن تحقق دائماً من مصدره')
        
        except Exception as e:
            report['archive_error'] = str(e)
    
    except Exception as e:
        report['error'] = str(e)
    
    return report

# ------------------------------------------------------------
# تطوير الخيار 10: فحص احتمال وجود صفحة تصيد متطور
def handle_phishing_check_enhanced():
    """فحص احتمال وجود صفحة تصيد متطور"""
    print("=" * 60)
    print("فحص احتمال وجود صفحة تصيد متطور")
    print("=" * 60)
    
    u = input("أدخل رابط للتحقق من احتمال كونه صفحة تصيد: ").strip()
    
    if not u:
        print("لم تقم بإدخال رابط!")
        return None
    
    u = normalize_url(u)
    
    if not validate_url(u):
        print("الرابط غير صالح!")
        return None
    
    print(f"\nجار فحص الرابط للكشف عن التصيد...")
    report = phishing_check_enhanced(u)
    
    print("\n" + "=" * 60)
    print("نتائج الفحص المتطور")
    print("=" * 60)
    
    print(f"\nالرابط المدخل: {u}")
    print(f"الرابط النهائي: {report.get('final_url', u)}")
    print(f"وقت الفحص: {report.get('scanned_at')}")
    
    # معلومات الصفحة
    page_info = report.get('page_info', {})
    if page_info:
        print(f"\nمعلومات الصفحة:")
        print(f"   العنوان: {page_info.get('title', 'غير موجود')[:50]}...")
        print(f"   عدد الروابط: {page_info.get('link_count', 0)}")
        print(f"   عدد النماذج: {page_info.get('form_count', 0)}")
        print(f"   عدد الإطارات: {page_info.get('iframe_count', 0)}")
    
    # تحليل الدومين
    domain_analysis = report.get('domain_analysis', {})
    if domain_analysis:
        print(f"\nتحليل الدومين:")
        print(f"   الدومين: {domain_analysis.get('domain')}")
        
        if domain_analysis.get('ip_address'):
            print(f"   عنوان IP: {domain_analysis.get('ip_address')}")
        
        if domain_analysis.get('domain_age_days'):
            age = domain_analysis['domain_age_days']
            print(f"   عمر الدومين: {age} يوم")
            
            if age < 30:
                print(f"   الدومين جديد جداً")
            elif age < 365:
                print(f"   الدومين جديد")
        
        if domain_analysis.get('ssl_info'):
            ssl = domain_analysis['ssl_info']
            print(f"   SSL: {'صالح' if ssl.get('valid') else 'غير صالح'}")
            if ssl.get('valid') and ssl.get('days_remaining'):
                print(f"   المتبقي: {ssl.get('days_remaining')} يوم")
    
    # تحليل المخاطر
    risk_analysis = report.get('risk_analysis', {})
    if risk_analysis:
        print(f"\nتحليل مخاطر التصيد:")
        print(f"   النتيجة: {risk_analysis.get('verdict', 'غير معروف')}")
        print(f"   النقاط: {risk_analysis.get('score', 0)}/100")
        print(f"   المستوى: {risk_analysis.get('risk_level', 'غير معروف')}")
        
        # تفاصيل النقاط
        score_details = risk_analysis.get('score_details', {})
        if score_details:
            print(f"\n   تفاصيل النقاط:")
            for category, points in score_details.items():
                if points != 0:
                    print(f"     {category}: {points:+d}")
        
        # المؤشرات
        indicators = risk_analysis.get('indicators', [])
        if indicators:
            print(f"\n   مؤشرات التصيد ({len(indicators)}):")
            for i, indicator in enumerate(indicators[:10], 1):
                print(f"     {i}. {indicator}")
            if len(indicators) > 10:
                print(f"     ... و{len(indicators) - 10} مؤشرات أخرى")
    
    # الكلمات المفتاحية للتصيد
    phishing_keywords = report.get('phishing_keywords', {})
    if phishing_keywords:
        found_keywords = phishing_keywords.get('found', [])
        if found_keywords:
            print(f"\nكلمات تصيد مكتشفة ({len(found_keywords)}):")
            for keyword in found_keywords[:10]:
                print(f"   • {keyword}")
            if len(found_keywords) > 10:
                print(f"   • ... و{len(found_keywords) - 10} كلمات أخرى")
    
    # تحليل المحتوى
    content_analysis = report.get('content_analysis', {})
    if content_analysis:
        print(f"\nتحليل المحتوى:")
        
        forms = content_analysis.get('forms', [])
        if forms:
            print(f"   النماذج ({len(forms)}):")
            for form in forms[:2]:
                action = form.get('action', 'غير محدد')
                method = form.get('method', 'GET')
                inputs = len(form.get('inputs', []))
                print(f"     • {action[:30]}... ({method}, {inputs} حقل)")
        
        iframes = content_analysis.get('iframes', [])
        if iframes:
            print(f"   الإطارات ({len(iframes)}):")
            for iframe in iframes[:2]:
                src = iframe.get('src', 'غير محدد')
                print(f"     • {src[:40]}...")
    
    # التحليل التقني
    technical_analysis = report.get('technical_analysis', {})
    if technical_analysis:
        print(f"\nالتحليل التقني:")
        
        headers = technical_analysis.get('security_headers', {})
        if headers:
            missing = [h for h, v in headers.items() if not v.get('present')]
            if missing:
                print(f"   هيدرات أمان مفقودة ({len(missing)}):")
                for header in missing[:3]:
                    print(f"     • {header}")
            else:
                print(f"   جميع هيدرات الأمان موجودة")
    
    # التوصيات
    recommendations = report.get('recommendations', [])
    if recommendations:
        print(f"\nالتوصيات:")
        for i, rec in enumerate(recommendations[:5], 1):
            print(f"   {i}. {rec}")
    
    # التقييم النهائي
    score = risk_analysis.get('score', 0) if risk_analysis else 0
    verdict = risk_analysis.get('verdict', 'غير معروف') if risk_analysis else 'غير معروف'
    
    print(f"\nالتقييم النهائي:")
    
    if score >= 80:
        print("   خطر عالي جداً - صفحة تصيد محتملة")
        print("   تجنب هذا الرابط تماماً")
    elif score >= 60:
        print("   خطر عالي - احتمال تصيد كبير")
        print("   كن حذراً جداً")
    elif score >= 40:
        print("   خطر متوسط - بعض مؤشرات التصيد")
        print("   تحقق من مصدر الرابط")
    elif score >= 20:
        print("   خطر منخفض - مؤشرات قليلة")
        print("   الرابط مقبول لكن انتبه")
    else:
        print("   آمن - لا توجد مؤشرات تصيد قوية")
        print("   يبدو الرابط آمناً")
    
    # فحوصات إضافية
    print(f"\nفحوصات إضافية:")
    
    checks = report.get('checks', {})
    if checks:
        for check_name, result in checks.items():
            if result.get('passed'):
                print(f"   ✓ {check_name}")
            else:
                print(f"   ✗ {check_name}: {result.get('reason', 'فشل')}")
    
    # حفظ التقرير
    print("\n" + "=" * 60)
    save = input("هل تريد حفظ تقرير الفحص؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        timestamp = int(time.time())
        domain = urlparse(u).hostname or 'phishing_check'
        safe_domain = sanitize_filename(domain)
        
        filename = f"phishing_{safe_domain}_{timestamp}.txt"
        filepath = os.path.join(folder, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("تقرير فحص صفحة تصيد متطور\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"الرابط المدخل: {u}\n")
                f.write(f"الرابط النهائي: {report.get('final_url', u)}\n")
                f.write(f"وقت الفحص: {report.get('scanned_at')}\n\n")
                
                f.write(f"النتيجة: {verdict}\n")
                f.write(f"النقاط: {score}/100\n")
                f.write(f"المستوى: {risk_analysis.get('risk_level', 'غير معروف') if risk_analysis else 'غير معروف'}\n\n")
                
                f.write("تفاصيل النقاط:\n")
                if risk_analysis and risk_analysis.get('score_details'):
                    for category, points in risk_analysis['score_details'].items():
                        f.write(f"  {category}: {points:+d}\n")
                
                f.write("\nمؤشرات التصيد:\n")
                if risk_analysis and risk_analysis.get('indicators'):
                    for indicator in risk_analysis['indicators']:
                        f.write(f"  • {indicator}\n")
                
                f.write("\nكلمات تصيد مكتشفة:\n")
                if phishing_keywords and phishing_keywords.get('found'):
                    for keyword in phishing_keywords['found']:
                        f.write(f"  • {keyword}\n")
                
                f.write("\nالتوصيات:\n")
                for rec in recommendations:
                    f.write(f"  • {rec}\n")
                
                f.write("\nفحوصات إضافية:\n")
                if checks:
                    for check_name, result in checks.items():
                        status = '✓' if result.get('passed') else '✗'
                        reason = result.get('reason', '')
                        f.write(f"  {status} {check_name}")
                        if reason:
                            f.write(f": {reason}")
                        f.write("\n")
            
            print(f"تم حفظ التقرير: {filepath}")
        except Exception as e:
            print(f"خطأ في الحفظ: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى فحص احتمال التصيد")
    print("=" * 60)
    
    return report

def phishing_check_enhanced(url):
    """فحص احتمال وجود صفحة تصيد متطور"""
    report = {
        'url': url,
        'final_url': url,
        'scanned_at': now_str(),
        'page_info': {},
        'domain_analysis': {},
        'risk_analysis': {},
        'phishing_keywords': {},
        'content_analysis': {},
        'technical_analysis': {},
        'checks': {},
        'recommendations': []
    }
    
    try:
        session = create_session()
        
        # جلب الصفحة
        response = session.get(
            url,
            timeout=15,
            allow_redirects=True,
            headers={'User-Agent': get_random_user_agent()}
        )
        
        report['final_url'] = response.url
        html_content = response.text[:500000]  # أول 500KB فقط
        parsed = urlparse(response.url)
        domain = parsed.netloc
        
        # معلومات الصفحة
        page_info = {}
        
        # استخراج العنوان
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE)
        page_info['title'] = title_match.group(1).strip() if title_match else 'غير موجود'
        
        # حساب الروابط
        link_count = len(re.findall(r'<a[^>]*href=[^>]*>', html_content, re.IGNORECASE))
        page_info['link_count'] = link_count
        
        # حساب النماذج
        form_count = len(re.findall(r'<form[^>]*>', html_content, re.IGNORECASE))
        page_info['form_count'] = form_count
        
        # حساب الإطارات
        iframe_count = len(re.findall(r'<iframe[^>]*>', html_content, re.IGNORECASE))
        page_info['iframe_count'] = iframe_count
        
        report['page_info'] = page_info
        
        # تحليل الدومين
        domain_analysis = {}
        domain_analysis['domain'] = domain
        
        try:
            # عنوان IP
            ip_address = socket.gethostbyname(domain)
            domain_analysis['ip_address'] = ip_address
            
            # WHOIS معلومات
            if WHOIS_AVAILABLE:
                try:
                    who = whois.whois(domain)
                    
                    # عمر الدومين
                    if who.creation_date:
                        if isinstance(who.creation_date, list):
                            creation_date = who.creation_date[0]
                        else:
                            creation_date = who.creation_date
                        
                        if creation_date:
                            now = datetime.datetime.now(datetime.timezone.utc)
                            if isinstance(creation_date, str):
                                from dateutil import parser
                                creation_date = parser.parse(creation_date)
                            
                            age_days = (now - creation_date).days
                            domain_analysis['domain_age_days'] = age_days
                except:
                    pass
        except:
            pass
        
        # معلومات SSL
        if parsed.scheme == 'https':
            try:
                ssl_info = scan_ssl_enhanced(response.url)
                domain_analysis['ssl_info'] = {
                    'valid': ssl_info.get('valid', False),
                    'days_remaining': ssl_info.get('days_remaining', 0)
                }
            except:
                domain_analysis['ssl_info'] = {'valid': False}
        
        report['domain_analysis'] = domain_analysis
        
        # كلمات التصيد
        phishing_keywords = {
            'found': [],
            'count': 0
        }
        
        # قائمة كلمات التصيد الموسعة
        phishing_word_list = [
            'login', 'signin', 'sign-in', 'log-in', 'bank', 'secure', 'confirm',
            'account', 'password', 'verify', 'update', 'paypal', 'ebay', 'amazon',
            'apple', 'microsoft', 'google', 'facebook', 'instagram', 'whatsapp',
            'verification', 'authentication', 'security', 'update', 'billing',
            'payment', 'credit', 'card', 'social', 'security', 'ssn', 'password reset',
            'account recovery', 'verify identity', 'confirm details', 'urgent action required',
            'suspicious activity', 'limited time', 'click here', 'verify now',
            'update information', 'security check', 'unauthorized access',
            'account suspended', 'verify account', 'confirm password'
        ]
        
        html_lower = html_content.lower()
        
        for keyword in phishing_word_list:
            if keyword in html_lower:
                phishing_keywords['found'].append(keyword)
        
        phishing_keywords['count'] = len(phishing_keywords['found'])
        report['phishing_keywords'] = phishing_keywords
        
        # تحليل المخاطر
        risk_score = 0
        score_details = {}
        indicators = []
        
        # 1. عمر الدومين
        age = domain_analysis.get('domain_age_days')
        if age is not None:
            if age < 7:
                risk_score += 20
                score_details['عمر الدومين'] = 20
                indicators.append('الدومين جديد جداً (أقل من أسبوع)')
            elif age < 30:
                risk_score += 15
                score_details['عمر الدومين'] = 15
                indicators.append('الدومين جديد (أقل من شهر)')
            elif age < 365:
                risk_score += 5
                score_details['عمر الدومين'] = 5
                indicators.append('الدومين عمره أقل من سنة')
        
        # 2. SSL
        ssl_info = domain_analysis.get('ssl_info', {})
        if not ssl_info.get('valid', False):
            risk_score += 15
            score_details['SSL'] = 15
            indicators.append('لا يوجد SSL أو غير صالح')
        else:
            days_left = ssl_info.get('days_remaining', 0)
            if days_left < 30:
                risk_score += 10
                score_details['SSL'] = 10
                indicators.append('SSL ينتهي قريباً')
        
        # 3. كلمات التصيد
        keyword_count = phishing_keywords['count']
        if keyword_count >= 10:
            risk_score += 25
            score_details['كلمات تصيد'] = 25
            indicators.append(f'الكثير من كلمات التصيد ({keyword_count})')
        elif keyword_count >= 5:
            risk_score += 15
            score_details['كلمات تصيد'] = 15
            indicators.append(f'كلمات تصيد متوسطة ({keyword_count})')
        elif keyword_count >= 2:
            risk_score += 5
            score_details['كلمات تصيد'] = 5
            indicators.append(f'قليل من كلمات التصيد ({keyword_count})')
        
        # 4. النماذج
        if form_count >= 3:
            risk_score += 10
            score_details['نماذج كثيرة'] = 10
            indicators.append(f'كثير من النماذج ({form_count})')
        elif form_count > 0:
            risk_score += 5
            score_details['نماذج'] = 5
            indicators.append('يحتوي على نماذج')
        
        # 5. الإطارات
        if iframe_count > 0:
            risk_score += 10
            score_details['إطارات'] = 10
            indicators.append(f'يحتوي على إطارات ({iframe_count})')
        
        # 6. عنوان IP مباشر
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            risk_score += 20
            score_details['عنوان IP مباشر'] = 20
            indicators.append('يستخدم عنوان IP مباشر بدلاً من الدومين')
        
        # 7. دومين طويل أو معقد
        if len(domain) > 30:
            risk_score += 5
            score_details['دومين طويل'] = 5
            indicators.append('اسم دومين طويل جداً')
        
        # 8. استخدام شركات استضافة مجانية
        free_hosting = ['.github.io', '.000webhostapp.com', '.herokuapp.com', 
                       '.netlify.app', '.vercel.app', '.firebaseapp.com']
        
        if any(host in domain for host in free_hosting):
            risk_score += 10
            score_details['استضافة مجانية'] = 10
            indicators.append('يستخدم استضافة مجانية')
        
        # 9. دومينات مشبوهة
        suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.win']
        for suspicious in suspicious_domains:
            if domain.endswith(suspicious):
                risk_score += 15
                score_details['دومين مشبوه'] = 15
                indicators.append(f'امتداد دومين مشبوه: {suspicious}')
                break
        
        # تحديد المستوى
        if risk_score >= 80:
            verdict = 'تصيد محتمل'
            risk_level = 'مرتفع جداً'
        elif risk_score >= 60:
            verdict = 'مشبوه جداً'
            risk_level = 'مرتفع'
        elif risk_score >= 40:
            verdict = 'مشبوه'
            risk_level = 'متوسط'
        elif risk_score >= 20:
            verdict = 'مقبول'
            risk_level = 'منخفض'
        else:
            verdict = 'آمن'
            risk_level = 'آمن'
        
        report['risk_analysis'] = {
            'score': risk_score,
            'verdict': verdict,
            'risk_level': risk_level,
            'score_details': score_details,
            'indicators': indicators
        }
        
        # تحليل المحتوى
        content_analysis = {}
        
        # استخراج النماذج
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        for form_html in form_matches[:5]:  # أول 5 نماذج فقط
            form_info = {'inputs': []}
            
            # استخراج action
            action_match = re.search(r'action=["\']?([^"\'\s>]+)["\']?', form_html, re.IGNORECASE)
            if action_match:
                form_info['action'] = action_match.group(1)
            
            # استخراج method
            method_match = re.search(r'method=["\']?([^"\'\s>]+)["\']?', form_html, re.IGNORECASE)
            if method_match:
                form_info['method'] = method_match.group(1).upper()
            else:
                form_info['method'] = 'GET'
            
            # استخراج الحقول
            input_matches = re.findall(r'<input[^>]*>', form_html, re.IGNORECASE)
            form_info['inputs'] = input_matches[:10]  # أول 10 حقول فقط
            
            forms.append(form_info)
        
        content_analysis['forms'] = forms
        
        # استخراج الإطارات
        iframes = []
        iframe_pattern = r'<iframe[^>]*>'
        iframe_matches = re.findall(iframe_pattern, html_content, re.IGNORECASE)
        
        for iframe_html in iframe_matches[:5]:  # أول 5 إطارات فقط
            iframe_info = {}
            
            # استخراج src
            src_match = re.search(r'src=["\']?([^"\'\s>]+)["\']?', iframe_html, re.IGNORECASE)
            if src_match:
                iframe_info['src'] = src_match.group(1)
            
            iframes.append(iframe_info)
        
        content_analysis['iframes'] = iframes
        
        report['content_analysis'] = content_analysis
        
        # التحليل التقني
        technical_analysis = {}
        
        # هيدرات الأمان
        security_headers = {}
        important_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        
        for header in important_headers:
            if header in response.headers:
                security_headers[header] = {
                    'present': True,
                    'value': response.headers[header]
                }
            else:
                security_headers[header] = {'present': False}
        
        technical_analysis['security_headers'] = security_headers
        report['technical_analysis'] = technical_analysis
        
        # الفحوصات
        checks = {}
        
        # فحص SSL
        checks['SSL'] = {
            'passed': ssl_info.get('valid', False),
            'reason': 'SSL صالح' if ssl_info.get('valid', False) else 'SSL غير صالح أو مفقود'
        }
        
        # فحص عمر الدومين
        if age is not None:
            checks['عمر الدومين'] = {
                'passed': age >= 365,
                'reason': f'{age} يوم' + (' (جديد)' if age < 365 else ' (قديم)')
            }
        
        # فحص كلمات التصيد
        checks['كلمات تصيد'] = {
            'passed': keyword_count < 3,
            'reason': f'{keyword_count} كلمة'
        }
        
        # فحص النماذج
        checks['النماذج'] = {
            'passed': form_count == 0,
            'reason': f'{form_count} نموذج'
        }
        
        report['checks'] = checks
        
        # التوصيات
        recommendations = report['recommendations']
        
        if risk_score >= 60:
            recommendations.append('تجنب هذا الرابط - احتمال تصيد عالي')
        elif risk_score >= 40:
            recommendations.append('كن حذراً - تحقق من مصدر الرابط')
        
        if not ssl_info.get('valid', False):
            recommendations.append('الموقع لا يستخدم SSL آمن')
        
        if keyword_count >= 5:
            recommendations.append('يحتوي على الكثير من كلمات التصيد')
        
        if form_count > 0:
            recommendations.append('لا تدخل معلومات حساسة في النماذج')
        
        if not recommendations:
            recommendations.append('يبدو الرابط آمناً، لكن انتبه دائماً لمصدر الروابط')
    
    except Exception as e:
        report['error'] = str(e)
    
    return report

# ------------------------------------------------------------
# تطوير الخيار 11: فحص متعدد عبر 5 خانات متطور
def prompt_five_links_and_scan_enhanced():
    """فحص متعدد عبر 5 خانات متطور"""
    print("=" * 60)
    print("فحص متعدد للروابط - 5 خانات متطور")
    print("=" * 60)
    
    print("أدخل حتى خمس روابط (اترك الخانة فارغة إذا لم تُدخل):\n")
    
    links = []
    for i in range(1, 6):
        u = input(f"الرابط {i}: ").strip()
        if u:
            try:
                normalized = normalize_url(u)
                if validate_url(normalized):
                    links.append(normalized)
                    print(f"  تم إضافة الرابط")
                else:
                    print(f"  رابط غير صالح - تم تخطيه")
            except:
                print(f"  رابط غير صالح - تم تخطيه")
        else:
            print(f"  خانة فارغة - تم تخطيها")
    
    if not links:
        print("\nلم تدخل أي روابط صالحة!")
        return None
    
    print(f"\nسيتم فحص {len(links)} رابط")
    
    print("\n" + "=" * 60)
    print("خيارات الفحص المتطور")
    print("=" * 60)
    
    print("\nاختر مستوى الفحص:")
    print("  1) فحص سريع (معلومات أساسية)")
    print("  2) فحص متوسّط (معلومات مفصلة)")
    print("  3) فحص شامل (جميع الفحوصات)")
    
    scan_level = input("\nاختر المستوى (1-3): ").strip()
    
    if scan_level == '1':
        scan_type = 'سريع'
        scan_func = scan_basic_enhanced
    elif scan_level == '2':
        scan_type = 'متوسّط'
        scan_func = lambda url: {
            'basic': scan_basic_enhanced(url),
            'content': analyze_content_enhanced(url),
            'phishing': phishing_check_enhanced(url)['risk_analysis']
        }
    elif scan_level == '3':
        scan_type = 'شامل'
        scan_func = lambda url: handle_scan_url_quick_manual_enhanced(url)[0]
    else:
        scan_type = 'سريع'
        scan_func = scan_basic_enhanced
        print("اختيار غير صالح - سيتم استخدام الفحص السريع")
    
    print(f"\nجار الفحص ({scan_type})...")
    
    # خيارات الحفظ
    print("\n" + "=" * 60)
    save_option = input("هل تريد حفظ التقارير؟ (نعم/لا): ").strip().lower() == "نعم"
    
    if save_option:
        folder = input("مجلد الحفظ (افتراضي: results): ").strip() or "results"
        os.makedirs(folder, exist_ok=True)
        
        save_each = input("حفظ تقرير منفصل لكل رابط؟ (نعم/لا): ").strip().lower() == "نعم"
        save_summary = input("حفظ تقرير إجمالي؟ (نعم/لا): ").strip().lower() == "نعم"
    else:
        folder = None
        save_each = False
        save_summary = False
    
    # فحص الروابط
    results = []
    
    for idx, url in enumerate(links, 1):
        print(f"\n[{idx}/{len(links)}] فحص الرابط: {url[:50]}...")
        
        try:
            report = scan_func(url)
            results.append({
                'url': url,
                'report': report,
                'success': True
            })
            
            # عرض ملخص سريع
            if scan_level == '1':
                print(f"   رمز الحالة: {report.get('status_code', 'غير معروف')}")
                print(f"   وقت الاستجابة: {report.get('response_time', 0):.2f} ثانية")
            elif scan_level == '2':
                phishing = report.get('phishing', {})
                print(f"   نتيجة التصيد: {phishing.get('verdict', 'غير معروف')}")
                print(f"   النقاط: {phishing.get('score', 0)}")
            elif scan_level == '3':
                phishing = report.get('phishing_analysis', {})
                print(f"   نتيجة التصيد: {phishing.get('verdict', 'غير معروف')}")
                print(f"   النقاط: {phishing.get('score', 0)}")
        
        except Exception as e:
            print(f"   خطأ في الفحص: {e}")
            results.append({
                'url': url,
                'error': str(e),
                'success': False
            })
    
    # عرض النتائج الإجمالية
    print("\n" + "=" * 60)
    print("النتائج الإجمالية")
    print("=" * 60)
    
    successful = sum(1 for r in results if r['success'])
    failed = len(results) - successful
    
    print(f"\nإحصائيات:")
    print(f"   إجمالي الروابط: {len(results)}")
    print(f"   فحص ناجح: {successful}")
    print(f"   فحص فاشل: {failed}")
    
    # تحليل نتائج التصيد (إذا كانت متاحة)
    if scan_level in ['2', '3']:
        phishing_results = []
        for result in results:
            if result['success']:
                report = result['report']
                if scan_level == '2':
                    phishing = report.get('phishing', {})
                else:
                    phishing = report.get('phishing_analysis', {})
                
                if phishing:
                    phishing_results.append({
                        'url': result['url'],
                        'verdict': phishing.get('verdict', 'غير معروف'),
                        'score': phishing.get('score', 0)
                    })
        
        if phishing_results:
            print(f"\nنتائج فحص التصيد:")
            
            # تصنيف النتائج
            categories = {
                'تصيد محتمل': 0,
                'مشبوه جداً': 0,
                'مشبوه': 0,
                'مقبول': 0,
                'آمن': 0
            }
            
            for result in phishing_results:
                verdict = result['verdict']
                if verdict in categories:
                    categories[verdict] += 1
                else:
                    # محاولة تصنيف بناءً على النقاط
                    score = result['score']
                    if score >= 80:
                        categories['تصيد محتمل'] += 1
                    elif score >= 60:
                        categories['مشبوه جداً'] += 1
                    elif score >= 40:
                        categories['مشبوه'] += 1
                    elif score >= 20:
                        categories['مقبول'] += 1
                    else:
                        categories['آمن'] += 1
            
            for category, count in categories.items():
                if count > 0:
                    print(f"   {category}: {count}")
            
            # عرض الروابط الخطرة
            dangerous = [r for r in phishing_results if r['score'] >= 60]
            if dangerous:
                print(f"\nالروابط الخطرة ({len(dangerous)}):")
                for r in dangerous[:3]:
                    print(f"   • {r['url'][:40]}... ({r['verdict']}, {r['score']} نقطة)")
                if len(dangerous) > 3:
                    print(f"   • ... و{len(dangerous) - 3} روابط خطرة أخرى")
    
    # حفظ التقارير
    if save_option and folder:
        timestamp = int(time.time())
        
        # حفظ تقارير فردية
        if save_each:
            print(f"\nجار حفظ التقارير الفردية...")
            
            for i, result in enumerate(results):
                if result['success']:
                    domain = urlparse(result['url']).hostname or f"link_{i}"
                    safe_domain = sanitize_filename(domain)
                    
                    filename = f"multi_scan_{safe_domain}_{timestamp}_{i}.txt"
                    filepath = os.path.join(folder, filename)
                    
                    try:
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write("=" * 60 + "\n")
                            f.write(f"تقرير فحص رابط\n")
                            f.write("=" * 60 + "\n\n")
                            
                            f.write(f"الرابط: {result['url']}\n")
                            f.write(f"وقت الفحص: {now_str()}\n")
                            f.write(f"مستوى الفحص: {scan_type}\n\n")
                            
                            f.write("النتائج:\n")
                            
                            if scan_level == '1':
                                report = result['report']
                                f.write(f"  رمز الحالة: {report.get('status_code', 'غير معروف')}\n")
                                f.write(f"  وقت الاستجابة: {report.get('response_time', 0):.2f} ثانية\n")
                                f.write(f"  نوع المحتوى: {report.get('content_type', 'غير معروف')}\n")
                            
                            elif scan_level == '2':
                                report = result['report']
                                f.write(f"  معلومات أساسية:\n")
                                f.write(f"    رمز الحالة: {report['basic'].get('status_code', 'غير معروف')}\n")
                                f.write(f"    وقت الاستجابة: {report['basic'].get('response_time', 0):.2f} ثانية\n\n")
                                
                                f.write(f"  تحليل التصيد:\n")
                                phishing = report.get('phishing', {})
                                f.write(f"    النتيجة: {phishing.get('verdict', 'غير معروف')}\n")
                                f.write(f"    النقاط: {phishing.get('score', 0)}\n")
                            
                            elif scan_level == '3':
                                # حفظ مختصر للتقرير الشامل
                                report = result['report']
                                phishing = report.get('phishing_analysis', {})
                                f.write(f"  نتيجة التصيد: {phishing.get('verdict', 'غير معروف')}\n")
                                f.write(f"  نقاط الخطر: {phishing.get('score', 0)}\n")
                            
                        print(f"  تم حفظ: {os.path.basename(filepath)}")
                    except Exception as e:
                        print(f"  خطأ في حفظ التقرير الفردي: {e}")
        
        # حفظ تقرير إجمالي
        if save_summary:
            print(f"\nجار حفظ التقرير الإجمالي...")
            
            summary_file = os.path.join(folder, f"multi_scan_summary_{timestamp}.txt")
            
            try:
                with open(summary_file, 'w', encoding='utf-8') as f:
                    f.write("=" * 60 + "\n")
                    f.write("تقرير فحص متعدد للروابط\n")
                    f.write("=" * 60 + "\n\n")
                    
                    f.write(f"وقت الفحص: {now_str()}\n")
                    f.write(f"عدد الروابط: {len(links)}\n")
                    f.write(f"مستوى الفحص: {scan_type}\n")
                    f.write(f"فحص ناجح: {successful}\n")
                    f.write(f"فحص فاشل: {failed}\n\n")
                    
                    f.write("النتائج التفصيلية:\n")
                    for i, result in enumerate(results, 1):
                        f.write(f"\n[{i}] {result['url']}\n")
                        
                        if not result['success']:
                            f.write(f"  خطأ: {result['error']}\n")
                            continue
                        
                        report = result['report']
                        
                        if scan_level == '1':
                            f.write(f"  رمز الحالة: {report.get('status_code', 'غير معروف')}\n")
                            f.write(f"  وقت الاستجابة: {report.get('response_time', 0):.2f} ثانية\n")
                        
                        elif scan_level == '2':
                            phishing = report.get('phishing', {})
                            f.write(f"  نتيجة التصيد: {phishing.get('verdict', 'غير معروف')}\n")
                            f.write(f"  نقاط الخطر: {phishing.get('score', 0)}\n")
                        
                        elif scan_level == '3':
                            phishing = report.get('phishing_analysis', {})
                            f.write(f"  نتيجة التصيد: {phishing.get('verdict', 'غير معروف')}\n")
                            f.write(f"  نقاط الخطر: {phishing.get('score', 0)}\n")
                
                print(f"تم حفظ التقرير الإجمالي: {summary_file}")
            
            except Exception as e:
                print(f"خطأ في حفظ التقرير الإجمالي: {e}")
    
    print("\n" + "=" * 60)
    print("انتهى الفحص المتعدد")
    print("=" * 60)
    
    return results

def handle_scan_url_quick_manual_enhanced(u):
    """دالة مساعدة لفحص سريع محسن"""
    report = {'input_url': u, 'scanned_at': now_str()}
    
    report['basic'] = scan_basic_enhanced(u)
    
    parsed = urlparse(u)
    if parsed.scheme == 'https':
        report['ssl'] = scan_ssl_enhanced(u)
    else:
        report['ssl'] = {'note': 'لا يستخدم HTTPS'}
    
    report['content_analysis'] = analyze_content_enhanced(u)
    
    media_links = report['content_analysis'].get('media_links', [])
    report['media_analysis'] = analyze_media_links_enhanced(media_links, max_links=5)
    
    if WHOIS_AVAILABLE:
        report['whois'] = whois_info_enhanced(parsed.hostname)
    else:
        report['whois'] = {'note': 'whois غير متوفر'}
    
    report['network'] = network_info_enhanced(parsed.hostname)
    report['traffic'] = traffic_analysis_enhanced(u)
    
    ph = phishing_heuristic_enhanced({
        'input_url': u,
        'ssl': report.get('ssl', {}),
        'whois': report.get('whois', {}),
        'basic': report.get('basic', {}),
        'content_analysis': report.get('content_analysis', {}),
        'media_analysis': report.get('media_analysis', [])
    })
    
    report['phishing_analysis'] = ph
    
    return report, ph

def phishing_heuristic_enhanced(report):
    """خوارزمية تصيد محسنة"""
    score = 0
    reasons = []
    details = {}
    
    # 1. SSL/شهادة الأمان
    sslr = report.get('ssl', {})
    if isinstance(sslr, dict):
        if not sslr.get('valid', False):
            score += 20
            reasons.append('شهادة SSL غير صالحة أو مفقودة')
            details['ssl_invalid'] = True
        else:
            days_left = sslr.get('days_remaining')
            if isinstance(days_left, (int, float)):
                if days_left < 7:
                    score += 15
                    reasons.append(f'شهادة SSL تنتهي خلال {days_left} أيام')
                    details['ssl_expiring_soon'] = True
                elif days_left < 30:
                    score += 10
                    reasons.append(f'شهادة SSL تنتهي خلال {days_left} أيام')
                    details['ssl_near_expiry'] = True
    
    # 2. معلومات الدومين
    who = report.get('whois', {})
    if isinstance(who, dict):
        age = who.get('age_days')
        if age is not None:
            if age < 7:
                score += 20
                reasons.append(f'الدومين جديد جداً ({age} أيام)')
                details['domain_very_new'] = True
            elif age < 30:
                score += 15
                reasons.append(f'الدومين جديد ({age} أيام)')
                details['domain_new'] = True
            elif age < 365:
                score += 5
                reasons.append(f'الدومين عمره أقل من سنة ({age} أيام)')
                details['domain_young'] = True
        
        if who.get('analysis', {}).get('has_privacy', False):
            score += 5
            reasons.append('معلومات WHOIS مخفية')
            details['whois_privacy'] = True
    
    # 3. التحويلات
    basic = report.get('basic', {})
    if isinstance(basic, dict):
        chain_len = len(basic.get('redirect_chain', []))
        
        if chain_len >= 5:
            score += 15
            reasons.append(f'سلسلة إعادة توجيه طويلة جداً ({chain_len} تحويلات)')
            details['long_redirects'] = chain_len
        elif chain_len >= 3:
            score += 10
            reasons.append(f'سلسلة إعادة توجيه طويلة ({chain_len} تحويلات)')
            details['multiple_redirects'] = chain_len
        elif chain_len > 0:
            score += 5
            reasons.append(f'يوجد إعادة توجيه ({chain_len} تحويلات)')
            details['has_redirects'] = chain_len
    
    # 4. تحليل المحتوى
    cont = report.get('content_analysis', {})
    if cont:
        # كلمات التصيد
        phishing_words = cont.get('phishing_indicators', [])
        if phishing_words:
            score += len(phishing_words) * 3
            reasons.append(f'يوجد {len(phishing_words)} كلمات تصيد')
            details['phishing_words'] = phishing_words
        
        # الأنماط المشبوهة
        suspicious_patterns = cont.get('suspicious_patterns', [])
        if suspicious_patterns:
            score += len(suspicious_patterns) * 2
            reasons.append(f'يوجد {len(suspicious_patterns)} أنماط مشبوهة')
            details['suspicious_patterns'] = suspicious_patterns
        
        # النماذج
        form_count = cont.get('form_count', 0)
        if form_count > 0:
            score += form_count * 2
            reasons.append(f'يحتوي على {form_count} نموذج')
            details['forms'] = form_count
        
        # الإطارات
        iframe_count = cont.get('iframe_count', 0)
        if iframe_count > 0:
            score += iframe_count * 3
            reasons.append(f'يحتوي على {iframe_count} إطار')
            details['iframes'] = iframe_count
    
    # 5. روابط الوسائط
    medias = report.get('media_analysis', [])
    for m in medias:
        if m.get('analysis', {}).get('pdf_details', {}).get('has_javascript'):
            score += 10
            reasons.append('ملف PDF يحتوي على JavaScript')
            details['pdf_js'] = True
    
    # 6. عنوان IP مباشر
    try:
        host = urlparse(report.get('input_url', '')).hostname or ''
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
            score += 15
            reasons.append('استخدام عنوان IP مباشرة بدل الدومين')
            details['direct_ip'] = True
    except:
        pass
    
    # 7. حجم الصفحة
    if basic.get('content_length', 0) < 1000:
        score += 5
        reasons.append('صفحة صغيرة جداً (أقل من 1KB)')
        details['small_page'] = True
    
    # 8. كود الحالة
    status_code = basic.get('status_code')
    if status_code and status_code >= 400:
        score += 10
        reasons.append(f'رمز حالة خطأ: {status_code}')
        details['error_status'] = status_code
    
    # تحديد النتيجة النهائية
    if score >= 80:
        verdict = 'تصيد محتمل'
    elif score >= 60:
        verdict = 'مشبوه جداً'
    elif score >= 40:
        verdict = 'مشبوه'
    elif score >= 20:
        verdict = 'مقبول'
    else:
        verdict = 'آمن'
    
    return {
        'score': score,
        'verdict': verdict,
        'reasons': reasons,
        'details': details
    }

# ------------------------------------------------------------
# تطوير الدوال الأساسية المحسنة
def scan_basic_enhanced(url):
    """فحص أساسي محسن"""
    out = {
        'status_code': None,
        'final_url': url,
        'redirect_chain': [],
        'response_time': 0,
        'content_type': '',
        'server_headers': {},
        'cookies': {},
        'text_preview': '',
        'content_length': 0,
        'encoding': '',
        'history': []
    }
    
    try:
        session = create_session()
        start_time = time.time()
        
        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": get_random_user_agent()},
            stream=True
        )
        
        out['response_time'] = round(time.time() - start_time, 3)
        out['status_code'] = response.status_code
        out['final_url'] = response.url
        out['content_type'] = response.headers.get('Content-Type', '')
        out['encoding'] = response.encoding
        out['content_length'] = len(response.content)
        
        # جمع الهيدرات
        out['server_headers'] = dict(response.headers)
        
        # الكوكيز
        out['cookies'] = requests.utils.dict_from_cookiejar(response.cookies)
        
        # سلسلة التحويلات
        if response.history:
            out['redirect_chain'] = [resp.url for resp in response.history]
            out['history'] = [{
                'url': resp.url,
                'status_code': resp.status_code
            } for resp in response.history]
        
        # معاينة النص
        try:
            out['text_preview'] = response.text[:2000]
        except:
            out['text_preview'] = response.content[:2000]
    
    except Exception as e:
        out['error'] = str(e)
    
    return out

def scan_ssl_enhanced(url):
    """فحص SSL محسن"""
    out = {
        'valid': False,
        'certificate': {},
        'vulnerabilities': [],
        'grade': 'F',
        'days_remaining': 0
    }
    
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            out['note'] = 'لا يستخدم HTTPS'
            return out
        
        host = parsed.hostname
        port = parsed.port or 443
        
        context = ssl.create_default_context()
        
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                out['valid'] = True
                out['certificate'] = cert
                
                # استخراج التواريخ
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                
                if not_before and not_after:
                    try:
                        from dateutil import parser
                        nb = parser.parse(not_before)
                        na = parser.parse(not_after)
                        
                        now = datetime.datetime.now(datetime.timezone.utc)
                        days_left = (na - now).days
                        out['days_remaining'] = days_left
                        
                        # تحديد التقييم
                        if days_left < 0:
                            out['grade'] = 'F'
                            out['vulnerabilities'].append('شهادة منتهية')
                        elif days_left < 7:
                            out['grade'] = 'D'
                        elif days_left < 30:
                            out['grade'] = 'C'
                        elif days_left < 90:
                            out['grade'] = 'B'
                        else:
                            out['grade'] = 'A'
                    
                    except Exception as e:
                        out['date_error'] = str(e)
                
                # فحص تشفرات ضعيفة
                cipher = ss.cipher()
                if cipher:
                    weak_ciphers = ['RC4', 'DES', '3DES', 'NULL']
                    if any(weak in cipher[0] for weak in weak_ciphers):
                        out['vulnerabilities'].append(f'تشفير ضعيف: {cipher[0]}')
    
    except ssl.SSLCertVerificationError as e:
        out['valid'] = False
        out['error'] = str(e)
    except Exception as e:
        out['valid'] = False
        out['error'] = str(e)
    
    return out

def analyze_content_enhanced(url):
    """تحليل محتوى محسن"""
    out = {
        'title': 'غير موجود',
        'meta_description': '',
        'num_links': 0,
        'external_links': [],
        'internal_links': [],
        'media_links': [],
        'form_count': 0,
        'iframe_count': 0,
        'suspicious_patterns': [],
        'phishing_indicators': []
    }
    
    try:
        session = create_session()
        response = session.get(url, timeout=REQUEST_TIMEOUT)
        html_text = response.text
        html_lower = html_text.lower()
        
        # العنوان
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html_text, re.IGNORECASE)
        if title_match:
            out['title'] = title_match.group(1).strip()[:200]
        
        # وصف الميتا
        meta_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html_text, re.IGNORECASE)
        if meta_match:
            out['meta_description'] = meta_match.group(1).strip()[:200]
        
        # الروابط
        hrefs = re.findall(r'href=[\'"]?([^\'" >]+)', html_text, re.IGNORECASE)
        srcs = re.findall(r'src=[\'"]?([^\'" >]+)', html_text, re.IGNORECASE)
        links = list(dict.fromkeys(hrefs + srcs))
        
        out['num_links'] = len(links)
        
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        base_domain = urlparse(url).netloc
        
        for link in links:
            try:
                if re.match(r'^https?://', link, re.IGNORECASE):
                    full_link = link
                else:
                    full_link = urljoin(base, link)
                
                link_domain = urlparse(full_link).netloc
                
                if base_domain in link_domain or not link_domain:
                    out['internal_links'].append(full_link)
                else:
                    out['external_links'].append(full_link)
                
                # روابط الوسائط
                media_exts = ('.pdf', '.zip', '.exe', '.rar', '.7z', '.doc', '.docx', '.xls', '.xlsx', 
                             '.ppt', '.pptx', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.mp4', '.mp3', 
                             '.wav', '.apk', '.ipa')
                
                if any(full_link.lower().endswith(ext) for ext in media_exts):
                    out['media_links'].append(full_link)
            
            except:
                continue
        
        # الأنماط المشبوهة
        suspicious_patterns = [
            'eval(', 'document.write', 'base64,', 'atob(', 'unescape(', 'fromcharcode(',
            'onerror=', 'window.location', '.innerhtml', 'settimeout(',
            '<iframe', '<script>', 'javascript:', 'vbscript:', 'data:text/html'
        ]
        
        found_patterns = []
        for pattern in suspicious_patterns:
            if pattern in html_lower:
                found_patterns.append(pattern)
        
        out['suspicious_patterns'] = found_patterns
        
        # كلمات التصيد
        phishing_words = [
            'login', 'signin', 'bank', 'secure', 'confirm', 'account',
            'password', 'verify', 'update', 'paypal', 'credit', 'card',
            'social', 'security', 'ssn', 'password reset', 'account recovery'
        ]
        
        found_words = []
        for word in phishing_words:
            if word in html_lower:
                found_words.append(word)
        
        out['phishing_indicators'] = found_words
        
        # الفورمات والإطارات
        out['form_count'] = len(re.findall(r'<form', html_text, re.IGNORECASE))
        out['iframe_count'] = len(re.findall(r'<iframe', html_text, re.IGNORECASE))
    
    except Exception as e:
        out['error'] = str(e)
    
    return out

def analyze_media_links_enhanced(media_links, max_links=5):
    """تحليل روابط الوسائط محسن"""
    results = []
    
    for ml in media_links[:max_links]:
        info = {'url': ml}
        
        try:
            session = create_session()
            head_response = session.head(
                ml,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": get_random_user_agent()}
            )
            
            info['status_code'] = head_response.status_code
            info['content_type'] = head_response.headers.get('Content-Type', '')
            info['content_length'] = head_response.headers.get('Content-Length')
            
            # تحليل PDF
            if 'pdf' in info['content_type'] or ml.lower().endswith('.pdf'):
                try:
                    response = session.get(ml, timeout=12, stream=True)
                    chunk = response.raw.read(min(MAX_PREVIEW_BYTES, 50000))
                    
                    pdf_info = {
                        'has_javascript': bool(b'/JavaScript' in chunk or b'/JS' in chunk),
                        'has_forms': bool(b'/AcroForm' in chunk),
                        'has_attachments': bool(b'/EmbeddedFile' in chunk)
                    }
                    
                    info['pdf_details'] = pdf_info
                
                except Exception as e:
                    info['pdf_error'] = str(e)
            
            # تحليل الصور
            if PIL_AVAILABLE and ('image' in info['content_type'] or 
                                 ml.lower().endswith(('.jpg', '.jpeg', '.png', '.gif'))):
                try:
                    response = session.get(ml, timeout=12)
                    from io import BytesIO
                    img = Image.open(BytesIO(response.content))
                    
                    image_info = {
                        'format': img.format,
                        'size': img.size,
                        'width': img.width,
                        'height': img.height
                    }
                    
                    info['image_details'] = image_info
                
                except Exception as e:
                    info['image_error'] = str(e)
        
        except Exception as e:
            info['error'] = str(e)
        
        results.append(info)
    
    return results

def whois_info_enhanced(domain):
    """معلومات WHOIS محسنة"""
    out = {
        'domain': domain,
        'creation_date': None,
        'expiration_date': None,
        'registrar': None,
        'country': None,
        'age_days': None,
        'analysis': {}
    }
    
    if not WHOIS_AVAILABLE:
        out['error'] = 'مكتبة whois غير مثبتة'
        return out
    
    try:
        w = whois.whois(domain)
        
        out['creation_date'] = str(w.creation_date)
        out['expiration_date'] = str(w.expiration_date)
        out['registrar'] = str(w.registrar)
        out['country'] = str(w.country)
        
        # حساب العمر
        try:
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    cd = w.creation_date[0]
                else:
                    cd = w.creation_date
                
                if cd:
                    now = datetime.datetime.now(datetime.timezone.utc)
                    if isinstance(cd, str):
                        from dateutil import parser
                        cd = parser.parse(cd)
                    
                    age_days = (now - cd).days
                    out['age_days'] = age_days
                    
                    # تحليل العمر
                    if age_days < 30:
                        out['analysis']['age_category'] = 'جديد'
                    elif age_days < 365:
                        out['analysis']['age_category'] = 'شباب'
                    else:
                        out['analysis']['age_category'] = 'قديم'
        
        except Exception as e:
            out['age_error'] = str(e)
        
        # تحليل إضافي
        out['analysis']['has_privacy'] = any('privacy' in str(s).lower() for s in w.status) if w.status else False
        out['analysis']['is_expired'] = any('expired' in str(s).lower() for s in w.status) if w.status else False
    
    except Exception as e:
        out['error'] = str(e)
    
    return out

def network_info_enhanced(domain):
    """معلومات الشبكة محسنة"""
    out = {
        'domain': domain,
        'ip_addresses': [],
        'ipv4_addresses': [],
        'ipv6_addresses': [],
        'reverse_dns': []
    }
    
    try:
        # IPv4
        try:
            ipv4_info = socket.getaddrinfo(domain, None, socket.AF_INET)
            ipv4_addresses = list(set([info[4][0] for info in ipv4_info]))
            out['ipv4_addresses'] = ipv4_addresses
        except:
            pass
        
        # IPv6
        try:
            ipv6_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
            ipv6_addresses = list(set([info[4][0] for info in ipv6_info]))
            out['ipv6_addresses'] = ipv6_addresses
        except:
            pass
        
        # جميع عناوين IP
        out['ip_addresses'] = out['ipv4_addresses'] + out['ipv6_addresses']
        
        # DNS عكسي
        for ip in out['ipv4_addresses'][:3]:  # أول 3 عناوين فقط
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                out['reverse_dns'].append({'ip': ip, 'hostname': hostname})
            except:
                out['reverse_dns'].append({'ip': ip, 'hostname': 'غير متاح'})
    
    except Exception as e:
        out['error'] = str(e)
    
    return out

def traffic_analysis_enhanced(url):
    """تحليل حركة المرور محسن"""
    out = {
        'request_info': {},
        'performance': {},
        'security': {}
    }
    
    try:
        session = create_session()
        start_time = time.time()
        
        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": get_random_user_agent()}
        )
        
        end_time = time.time()
        
        out['request_info'] = {
            'status_code': response.status_code,
            'final_url': response.url,
            'redirect_count': len(response.history),
            'duration_seconds': round(end_time - start_time, 3)
        }
        
        out['performance'] = {
            'content_length': len(response.content),
            'headers_count': len(response.headers),
            'cookies_count': len(response.cookies)
        }
        
        # هيدرات الأمان
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection'
        ]
        
        security_info = {}
        for header in security_headers:
            if header in response.headers:
                security_info[header] = {
                    'present': True,
                    'value': response.headers[header]
                }
            else:
                security_info[header] = {'present': False}
        
        out['security'] = security_info
    
    except Exception as e:
        out['error'] = str(e)
    
    return out

# ------------------------------------------------------------
# تطوير دوال الحفظ والتقارير
def save_report_files_enhanced(basepath, report, summary=None):
    """حفظ تقارير محسنة"""
    txt = report_to_text_ar_enhanced(report, summary)
    htmlt = report_to_html_ar_enhanced(report, summary)
    
    txt_path = basepath + ".txt"
    html_path = basepath + ".html"
    
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(txt)
    
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(htmlt)
    
    if REPORTLAB_AVAILABLE:
        try:
            pdf_path = basepath + ".pdf"
            save_report_pdf_enhanced(pdf_path, report, summary)
            return [txt_path, html_path, pdf_path]
        except Exception:
            return [txt_path, html_path]
    
    return [txt_path, html_path]

def report_to_text_ar_enhanced(report, summary=None):
    """تقرير نصي محسن"""
    lines = []
    lines.append("=" * 60)
    lines.append(f"تقرير الفحص المتطور - {now_str()}")
    lines.append("=" * 60)
    
    if summary:
        lines.append(f"\nالملخص: {summary.get('verdict', '')}")
        lines.append(f"النقاط: {summary.get('score', 0)}")
        lines.append(f"المستوى: {summary.get('risk_level', summary.get('threat_level', 'غير معروف'))}")
        
        if summary.get('reasons'):
            lines.append("\nالأسباب/المؤشرات:")
            for r in summary['reasons']:
                lines.append(f"- {r}")
    
    lines.append("\n" + "=" * 60)
    lines.append("التفاصيل الكاملة")
    lines.append("=" * 60)
    
    for section, data in report.items():
        lines.append(f"\n{section.upper()}:")
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    lines.append(f"  {key}:")
                    if isinstance(value, dict):
                        for k, v in value.items():
                            lines.append(f"    {k}: {v}")
                    else:
                        for item in value[:10]:  # أول 10 عناصر فقط
                            lines.append(f"    - {item}")
                        if len(value) > 10:
                            lines.append(f"    - ... و{len(value) - 10} عناصر أخرى")
                else:
                    lines.append(f"  {key}: {value}")
        elif isinstance(data, list):
            for item in data[:10]:  # أول 10 عناصر فقط
                lines.append(f"  - {item}")
            if len(data) > 10:
                lines.append(f"  - ... و{len(data) - 10} عناصر أخرى")
        else:
            lines.append(f"  {data}")
    
    return "\n".join(lines)

def report_to_html_ar_enhanced(report, summary=None):
    """تقرير HTML محسن"""
    css = """
    <style>
        body {
            font-family: Arial, sans-serif;
            direction: rtl;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .report {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #333;
        }
        .summary {
            background: #e8f4f8;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .details {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .good { color: green; }
        .warning { color: orange; }
        .danger { color: red; }
        pre {
            background: #f4f4f4;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        ul { padding-right: 20px; }
        li { margin: 5px 0; }
    </style>
    """
    
    html_parts = []
    html_parts.append(f"<html><head><meta charset='utf-8'>{css}</head><body>")
    html_parts.append("<div class='report'>")
    
    html_parts.append(f"<h1>تقرير الفحص المتطور</h1>")
    html_parts.append(f"<h3>{html.escape(now_str())}</h3>")
    
    if summary:
        html_parts.append("<div class='summary'>")
        
        verdict = summary.get('verdict', '')
        score = summary.get('score', 0)
        
        # لون النتيجة
        if 'تصيد' in verdict or score >= 60:
            verdict_class = 'danger'
        elif 'مشبوه' in verdict or score >= 30:
            verdict_class = 'warning'
        else:
            verdict_class = 'good'
        
        html_parts.append(f"<h2 class='{verdict_class}'>الملخص: {html.escape(verdict)}</h2>")
        html_parts.append(f"<h3>النقاط: {score}</h3>")
        
        if summary.get('reasons'):
            html_parts.append("<h4>الأسباب/المؤشرات:</h4><ul>")
            for r in summary['reasons']:
                html_parts.append(f"<li>{html.escape(r)}</li>")
            html_parts.append("</ul>")
        
        html_parts.append("</div>")
    
    html_parts.append("<div class='details'>")
    html_parts.append("<h2>التفاصيل الكاملة</h2>")
    
    for section, data in report.items():
        html_parts.append(f"<h3>{html.escape(section.upper())}</h3>")
        
        if isinstance(data, dict):
            html_parts.append("<ul>")
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    html_parts.append(f"<li><strong>{html.escape(str(key))}:</strong>")
                    
                    if isinstance(value, dict):
                        html_parts.append("<ul>")
                        for k, v in value.items():
                            html_parts.append(f"<li>{html.escape(str(k))}: {html.escape(str(v))}</li>")
                        html_parts.append("</ul>")
                    else:
                        html_parts.append("<ul>")
                        for item in value[:5]:  # أول 5 عناصر فقط
                            html_parts.append(f"<li>{html.escape(str(item))}</li>")
                        if len(value) > 5:
                            html_parts.append(f"<li>... و{len(value) - 5} عناصر أخرى</li>")
                        html_parts.append("</ul>")
                    
                    html_parts.append("</li>")
                else:
                    html_parts.append(f"<li><strong>{html.escape(str(key))}:</strong> {html.escape(str(value))}</li>")
            html_parts.append("</ul>")
        elif isinstance(data, list):
            html_parts.append("<ul>")
            for item in data[:5]:  # أول 5 عناصر فقط
                html_parts.append(f"<li>{html.escape(str(item))}</li>")
            if len(data) > 5:
                html_parts.append(f"<li>... و{len(data) - 5} عناصر أخرى</li>")
            html_parts.append("</ul>")
        else:
            html_parts.append(f"<pre>{html.escape(str(data))}</pre>")
    
    html_parts.append("</div>")
    html_parts.append("</div></body></html>")
    
    return "\n".join(html_parts)

def save_report_pdf_enhanced(path, report, summary=None):
    """حفظ تقرير PDF محسن"""
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab غير مثبت")
    
    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    
    # إنشاء أنماط مخصصة للعربية
    arabic_style = ParagraphStyle(
        'ArabicStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        alignment=TA_RIGHT,
        rightIndent=20
    )
    
    title_style = ParagraphStyle(
        'ArabicTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=16,
        alignment=TA_CENTER,
        spaceAfter=30
    )
    
    heading_style = ParagraphStyle(
        'ArabicHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        alignment=TA_RIGHT,
        spaceAfter=10
    )
    
    story = []
    
    # العنوان
    story.append(Paragraph(f"تقرير الفحص المتطور - {now_str()}", title_style))
    story.append(Spacer(1, 20))
    
    # الملخص
    if summary:
        verdict = summary.get('verdict', '')
        score = summary.get('score', 0)
        
        story.append(Paragraph(f"الملخص: {verdict}", heading_style))
        story.append(Paragraph(f"النقاط: {score}", arabic_style))
        
        if summary.get('reasons'):
            story.append(Paragraph("الأسباب/المؤشرات:", arabic_style))
            for r in summary['reasons']:
                story.append(Paragraph(f"- {r}", arabic_style))
        
        story.append(Spacer(1, 20))
    
    # التفاصيل
    story.append(Paragraph("التفاصيل الكاملة", heading_style))
    story.append(Spacer(1, 10))
    
    for section, data in report.items():
        story.append(Paragraph(section.upper(), heading_style))
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    story.append(Paragraph(f"{key}:", arabic_style))
                    
                    if isinstance(value, dict):
                        for k, v in value.items():
                            story.append(Paragraph(f"  {k}: {v}", arabic_style))
                    else:
                        for item in value[:5]:
                            story.append(Paragraph(f"  - {item}", arabic_style))
                        if len(value) > 5:
                            story.append(Paragraph(f"  - ... و{len(value) - 5} عناصر أخرى", arabic_style))
                else:
                    story.append(Paragraph(f"{key}: {value}", arabic_style))
        elif isinstance(data, list):
            for item in data[:5]:
                story.append(Paragraph(f"- {item}", arabic_style))
            if len(data) > 5:
                story.append(Paragraph(f"- ... و{len(data) - 5} عناصر أخرى", arabic_style))
        else:
            story.append(Paragraph(str(data), arabic_style))
        
        story.append(Spacer(1, 10))
    
    doc.build(story)

# ------------------------------------------------------------
# القائمة الرئيسية المحسنة
def main_menu_enhanced():
    """القائمة الرئيسية المحسنة"""
    while True:
        print("\n" + "=" * 60)
        print("أداة الفحص فروا - القائمة الرئيسية")
        print("=" * 60)
        
        print("\nاختر رقم العملية:")
        print(" 1) فحص رابط سريع (معلومات موسعة)")
        print(" 2) توسيع/تحليل روابط مختصرة")
        print(" 3) فحص بريد إلكتروني")
        print(" 4) فحص كلمة مرور (تحليل مفصل)")
        print(" 5) فحص ملف برمجي")
        print(" 6) فحص QR من صورة")
        print(" 7) فحص روابط تحميل")
        print(" 8) فحص ملف عام (أي صيغة)")
        print(" 9) فحص تطبيقات الجوال (APK/IPA)")
        print("10) فحص احتمال صفحة تصيد")
        print("11) فحص متعدد للروابط (5 خانات)")
        print(" 0) خروج")
        
        print("\n" + "-" * 60)
        ch = input("أدخل رقم الخيار: ").strip()
        print("-" * 60)
        
        try:
            if ch == "1":
                handle_scan_url_quick_enhanced()
            elif ch == "2":
                handle_expand_short_url_enhanced()
            elif ch == "3":
                handle_scan_email_enhanced()
            elif ch == "4":
                handle_check_password_enhanced()
            elif ch == "5":
                handle_scan_code_file_enhanced()
            elif ch == "6":
                handle_scan_qr_enhanced()
            elif ch == "7":
                handle_scan_download_links_enhanced()
            elif ch == "8":
                handle_scan_generic_file_enhanced()
            elif ch == "9":
                handle_scan_apk_ipa_enhanced()
            elif ch == "10":
                handle_phishing_check_enhanced()
            elif ch == "11":
                prompt_five_links_and_scan_enhanced()
            elif ch == "0":
                print("\n" + "=" * 60)
                print("شكراً لاستخدام أداة فروا")
                print("مع السلامة")
                print("=" * 60)
                break
            else:
                print("خيار غير صالح!")
        
        except KeyboardInterrupt:
            print("\nتم إلغاء العملية")
            continue
        
        except Exception as e:
            print(f"\nخطأ غير متوقع: {e}")
            traceback.print_exc()
            
            retry = input("\nهل تريد إعادة المحاولة؟ (نعم/لا): ").strip().lower()
            if retry != "نعم":
                print("\nمع السلامة")
                break

# ------------------------------------------------------------
# تشغيل البرنامج
if __name__ == "__main__":
    try:
        # فحص المكتبات المطلوبة
        print("\n" + "=" * 60)
        print("فحص المكتبات المثبتة...")
        print("=" * 60)
        
        libraries = [
            ("requests", REQUESTS_AVAILABLE, "pip install requests"),
            ("whois", WHOIS_AVAILABLE, "pip install python-whois"),
            ("PIL (Pillow)", PIL_AVAILABLE, "pip install pillow"),
            ("pyzbar", PYZBAR_AVAILABLE, "pip install pyzbar"),
            ("reportlab", REPORTLAB_AVAILABLE, "pip install reportlab"),
            ("BeautifulSoup4", BS4_AVAILABLE, "pip install beautifulsoup4")
        ]
        
        all_available = True
        for lib_name, available, install_cmd in libraries:
            status = "مثبت" if available else "غير مثبت"
            print(f"{lib_name}: {status}")
            
            if not available:
                all_available = False
                print(f"  للتثبيت: {install_cmd}")
        
        print("\n" + "=" * 60)
        
        if not all_available:
            print("بعض المكتبات غير مثبتة")
            print("بعض المميزات قد لا تعمل بشكل كامل")
            
            continue_anyway = input("\nهل تريد المتابعة رغم ذلك؟ (نعم/لا): ").strip().lower()
            if continue_anyway != "نعم":
                print("مع السلامة")
                sys.exit(0)
        
        # بدء القائمة الرئيسية
        main_menu_enhanced()
    
    except KeyboardInterrupt:
        print("\n\nتم إيقاف البرنامج")
        print("مع السلامة")
    
    except Exception as e:
        print(f"\nخطأ فادح: {e}")
        traceback.print_exc()
        print("مع السلامة")