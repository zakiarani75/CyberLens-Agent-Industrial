"""
CyberLens Agent - Industrial Level QR Intelligence Platform
Developed By Zakia Rani
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
import cv2
import numpy as np
from pyzbar.pyzbar import decode
import json
from datetime import datetime, timedelta
import os
from pathlib import Path
import requests
import re
import hashlib
import ssl
import socket
from urllib.parse import urlparse, unquote
import whois
import dns.resolver
from bs4 import BeautifulSoup
import tldextract

# ============ APP SETUP ============

app = FastAPI(
    title="CyberLens Agent",
    description="Cyber Security Intelligence Platform",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

# ============ SCAN DATABASE ============

scan_history = []
total_scans = 0
safe_count = 0
suspicious_count = 0
dangerous_count = 0
top_domains = {}

# ============ API ENDPOINTS ============

@app.get("/")
def home():
    return {
        "platform": "CyberLens Agent",
        "developer": "Zakia Rani",
        "status": "active",
        "version": "2.0.0"
    }

@app.get("/api/dashboard")
def get_dashboard():
    """Dashboard statistics"""
    global total_scans, safe_count, suspicious_count, dangerous_count
    
    # Top domains sorted
    sorted_domains = sorted(top_domains.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        "total_scans": total_scans,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "dangerous_count": dangerous_count,
        "top_domains": [{"domain": d, "count": c} for d, c in sorted_domains],
        "recent_scans": scan_history[-10:] if scan_history else []
    }

@app.get("/api/history")
def get_history():
    """Get all scan history"""
    return {
        "total": len(scan_history),
        "scans": scan_history[-50:]  # Last 50 scans
    }

@app.post("/api/qr/scan")
async def scan_qr(file: UploadFile = File(...)):
    """
    Complete QR code analysis
    Returns full intelligence report
    """
    global total_scans, safe_count, suspicious_count, dangerous_count
    
    try:
        # Read image
        contents = await file.read()
        nparr = np.frombuffer(contents, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            raise HTTPException(400, "Could not read image file")
        
        # Decode QR
        decoded_objects = decode(img)
        
        if not decoded_objects:
            return {
                "success": True,
                "message": "No QR code found in image",
                "data": None
            }
        
        # Process each QR code
        results = []
        for obj in decoded_objects:
            qr_data = obj.data.decode('utf-8')
            result = analyze_qr_complete(qr_data)
            results.append(result)
        
        # Update statistics
        total_scans += 1
        main_result = results[0]
        
        if main_result["threat_level"] == "Safe":
            safe_count += 1
        elif main_result["threat_level"] in ["Suspicious", "Medium Risk"]:
            suspicious_count += 1
        else:
            dangerous_count += 1
        
        # Track domains
        domain = main_result.get("domain_info", {}).get("domain")
        if domain:
            top_domains[domain] = top_domains.get(domain, 0) + 1
        
        # Save to history
        history_entry = {
            "id": total_scans,
            "timestamp": datetime.now().isoformat(),
            "qr_data": main_result.get("qr_info", {}).get("content", "N/A"),
            "threat_level": main_result["threat_level"],
            "security_score": main_result["security_analysis"]["security_score"]
        }
        scan_history.append(history_entry)
        
        return {
            "success": True,
            "message": "QR code analyzed successfully",
            "data": results[0] if results else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Error: {str(e)}")

def analyze_qr_complete(qr_data):
    """
    Complete analysis of QR code data
    Returns full intelligence report
    """
    
    # Basic QR info
    qr_info = {
        "content": qr_data,
        "type": detect_qr_type(qr_data),
        "category": detect_qr_category(qr_data),
        "length": len(qr_data)
    }
    
    # URL Intelligence
    url_info = {}
    domain_info = {}
    company_info = {}
    
    if qr_data.startswith(("http://", "https://", "www.")):
        url_info = analyze_url(qr_data)
        domain_info = analyze_domain(qr_data)
        company_info = analyze_company(qr_data)
    
    # Email Intelligence
    email_info = analyze_email(qr_data)
    
    # Product Intelligence
    product_info = analyze_product(qr_data)
    
    # Application Intelligence
    app_info = analyze_application(qr_data)
    
    # Brand Verification
    brand_info = verify_brand(qr_data, company_info)
    
    # Threat Analysis
    threat_info = analyze_threats(qr_data, url_info, domain_info)
    
    # Security Analysis
    security_info = calculate_security_scores(threat_info, domain_info, brand_info)
    
    # OSINT Information
    osint_info = gather_osint(qr_data, domain_info)
    
    # Generate recommendations
    recommendations = generate_recommendations(security_info, threat_info)
    
    # Determine threat level
    threat_level = determine_threat_level(security_info["security_score"])
    
    return {
        "qr_info": qr_info,
        "url_info": url_info if url_info else None,
        "domain_info": domain_info if domain_info else None,
        "company_info": company_info if company_info else None,
        "email_info": email_info if email_info else None,
        "product_info": product_info if product_info else None,
        "application_info": app_info if app_info else None,
        "brand_verification": brand_info,
        "threat_analysis": threat_info,
        "security_analysis": security_info,
        "osint_findings": osint_info,
        "recommendations": recommendations,
        "threat_level": threat_level,
        "final_verdict": generate_final_verdict(security_info, threat_info)
    }

def detect_qr_type(data):
    """Detect what type of data is in QR"""
    if data.startswith(("http://", "https://")):
        return "URL"
    elif "@" in data and "." in data:
        return "Email"
    elif data.startswith("WIFI:"):
        return "WiFi Configuration"
    elif data.startswith("MATMSG:"):
        return "Email Message"
    elif data.startswith("TEL:"):
        return "Phone Number"
    elif data.startswith("SMSTO:"):
        return "SMS"
    elif data.startswith("BEGIN:VCARD"):
        return "Contact Card"
    elif data.startswith("BEGIN:VEVENT"):
        return "Calendar Event"
    elif data.startswith("bitcoin:") or data.startswith("BTC:"):
        return "Cryptocurrency Address"
    elif re.match(r'^\d+$', data):
        return "Numeric Code"
    else:
        return "Text"

def detect_qr_category(data):
    """Detect category of QR content"""
    if data.startswith(("http://", "https://")):
        url_lower = data.lower()
        
        # Social Media
        social_platforms = ["facebook", "twitter", "instagram", "linkedin", 
                          "youtube", "tiktok", "snapchat", "pinterest", "whatsapp"]
        for platform in social_platforms:
            if platform in url_lower:
                return f"Social Media - {platform.capitalize()}"
        
        # E-commerce
        ecommerce = ["amazon", "ebay", "aliexpress", "shopify", "etsy", "walmart", "daraz"]
        for site in ecommerce:
            if site in url_lower:
                return f"E-commerce - {site.capitalize()}"
        
        # Payment
        payment = ["paypal", "stripe", "razorpay", "paytm", "googlepay", "applepay"]
        for p in payment:
            if p in url_lower:
                return f"Payment - {p.capitalize()}"
        
        # Banking
        banks = ["bank", "hbl", "ubl", "allied", "meezan", "nbp"]
        for bank in banks:
            if bank in url_lower:
                return f"Banking - {bank.capitalize()}"
        
        return "Website"
    elif "@" in data:
        return "Contact Email"
    else:
        return "Text Content"

def analyze_url(url):
    """Complete URL analysis"""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    
    extracted = tldextract.extract(url)
    
    # Expand shortened URLs
    expanded_url = expand_url(url)
    
    # Check SSL
    ssl_valid = check_ssl(domain)
    
    # Get website info
    website_info = get_website_info(url)
    
    return {
        "original_url": url,
        "expanded_url": expanded_url,
        "domain": domain,
        "scheme": parsed.scheme,
        "path": parsed.path,
        "query_params": parsed.query if parsed.query else None,
        "ssl_valid": ssl_valid,
        "website_name": website_info.get("title", domain),
        "description": website_info.get("description", ""),
        "has_favicon": website_info.get("has_favicon", False),
        "redirects": website_info.get("redirects", 0),
        "server": website_info.get("server", "Unknown")
    }

def expand_url(short_url):
    """Expand shortened URLs"""
    try:
        response = requests.head(short_url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return short_url

def check_ssl(domain):
    """Check SSL certificate validity"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "issuer": dict(cert.get("issuer", [])).get("organizationName", "Unknown"),
                    "expiry": cert.get("notAfter", "Unknown"),
                    "subject": dict(cert.get("subject", [])).get("commonName", domain)
                }
    except:
        return {
            "valid": False,
            "issuer": "No SSL",
            "expiry": "N/A",
            "subject": domain
        }

def get_website_info(url):
    """Fetch website information"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        title = soup.title.string if soup.title else "No title"
        desc_tag = soup.find('meta', attrs={'name': 'description'})
        description = desc_tag['content'] if desc_tag and desc_tag.get('content') else ""
        favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        
        return {
            "title": title.strip() if title else "Unknown",
            "description": description.strip() if description else "",
            "has_favicon": favicon is not None,
            "redirects": len(response.history),
            "server": response.headers.get('Server', 'Unknown')
        }
    except:
        return {
            "title": "Could not fetch",
            "description": "",
            "has_favicon": False,
            "redirects": 0,
            "server": "Unknown"
        }

def analyze_domain(url):
    """Complete domain analysis"""
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        
        # Calculate domain age
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            age_years = age_days // 365
        else:
            age_days = 0
            age_years = 0
        
        # DNS records
        dns_records = []
        try:
            answers = dns.resolver.resolve(domain, 'A')
            dns_records = [str(r) for r in answers]
        except:
            pass
        
        return {
            "domain": domain,
            "registrar": w.registrar or "Unknown",
            "creation_date": str(creation_date) if creation_date else "Unknown",
            "expiry_date": str(expiry_date) if expiry_date else "Unknown",
            "domain_age_days": age_days,
            "domain_age_years": age_years,
            "name_servers": w.name_servers if w.name_servers else [],
            "dns_records": dns_records,
            "registrant_country": w.country or "Unknown",
            "registrant_organization": w.org or "Unknown"
        }
    except:
        return {
            "domain": domain,
            "registrar": "Could not fetch",
            "creation_date": "Unknown",
            "domain_age_days": 0,
            "domain_age_years": 0,
            "registrant_country": "Unknown"
        }

def analyze_company(url):
    """Identify company from URL"""
    extracted = tldextract.extract(url)
    domain = extracted.domain.lower()
    
    # Known companies database
    companies = {
        "google": {
            "name": "Google LLC",
            "industry": "Technology",
            "parent": "Alphabet Inc.",
            "trusted": True,
            "website": "https://about.google"
        },
        "facebook": {
            "name": "Meta Platforms, Inc.",
            "industry": "Social Media",
            "parent": "Meta",
            "trusted": True,
            "website": "https://about.meta.com"
        },
        "whatsapp": {
            "name": "WhatsApp LLC",
            "industry": "Communication",
            "parent": "Meta Platforms, Inc.",
            "trusted": True,
            "website": "https://www.whatsapp.com"
        },
        "instagram": {
            "name": "Instagram LLC",
            "industry": "Social Media",
            "parent": "Meta Platforms, Inc.",
            "trusted": True,
            "website": "https://about.instagram.com"
        },
        "twitter": {
            "name": "Twitter (X Corp.)",
            "industry": "Social Media",
            "parent": "X Corp.",
            "trusted": True,
            "website": "https://about.twitter.com"
        },
        "linkedin": {
            "name": "LinkedIn Corporation",
            "industry": "Professional Networking",
            "parent": "Microsoft Corporation",
            "trusted": True,
            "website": "https://about.linkedin.com"
        },
        "amazon": {
            "name": "Amazon.com, Inc.",
            "industry": "E-commerce",
            "parent": "Amazon",
            "trusted": True,
            "website": "https://www.amazon.com"
        },
        "apple": {
            "name": "Apple Inc.",
            "industry": "Technology",
            "parent": "Apple",
            "trusted": True,
            "website": "https://www.apple.com"
        },
        "microsoft": {
            "name": "Microsoft Corporation",
            "industry": "Technology",
            "parent": "Microsoft",
            "trusted": True,
            "website": "https://www.microsoft.com"
        },
        "youtube": {
            "name": "YouTube LLC",
            "industry": "Video Sharing",
            "parent": "Google LLC",
            "trusted": True,
            "website": "https://www.youtube.com"
        },
        "netflix": {
            "name": "Netflix, Inc.",
            "industry": "Entertainment",
            "parent": "Netflix",
            "trusted": True,
            "website": "https://www.netflix.com"
        },
        "paypal": {
            "name": "PayPal Holdings, Inc.",
            "industry": "Financial Services",
            "parent": "PayPal",
            "trusted": True,
            "website": "https://www.paypal.com"
        }
    }
    
    if domain in companies:
        company = companies[domain]
        return {
            "name": company["name"],
            "domain": f"{domain}.com",
            "industry": company["industry"],
            "parent_company": company["parent"],
            "trusted": company["trusted"],
            "official_website": company["website"],
            "reputation": "Excellent" if company["trusted"] else "Unknown"
        }
    
    return {
        "name": domain.capitalize(),
        "domain": f"{domain}.com",
        "industry": "Unknown",
        "parent_company": "Unknown",
        "trusted": False,
        "official_website": f"https://{extracted.domain}.{extracted.suffix}",
        "reputation": "Unknown"
    }

def analyze_email(data):
    """Extract and analyze email addresses"""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, data)
    
    if emails:
        results = []
        for email in emails:
            domain = email.split('@')[1]
            
            # Check for disposable email
            disposable_domains = [
                "tempmail.com", "throwaway.com", "mailinator.com",
                "guerrillamail.com", "sharklasers.com", "yopmail.com"
            ]
            is_disposable = domain in disposable_domains
            
            results.append({
                "email": email,
                "domain": domain,
                "is_disposable": is_disposable,
                "reputation": "Disposable" if is_disposable else "Personal/Business"
            })
        
        return results
    
    return None

def analyze_product(data):
    """Detect product information from QR data"""
    url_lower = data.lower()
    
    # Product patterns
    products = {
        "iphone": {"name": "iPhone", "brand": "Apple", "category": "Smartphone"},
        "samsung": {"name": "Samsung Galaxy", "brand": "Samsung", "category": "Smartphone"},
        "nike": {"name": "Nike Product", "brand": "Nike", "category": "Footwear"},
        "adidas": {"name": "Adidas Product", "brand": "Adidas", "category": "Footwear"},
        "coca-cola": {"name": "Coca-Cola", "brand": "Coca-Cola Company", "category": "Beverage"},
        "pepsi": {"name": "Pepsi", "brand": "PepsiCo", "category": "Beverage"},
        "macbook": {"name": "MacBook", "brand": "Apple", "category": "Laptop"},
        "airpods": {"name": "AirPods", "brand": "Apple", "category": "Accessories"}
    }
    
    for key, product in products.items():
        if key in url_lower:
            return {
                "product_name": product["name"],
                "brand": product["brand"],
                "category": product["category"],
                "official_website": f"https://www.{product['brand'].lower().replace(' ', '')}.com"
            }
    
    return None

def analyze_application(data):
    """Detect application information"""
    url_lower = data.lower()
    
    apps = {
        "whatsapp": {
            "name": "WhatsApp",
            "developer": "Meta Platforms, Inc.",
            "category": "Communication",
            "package": "com.whatsapp"
        },
        "instagram": {
            "name": "Instagram",
            "developer": "Meta Platforms, Inc.",
            "category": "Social Media",
            "package": "com.instagram.android"
        },
        "facebook": {
            "name": "Facebook",
            "developer": "Meta Platforms, Inc.",
            "category": "Social Media",
            "package": "com.facebook.katana"
        },
        "twitter": {
            "name": "Twitter (X)",
            "developer": "X Corp.",
            "category": "Social Media",
            "package": "com.twitter.android"
        },
        "snapchat": {
            "name": "Snapchat",
            "developer": "Snap Inc.",
            "category": "Social Media",
            "package": "com.snapchat.android"
        },
        "tiktok": {
            "name": "TikTok",
            "developer": "ByteDance",
            "category": "Social Media",
            "package": "com.zhiliaoapp.musically"
        },
        "youtube": {
            "name": "YouTube",
            "developer": "Google LLC",
            "category": "Video Streaming",
            "package": "com.google.android.youtube"
        },
        "gmail": {
            "name": "Gmail",
            "developer": "Google LLC",
            "category": "Email",
            "package": "com.google.android.gm"
        },
        "google-maps": {
            "name": "Google Maps",
            "developer": "Google LLC",
            "category": "Navigation",
            "package": "com.google.android.apps.maps"
        }
    }
    
    for key, app in apps.items():
        if key in url_lower:
            return app
    
    return None

def verify_brand(data, company_info):
    """Verify if brand is legitimate or fake"""
    
    # Common brand squatted domains
    squatting_patterns = [
        "faceb00k", "face-book", "fac3book", "faceboook",
        "whatsappp", "whats-ap", "whatsapp1",
        "instagr4m", "insta-gram", "instagramm",
        "g00gle", "go0gle", "googel",
        "amaz0n", "amazzon", "amazoon"
    ]
    
    data_lower = data.lower()
    is_fake = False
    impersonated_brand = None
    
    for pattern in squatting_patterns:
        if pattern in data_lower:
            is_fake = True
            # Determine which brand is being impersonated
            if "face" in pattern:
                impersonated_brand = "Facebook"
            elif "whatsapp" in pattern:
                impersonated_brand = "WhatsApp"
            elif "insta" in pattern:
                impersonated_brand = "Instagram"
            elif "goog" in pattern:
                impersonated_brand = "Google"
            elif "amaz" in pattern:
                impersonated_brand = "Amazon"
            break
    
    # Check for brand names in suspicious contexts
    brand_names = ["google", "facebook", "whatsapp", "instagram", "amazon", "paypal", "netflix", "apple"]
    for brand in brand_names:
        if brand in data_lower:
            # Check if it's actually the official domain
            extracted = tldextract.extract(data)
            domain = extracted.domain.lower()
            
            if domain != brand:
                is_fake = True
                impersonated_brand = brand.capitalize()
    
    return {
        "is_legitimate": not is_fake,
        "impersonated_brand": impersonated_brand,
        "brand_trust_score": 10 if not is_fake else 30 if impersonated_brand else 50,
        "verification_details": "Official brand verified" if not is_fake else f"Warning: May be impersonating {impersonated_brand}"
    }

def analyze_threats(data, url_info, domain_info):
    """Complete threat analysis"""
    threats = []
    
    # Check for malicious patterns
    malicious_patterns = {
        "phishing": [
            r'login[0-9]*\.', r'verify.*account', r'secure.*login',
            r'password.*reset', r'bank.*verify', r'update.*payment',
            r'confirm.*identity', r'unusual.*activity'
        ],
        "scam": [
            r'lottery.*winner', r'you.*won', r'free.*prize',
            r'claim.*reward', r'congratulations.*you',
            r'million.*dollar', r'selected.*winner'
        ],
        "malware": [
            r'\.exe$', r'\.apk$', r'\.dmg$', r'\.bat$',
            r'\.vbs$', r'\.scr$', r'\.js$', r'\.jar$'
        ]
    }
    
    data_lower = data.lower()
    
    # Check patterns
    for threat_type, patterns in malicious_patterns.items():
        for pattern in patterns:
            if re.search(pattern, data_lower):
                threats.append({
                    "type": threat_type.upper(),
                    "description": f"Detected {threat_type} pattern in QR content",
                    "severity": "HIGH"
                })
    
    # Check for suspicious redirects
    if url_info and url_info.get("redirects", 0) > 2:
        threats.append({
            "type": "REDIRECT",
            "description": f"Multiple redirects detected ({url_info['redirects']})",
            "severity": "MEDIUM"
        })
    
    # Check domain age
    if domain_info and domain_info.get("domain_age_days", 0) < 30:
        threats.append({
            "type": "NEW_DOMAIN",
            "description": f"Domain is very new ({domain_info['domain_age_days']} days old)",
            "severity": "MEDIUM"
        })
    
    # Check for IP address instead of domain
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    if re.search(ip_pattern, data):
        threats.append({
            "type": "DIRECT_IP",
            "description": "QR code uses IP address instead of domain name",
            "severity": "HIGH"
        })
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.date', '.men']
    for tld in suspicious_tlds:
        if tld in data_lower:
            threats.append({
                "type": "SUSPICIOUS_TLD",
                "description": f"Domain uses suspicious TLD: {tld}",
                "severity": "HIGH"
            })
    
    return {
        "total_threats": len(threats),
        "threats": threats,
        "has_phishing": any(t["type"] == "PHISHING" for t in threats),
        "has_malware": any(t["type"] == "MALWARE" for t in threats),
        "has_scam": any(t["type"] == "SCAM" for t in threats),
        "has_redirects": any(t["type"] == "REDIRECT" for t in threats),
        "high_severity_count": sum(1 for t in threats if t["severity"] == "HIGH"),
        "medium_severity_count": sum(1 for t in threats if t["severity"] == "MEDIUM")
    }

def calculate_security_scores(threat_info, domain_info, brand_info):
    """Calculate all security scores"""
    
    security_score = 100
    threat_score = 0
    reputation_score = 80
    
    # Deduct for threats
    if threat_info:
        threat_score = threat_info["total_threats"] * 15
        security_score -= threat_info["high_severity_count"] * 20
        security_score -= threat_info["medium_severity_count"] * 10
    
    # Domain reputation
    if domain_info:
        age_days = domain_info.get("domain_age_days", 0)
        if age_days < 30:
            reputation_score -= 30
            security_score -= 20
        elif age_days < 365:
            reputation_score -= 10
            security_score -= 10
        elif age_days > 365 * 3:
            reputation_score += 10
    
    # Brand trust
    if brand_info:
        security_score -= brand_info.get("brand_trust_score", 0) // 2
        if not brand_info.get("is_legitimate", True):
            reputation_score -= 30
    
    # Normalize scores
    security_score = max(0, min(100, security_score))
    threat_score = max(0, min(100, threat_score))
    reputation_score = max(0, min(100, reputation_score))
    
    trust_score = max(0, security_score - threat_score // 2)
    risk_score = 100 - security_score
    
    return {
        "security_score": security_score,
        "threat_score": threat_score,
        "trust_score": trust_score,
        "reputation_score": reputation_score,
        "risk_score": risk_score,
        "risk_level": "Low" if risk_score < 30 else "Medium" if risk_score < 60 else "High"
    }

def gather_osint(data, domain_info):
    """Gather OSINT information"""
    findings = []
    
    # Investigate domain
    if domain_info:
        finding = {
            "type": "Domain Investigation",
            "data": {
                "domain": domain_info.get("domain", "Unknown"),
                "registrar": domain_info.get("registrar", "Unknown"),
                "country": domain_info.get("registrant_country", "Unknown"),
                "organization": domain_info.get("registrant_organization", "Unknown"),
                "age": f"{domain_info.get('domain_age_years', 0)} years, {domain_info.get('domain_age_days', 0) % 365} days"
            }
        }
        findings.append(finding)
    
    # Investigate URL
    if data.startswith(("http://", "https://")):
        finding = {
            "type": "URL Investigation",
            "data": {
                "url": data,
                "has_https": data.startswith("https://"),
                "url_length": len(data),
                "has_special_chars": bool(re.search(r'[%@!$^&*()]', data))
            }
        }
        findings.append(finding)
    
    return findings

def generate_recommendations(security_info, threat_info):
    """Generate security recommendations"""
    recommendations = []
    
    if security_info["security_score"] >= 80:
        recommendations.append("This QR code appears safe to scan")
        recommendations.append("Always verify QR codes from unknown sources")
        recommendations.append("Keep your QR scanner app updated")
    elif security_info["security_score"] >= 50:
        recommendations.append("Exercise caution with this QR code")
        recommendations.append("Verify the URL before visiting")
        recommendations.append("Do not enter personal information")
        recommendations.append("Check for SSL certificate")
    else:
        recommendations.append("DO NOT scan this QR code")
        recommendations.append("This QR code shows multiple risk indicators")
        recommendations.append("Report this QR code to security team")
        recommendations.append("Avoid providing any personal information")
    
    if threat_info:
        if threat_info.get("has_phishing"):
            recommendations.append("Phishing risk detected - Do not enter credentials")
        if threat_info.get("has_malware"):
            recommendations.append("Malware risk detected - Do not download files")
        if threat_info.get("has_scam"):
            recommendations.append("Scam pattern detected - Do not make payments")
    
    return recommendations

def determine_threat_level(security_score):
    """Determine threat level from score"""
    if security_score >= 80:
        return "Safe"
    elif security_score >= 60:
        return "Medium Risk"
    elif security_score >= 40:
        return "Suspicious"
    else:
        return "Dangerous"

def generate_final_verdict(security_info, threat_info):
    """Generate final verdict"""
    score = security_info["security_score"]
    
    if score >= 80:
        return "This QR code is SAFE to use. No security threats detected."
    elif score >= 60:
        return "This QR code requires CAUTION. Some minor risks detected."
    elif score >= 40:
        return "This QR code is SUSPICIOUS. Proceed with extreme caution."
    else:
        return "This QR code is DANGEROUS. DO NOT scan or open this QR code."

# ============ REPORT GENERATION ============

@app.get("/api/report/{scan_id}")
def get_report(scan_id: int, format: str = "json"):
    """Generate report for a specific scan"""
    
    if scan_id < 1 or scan_id > len(scan_history):
        raise HTTPException(404, "Scan not found")
    
    scan = scan_history[scan_id - 1]
    
    if format == "json":
        return scan
    
    return {"error": f"Format '{format}' not supported yet"}

@app.get("/api/report/download/{scan_id}")
def download_report(scan_id: int):
    """Download scan report as JSON"""
    
    if scan_id < 1 or scan_id > len(scan_history):
        raise HTTPException(404, "Scan not found")
    
    scan = scan_history[scan_id - 1]
    
    report_path = REPORTS_DIR / f"report_{scan_id}.json"
    with open(report_path, 'w') as f:
        json.dump(scan, f, indent=2)
    
    return FileResponse(
        report_path,
        media_type="application/json",
        filename=f"CyberLens_Report_{scan_id}.json"
    )

# ============ SERVER START ============

if __name__ == "__main__":
    import uvicorn
    print("""
    CyberLens Agent v2.0
    Developed By Zakia Rani
    Server starting...
    """)
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
