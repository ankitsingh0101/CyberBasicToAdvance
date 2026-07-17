"""
url_checker.py
Extracts URLs from email body, defangs them for safe display,
checks against known phishing patterns, and optionally queries VirusTotal.
"""

import re
import urllib.parse
import requests
import hashlib
import time


# ── Known bad patterns ────────────────────────────────────────────────────────

# URL shorteners — often used to hide phishing destinations
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "linktr.ee", "rb.gy", "cutt.ly"
}

# Free hosting / suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # free Freenom domains
    ".xyz", ".top", ".club", ".online", ".site", ".website",
    ".info", ".biz", ".click", ".link"
}

# Brands commonly impersonated in phishing URLs
IMPERSONATED_BRANDS = [
    "paypal", "amazon", "apple", "google", "microsoft", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "icloud", "outlook", "office365", "wellsfargo", "chase",
    "bankofamerica", "citibank", "irs", "fedex", "dhl", "ups"
]

# Phishing keyword patterns in URLs
PHISHING_URL_KEYWORDS = [
    "verify", "confirm", "update", "secure", "login", "signin",
    "account", "banking", "password", "credential", "reset",
    "suspended", "locked", "urgent", "limited", "expire"
]


# ── URL extraction ────────────────────────────────────────────────────────────

def extract_urls(text):
    """Extract all URLs from email body text."""
    # Match http/https URLs
    pattern = r'https?://[^\s<>"\')\]]+[^\s<>"\')\].,!?]'
    urls = re.findall(pattern, text, re.IGNORECASE)

    # Also catch URLs in HTML href attributes
    href_pattern = r'href=["\']?(https?://[^\s"\'<>]+)["\']?'
    href_urls = re.findall(href_pattern, text, re.IGNORECASE)

    all_urls = list(set(urls + href_urls))
    return all_urls[:20]  # cap at 20 URLs


def defang_url(url):
    """
    Defang a URL for safe display — replace dots and :// so it
    can't be accidentally clicked. Standard in security reports.
    e.g. https://evil.com → hxxps://evil[.]com
    """
    defanged = url.replace("https://", "hxxps://")
    defanged = defanged.replace("http://", "hxxp://")
    # Replace dots in domain only (first part before path)
    parsed = urllib.parse.urlparse(url)
    domain_defanged = parsed.netloc.replace(".", "[.]")
    defanged = defanged.replace(parsed.netloc, domain_defanged)
    return defanged


def get_domain(url):
    """Extract domain from URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


# ── URL analysis ──────────────────────────────────────────────────────────────

def check_url_shortener(url):
    domain = get_domain(url)
    # Strip www.
    domain = re.sub(r'^www\.', '', domain)
    if domain in URL_SHORTENERS:
        return True, f"URL shortener detected ({domain}) — hides real destination"
    return False, ""


def check_suspicious_tld(url):
    domain = get_domain(url)
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True, f"Suspicious TLD ({tld}) — commonly used in free phishing domains"
    return False, ""


def check_brand_impersonation(url):
    """Check if URL contains a brand name but is NOT that brand's real domain."""
    domain = get_domain(url).lower()
    for brand in IMPERSONATED_BRANDS:
        if brand in domain:
            # Check if it's the legitimate domain (e.g. paypal.com, amazon.com)
            legit_pattern = rf'^(www\.)?{re.escape(brand)}\.(com|co\.\w+|org|net)$'
            if not re.match(legit_pattern, domain):
                return True, f"Brand impersonation — '{brand}' in URL but domain is '{domain}'"
    return False, ""


def check_phishing_keywords(url):
    url_lower = url.lower()
    found = [kw for kw in PHISHING_URL_KEYWORDS if kw in url_lower]
    if len(found) >= 2:
        return True, f"Multiple phishing keywords in URL: {', '.join(found)}"
    elif found:
        return False, f"Phishing keyword present: {found[0]}"  # just a warning
    return False, ""


def check_ip_url(url):
    """URLs using raw IP instead of domain are highly suspicious."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.split(":")[0]
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, host):
        return True, f"URL uses raw IP address ({host}) instead of domain — highly suspicious"
    return False, ""


def check_subdomain_abuse(url):
    """Attackers use legitimate-looking subdomains: paypal.com.evil.net"""
    domain = get_domain(url)
    parts = domain.split(".")
    if len(parts) > 3:
        # Check if a brand appears as a subdomain
        subdomain = ".".join(parts[:-2])
        for brand in IMPERSONATED_BRANDS:
            if brand in subdomain:
                return True, f"Brand '{brand}' used as subdomain — classic phishing trick (real domain: {'.'.join(parts[-2:])})"
    return False, ""


def check_homograph(url):
    """Detect homograph attacks — look-alike characters (e.g. paypaI with capital i)."""
    domain = get_domain(url)
    # Check for mixed scripts or suspicious lookalikes
    suspicious_chars = re.findall(r'[^\x00-\x7F]', domain)
    if suspicious_chars:
        return True, f"Non-ASCII characters in domain — possible homograph/IDN attack"
    return False, ""


# ── VirusTotal ────────────────────────────────────────────────────────────────

def check_virustotal(url, api_key):
    """
    Query VirusTotal API v3 for a URL's reputation.
    Returns (is_malicious, detections, total_engines, permalink)
    """
    if not api_key or api_key.strip() == "YOUR_VT_API_KEY":
        return None, 0, 0, ""

    headers = {"x-apikey": api_key}

    try:
        # Encode URL for VT API
        url_id = urllib.parse.quote_plus(url)

        # First try direct URL lookup
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            permalink = f"https://www.virustotal.com/gui/url/{url_id}"
            return (malicious + suspicious) > 0, malicious + suspicious, total, permalink

        elif response.status_code == 404:
            # URL not in VT yet — submit it
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            if submit.status_code == 200:
                return None, 0, 0, ""  # queued, no result yet

    except requests.RequestException as e:
        pass

    return None, 0, 0, ""


# ── Main URL analysis ─────────────────────────────────────────────────────────

def analyze_urls(body_text, vt_api_key=""):
    """
    Extract and analyze all URLs from email body.
    Returns list of per-URL results and an overall URL risk score.
    """
    urls = extract_urls(body_text)
    results = []
    total_score = 0

    for url in urls:
        url_findings = []
        url_score = 0
        defanged = defang_url(url)

        # Run all local checks
        checks = [
            check_ip_url,
            check_url_shortener,
            check_suspicious_tld,
            check_brand_impersonation,
            check_subdomain_abuse,
            check_homograph,
            check_phishing_keywords,
        ]

        weights = {
            check_ip_url: 40,
            check_url_shortener: 20,
            check_suspicious_tld: 25,
            check_brand_impersonation: 40,
            check_subdomain_abuse: 45,
            check_homograph: 40,
            check_phishing_keywords: 15,
        }

        for check_fn in checks:
            flagged, message = check_fn(url)
            if message:
                severity = "fail" if flagged else "warn"
                url_findings.append((severity, message))
                if flagged:
                    url_score += weights.get(check_fn, 10)

        # VirusTotal check
        vt_malicious, vt_detections, vt_total, vt_link = check_virustotal(url, vt_api_key)
        if vt_malicious is True:
            url_findings.append(("fail",
                f"VirusTotal: {vt_detections}/{vt_total} engines flagged as malicious — {vt_link}"))
            url_score += 50
        elif vt_malicious is False and vt_total > 0:
            url_findings.append(("pass", f"VirusTotal: 0/{vt_total} engines flagged — clean"))
        elif vt_api_key and vt_api_key != "YOUR_VT_API_KEY":
            url_findings.append(("info", "VirusTotal: URL not yet analysed or queued"))

        if not url_findings:
            url_findings.append(("pass", "No suspicious indicators found"))

        url_score = min(url_score, 100)
        total_score = max(total_score, url_score)  # worst URL drives overall score

        results.append({
            "url": url,
            "defanged": defanged,
            "domain": get_domain(url),
            "score": url_score,
            "findings": url_findings,
        })

    return results, min(total_score, 100)
