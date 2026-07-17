"""
header_analyzer.py
Analyzes email headers for SPF, DKIM, DMARC, spoofing indicators,
reply-to mismatches, and suspicious routing.
"""

import re
import email
from email import policy


# ── Helpers ────────────────────────────────────────────────────────────────────

def extract_domain(address):
    """Pull domain from an email address like user@domain.com → domain.com"""
    match = re.search(r'@([\w\.\-]+)', address or "")
    return match.group(1).lower() if match else ""


def parse_email(raw_text):
    """Parse raw email text into a Message object."""
    try:
        msg = email.message_from_string(raw_text, policy=policy.default)
        return msg
    except Exception:
        return None


# ── Header checks ──────────────────────────────────────────────────────────────

def check_spf(msg):
    """
    Check Authentication-Results or Received-SPF header for SPF result.
    SPF (Sender Policy Framework) verifies the sending mail server is
    authorised by the domain owner.
    """
    findings = []
    score = 0

    auth_results = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")
    combined = (auth_results + " " + received_spf).lower()

    if "spf=pass" in combined:
        findings.append(("pass", "SPF", "SPF check passed — sending server is authorised"))
    elif "spf=fail" in combined:
        findings.append(("fail", "SPF", "SPF FAILED — sending server is NOT authorised by this domain"))
        score += 30
    elif "spf=softfail" in combined:
        findings.append(("warn", "SPF", "SPF soft-fail — server is suspicious but not definitively unauthorised"))
        score += 15
    elif "spf=neutral" in combined:
        findings.append(("info", "SPF", "SPF neutral — domain has no SPF policy defined"))
        score += 10
    else:
        findings.append(("warn", "SPF", "No SPF result found in headers — could not verify sender"))
        score += 10

    return findings, score


def check_dkim(msg):
    """
    DKIM (DomainKeys Identified Mail) adds a cryptographic signature.
    A pass means the email content wasn't tampered with in transit.
    """
    findings = []
    score = 0

    auth_results = msg.get("Authentication-Results", "").lower()
    dkim_sig = msg.get("DKIM-Signature", "")

    if "dkim=pass" in auth_results:
        findings.append(("pass", "DKIM", "DKIM signature valid — email content not tampered with"))
    elif "dkim=fail" in auth_results:
        findings.append(("fail", "DKIM", "DKIM FAILED — email may have been modified in transit"))
        score += 25
    elif dkim_sig:
        findings.append(("info", "DKIM", "DKIM signature present but result not confirmed in headers"))
        score += 5
    else:
        findings.append(("warn", "DKIM", "No DKIM signature found — email authenticity unverified"))
        score += 15

    return findings, score


def check_dmarc(msg):
    """
    DMARC (Domain-based Message Authentication, Reporting & Conformance)
    ties SPF and DKIM together and tells receivers what to do on failure.
    """
    findings = []
    score = 0

    auth_results = msg.get("Authentication-Results", "").lower()

    if "dmarc=pass" in auth_results:
        findings.append(("pass", "DMARC", "DMARC passed — domain authentication policy satisfied"))
    elif "dmarc=fail" in auth_results:
        findings.append(("fail", "DMARC", "DMARC FAILED — email violates domain authentication policy"))
        score += 30
    elif "dmarc=bestguesspass" in auth_results:
        findings.append(("warn", "DMARC", "DMARC best-guess pass — domain has no strict policy"))
        score += 10
    else:
        findings.append(("warn", "DMARC", "No DMARC result found — domain may lack policy"))
        score += 10

    return findings, score


def check_from_reply_to_mismatch(msg):
    """
    Phishers often set Reply-To to a different domain than From.
    When victim replies, response goes to the attacker.
    """
    findings = []
    score = 0

    from_addr = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))

    from_domain = extract_domain(from_addr)
    reply_domain = extract_domain(reply_to)

    if reply_to and from_domain and reply_domain:
        if from_domain != reply_domain:
            findings.append(("fail", "Reply-To",
                f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}) — classic phishing trick"))
            score += 35
        else:
            findings.append(("pass", "Reply-To", f"Reply-To matches From domain ({from_domain})"))
    else:
        findings.append(("info", "Reply-To", "No Reply-To header present"))

    return findings, score


def check_display_name_spoofing(msg):
    """
    Attacker sets display name to a trusted brand (e.g. 'PayPal Support')
    but the actual email address is from a random domain.
    """
    findings = []
    score = 0

    from_header = str(msg.get("From", ""))
    trusted_brands = [
        "paypal", "amazon", "apple", "google", "microsoft", "netflix",
        "bank", "fedex", "dhl", "irs", "support", "security", "alert",
        "noreply", "verify", "account", "admin"
    ]

    display_match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    if display_match:
        display_name = display_match.group(1).lower().strip()
        domain = extract_domain(from_header)

        for brand in trusted_brands:
            if brand in display_name:
                # Check if domain actually matches the brand
                if brand not in domain:
                    findings.append(("fail", "Display Name",
                        f"Display name contains '{brand}' but sending domain is '{domain}' — possible spoofing"))
                    score += 40
                    return findings, score

    findings.append(("pass", "Display Name", "No display name spoofing detected"))
    return findings, score


def check_received_chain(msg):
    """
    The Received headers trace the email's path. Suspicious if
    the originating IP region doesn't match the claimed sender domain.
    """
    findings = []
    score = 0

    received_headers = msg.get_all("Received") or []

    if len(received_headers) > 6:
        findings.append(("warn", "Routing",
            f"Unusually long routing chain ({len(received_headers)} hops) — may indicate relay abuse"))
        score += 10
    elif received_headers:
        findings.append(("info", "Routing",
            f"Email passed through {len(received_headers)} mail server(s)"))

    # Look for suspicious keywords in routing
    chain_text = " ".join(received_headers).lower()
    if any(kw in chain_text for kw in ["localhost", "127.0.0.1", "unknown"]):
        findings.append(("warn", "Routing", "Received chain contains 'unknown' or localhost — suspicious origin"))
        score += 15

    return findings, score


def analyze_headers(raw_email):
    """Run all header checks and return combined findings + score."""
    msg = parse_email(raw_email)
    if not msg:
        return [], 0, {}

    all_findings = []
    total_score = 0

    checks = [
        check_spf,
        check_dkim,
        check_dmarc,
        check_from_reply_to_mismatch,
        check_display_name_spoofing,
        check_received_chain,
    ]

    for check in checks:
        findings, score = check(msg)
        all_findings.extend(findings)
        total_score += score

    # Extract useful metadata
    meta = {
        "from": str(msg.get("From", "N/A")),
        "to": str(msg.get("To", "N/A")),
        "subject": str(msg.get("Subject", "N/A")),
        "date": str(msg.get("Date", "N/A")),
        "reply_to": str(msg.get("Reply-To", "N/A")),
        "message_id": str(msg.get("Message-ID", "N/A")),
    }

    return all_findings, min(total_score, 100), meta
