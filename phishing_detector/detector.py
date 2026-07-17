"""
detector.py
Combines header_analyzer, url_checker, and nlp_analyzer into
one unified phishing risk score with verdict and explanation.
"""

import email
from email import policy

from header_analyzer import analyze_headers
from url_checker import analyze_urls
from nlp_analyzer import analyze_text, get_phishing_summary


# ── Risk scoring ──────────────────────────────────────────────────────────────

WEIGHTS = {
    "headers": 0.35,   # 35% of final score
    "urls":    0.35,   # 35%
    "nlp":     0.30,   # 30%
}

def get_verdict(score):
    if score >= 70:
        return "PHISHING", "danger", "High likelihood of phishing. Do not click any links or provide information."
    elif score >= 40:
        return "SUSPICIOUS", "warning", "Multiple suspicious indicators. Treat with caution."
    elif score >= 15:
        return "LOW RISK", "info", "Minor indicators found. Likely safe but worth reviewing."
    else:
        return "CLEAN", "safe", "No significant phishing indicators detected."


# ── Body extraction ───────────────────────────────────────────────────────────

def extract_body(raw_email):
    """Extract plain text body from email."""
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        subject = str(msg.get("Subject", ""))

        body_parts = []
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    body_parts.append(part.get_content())
                elif ctype == "text/html":
                    # Strip HTML tags for text analysis
                    import re
                    html = part.get_content()
                    text = re.sub(r'<[^>]+>', ' ', html)
                    body_parts.append(text)
        else:
            body_parts.append(msg.get_content())

        return subject, " ".join(body_parts)
    except Exception:
        return "", raw_email  # fallback: treat whole input as body


# ── Main analysis ─────────────────────────────────────────────────────────────

def analyze_email(raw_email, vt_api_key=""):
    """
    Full pipeline: parse → header check → URL check → NLP check → score.
    Returns a complete result dict.
    """

    subject, body = extract_body(raw_email)

    # Run all three analyzers
    header_findings, header_score, meta = analyze_headers(raw_email)
    url_results, url_score = analyze_urls(body, vt_api_key)
    nlp_findings, nlp_score, category_hits = analyze_text(body, subject)

    # Weighted final score
    final_score = int(
        header_score * WEIGHTS["headers"] +
        url_score    * WEIGHTS["urls"] +
        nlp_score    * WEIGHTS["nlp"]
    )
    final_score = min(final_score, 100)

    verdict, severity, advice = get_verdict(final_score)
    phishing_summary = get_phishing_summary(category_hits)

    return {
        "score": final_score,
        "verdict": verdict,
        "severity": severity,
        "advice": advice,
        "phishing_summary": phishing_summary,
        "meta": meta,
        "header_score": header_score,
        "url_score": url_score,
        "nlp_score": nlp_score,
        "header_findings": header_findings,
        "url_results": url_results,
        "nlp_findings": nlp_findings,
        "category_hits": category_hits,
        "subject": subject,
    }
