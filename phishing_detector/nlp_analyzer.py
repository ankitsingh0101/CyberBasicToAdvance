"""
nlp_analyzer.py
NLP-based phishing language detector using regex pattern matching.
Detects urgency, threats, reward bait, credential harvesting language,
impersonation phrases, and suspicious call-to-action patterns.
"""

import re
from collections import defaultdict


# ── Pattern categories ────────────────────────────────────────────────────────

PATTERNS = {
    "urgency": {
        "weight": 15,
        "patterns": [
            r'\burgent\b', r'\bimmediately\b', r'\bright away\b',
            r'\bwithin\s+\d+\s+(hours?|days?|minutes?)\b',
            r'\bexpir(e|es|ing|ed)\b', r'\bdeadline\b', r'\bexpiration\b',
            r'\bact\s+now\b', r'\bdo\s+not\s+delay\b', r'\blast\s+chance\b',
            r'\btime\s+(is\s+running\s+out|sensitive|critical)\b',
            r'\b(today|tonight|now)\s+only\b', r'\bfinal\s+notice\b',
            r'\blimited\s+time\b', r'\bno\s+time\s+to\s+waste\b',
        ]
    },
    "threat": {
        "weight": 20,
        "patterns": [
            r'\baccount\s+(will\s+be\s+)?(suspended|terminated|closed|disabled|deactivated|blocked)\b',
            r'\b(suspend|terminate|close|disable|block)\s+(your\s+)?account\b',
            r'\blegal\s+(action|proceedings?)\b',
            r'\bcriminal\s+(charges?|investigation)\b',
            r'\breport(ed)?\s+to\s+(authorities|police|irs|government)\b',
            r'\bwarrant\b', r'\barrest\b',
            r'\byour\s+(account|access|service)\s+(has\s+been|will\s+be)\b',
            r'\bunauthori[sz]ed\s+(access|activity|login|transaction)\b',
            r'\bsuspicious\s+(activity|login|access|transaction)\b',
            r'\bsecurity\s+(breach|alert|warning|violation)\b',
        ]
    },
    "reward_bait": {
        "weight": 18,
        "patterns": [
            r'\b(you\s+have\s+)?(won|win|winner)\b',
            r'\bcongratulations?\b',
            r'\bprize\b', r'\breward\b', r'\bgift\s*(card)?\b',
            r'\b(free|complimentary)\s+(iphone|ipad|gift|prize|trip|vacation)\b',
            r'\b\$\s*[\d,]+\s*(million|thousand|prize|reward|cash)\b',
            r'\bclaim\s+(your\s+)?(prize|reward|winnings?)\b',
            r'\blottery\b', r'\bjackpot\b', r'\binheritance\b',
            r'\bnigerian?\b.*\bprince\b',
            r'\bunexpected\s+(funds?|money|prize|reward)\b',
        ]
    },
    "credential_harvesting": {
        "weight": 25,
        "patterns": [
            r'\b(verify|confirm|update|validate)\s+(your\s+)?(account|identity|email|password|information|details)\b',
            r'\benter\s+(your\s+)?(password|credentials?|login|username|card\s+number)\b',
            r'\b(click|tap)\s+(here|below|the\s+link)\s+to\s+(verify|confirm|login|sign\s+in)\b',
            r'\bsign\s+in\s+to\s+(verify|confirm|restore|recover)\b',
            r'\bprovide\s+(your\s+)?(personal|account|banking|payment)\s+(information|details)\b',
            r'\bsocial\s+security\s+number\b', r'\bssn\b',
            r'\bcredit\s+card\s+(number|details|information)\b',
            r'\bbank\s+account\s+(number|details)\b',
        ]
    },
    "impersonation": {
        "weight": 20,
        "patterns": [
            r'\b(apple|google|microsoft|amazon|paypal|netflix|facebook)\s+(support|team|security|account)\b',
            r'\bapple\s+id\b', r'\bgoogle\s+account\b',
            r'\birs\b', r'\binternal\s+revenue\s+service\b',
            r'\b(your\s+)?(bank|financial\s+institution)\b.*\b(alert|notice|warning)\b',
            r'\bdear\s+(customer|user|member|valued\s+(customer|member))\b',
            r'\btech\s+support\b.*\b(call|contact|phone)\b',
            r'\bwindows\s+(support|security|team)\b',
        ]
    },
    "suspicious_cta": {
        "weight": 15,
        "patterns": [
            r'\bdo\s+not\s+(share|forward|show)\s+(this|email)\b',
            r'\bkeep\s+(this\s+)?(confidential|secret|private)\b',
            r'\bdo\s+not\s+reply\s+to\s+this\s+email\b',
            r'\bopen\s+attachment\b',
            r'\bdownload\s+(and\s+)?(run|execute|open|install)\b',
            r'\benable\s+(macros?|content|editing)\b',
            r'\bdisable\s+(antivirus|firewall|security)\b',
            r'\bbypass\s+(security|verification|check)\b',
        ]
    }
}


# ── Subject line analysis ─────────────────────────────────────────────────────

SUSPICIOUS_SUBJECT_PATTERNS = [
    (r'\b(urgent|immediate|action\s+required|important)\b', "Urgency keyword in subject"),
    (r're:\s*re:\s*re:', "Excessive Re: prefix — may fake thread history"),
    (r'\b(winner|won|prize|lottery|congratulations?)\b', "Reward bait in subject"),
    (r'\b(verify|confirm|update|suspended|locked|limited)\b', "Account action keyword in subject"),
    (r'\b(password|credentials?|login|sign.?in)\b', "Credential keyword in subject"),
    (r'[A-Z]{5,}', "ALL CAPS words — urgency manipulation"),
    (r'[!]{2,}', "Multiple exclamation marks — urgency manipulation"),
    (r'\$[\d,]+', "Dollar amount in subject — reward bait"),
]


# ── Main analyzer ─────────────────────────────────────────────────────────────

def analyze_text(body_text, subject=""):
    """
    Analyze email body and subject for phishing language patterns.
    Returns findings list and a risk score.
    """
    findings = []
    total_score = 0
    category_hits = defaultdict(list)

    body_lower = body_text.lower()

    # Analyze body by category
    for category, config in PATTERNS.items():
        weight = config["weight"]
        matched_patterns = []

        for pattern in config["patterns"]:
            matches = re.findall(pattern, body_lower, re.IGNORECASE)
            if matches:
                matched_patterns.extend(matches if isinstance(matches[0], str) else [pattern])

        if matched_patterns:
            # Deduplicate and clean
            unique = list(set(str(m).strip() for m in matched_patterns if str(m).strip()))[:4]
            category_hits[category] = unique

            category_labels = {
                "urgency": "Urgency language",
                "threat": "Threat / intimidation",
                "reward_bait": "Reward bait",
                "credential_harvesting": "Credential harvesting",
                "impersonation": "Impersonation language",
                "suspicious_cta": "Suspicious call-to-action",
            }

            label = category_labels.get(category, category)
            hit_count = len(unique)

            if hit_count >= 3:
                severity = "fail"
                score_add = weight * 2
            elif hit_count >= 1:
                severity = "warn"
                score_add = weight
            else:
                continue

            findings.append((severity, label,
                f"Found {hit_count} indicator(s): {', '.join(f'\"{x}\"' for x in unique[:3])}"))
            total_score += score_add

    # Analyze subject line
    if subject:
        subject_lower = subject.lower()
        subject_hits = []
        for pattern, description in SUSPICIOUS_SUBJECT_PATTERNS:
            if re.search(pattern, subject_lower, re.IGNORECASE):
                subject_hits.append(description)

        if subject_hits:
            findings.append(("warn", "Subject line",
                f"{len(subject_hits)} suspicious indicator(s): {'; '.join(subject_hits[:3])}"))
            total_score += len(subject_hits) * 8

    # Check reading level — phishing emails often use very simple language
    words = body_text.split()
    sentences = re.split(r'[.!?]+', body_text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 10]

    if sentences:
        avg_words_per_sentence = len(words) / max(len(sentences), 1)
        if avg_words_per_sentence < 8:
            findings.append(("info", "Readability",
                f"Very short sentences (avg {avg_words_per_sentence:.1f} words) — may indicate template phishing email"))
            total_score += 5

    # Check for personalisation — phishing often lacks it
    if not re.search(r'\b(dear\s+\w+|hi\s+\w+|hello\s+\w+)\b', body_lower):
        if len(body_text) > 100:
            findings.append(("info", "Personalisation",
                "Email uses no personal greeting — generic mass-phishing indicator"))
            total_score += 5

    return findings, min(total_score, 100), dict(category_hits)


def get_phishing_summary(category_hits):
    """Generate a human-readable summary of what type of phishing this looks like."""
    if not category_hits:
        return "No phishing language patterns detected."

    summaries = []
    if "threat" in category_hits:
        summaries.append("uses intimidation/threats to create fear")
    if "urgency" in category_hits:
        summaries.append("creates false urgency to rush the victim")
    if "credential_harvesting" in category_hits:
        summaries.append("attempts to steal login credentials")
    if "reward_bait" in category_hits:
        summaries.append("uses fake rewards to lure victims")
    if "impersonation" in category_hits:
        summaries.append("impersonates a trusted brand or authority")
    if "suspicious_cta" in category_hits:
        summaries.append("uses suspicious calls-to-action")

    if summaries:
        return "This email " + ", ".join(summaries) + "."
    return "Suspicious language patterns detected."
