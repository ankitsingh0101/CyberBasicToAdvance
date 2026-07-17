"""
app.py
Flask web UI for the phishing email detector.
Run: python app.py
Then open: http://localhost:5000
"""

import os
import sys
from flask import Flask, render_template_string, request, jsonify

sys.path.insert(0, os.path.dirname(__file__))
from detector import analyze_email

app = Flask(__name__)

# ── HTML Template ─────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Phishing Email Detector</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #0f172a; color: #e2e8f0; min-height: 100vh; padding: 2rem 1rem; }
    .container { max-width: 900px; margin: 0 auto; }
    h1 { font-size: 24px; font-weight: 700; color: #f1f5f9; margin-bottom: 4px; }
    .subtitle { color: #64748b; font-size: 14px; margin-bottom: 2rem; }

    .input-card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }
    label { font-size: 13px; color: #94a3b8; display: block; margin-bottom: 6px; }
    textarea { width: 100%; background: #0f172a; border: 1px solid #334155; border-radius: 8px;
               color: #e2e8f0; font-family: 'Courier New', monospace; font-size: 13px;
               padding: 12px; resize: vertical; min-height: 200px; outline: none; }
    textarea:focus { border-color: #3b82f6; }
    input[type=text] { width: 100%; background: #0f172a; border: 1px solid #334155; border-radius: 8px;
                       color: #e2e8f0; font-size: 13px; padding: 10px 12px; outline: none; margin-bottom: 1rem; }
    input[type=text]:focus { border-color: #3b82f6; }
    .row { display: flex; gap: 12px; align-items: flex-end; margin-top: 1rem; }
    button { background: #3b82f6; color: white; border: none; border-radius: 8px;
             padding: 10px 24px; font-size: 14px; font-weight: 500; cursor: pointer; }
    button:hover { background: #2563eb; }
    button:disabled { background: #334155; cursor: not-allowed; }
    .sample-btn { background: #1e293b; border: 1px solid #334155; color: #94a3b8; font-size: 12px; padding: 6px 12px; }
    .sample-btn:hover { background: #334155; color: #e2e8f0; }

    #results { display: none; }
    .verdict-box { border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }
    .verdict-danger  { background: #450a0a; border: 1px solid #dc2626; }
    .verdict-warning { background: #431407; border: 1px solid #d97706; }
    .verdict-info    { background: #0c1a3b; border: 1px solid #3b82f6; }
    .verdict-safe    { background: #052e16; border: 1px solid #16a34a; }
    .verdict-label { font-size: 22px; font-weight: 700; margin-bottom: 4px; }
    .verdict-danger  .verdict-label { color: #f87171; }
    .verdict-warning .verdict-label { color: #fbbf24; }
    .verdict-info    .verdict-label { color: #60a5fa; }
    .verdict-safe    .verdict-label { color: #4ade80; }
    .verdict-advice { font-size: 13px; color: #94a3b8; margin-bottom: 10px; }
    .verdict-summary { font-size: 13px; color: #cbd5e1; font-style: italic; }

    .score-bar-wrap { display: flex; align-items: center; gap: 10px; margin: 6px 0; }
    .score-bar-track { flex: 1; height: 8px; background: #1e293b; border-radius: 4px; overflow: hidden; }
    .score-bar-fill { height: 100%; border-radius: 4px; transition: width 0.6s; }
    .score-label { font-size: 12px; color: #64748b; width: 70px; }
    .score-value { font-size: 12px; color: #94a3b8; width: 45px; text-align: right; }

    .section { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 1.25rem; margin-bottom: 1rem; }
    .section-title { font-size: 13px; font-weight: 600; color: #94a3b8; text-transform: uppercase;
                     letter-spacing: 0.05em; margin-bottom: 12px; }
    .finding { display: flex; gap: 8px; padding: 6px 0; border-bottom: 1px solid #0f172a; font-size: 13px; }
    .finding:last-child { border-bottom: none; }
    .finding-icon { width: 18px; text-align: center; flex-shrink: 0; margin-top: 1px; }
    .finding-label { font-weight: 500; color: #cbd5e1; min-width: 120px; }
    .finding-detail { color: #64748b; }
    .f-fail { color: #f87171; }
    .f-warn { color: #fbbf24; }
    .f-pass { color: #4ade80; }
    .f-info { color: #60a5fa; }

    .url-block { background: #0f172a; border-radius: 8px; padding: 10px 12px; margin-bottom: 8px; }
    .url-domain { font-family: monospace; font-size: 12px; color: #94a3b8; word-break: break-all; margin-bottom: 6px; }
    .url-score-pill { font-size: 11px; padding: 2px 8px; border-radius: 4px; margin-left: 8px; }
    .meta-grid { display: grid; grid-template-columns: 110px 1fr; gap: 4px 12px; font-size: 13px; }
    .meta-key { color: #64748b; }
    .meta-val { color: #cbd5e1; word-break: break-all; }

    .spinner { display: none; width: 18px; height: 18px; border: 2px solid #334155;
               border-top-color: #3b82f6; border-radius: 50%; animation: spin 0.7s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
<div class="container">
  <h1>🎣 Phishing Email Detector</h1>
  <p class="subtitle">Paste a raw email below — checks headers, URLs, and language patterns</p>

  <div class="input-card">
    <label>Raw email (paste full email including headers, or just the body)</label>
    <textarea id="emailInput" placeholder="Paste your email here...&#10;&#10;From: support@paypa1.com&#10;To: you@email.com&#10;Subject: URGENT: Your account has been suspended!&#10;&#10;Dear Customer,&#10;Your account has been suspended. Click here to verify immediately..."></textarea>

    <label style="margin-top:1rem;">VirusTotal API Key <span style="color:#475569;">(optional — free at virustotal.com)</span></label>
    <input type="text" id="vtKey" placeholder="Enter your VirusTotal API key for URL scanning..."/>

    <div class="row">
      <button onclick="analyze()" id="analyzeBtn">Analyze Email</button>
      <div class="spinner" id="spinner"></div>
      <button class="sample-btn" onclick="loadSample('phishing')">Load phishing sample</button>
      <button class="sample-btn" onclick="loadSample('legit')">Load legit sample</button>
    </div>
  </div>

  <div id="results"></div>
</div>

<script>
const SAMPLES = {
  phishing: `From: "PayPal Security" <security@paypa1-alert.com>
To: victim@email.com
Subject: URGENT: Your PayPal account has been suspended!
Date: Mon, 29 May 2026 09:00:00 +0000
Reply-To: collect@evil-domain.tk
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail

Dear Customer,

URGENT ACTION REQUIRED! Your PayPal account has been suspended due to suspicious activity detected on your account.

You must verify your identity immediately within 24 hours or your account will be permanently terminated and legal action may be initiated.

Click here to verify your account now: http://paypal-secure-verify.xyz/login?ref=suspended

Please provide your:
- Username and password
- Credit card number and CVV
- Social Security Number for identity verification

If you do not confirm your account details within 24 hours, we will be forced to permanently close your account and report your activity to the authorities.

Do not share this email with anyone. Keep this confidential.

PayPal Security Team`,

  legit: `From: "GitHub" <noreply@github.com>
To: developer@example.com
Subject: [GitHub] Your repository was starred
Date: Mon, 29 May 2026 10:00:00 +0000
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
DKIM-Signature: v=1; a=rsa-sha256; d=github.com; s=pf2014;

Hi developer,

Someone starred your repository awesome-project.

You can view the repository here: https://github.com/developer/awesome-project

You can disable these notifications in your notification settings:
https://github.com/settings/notifications

Thanks,
The GitHub Team`
};

function loadSample(type) {
  document.getElementById('emailInput').value = SAMPLES[type];
}

async function analyze() {
  const emailText = document.getElementById('emailInput').value.trim();
  const vtKey = document.getElementById('vtKey').value.trim();

  if (!emailText) { alert('Please paste an email first.'); return; }

  const btn = document.getElementById('analyzeBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'block';
  document.getElementById('results').style.display = 'none';

  try {
    const resp = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: emailText, vt_key: vtKey })
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    alert('Error analyzing email: ' + e.message);
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function scoreColor(s) {
  if (s >= 70) return '#ef4444';
  if (s >= 40) return '#f59e0b';
  if (s >= 15) return '#3b82f6';
  return '#22c55e';
}

function fIcon(sev) {
  return {fail:'✗', warn:'⚠', pass:'✓', info:'ℹ'}[sev] || '•';
}

function renderResults(r) {
  const verdictClass = {PHISHING:'danger', SUSPICIOUS:'warning', 'LOW RISK':'info', CLEAN:'safe'}[r.verdict] || 'info';

  let html = `
  <div class="verdict-box verdict-${verdictClass}">
    <div class="verdict-label">${r.verdict} — ${r.score}/100</div>
    <div class="verdict-advice">${r.advice}</div>
    ${r.phishing_summary && r.phishing_summary !== 'No phishing language patterns detected.' ? `<div class="verdict-summary">${r.phishing_summary}</div>` : ''}
  </div>

  <div class="section">
    <div class="section-title">Score breakdown</div>
    ${['Headers','URLs','Language'].map((label, i) => {
      const s = [r.header_score, r.url_score, r.nlp_score][i];
      return `<div class="score-bar-wrap">
        <div class="score-label">${label}</div>
        <div class="score-bar-track"><div class="score-bar-fill" style="width:${s}%; background:${scoreColor(s)}"></div></div>
        <div class="score-value">${s}/100</div>
      </div>`;
    }).join('')}
  </div>`;

  // Metadata
  if (r.meta) {
    const metaEntries = Object.entries(r.meta).filter(([k,v]) => v && v !== 'N/A');
    if (metaEntries.length) {
      html += `<div class="section"><div class="section-title">Email metadata</div><div class="meta-grid">`;
      metaEntries.forEach(([k,v]) => {
        html += `<div class="meta-key">${k.replace(/_/g,' ')}</div><div class="meta-val">${v.substring(0,120)}</div>`;
      });
      html += `</div></div>`;
    }
  }

  // Header findings
  html += `<div class="section"><div class="section-title">Header analysis (${r.header_score}/100)</div>`;
  r.header_findings.forEach(([sev, label, detail]) => {
    html += `<div class="finding"><div class="finding-icon f-${sev}">${fIcon(sev)}</div>
      <div class="finding-label">${label}</div><div class="finding-detail">${detail}</div></div>`;
  });
  html += `</div>`;

  // URL findings
  html += `<div class="section"><div class="section-title">URL analysis (${r.url_score}/100)</div>`;
  if (r.url_results && r.url_results.length) {
    r.url_results.forEach(u => {
      const pc = scoreColor(u.score);
      html += `<div class="url-block">
        <div class="url-domain">${u.defanged} <span class="url-score-pill" style="background:${pc}22;color:${pc}">${u.score}/100</span></div>`;
      u.findings.forEach(([sev, msg]) => {
        html += `<div class="finding" style="padding:3px 0;border:none">
          <div class="finding-icon f-${sev}">${fIcon(sev)}</div>
          <div class="finding-detail">${msg}</div></div>`;
      });
      html += `</div>`;
    });
  } else {
    html += `<div style="color:#64748b;font-size:13px;">No URLs found in email body</div>`;
  }
  html += `</div>`;

  // NLP findings
  html += `<div class="section"><div class="section-title">Language analysis (${r.nlp_score}/100)</div>`;
  if (r.nlp_findings && r.nlp_findings.length) {
    r.nlp_findings.forEach(([sev, label, detail]) => {
      html += `<div class="finding"><div class="finding-icon f-${sev}">${fIcon(sev)}</div>
        <div class="finding-label">${label}</div><div class="finding-detail">${detail}</div></div>`;
    });
  } else {
    html += `<div class="finding"><div class="finding-icon f-pass">✓</div>
      <div class="finding-label">Clean</div><div class="finding-detail">No suspicious language detected</div></div>`;
  }
  html += `</div>`;

  const resultsDiv = document.getElementById('results');
  resultsDiv.innerHTML = html;
  resultsDiv.style.display = 'block';
  resultsDiv.scrollIntoView({ behavior: 'smooth' });
}
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    raw_email = data.get("email", "")
    vt_key = data.get("vt_key", "")

    if not raw_email.strip():
        return jsonify({"error": "No email provided"}), 400

    result = analyze_email(raw_email, vt_api_key=vt_key)

    # Ensure JSON-serializable
    return jsonify({
        "score": result["score"],
        "verdict": result["verdict"],
        "severity": result["severity"],
        "advice": result["advice"],
        "phishing_summary": result["phishing_summary"],
        "meta": result["meta"],
        "header_score": result["header_score"],
        "url_score": result["url_score"],
        "nlp_score": result["nlp_score"],
        "header_findings": result["header_findings"],
        "url_results": [
            {
                "url": u["url"],
                "defanged": u["defanged"],
                "domain": u["domain"],
                "score": u["score"],
                "findings": u["findings"],
            }
            for u in result["url_results"]
        ],
        "nlp_findings": result["nlp_findings"],
    })


if __name__ == "__main__":
    print("\n  Phishing Email Detector — Web UI")
    print("  Open: http://localhost:5000\n")
    app.run(debug=True, port=5000)
