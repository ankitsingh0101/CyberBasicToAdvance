"""
Report generator — creates a clean HTML report from scan results.
"""

from datetime import datetime


def generate_html_report(target, ip, ports_scanned, results, os_hint, output_file="scan_report.html"):
    """Generate a clean, interactive HTML scan report."""

    total_open = len(results)
    high_risk = [r for r in results if r["risk"] == "high"]
    medium_risk = [r for r in results if r["risk"] == "medium"]
    low_risk = [r for r in results if r["risk"] == "low"]
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def risk_badge(risk):
        colors = {
            "high":   ("bg:#fee2e2; color:#991b1b;", "HIGH"),
            "medium": ("bg:#fef3c7; color:#92400e;", "MED"),
            "low":    ("bg:#d1fae5; color:#065f46;", "LOW"),
        }
        style, label = colors.get(risk, ("bg:#f3f4f6; color:#374151;", risk.upper()))
        return f'<span style="font-size:11px; padding:2px 8px; border-radius:4px; font-weight:500; {style}">{label}</span>'

    def rows_html():
        if not results:
            return '<tr><td colspan="6" style="text-align:center; color:#6b7280; padding:2rem;">No open ports found</td></tr>'
        rows = []
        for r in results:
            banner_td = f'<span style="font-family:monospace; font-size:12px; color:#6b7280;">{r["banner"][:80]}</span>' if r["banner"] else '<span style="color:#d1d5db;">—</span>'
            rows.append(f"""
            <tr>
              <td style="font-weight:500; font-family:monospace;">{r['port']}</td>
              <td>{r['protocol']}</td>
              <td><span style="color:#16a34a; font-weight:500;">{r['state']}</span></td>
              <td>{r['service']}</td>
              <td>{banner_td}</td>
              <td>{risk_badge(r['risk'])}</td>
            </tr>""")
        return "\n".join(rows)

    high_warning = ""
    if high_risk:
        port_list = ", ".join(str(r["port"]) for r in high_risk)
        high_warning = f"""
        <div style="border:1px solid #fca5a5; background:#fff1f2; border-radius:8px; padding:1rem 1.25rem; margin-bottom:1.5rem;">
          <p style="font-weight:500; color:#991b1b; margin:0 0 4px;">High-risk ports detected</p>
          <p style="font-size:13px; color:#b91c1c; margin:0;">
            Ports {port_list} are associated with commonly exploited services.
            Ensure these are intentionally exposed and properly secured.
          </p>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Scan Report — {target}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }}
    .container {{ max-width: 960px; margin: 2rem auto; padding: 0 1.5rem; }}
    .header {{ background: #0f172a; color: white; border-radius: 12px; padding: 2rem; margin-bottom: 1.5rem; }}
    .header h1 {{ font-size: 22px; font-weight: 600; margin-bottom: 0.5rem; }}
    .header p {{ font-size: 13px; color: #94a3b8; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 1.5rem; }}
    .stat {{ background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 1rem; }}
    .stat-label {{ font-size: 12px; color: #64748b; margin-bottom: 4px; }}
    .stat-value {{ font-size: 24px; font-weight: 600; color: #0f172a; }}
    .stat-value.danger {{ color: #dc2626; }}
    .stat-value.warn {{ color: #d97706; }}
    .stat-value.ok {{ color: #16a34a; }}
    .card {{ background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 1.25rem; margin-bottom: 1.5rem; }}
    .card h2 {{ font-size: 15px; font-weight: 600; margin-bottom: 1rem; color: #0f172a; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ text-align: left; font-size: 11px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }}
    td {{ padding: 10px 12px; border-bottom: 0.5px solid #f1f5f9; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #f8fafc; }}
    .filter-row {{ display: flex; gap: 8px; margin-bottom: 1rem; flex-wrap: wrap; }}
    .filter-btn {{ font-size: 12px; padding: 4px 12px; border-radius: 6px; border: 1px solid #e2e8f0; background: white; cursor: pointer; color: #374151; }}
    .filter-btn.active {{ background: #0f172a; color: white; border-color: #0f172a; }}
    footer {{ text-align: center; font-size: 12px; color: #94a3b8; padding: 2rem 0; }}
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Port Scan Report</h1>
    <p>Target: <strong style="color:white;">{target}</strong> ({ip}) &nbsp;|&nbsp; Scanned: {scan_time} &nbsp;|&nbsp; OS Hint: {os_hint}</p>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="stat-label">Ports scanned</div>
      <div class="stat-value">{ports_scanned:,}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Open ports</div>
      <div class="stat-value {'danger' if total_open > 10 else 'ok'}">{total_open}</div>
    </div>
    <div class="stat">
      <div class="stat-label">High risk</div>
      <div class="stat-value {'danger' if high_risk else 'ok'}">{len(high_risk)}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Medium risk</div>
      <div class="stat-value {'warn' if medium_risk else 'ok'}">{len(medium_risk)}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Low risk</div>
      <div class="stat-value ok">{len(low_risk)}</div>
    </div>
  </div>

  {high_warning}

  <div class="card">
    <h2>Open ports</h2>
    <div class="filter-row">
      <button class="filter-btn active" onclick="filterTable('all', this)">All ({total_open})</button>
      <button class="filter-btn" onclick="filterTable('high', this)">High risk ({len(high_risk)})</button>
      <button class="filter-btn" onclick="filterTable('medium', this)">Medium risk ({len(medium_risk)})</button>
      <button class="filter-btn" onclick="filterTable('low', this)">Low risk ({len(low_risk)})</button>
    </div>
    <table id="results-table">
      <thead>
        <tr>
          <th>Port</th>
          <th>Protocol</th>
          <th>State</th>
          <th>Service</th>
          <th>Banner</th>
          <th>Risk</th>
        </tr>
      </thead>
      <tbody>
        {rows_html()}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Recommendations</h2>
    <table>
      <thead><tr><th>Finding</th><th>Action</th></tr></thead>
      <tbody>
        {"<tr><td>Telnet (port 23) is open</td><td>Replace with SSH immediately — Telnet transmits passwords in plaintext</td></tr>" if any(r['port']==23 for r in results) else ""}
        {"<tr><td>FTP (port 21) is open</td><td>Use SFTP or FTPS instead — plain FTP sends credentials unencrypted</td></tr>" if any(r['port']==21 for r in results) else ""}
        {"<tr><td>RDP (port 3389) is open</td><td>Restrict access to VPN/trusted IPs only — common brute force target</td></tr>" if any(r['port']==3389 for r in results) else ""}
        {"<tr><td>Metasploit default (port 4444) is open</td><td>Investigate immediately — this port is associated with Meterpreter shells</td></tr>" if any(r['port']==4444 for r in results) else ""}
        {"<tr><td>Redis (port 6379) is open</td><td>Add authentication and bind to localhost if not needed externally</td></tr>" if any(r['port']==6379 for r in results) else ""}
        {"<tr><td>MongoDB (port 27017) is open</td><td>Enable authentication — unauthenticated MongoDB is a critical exposure</td></tr>" if any(r['port']==27017 for r in results) else ""}
        <tr><td>General advice</td><td>Close all unused ports with firewall rules. Audit all open services regularly.</td></tr>
      </tbody>
    </table>
  </div>

  <footer>Generated by Network Port Scanner &nbsp;|&nbsp; {scan_time}</footer>
</div>

<script>
  function filterTable(risk, btn) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const rows = document.querySelectorAll('#results-table tbody tr');
    rows.forEach(row => {{
      if (risk === 'all') {{ row.style.display = ''; return; }}
      const badge = row.querySelector('span');
      const text = badge ? badge.textContent.toLowerCase() : '';
      row.style.display = text.includes(risk.slice(0,3)) ? '' : 'none';
    }});
  }}
</script>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
