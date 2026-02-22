"""
=============================================================
EMAIL ALERT SERVICE
=============================================================
Sends threat alert emails when risk score >= 60.

Setup (add to your .env):
    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=587
    SMTP_USER=your-gmail@gmail.com
    SMTP_PASSWORD=your-app-password   ← Gmail App Password (not your login password)
    ALERT_EMAIL=klu2300030288@outlook.com

How to get Gmail App Password:
  1. Go to myaccount.google.com
  2. Security → 2-Step Verification → App passwords
  3. Create password for "Mail"
  4. Copy 16-char password → paste in SMTP_PASSWORD

Outlook/Hotmail SMTP alternative:
    SMTP_HOST=smtp-mail.outlook.com
    SMTP_PORT=587
    SMTP_USER=klu2300030288@outlook.com
    SMTP_PASSWORD=your-outlook-password
=============================================================
"""

import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

logger = logging.getLogger(__name__)


def get_email_settings():
    from app.core.config import settings
    return {
        "host":     getattr(settings, "SMTP_HOST",     "smtp.gmail.com"),
        "port":     int(getattr(settings, "SMTP_PORT", 587)),
        "user":     getattr(settings, "SMTP_USER",     ""),
        "password": getattr(settings, "SMTP_PASSWORD", ""),
        "to":       getattr(settings, "ALERT_EMAIL",   "klu2300030288@outlook.com"),
    }


def build_email_html(enriched: dict) -> str:
    """Build a professional HTML threat alert email."""
    severity     = enriched.get("severity", "unknown").upper()
    risk_score   = enriched.get("risk_score", 0)
    raw_log      = enriched.get("raw_log", "")[:500]
    techniques   = enriched.get("mitre_techniques", [])
    iocs         = enriched.get("extracted_iocs", [])[:8]
    actions      = enriched.get("recommended_actions", [])[:5]
    db_matches   = enriched.get("db_matches", [])
    live_intel   = enriched.get("live_intel", [])[:3]
    ai_summary   = enriched.get("llm_summary", "")[:600]
    source       = enriched.get("source_system", "unknown")
    alert_id     = enriched.get("id", "N/A")[:8]
    timestamp    = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    sev_colors = {
        "CRITICAL": ("#7c3aed", "#ede9fe"),
        "HIGH":     ("#dc2626", "#fee2e2"),
        "MEDIUM":   ("#d97706", "#fef3c7"),
        "LOW":      ("#059669", "#d1fae5"),
    }
    sev_color, sev_bg = sev_colors.get(severity, ("#6b7280", "#f3f4f6"))

    ioc_rows = "".join(
        f'<tr><td style="padding:4px 8px;font-family:monospace;font-size:12px;color:#1e293b;border-bottom:1px solid #e2e8f0">{ioc[:60]}</td></tr>'
        for ioc in iocs
    )
    technique_badges = " ".join(
        f'<span style="display:inline-block;background:#ede9fe;color:#5b21b6;padding:2px 8px;border-radius:4px;font-size:11px;margin:2px;font-family:monospace">{t}</span>'
        for t in techniques
    )
    action_rows = "".join(
        f'<li style="padding:3px 0;color:#374151;font-size:13px">{a}</li>'
        for a in actions
    )
    match_rows = "".join(
        f'<tr><td style="padding:4px 8px;font-size:12px;font-family:monospace;color:#dc2626">{m.get("value","")[:40]}</td>'
        f'<td style="padding:4px 8px;font-size:12px;color:#6b7280">{m.get("ioc_type","")}</td>'
        f'<td style="padding:4px 8px;font-size:12px;font-weight:bold;color:#dc2626">{m.get("risk_score","")}/100</td>'
        f'<td style="padding:4px 8px;font-size:12px;color:#6b7280">{m.get("source","")}</td></tr>'
        for m in db_matches
    )
    live_rows = "".join(
        f'<li style="padding:2px 0;color:#0369a1;font-size:12px;font-family:monospace">{item}</li>'
        for item in live_intel
    )

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:24px 0">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)">

  <!-- Header -->
  <tr><td style="background:#0f172a;padding:20px 24px">
    <table width="100%"><tr>
      <td>
        <div style="color:#06b6d4;font-size:10px;letter-spacing:3px;font-family:monospace;margin-bottom:4px">THREAT INTEL FUSION ENGINE</div>
        <div style="color:#ffffff;font-size:20px;font-weight:bold">🚨 Threat Alert Detected</div>
      </td>
      <td align="right">
        <div style="background:{sev_color};color:#fff;padding:6px 14px;border-radius:4px;font-weight:bold;font-size:14px;letter-spacing:1px">{severity}</div>
        <div style="color:#94a3b8;font-size:11px;margin-top:4px;text-align:right">Risk: {risk_score}/100</div>
      </td>
    </tr></table>
  </td></tr>

  <!-- Risk Score Bar -->
  <tr><td style="background:{sev_bg};padding:10px 24px;border-bottom:3px solid {sev_color}">
    <table width="100%"><tr>
      <td style="color:{sev_color};font-size:12px;font-family:monospace">Alert ID: {alert_id} &nbsp;|&nbsp; Source: {source} &nbsp;|&nbsp; {timestamp}</td>
    </tr></table>
  </td></tr>

  <!-- Raw Log -->
  <tr><td style="padding:20px 24px">
    <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Raw Log</div>
    <div style="background:#0f172a;border-radius:6px;padding:12px;font-family:monospace;font-size:12px;color:#94a3b8;word-break:break-all">{raw_log}</div>
  </td></tr>

  {'<!-- DB Matches --><tr><td style="padding:0 24px 20px"><div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">⚠️ Threat Database Matches</div><table width="100%" style="border-collapse:collapse;border:1px solid #fee2e2;border-radius:6px;overflow:hidden"><tr style="background:#fee2e2"><th style="padding:6px 8px;text-align:left;font-size:11px;color:#dc2626">IOC Value</th><th style="padding:6px 8px;text-align:left;font-size:11px;color:#dc2626">Type</th><th style="padding:6px 8px;text-align:left;font-size:11px;color:#dc2626">Risk</th><th style="padding:6px 8px;text-align:left;font-size:11px;color:#dc2626">Source</th></tr>' + match_rows + '</table></td></tr>' if db_matches else ''}

  {'<!-- Live Intel --><tr><td style="padding:0 24px 20px"><div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">🌐 Live Threat Intel</div><ul style="margin:0;padding-left:16px">' + live_rows + '</ul></td></tr>' if live_intel else ''}

  <!-- Extracted IOCs -->
  {'<tr><td style="padding:0 24px 20px"><div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Extracted IOCs</div><table width="100%" style="border-collapse:collapse;background:#f8fafc;border-radius:6px;overflow:hidden">' + ioc_rows + '</table></td></tr>' if ioc_rows else ''}

  <!-- MITRE -->
  {'<tr><td style="padding:0 24px 20px"><div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">MITRE ATT&CK Techniques</div><div>' + technique_badges + '</div></td></tr>' if technique_badges else ''}

  <!-- AI Summary -->
  {'<tr><td style="padding:0 24px 20px"><div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">🤖 AI Threat Analysis</div><div style="background:#f8fafc;border-left:3px solid #06b6d4;padding:12px;font-size:13px;color:#374151;line-height:1.6;white-space:pre-wrap">' + ai_summary + '</div></td></tr>' if ai_summary else ''}

  <!-- Recommended Actions -->
  {'<tr><td style="padding:0 24px 20px"><div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">✅ Recommended Actions</div><ul style="margin:0;padding-left:16px">' + action_rows + '</ul></td></tr>' if action_rows else ''}

  <!-- Footer -->
  <tr><td style="background:#0f172a;padding:16px 24px">
    <table width="100%"><tr>
      <td style="color:#475569;font-size:11px;font-family:monospace">Threat Intel Fusion Engine &nbsp;·&nbsp; Automated Alert System</td>
      <td align="right" style="color:#475569;font-size:11px">Risk threshold: ≥60 triggers this email</td>
    </tr></table>
  </td></tr>

</table>
</td></tr></table>
</body>
</html>
"""


async def send_threat_email(enriched: dict) -> bool:
    """
    Send threat alert email if risk score >= 60.
    Returns True if sent successfully, False otherwise.
    """
    risk_score = enriched.get("risk_score", 0)
    
    cfg = get_email_settings()
    
    # Print full debug info to terminal
    print(f"\n{'='*50}")
    print(f"EMAIL DEBUG INFO")
    print(f"{'='*50}")
    print(f"Risk Score  : {risk_score}/100")
    print(f"Threshold   : 60")
    print(f"Should send : {risk_score >= 60}")
    print(f"SMTP Host   : {cfg['host']}")
    print(f"SMTP Port   : {cfg['port']}")
    print(f"SMTP User   : {cfg['user'] or 'NOT SET'}")
    print(f"Password    : {'SET (' + str(len(cfg['password'])) + ' chars)' if cfg['password'] else 'NOT SET'}")
    print(f"Send To     : {cfg['to']}")
    print(f"{'='*50}\n")
    
    if risk_score < 60:
        print(f"⚠️  Risk {risk_score} < 60 — email NOT sent")
        logger.info(f"Risk score {risk_score} < 60 — email not sent")
        return False

    if not cfg["user"] or not cfg["password"]:
        print("❌ SMTP_USER or SMTP_PASSWORD missing in .env — email NOT sent")
        logger.warning("SMTP credentials not configured in .env — email not sent")
        return False

    severity  = enriched.get("severity", "unknown").upper()
    risk      = enriched.get("risk_score", 0)
    source    = enriched.get("source_system", "system")

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 [{severity}] Threat Alert — Risk Score {risk}/100 | {source}"
        msg["From"]    = f"Threat Intel Fusion <{cfg['user']}>"
        msg["To"]      = cfg["to"]

        # Plain text fallback
        plain = f"""
THREAT ALERT DETECTED
=====================
Severity  : {severity}
Risk Score: {risk}/100
Source    : {source}
Time      : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Raw Log:
{enriched.get('raw_log', '')[:300]}

IOCs Found: {', '.join(enriched.get('extracted_iocs', [])[:5])}
MITRE     : {', '.join(enriched.get('mitre_techniques', [])[:3])}

Actions:
{chr(10).join('- ' + a for a in enriched.get('recommended_actions', [])[:4])}

-- Threat Intel Fusion Engine (automated alert, risk >= 60)
"""
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(build_email_html(enriched), "html"))

        print(f"📧 Connecting to {cfg['host']}:{cfg['port']}...")
        
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=20) as server:
            server.set_debuglevel(0)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(cfg["user"], cfg["password"])
            server.sendmail(cfg["user"], cfg["to"], msg.as_string())

        print(f"✅ EMAIL SENT → {cfg['to']} | Risk: {risk}/100 | {severity}")
        logger.info(f"✅ Email sent → {cfg['to']} | Risk: {risk}/100 | {severity}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ AUTH FAILED: {e}")
        print("   → Check SMTP_USER and SMTP_PASSWORD in .env")
        print("   → For Outlook: use your actual login password")
        print("   → If 2FA enabled: create App Password at account.microsoft.com")
        logger.error(f"❌ SMTP auth failed: {e}")
        return False
    except smtplib.SMTPException as e:
        print(f"❌ SMTP ERROR: {e}")
        logger.error(f"❌ SMTP error: {e}")
        return False
    except Exception as e:
        print(f"❌ EMAIL FAILED: {type(e).__name__}: {e}")
        logger.error(f"❌ Email send failed: {e}")
        return False