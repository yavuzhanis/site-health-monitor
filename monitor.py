import json
import os
import smtplib
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse
import requests

TIMEOUT = int(os.getenv("TIMEOUT_SECONDS", "8"))
MAX_WORKERS = 15
STATE_FILE = "state.json"

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
RECEIVER_EMAILS_RAW = os.getenv("RECEIVER_EMAILS", "")
RECEIVERS = [
    email.strip() for email in RECEIVER_EMAILS_RAW.split(",") if email.strip()
]

DANGER_KEYWORDS = [
    "database connection error",
    "sqlstate[",
    "fatal error:",
    "uncaught exception",
    "error establishing a database connection",
    "access denied for user",
    "whitelabel error page",
]


def load_sites():
    if os.path.exists("sites.txt"):
        with open("sites.txt", "r", encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
    return []


def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def diagnose_error(status_type, code, detail):
    if status_type == "CONNECTION_ERROR":
        return (
            "DNS / Bağlantı Hatası",
            "Domain A/CNAME kaydı eksik veya sunucu kapalı.",
        )
    elif status_type == "TIMEOUT":
        return (
            "Zaman Aşımı",
            f"Sunucu {TIMEOUT}s içinde yanıt vermedi. Aşırı yüklenme olabilir.",
        )
    elif status_type == "BODY_ERROR":
        return "Backend / Veritabanı Hatası", f"Sayfa içinde hata tespit edildi: {detail}"
    elif code == 403:
        return (
            "403 Forbidden",
            "WAF / Bot koruması isteği engelledi veya yetki kısıtlaması var.",
        )
    elif code == 404:
        return "404 Not Found", "Hedef sayfa veya route bulunamadı."
    elif code == 500:
        return "500 Sunucu Hatası", "Backend tarafında yakalanmamış kritik hata."
    elif code in [502, 503]:
        return (
            f"{code} Servis Dışı",
            "PHP-FPM veya upstream sunucu yanıt vermiyor.",
        )
    return f"HTTP {code}", detail


def execute_request(url: str):
    start = time.time()
    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Universal-Health-Check/4.0"
            },
        )
        elapsed = round(time.time() - start, 2)

        if response.status_code >= 400:
            return {
                "ok": False,
                "url": url,
                "status": "HTTP_ERROR",
                "code": response.status_code,
                "detail": response.reason,
                "time": elapsed,
            }

        # İçerik Hata Taraması
        body_sample = response.text[:20000].lower()
        for kw in DANGER_KEYWORDS:
            if kw in body_sample:
                return {
                    "ok": False,
                    "url": url,
                    "status": "BODY_ERROR",
                    "code": response.status_code,
                    "detail": kw,
                    "time": elapsed,
                }

        return {
            "ok": True,
            "url": url,
            "status": "OK",
            "code": response.status_code,
            "time": elapsed,
        }

    except requests.exceptions.Timeout:
        return {
            "ok": False,
            "url": url,
            "status": "TIMEOUT",
            "code": "-",
            "detail": f">{TIMEOUT}s",
            "time": "-",
        }
    except requests.exceptions.ConnectionError:
        return {
            "ok": False,
            "url": url,
            "status": "CONNECTION_ERROR",
            "code": "-",
            "detail": "DNS Hatası",
            "time": "-",
        }
    except Exception as e:
        return {
            "ok": False,
            "url": url,
            "status": "EXCEPTION",
            "code": "-",
            "detail": str(e)[:30],
            "time": "-",
        }


def check_single_site(url: str):
    res = execute_request(url)
    if not res["ok"]:
        time.sleep(3)
        retry_res = execute_request(url)
        if retry_res["ok"]:
            return retry_res
        res = retry_res
    return res


def send_email_alert(subject, html_content):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD or not RECEIVERS:
        print(
            "Bilgi: E-posta secrets tanımlanmamış, mail gönderimi atlanıyor."
        )
        return

    msg = MIMEMultipart("alternative")
    msg["From"] = f"Uptime Monitör <{GMAIL_USER}>"
    msg["To"] = ", ".join(RECEIVERS)
    msg["Subject"] = subject
    msg.attach(MIMEText(html_content, "html"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, RECEIVERS, msg.as_string())
        server.quit()
        print(f"E-posta başarıyla iletildi -> {', '.join(RECEIVERS)}")
    except Exception as e:
        print(f"E-posta hatası: {e}")


def generate_dashboard(results, now_tr, uptime_rate):
    """GitHub Pages için statik dashboard oluşturur."""
    os.makedirs("public", exist_ok=True)

    rows = ""
    for r in sorted(results, key=lambda x: x["ok"]):
        badge = (
            '<span class="badge up">AKTİF</span>'
            if r["ok"]
            else '<span class="badge down">KESİNTİ</span>'
        )
        code_view = (
            f"<code>HTTP {r['code']}</code>"
            if r["code"] != "-"
            else f"<code>{r['status']}</code>"
        )
        time_view = f"{r['time']}s" if r["time"] != "-" else "-"
        detail_view = r.get("detail", "-") if not r["ok"] else "Sorunsuz"

        rows += f"""
        <tr>
            <td><strong><a href="{r['url']}" target="_blank">{r['url']}</a></strong></td>
            <td>{badge}</td>
            <td>{code_view}</td>
            <td>{time_view}</td>
            <td class="text-muted">{detail_view}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistem Durum Paneli</title>
    <style>
        :root {{ --primary: #0f172a; --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0; --success: #16a34a; --danger: #dc2626; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); margin: 0; padding: 24px 16px; color: #1e293b; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{ background: var(--primary); color: white; padding: 28px; border-radius: 12px; margin-bottom: 24px; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .header p {{ margin: 8px 0 0 0; color: #94a3b8; font-size: 14px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .card {{ background: var(--card); padding: 20px; border-radius: 12px; border: 1px solid var(--border); text-align: center; }}
        .card .title {{ font-size: 12px; font-weight: bold; color: #64748b; text-transform: uppercase; }}
        .card .value {{ font-size: 26px; font-weight: bold; margin-top: 6px; color: var(--primary); }}
        .table-card {{ background: var(--card); border-radius: 12px; border: 1px solid var(--border); overflow: hidden; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }}
        th {{ background: #f1f5f9; padding: 14px 16px; font-weight: 600; color: #475569; border-bottom: 1px solid var(--border); }}
        td {{ padding: 14px 16px; border-bottom: 1px solid var(--border); }}
        tr:last-child td {{ border-bottom: none; }}
        a {{ color: #2563eb; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .badge {{ padding: 4px 10px; border-radius: 99px; font-size: 11px; font-weight: bold; }}
        .badge.up {{ background: #dcfce7; color: #166534; }}
        .badge.down {{ background: #fee2e2; color: #991b1b; }}
        .text-muted {{ color: #64748b; font-size: 13px; }}
        code {{ background: #f1f5f9; padding: 3px 6px; border-radius: 4px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 Canlı Web Sağlık Durumu</h1>
            <p>Son Güncelleme: {now_tr}</p>
        </div>
        <div class="grid">
            <div class="card"><div class="title">Toplam Adres</div><div class="value">{len(results)}</div></div>
            <div class="card"><div class="title">Aktif Siteler</div><div class="value" style="color:var(--success)">{len([r for r in results if r['ok']])}</div></div>
            <div class="card"><div class="title">Hatalı Siteler</div><div class="value" style="color:var(--danger)">{len([r for r in results if not r['ok']])}</div></div>
            <div class="card"><div class="title">Erişilebilirlik</div><div class="value">%{uptime_rate}</div></div>
        </div>
        <div class="table-card">
            <table>
                <thead>
                    <tr><th>Adres</th><th>Durum</th><th>HTTP / Yanıt</th><th>Süre</th><th>Detay</th></tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"""
    with open("public/index.html", "w", encoding="utf-8") as f:
        f.write(html)


def main():
    sites = load_sites()
    if not sites:
        print("HATA: 'sites.txt' boş veya bulunamadı.")
        sys.exit(1)

    previous_state = load_state()
    current_state = {}

    print(f"Toplam {len(sites)} adres denetleniyor...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_single_site, sites))

    tz_tr = timezone(timedelta(hours=3))
    now_tr = datetime.now(tz_tr).strftime("%d.%m.%Y %H:%M:%S (TSİ)")

    new_failures = []
    recovered_sites = []
    current_failures = []

    for r in results:
        url = r["url"]
        is_ok = r["ok"]
        current_state[url] = is_ok

        was_ok = previous_state.get(url, True)

        if not is_ok:
            current_failures.append(r)
            if was_ok:  # Daha önce çalışıyordu, şimdi çöktü
                new_failures.append(r)
        else:
            if not was_ok:  # Daha önce çökmüştü, şimdi düzeldi
                recovered_sites.append(r)

    save_state(current_state)

    uptime_rate = round(
        ((len(sites) - len(current_failures)) / len(sites)) * 100, 1
    )

    # 1. GitHub Pages Paneli Oluştur
    generate_dashboard(results, now_tr, uptime_rate)

    # 2. Akıllı Bildirim Yönetimi
    if new_failures:
        table_rows = "".join(
            [
                f"""
            <tr style="border-bottom:1px solid #fee2e2;">
                <td style="padding:10px;"><a href="{item['url']}">{item['url']}</a></td>
                <td style="padding:10px; color:#dc2626; font-weight:bold;">{item['code']}</td>
                <td style="padding:10px;">{diagnose_error(item['status'], item['code'], item['detail'])[0]}</td>
            </tr>
        """
                for item in new_failures
            ]
        )

        email_html = f"""
        <div style="font-family:sans-serif; max-width:650px; margin:auto; background:#fff; padding:24px; border:1px solid #fee2e2; border-radius:10px;">
            <h2 style="color:#dc2626; margin-top:0;">🚨 Yeni Kesinti Algılandı</h2>
            <p>Aşağıdaki <strong>{len(new_failures)}</strong> site az önce yanıt vermeyi kesti:</p>
            <table style="width:100%; border-collapse:collapse; font-size:13px; text-align:left;">
                <tr style="background:#fee2e2; color:#991b1b;"><th style="padding:8px;">URL</th><th style="padding:8px;">Kod</th><th style="padding:8px;">Teşhis</th></tr>
                {table_rows}
            </table>
            <p style="font-size:12px; color:#6b7280; margin-top:20px;">Tarih: {now_tr}</p>
        </div>
        """
        send_email_alert(
            f"🚨 [DİKKAT] {len(new_failures)} Site Az Önce Çöktü!", email_html
        )

    elif recovered_sites:
        table_rows = "".join(
            [
                f"""
            <tr style="border-bottom:1px solid #dcfce7;">
                <td style="padding:10px;"><a href="{item['url']}">{item['url']}</a></td>
                <td style="padding:10px; color:#16a34a; font-weight:bold;">HTTP 200</td>
                <td style="padding:10px; color:#166534;">Yeniden Aktif ({item['time']}s)</td>
            </tr>
        """
                for item in recovered_sites
            ]
        )

        email_html = f"""
        <div style="font-family:sans-serif; max-width:650px; margin:auto; background:#fff; padding:24px; border:1px solid #bbf7d0; border-radius:10px;">
            <h2 style="color:#16a34a; margin-top:0;">🟢 Siteler Yeniden Erişilebilir</h2>
            <p>Daha önce çöken <strong>{len(recovered_sites)}</strong> site yeniden ayağa kalktı:</p>
            <table style="width:100%; border-collapse:collapse; font-size:13px; text-align:left;">
                <tr style="background:#dcfce7; color:#166534;"><th style="padding:8px;">URL</th><th style="padding:8px;">Durum</th><th style="padding:8px;">Yanıt Süresi</th></tr>
                {table_rows}
            </table>
            <p style="font-size:12px; color:#6b7280; margin-top:20px;">Tarih: {now_tr}</p>
        </div>
        """
        send_email_alert(
            f"🟢 [ÇÖZÜLDÜ] {len(recovered_sites)} Site Tekrar Yayında",
            email_html,
        )

    else:
        print("Durum değişikliği yok (Yeni çökme veya düzelme gerçekleşmedi).")


if __name__ == "__main__":
    main()