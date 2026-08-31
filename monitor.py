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
MAX_WORKERS = 25  # 160 site için eşzamanlı iş parçacığı artırıldı
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
        sites = []
        with open("sites.txt", "r", encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith("#"):
                    continue
                if not url.startswith("http://") and not url.startswith(
                    "https://"
                ):
                    url = f"https://{url}"
                sites.append(url)
        return sites
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
        return "DNS / Bağlantı Hatası", "Alan adı kaydı eksik veya sunucu kapalı."
    elif status_type == "TIMEOUT":
        return "Zaman Aşımı", f"Sunucu {TIMEOUT}s içinde yanıt vermedi."
    elif status_type == "BODY_ERROR":
        return "Backend / DB Hatası", f"Sayfa içi hata: {detail}"
    elif code == 403:
        return "403 Forbidden", "WAF engeli veya dizin yetki kısıtı."
    elif code == 404:
        return "404 Not Found", "Sayfa bulunamadı."
    elif code == 500:
        return "500 Sunucu Hatası", "Uygulama tarafında kritik hata."
    elif code in [502, 503]:
        return (
            f"{code} Servis Dışı",
            "PHP-FPM veya web sunucusu yanıt vermiyor.",
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


def send_mail(subject: str, html_body: str):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD or not RECEIVERS:
        print("Uyarı: Mail kimlik bilgileri tanımlı değil.")
        return

    msg = MIMEMultipart("alternative")
    msg["From"] = f"Uptime Monitör <{GMAIL_USER}>"
    msg["To"] = ", ".join(RECEIVERS)
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, RECEIVERS, msg.as_string())
        server.quit()
        print(f"E-posta başarıyla iletildi -> {', '.join(RECEIVERS)}")
    except Exception as e:
        print(f"E-posta gönderim hatası: {e}")


def build_email_template(
    title: str,
    subtitle: str,
    table_items: list,
    now_tr: str,
    uptime_rate: float,
    total_checked: int,
    total_failures: int,
):
    failure_rows = ""
    if table_items:
        for item in table_items:
            diag_title, diag_desc = diagnose_error(
                item["status"], item["code"], item.get("detail", "-")
            )
            code_badge = (
                f'<span style="background:#fee2e2; color:#b91c1c; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:12px;">{item["code"]}</span>'
                if item["code"] != "-"
                else '<span style="background:#f3f4f6; color:#4b5563; padding:3px 8px; border-radius:4px; font-size:12px;">-</span>'
            )
            failure_rows += f"""
            <tr style="border-bottom: 1px solid #edf2f7;">
                <td style="padding: 10px; font-weight:600;"><a href="{item['url']}" style="color:#2563eb; text-decoration:none;">{item['url']}</a></td>
                <td style="padding: 10px;">{code_badge}</td>
                <td style="padding: 10px; font-size:12px; color:#475569;"><strong>{diag_title}</strong><br>{diag_desc}</td>
            </tr>
            """
        table_section = f"""
        <h3 style="color:#dc2626; margin: 20px 0 10px 0; font-size:15px;">Listelenen Siteler ({len(table_items)})</h3>
        <table style="width:100%; border-collapse:collapse; font-size:13px; text-align:left; border:1px solid #fee2e2;">
            <tr style="background:#fee2e2; color:#991b1b;"><th style="padding:8px 10px;">URL</th><th style="padding:8px 10px;">Kod</th><th style="padding:8px 10px;">Teşhis</th></tr>
            {failure_rows}
        </table>
        """
    else:
        table_section = """
        <div style="background:#f0fdf4; border:1px solid #bbf7d0; color:#166534; padding:16px; border-radius:8px; text-align:center; margin: 20px 0; font-weight:600;">
            🎉 Harika! Tüm siteler eksiksiz ve sorunsuz çalışıyor (%100 Sağlık).
        </div>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f8fafc; padding: 24px 12px; margin: 0;">
        <div style="max-width: 680px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; border: 1px solid #e2e8f0;">
            <div style="background: #0f172a; padding: 20px 24px; color: #ffffff;">
                <h2 style="margin: 0; font-size: 18px;">{title}</h2>
                <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 12px;">{subtitle} • Zaman: {now_tr}</p>
            </div>
            <div style="padding: 20px 24px;">
                <table style="width: 100%; border-spacing: 8px; border-collapse: separate; margin: -8px;">
                    <tr>
                        <td style="background:#f8fafc; border:1px solid #e2e8f0; padding:12px; border-radius:8px; text-align:center; width:25%;">
                            <div style="font-size:11px; color:#64748b; font-weight:bold;">TARANAN</div>
                            <div style="font-size:18px; font-weight:bold; color:#0f172a;">{total_checked}</div>
                        </td>
                        <td style="background:#f0fdf4; border:1px solid #bbf7d0; padding:12px; border-radius:8px; text-align:center; width:25%;">
                            <div style="font-size:11px; color:#166534; font-weight:bold;">AKTİF</div>
                            <div style="font-size:18px; font-weight:bold; color:#15803d;">{total_checked - total_failures}</div>
                        </td>
                        <td style="background:#fef2f2; border:1px solid #fecaca; padding:12px; border-radius:8px; text-align:center; width:25%;">
                            <div style="font-size:11px; color:#991b1b; font-weight:bold;">HATALI</div>
                            <div style="font-size:18px; font-weight:bold; color:#dc2626;">{total_failures}</div>
                        </td>
                        <td style="background:#f8fafc; border:1px solid #e2e8f0; padding:12px; border-radius:8px; text-align:center; width:25%;">
                            <div style="font-size:11px; color:#64748b; font-weight:bold;">UPTIME</div>
                            <div style="font-size:18px; font-weight:bold; color:#2563eb;">%{uptime_rate}</div>
                        </td>
                    </tr>
                </table>
                {table_section}
            </div>
            <div style="background:#f8fafc; padding:14px; text-align:center; font-size:11px; color:#64748b; border-top:1px solid #e2e8f0;">
                Otomatik Uptime Botu tarafından GitHub Actions üzerinde taranmıştır.
            </div>
        </div>
    </body>
    </html>
    """


def main():
    sites = load_sites()
    if not sites:
        print("HATA: 'sites.txt' boş veya okunamadı.")
        sys.exit(1)

    is_daily_report = os.getenv("DAILY_REPORT", "false").lower() == "true"
    previous_state = load_state()
    current_state = {}

    print(f"Toplam {len(sites)} site taranıyor...")
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
            if was_ok:
                new_failures.append(r)
        else:
            if not was_ok:
                recovered_sites.append(r)

    save_state(current_state)
    uptime_rate = round(
        ((len(sites) - len(current_failures)) / len(sites)) * 100, 1
    )

    # 1. Günlük 24 Saatlik Bülten
    if is_daily_report:
        print(f"24 saatlik bülten gönderiliyor ({len(sites)} site)...")
        subject = f"📊 Günlük Sağlık Bülteni: %{uptime_rate} Uptime ({len(current_failures)} Kesinti)"
        html = build_email_template(
            "📊 Günlük Sağlık Bülteni",
            f"Toplam {len(sites)} site tarandı",
            current_failures,
            now_tr,
            uptime_rate,
            len(sites),
            len(current_failures),
        )
        send_mail(subject, html)
        return

    # 2. Anlık Alarm (Yeni Çökme)
    if new_failures:
        print(f"Yeni kesinti tespit edildi ({len(new_failures)} site).")
        subject = f"🚨 [ACİL ALARM] {len(new_failures)} Site Az Önce Çöktü!"
        html = build_email_template(
            "🚨 Yeni Kesinti Algılandı",
            f"{len(new_failures)} yeni site yanıt vermiyor",
            new_failures,
            now_tr,
            uptime_rate,
            len(sites),
            len(current_failures),
        )
        send_mail(subject, html)
    elif recovered_sites:
        print(f"Siteler düzeldi ({len(recovered_sites)} site).")
        subject = f"🟢 [ÇÖZÜLDÜ] {len(recovered_sites)} Site Tekrar Yayında"
        html = build_email_template(
            "🟢 Siteler Yeniden Erişilebilir",
            f"{len(recovered_sites)} site ayağa kalktı",
            recovered_sites,
            now_tr,
            uptime_rate,
            len(sites),
            len(current_failures),
        )
        send_mail(subject, html)
    else:
        print(
            f"Durum değişikliği yok. Toplam {len(sites)} site kontrol edildi."
        )


if __name__ == "__main__":
    main()
