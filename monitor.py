from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import smtplib
import socket
import ssl
import sys
import time
from urllib.parse import urlparse
import requests

# Konfigürasyon
TIMEOUT = int(os.getenv("TIMEOUT_SECONDS", "8"))
MAX_WORKERS = 15
SSL_ALERT_DAYS = 15  # SSL bitişine 15 günden az kalırsa uyar

# Gmail Bilgileri
GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
RECEIVER_EMAILS_RAW = os.getenv("RECEIVER_EMAILS", "")
RECEIVERS = [
    email.strip() for email in RECEIVER_EMAILS_RAW.split(",") if email.strip()
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


def get_ssl_days_left(hostname: str, port: int = 443):
    """SSL sertifikasının bitişine kaç gün kaldığını hesaplar."""
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(), server_hostname=hostname)
    conn.settimeout(5.0)
    try:
        conn.connect((hostname, port))
        cert = conn.getpeercert()
        conn.close()

        # 'notAfter' formatı: May 15 12:00:00 2026 GMT
        expire_date = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (expire_date - now).days
        return days_left
    except Exception:
        return None


def execute_request(url: str):
    """Tekil HTTP isteği yapar."""
    start = time.time()
    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            headers={"User-Agent": "SiteHealthMonitor/3.0 (Advanced Probes)"},
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
            "detail": f"Zaman aşımı (> {TIMEOUT}s)",
            "time": "-",
        }
    except requests.exceptions.ConnectionError:
        return {
            "ok": False,
            "url": url,
            "status": "CONNECTION_ERROR",
            "code": "-",
            "detail": "DNS / Bağlantı Hatası",
            "time": "-",
        }
    except Exception as e:
        return {
            "ok": False,
            "url": url,
            "status": "EXCEPTION",
            "code": "-",
            "detail": str(e),
            "time": "-",
        }


def check_single_site(url: str):
    """Siteyi dener; hata verirse 3 saniye sonra 2. kez dener (Yalancı alarm önleme)."""
    res = execute_request(url)

    # 1. Denemede hata çıkarsa 3 sn bekleyip çift kontrol (Retry) yap
    if not res["ok"]:
        time.sleep(3)
        retry_res = execute_request(url)
        if retry_res["ok"]:
            return {
                "health": retry_res,
                "ssl_warning": None,
                "note": "Geçici dalgalanma (2. denemede kurtardı)",
            }
        res = retry_res

    # Site HTTPS ise SSL süresini denetle
    ssl_warning = None
    if url.startswith("https://"):
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443
            days = get_ssl_days_left(hostname, port)
            if days is not None and days <= SSL_ALERT_DAYS:
                ssl_warning = {
                    "url": url,
                    "domain": hostname,
                    "days_left": days,
                }
        except Exception:
            pass

    return {"health": res, "ssl_warning": ssl_warning}


def send_email_alert(failures: list, ssl_warnings: list, total_checked: int):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD or not RECEIVERS:
        print("HATA: Gmail kimlik bilgileri eksik!")
        return

    now_utc = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M:%S UTC")

    # Çöken Siteler Tablosu
    error_section = ""
    if failures:
        rows_error = "".join(
            [
                f"""
            <tr style="border-bottom: 1px solid #fee2e2;">
                <td style="padding: 10px; font-weight: bold;"><a href="{item['url']}" style="color: #2563eb; text-decoration: none;">{item['url']}</a></td>
                <td style="padding: 10px; color: #dc2626; font-weight: bold;">{item['code']}</td>
                <td style="padding: 10px; color: #4b5563;">{item['detail']}</td>
                <td style="padding: 10px; color: #6b7280;">{item['time']}s</td>
            </tr>
        """
                for item in failures
            ]
        )

        error_section = f"""
        <h3 style="color: #dc2626; margin-top: 25px; margin-bottom: 10px;">🔴 Kesinti Yaşayan Siteler ({len(failures)})</h3>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px; background: #fff; border-radius: 6px; overflow: hidden; border: 1px solid #fca5a5;">
            <thead>
                <tr style="background-color: #fee2e2; color: #991b1b; text-align: left;">
                    <th style="padding: 10px;">URL</th>
                    <th style="padding: 10px;">Durum Kodu</th>
                    <th style="padding: 10px;">Hata Sebebi</th>
                    <th style="padding: 10px;">Süre</th>
                </tr>
            </thead>
            <tbody>{rows_error}</tbody>
        </table>
        """

    # Süresi Yaklaşan SSL Sertifikaları Tablosu
    ssl_section = ""
    if ssl_warnings:
        rows_ssl = "".join(
            [
                f"""
            <tr style="border-bottom: 1px solid #fef3c7;">
                <td style="padding: 10px; font-weight: bold;"><a href="{item['url']}" style="color: #2563eb; text-decoration: none;">{item['domain']}</a></td>
                <td style="padding: 10px; color: #d97706; font-weight: bold;">{item['days_left']} gün kaldı</td>
                <td style="padding: 10px; color: #4b5563;">Sertifika yenilenmeli</td>
            </tr>
        """
                for item in ssl_warnings
            ]
        )

        ssl_section = f"""
        <h3 style="color: #d97706; margin-top: 25px; margin-bottom: 10px;">🔒 Süresi Yaklaşan SSL Sertifikaları ({len(ssl_warnings)})</h3>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px; background: #fff; border-radius: 6px; overflow: hidden; border: 1px solid #fde68a;">
            <thead>
                <tr style="background-color: #fef3c7; color: #92400e; text-align: left;">
                    <th style="padding: 10px;">Domain</th>
                    <th style="padding: 10px;">Kalan Süre</th>
                    <th style="padding: 10px;">İşlem</th>
                </tr>
            </thead>
            <tbody>{rows_ssl}</tbody>
        </table>
        """

    subject = f"🚨 İzleme Raporu: "
    if failures and ssl_warnings:
        subject += f"{len(failures)} Kesinti, {len(ssl_warnings)} SSL Uyarısı"
    elif failures:
        subject += f"{len(failures)} Sitede Kesinti Mevcut"
    else:
        subject += f"{len(ssl_warnings)} Domainde SSL Bitişi Yaklaştı"

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f3f4f6; padding: 20px; color: #1f2937;">
        <div style="max-width: 680px; margin: 0 auto; background: #ffffff; padding: 24px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
            <div style="border-bottom: 2px solid #e5e7eb; padding-bottom: 12px;">
                <h2 style="margin: 0; color: #111827;">Web Sağlık ve Güvenlik Raporu</h2>
                <p style="margin: 5px 0 0 0; font-size: 13px; color: #6b7280;">Taranan Toplam Adres: <strong>{total_checked}</strong> | Zaman: <strong>{now_utc}</strong></p>
            </div>
            
            {error_section}
            {ssl_section}
            
            <div style="margin-top: 30px; padding-top: 12px; border-top: 1px solid #e5e7eb; font-size: 11px; color: #9ca3af; text-align: center;">
                Bu rapor GitHub Actions üzerinde çalışan otomatik Uptime botu tarafından oluşturulmuştur.
            </div>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["From"] = f"Site Monitor <{GMAIL_USER}>"
    msg["To"] = ", ".join(RECEIVERS)
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, RECEIVERS, msg.as_string())
        server.quit()
        print(f"E-posta başarıyla {len(RECEIVERS)} alıcıya iletildi.")
    except Exception as e:
        print(f"E-posta gönderiminde hata: {e}")


def main():
    sites = load_sites()
    if not sites:
        print("HATA: 'sites.txt' boş veya okunamadı.")
        sys.exit(1)

    print(f"Toplam {len(sites)} site kontrol ediliyor (Eşzamanlı)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_single_site, sites))

    failures = []
    ssl_warnings = []

    for r in results:
        h = r["health"]
        if not h["ok"]:
            failures.append(h)
            print(f"❌ {h['url']} -> {h['status']} ({h['detail']})")
        else:
            print(f"✅ {h['url']} -> {h['code']} ({h['time']}s)")

        if r.get("ssl_warning"):
            ssl_warnings.append(r["ssl_warning"])
            print(
                f"🔒 SSL Uyarısı: {r['ssl_warning']['domain']} ({r['ssl_warning']['days_left']} gün kaldı)"
            )

    if failures or ssl_warnings:
        print(
            f"\nUyarılar mevcut (Hata: {len(failures)}, SSL: {len(ssl_warnings)}). E-posta gönderiliyor..."
        )
        send_email_alert(failures, ssl_warnings, len(sites))
        # Alarm durumunu GitHub arayüzünde görünür kılmak için
        sys.exit(1)
    else:
        print("\nTüm siteler sorunsuz çalışıyor ve SSL sertifikaları güncel.")


if __name__ == "__main__":
    main()