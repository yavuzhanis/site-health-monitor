from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import smtplib
import sys
import time
import requests

# Konfigürasyon
TIMEOUT = int(os.getenv("TIMEOUT_SECONDS", "8"))
MAX_WORKERS = 15  # 70 siteyi paralel taramak için eşzamanlı thread sayısı

# Gmail Bilgileri
GMAIL_USER = os.getenv("GMAIL_USER")  # Gönderici Gmail adresiniz
GMAIL_APP_PASSWORD = os.getenv(
    "GMAIL_APP_PASSWORD"
)  # 16 haneli Uygulama Şifresi
RECEIVER_EMAILS_RAW = os.getenv(
    "RECEIVER_EMAILS", ""
)  # Virgülle ayrılmış 2 alıcı
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


def check_single_site(url: str):
    """Tek bir siteyi denetler ve sonucu döndürür."""
    start = time.time()
    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            headers={"User-Agent": "SiteHealthMonitor/2.0 (Automated Check)"},
        )
        elapsed = round(time.time() - start, 2)

        if response.status_code >= 400:
            return {
                "url": url,
                "status": "HTTP_ERROR",
                "code": response.status_code,
                "detail": response.reason,
                "time": elapsed,
            }
        return {
            "url": url,
            "status": "OK",
            "code": response.status_code,
            "time": elapsed,
        }

    except requests.exceptions.Timeout:
        return {
            "url": url,
            "status": "TIMEOUT",
            "code": "-",
            "detail": f"Zaman aşımı (> {TIMEOUT}s)",
            "time": "-",
        }
    except requests.exceptions.ConnectionError:
        return {
            "url": url,
            "status": "CONNECTION_ERROR",
            "code": "-",
            "detail": "DNS / Bağlantı Hatası",
            "time": "-",
        }
    except Exception as e:
        return {
            "url": url,
            "status": "EXCEPTION",
            "code": "-",
            "detail": str(e),
            "time": "-",
        }


def send_email_alert(failures: list, total_checked: int):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD or not RECEIVERS:
        print("HATA: Gmail kimlik bilgileri veya alıcı adresler eksik!")
        return

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # HTML Tablo Satırları
    rows_html = ""
    for item in failures:
        rows_html += f"""
        <tr style="border-bottom: 1px solid #e0e0e0;">
            <td style="padding: 10px; font-weight: bold; color: #1a73e8;"><a href="{item['url']}">{item['url']}</a></td>
            <td style="padding: 10px; color: #d93025; font-weight: bold;">{item['code']}</td>
            <td style="padding: 10px; color: #5f6368;">{item['detail']}</td>
            <td style="padding: 10px; color: #5f6368;">{item['time']}</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px; color: #333;">
        <div style="max-width: 650px; margin: 0 auto; background: #ffffff; padding: 24px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="color: #d93025; margin-top: 0;">🚨 Site Kesintisi Uyarısı</h2>
            <p style="font-size: 14px; color: #555;">
                Yapılan saatlik denetimde toplam <strong>{total_checked}</strong> siteden 
                <span style="color: #d93025; font-weight: bold;">{len(failures)}</span> tanesinde hata tespit edildi.
            </p>
            
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; margin: 20px 0;">
                <thead>
                    <tr style="background-color: #f1f3f4;">
                        <th style="padding: 10px;">URL</th>
                        <th style="padding: 10px;">Kod</th>
                        <th style="padding: 10px;">Hata Nedeni</th>
                        <th style="padding: 10px;">Süre (s)</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
            
            <p style="font-size: 12px; color: #888; margin-bottom: 0;">
                Kontrol Zamanı: {now_utc}<br>
                Bu bildirim GitHub Actions otomatik denetleme servisi tarafından iletilmiştir.
            </p>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["From"] = f"Site Monitor <{GMAIL_USER}>"
    msg["To"] = ", ".join(RECEIVERS)
    msg["Subject"] = (
        f"🚨 [ACİL] {len(failures)} Sitede Hata Tespit Edildi ({now_utc})"
    )
    msg.attach(MIMEText(html_content, "html"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, RECEIVERS, msg.as_string())
        server.quit()
        print(f"E-posta başarıyla {len(RECEIVERS)} alıcıya gönderildi.")
    except Exception as e:
        print(f"E-posta gönderiminde kritik hata: {e}")


def main():
    sites = load_sites()
    if not sites:
        print("HATA: 'sites.txt' dosyası bulunamadı veya boş.")
        sys.exit(1)

    print(f"Toplam {len(sites)} site paralel olarak taranıyor...")

    failures = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_single_site, sites))

    for res in results:
        if res["status"] != "OK":
            failures.append(res)
            print(f"❌ {res['url']} -> {res['status']} ({res['detail']})")
        else:
            print(f"✅ {res['url']} -> {res['code']} ({res['time']}s)")

    if failures:
        print(
            f"\n{len(failures)} sitede problem var. E-posta hazırlanıyor..."
        )
        send_email_alert(failures, len(sites))
        sys.exit(1)
    else:
        print("\nTüm siteler aktif (HTTP 200).")


if __name__ == "__main__":
    main()