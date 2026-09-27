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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# SSL uyarılarını sustur
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ortam Değişkenleri & Konfigürasyon
TIMEOUT = int(os.getenv("TIMEOUT_SECONDS", "10"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "10"))
STATE_FILE = "state.json"
SSL_EXPIRY_THRESHOLD_DAYS = int(os.getenv("SSL_EXPIRY_THRESHOLD_DAYS", "14"))

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
RECEIVER_EMAILS_RAW = os.getenv("RECEIVER_EMAILS", "")
RECEIVERS = [
    email.strip() for email in RECEIVER_EMAILS_RAW.split(",") if email.strip()
]

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

STRICT_DANGER_KEYWORDS = [
    "fatal error: uncaught",
    "sqlstate[hy000]",
    "database connection error",
    "error establishing a database connection",
    "sayfa bulunamadı",
    "404 not found",
    "sunucu bulunamıyor",
]


def load_sites():
    if os.path.exists("sites.txt"):
        sites = []
        with open("sites.txt", "r", encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith("#"):
                    continue
                if not url.startswith("http://") and not url.startswith("https://"):
                    url = f"https://{url}"
                sites.append(url)
        return sorted(list(set(sites)))
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
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Uyarı: Durum dosyası yazılamadı: {e}")


def create_session():
    session = requests.Session()
    retries = Retry(
        total=2,
        backoff_factor=1,
        status_forcelist=[502, 503, 504],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retries,
        pool_connections=MAX_WORKERS,
        pool_maxsize=MAX_WORKERS,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


SESSION = create_session()


def get_ssl_expiry_days(hostname: str, port: int = 443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    return None
                expire_date_str = cert.get("notAfter")
                if expire_date_str:
                    expire_date = datetime.strptime(
                        expire_date_str, "%b %d %H:%M:%S %Y %Z"
                    )
                    return (expire_date - datetime.utcnow()).days
    except Exception:
        return None
    return None


def execute_request(url: str):
    start = time.time()
    parsed = urlparse(url)
    target_host = parsed.hostname

    if not target_host:
        return {
            "ok": False,
            "url": url,
            "status": "INVALID_URL",
            "code": "-",
            "detail": "Geçersiz URL Formatı",
            "time": "-",
        }

    # 1. DNS Çözümleme Testi
    try:
        socket.gethostbyname(target_host)
    except socket.gaierror:
        return {
            "ok": False,
            "url": url,
            "status": "DNS_NOT_FOUND",
            "code": "-",
            "detail": "Sunucu Bulunamıyor (DNS Yok)",
            "time": "-",
        }
    except Exception as e:
        return {
            "ok": False,
            "url": url,
            "status": "SOCKET_ERROR",
            "code": "-",
            "detail": f"Bağlantı Hatası: {str(e)[:25]}",
            "time": "-",
        }

    # 2. SSL Süre Kontrolü
    ssl_days = None
    if url.startswith("https://"):
        ssl_days = get_ssl_expiry_days(target_host, parsed.port or 443)

    # 3. HTTP İsteği ve Sahte 200 Denetimi
    try:
        response = SESSION.get(
            url,
            timeout=TIMEOUT,
            headers=BROWSER_HEADERS,
            allow_redirects=True,
            verify=False,
        )
        elapsed = round(time.time() - start, 2)

        # Wildcard / Sessiz Yönlendirme Analizi:
        # Eğer alt domain çöktüğü için sistem bizi ana domain portala yönlendirdiyse bunu çökme say!
        final_host = urlparse(response.url).hostname
        if final_host and final_host.lower() != target_host.lower():
            # Eğer www ekleme/çıkarma dışında farklı bir yere yönlendirildiyse
            clean_target = target_host.replace("www.", "")
            clean_final = final_host.replace("www.", "")
            if clean_target != clean_final:
                return {
                    "ok": False,
                    "url": url,
                    "status": "REDIRECT_MISMATCH",
                    "code": response.status_code,
                    "detail": f"Adres Yönlendirildi -> {final_host}",
                    "time": elapsed,
                }

        ssl_warning = ""
        if ssl_days is not None and ssl_days <= SSL_EXPIRY_THRESHOLD_DAYS:
            ssl_warning = f" (⚠️ SSL Bitiyor: {ssl_days} gün)"

        if response.status_code in [401, 403]:
            return {
                "ok": True,
                "url": url,
                "status": "PROTECTED",
                "code": response.status_code,
                "detail": f"Korumalı Alan{ssl_warning}",
                "time": elapsed,
            }

        if response.status_code >= 400:
            return {
                "ok": False,
                "url": url,
                "status": "HTTP_ERROR",
                "code": response.status_code,
                "detail": response.reason or f"HTTP {response.status_code}",
                "time": elapsed,
            }

        # Gövde Hata Metni / Soft 404 Denetimi
        body_sample = response.text[:25000].lower()
        for kw in STRICT_DANGER_KEYWORDS:
            if kw in body_sample:
                return {
                    "ok": False,
                    "url": url,
                    "status": "BODY_ERROR",
                    "code": response.status_code,
                    "detail": f"Kritik Hata / 404 ({kw})",
                    "time": elapsed,
                }

        return {
            "ok": True,
            "url": url,
            "status": "OK",
            "code": response.status_code,
            "detail": f"Sorunsuz Yanıt{ssl_warning}",
            "time": elapsed,
        }

    except requests.exceptions.SSLError:
        return {
            "ok": False,
            "url": url,
            "status": "SSL_ERROR",
            "code": "-",
            "detail": "Geçersiz / Eksik SSL Sertifikası",
            "time": "-",
        }

    except requests.exceptions.Timeout:
        return {
            "ok": False,
            "url": url,
            "status": "TIMEOUT",
            "code": "-",
            "detail": f">{TIMEOUT}s Zaman Aşımı",
            "time": "-",
        }

    except requests.exceptions.ConnectionError as ce:
        detail = "Sunucuya Bağlanılamadı"
        if "NameResolutionError" in str(ce) or "getaddrinfo failed" in str(ce):
            detail = "DNS Çözümlenemedi"
        return {
            "ok": False,
            "url": url,
            "status": "CONNECTION_ERROR",
            "code": "-",
            "detail": detail,
            "time": "-",
        }

    except Exception as e:
        return {
            "ok": False,
            "url": url,
            "status": "EXCEPTION",
            "code": "-",
            "detail": str(e)[:35],
            "time": "-",
        }


def check_single_site(url: str):
    res = execute_request(url)
    if not res["ok"]:
        time.sleep(2)
        retry_res = execute_request(url)
        if retry_res["ok"]:
            return retry_res
        res = retry_res
    return res


def send_mail(subject: str, html_body: str):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD or not RECEIVERS:
        print("Uyarı: Mail kimlik bilgileri eksik, e-posta gönderilemedi.")
        return

    msg = MIMEMultipart("alternative")
    msg["From"] = f"Kapadokya Uptime Monitor <{GMAIL_USER}>"
    msg["To"] = ", ".join(RECEIVERS)
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=15)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, RECEIVERS, msg.as_string())
        server.quit()
        print(f"E-posta başarıyla ulaştırıldı: {', '.join(RECEIVERS)}")
    except Exception as e:
        print(f"E-posta aktarım hatası: {e}")


def send_webhook_alert(subject: str, message: str):
    if WEBHOOK_URL:
        try:
            requests.post(
                WEBHOOK_URL,
                json={"content": f"**{subject}**\n{message}"},
                timeout=5,
            )
        except Exception:
            pass

    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            tg_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            requests.post(
                tg_url,
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": f"{subject}\n\n{message}",
                },
                timeout=5,
            )
        except Exception:
            pass


def render_dashboard_email(
    badge_title: str,
    badge_color: str,
    results: list,
    now_tr: str,
    uptime_rate: float,
    avg_latency: float,
):
    failures = [r for r in results if not r["ok"]]
    healthy_count = len(results) - len(failures)

    failure_cards = ""
    if failures:
        for f in failures:
            code_view = f"HTTP {f['code']}" if f["code"] != "-" else f["status"]
            failure_cards += f"""
            <table width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff; border:1px solid #fee2e2; border-left:4px solid #ef4444; border-radius:6px; margin-bottom:10px; font-family:Arial, sans-serif;">
                <tr>
                    <td style="padding:14px;">
                        <a href="{f['url']}" target="_blank" style="color:#0f172a; font-weight:bold; text-decoration:none; font-size:14px;">{f['url']}</a>
                        <div style="color:#dc2626; font-size:12px; margin-top:4px; font-weight:500;">⚠️ {f.get('detail', 'Erişim Hatası')}</div>
                    </td>
                    <td align="right" valign="top" style="padding:14px;">
                        <span style="background:#fef2f2; color:#991b1b; padding:4px 8px; border-radius:4px; font-size:11px; font-weight:bold; border:1px solid #fecaca; white-space:nowrap;">{code_view}</span>
                    </td>
                </tr>
            </table>
            """
    else:
        failure_cards = """
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:6px; margin-bottom:10px; font-family:Arial, sans-serif;">
            <tr>
                <td style="padding:18px; text-align:center; color:#15803d; font-weight:bold; font-size:14px;">
                    ✅ Harika! Taranan tüm dijital varlıklar aktif ve eksiksiz yanıt veriyor.
                </td>
            </tr>
        </table>
        """

    # "Sorunsuz çalışan siteler" bölümü tamamen temizlendi
    return f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head><meta charset="UTF-8"></head>
    <body style="margin:0; padding:20px 10px; background-color:#f1f5f9; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0" align="center" style="max-width:650px; margin:0 auto; background:#ffffff; border-radius:12px; overflow:hidden; border:1px solid #e2e8f0;">
            <tr>
                <td style="background:#0f172a; padding:24px 28px; color:#ffffff;">
                    <div style="display:inline-block; background:{badge_color}; color:#ffffff; font-size:10px; font-weight:bold; padding:4px 10px; border-radius:16px; text-transform:uppercase; margin-bottom:10px;">
                        {badge_title}
                    </div>
                    <h1 style="margin:0; font-size:20px; font-weight:bold;">Kapadokya Dijital Altyapı Denetimi</h1>
                    <p style="margin:4px 0 0 0; color:#94a3b8; font-size:12px;">Rapor Saati: {now_tr}</p>
                </td>
            </tr>
            <tr>
                <td style="padding:20px 24px; background:#f8fafc; border-bottom:1px solid #e2e8f0;">
                    <table width="100%" cellpadding="0" cellspacing="6">
                        <tr>
                            <td width="25%" align="center" style="background:#ffffff; padding:10px; border-radius:8px; border:1px solid #e2e8f0;">
                                <div style="font-size:10px; color:#64748b; font-weight:bold; text-transform:uppercase;">Erişilebilirlik</div>
                                <div style="font-size:18px; font-weight:bold; color:{'#10b981' if uptime_rate >= 90 else '#ef4444'}; margin-top:2px;">%{uptime_rate}</div>
                            </td>
                            <td width="25%" align="center" style="background:#ffffff; padding:10px; border-radius:8px; border:1px solid #e2e8f0;">
                                <div style="font-size:10px; color:#64748b; font-weight:bold; text-transform:uppercase;">Aktif</div>
                                <div style="font-size:18px; font-weight:bold; color:#10b981; margin-top:2px;">{healthy_count}</div>
                            </td>
                            <td width="25%" align="center" style="background:#ffffff; padding:10px; border-radius:8px; border:1px solid #e2e8f0;">
                                <div style="font-size:10px; color:#64748b; font-weight:bold; text-transform:uppercase;">Kesinti</div>
                                <div style="font-size:18px; font-weight:bold; color:{'#ef4444' if failures else '#64748b'}; margin-top:2px;">{len(failures)}</div>
                            </td>
                            <td width="25%" align="center" style="background:#ffffff; padding:10px; border-radius:8px; border:1px solid #e2e8f0;">
                                <div style="font-size:10px; color:#64748b; font-weight:bold; text-transform:uppercase;">Ort. Yanıt</div>
                                <div style="font-size:18px; font-weight:bold; color:#0f172a; margin-top:2px;">{avg_latency}s</div>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
            <tr>
                <td style="padding:24px 28px;">
                    <div style="font-size:14px; font-weight:bold; color:#0f172a; margin-bottom:12px;">🚨 Kesinti & İnceleme Gerektiren Siteler ({len(failures)})</div>
                    {failure_cards}
                </td>
            </tr>
            <tr>
                <td style="background:#f8fafc; padding:14px 24px; text-align:center; font-size:11px; color:#94a3b8; border-top:1px solid #e2e8f0;">
                    Kapadokya Üniversitesi Dijital Altyapı Denetim Botu
                </td>
            </tr>
        </table>
    </body>
    </html>
    """


def main():
    sites = load_sites()
    if not sites:
        print("HATA: 'sites.txt' listesi boş.")
        sys.exit(1)

    is_daily_report = os.getenv("DAILY_REPORT", "false").lower() == "true"
    previous_state = load_state()
    current_state = {}

    print(f"Toplam {len(sites)} site optimize parametrelerle denetleniyor...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_single_site, sites))

    tz_tr = timezone(timedelta(hours=3))
    now_tr = datetime.now(tz_tr).strftime("%d.%m.%Y %H:%M:%S (TSİ)")

    new_failures = []
    recovered_sites = []
    current_failures = []

    valid_latencies = [
        r["time"] for r in results if isinstance(r["time"], (int, float))
    ]
    avg_latency = (
        round(sum(valid_latencies) / len(valid_latencies), 2)
        if valid_latencies
        else 0.0
    )

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

    # 1. Günlük Sağlık Bülteni
    if is_daily_report:
        print("24 saatlik genel sağlık bülteni gönderiliyor...")
        badge_color = "#10b981" if uptime_rate >= 95 else "#ef4444"
        subject = f"📊 Altyapı Sağlık Bülteni: %{uptime_rate} Uptime ({len(current_failures)} Kesinti)"
        html = render_dashboard_email(
            "GÜNLÜK ALTYAPI BÜLTENİ",
            badge_color,
            results,
            now_tr,
            uptime_rate,
            avg_latency,
        )
        send_mail(subject, html)
        return

    # 2. Anlık Kesinti / Kurtarma Alarmları
    if new_failures:
        print(f"Yeni kesinti tespit edildi: {len(new_failures)} site.")
        subject = f"🚨 [ALARM] {len(new_failures)} Adres Yanıt Vermiyor!"
        html = render_dashboard_email(
            "ACİL KESİNTİ ALARMI",
            "#ef4444",
            results,
            now_tr,
            uptime_rate,
            avg_latency,
        )
        send_mail(subject, html)

        err_msg = "\n".join([f"- {f['url']} ({f['detail']})" for f in new_failures])
        send_webhook_alert(subject, f"Aşağıdaki adreslerde kesinti tespit edildi:\n{err_msg}")

    elif recovered_sites:
        print(f"Düzelen siteler tespit edildi: {len(recovered_sites)} site.")
        subject = f"🟢 [DÜZELDİ] {len(recovered_sites)} Site Tekrar Erişilebilir"
        html = render_dashboard_email(
            "SİSTEMLER DÜZELDİ",
            "#10b981",
            results,
            now_tr,
            uptime_rate,
            avg_latency,
        )
        send_mail(subject, html)

        rec_msg = "\n".join([f"- {r['url']}" for r in recovered_sites])
        send_webhook_alert(subject, f"Aşağıdaki adresler yeniden normale döndü:\n{rec_msg}")

    else:
        print(f"Değişiklik yok. Toplam {len(sites)} adres incelendi.")


if __name__ == "__main__":
    main()
