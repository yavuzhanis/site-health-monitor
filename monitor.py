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

# SSL uyarılarını sustur (kendi sertifikası olan alt domainler için)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = int(os.getenv("TIMEOUT_SECONDS", "10"))
MAX_WORKERS = 10  # Güvenlik duvarına takılmamak için 10 iş parçacığına optimize edildi
STATE_FILE = "state.json"

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
RECEIVER_EMAILS_RAW = os.getenv("RECEIVER_EMAILS", "")
RECEIVERS = [
    email.strip() for email in RECEIVER_EMAILS_RAW.split(",") if email.strip()
]

# Gerçek masaüstü Chrome tarayıcı başlıkları (WAF bypass için)
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
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def create_session():
    session = requests.Session()
    retries = Retry(
        total=2,
        backoff_factor=1,
        status_forcelist=[502, 503, 504],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


SESSION = create_session()


def execute_request(url: str):
    start = time.time()
    try:
        response = SESSION.get(
            url,
            timeout=TIMEOUT,
            headers=BROWSER_HEADERS,
            allow_redirects=True,
            verify=False,  # Alt alan adı SSL zincir uyumsuzluklarını false-positive yapmaz
        )
        elapsed = round(time.time() - start, 2)

        # 401/403: Bazı paneller parola veya kampüs içi korumalıdır, bu sitenin çöktüğü anlamına gelmez!
        if response.status_code in [401, 403]:
            return {
                "ok": True,
                "url": url,
                "status": "PROTECTED",
                "code": response.status_code,
                "detail": "Korumalı / Giriş Yetkisi Gerekiyor",
                "time": elapsed,
            }

        if response.status_code >= 400:
            return {
                "ok": False,
                "url": url,
                "status": "HTTP_ERROR",
                "code": response.status_code,
                "detail": response.reason,
                "time": elapsed,
            }

        # Beyaz sayfa / kritik SQL hatası kontrolü
        body_sample = response.text[:25000].lower()
        for kw in STRICT_DANGER_KEYWORDS:
            if kw in body_sample:
                return {
                    "ok": False,
                    "url": url,
                    "status": "BODY_ERROR",
                    "code": response.status_code,
                    "detail": f"Kritik Hata Metni ({kw})",
                    "time": elapsed,
                }

        return {
            "ok": True,
            "url": url,
            "status": "OK",
            "code": response.status_code,
            "detail": "Sorunsuz Yanıt",
            "time": elapsed,
        }

    except requests.exceptions.SSLError:
        # HTTPS başarısız olduysa HTTP ile bir kez daha dene
        if url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            try:
                r_http = SESSION.get(
                    http_url,
                    timeout=TIMEOUT,
                    headers=BROWSER_HEADERS,
                    allow_redirects=True,
                    verify=False,
                )
                if r_http.status_code < 400 or r_http.status_code in [401, 403]:
                    return {
                        "ok": True,
                        "url": url,
                        "status": "OK_HTTP_FALLBACK",
                        "code": r_http.status_code,
                        "detail": "HTTP Üzerinden Aktif (SSL Yok)",
                        "time": round(time.time() - start, 2),
                    }
            except Exception:
                pass
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
    except requests.exceptions.ConnectionError:
        return {
            "ok": False,
            "url": url,
            "status": "CONNECTION_ERROR",
            "code": "-",
            "detail": "DNS Kaydı Yok veya Sunucu Kapalı",
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
    # İlk istek başarısız olursa 2 saniye bekleyip doğrula (Ağ dalgalanmalarını bertaraf et)
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
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, RECEIVERS, msg.as_string())
        server.quit()
        print(f"E-posta başarıyla ulaştırıldı: {', '.join(RECEIVERS)}")
    except Exception as e:
        print(f"E-posta aktarım hatası: {e}")


def render_dashboard_email(
    badge_title: str,
    badge_color: str,
    results: list,
    now_tr: str,
    uptime_rate: float,
    avg_latency: float,
):
    total_sites = len(results)
    failures = [r for r in results if not r["ok"]]
    healthy = [r for r in results if r["ok"]]

    # Hatalı siteler kart listesi
    failure_cards = ""
    if failures:
        for f in failures:
            code_view = (
                f"HTTP {f['code']}" if f["code"] != "-" else f["status"]
            )
            failure_cards += f"""
            <div style="background:#fff; border-left:4px solid #ef4444; border-radius:8px; padding:14px 16px; margin-bottom:10px; box-shadow:0 1px 3px rgba(0,0,0,0.05); border:1px solid #fee2e2; border-left-width:4px;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                        <a href="{f['url']}" target="_blank" style="color:#0f172a; font-weight:700; text-decoration:none; font-size:14px;">{f['url']}</a>
                        <div style="color:#dc2626; font-size:12px; margin-top:4px; font-weight:500;">⚠️ {f.get('detail', 'Erişim Hatası')}</div>
                    </div>
                    <span style="background:#fef2f2; color:#991b1b; padding:4px 10px; border-radius:6px; font-size:11px; font-weight:700; border:1px solid #fecaca;">{code_view}</span>
                </div>
            </div>
            """
    else:
        failure_cards = """
        <div style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:8px; padding:20px; text-align:center; color:#15803d; font-weight:600;">
            ✅ Harika! Taranan tüm dijital varlıklar aktif ve eksiksiz yanıt veriyor.
        </div>
        """

    # Hızlı erişim için çalışan sitelerin mini listesi (ilk 10 veya özet)
    healthy_rows = ""
    for h in healthy[:8]:
        lat_badge = (
            "#10b981"
            if h["time"] != "-" and h["time"] < 1.0
            else ("#f59e0b" if h["time"] != "-" and h["time"] < 2.5 else "#64748b")
        )
        healthy_rows += f"""
        <tr style="border-bottom:1px solid #f1f5f9; font-size:12px;">
            <td style="padding:8px 0;"><a href="{h['url']}" style="color:#334155; text-decoration:none;">{h['url']}</a></td>
            <td style="padding:8px 0; text-align:right;"><span style="color:{lat_badge}; font-weight:bold;">{h['time']}s</span></td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head><meta charset="UTF-8"></head>
    <body style="margin:0; padding:24px 12px; background-color:#f1f5f9; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
        <div style="max-width:680px; margin:0 auto; background:#ffffff; border-radius:16px; overflow:hidden; box-shadow:0 4px 12px rgba(0,0,0,0.04); border:1px solid #e2e8f0;">
            
            <!-- Header -->
            <div style="background:linear-gradient(135deg, #0f172a 0%, #1e293b 100%); padding:28px 32px; color:#ffffff;">
                <div style="display:inline-block; background:{badge_color}; color:#ffffff; font-size:11px; font-weight:800; padding:4px 12px; border-radius:20px; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:12px;">
                    {badge_title}
                </div>
                <h1 style="margin:0; font-size:22px; font-weight:800; letter-spacing:-0.5px;">Kapadokya Dijital Altyapı Denetimi</h1>
                <p style="margin:6px 0 0 0; color:#94a3b8; font-size:13px;">Son Rapor: {now_tr}</p>
            </div>

            <!-- KPI Metrikleri -->
            <div style="padding:24px 32px; background:#f8fafc; border-bottom:1px solid #e2e8f0;">
                <table style="width:100%; border-collapse:collapse;">
                    <tr>
                        <td style="width:25%; text-align:center; padding:12px; background:#ffffff; border-radius:10px; border:1px solid #e2e8f0;">
                            <div style="font-size:11px; color:#64748b; font-weight:700; text-transform:uppercase;">Erişilebilirlik</div>
                            <div style="font-size:22px; font-weight:800; color:{'#10b981' if uptime_rate >= 90 else '#ef4444'}; margin-top:4px;">%{uptime_rate}</div>
                        </td>
                        <td style="width:4%;"></td>
                        <td style="width:23%; text-align:center; padding:12px; background:#ffffff; border-radius:10px; border:1px solid #e2e8f0;">
                            <div style="font-size:11px; color:#64748b; font-weight:700; text-transform:uppercase;">Aktif</div>
                            <div style="font-size:22px; font-weight:800; color:#10b981; margin-top:4px;">{len(healthy)}</div>
                        </td>
                        <td style="width:4%;"></td>
                        <td style="width:23%; text-align:center; padding:12px; background:#ffffff; border-radius:10px; border:1px solid #e2e8f0;">
                            <div style="font-size:11px; color:#64748b; font-weight:700; text-transform:uppercase;">Kesinti</div>
                            <div style="font-size:22px; font-weight:800; color:{'#ef4444' if failures else '#64748b'}; margin-top:4px;">{len(failures)}</div>
                        </td>
                        <td style="width:4%;"></td>
                        <td style="width:25%; text-align:center; padding:12px; background:#ffffff; border-radius:10px; border:1px solid #e2e8f0;">
                            <div style="font-size:11px; color:#64748b; font-weight:700; text-transform:uppercase;">Ort. Yanıt</div>
                            <div style="font-size:22px; font-weight:800; color:#0f172a; margin-top:4px;">{avg_latency}s</div>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Ana İçerik -->
            <div style="padding:28px 32px;">
                <h3 style="margin:0 0 14px 0; font-size:15px; color:#0f172a; font-weight:700;">
                    🚨 İnceleme Gerektiren Siteler ({len(failures)})
                </h3>
                {failure_cards}

                <div style="margin-top:32px; padding-top:20px; border-top:1px solid #e2e8f0;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
                        <span style="font-size:13px; font-weight:700; color:#475569;">Sorunsuz Çalışan Siteler (Örnek Kesit)</span>
                        <span style="font-size:12px; color:#10b981; font-weight:bold;">{len(healthy)}/{total_sites} Adres Aktif</span>
                    </div>
                    <table style="width:100%; border-collapse:collapse;">
                        {healthy_rows}
                    </table>
                </div>
            </div>

            <!-- Footer -->
            <div style="background:#f8fafc; padding:16px 32px; text-align:center; font-size:12px; color:#94a3b8; border-top:1px solid #e2e8f0;">
                Bu rapor Kapadokya Üniversitesi Uptime Botu tarafından GitHub Actions üzerinde otomatik olarak derlenmiştir.
            </div>

        </div>
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

    # 1. 24 Saatlik Genel Sağlık Özeti (Manuel tetikleme veya Sabah 09:17)
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

    # 2. Anlık Çökme Uyarısı (Sadece yeni bir site çökerse)
    if new_failures:
        print(f"Yeni kesinti: {len(new_failures)} site.")
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
    elif recovered_sites:
        print(f"Düzelen siteler: {len(recovered_sites)} site.")
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
    else:
        print(f"Değişiklik yok. Toplam {len(sites)} adres sağlıklı.")


if __name__ == "__main__":
    main()
