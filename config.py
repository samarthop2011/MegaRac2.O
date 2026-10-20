import os
from dotenv import load_dotenv
load_dotenv()

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
CHANNEL_ID    = int(os.getenv("CHANNEL_ID", "0") or 0)   # 0 = reply where invoked
PREFIX        = os.getenv("PREFIX", "!")

DORK = os.getenv(
    "DORK",
    'ssl.cert.issuer.cn="megarac.com" && app="lighttpd" && country!="CN" && port="443"',
)

# speed knobs
DISCOVERY_WORKERS = int(os.getenv("DISCOVERY_WORKERS", "40"))
VERIFY_CONCURRENCY = int(os.getenv("VERIFY_CONCURRENCY", "300"))
CVE_CONCURRENCY    = int(os.getenv("CVE_CONCURRENCY", "120"))
TLS_TIMEOUT  = float(os.getenv("TLS_TIMEOUT", "6"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "8"))
EXPAND       = os.getenv("EXPAND", "1") == "1"
WATCH_MINUTES = int(os.getenv("WATCH_MINUTES", "10"))

SEEN_FILE = "seen_ips.json"
VULN_FILE = "vulnerable.json"
