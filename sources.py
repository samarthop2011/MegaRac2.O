"""
40 ZERO-KEY sources. No API keys, no tokens, no login.
Returns untrusted candidate IPs; verify.py confirms every one.
"""
from __future__ import annotations
import re, base64, socket, time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

TIMEOUT = 25
UA = {"User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")}
DORKS = [
    'ssl.cert.issuer.cn="megarac.com"',
    'ssl.cert.subject.cn="megarac.com"',
    'ssl:"megarac.com"',
    'app="lighttpd" && title="MegaRAC"',
    'http.title:"MegaRAC"',
    'http.html:"MegaRAC"',
]
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HOSTRE = re.compile(r"(?:(?:[a-z0-9_\-]+)\.)+megarac\.com", re.I)

def _ips(t): return IPV4.findall(t or "")
def _hosts(t): return {h.lower() for h in HOSTRE.findall(t or "")}
def _b64(s): return base64.b64encode(s.encode()).decode()

def _resolve(hosts):
    out = []
    for h in hosts:
        h = (h or "").strip().strip(".").lower()
        if not h: continue
        if IPV4.fullmatch(h): out.append(h); continue
        try:
            for ai in socket.getaddrinfo(h, None, socket.AF_INET): out.append(ai[4][0])
        except Exception: pass
    return out

def _sess():
    s = requests.Session(); s.headers.update(UA); return s

# 1-14 search / scanners
def s_zoomeye(s):
    ips, base = [], "https://www.zoomeye.ai/api/search"
    for dork in DORKS[:4]:
        for page in range(1, 6):
            r = s.get(base, params={"q": _b64(dork), "page": page, "pageSize": 100}, timeout=TIMEOUT)
            m = (r.json().get("matches") or r.json().get("data") or [])
            ips += [x.get("ip") for x in m if x.get("ip")]
            if len(m) < 100: break
    return ips

def s_shodan_web(s):
    r = s.get("https://www.shodan.io/search",
              params={"query": 'ssl.cert.issuer.cn:"megarac.com"'}, timeout=TIMEOUT)
    return _ips(r.text)

def s_censys_web(s):
    r = s.get("https://search.censys.io/search",
              params={"resource": "hosts",
                      "q": "services.tls.certificates.leaf_data.issuer.common_name: megarac.com"},
              timeout=TIMEOUT)
    return _ips(r.text)

def s_fofa_web(s):
    r = s.get("https://fofa.info/result", params={"qbase64": _b64('cert="megarac.com"')}, timeout=TIMEOUT)
    return _ips(r.text)

def s_netlas_web(s):
    r = s.get("https://app.netlas.io/hosts/",
              params={"q": 'certificate.issuer.common_name:"megarac.com"'}, timeout=TIMEOUT)
    return _ips(r.text)

def s_criminalip_web(s):
    r = s.get("https://www.criminalip.io/asset/search",
              params={"query": 'cert_issuer_cn:"megarac.com"'}, timeout=TIMEOUT)
    return _ips(r.text)

def s_quake_web(s):
    r = s.get("https://quake.360.net/quake/", params={"query": 'cert:"megarac.com"'}, timeout=TIMEOUT)
    return _ips(r.text)

def s_hunter_web(s):
    r = s.get("https://hunter.how/search", params={"query": 'cert="megarac.com"'}, timeout=TIMEOUT)
    return _ips(r.text)

def s_onyphe_web(s):
    r = s.get("https://www.onyphe.io/search/",
              params={"q": 'certificate.issuer.commonname:"megarac.com"'}, timeout=TIMEOUT)
    return _ips(r.text)

def s_urlscan(s):
    r = s.get("https://urlscan.io/api/v1/search/",
              params={"q": "page.domain:megarac.com", "size": 100}, timeout=TIMEOUT)
    return _ips(r.text)

def s_leakix(s):
    r = s.get("https://leakix.net/api/search",
              params={"q": 'ssl.certificate.issuer_cn:"megarac.com"'}, timeout=TIMEOUT)
    return _ips(r.text)

def s_publicwww(s):
    r = s.get("https://publicwww.com/websites/%22MegaRAC%22/", timeout=TIMEOUT)
    return _resolve(_hosts(r.text))

def s_nerdydata(s):
    r = s.get("https://www.nerdydata.com/search?query=MegaRAC", timeout=TIMEOUT)
    return _resolve(_hosts(r.text))

# 15-18 certificate transparency
def s_crtsh(s):
    r = s.get("https://crt.sh/", params={"q": "%.megarac.com", "output": "json"}, timeout=TIMEOUT)
    return _resolve(_hosts(r.text))

def s_certspotter(s):
    r = s.get("https://api.certspotter.com/v1/issuances",
              params={"domain": "megarac.com", "include_subdomains": "true",
                      "expand": "dns_names"}, timeout=TIMEOUT)
    return _resolve(_hosts(r.text))

def s_googlect(s):
    r = s.get("https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch",
              params={"include_subdomains": "true", "domain": "megarac.com"}, timeout=TIMEOUT)
    return _resolve(_hosts(r.text))

def s_certstream(s):
    try:
        from websocket import create_connection
        ws = create_connection("wss://certstream.calidog.io/", timeout=10)
        ips, end = [], time.time() + 10
        while time.time() < end:
            msg = ws.recv()
            if "megarac" in msg: ips += _ips(msg)
        ws.close(); return ips
    except Exception:
        return []

# 19-32 DNS / passive DNS
def s_hackertarget(s):
    r = s.get("https://api.hackertarget.com/hostsearch/", params={"q": "megarac.com"}, timeout=TIMEOUT)
    return _resolve({ln.split(",")[0] for ln in r.text.splitlines() if "," in ln})

def s_hackertarget_rev(s):
    r = s.get("https://api.hackertarget.com/reverseiplookup/", params={"q": "megarac.com"}, timeout=TIMEOUT)
    return _ips(r.text)

def s_rapiddns(s):
    r = s.get("https://rapiddns.io/subdomain/megarac.com", params={"full": 1}, timeout=TIMEOUT)
    return _ips(r.text)

def s_bufferover(s):
    r = s.get("https://dns.bufferover.run/dns", params={"q": ".megarac.com"}, timeout=TIMEOUT)
    return _ips(r.text)

def s_mnemonic(s):
    r = s.get("https://passivedns.mnemonic.no/search",
              params={"query": "megarac.com", "aggregateResult": "true"}, timeout=TIMEOUT)
    return _ips(r.text)

def s_threatcrowd(s):
    r = s.get("https://www.threatcrowd.org/searchApi/v2/domain/report/",
              params={"domain": "megarac.com"}, timeout=TIMEOUT)
    return _ips(r.text)

def s_robtex(s):
    r = s.get("https://freeapi.robtex.com/dnsquery/", params={"q": "megarac.com"}, timeout=TIMEOUT)
    return _ips(r.text)

def s_otx(s):
    r = s.get("https://otx.alienvault.com/api/v1/indicators/domain/megarac.com/passive_dns",
              timeout=TIMEOUT)
    return _ips(r.text)

def s_dnsdumpster(s):
    r = s.get("https://dnsdumpster.com/", timeout=TIMEOUT)
    return _ips(r.text)

def s_viewdns(s):
    r = s.get("https://viewdns.info/iphistory/", params={"domain": "megarac.com"}, timeout=TIMEOUT)
    return _ips(r.text)

def s_google_doh(s):
    r = s.get("https://dns.google/resolve", params={"name": "megarac.com", "type": "A"}, timeout=TIMEOUT)
    return _ips(r.text)

def s_cloudflare_doh(s):
    r = s.get("https://cloudflare-dns.com/dns-query", params={"name": "megarac.com", "type": "A"},
              headers={"accept": "application/dns-json"}, timeout=TIMEOUT)
    return _ips(r.text)

def s_bgpview(s):
    r = s.get("https://api.bgpview.io/search", params={"query_string": "megarac.com"}, timeout=TIMEOUT)
    return _ips(r.text)

def s_ipwhois(s):
    r = s.get("https://ipwho.is/megarac.com", timeout=TIMEOUT)
    return _ips(r.text)

# 33-38 archives / datasets
def s_wayback(s):
    r = s.get("http://web.archive.org/cdx/search/cdx",
              params={"url": "*.megarac.com", "output": "json", "fl": "original",
                      "collapse": "urlkey", "limit": 5000}, timeout=TIMEOUT)
    return _resolve(_hosts(r.text))

def s_commoncrawl(s):
    idx = s.get("https://index.commoncrawl.org/collinfo.json", timeout=TIMEOUT).json()
    r = s.get(idx[0]["cdx-api"], params={"url": "*.megarac.com", "output": "json"}, timeout=TIMEOUT)
    return _resolve(_hosts(r.text))

def s_github_search(s):
    r = s.get("https://api.github.com/search/repositories",
              params={"q": "CVE-2024-54085", "per_page": 25}, timeout=TIMEOUT)
    return _ips(r.text)

def s_github_raw(s):
    ips = []
    r = s.get("https://api.github.com/search/repositories",
              params={"q": "megarac CVE-2024-54085", "per_page": 12}, timeout=TIMEOUT)
    for repo in r.json().get("items", []):
        for br in ("main", "master"):
            for p in ("README.md", "ips.txt", "hosts.txt", "megarac.txt", "targets.txt"):
                try:
                    t = s.get(f"https://raw.githubusercontent.com/{repo['full_name']}/{br}/{p}",
                              timeout=TIMEOUT)
                    if t.status_code == 200: ips += _ips(t.text)
                except Exception: pass
    return ips

def s_sonar(s):
    r = s.get("https://opendata.rapid7.com/sonar.https/", timeout=TIMEOUT)
    return _ips(r.text)

def s_shadowserver(s):
    r = s.get("https://ftp.shadowserver.org/scanning-reports/", timeout=TIMEOUT)
    return _ips(r.text)

# registry (standalone sources) — methods 39/40 live in aggregator
SOURCES = [
    ("zoomeye", s_zoomeye), ("shodan_web", s_shodan_web), ("censys_web", s_censys_web),
    ("fofa_web", s_fofa_web), ("netlas_web", s_netlas_web), ("criminalip_web", s_criminalip_web),
    ("quake_web", s_quake_web), ("hunter_web", s_hunter_web), ("onyphe_web", s_onyphe_web),
    ("urlscan", s_urlscan), ("leakix", s_leakix), ("publicwww", s_publicwww),
    ("nerdydata", s_nerdydata), ("crtsh", s_crtsh), ("certspotter", s_certspotter),
    ("googlect", s_googlect), ("certstream", s_certstream), ("hackertarget", s_hackertarget),
    ("hackertarget_rev", s_hackertarget_rev), ("rapiddns", s_rapiddns), ("bufferover", s_bufferover),
    ("mnemonic", s_mnemonic), ("threatcrowd", s_threatcrowd), ("robtex", s_robtex),
    ("otx", s_otx), ("dnsdumpster", s_dnsdumpster), ("viewdns", s_viewdns),
    ("google_doh", s_google_doh), ("cloudflare_doh", s_cloudflare_doh), ("bgpview", s_bgpview),
    ("ipwhois", s_ipwhois), ("wayback", s_wayback), ("commoncrawl", s_commoncrawl),
    ("github_search", s_github_search), ("github_raw", s_github_raw), ("sonar", s_sonar),
    ("shadowserver", s_shadowserver),
]

def discover(max_workers=40):
    s = _sess()
    found = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(fn, s): name for name, fn in SOURCES}
        for fut in as_completed(futs):
            try:
                for ip in fut.result() or []:
                    found.setdefault(ip, set()).add(futs[fut])
            except Exception:
                pass
    return found
