"""Only real MegaRAC survives. Cert match is authoritative; HTTP is fallback."""
import asyncio, ssl
from cryptography import x509

MARKERS = ("megarac", "megarac sp", "sp-x", "/redfish", "/rpc/")

async def _cert_ok(ip, port=443, timeout=6):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip), timeout)
    except Exception:
        return False
    try:
        der = w.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        w.close()
    if not der:
        return False
    c = x509.load_der_x509_certificate(der)
    blob = (c.issuer.rfc4514_string() + "|" + c.subject.rfc4514_string()).lower()
    return "megarac" in blob

async def is_megarac(session, ip, timeout=8):
    if await _cert_ok(ip, timeout=min(timeout, 6)):
        return True, "cert"
    try:
        async with session.get(f"https://{ip}/", timeout=timeout, ssl=False,
                               allow_redirects=True) as r:
            body = (await r.text())[:200000].lower()
            server = r.headers.get("Server", "").lower()
    except Exception:
        return False, "dead"
    if "lighttpd" in server and any(m in body for m in MARKERS):
        return True, "http"
    if "megarac" in body:
        return True, "body"
    return False, "no-match"
