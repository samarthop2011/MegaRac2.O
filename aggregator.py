"""discover -> verify -> expand -> CVE, all async and streamed."""
import asyncio, ipaddress
import aiohttp
from sources import discover
from verify import is_megarac
from mcve import check_ip as cve_check
import config

UA = {"User-Agent": "Mozilla/5.0 (compatible; megarac-bot)"}

def _connector():
    return aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, ssl=False)

async def _geo(session, ip):
    try:
        async with session.get(f"http://ip-api.com/json/{ip}", timeout=5) as r:
            d = await r.json()
        if d.get("status") == "success":
            return f"{d.get('country','?')}, {d.get('city','?')} ({d.get('isp','?')})"
    except Exception:
        pass
    return "Unknown"

async def _probe(ip, port=443, t=3):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), t)
        w.close(); return ip
    except Exception:
        return None

class Pipeline:
    def __init__(self, seen: set):
        self.seen = seen

    async def run(self, full=False, on_progress=None):
        cand = await asyncio.to_thread(discover, config.DISCOVERY_WORKERS)
        todo = {ip: s for ip, s in cand.items() if full or ip not in self.seen}
        self.seen.update(cand.keys())
        total = len(todo)
        if on_progress:
            await on_progress(f"discovered {total} new candidates from "
                              f"{len({x for s in cand.values() for x in s})} sources")

        confirmed, vuln = [], []
        async with aiohttp.ClientSession(connector=_connector(),
                                         headers=UA,
                                         timeout=aiohttp.ClientTimeout(total=20)) as session:
            # verify (async, bounded)
            sem = asyncio.Semaphore(config.VERIFY_CONCURRENCY)
            done = 0
            async def v(ip):
                nonlocal done
                async with sem:
                    ok, _ = await is_megarac(session, ip, config.HTTP_TIMEOUT)
                done += 1
                if on_progress and done % 50 == 0:
                    await on_progress(f"verified {done}/{total} | {len(confirmed)} MegaRAC")
                if ok: confirmed.append(ip)
            await asyncio.gather(*(v(ip) for ip in todo))

            # expand neighbours (method #40)
            if config.EXPAND and confirmed:
                extra = set()
                for ip in list(confirmed):
                    hosts = [str(h) for h in
                             ipaddress.ip_network(f"{ip}/24", strict=False).hosts()]
                    res = await asyncio.gather(*(_probe(h) for h in hosts))
                    extra.update(x for x in res if x)
                extra -= set(confirmed)
                if extra:
                    sem2 = asyncio.Semaphore(config.VERIFY_CONCURRENCY)
                    async def v2(ip):
                        async with sem2:
                            ok, _ = await is_megarac(session, ip, config.HTTP_TIMEOUT)
                        if ok: confirmed.append(ip)
                    await asyncio.gather(*(v2(ip) for ip in extra))

            # CVE check on confirmed only
            sem3 = asyncio.Semaphore(config.CVE_CONCURRENCY)
            async def c(ip):
                async with sem3:
                    r = await cve_check(session, ip, timeout=config.TLS_TIMEOUT)
                if r.get("vulnerable"):
                    r["geo"] = await _geo(session, ip)
                    vuln.append(r)
            await asyncio.gather(*(c(ip) for ip in confirmed))

        return {"candidates": total, "confirmed": len(confirmed), "vulns": vuln}
