# MegaRAC Scanner Bot

Discord bot that finds internet-exposed **AMI MegaRAC** BMCs from **40 zero-key sources**,
verifies each one is really MegaRAC, and confirms **CVE-2024-54085** (auth bypass) by
creating an admin account and logging in. Only **100% vulnerable** hosts are posted.

**No API keys. No tokens. No login.** (except your Discord bot token, obviously)

## How it works
1. **Discover** — 40 anonymous sources (ZoomEye web API, CT logs, passive DNS, archives,
   plus HTML scraping of engines whose APIs normally need a key).
2. **Verify (the guarantee)** — every candidate must present a TLS cert with `megarac.com`
   in its issuer/subject CN, or serve the MegaRAC HTTP fingerprint. Nothing unverified passes.
3. **Expand** — confirmed hosts get their `/24` rescanned on :443.
4. **CVE check** — `mcve.py` spoofs `X-Server-Addr`, creates an admin account, verifies login.
5. **Report** — vulnerable IPs posted to Discord with credentials + geo.

## Setup
```bash
git clone https://github.com/<your-user>/<your-repo>.git
cd megarac-bot
pip install -r requirements.txt
cp .env.example .env      # put your DISCORD_TOKEN in it
python bot.py
```

## Commands
| Command | What |
|---|---|
| `!scan` | one scan, post new vulnerable hosts |
| `!scan full` | rescan everything (ignore seen cache) |
| `!watch [min]` | keep scanning every N minutes |
| `!stop` | stop the watch loop |
| `!vulns` | list known vulnerable IPs |
| `!status` | counts + concurrency |
| `!sources` | list the sources |

## Notes
- `seen_ips.json` avoids re-verifying hosts (keeps it fast).
- `vulnerable.json` is your permanent hit list.
- Tune speed with `VERIFY_CONCURRENCY` / `CVE_CONCURRENCY`.
