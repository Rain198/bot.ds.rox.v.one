import os
import asyncio
import time
import json
import base64
import hmac
import hashlib

import discord
from discord.ext import commands
import aiosqlite
from aiohttp import web

print("BOOT: main.py started", flush=True)

# ================= ENV =================
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
API_SECRET = os.getenv("API_SECRET")
PORT = int(os.getenv("PORT", 8080))

if not DISCORD_TOKEN:
    raise RuntimeError("DISCORD_TOKEN is not set")

if not API_SECRET:
    raise RuntimeError("API_SECRET is not set")

# ================= DISCORD =================
intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

# ================= DATABASE =================
async def db_init():
    async with aiosqlite.connect("data.db") as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                discord_id INTEGER PRIMARY KEY,
                auth_code TEXT,
                hwid TEXT
            )
        """)
        await db.commit()


# ================= TOKEN =================
def sign_token(payload: dict) -> str:
    raw = json.dumps(payload).encode()
    sig = hmac.new(API_SECRET.encode(), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).decode() + "." + base64.urlsafe_b64encode(sig).decode()


# ================= API =================
async def api_ping(request):
    return web.json_response({"ok": True})

async def api_login(request):
    data = await request.json()
    auth_code = data.get("auth_code")
    hwid = data.get("hwid_hash")

    if not auth_code or not hwid:
        return web.json_response({"error": "BAD_DATA"}, status=400)

    async with aiosqlite.connect("data.db") as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM users WHERE auth_code=?", (auth_code,))
        user = await cur.fetchone()

        if not user:
            return web.json_response({"error": "NOT_FOUND"}, status=404)

        if user["hwid"] and user["hwid"] != hwid:
            return web.json_response({"error": "HWID_MISMATCH"}, status=403)

        if not user["hwid"]:
            await db.execute("UPDATE users SET hwid=? WHERE discord_id=?", (hwid, user["discord_id"]))
            await db.commit()

        token = sign_token({
            "discord_id": user["discord_id"],
            "exp": int(time.time()) + 1800
        })

        return web.json_response({
            "ok": True,
            "token": token
        })


async def start_api():
    app = web.Application()
    app.router.add_get("/api/ping", api_ping)
    app.router.add_post("/api/login", api_login)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()

    print(f"API started on port {PORT}", flush=True)


# ================= DISCORD EVENTS =================
@bot.event
async def on_ready():
    print(f"Logged in as {bot.user}", flush=True)


@bot.command()
async def auth(ctx):
    code = os.urandom(4).hex()

    async with aiosqlite.connect("data.db") as db:
        await db.execute(
            "INSERT OR REPLACE INTO users(discord_id, auth_code, hwid) VALUES(?,?,NULL)",
            (ctx.author.id, code)
        )
        await db.commit()

    await ctx.send(f"Your AuthCode: `{code}`")


# ================= MAIN =================
async def main():
    print("BOOT: init db...", flush=True)
    await db_init()
    print("BOOT: db ok", flush=True)

    print("BOOT: start api...", flush=True)
    await start_api()
    print("BOOT: api ok", flush=True)

    print("BOOT: starting discord bot...", flush=True)
    await bot.start(DISCORD_TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
