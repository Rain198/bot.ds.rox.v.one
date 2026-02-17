# main_unified_v3.py
# Discord bot + aiohttp API with subscription management and audit logging

import os
import asyncio
import time
import json
import base64
import hmac
import hashlib
import secrets
import string
import re
from typing import Optional, List, Dict, Any

import discord
from discord.ext import commands
import aiosqlite
from aiohttp import web

DISCORD_TOKEN = (os.getenv("DISCORD_TOKEN") or "").strip()
API_SECRET = (os.getenv("API_SECRET") or "").strip()
PORT = int(os.getenv("PORT", "8080"))

DB_FILE = "data.db"

VALID_PRODUCTS = {"fish", "alhim", "enchant"}

def now_ts() -> int:
    return int(time.time())

def gen_auth_code() -> str:
    body = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(18))
    return "AUTH-" + "-".join(body[i:i+6] for i in range(0, 18, 6))

def sign_token(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(API_SECRET.encode(), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=") + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")

def verify_token(token: str) -> Dict[str, Any]:
    raw_b64, sig_b64 = token.split(".", 1)
    raw = base64.urlsafe_b64decode(raw_b64 + "===")
    sig = base64.urlsafe_b64decode(sig_b64 + "===")
    expected = hmac.new(API_SECRET.encode(), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("bad signature")
    return json.loads(raw.decode())

# ================= DB =================

async def db_init():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            discord_id INTEGER PRIMARY KEY,
            auth_code TEXT UNIQUE,
            hwid TEXT
        );

        CREATE TABLE IF NOT EXISTS subs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id INTEGER NOT NULL,
            product TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            paused_at INTEGER
        );
        """)
        await db.commit()

async def db_add_user(discord_id: int):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("INSERT OR IGNORE INTO users(discord_id) VALUES(?)", (discord_id,))
        await db.commit()

async def db_set_auth(discord_id: int, code: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE users SET auth_code=? WHERE discord_id=?", (code, discord_id))
        await db.commit()

async def db_get_user_by_auth(code: str):
    async with aiosqlite.connect(DB_FILE) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM users WHERE auth_code=?", (code,))
        return await cur.fetchone()

async def db_add_sub(discord_id: int, product: str, days: int):
    expires = now_ts() + days * 86400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("INSERT INTO subs(discord_id, product, expires_at) VALUES(?,?,?)",
                         (discord_id, product, expires))
        await db.commit()

async def db_get_active_products(discord_id: int):
    now_ = now_ts()
    async with aiosqlite.connect(DB_FILE) as db:
        cur = await db.execute(
            "SELECT product FROM subs WHERE discord_id=? AND revoked=0 AND paused_at IS NULL AND expires_at>?",
            (discord_id, now_))
        rows = await cur.fetchall()
        return [r[0] for r in rows]

# ================= BOT =================

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    print("Bot ready:", bot.user)

@bot.event
async def on_member_join(member):
    await db_add_user(member.id)
    channel = await member.create_dm()
    code = gen_auth_code()
    await db_set_auth(member.id, code)
    await channel.send(f"Ваш AuthCode: {code}")

@bot.command()
@commands.has_permissions(administrator=True)
async def givesub(ctx, product: str, days: int, member: discord.Member):
    if product not in VALID_PRODUCTS:
        await ctx.send("Неверный продукт")
        return
    await db_add_sub(member.id, product, days)
    await ctx.send("Подписка выдана")

# ================= API =================

async def api_login(request):
    data = await request.json()
    code = data.get("auth_code")
    hwid = data.get("hwid_hash")
    user = await db_get_user_by_auth(code)
    if not user:
        return web.json_response({"ok": False})
    products = await db_get_active_products(user["discord_id"])
    token = sign_token({"discord_id": user["discord_id"], "exp": now_ts() + 1800})
    return web.json_response({"ok": True, "products": products, "token": token})

async def start_api():
    app = web.Application()
    app.router.add_post("/api/login", api_login)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()

async def main():
    await db_init()
    await start_api()
    await bot.start(DISCORD_TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
