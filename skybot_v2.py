# skybot_v2.py
# Python 3.10+
# pip install -U discord.py aiohttp aiosqlite

import os
import asyncio
import time
import re
import string
import secrets
import base64
import json
import hmac
import hashlib
from typing import Optional, Dict, Tuple, List

import discord
from discord.ext import commands
import aiosqlite
from aiohttp import web, ClientSession

# ============================================================
# CONFIG (use env vars; DO NOT hardcode secrets)
# ============================================================

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
API_SECRET    = os.getenv("API_SECRET", "").strip()  # used to sign short-lived session tokens
API_HOST      = os.getenv("API_HOST", "0.0.0.0")
API_PORT      = int(os.getenv("PORT", os.getenv("API_PORT", "8080")))

# Discord server onboarding
CLIENTS_CATEGORY_NAME = os.getenv("CLIENTS_CATEGORY_NAME", "clients")
ADMIN_ROLE_NAME       = os.getenv("ADMIN_ROLE_NAME", "ADMINISTRATOR")

# Script fetching (optional):
# - If script storage requires a static header (simple protection), set:
#   SCRIPTS_FETCH_HEADER_NAME="X-Storage-Key"
#   SCRIPTS_FETCH_HEADER_VALUE="..."
SCRIPTS_FETCH_HEADER_NAME  = os.getenv("SCRIPTS_FETCH_HEADER_NAME", "").strip()
SCRIPTS_FETCH_HEADER_VALUE = os.getenv("SCRIPTS_FETCH_HEADER_VALUE", "").strip()

DB_FILE = os.getenv("DB_FILE", "data.db")

# Session token TTL (seconds)
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "1800"))  # 30 min

# Subscription products (tags)
VALID_PRODUCTS = {"fish", "alhim", "enchant"}

# ============================================================
# UTILS
# ============================================================

ALPH = string.ascii_uppercase + string.digits
DURATION_RE = re.compile(r"^\s*(\d+)\s*(h|d|w|mo)\s*$", re.IGNORECASE)
UNIT_SECONDS = {"h": 3600, "d": 86400, "w": 604800, "mo": 2592000}
MIN_SECONDS = 3600
MAX_SECONDS = 90 * 86400

def now_ts() -> int:
    return int(time.time())

def parse_duration(text: str) -> int:
    m = DURATION_RE.match(text or "")
    if not m:
        raise ValueError("Формат: 1h / 1d / 1w / 1mo (пример: 3d)")
    n = int(m.group(1))
    u = m.group(2).lower()
    sec = n * UNIT_SECONDS[u]
    return max(MIN_SECONDS, min(MAX_SECONDS, sec))

def gen_code(prefix: str, groups: int = 3, group_len: int = 6) -> str:
    body = "".join(secrets.choice(ALPH) for _ in range(groups * group_len))
    return prefix + "-" + "-".join(body[i:i+group_len] for i in range(0, len(body), group_len))

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_token(payload: dict) -> str:
    """
    Minimal HMAC-signed token (similar to JWT, but without header):
    token = base64url(json_payload) + "." + base64url(hmac_sha256(payload))
    """
    if not API_SECRET:
        raise RuntimeError("API_SECRET is not set")
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(API_SECRET.encode("utf-8"), raw, hashlib.sha256).digest()
    return f"{b64url(raw)}.{b64url(sig)}"

def verify_token(token: str) -> dict:
    if not API_SECRET:
        raise RuntimeError("API_SECRET is not set")
    try:
        p1, p2 = token.split(".", 1)
        raw = b64url_decode(p1)
        sig = b64url_decode(p2)
        expected = hmac.new(API_SECRET.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("bad signature")
        payload = json.loads(raw.decode("utf-8"))
        if int(payload.get("exp", 0)) < now_ts():
            raise ValueError("expired")
        return payload
    except Exception as e:
        raise ValueError("invalid token") from e

def is_admin_member(member: discord.Member) -> bool:
    if member.guild_permissions.administrator:
        return True
    return any(r.name == ADMIN_ROLE_NAME for r in member.roles)

def admin_only():
    async def predicate(ctx: commands.Context):
        return isinstance(ctx.author, discord.Member) and is_admin_member(ctx.author)
    return commands.check(predicate)

# ============================================================
# BOT INIT
# ============================================================

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# ============================================================
# DB
# ============================================================

async def db_init():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            discord_id      INTEGER PRIMARY KEY,
            lang            TEXT NOT NULL DEFAULT 'ru',
            auth_code       TEXT UNIQUE,
            hwid            TEXT,
            user_channel_id INTEGER,
            created_at      INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS subs(
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id  INTEGER NOT NULL,
            product     TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL,
            revoked     INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_subs_user ON subs(discord_id);
        CREATE INDEX IF NOT EXISTS idx_subs_expires ON subs(expires_at);

        CREATE TABLE IF NOT EXISTS scripts(
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            product       TEXT NOT NULL,
            filename      TEXT NOT NULL,
            storage_type  TEXT NOT NULL,            -- 'local' or 'url'
            storage_path  TEXT NOT NULL,            -- local path or https url
            sha256        TEXT,
            enabled       INTEGER NOT NULL DEFAULT 1,
            created_at    INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_scripts_prod ON scripts(product);
        """)
        await db.commit()

async def db_ensure_user(discord_id: int):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT OR IGNORE INTO users(discord_id, created_at) VALUES(?, ?)",
            (discord_id, now_ts())
        )
        await db.commit()

async def db_get_user(discord_id: int):
    async with aiosqlite.connect(DB_FILE) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM users WHERE discord_id=?", (discord_id,))
        return await cur.fetchone()

async def db_set_lang(discord_id: int, lang: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE users SET lang=? WHERE discord_id=?", (lang, discord_id))
        await db.commit()

async def db_set_user_channel(discord_id: int, channel_id: int):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE users SET user_channel_id=? WHERE discord_id=?", (channel_id, discord_id))
        await db.commit()

async def db_get_user_by_auth(auth_code: str):
    async with aiosqlite.connect(DB_FILE) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM users WHERE auth_code=?", (auth_code,))
        return await cur.fetchone()

async def db_unique_auth_code() -> str:
    while True:
        code = gen_code("AUTH", groups=3, group_len=6)
        if await db_get_user_by_auth(code) is None:
            return code

async def db_set_auth(discord_id: int, auth_code: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE users SET auth_code=? WHERE discord_id=?", (auth_code, discord_id))
        await db.commit()

async def db_set_hwid(discord_id: int, hwid_hash: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE users SET hwid=? WHERE discord_id=?", (hwid_hash, discord_id))
        await db.commit()

async def db_add_sub(discord_id: int, product: str, created_at: int, expires_at: int):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO subs(discord_id, product, created_at, expires_at) VALUES(?,?,?,?)",
            (discord_id, product, created_at, expires_at)
        )
        await db.commit()

async def db_get_active_products(discord_id: int, now_: int) -> List[str]:
    async with aiosqlite.connect(DB_FILE) as db:
        cur = await db.execute(
            "SELECT product FROM subs WHERE discord_id=? AND revoked=0 AND expires_at>? ORDER BY expires_at ASC",
            (discord_id, now_)
        )
        rows = await cur.fetchall()
        return [r[0] for r in rows]

async def db_add_script(product: str, filename: str, storage_type: str, storage_path: str, sha256: str | None):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO scripts(product, filename, storage_type, storage_path, sha256, created_at) VALUES(?,?,?,?,?,?)",
            (product, filename, storage_type, storage_path, sha256, now_ts())
        )
        await db.commit()

async def db_list_scripts_for_products(products: List[str]):
    if not products:
        return []
    q_marks = ",".join(["?"] * len(products))
    async with aiosqlite.connect(DB_FILE) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            f"SELECT * FROM scripts WHERE enabled=1 AND product IN ({q_marks}) ORDER BY product ASC, id ASC",
            tuple(products)
        )
        return await cur.fetchall()

async def db_get_script(script_id: int):
    async with aiosqlite.connect(DB_FILE) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM scripts WHERE id=? AND enabled=1", (script_id,))
        return await cur.fetchone()

# ============================================================
# DISCORD: personal channel + onboarding
# ============================================================

async def ensure_client_channel(member: discord.Member) -> discord.TextChannel:
    guild = member.guild
    await db_ensure_user(member.id)

    category = discord.utils.get(guild.categories, name=CLIENTS_CATEGORY_NAME)
    if category is None:
        category = await guild.create_category(CLIENTS_CATEGORY_NAME)

    desired_name = f"client-{member.id}"
    channel = discord.utils.get(guild.text_channels, name=desired_name)

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        member: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
    }
    admin_role = discord.utils.get(guild.roles, name=ADMIN_ROLE_NAME)
    if admin_role:
        overwrites[admin_role] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)

    me = guild.me or guild.get_member(bot.user.id) if bot.user else None
    if me:
        overwrites[me] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)

    if channel is None:
        channel = await guild.create_text_channel(
            desired_name,
            category=category,
            overwrites=overwrites,
            topic=f"client:{member.id}",
        )
        await db_set_user_channel(member.id, channel.id)
    else:
        # ensure it's in correct category
        await channel.edit(category=category)

    return channel

def tr(lang: str, key: str) -> str:
    RU = {
        "welcome_title": "Добро пожаловать!",
        "choose_lang": "Выберите язык, на котором бот будет общаться с вами:",
        "ru": "Русский",
        "en": "English",
        "lang_set_ru": "Язык установлен: **Русский** ✅",
        "lang_set_en": "Language set: **English** ✅",
        "next_step_ru": "Нажмите кнопку ниже, чтобы сгенерировать ваш **AuthCode**.",
        "next_step_en": "Click the button below to generate your **AuthCode**.",
        "gen_auth_ru": "Сгенерировать AuthCode",
        "gen_auth_en": "Generate AuthCode",
        "auth_ready_ru": "Ваш AuthCode:",
        "auth_ready_en": "Your AuthCode:",
        "auth_hint_ru": "Вставьте этот код в лаунчер. После первой авторизации код привяжется к вашему HWID.",
        "auth_hint_en": "Paste this code into the launcher. After first login it will be bound to your HWID.",
        "already_auth_ru": "У вас уже есть AuthCode:",
        "already_auth_en": "You already have an AuthCode:",
    }
    EN = RU  # (keys contain both languages)
    d = RU if lang == "ru" else EN
    return d.get(key, key)

class LangView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Русский", style=discord.ButtonStyle.primary, custom_id="lang_ru")
    async def set_ru(self, interaction: discord.Interaction, button: discord.ui.Button):
        await db_ensure_user(interaction.user.id)
        await db_set_lang(interaction.user.id, "ru")
        await interaction.response.send_message(
            f"{tr('ru','lang_set_ru')}\n{tr('ru','next_step_ru')}",
            view=GenerateAuthView(lang="ru"),
            ephemeral=False
        )

    @discord.ui.button(label="English", style=discord.ButtonStyle.secondary, custom_id="lang_en")
    async def set_en(self, interaction: discord.Interaction, button: discord.ui.Button):
        await db_ensure_user(interaction.user.id)
        await db_set_lang(interaction.user.id, "en")
        await interaction.response.send_message(
            f"{tr('en','lang_set_en')}\n{tr('en','next_step_en')}",
            view=GenerateAuthView(lang="en"),
            ephemeral=False
        )

class GenerateAuthView(discord.ui.View):
    def __init__(self, lang: str = "ru"):
        super().__init__(timeout=None)
        self.lang = lang

    @discord.ui.button(label="Сгенерировать AuthCode", style=discord.ButtonStyle.success, custom_id="gen_auth_btn")
    async def gen_auth(self, interaction: discord.Interaction, button: discord.ui.Button):
        await db_ensure_user(interaction.user.id)
        user = await db_get_user(interaction.user.id)
        lang = (user["lang"] if user else None) or self.lang or "ru"

        # if already exists - reuse
        auth = user["auth_code"] if user and user["auth_code"] else None
        if not auth:
            auth = await db_unique_auth_code()
            await db_set_auth(interaction.user.id, auth)
            user = await db_get_user(interaction.user.id)

        msg = (
            f"🔐 {tr(lang,'auth_ready_ru' if lang=='ru' else 'auth_ready_en')} `{auth}`\n"
            f"{tr(lang,'auth_hint_ru' if lang=='ru' else 'auth_hint_en')}"
        )
        await interaction.response.send_message(msg, ephemeral=False)

    async def on_timeout(self):
        return

# Update the button label dynamically when the view is sent
# (Discord requires label at definition time; we tweak it in constructor)
GenerateAuthView.__init__.__defaults__ = ("ru",)

# ============================================================
# COMMANDS (admin)
# ============================================================

@bot.command(name="panel")
@admin_only()
async def panel_cmd(ctx: commands.Context, member: discord.Member):
    """Resend onboarding panel to a user's personal channel."""
    ch = await ensure_client_channel(member)
    await ch.send(
        f"👋 {tr('ru','choose_lang')}",
        view=LangView()
    )
    await ctx.reply("✅ Панель отправлена.", mention_author=False)

@bot.command(name="givesub")
@admin_only()
async def givesub_cmd(ctx: commands.Context, product: str, duration: str, member: discord.Member):
    """
    Give a subscription (product tag) for a duration.
    Example: !givesub fish 30d @user
    """
    product = (product or "").lower().strip()
    if product not in VALID_PRODUCTS:
        await ctx.reply(f"❌ Неизвестный продукт. Доступно: {', '.join(sorted(VALID_PRODUCTS))}", mention_author=False)
        return
    try:
        sec = parse_duration(duration)
    except Exception as e:
        await ctx.reply(f"❌ {e}", mention_author=False)
        return

    created = now_ts()
    expires = created + sec
    await db_ensure_user(member.id)
    await db_add_sub(member.id, product, created, expires)

    ch = await ensure_client_channel(member)
    await ch.send(f"✅ Подписка **{product}** активна до <t:{expires}:F> (<t:{expires}:R>)")
    await ctx.reply("✅ Выдано.", mention_author=False)

@bot.command(name="addscript")
@admin_only()
async def addscript_cmd(ctx: commands.Context, product: str, filename: str, storage: str, sha256: str = ""):
    """
    Add a script entry for a product.
    storage: local:/path/to/file OR https://.../file
    Example:
      !addscript fish myscript.py https://example.com/myscript.py <sha256>
      !addscript fish myscript.py local:./scripts/myscript.py <sha256>
    """
    product = (product or "").lower().strip()
    if product not in VALID_PRODUCTS:
        await ctx.reply(f"❌ Неизвестный продукт. Доступно: {', '.join(sorted(VALID_PRODUCTS))}", mention_author=False)
        return

    storage = storage.strip()
    if storage.startswith("local:"):
        storage_type = "local"
        storage_path = storage[len("local:"):].strip()
        if not storage_path:
            await ctx.reply("❌ Для local: укажи путь к файлу.", mention_author=False)
            return
    elif storage.startswith("http://") or storage.startswith("https://"):
        storage_type = "url"
        storage_path = storage
    else:
        await ctx.reply("❌ storage должен быть local:PATH или https://URL", mention_author=False)
        return

    sha = sha256.strip().lower() or None
    await db_add_script(product, filename, storage_type, storage_path, sha)
    await ctx.reply("✅ Скрипт добавлен.", mention_author=False)

@bot.command(name="listscripts")
@admin_only()
async def listscripts_cmd(ctx: commands.Context):
    # list all enabled scripts
    async with aiosqlite.connect(DB_FILE) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM scripts WHERE enabled=1 ORDER BY product, id")
        rows = await cur.fetchall()
    if not rows:
        await ctx.reply("Скриптов нет.", mention_author=False)
        return
    lines = ["**Скрипты:**"]
    for r in rows:
        lines.append(f"• `#{r['id']}` [{r['product']}] {r['filename']} ({r['storage_type']})")
    await ctx.reply("\n".join(lines), mention_author=False)

# ============================================================
# EVENTS
# ============================================================

@bot.event
async def on_ready():
    print(f"✅ Logged in as {bot.user} (id={bot.user.id})")
    # persistent views (so buttons work after restart)
    bot.add_view(LangView())
    bot.add_view(GenerateAuthView(lang="ru"))

@bot.event
async def on_member_join(member: discord.Member):
    # Create personal channel and send onboarding
    ch = await ensure_client_channel(member)
    await ch.send(
        f"👋 **{tr('ru','welcome_title')}**\n{tr('ru','choose_lang')}",
        view=LangView()
    )

# ============================================================
# HTTP API (Launcher)
# ============================================================

def bearer_token(request: web.Request) -> str | None:
    h = request.headers.get("Authorization", "")
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return None

async def api_ping(request: web.Request) -> web.Response:
    return web.json_response({"ok": True})

async def api_login(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "BAD_JSON"}, status=400)

    auth_code = str(data.get("auth_code", "")).strip()
    hwid_hash = str(data.get("hwid_hash", "")).strip()

  
