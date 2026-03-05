# main.py
# Python 3.10+
# pip install -U discord.py aiohttp aiosqlite
#
# Full version (keys + launcher API + scripts + client channels + support button)
# Requested behavior:
# - !help only in personal client channel (category Sup). Else bot sends help panel into personal channel.
# - !ahelp admin-only.
# - NO RuntimeError crash for missing DISCORD_TOKEN; secrets from env OR DISCORD_TOKEN.txt / API_SECRET.txt.
# - KEY выдача: в client-канал отправляется ОДНА красивая панель (embed) БЕЗ кнопки Support,
#   БЕЗ отправки в ЛС, БЕЗ дополнительной "Панели клиента" вторым сообщением.
#   (Support-кнопка остаётся доступной в !help панели.)
#
# Notes:
# - Создай каналы: #support, #key-log1, #key-log2, #key-log3
# - Создай роль: ADMINISTRATOR (или поменяй ADMIN_ROLE_NAME в env)

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
from typing import Dict, List, Optional

import discord
from discord.ext import commands, tasks
import aiosqlite
from aiohttp import web, ClientSession

# ============================================================
# CONFIG
# ============================================================

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
API_SECRET    = os.getenv("API_SECRET", "").strip()

API_HOST      = os.getenv("API_HOST", "0.0.0.0")
API_PORT      = int(os.getenv("PORT", os.getenv("API_PORT", "8080")))

DB_FILE = os.getenv("DB_FILE", "data.db")

TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "1800"))  # 30 min

ADMIN_ROLE_NAME = os.getenv("ADMIN_ROLE_NAME", "ADMINISTRATOR")

# Personal channels
CLIENTS_CATEGORY_NAME = os.getenv("CLIENTS_CATEGORY_NAME", "Sup")
SUPPORT_CHANNEL_NAME  = os.getenv("SUPPORT_CHANNEL_NAME", "support")
SUPPORT_COOLDOWN_SEC  = int(os.getenv("SUPPORT_COOLDOWN_SEC", "300"))  # 5 minutes

# Log channels for keys
KEY_LOG1_NAME = os.getenv("KEY_LOG1_NAME", "key-log1")  # fish
KEY_LOG2_NAME = os.getenv("KEY_LOG2_NAME", "key-log2")  # alhim
KEY_LOG3_NAME = os.getenv("KEY_LOG3_NAME", "key-log3")  # enchant

# Rate-limit for launcher login (seconds)
LOGIN_RL_SECONDS = min(int(os.getenv("LOGIN_RL_SECONDS", "10")), 10)  # max 10s

# Keys TTL rules
KEY_MAX_DAYS = int(os.getenv("KEY_MAX_DAYS", "30"))  # max 30 days
KEY_MIN_SECONDS = 60  # 1 minute

# Script fetching (optional)
SCRIPTS_FETCH_HEADER_NAME  = os.getenv("SCRIPTS_FETCH_HEADER_NAME", "").strip()
SCRIPTS_FETCH_HEADER_VALUE = os.getenv("SCRIPTS_FETCH_HEADER_VALUE", "").strip()

VALID_PRODUCTS = {"fish", "alhim", "enchant"}

# ============================================================
# Secrets loader (env OR txt files)
# ============================================================

def read_text_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""
    except Exception:
        return ""

def ensure_secrets_loaded() -> None:
    global DISCORD_TOKEN, API_SECRET
    if not DISCORD_TOKEN:
        DISCORD_TOKEN = read_text_file("DISCORD_TOKEN.txt")
    if not API_SECRET:
        API_SECRET = read_text_file("API_SECRET.txt")

# ============================================================
# UTILS
# ============================================================

ALPH_KEY = string.ascii_letters + string.digits
KEY_DURATION_RE = re.compile(r"^\s*(\d+)\s*([mhd])\s*$", re.IGNORECASE)

def now_ts() -> int:
    return int(time.time())

def gen_key32() -> str:
    return "".join(secrets.choice(ALPH_KEY) for _ in range(32))

def parse_key_duration(text: str) -> int:
    """
    Format: 1m / 1h / 1d / 30d (up to 30d).
    Returns seconds.
    """
    m = KEY_DURATION_RE.match(text or "")
    if not m:
        raise ValueError("Формат срока: 1m / 1h / 1d / 30d (пример: 15m или 30d)")
    n = int(m.group(1))
    u = m.group(2).lower()
    if n <= 0:
        raise ValueError("Срок должен быть больше 0.")
    if u == "m":
        sec = n * 60
    elif u == "h":
        sec = n * 3600
    else:
        if n > KEY_MAX_DAYS:
            raise ValueError(f"Максимум {KEY_MAX_DAYS} дней.")
        sec = n * 86400

    if sec < KEY_MIN_SECONDS:
        raise ValueError("Минимальный срок — 1m.")
    if sec > KEY_MAX_DAYS * 86400:
        raise ValueError(f"Максимальный срок — {KEY_MAX_DAYS} дней.")
    return sec

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_token(payload: dict) -> str:
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

# Support button cooldown (in-memory; resets on restart)
_support_last_press: Dict[int, int] = {}  # user_id -> unix ts

# ============================================================
# DB
# ============================================================

async def db_init():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.executescript("""
        CREATE TABLE IF NOT EXISTS keys(
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            key             TEXT UNIQUE NOT NULL,
            product         TEXT NOT NULL,
            discord_id      INTEGER NOT NULL,
            hwid            TEXT,
            created_at      INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            active          INTEGER NOT NULL DEFAULT 1,
            log_channel_id  INTEGER,
            log_message_id  INTEGER,
            last_login_at   INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_keys_active_expires ON keys(active, expires_at);
        CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key);

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

async def db_add_key(key: str, product: str, discord_id: int, created_at: int, expires_at: int,
                     log_channel_id: int, log_message_id: int):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            """INSERT INTO keys(key, product, discord_id, created_at, expires_at, active, log_channel_id, log_message_id)
               VALUES(?,?,?,?,?,1,?,?)""",
            (key, product, discord_id, created_at, expires_at, log_channel_id, log_message_id)
        )
        await db.commit()

async def db_get_key_row(key: str):
    async with aiosqlite.connect(DB_FILE) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM keys WHERE key=?", (key,))
        return await cur.fetchone()

async def db_set_key_hwid_and_login(kid: int, hwid_hash: str, login_at: int):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE keys SET hwid=?, last_login_at=? WHERE id=?", (hwid_hash, login_at, kid))
        await db.commit()

async def db_set_key_login_only(kid: int, login_at: int):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE keys SET last_login_at=? WHERE id=?", (login_at, kid))
        await db.commit()


async def db_delete_key_by_id(kid: int):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM keys WHERE id=?", (kid,))
        await db.commit()

async def db_get_user_keys_missing_hwid(discord_id: int, now: int):
    async with aiosqlite.connect(DB_FILE) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM keys WHERE discord_id=? AND active=1 AND expires_at>? AND (hwid IS NULL OR hwid='')",
            (discord_id, now)
        )
        return await cur.fetchall()

async def db_set_hwid_for_user_missing(discord_id: int, hwid_hash: str, now: int):
    """Set HWID for all user's keys that have no HWID yet. Returns number of updated rows."""
    async with aiosqlite.connect(DB_FILE) as db:
        cur = await db.execute(
            "UPDATE keys SET hwid=? WHERE discord_id=? AND active=1 AND expires_at>? AND (hwid IS NULL OR hwid='')",
            (hwid_hash, discord_id, now)
        )
        await db.commit()
        return cur.rowcount
async def db_expire_due_keys(now_: int, limit: int = 50):
    async with aiosqlite.connect(DB_FILE) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT * FROM keys
               WHERE active=1 AND expires_at <= ?
               ORDER BY expires_at ASC
               LIMIT ?""",
            (now_, limit)
        )
        rows = await cur.fetchall()
        if rows:
            ids = [int(r["id"]) for r in rows]
            q = ",".join(["?"] * len(ids))
            await db.execute(f"UPDATE keys SET active=0 WHERE id IN ({q})", tuple(ids))
            await db.commit()
        return rows

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
# DISCORD: personal channels + panel
# ============================================================

async def ensure_client_channel(member: discord.Member) -> discord.TextChannel:
    guild = member.guild

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

    me = guild.me or (guild.get_member(bot.user.id) if bot.user else None)
    if me:
        overwrites[me] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)

    if channel is None:
        channel = await guild.create_text_channel(
            desired_name,
            category=category,
            overwrites=overwrites,
            topic=f"client:{member.id}",
        )
    else:
        await channel.edit(category=category, overwrites=overwrites)

    return channel

def is_user_client_channel(member: discord.Member, channel: discord.abc.GuildChannel) -> bool:
    if not isinstance(channel, discord.TextChannel):
        return False
    if channel.name == f"client-{member.id}":
        return True
    if channel.topic and f"client:{member.id}" in channel.topic:
        return True
    return False

class ClientPanelView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="🆘 Support", style=discord.ButtonStyle.danger, custom_id="client_support_btn")
    async def support_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        uid = interaction.user.id
        now_ = now_ts()
        last = _support_last_press.get(uid, 0)
        left = SUPPORT_COOLDOWN_SEC - (now_ - last)
        if left > 0:
            await interaction.response.send_message(
                f"⏳ Подожди ещё **{left} сек.** перед повторным обращением в support.",
                ephemeral=True
            )
            return

        _support_last_press[uid] = now_

        guild = interaction.guild
        if guild is None:
            await interaction.response.send_message("❌ Это можно нажимать только на сервере.", ephemeral=True)
            return

        support_ch = discord.utils.get(guild.text_channels, name=SUPPORT_CHANNEL_NAME)
        if support_ch is None:
            await interaction.response.send_message(
                f"❌ Не найден канал #{SUPPORT_CHANNEL_NAME}. Создай его.",
                ephemeral=True
            )
            return

        admin_role = discord.utils.get(guild.roles, name=ADMIN_ROLE_NAME)
        role_mention = admin_role.mention if admin_role else "@here"

        src_ch = interaction.channel
        src_mention = src_ch.mention if isinstance(src_ch, discord.abc.GuildChannel) else "(unknown channel)"

        await support_ch.send(
            f"{role_mention}\n"
            f"🆘 Support request from {interaction.user.mention}\n"
            f"Channel: {src_mention}"
        )

        await interaction.response.send_message("✅ Запрос в support отправлен.", ephemeral=True)

async def send_client_panel(member: discord.Member):
    ch = await ensure_client_channel(member)
    embed = discord.Embed(
        title="Панель клиента",
        description=(
            "Нажми кнопку **Support**, если нужна помощь.\n\n"
            "Если тебе выдали ключ — используй его в лаунчере."
        )
    )
    await ch.send(embed=embed, view=ClientPanelView())

def user_help_embed() -> discord.Embed:
    return discord.Embed(
        title="Помощь",
        description=(
            "Нажми кнопку **Support**, если нужна помощь.\n"
            f"КД на кнопку: **{SUPPORT_COOLDOWN_SEC // 60} мин**.\n\n"
            "Команды игрока:\n"
            "• `!help` — показать это меню (только в твоём личном канале)"
        )
    )

# ============================================================
# DISCORD: key logging helpers
# ============================================================

def get_key_log_channel_name(product: str) -> str:
    if product == "fish":
        return KEY_LOG1_NAME
    if product == "alhim":
        return KEY_LOG2_NAME
    return KEY_LOG3_NAME

async def find_log_channel(guild: discord.Guild, name: str) -> discord.TextChannel:
    ch = discord.utils.get(guild.text_channels, name=name)
    if ch is None:
        raise RuntimeError(f"Не найден канал #{name}. Создай канал с таким именем.")
    return ch

def key_embed(product: str, key: str, target: discord.abc.User, created: int, expires: int, active: bool, hwid: Optional[str] = None) -> discord.Embed:
    status = "✅ ACTIVE" if active else "⛔ INACTIVE"
    e = discord.Embed(
        title=f"KEY: {product.upper()}",
        description=f"**Key:** `{key}`\n**User:** {target.mention} (`{target.id}`)\n**Status:** {status}",
    )
    e.add_field(name="Created", value=f"<t:{created}:F> (<t:{created}:R>)", inline=False)
    e.add_field(name="Expires", value=f"<t:{expires}:F> (<t:{expires}:R>)", inline=False)
    e.add_field(name="HWID", value=(f"`{hwid}`" if hwid else "—"), inline=False)
    return e

def client_key_embed(product: str, key: str, created: int, expires: int) -> discord.Embed:
    e = discord.Embed(title="🔑 Тебе выдан ключ")
    e.add_field(name="Продукт", value=product.upper(), inline=False)
    e.add_field(name="Key", value=f"`{key}`", inline=False)
    e.add_field(name="Создан", value=f"<t:{created}:F> (<t:{created}:R>)", inline=False)
    e.add_field(name="Истекает", value=f"<t:{expires}:F> (<t:{expires}:R>)", inline=False)
    return e

async def update_key_log_message_from_row(row):
    try:
        log_channel_id = int(row["log_channel_id"] or 0)
        log_message_id = int(row["log_message_id"] or 0)
        if not log_channel_id or not log_message_id:
            return

        log_ch = None
        for g in bot.guilds:
            ch = g.get_channel(log_channel_id)
            if isinstance(ch, discord.TextChannel):
                log_ch = ch
                break
        if log_ch is None:
            return

        msg = await log_ch.fetch_message(log_message_id)
        uid = int(row["discord_id"])
        user = bot.get_user(uid) or await bot.fetch_user(uid)

        emb = key_embed(
            product=str(row["product"]),
            key=str(row["key"]),
            target=user,
            created=int(row["created_at"]),
            expires=int(row["expires_at"]),
            active=bool(int(row["active"])),
            hwid=(row["hwid"] or None)
        )
        await msg.edit(embed=emb)
    except Exception:
        return

# ============================================================
# COMMANDS
# ============================================================

@bot.command(name="help")
async def help_cmd(ctx: commands.Context):
    """
    Для обычных игроков: !help ТОЛЬКО в личном канале.
    Если команда введена не в личном канале — бот отправит help в личный канал.
    Админам: !help не показывает админ-команды; используйте !ahelp.
    """
    if not isinstance(ctx.author, discord.Member) or ctx.guild is None:
        await ctx.reply("❌ Используй эту команду на сервере.", mention_author=False)
        return

    member: discord.Member = ctx.author
    client_ch = await ensure_client_channel(member)

    if is_admin_member(member) and not is_user_client_channel(member, ctx.channel):
        await ctx.reply("👑 Для админ-команд используй **!ahelp**.", mention_author=False)
        return

    if not is_user_client_channel(member, ctx.channel):
        await client_ch.send(embed=user_help_embed(), view=ClientPanelView())
        await ctx.reply(f"✅ Я отправил помощь в твой личный канал: {client_ch.mention}", mention_author=False)
        return

    await ctx.reply(embed=user_help_embed(), view=ClientPanelView(), mention_author=False)

@bot.command(name="ahelp")
@admin_only()
async def ahelp_cmd(ctx: commands.Context):
    e = discord.Embed(title="Админ-помощь", description="Команды администратора:")

    e.add_field(
        name="🔑 Ключи",
        value=(
            "`!genfih <1m|1h|1d|30d> @user`\n"
            "`!genalhim <1m|1h|1d|30d> @user`\n"
            "`!genenchant <1m|1h|1d|30d> @user`\n"
        ),
        inline=False
    )
    e.add_field(
        name="🧰 Панель",
        value="`!panel @user` — отправить панель в личный канал клиента",
        inline=False
    )
    e.add_field(
        name="📦 Скрипты",
        value=(
            "`!addscript <product> <filename> <local:PATH|https://URL> [sha256]`\n"
            "`!listscripts` — список скриптов"
        ),
        inline=False
    )
    await ctx.reply(embed=e, mention_author=False)

@bot.command(name="panel")
@admin_only()
async def panel_cmd(ctx: commands.Context, member: discord.Member):
    await send_client_panel(member)
    await ctx.reply("✅ Панель отправлена.", mention_author=False)

async def issue_key(ctx: commands.Context, product: str, duration_text: str, target: discord.Member):
    """
    KEY issuance:
    - log message in key-logX (with HWID updates later)
    - single clean embed in client's personal channel (NO support button, NO DM, NO extra panel)
    """
    product = product.lower().strip()
    if product not in VALID_PRODUCTS:
        await ctx.reply(f"❌ Неизвестный продукт. Доступно: {', '.join(sorted(VALID_PRODUCTS))}", mention_author=False)
        return
    try:
        sec = parse_key_duration(duration_text)
    except Exception as e:
        await ctx.reply(f"❌ {e}", mention_author=False)
        return

    created = now_ts()
    expires = created + sec
    key = gen_key32()

    # --- LOG CHANNEL ---
    try:
        log_name = get_key_log_channel_name(product)
        log_ch = await find_log_channel(ctx.guild, log_name)
    except Exception as e:
        await ctx.reply(f"❌ {e}", mention_author=False)
        return

    log_emb = key_embed(product, key, target, created, expires, True, hwid=None)
    log_msg = await log_ch.send(embed=log_emb)

    await db_add_key(
        key=key,
        product=product,
        discord_id=target.id,
        created_at=created,
        expires_at=expires,
        log_channel_id=log_ch.id,
        log_message_id=log_msg.id
    )

    # --- CLIENT PERSONAL CHANNEL: single clean key panel (NO BUTTONS) ---
    try:
        client_ch = await ensure_client_channel(target)
        await client_ch.send(embed=client_key_embed(product, key, created, expires))
    except Exception:
        pass

    await ctx.reply(
        f"✅ Ключ выдан {target.mention} на **{duration_text}**. Лог: {log_ch.mention} | ✅ отправлено в client-канал",
        mention_author=False
    )

@bot.command(name="genfih")
@admin_only()
async def genfih_cmd(ctx: commands.Context, duration: str, member: discord.Member):
    await issue_key(ctx, "fish", duration, member)

@bot.command(name="genalhim")
@admin_only()
async def genalhim_cmd(ctx: commands.Context, duration: str, member: discord.Member):
    await issue_key(ctx, "alhim", duration, member)

@bot.command(name="genenchant")
@admin_only()
async def genenchant_cmd(ctx: commands.Context, duration: str, member: discord.Member):
    await issue_key(ctx, "enchant", duration, member)

@bot.command(name="addscript")
@admin_only()
async def addscript_cmd(ctx: commands.Context, product: str, filename: str, storage: str, sha256: str = ""):
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
    bot.add_view(ClientPanelView())  # persistent view (buttons after restart)
    if not key_expire_loop.is_running():
        key_expire_loop.start()

@bot.event
async def on_member_join(member: discord.Member):
    # Optional: auto-send client panel when someone joins.
    # If you don't want it, comment next 3 lines.
    try:
        await send_client_panel(member)
    except Exception:
        pass

# ============================================================
# KEY EXPIRATION LOOP
# ============================================================

@tasks.loop(seconds=30)
async def key_expire_loop():
    rows = await db_expire_due_keys(now_ts(), limit=50)
    for r in rows:
        await update_key_log_message_from_row(r)

@key_expire_loop.before_loop
async def _before_key_expire_loop():
    await bot.wait_until_ready()

# ============================================================
# HTTP API (Launcher)
# ============================================================

_ip_last_login: Dict[str, int] = {}

def get_client_ip(request: web.Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return (request.remote or "unknown").strip()

def check_ip_rate_limit(ip: str, now_: int) -> int:
    if ip in _ip_last_login:
        wait = LOGIN_RL_SECONDS - (now_ - _ip_last_login[ip])
        if wait > 0:
            return wait
    return 0

def mark_ip_login(ip: str, now_: int):
    _ip_last_login[ip] = now_

def bearer_token(request: web.Request) -> str | None:
    h = request.headers.get("Authorization", "")
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return None

async def api_ping(request: web.Request) -> web.Response:
    return web.json_response({"ok": True})

async def api_login(request: web.Request) -> web.Response:
    """
    POST /api/login
    body: { "key": "<32 chars>", "hwid_hash": "<hash>" }
    """
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "BAD_JSON"}, status=400)

    key = str(data.get("key", "")).strip()
    hwid_hash = str(data.get("hwid_hash", "")).strip()
    if not key or not hwid_hash:
        return web.json_response({"ok": False, "error": "MISSING_FIELDS"}, status=400)

    ip = get_client_ip(request)
    n = now_ts()

    # rate-limit by IP: only on SUCCESS
    wait = check_ip_rate_limit(ip, n)
    if wait > 0:
        return web.json_response({"ok": False, "error": "RATE_LIMIT", "retry_after": wait}, status=429)

    row = await db_get_key_row(key)
    if row is None:
        return web.json_response({"ok": False, "error": "KEY_NOT_FOUND"}, status=404)

    if int(row["active"]) != 1:
        return web.json_response({"ok": False, "error": "KEY_INACTIVE"}, status=403)

    if int(row["expires_at"]) <= n:
        # Mark inactive in log (optional audit), then delete the key from DB
        try:
            # make a shallow copy with active=0 for embed rendering
            row_dict = dict(row)
            row_dict["active"] = 0
            await update_key_log_message_from_row(row_dict)  # accepts Mapping-like
        except Exception:
            pass

        await db_delete_key_by_id(int(row["id"]))
        return web.json_response({"ok": False, "error": "KEY_EXPIRED"}, status=403)

    saved_hwid = row["hwid"]
    if not saved_hwid:
        # First activation: bind HWID to this key, then propagate to other keys of the same Discord user
        await db_set_key_hwid_and_login(int(row["id"]), hwid_hash, n)

        # refresh row + update log message for this key
        row = await db_get_key_row(key)
        if row:
            await update_key_log_message_from_row(row)

            # Propagate HWID to other active, non-expired keys of this user that have no HWID yet
            other_rows = await db_get_user_keys_missing_hwid(int(row["discord_id"]), n)
            # After db_set_key_hwid_and_login this key no longer matches "missing hwid", so this targets only other keys
            if other_rows:
                await db_set_hwid_for_user_missing(int(row["discord_id"]), hwid_hash, n)
                # Update key-log messages for affected keys so HWID appears there too
                for r in other_rows:
                    try:
                        rr = await db_get_key_row(str(r["key"]))
                        if rr:
                            await update_key_log_message_from_row(rr)
                    except Exception:
                        pass
    else:
        if str(saved_hwid) != hwid_hash:
            return web.json_response({"ok": False, "error": "HWID_MISMATCH"}, status=403)
        await db_set_key_login_only(int(row["id"]), n)

    token = sign_token({
        "v": 1,
        "discord_id": int(row["discord_id"]),
        "product": str(row["product"]),
        "key_id": int(row["id"]),
        "exp": n + TOKEN_TTL_SECONDS
    })

    mark_ip_login(ip, n)

    return web.json_response({
        "ok": True,
        "discord_id": str(int(row["discord_id"])),
        "product": str(row["product"]),
        "server_time": n,
        "expires_at": int(row["expires_at"]),
        "token": token
    })

async def api_catalog(request: web.Request) -> web.Response:
    tok = bearer_token(request)
    if not tok:
        return web.json_response({"ok": False, "error": "NO_TOKEN"}, status=401)
    try:
        payload = verify_token(tok)
    except Exception:
        return web.json_response({"ok": False, "error": "BAD_TOKEN"}, status=401)

    product = str(payload.get("product", "")).strip()
    if product not in VALID_PRODUCTS:
        return web.json_response({"ok": True, "scripts": []})

    rows = await db_list_scripts_for_products([product])
    scripts = []
    for r in rows:
        scripts.append({
            "id": int(r["id"]),
            "product": r["product"],
            "filename": r["filename"],
            "sha256": (r["sha256"] or ""),
        })
    return web.json_response({"ok": True, "scripts": scripts})

async def api_script(request: web.Request) -> web.StreamResponse:
    tok = bearer_token(request)
    if not tok:
        return web.json_response({"ok": False, "error": "NO_TOKEN"}, status=401)
    try:
        payload = verify_token(tok)
    except Exception:
        return web.json_response({"ok": False, "error": "BAD_TOKEN"}, status=401)

    product = str(payload.get("product", "")).strip()
    if product not in VALID_PRODUCTS:
        return web.json_response({"ok": False, "error": "FORBIDDEN"}, status=403)

    try:
        script_id = int(request.match_info["id"])
    except Exception:
        return web.json_response({"ok": False, "error": "BAD_ID"}, status=400)

    r = await db_get_script(script_id)
    if r is None:
        return web.json_response({"ok": False, "error": "NOT_FOUND"}, status=404)

    if r["product"] != product:
        return web.json_response({"ok": False, "error": "FORBIDDEN"}, status=403)

    filename = r["filename"]
    storage_type = r["storage_type"]
    storage_path = r["storage_path"]
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

    if storage_type == "local":
        try:
            return web.FileResponse(path=storage_path, headers=headers)
        except Exception:
            return web.json_response({"ok": False, "error": "FILE_ERROR"}, status=500)

    if storage_type == "url":
        req_headers = {}
        if SCRIPTS_FETCH_HEADER_NAME and SCRIPTS_FETCH_HEADER_VALUE:
            req_headers[SCRIPTS_FETCH_HEADER_NAME] = SCRIPTS_FETCH_HEADER_VALUE

        try:
            async with ClientSession() as session:
                async with session.get(storage_path, headers=req_headers, timeout=60) as resp:
                    if resp.status != 200:
                        return web.json_response({"ok": False, "error": "UPSTREAM_ERROR", "status": resp.status}, status=502)
                    out = web.StreamResponse(status=200, headers=headers)
                    await out.prepare(request)
                    async for chunk in resp.content.iter_chunked(1024 * 64):
                        await out.write(chunk)
                    await out.write_eof()
                    return out
        except Exception:
            return web.json_response({"ok": False, "error": "UPSTREAM_EXCEPTION"}, status=502)

    return web.json_response({"ok": False, "error": "BAD_STORAGE_TYPE"}, status=500)

async def start_api():
    app = web.Application()
    app.router.add_get("/api/ping", api_ping)
    app.router.add_post("/api/login", api_login)
    app.router.add_get("/api/catalog", api_catalog)
    app.router.add_get("/api/script/{id}", api_script)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, API_HOST, API_PORT)
    await site.start()
    print(f"✅ API started on {API_HOST}:{API_PORT}")

# ============================================================
# RUN
# ============================================================

async def main():
    ensure_secrets_loaded()

    # No traceback: just message and exit
    if not DISCORD_TOKEN:
        print("❌ DISCORD_TOKEN не найден. Создай файл DISCORD_TOKEN.txt рядом с main.py и вставь токен.")
        return
    if not API_SECRET:
        print("❌ API_SECRET не найден. Создай файл API_SECRET.txt рядом с main.py и вставь секрет.")
        return

    await db_init()
    await start_api()
    await bot.start(DISCORD_TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
