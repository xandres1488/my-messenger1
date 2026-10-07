import os
import json
import base64
import mimetypes
import secrets
import hmac
import hashlib
import struct
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request, Form, Depends, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Boolean, LargeBinary, select, or_, and_
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from pwdlib import PasswordHash
import jwt

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ALGORITHM = "HS256"
MAX_FILE_SIZE = 8 * 1024 * 1024

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
password_hash = PasswordHash.recommended()

app = FastAPI(title="RayfGram")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(80), default="")
    bio: Mapped[str] = mapped_column(String(160), default="")
    avatar: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    avatar_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    totp_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    stars: Mapped[int] = mapped_column(Integer, default=0)


class Chat(Base):
    __tablename__ = "chats"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user1_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    user2_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Block(Base):
    __tablename__ = "blocks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    blocker_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    blocked_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    receiver_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    text: Mapped[str] = mapped_column(Text, default="")
    file_data: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    file_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    file_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    edited: Mapped[bool] = mapped_column(Boolean, default=False)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reply_to_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    secret: Mapped[bool] = mapped_column(Boolean, default=False)


class Group(Base):
    __tablename__ = "groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(String(500), default="")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    invite_code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class GroupMember(Base):
    __tablename__ = "group_members"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)


class GroupMessage(Base):
    __tablename__ = "group_messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    text: Mapped[str] = mapped_column(Text, default="")
    file_data: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    file_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    file_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    reply_to_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class Channel(Base):
    __tablename__ = "channels"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    invite_code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ChannelMember(Base):
    __tablename__ = "channel_members"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    channel_id: Mapped[int] = mapped_column(ForeignKey("channels.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)


class ChannelPost(Base):
    __tablename__ = "channel_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    channel_id: Mapped[int] = mapped_column(ForeignKey("channels.id"), index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    text: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)


class Reaction(Base):
    __tablename__ = "reactions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    emoji: Mapped[str] = mapped_column(String(16))


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Мягкая миграция существующей базы: старые аккаунты и сообщения сохраняются.
        await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(80) DEFAULT ''")
        await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS bio VARCHAR(160) DEFAULT ''")
        await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar BYTEA")
        await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_type VARCHAR(100)")
        await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ")
        await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ")
        await conn.exec_driver_sql("UPDATE users SET display_name = username WHERE display_name IS NULL OR display_name = ''")
        await conn.exec_driver_sql("UPDATE users SET last_seen = NOW() WHERE last_seen IS NULL")
        await conn.exec_driver_sql("UPDATE users SET created_at = NOW() WHERE created_at IS NULL")
        await conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_data BYTEA")
        await conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_name VARCHAR(255)")
        await conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_type VARCHAR(100)")
        await conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited BOOLEAN DEFAULT FALSE")
        await conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted BOOLEAN DEFAULT FALSE")
        await conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at TIMESTAMPTZ")
        await conn.exec_driver_sql("UPDATE messages SET edited = FALSE WHERE edited IS NULL")
        await conn.exec_driver_sql("UPDATE messages SET deleted = FALSE WHERE deleted IS NULL")
        await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(64)")
        await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE")
        await conn.exec_driver_sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS stars INTEGER DEFAULT 0")
        await conn.exec_driver_sql("UPDATE users SET stars = 0 WHERE stars IS NULL")
        await conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to_id INTEGER")
        await conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN IF NOT EXISTS pinned BOOLEAN DEFAULT FALSE")
        await conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN IF NOT EXISTS secret BOOLEAN DEFAULT FALSE")
        await conn.exec_driver_sql("UPDATE messages SET pinned = FALSE WHERE pinned IS NULL")
        await conn.exec_driver_sql("UPDATE messages SET secret = FALSE WHERE secret IS NULL")
        await conn.exec_driver_sql("""
            CREATE TABLE IF NOT EXISTS chats (
                id SERIAL PRIMARY KEY,
                user1_id INTEGER NOT NULL REFERENCES users(id),
                user2_id INTEGER NOT NULL REFERENCES users(id),
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        await conn.exec_driver_sql("""
            CREATE TABLE IF NOT EXISTS blocks (
                id SERIAL PRIMARY KEY,
                blocker_id INTEGER NOT NULL REFERENCES users(id),
                blocked_id INTEGER NOT NULL REFERENCES users(id),
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_chats_user1_id ON chats(user1_id)")
        await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_chats_user2_id ON chats(user2_id)")
        await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_blocks_blocker_id ON blocks(blocker_id)")
        await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_blocks_blocked_id ON blocks(blocked_id)")


@app.on_event("startup")
async def startup():
    await init_db()


def make_token(user_id: int) -> str:
    payload = {"sub": str(user_id), "exp": datetime.now(timezone.utc) + timedelta(days=30)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_user_id_from_token(token: str) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


async def current_user(request: Request) -> User:
    token = request.headers.get("Authorization", "").replace("Bearer ", "", 1)
    if not token:
        token = request.cookies.get("token", "")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    uid = get_user_id_from_token(token)
    async with SessionLocal() as db:
        user = await db.get(User, uid)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user


def user_public(user: User, online: bool = False) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name or user.username,
        "bio": user.bio or "",
        "online": online,
        "last_seen": user.last_seen.isoformat() if user.last_seen else None,
        "avatar": f"/api/avatar/{user.id}" if user.avatar else None,
        "verified": user.username.lower() in {"rayf", "monk", "rayfgrambot"},
        "twofa": bool(user.totp_enabled),
        "stars": int(user.stars or 0),
    }


def msg_public(m: Message) -> dict:
    return {
        "id": m.id,
        "sender_id": m.sender_id,
        "receiver_id": m.receiver_id,
        "text": "" if m.deleted else m.text,
        "file_name": None if m.deleted else m.file_name,
        "file_type": None if m.deleted else m.file_type,
        "file_url": f"/api/file/{m.id}" if m.file_data and not m.deleted else None,
        "created_at": m.created_at.isoformat(),
        "edited": m.edited,
        "deleted": m.deleted,
        "read": m.read_at is not None,
        "read_at": m.read_at.isoformat() if m.read_at else None,
        "reply_to_id": m.reply_to_id,
        "pinned": bool(m.pinned),
        "secret": bool(m.secret),
    }


# Connected users: user_id -> websocket
connections: dict[int, WebSocket] = {}


async def send_ws(user_id: int, data: dict):
    ws = connections.get(user_id)
    if ws:
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            connections.pop(user_id, None)


async def ensure_chat(db, a_id: int, b_id: int):
    u1, u2 = sorted((int(a_id), int(b_id)))
    chat = await db.scalar(select(Chat).where(Chat.user1_id == u1, Chat.user2_id == u2).limit(1))
    if not chat:
        chat = Chat(user1_id=u1, user2_id=u2)
        db.add(chat)
        await db.flush()
    return chat


async def is_blocked(db, sender_id: int, receiver_id: int) -> bool:
    return bool(await db.scalar(select(Block).where(Block.blocker_id == receiver_id, Block.blocked_id == sender_id)))


@app.get("/api/rayfstar")
async def rayfstar(user: User = Depends(current_user)):
    return {"stars": int(user.stars or 0)}


@app.get("/api/stars")
async def stars(user: User = Depends(current_user)):
    return {"stars": int(user.stars or 0)}


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(HTML)



def totp_now(secret: str, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    counter = int(time.time() // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 15
    code = (struct.unpack(">I", digest[off:off+4])[0] & 0x7fffffff) % (10 ** digits)
    return str(code).zfill(digits)

def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code.isdigit():
        return False
    now = int(time.time() // 30)
    for offset in (-1, 0, 1):
        key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
        digest = hmac.new(key, struct.pack(">Q", now + offset), hashlib.sha1).digest()
        off = digest[-1] & 15
        value = (struct.unpack(">I", digest[off:off+4])[0] & 0x7fffffff) % 1000000
        if hmac.compare_digest(str(value).zfill(6), code):
            return True
    return False

def group_public(g: Group) -> dict:
    return {"id": g.id, "name": g.name, "description": g.description, "invite_code": g.invite_code, "owner_id": g.owner_id}

def channel_public(c: Channel) -> dict:
    return {"id": c.id, "name": c.name, "username": c.username, "description": c.description, "invite_code": c.invite_code, "owner_id": c.owner_id}

@app.post("/api/register")
async def register(username: str = Form(...), password: str = Form(...), display_name: str = Form("")):
    username = username.strip().lower()
    display_name = display_name.strip()
    if len(username) < 3 or len(username) > 32:
        raise HTTPException(400, "Username: 3–32 символа")
    if len(password) < 6:
        raise HTTPException(400, "Пароль: минимум 6 символов")
    async with SessionLocal() as db:
        exists = await db.scalar(select(User).where(User.username == username))
        if exists:
            raise HTTPException(400, "Такой username уже существует")
        user = User(
            username=username,
            password_hash=password_hash.hash(password),
            display_name=display_name or username,
            last_seen=datetime.now(timezone.utc),
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return {"token": make_token(user.id), "user": user_public(user)}


@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...), code: str = Form("")):
    username = username.strip().lower()
    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.username == username))
        if not user or not password_hash.verify(password, user.password_hash):
            raise HTTPException(401, "Неверный username или пароль")
        if user.totp_enabled:
            if not verify_totp(user.totp_secret or "", code.strip()):
                return JSONResponse({"twofa_required": True, "message": "Введите код 2FA из приложения-аутентификатора"}, status_code=200)
        user.last_seen = datetime.now(timezone.utc)
        await db.commit()
        return {"token": make_token(user.id), "user": user_public(user)}


@app.get("/api/me")
async def me(user: User = Depends(current_user)):
    return user_public(user, user.id in connections)


@app.get("/api/users")
async def users(request: Request):
    user = await current_user(request)
    q = request.query_params.get("q", "").strip().lower()
    async with SessionLocal() as db:
        result = await db.execute(select(User).where(User.id != user.id).order_by(User.display_name))
        items = result.scalars().all()
        if q:
            items = [u for u in items if q in u.username.lower() or q in (u.display_name or "").lower()]
        return [user_public(u, u.id in connections) for u in items]


@app.get("/api/chats")
async def chats(request: Request):
    """Return persistent chats plus legacy conversations found in messages."""
    user = await current_user(request)
    async with SessionLocal() as db:
        result = await db.execute(
            select(Chat).where(or_(Chat.user1_id == user.id, Chat.user2_id == user.id)).order_by(Chat.created_at.desc())
        )
        chat_rows = result.scalars().all()

        other_ids = set()
        chat_created = {}
        for c in chat_rows:
            oid = c.user2_id if c.user1_id == user.id else c.user1_id
            other_ids.add(oid)
            chat_created[oid] = c.created_at

        msg_result = await db.execute(
            select(Message).where(or_(Message.sender_id == user.id, Message.receiver_id == user.id)).order_by(Message.created_at.desc())
        )
        msg_rows = msg_result.scalars().all()
        latest_by_user = {}
        for m in msg_rows:
            oid = m.receiver_id if m.sender_id == user.id else m.sender_id
            if oid == user.id:
                continue
            other_ids.add(oid)
            if oid not in latest_by_user:
                latest_by_user[oid] = m

        if not other_ids:
            return []

        users_result = await db.execute(select(User).where(User.id.in_(list(other_ids))))
        by_id = {u.id: u for u in users_result.scalars().all()}

        items = []
        for other_id in other_ids:
            u = by_id.get(other_id)
            if not u:
                continue
            latest = latest_by_user.get(other_id)
            created = chat_created.get(other_id) or (latest.created_at if latest else datetime.now(timezone.utc))
            item = user_public(u, u.id in connections)
            item["last_message"] = "" if not latest else ("" if latest.deleted else (latest.text or ("📎 " + (latest.file_name or "Файл"))))
            item["last_message_at"] = latest.created_at.isoformat() if latest else created.isoformat()
            item["unread"] = 0
            item["blocked"] = bool(await db.scalar(select(Block).where(Block.blocker_id == user.id, Block.blocked_id == other_id)))
            items.append(item)

        items.sort(key=lambda x: x["last_message_at"], reverse=True)
        return items


@app.post("/api/chats/{other_id}/clear")
async def clear_chat(other_id: int, user: User = Depends(current_user)):
    if other_id == user.id:
        raise HTTPException(400, "Нельзя очистить чат с самим собой")
    async with SessionLocal() as db:
        chat = await db.scalar(select(Chat).where(or_(and_(Chat.user1_id == user.id, Chat.user2_id == other_id), and_(Chat.user1_id == other_id, Chat.user2_id == user.id))))
        has_messages = bool(await db.scalar(select(Message.id).where(or_(and_(Message.sender_id == user.id, Message.receiver_id == other_id), and_(Message.sender_id == other_id, Message.receiver_id == user.id))).limit(1)))
        if not chat and not has_messages:
            raise HTTPException(404, "Чат не найден")
        await db.execute(Message.__table__.delete().where(or_(and_(Message.sender_id == user.id, Message.receiver_id == other_id), and_(Message.sender_id == other_id, Message.receiver_id == user.id))))
        if not chat:
            await ensure_chat(db, user.id, other_id)
        await db.commit()
        return {"ok": True}


@app.delete("/api/chats/{other_id}")
async def delete_chat(other_id: int, user: User = Depends(current_user)):
    if other_id == user.id:
        raise HTTPException(400, "Нельзя удалить чат с самим собой")
    async with SessionLocal() as db:
        await db.execute(Message.__table__.delete().where(or_(and_(Message.sender_id == user.id, Message.receiver_id == other_id), and_(Message.sender_id == other_id, Message.receiver_id == user.id))))
        await db.execute(Chat.__table__.delete().where(or_(and_(Chat.user1_id == user.id, Chat.user2_id == other_id), and_(Chat.user1_id == other_id, Chat.user2_id == user.id))))
        await db.commit()
        return {"ok": True}


@app.post("/api/chats/{other_id}/block")
async def block_user(other_id: int, user: User = Depends(current_user)):
    if other_id == user.id:
        raise HTTPException(400, "Нельзя заблокировать себя")
    async with SessionLocal() as db:
        target = await db.get(User, other_id)
        if not target:
            raise HTTPException(404, "Пользователь не найден")
        exists = await db.scalar(select(Block).where(Block.blocker_id == user.id, Block.blocked_id == other_id))
        if not exists:
            db.add(Block(blocker_id=user.id, blocked_id=other_id))
            await db.commit()
        return {"ok": True, "blocked": True}


@app.delete("/api/chats/{other_id}/block")
async def unblock_user(other_id: int, user: User = Depends(current_user)):
    async with SessionLocal() as db:
        await db.execute(Block.__table__.delete().where(Block.blocker_id == user.id, Block.blocked_id == other_id))
        await db.commit()
        return {"ok": True, "blocked": False}


@app.get("/api/chats/{other_id}/block")
async def block_status(other_id: int, user: User = Depends(current_user)):
    async with SessionLocal() as db:
        return {"blocked": bool(await db.scalar(select(Block).where(Block.blocker_id == user.id, Block.blocked_id == other_id)))}


@app.get("/api/messages/{other_id}")
async def messages(other_id: int, request: Request):
    user = await current_user(request)
    async with SessionLocal() as db:
        if other_id != user.id:
            await ensure_chat(db, user.id, other_id)
            await db.commit()
        result = await db.execute(
            select(Message)
            .where(
                or_(
                    and_(Message.sender_id == user.id, Message.receiver_id == other_id),
                    and_(Message.sender_id == other_id, Message.receiver_id == user.id),
                )
            )
            .order_by(Message.created_at)
            .limit(500)
        )
        rows = result.scalars().all()
        now = datetime.now(timezone.utc)
        changed = False
        for m in rows:
            if m.receiver_id == user.id and m.read_at is None:
                m.read_at = now
                changed = True
                await send_ws(m.sender_id, {"type": "read", "message_id": m.id})
        if changed:
            await db.commit()
        return [msg_public(m) for m in rows]



@app.get("/api/profile/{username}")
async def public_profile(username: str):
    async with SessionLocal() as db:
        u = await db.scalar(select(User).where(User.username == username.strip().lower()))
        if not u:
            raise HTTPException(404, "Пользователь не найден")
        return user_public(u, u.id in connections)

@app.post("/api/2fa/setup")
async def twofa_setup(user: User = Depends(current_user)):
    async with SessionLocal() as db:
        u = await db.get(User, user.id)
        if not u.totp_secret:
            u.totp_secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
            await db.commit()
        uri = "otpauth://totp/RayfGram:" + urllib.parse.quote(u.username) + "?secret=" + u.totp_secret + "&issuer=RayfGram"
        return {"secret": u.totp_secret, "otpauth": uri, "enabled": bool(u.totp_enabled)}

@app.post("/api/2fa/enable")
async def twofa_enable(code: str = Form(...), user: User = Depends(current_user)):
    async with SessionLocal() as db:
        u = await db.get(User, user.id)
        if not u.totp_secret or not verify_totp(u.totp_secret, code.strip()):
            raise HTTPException(400, "Неверный код 2FA")
        u.totp_enabled = True
        await db.commit()
        return {"enabled": True}

@app.post("/api/2fa/disable")
async def twofa_disable(code: str = Form(...), user: User = Depends(current_user)):
    async with SessionLocal() as db:
        u = await db.get(User, user.id)
        if not u.totp_enabled or not verify_totp(u.totp_secret or "", code.strip()):
            raise HTTPException(400, "Неверный код 2FA")
        u.totp_enabled = False
        await db.commit()
        return {"enabled": False}

@app.post("/api/groups")
async def create_group(name: str = Form(...), description: str = Form(""), user: User = Depends(current_user)):
    name = name.strip()[:100]
    if not name: raise HTTPException(400, "Название группы обязательно")
    async with SessionLocal() as db:
        g = Group(name=name, description=description.strip()[:500], owner_id=user.id, invite_code=secrets.token_urlsafe(10))
        db.add(g); await db.flush()
        db.add(GroupMember(group_id=g.id, user_id=user.id, is_admin=True))
        await db.commit(); await db.refresh(g)
        return group_public(g)

@app.get("/api/groups")
async def my_groups(user: User = Depends(current_user)):
    async with SessionLocal() as db:
        r = await db.execute(select(Group).join(GroupMember, Group.id == GroupMember.group_id).where(GroupMember.user_id == user.id))
        return [group_public(g) for g in r.scalars().all()]

@app.post("/api/groups/join/{code}")
async def join_group(code: str, user: User = Depends(current_user)):
    async with SessionLocal() as db:
        g = await db.scalar(select(Group).where(Group.invite_code == code))
        if not g: raise HTTPException(404, "Группа не найдена")
        exists = await db.scalar(select(GroupMember).where(GroupMember.group_id == g.id, GroupMember.user_id == user.id))
        if not exists:
            db.add(GroupMember(group_id=g.id, user_id=user.id))
            await db.commit()
        return group_public(g)

@app.get("/api/groups/{group_id}/messages")
async def group_messages(group_id: int, user: User = Depends(current_user)):
    async with SessionLocal() as db:
        member = await db.scalar(select(GroupMember).where(GroupMember.group_id == group_id, GroupMember.user_id == user.id))
        if not member: raise HTTPException(403, "Вы не участник")
        r = await db.execute(select(GroupMessage).where(GroupMessage.group_id == group_id).order_by(GroupMessage.created_at).limit(500))
        rows = r.scalars().all()
        return [{"id":m.id,"sender_id":m.sender_id,"group_id":m.group_id,"text":m.text,"file_name":m.file_name,"file_url":f"/api/group-file/{m.id}" if m.file_data else None,"created_at":m.created_at.isoformat(),"reply_to_id":m.reply_to_id,"pinned":m.pinned} for m in rows]

@app.post("/api/channels")
async def create_channel(name: str = Form(...), username: str = Form(...), description: str = Form(""), user: User = Depends(current_user)):
    username=username.strip().lower().lstrip("@")
    if not username or not username.replace("_","").isalnum(): raise HTTPException(400,"Некорректный username канала")
    async with SessionLocal() as db:
        if await db.scalar(select(Channel).where(Channel.username == username)): raise HTTPException(400,"Такой канал уже есть")
        c=Channel(name=name.strip()[:100],username=username[:32],description=description.strip()[:500],owner_id=user.id,invite_code=secrets.token_urlsafe(10))
        db.add(c); await db.flush(); db.add(ChannelMember(channel_id=c.id,user_id=user.id)); await db.commit(); await db.refresh(c)
        return channel_public(c)

@app.get("/api/channels")
async def channels(user: User = Depends(current_user)):
    async with SessionLocal() as db:
        r=await db.execute(select(Channel).join(ChannelMember, Channel.id==ChannelMember.channel_id).where(ChannelMember.user_id==user.id))
        return [channel_public(c) for c in r.scalars().all()]

@app.post("/api/channels/join/{code}")
async def join_channel(code: str, user: User = Depends(current_user)):
    async with SessionLocal() as db:
        c=await db.scalar(select(Channel).where(Channel.invite_code==code))
        if not c: raise HTTPException(404,"Канал не найден")
        if not await db.scalar(select(ChannelMember).where(ChannelMember.channel_id==c.id,ChannelMember.user_id==user.id)):
            db.add(ChannelMember(channel_id=c.id,user_id=user.id)); await db.commit()
        return channel_public(c)


@app.get("/api/channels/{channel_id}/messages")
async def channel_messages(channel_id:int,user:User=Depends(current_user)):
    async with SessionLocal() as db:
        member=await db.scalar(select(ChannelMember).where(ChannelMember.channel_id==channel_id,ChannelMember.user_id==user.id))
        if not member: raise HTTPException(403,"Вы не подписаны")
        r=await db.execute(select(ChannelPost).where(ChannelPost.channel_id==channel_id).order_by(ChannelPost.created_at).limit(500))
        return [{"id":p.id,"channel_id":p.channel_id,"sender_id":p.sender_id,"text":p.text,"created_at":p.created_at.isoformat(),"pinned":p.pinned} for p in r.scalars().all()]

@app.post("/api/pin/{message_id}")
async def pin_message(message_id:int,user:User=Depends(current_user)):
    async with SessionLocal() as db:
        m=await db.get(Message,message_id)
        if not m or m.sender_id!=user.id and m.receiver_id!=user.id: raise HTTPException(404,"Сообщение не найдено")
        m.pinned=not m.pinned; await db.commit()
        payload={"type":"message_update","message":msg_public(m)}
        await send_ws(m.sender_id,payload); await send_ws(m.receiver_id,payload)
        return msg_public(m)

@app.post("/api/react/{message_id}")
async def react(message_id:int, emoji:str=Form(...), user:User=Depends(current_user)):
    emoji=emoji.strip()[:8]
    async with SessionLocal() as db:
        m=await db.get(Message,message_id)
        if not m or (m.sender_id!=user.id and m.receiver_id!=user.id): raise HTTPException(404,"Сообщение не найдено")
        old=await db.scalar(select(Reaction).where(Reaction.message_id==message_id,Reaction.user_id==user.id))
        if old: old.emoji=emoji
        else: db.add(Reaction(message_id=message_id,user_id=user.id,emoji=emoji))
        await db.commit()
        return {"message_id":message_id,"emoji":emoji}

@app.get("/api/reactions/{message_id}")
async def reactions(message_id:int,user:User=Depends(current_user)):
    async with SessionLocal() as db:
        r=await db.execute(select(Reaction).where(Reaction.message_id==message_id))
        return [{"user_id":x.user_id,"emoji":x.emoji} for x in r.scalars().all()]

@app.post("/api/profile")
async def profile(request: Request, display_name: str = Form(...), bio: str = Form("")):
    user = await current_user(request)
    display_name = display_name.strip()[:80]
    bio = bio.strip()[:160]
    if not display_name:
        raise HTTPException(400, "Имя не может быть пустым")
    async with SessionLocal() as db:
        dbuser = await db.get(User, user.id)
        dbuser.display_name = display_name
        dbuser.bio = bio
        await db.commit()
        await db.refresh(dbuser)
        return user_public(dbuser, dbuser.id in connections)


@app.post("/api/avatar")
async def avatar(request: Request, file: UploadFile = File(...)):
    user = await current_user(request)
    data = await file.read()
    if len(data) > 2 * 1024 * 1024:
        raise HTTPException(400, "Аватар максимум 2 МБ")
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(400, "Аватар должен быть изображением")
    async with SessionLocal() as db:
        dbuser = await db.get(User, user.id)
        dbuser.avatar = data
        dbuser.avatar_type = file.content_type
        await db.commit()
        await send_ws(user.id, {"type": "profile", "avatar": f"/api/avatar/{user.id}"})
        return user_public(dbuser, user.id in connections)


@app.get("/api/avatar/{user_id}")
async def get_avatar(user_id: int):
    async with SessionLocal() as db:
        user = await db.get(User, user_id)
        if not user or not user.avatar:
            raise HTTPException(404)
        return Response(content=user.avatar, media_type=user.avatar_type or "image/jpeg")


@app.get("/api/file/{message_id}")
async def get_file(message_id: int):
    async with SessionLocal() as db:
        m = await db.get(Message, message_id)
        if not m or not m.file_data or m.deleted:
            raise HTTPException(404)
        return Response(
            content=m.file_data,
            media_type=m.file_type or "application/octet-stream",
            headers={"Content-Disposition": f'inline; filename="{m.file_name or "file"}"'},
        )


@app.get("/api/search")
async def search(request: Request):
    user = await current_user(request)
    q = request.query_params.get("q", "").strip()
    if len(q) < 2:
        return []
    async with SessionLocal() as db:
        result = await db.execute(
            select(Message)
            .where(
                and_(
                    or_(Message.sender_id == user.id, Message.receiver_id == user.id),
                    Message.deleted == False,
                    Message.text.ilike(f"%{q}%"),
                )
            )
            .order_by(Message.created_at.desc())
            .limit(50)
        )
        rows = result.scalars().all()
        return [msg_public(m) for m in rows]



@app.get("/api/group-file/{message_id}")
async def get_group_file(message_id:int,user:User=Depends(current_user)):
    async with SessionLocal() as db:
        m=await db.get(GroupMessage,message_id)
        if not m or not m.file_data: raise HTTPException(404)
        member=await db.scalar(select(GroupMember).where(GroupMember.group_id==m.group_id,GroupMember.user_id==user.id))
        if not member: raise HTTPException(403)
        return Response(content=m.file_data,media_type=m.file_type or "application/octet-stream",headers={"Content-Disposition":f'inline; filename="{m.file_name or "file"}"'})

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    token = ws.query_params.get("token", "")
    try:
        uid = get_user_id_from_token(token)
    except HTTPException:
        await ws.close(code=1008)
        return

    old = connections.get(uid)
    if old and old is not ws:
        try:
            await old.close()
        except Exception:
            pass
    connections[uid] = ws

    async with SessionLocal() as db:
        user = await db.get(User, uid)
        if user:
            user.last_seen = datetime.now(timezone.utc)
            await db.commit()

    await send_ws(uid, {"type": "connected", "user_id": uid})
    await broadcast_presence(uid, True)

    try:
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except Exception:
                continue

            typ = data.get("type")
            if typ == "ping":
                async with SessionLocal() as db:
                    user = await db.get(User, uid)
                    if user:
                        user.last_seen = datetime.now(timezone.utc)
                        await db.commit()
                continue

            if typ == "typing":
                # Typing state is transient: it is never written to the database.
                peer_id = int(data.get("peer_id") or 0)
                if peer_id and peer_id != uid:
                    await send_ws(peer_id, {
                        "type": "typing",
                        "user_id": uid,
                        "typing": bool(data.get("typing", False))
                    })
                continue

            if typ == "send":
                receiver_id = int(data.get("receiver_id", 0))
                text = str(data.get("text", "")).strip()
                file_b64 = data.get("file_data")
                file_name = data.get("file_name")
                file_type = data.get("file_type")
                reply_to_id = int(data.get("reply_to_id") or 0) or None
                secret = bool(data.get("secret", False))
                if not receiver_id or (not text and not file_b64):
                    continue

                file_data = None
                if file_b64:
                    try:
                        file_data = base64.b64decode(file_b64)
                    except Exception:
                        continue
                    if len(file_data) > MAX_FILE_SIZE:
                        await send_ws(uid, {"type": "error", "message": "Файл максимум 8 МБ"})
                        continue

                async with SessionLocal() as db:
                    receiver = await db.get(User, receiver_id)
                    if not receiver:
                        continue
                    if await is_blocked(db, uid, receiver_id):
                        await send_ws(uid, {"type": "error", "message": "Пользователь заблокировал вам сообщения"})
                        continue
                    await ensure_chat(db, uid, receiver_id)
                    m = Message(
                        sender_id=uid,
                        receiver_id=receiver_id,
                        text=text[:4000],
                        file_data=file_data,
                        file_name=(file_name or "")[:255] if file_name else None,
                        file_type=(file_type or "application/octet-stream")[:100] if file_data else None,
                        reply_to_id=reply_to_id,
                        secret=secret,
                    )
                    db.add(m)
                    await db.commit()
                    await db.refresh(m)
                    payload = {"type": "message", "message": msg_public(m)}
                await send_ws(uid, payload)
                await send_ws(receiver_id, payload)


            elif typ == "channel_send":
                channel_id=int(data.get("channel_id") or 0); text=str(data.get("text","")).strip()
                if not channel_id or not text: continue
                async with SessionLocal() as db:
                    member=await db.scalar(select(ChannelMember).where(ChannelMember.channel_id==channel_id,ChannelMember.user_id==uid))
                    channel=await db.get(Channel,channel_id)
                    if not member or not channel: continue
                    if channel.owner_id != uid: continue
                    cp=ChannelPost(channel_id=channel_id,sender_id=uid,text=text[:4000])
                    db.add(cp); await db.commit(); await db.refresh(cp)
                    mr=await db.execute(select(ChannelMember).where(ChannelMember.channel_id==channel_id))
                    member_ids=[x.user_id for x in mr.scalars().all()]
                    payload={"type":"channel_message","message":{"id":cp.id,"channel_id":channel_id,"sender_id":uid,"text":cp.text,"created_at":cp.created_at.isoformat(),"pinned":False}}
                for member_id in member_ids: await send_ws(member_id,payload)

            elif typ == "group_send":
                group_id=int(data.get("group_id") or 0); text=str(data.get("text","")).strip()
                reply_to_id=int(data.get("reply_to_id") or 0) or None
                if not group_id or not text: continue
                async with SessionLocal() as db:
                    member=await db.scalar(select(GroupMember).where(GroupMember.group_id==group_id,GroupMember.user_id==uid))
                    if not member: continue
                    gm=GroupMessage(group_id=group_id,sender_id=uid,text=text[:4000],reply_to_id=reply_to_id)
                    db.add(gm); await db.commit(); await db.refresh(gm)
                    mr=await db.execute(select(GroupMember).where(GroupMember.group_id==group_id))
                    member_ids=[x.user_id for x in mr.scalars().all()]
                    payload={"type":"group_message","message":{"id":gm.id,"group_id":group_id,"sender_id":uid,"text":gm.text,"created_at":gm.created_at.isoformat(),"reply_to_id":gm.reply_to_id,"pinned":False}}
                for member_id in member_ids: await send_ws(member_id,payload)

            elif typ == "call_offer" or typ == "call_answer" or typ == "call_ice":
                peer_id=int(data.get("peer_id") or 0)
                if peer_id:
                    data["from_id"]=uid
                    await send_ws(peer_id, data)

            elif typ == "read":
                message_id = int(data.get("message_id", 0))
                async with SessionLocal() as db:
                    m = await db.get(Message, message_id)
                    if m and m.receiver_id == uid and m.read_at is None:
                        m.read_at = datetime.now(timezone.utc)
                        await db.commit()
                        await send_ws(m.sender_id, {"type": "read", "message_id": m.id})

            elif typ == "edit":
                message_id = int(data.get("message_id", 0))
                new_text = str(data.get("text", "")).strip()[:4000]
                async with SessionLocal() as db:
                    m = await db.get(Message, message_id)
                    if m and m.sender_id == uid and not m.deleted and new_text:
                        m.text = new_text
                        m.edited = True
                        await db.commit()
                        payload = {"type": "message_update", "message": msg_public(m)}
                        await send_ws(m.sender_id, payload)
                        await send_ws(m.receiver_id, payload)

            elif typ == "delete":
                message_id = int(data.get("message_id", 0))
                async with SessionLocal() as db:
                    m = await db.get(Message, message_id)
                    if m and m.sender_id == uid and not m.deleted:
                        m.deleted = True
                        m.text = ""
                        m.file_data = None
                        await db.commit()
                        payload = {"type": "message_update", "message": msg_public(m)}
                        await send_ws(m.sender_id, payload)
                        await send_ws(m.receiver_id, payload)

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if connections.get(uid) is ws:
            connections.pop(uid, None)
            async with SessionLocal() as db:
                user = await db.get(User, uid)
                if user:
                    user.last_seen = datetime.now(timezone.utc)
                    await db.commit()
            await broadcast_presence(uid, False)


async def broadcast_presence(user_id: int, online: bool):
    await send_ws(user_id, {"type": "presence", "user_id": user_id, "online": online})
    for other_id in list(connections.keys()):
        if other_id != user_id:
            await send_ws(other_id, {"type": "presence", "user_id": user_id, "online": online})


HTML = r"""
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>RayfGram</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#0e1621;color:#fff;height:100vh;overflow:hidden}
button,input,textarea{font:inherit}button{cursor:pointer;border:0}.hidden{display:none!important}
#auth{height:100vh;display:grid;place-items:center;padding:20px;background:linear-gradient(145deg,#0e1621,#172b3d)}
.card{width:min(420px,100%);background:#17212b;border-radius:22px;padding:28px;box-shadow:0 20px 60px #0008}
.logo{font-size:34px;font-weight:800;margin-bottom:8px}.sub{color:#9db0bf;margin-bottom:22px}
.field{width:100%;padding:14px 15px;border-radius:12px;border:1px solid #2a3a48;background:#0e1621;color:#fff;margin:7px 0;outline:0}
.primary{background:#2aabee;color:#fff;padding:13px 18px;border-radius:12px;width:100%;font-weight:700;margin-top:8px}.switch{color:#2aabee;background:none;margin-top:14px;width:100%}
#app{height:100vh;display:flex}.sidebar{width:360px;max-width:38%;background:#17212b;border-right:1px solid #253442;display:flex;flex-direction:column}
.top{padding:13px 14px;border-bottom:1px solid #253442}.brand{font-size:23px;font-weight:800;letter-spacing:-.4px}.toprow{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.icon{background:none;color:#b8c8d3;font-size:22px;padding:7px;border-radius:9px}.icon:hover{background:#223442}
.search{background:#0e1621;border:0;border-radius:10px;color:#fff;width:100%;padding:11px 13px;outline:0}
.userlist{overflow:auto;flex:1}.user{display:flex;gap:11px;align-items:center;padding:12px 14px;border-bottom:1px solid #20303c}.user:hover,.user.active{background:#223442}
.avatar{width:48px;height:48px;border-radius:50%;background:#2aabee;display:grid;place-items:center;font-weight:800;flex:none;overflow:hidden}.avatar img{width:100%;height:100%;object-fit:cover}
.uinfo{min-width:0;flex:1}.uname{font-weight:700}.preview{color:#91a3b0;font-size:13px;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dot{width:9px;height:9px;border-radius:50%;background:#35d07f;display:inline-block;margin-right:5px}
.chat{flex:1;display:flex;flex-direction:column;min-width:0;background:#0e1621}
.chathead{
 height:64px;
 min-height:64px;
 background:#000;
 border-bottom:1px solid #171717;
 display:flex;
 align-items:center;
 padding:7px 10px 7px 8px;
 gap:10px;
 position:relative;
 z-index:5;
}
.chathead .back{
 display:none;
 width:44px;
 height:44px;
 padding:0;
 border:0;
 background:transparent;
 color:#fff;
 font-size:40px;
 line-height:40px;
 font-weight:300;
 flex:none;
}
.chathead .chat-avatar-wrap{
 flex:none;
 display:flex;
 align-items:center;
 justify-content:center;
}
.chathead .chat-avatar{
 width:44px;
 height:44px;
 border-radius:50%;
 background:#667887;
 display:grid;
 place-items:center;
 color:#17212b;
 font-size:21px;
 font-weight:800;
 overflow:hidden;
 flex:none;
}
.chathead .chat-avatar img{
 width:100%;
 height:100%;
 object-fit:cover;
}
.chathead .chat-main{
 min-width:0;
 flex:1;
 cursor:pointer;
 padding:1px 0;
}
.chatname{
 font-weight:700;
 font-size:18px;
 line-height:22px;
 color:#fff;
 white-space:nowrap;
 overflow:hidden;
 text-overflow:ellipsis;
}
.status{
 font-size:15px;
 line-height:19px;
 color:#fff;
 margin-top:0;
 white-space:nowrap;
 overflow:hidden;
 text-overflow:ellipsis;
}
.chathead .chat-menu{
 width:42px;
 height:46px;
 padding:0;
 border:0;
 background:transparent;
 color:#fff;
 font-size:31px;
 line-height:42px;
 flex:none;
}
.chathead .chat-menu:active{transform:scale(.9)}
.chat-menu + .chat-menu-panel{}

.chathead .verified-badge{vertical-align:middle;margin-left:3px}
.chathead .dot{display:none}
@media(max-width:700px){
 .chathead{
   height:58px;
   min-height:58px;
   padding:5px 7px 5px 4px;
   gap:8px;
 }
 .chathead .back{
   display:block;
 }
 .chathead .chat-avatar{
   width:42px;
   height:42px;
   font-size:20px;
 }
 .chatname{font-size:18px;line-height:21px}
 .status{font-size:15px;line-height:18px}
 .chathead .chat-menu{
   width:40px;
   height:44px;
   font-size:30px;
 }
}

.messages{flex:1;overflow:auto;display:flex;flex-direction:column;justify-content:flex-end;padding:18px 7%;background:radial-gradient(circle at 50% 20%,#162533,#0e1621 60%)}
.msgrow{display:flex;margin:5px 0;flex:none}.msgrow.mine{justify-content:flex-end}.bubble{max-width:min(72%,520px);background:#182b39;padding:8px 10px;border-radius:12px 12px 12px 3px;box-shadow:0 1px 2px #0004}.mine .bubble{background:#2b5278;border-radius:12px 12px 3px 12px}
.msgtext{white-space:pre-wrap;word-break:break-word}.meta{font-size:11px;color:#a7bac7;text-align:right;margin-top:3px}.deleted{font-style:italic;color:#91a3b0}
.file{display:block;margin:4px 0;color:#fff;text-decoration:none;background:#ffffff14;border-radius:8px;padding:9px}.file:hover{background:#ffffff22}
.composer{display:flex;gap:7px;padding:9px 12px;background:#17212b;border-top:1px solid #253442;align-items:flex-end}.attach{font-size:22px}.composer textarea{flex:1;resize:none;max-height:120px;border:0;background:#0e1621;color:#fff;border-radius:12px;padding:11px;outline:0}.send{background:#2aabee;color:#fff;border-radius:12px;padding:11px 16px;font-weight:700}
.context{position:fixed;background:#17212b;border:1px solid #2d4150;border-radius:12px;box-shadow:0 10px 35px #0008;padding:6px;z-index:20}.context button{display:block;background:none;color:#fff;padding:10px 15px;width:150px;text-align:left;border-radius:8px}.context button:hover{background:#223442}
.drawer{position:fixed;inset:0;background:#0008;z-index:10}.panel{position:absolute;right:0;top:0;height:100%;width:min(420px,92%);background:#17212b;padding:18px;overflow:auto}.panel h2{margin-top:0}.close{float:right}.profile-big{display:grid;place-items:center;margin:20px}.profile-big .avatar{width:110px;height:110px;font-size:32px}
.verified-badge{display:inline-flex;vertical-align:middle;align-items:center;justify-content:center;width:19px;height:19px;margin-left:5px;border-radius:50%;background:#2aabee;color:#fff;font-size:13px;font-weight:900;line-height:19px;position:relative;box-shadow:0 0 0 1px #0e1621}
.verified-badge::after{content:"✓";position:absolute;left:0;top:0;width:19px;height:19px;text-align:center;line-height:19px;color:#fff;font-size:13px;font-weight:900}
.profile-page{padding:8px 2px 30px;max-width:520px;margin:0 auto}
.profile-hero{width:100%;box-sizing:border-box;text-align:center;padding:18px 16px 22px;background:linear-gradient(180deg,#1d2b36 0%,#17212b 100%);border:1px solid #273946;border-radius:24px;display:flex;flex-direction:column;align-items:center;justify-content:center}
.profile-hero .profile-avatar{width:126px;height:126px;min-width:126px;margin:2px auto 16px;border-radius:50%;font-size:42px;background:#2aabee;display:flex;align-items:center;justify-content:center;overflow:hidden;font-weight:800;box-shadow:0 0 0 5px #243541,0 12px 35px #0007;align-self:center}
.profile-hero .profile-avatar img{display:block;width:100%;height:100%;object-fit:cover}
.profile-name{font-size:27px;font-weight:800;letter-spacing:-.5px;line-height:1.2;display:flex;align-items:center;justify-content:center;gap:4px;flex-wrap:wrap;width:100%}
.profile-username{color:#8ea2b1;margin-top:7px;font-size:15px;line-height:1.3;width:100%}
.profile-status{margin-top:9px;color:#8ea2b1;font-size:14px;width:100%}
.profile-actions{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin:12px 0 18px}
.profile-action{background:#22272d;border:1px solid #2b333b;color:#fff;border-radius:18px;padding:13px 7px;font-weight:700;min-height:62px}
.profile-action span{display:block;font-size:23px;margin-bottom:3px}
.profile-info{background:#171b20;border-radius:20px;overflow:hidden;border:1px solid #20262d}
.profile-row{padding:14px 16px;border-bottom:1px solid #252a30}
.profile-row:last-child{border-bottom:0}
.profile-label{font-size:13px;color:#8996a3;margin-bottom:4px}
.profile-value{font-size:16px;word-break:break-word}
.profile-verified{color:#2aabee;font-weight:700;margin-top:10px}
.profile-section{margin:16px 4px 8px;color:#8b9aa8;font-size:13px;font-weight:700}
.profile-edit .field{margin-bottom:8px}
.save{background:#2aabee;color:#fff;border-radius:10px;padding:12px;width:100%;margin-top:10px}
.toast{position:fixed;left:50%;bottom:80px;transform:translateX(-50%);background:#263b4a;color:#fff;padding:11px 16px;border-radius:10px;z-index:30;box-shadow:0 5px 25px #0008}
@media(max-width:700px){.panel{width:100%;padding:14px 16px}.drawer{background:#0e1621}.sidebar{max-width:none;width:100%}.chat{display:none}.sidebar.chat-open{display:none}.chat.chat-open{display:flex}.chathead .back{display:block}.messages{padding:14px 4%}.bubble{max-width:84%}}

.bottom-nav{display:none}
@media(max-width:700px){
 .bottom-nav{display:grid;grid-template-columns:repeat(4,1fr);gap:5px;margin:8px 10px 10px;padding:5px;background:#20262d;border:1px solid #2a3037;border-radius:28px}
 .bottom-nav button{background:transparent;color:#aeb8c1;border:0;border-radius:22px;padding:8px 3px;font-size:11px;font-weight:700}
 .bottom-nav button.active{background:#353b43;color:#fff}
 .bottom-nav .nav-ico{display:block;font-size:22px;line-height:22px;margin-bottom:2px}
}

/* ===== RayfGram Black & Gray Theme + Motion Pack ===== */
:root{
  --rg-black:#050505;
  --rg-dark:#0b0b0b;
  --rg-panel:#111111;
  --rg-panel2:#171717;
  --rg-line:#252525;
  --rg-gray:#8d8d8d;
  --rg-light:#d8d8d8;
  --rg-white:#f4f4f4;
  --rg-bubble:#1b1b1b;
  --rg-bubble-mine:#292929;
  --rg-shadow:rgba(0,0,0,.55);
}
html,body{
  background:var(--rg-black)!important;
  color:var(--rg-white)!important;
}
body{
  transition:background .35s ease,color .35s ease;
}
button,input,textarea,select{
  transition:background-color .22s ease,border-color .22s ease,color .22s ease,
              transform .16s ease,box-shadow .22s ease,opacity .22s ease;
}
button:active{transform:scale(.96)}
button:hover{filter:brightness(1.12)}
.hidden{transition:opacity .2s ease,transform .2s ease}

/* Main surfaces */
.app,.drawer,.panel,.sidebar,.chat,.auth,.modal,.settings,.profile{
  background:var(--rg-dark)!important;
  color:var(--rg-white)!important;
}
.sidebar,.chathead,.composer,.bottom-nav{
  background:var(--rg-panel)!important;
  border-color:var(--rg-line)!important;
}
.user:hover,.user.active{
  background:#1d1d1d!important;
}
.search{
  background:#151515!important;
  color:var(--rg-white)!important;
  border:1px solid #242424!important;
}
.search:focus{
  box-shadow:0 0 0 2px #3a3a3a,0 0 18px rgba(255,255,255,.06);
}

/* Remove blue/colored accents */
button,.send,.save,.icon,.chat-menu{
  color:var(--rg-white)!important;
}
.send,.save{
  background:#2b2b2b!important;
  border:1px solid #3a3a3a!important;
}
.send:hover,.save:hover{background:#3a3a3a!important}
.composer textarea{
  background:#101010!important;
  color:var(--rg-white)!important;
  border:1px solid #242424!important;
}
.bubble{
  background:var(--rg-bubble)!important;
  box-shadow:0 2px 8px var(--rg-shadow)!important;
  border:1px solid #242424;
}
.mine .bubble{
  background:var(--rg-bubble-mine)!important;
  border-color:#383838;
}
.meta,.status,.preview{color:#9b9b9b!important}
.dot{background:#bdbdbd!important;box-shadow:0 0 8px rgba(255,255,255,.28)}

.avatar,.chat-avatar{
  background:#5b5b5b!important;
  color:#111!important;
  box-shadow:0 0 0 1px #343434,0 4px 14px rgba(0,0,0,.45);
}

/* Header */
.chathead{
  background:#000!important;
  border-bottom:1px solid #202020!important;
  box-shadow:0 2px 16px rgba(0,0,0,.45);
}
.chathead .back,.chathead .chat-menu{
  color:#e8e8e8!important;
}
.chathead .chat-main:hover .chatname{
  color:#fff;
}
.chathead .status{
  transition:opacity .18s ease,transform .18s ease,color .18s ease;
}
.chathead .status:has(+ *){}


/* Messages background */
.messages{
  background:
    radial-gradient(circle at 50% 10%,#181818 0%,#0c0c0c 48%,#050505 100%)!important;
}

/* File cards / menus */
.file,.context button{
  background:#191919!important;
  color:#ddd!important;
  border-color:#2a2a2a!important;
}
.file:hover,.context button:hover{background:#262626!important}

/* ===== Animations ===== */
@keyframes rgPageIn{
  from{opacity:0;transform:translateY(8px)}
  to{opacity:1;transform:translateY(0)}
}
@keyframes rgChatOpen{
  from{opacity:0;transform:translateX(22px)}
  to{opacity:1;transform:translateX(0)}
}
@keyframes rgChatHead{
  from{opacity:0;transform:translateY(-12px)}
  to{opacity:1;transform:translateY(0)}
}
@keyframes rgAvatarIn{
  0%{opacity:0;transform:scale(.72)}
  70%{transform:scale(1.08)}
  100%{opacity:1;transform:scale(1)}
}
@keyframes rgMessageIn{
  from{opacity:0;transform:translateY(10px) scale(.97)}
  to{opacity:1;transform:translateY(0) scale(1)}
}
@keyframes rgMineIn{
  from{opacity:0;transform:translateX(14px) scale(.97)}
  to{opacity:1;transform:translateX(0) scale(1)}
}
@keyframes rgOtherIn{
  from{opacity:0;transform:translateX(-14px) scale(.97)}
  to{opacity:1;transform:translateX(0) scale(1)}
}
@keyframes rgUserIn{
  from{opacity:0;transform:translateX(-12px)}
  to{opacity:1;transform:translateX(0)}
}
@keyframes rgButtonGlow{
  0%,100%{box-shadow:0 0 0 rgba(255,255,255,0)}
  50%{box-shadow:0 0 16px rgba(255,255,255,.08)}
}
@keyframes rgPulseGray{
  0%,100%{box-shadow:0 0 0 0 rgba(220,220,220,.12)}
  50%{box-shadow:0 0 0 7px rgba(220,220,220,0)}
}
@keyframes rgSearch{
  from{transform:scale(.985);opacity:.8}
  to{transform:scale(1);opacity:1}
}
@keyframes rgBottom{
  from{opacity:0;transform:translateY(12px)}
  to{opacity:1;transform:translateY(0)}
}

.app{animation:rgPageIn .35s ease both}
.chathead{animation:rgChatHead .3s ease both}
.chat.chat-open{animation:rgChatOpen .3s cubic-bezier(.2,.8,.2,1) both}
.chat-avatar{animation:rgAvatarIn .42s cubic-bezier(.2,.8,.2,1) both}
.chatname,.status{animation:rgPageIn .35s ease .06s both}
.search:focus{animation:rgSearch .2s ease both}
.bottom-nav{animation:rgBottom .35s ease both}
.send,.save{animation:rgButtonGlow 3s ease-in-out infinite}

.msgrow{
  animation:rgMessageIn .28s ease both;
  transform-origin:bottom;
}
.msgrow.mine{animation-name:rgMineIn}
.msgrow:not(.mine){animation-name:rgOtherIn}

.user{
  animation:rgUserIn .28s ease both;
}
.user:nth-child(1){animation-delay:.02s}
.user:nth-child(2){animation-delay:.04s}
.user:nth-child(3){animation-delay:.06s}
.user:nth-child(4){animation-delay:.08s}
.user:nth-child(5){animation-delay:.10s}
.user:nth-child(6){animation-delay:.12s}
.user:nth-child(7){animation-delay:.14s}
.user:nth-child(8){animation-delay:.16s}

.dot{animation:rgPulseGray 1.8s ease-in-out infinite}
.avatar:hover,.chat-avatar:hover{
  transform:scale(1.045);
  transition:transform .2s ease,box-shadow .2s ease;
  box-shadow:0 0 0 1px #555,0 0 18px rgba(255,255,255,.08);
}
.chat-menu:hover,.back:hover{transform:scale(1.08)}
.chat-menu:active,.back:active{transform:scale(.9)}

@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{
    animation-duration:.001ms!important;
    animation-iteration-count:1!important;
    transition-duration:.001ms!important;
    scroll-behavior:auto!important;
  }
}


/* ===== RayfGram blue verification ===== */
.verified-badge{
  display:inline-flex!important;
  width:18px!important;
  height:18px!important;
  margin-left:4px!important;
  vertical-align:-3px!important;
  flex:none;
  filter:none!important;
  opacity:1!important;
  line-height:0;
  position:relative;
  animation:rgVerifiedPop .34s cubic-bezier(.2,.8,.2,1) both;
}
.verified-badge svg{
  width:18px;
  height:18px;
  display:block;
  overflow:visible;
}
.verified-badge circle{fill:#20a7ff}
.verified-badge path{
  fill:none;
  stroke:#fff;
  stroke-width:2.35;
  stroke-linecap:round;
  stroke-linejoin:round;
}
@keyframes rgVerifiedPop{
  0%{opacity:0;transform:scale(.55) rotate(-8deg)}
  65%{opacity:1;transform:scale(1.12) rotate(2deg)}
  100%{opacity:1;transform:scale(1) rotate(0)}
}
.chatname .verified-badge{
  width:18px!important;
  height:18px!important;
  vertical-align:-3px!important;
}



/* ===== RayfGram v3 Cinematic Motion Upgrade ===== */
@keyframes rgDrawerFade{from{opacity:0}to{opacity:1}}
@keyframes rgDrawerPanel{from{opacity:0;transform:translateX(34px) scale(.985)}to{opacity:1;transform:translateX(0) scale(1)}}
@keyframes rgDrawerPanelClose{from{opacity:1;transform:translateX(0) scale(1)}to{opacity:0;transform:translateX(34px) scale(.985)}}
@keyframes rgSoftRise{from{opacity:0;transform:translateY(18px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}
@keyframes rgSoftScale{0%{opacity:0;transform:scale(.88)}65%{opacity:1;transform:scale(1.035)}100%{opacity:1;transform:scale(1)}}
@keyframes rgTap{0%{transform:scale(1)}45%{transform:scale(.94)}100%{transform:scale(1)}}
@keyframes rgSendPop{0%{opacity:0;transform:translateY(8px) scale(.72)}70%{opacity:1;transform:translateY(-1px) scale(1.07)}100%{opacity:1;transform:translateY(0) scale(1)}}
@keyframes rgTypingDot{0%,60%,100%{transform:translateY(0);opacity:.35}30%{transform:translateY(-4px);opacity:1}}
@keyframes rgToastIn{from{opacity:0;transform:translate(-50%,12px) scale(.92)}to{opacity:1;transform:translate(-50%,0) scale(1)}}
@keyframes rgAuthIn{from{opacity:0;transform:translateY(22px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
@keyframes rgGlowLine{0%,100%{box-shadow:0 0 0 rgba(255,255,255,0)}50%{box-shadow:0 0 24px rgba(255,255,255,.055)}}

#auth .card{animation:rgAuthIn .5s cubic-bezier(.2,.8,.2,1) both}
.auth .field:focus,.field:focus{box-shadow:0 0 0 2px #303030,0 0 22px rgba(255,255,255,.055)!important;transform:translateY(-1px)}
.primary:active,.save:active,.send:active,.profile-action:active,.icon:active,.chat-menu:active,.back:active{animation:rgTap .18s ease both}

.drawer.rg-opening{animation:rgDrawerFade .2s ease both}
.drawer.rg-opening .panel{animation:rgDrawerPanel .3s cubic-bezier(.2,.8,.2,1) both}
.drawer.rg-closing{animation:rgDrawerFade .22s ease reverse both}
.drawer.rg-closing .panel{animation:rgDrawerPanelClose .22s ease both}

.drawer .panel h2{animation:rgSoftRise .28s ease .04s both}
.drawer .panel > .save,
.drawer .panel > .profile-actions,
.drawer .panel > .profile-info,
.drawer .panel > .profile-section{animation:rgSoftRise .28s ease both;animation-delay:calc(var(--rg-i,0) * 35ms + 70ms)}
.drawer .panel > .save:nth-of-type(1){--rg-i:1}
.drawer .panel > .save:nth-of-type(2){--rg-i:2}
.drawer .panel > .save:nth-of-type(3){--rg-i:3}
.drawer .panel > .save:nth-of-type(4){--rg-i:4}
.drawer .panel > .save:nth-of-type(5){--rg-i:5}

.profile-hero{animation:rgSoftScale .4s cubic-bezier(.2,.8,.2,1) .05s both}
.profile-hero .profile-avatar{animation:rgAvatarIn .5s cubic-bezier(.2,.8,.2,1) .1s both}
.profile-name{animation:rgSoftRise .32s ease .18s both}
.profile-username{animation:rgSoftRise .32s ease .22s both}
.profile-status{animation:rgSoftRise .32s ease .26s both}
.profile-actions{animation:rgSoftRise .32s ease .3s both}
.profile-info{animation:rgSoftRise .34s ease .34s both}

.msgrow{animation-delay:var(--rg-msg-delay,0ms)!important}
.msgrow .bubble{transition:transform .18s ease,box-shadow .18s ease}
.msgrow .bubble:hover{transform:translateY(-1px);box-shadow:0 5px 18px rgba(0,0,0,.32)!important}
.msgrow.mine .bubble:hover{transform:translateY(-1px) scale(1.008)}

.composer{animation:rgGlowLine 4s ease-in-out infinite}
.send{position:relative;overflow:hidden}
.send::after{content:"";position:absolute;inset:-40% -80%;background:linear-gradient(110deg,transparent 35%,rgba(255,255,255,.10) 50%,transparent 65%);transform:translateX(-65%);animation:rgSendShine 4.8s ease-in-out infinite;pointer-events:none}
@keyframes rgSendShine{0%,55%{transform:translateX(-65%)}75%,100%{transform:translateX(65%)}}

.chat-menu{transition:transform .16s ease,opacity .16s ease,background .16s ease!important}
.chat-menu:hover{background:#141414!important}

.toast{animation:rgToastIn .28s cubic-bezier(.2,.8,.2,1) both}

/* Typing state gets a tiny breathing motion without changing the UI. */
#chatStatus{transition:opacity .18s ease,transform .18s ease}
#chatStatus.rg-typing{animation:rgSoftRise .22s ease both;font-weight:600}

/* More natural list entrance for longer chat lists. */
.user:nth-child(9){animation-delay:.18s}.user:nth-child(10){animation-delay:.20s}.user:nth-child(11){animation-delay:.22s}.user:nth-child(12){animation-delay:.24s}.user:nth-child(13){animation-delay:.26s}.user:nth-child(14){animation-delay:.28s}.user:nth-child(15){animation-delay:.30s}

@media(prefers-reduced-motion:reduce){
  .drawer.rg-opening,.drawer.rg-closing,.drawer.rg-opening .panel,.drawer.rg-closing .panel,
  #auth .card,.profile-hero,.profile-hero .profile-avatar,.profile-name,.profile-username,.profile-status,
  .profile-actions,.profile-info,.toast,.send::after{animation:none!important}
}

</style>
</head>
<body>
<div id="auth">
 <div class="card">
  <div class="logo">✈️ RayfGram</div><div class="sub">Личный мессенджер</div>
  <div id="loginBox">
   <input id="loginUser" class="field" placeholder="Username">
   <input id="loginPass" class="field" type="password" placeholder="Пароль">
   <button class="primary" onclick="login()">Войти</button>
   <button class="switch" onclick="showRegister()">Создать аккаунт</button>
  </div>
  <div id="regBox" class="hidden">
   <input id="regName" class="field" placeholder="Имя">
   <input id="regUser" class="field" placeholder="Username">
   <input id="regPass" class="field" type="password" placeholder="Пароль (6+)">
   <button class="primary" onclick="register()">Зарегистрироваться</button>
   <button class="switch" onclick="showLogin()">У меня уже есть аккаунт</button>
  </div>
 </div>
</div>

<div id="app" class="hidden">
 <aside class="sidebar" id="sidebar">
  <div class="top">
   <div class="toprow"><span class="brand">RayfGram</span><span><button class="icon" onclick="openCommunities()">👥</button><button class="icon" onclick="searchMessages()">🔎</button><button class="icon" onclick="openProfile()">👤</button><button class="icon" onclick="openSettings()">⚙️</button></span></div>
   <input id="search" class="search" placeholder="🔍 Найти пользователя или чат" oninput="loadUsers()">
 </div>
 <div id="userlist" class="userlist"></div>
 <nav class="bottom-nav">
   <button class="active" onclick="navChats()"><span class="nav-ico">💬</span>Чаты</button>
   <button onclick="navContacts()"><span class="nav-ico">👤</span>Контакты</button>
   <button onclick="openSettings()"><span class="nav-ico">⚙️</span>Настройки</button>
   <button onclick="openProfile()"><span class="nav-ico">◉</span>Профиль</button>
 </nav>
 </aside>
 <main class="chat" id="chat">
  <div class="chathead">
   <button class="icon back" onclick="closeChat()" aria-label="Назад">‹</button>
   <div id="chatAvatarWrap" class="chat-avatar-wrap">
    <div id="chatAvatar" class="chat-avatar">?</div>
   </div>
   <div class="chat-main" onclick="selected&&openPublicProfile(selected.username)">
    <div id="chatName" class="chatname">Выберите чат</div>
    <div id="chatStatus" class="status"></div>
   </div>
   <button class="chat-menu" onclick="showChatMenu(event)" aria-label="Меню">⋮</button>
  </div>
  <div id="messages" class="messages"><div style="text-align:center;color:#718694;margin-top:30vh">Выберите пользователя 👈</div></div>
  <div class="composer">
   <input id="fileInput" type="file" hidden onchange="pickedFile()">
   <button class="icon attach" onclick="fileInput.click()">📎</button>
   <textarea id="text" rows="1" placeholder="Сообщение..." oninput="onTextInput()" onkeydown="keySend(event)"></textarea>
   <button class="icon" onclick="startVoice()">🎤</button><button class="send" onclick="sendMessage()">➤</button>
  </div>
 </main>
</div>

<div id="drawer" class="drawer hidden" onclick="if(event.target===this)closeDrawer()">
 <div class="panel">
  <button class="icon close" onclick="closeDrawer()">✕</button>
  <div id="panelContent"></div>
 </div>
</div>
<div id="toast" class="toast hidden"></div>
<div id="ctx" class="context hidden"></div>

<script>
let token=localStorage.getItem('rayf_token');
let me=null, users=[], selected=null, ws=null, reconnectTimer=null, pendingFile=null, editingId=null, pingTimer=null;
let typingTimer=null, isTyping=false, typingUserId=null;
const $=id=>document.getElementById(id);

function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function initials(u){return esc((u?.display_name||u?.username||'?').slice(0,1).toUpperCase());}
function avatarHtml(u,cls='avatar'){return u?.avatar?`<div class="${cls}"><img src="${u.avatar}?t=${Date.now()}"></div>`:`<div class="${cls}">${initials(u)}</div>`;}
function verifiedBadge(){
  return '<span class="verified-badge" title="Подтверждённый аккаунт" aria-label="Подтверждённый аккаунт"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="12"></circle><path d="M7.3 12.4l3.05 3.05 6.45-6.9"></path></svg></span>';
}
function navChats(){closeChat();loadUsers();setNav(0);}
function navContacts(){$('search').focus();$('search').value='';loadUsers();setNav(1);}
function setNav(i){document.querySelectorAll('.bottom-nav button').forEach((b,n)=>b.classList.toggle('active',n===i));}

async function api(url,opt={}){opt.headers=opt.headers||{};if(token)opt.headers.Authorization='Bearer '+token;let r=await fetch(url,opt);if(!r.ok){let t=await r.text();throw new Error(t||'Ошибка');}return r.json();}
function showToast(t){$('toast').textContent=t;$('toast').classList.remove('hidden');setTimeout(()=>$('toast').classList.add('hidden'),2500);}
function showRegister(){$('loginBox').classList.add('hidden');$('regBox').classList.remove('hidden')}
function showLogin(){$('regBox').classList.add('hidden');$('loginBox').classList.remove('hidden')}

async function login(){
 try{let fd=new FormData();fd.append('username',$('loginUser').value);fd.append('password',$('loginPass').value);if(window.loginCode)fd.append('code',window.loginCode);let r=await fetch('/api/login',{method:'POST',body:fd});if(!r.ok)throw Error(await r.text());let d=await r.json();if(d.twofa_required){let code=prompt('🔐 Введите 6-значный код 2FA');if(!code)return;window.loginCode=code;return login()}window.loginCode='';token=d.token;localStorage.setItem('rayf_token',token);await startApp()}catch(e){showToast(e.message)}
}
async function register(){
 try{let fd=new FormData();fd.append('username',$('regUser').value);fd.append('password',$('regPass').value);fd.append('display_name',$('regName').value);let r=await fetch('/api/register',{method:'POST',body:fd});if(!r.ok)throw Error(await r.text());let d=await r.json();token=d.token;localStorage.setItem('rayf_token',token);await startApp()}catch(e){showToast(e.message)}
}
async function startApp(){
 try{me=await api('/api/me');normalizeVerified(me);$('auth').classList.add('hidden');$('app').classList.remove('hidden');connect();loadUsers()}catch(e){localStorage.removeItem('rayf_token');showLogin()}
}
function connect(){
 if(ws && (ws.readyState===WebSocket.OPEN||ws.readyState===WebSocket.CONNECTING))return;
 let proto=location.protocol==='https:'?'wss':'ws';ws=new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`);
 ws.onopen=()=>{clearTimeout(reconnectTimer);clearInterval(pingTimer);pingTimer=setInterval(()=>{if(ws?.readyState===1)ws.send(JSON.stringify({type:'ping'}))},25000)};
 ws.onclose=()=>{clearTimeout(reconnectTimer);reconnectTimer=setTimeout(connect,1800)};
 ws.onmessage=e=>handleWS(JSON.parse(e.data));
}
function handleWS(d){
 if(d.type==='call_offer'||d.type==='call_answer'||d.type==='call_ice'){handleCall(d);return}
 if(d.type==='group_message'||d.type==='channel_message'){if(communityType&&((d.type==='group_message'&&communityType==='group'&&d.message.group_id===communityId)||(d.type==='channel_message'&&communityType==='channel'&&d.message.channel_id===communityId))){renderCommunityMessage(d.message);scrollBottom()}return}
 if(d.type==='error'){showToast(d.message||'Ошибка');return}
 if(d.type==='message'){let m=d.message;if(selected && (m.sender_id===selected.id||m.receiver_id===selected.id)){renderMessage(m,true)};loadUsers();notifyIfNeeded(m)}
 if(d.type==='read'){updateMessageRead(d.message_id)}
 if(d.type==='message_update'){if(selected && (d.message.sender_id===selected.id||d.message.receiver_id===selected.id))renderMessage(d.message,false);loadUsers()}
 if(d.type==='presence'){
   let u=users.find(x=>x.id===d.user_id);
   if(u){u.online=d.online;renderUsers()}
   if(selected&&selected.id===d.user_id){
     selected.online=d.online;
     if(typingUserId!==selected.id)updateHeader();
   }
 }
 if(d.type==='typing'){
   if(selected&&selected.id===d.user_id){
     typingUserId=d.typing?d.user_id:null;
     updateHeader();
     if(d.typing){
       clearTimeout(selected._typingResetTimer);
       selected._typingResetTimer=setTimeout(()=>{
         if(selected&&selected.id===d.user_id){
           typingUserId=null;
           updateHeader();
         }
       },3500);
     }
   }
 }
 if(d.type==='profile'){me.avatar=d.avatar;openProfile()}
}
function notifyIfNeeded(m){if(document.hidden && m.sender_id!==me.id && selected?.id!==m.sender_id && 'Notification' in window && Notification.permission==='granted'){new Notification('RayfGram',{body:m.text||'📎 Файл'})}}

function normalizeVerified(u){
  if(!u)return u;
  u.verified=['rayf','monk','rayfgrambot'].includes(String(u.username||'').replace(/^@/,'').toLowerCase());
  return u;
}
function renderUsers(){
 $('userlist').innerHTML=users.map(u=>`<div class="user ${selected?.id===u.id?'active':''}" onclick="selectUser(${u.id})">
 ${avatarHtml(u)}<div class="uinfo"><div class="uname">${u.online?'<span class="dot"></span>':''}${esc(u.display_name)} ${u.verified?verifiedBadge():''}</div><div class="preview">${u.blocked ? '🚫 Заблокирован' : (u.last_message ? esc(u.last_message) : '@'+esc(u.username))}</div></div></div>`).join('')||`<div style="padding:25px;color:#8193a0;text-align:center">${$('search').value.trim()?'Ничего не найдено':'Здесь пока нет чатов.<br><br>🔍 Найди пользователя через поиск и начни разговор.'}</div>`;
}
async function loadUsers(){
 try{
   const q=$('search').value.trim();
   users=q ? await api('/api/users?q='+encodeURIComponent(q)) : await api('/api/chats');
   users=users.map(normalizeVerified);
   renderUsers();
 }catch(e){}
}
async function selectUser(id){
 if(selected?.id!==id)stopTyping();
 typingUserId=null;
 selected=users.find(u=>u.id===id);if(!selected)return;
 $('sidebar').classList.add('chat-open');
 const chat=$('chat');
 chat.classList.remove('chat-open');
 void chat.offsetWidth;
 chat.classList.add('chat-open');
 updateHeader();
 await loadMessages();
 renderUsers();
}
function closeChat(){
 stopTyping();
 clearTimeout(selected?._typingResetTimer);
 typingUserId=null;
 $('sidebar').classList.remove('chat-open');
 $('chat').classList.remove('chat-open');
 selected=null;
 communityType=null;
 communityId=null;
}
function updateHeader(){
 if(!selected)return;
 const wrap=$('chatAvatarWrap');
 if(wrap)wrap.innerHTML=avatarHtml(selected,'chat-avatar').replace('class="chat-avatar"','id="chatAvatar" class="chat-avatar"');
 $('chatName').innerHTML=esc(selected.display_name||selected.username)+' '+(selected.verified?verifiedBadge():'');
 const status=$('chatStatus');
 const typing=typingUserId===selected.id;
 status.textContent = typing ? 'печатает..' : selected.online ? 'в сети' : 'был(а) недавно';
 status.classList.toggle('rg-typing',typing);
}
function showChatMenu(e){
 e?.stopPropagation();
 if(!selected)return;
 const name=esc(selected.display_name||selected.username);
 openDrawer(`<h2>⋮ ${name}</h2>
   <button class="save" onclick="openPublicProfile('${esc(selected.username)}');closeDrawer()">👤 Открыть профиль</button>
   <button class="save" style="margin-top:8px" onclick="clearChat()">🗑️ Очистить историю</button>
   <button class="save" style="margin-top:8px" onclick="deleteChat()">❌ Удалить чат</button>
   <button class="save" style="margin-top:8px" onclick="blockChatUser()">🚫 Заблокировать</button>
   <button class="save" style="margin-top:8px" onclick="toggleSecret();closeDrawer()">🔒 Секретный режим</button>`);
}
async function clearChat(){
 if(!selected)return;
 if(!confirm('Очистить историю? Все сообщения в этом чате будут удалены, но сам чат останется.'))return;
 const id=selected.id;
 try{
   await api('/api/chats/'+id+'/clear',{method:'POST'});
   $('messages').innerHTML='<div style="text-align:center;color:#718694;margin-top:30vh">История очищена</div>';
   closeDrawer();
   await loadUsers();
   selected=users.find(u=>u.id===id)||selected;
   updateHeader();
   renderUsers();
   showToast('История чата очищена');
 }catch(e){showToast(e.message)}
}
async function deleteChat(){
 if(!selected)return;
 if(!confirm('Удалить чат полностью? История сообщений и чат будут удалены.'))return;
 const id=selected.id;
 try{
   await api('/api/chats/'+id,{method:'DELETE'});
   closeDrawer();
   closeChat();
   await loadUsers();
   showToast('Чат удалён');
 }catch(e){showToast(e.message)}
}
async function blockChatUser(){
 if(!selected)return;
 if(!confirm('Заблокировать пользователя? Он больше не сможет отправлять тебе сообщения.'))return;
 const id=selected.id;
 try{
   await api('/api/chats/'+id+'/block',{method:'POST'});
   closeDrawer();
   showToast('Пользователь заблокирован');
 }catch(e){showToast(e.message)}
}
async function loadMessages(){if(!selected)return;try{let ms=await api('/api/messages/'+selected.id);$('messages').innerHTML='';ms.forEach(m=>renderMessage(m,false));scrollBottom()}catch(e){}}
function renderMessage(m,append){
 if(!selected)return;
 if(!append){let old=$(`m${m.id}`);if(old)old.remove()}
 else if($(`m${m.id}`))return;
 let row=document.createElement('div');row.className='msgrow '+(m.sender_id===me.id?'mine':'');row.id='m'+m.id;
 const delay=Math.min($('messages').children.length,12)*18;
 row.style.setProperty('--rg-msg-delay',delay+'ms');
 let time=new Date(m.created_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
 let body=m.deleted?'<span class="deleted">Сообщение удалено</span>':`${m.reply_to_id?`<div class="preview">↩️ Ответ #${m.reply_to_id}</div>`:''}${m.secret?'🔒 ':''}${m.file_url?`<a class="file" target="_blank" href="${m.file_url}">📎 ${esc(m.file_name||'Файл')}</a>`:''}${m.text?`<div class="msgtext">${esc(m.text)}</div>`:''}`;
 let checks=m.sender_id===me.id?` ${m.read?'✓✓':'✓'}`:'';
 row.innerHTML=`<div class="bubble" oncontextmenu="openContext(event,${m.id},${m.sender_id===me.id&&!m.deleted})">${body}<div class="meta">${time}${m.edited?' · изменено':''}${checks}</div></div>`;
 $('messages').appendChild(row);
 if(append){
   row.style.animation='none';
   void row.offsetWidth;
   row.style.animation='';
   scrollBottom();
 }
}
function updateMessageRead(id){let row=$(`m${id}`);if(row){let meta=row.querySelector('.meta');if(meta&&!meta.textContent.includes('✓✓'))meta.textContent+=' ✓✓'}}
function scrollBottom(){let x=$('messages');x.scrollTop=x.scrollHeight}
function sendTypingState(value){
 if(!selected||!ws||ws.readyState!==1)return;
 ws.send(JSON.stringify({type:'typing',peer_id:selected.id,typing:!!value}));
}
function stopTyping(){
 clearTimeout(typingTimer);
 if(isTyping){
   isTyping=false;
   sendTypingState(false);
 }
}
function onTextInput(){
 if(!selected||!ws||ws.readyState!==1)return;
 if(!$('text').value.trim()){
   stopTyping();
   return;
 }
 if(!isTyping){
   isTyping=true;
   sendTypingState(true);
 }
 clearTimeout(typingTimer);
 typingTimer=setTimeout(stopTyping,1800);
}
function keySend(e){
 if(e.key==='Enter'&&!e.shiftKey){
   e.preventDefault();
   stopTyping();
   sendMessage();
 }
}
function pickedFile(){pendingFile=$('fileInput').files[0]||null;if(pendingFile)showToast('Прикреплено: '+pendingFile.name)}
async function sendMessage(){
 if(communityType&&ws&&ws.readyState===1){
  let text=$('text').value.trim();if(!text)return;
  ws.send(JSON.stringify({type:communityType==='group'?'group_send':'channel_send',group_id:communityType==='group'?communityId:undefined,channel_id:communityType==='channel'?communityId:undefined,text,reply_to_id:replyToId}));
  $('text').value='';replyToId=null;return;
 }
 if(!selected||!ws||ws.readyState!==1)return;
 stopTyping();
 let text=$('text').value.trim();if(!text&&!pendingFile)return;
 if(editingId){ws.send(JSON.stringify({type:'edit',message_id:editingId,text}));editingId=null;$('text').value='';return}
 let data={type:'send',receiver_id:selected.id,text:secretMode?xorSecret(text):text,reply_to_id:replyToId,secret:secretMode};
 if(pendingFile){if(pendingFile.size>8*1024*1024){showToast('Файл максимум 8 МБ');return}let b64=await fileToBase64(pendingFile);data.file_data=b64;data.file_name=pendingFile.name;data.file_type=pendingFile.type||'application/octet-stream'}
 ws.send(JSON.stringify(data));$('text').value='';$('fileInput').value='';pendingFile=null;replyToId=null;
}
function fileToBase64(f){return new Promise((res,rej)=>{let r=new FileReader();r.onload=()=>res(r.result.split(',')[1]);r.onerror=rej;r.readAsDataURL(f)})}
function openContext(e,id,canEdit){e.preventDefault();let c=$('ctx');c.style.left=Math.min(e.clientX,innerWidth-190)+'px';c.style.top=Math.min(e.clientY,innerHeight-220)+'px';c.innerHTML='';let b=document.createElement('button');b.textContent='↩️ Ответить';b.onclick=()=>replyMessage(id);c.appendChild(b);b=document.createElement('button');b.textContent='😂 Реакция';b.onclick=()=>reactMessage(id);c.appendChild(b);b=document.createElement('button');b.textContent='📌 Закрепить';b.onclick=()=>pinMessage(id);c.appendChild(b);if(canEdit){b=document.createElement('button');b.textContent='✏️ Редактировать';b.onclick=()=>editMessage(id);c.appendChild(b);b=document.createElement('button');b.textContent='🗑️ Удалить';b.onclick=()=>deleteMessage(id);c.appendChild(b)}c.classList.remove('hidden')}
document.addEventListener('click',e=>{if(!$('ctx').contains(e.target))$('ctx').classList.add('hidden')});
function editMessage(id){$('ctx').classList.add('hidden');let row=$(`m${id}`);let t=row?.querySelector('.msgtext')?.textContent||'';$('text').value=t;editingId=id;$('text').focus();showToast('Редактирование — отправь изменённый текст')}
function deleteMessage(id){$('ctx').classList.add('hidden');if(confirm('Удалить сообщение?'))ws.send(JSON.stringify({type:'delete',message_id:id}))}

let replyToId=null, secretMode=false, mediaRecorder=null, audioChunks=[];
function replyMessage(id){$('ctx').classList.add('hidden');replyToId=id;showToast('↩️ Ответ на сообщение #'+id);$('text').focus()}
async function reactMessage(id){$('ctx').classList.add('hidden');let e=prompt('Реакция','❤️');if(!e)return;let fd=new FormData();fd.append('emoji',e);try{await api('/api/react/'+id,{method:'POST',body:fd});showToast('Реакция добавлена '+e)}catch(err){showToast(err.message)}}
async function pinMessage(id){$('ctx').classList.add('hidden');try{await api('/api/pin/'+id,{method:'POST'});loadMessages();showToast('📌 Закрепление изменено')}catch(e){showToast(e.message)}}
function toggleSecret(){secretMode=!secretMode;showToast(secretMode?'🔒 Секретный режим включён':'🔓 Секретный режим выключен')}
function xorSecret(text){let key=localStorage.getItem('rayf_secret_key');if(!key){key=prompt('Придумай общий секретный ключ для этого чата');if(!key)return text;localStorage.setItem('rayf_secret_key',key)}let out='';for(let i=0;i<text.length;i++)out+=String.fromCharCode(text.charCodeAt(i)^key.charCodeAt(i%key.length));return btoa(unescape(encodeURIComponent(out)))}
async function startVoice(){if(!selected)return;try{let stream=await navigator.mediaDevices.getUserMedia({audio:true});mediaRecorder=new MediaRecorder(stream);audioChunks=[];mediaRecorder.ondataavailable=e=>audioChunks.push(e.data);mediaRecorder.onstop=async()=>{let blob=new Blob(audioChunks,{type:'audio/webm'});pendingFile=new File([blob],'voice-message.webm',{type:'audio/webm'});await sendMessage();stream.getTracks().forEach(t=>t.stop())};mediaRecorder.start();showToast('🎤 Запись до 15 секунд…');setTimeout(()=>{if(mediaRecorder&&mediaRecorder.state==='recording')mediaRecorder.stop()},15000)}catch(e){showToast('Разреши микрофон для голосового сообщения')}}
async function startCall(){if(!selected)return;if(!window.RTCPeerConnection){showToast('Звонки не поддерживаются');return}try{const pc=new RTCPeerConnection();window.callPC=pc;const stream=await navigator.mediaDevices.getUserMedia({audio:true});stream.getTracks().forEach(t=>pc.addTrack(t,stream));pc.onicecandidate=e=>{if(e.candidate)ws.send(JSON.stringify({type:'call_ice',peer_id:selected.id,candidate:e.candidate}))};pc.ontrack=e=>{let a=document.getElementById('remoteAudio')||Object.assign(document.createElement('audio'),{id:'remoteAudio',autoplay:true});a.srcObject=e.streams[0];if(!a.parentNode)document.body.appendChild(a)};let offer=await pc.createOffer();await pc.setLocalDescription(offer);ws.send(JSON.stringify({type:'call_offer',peer_id:selected.id,sdp:offer}));showToast('📞 Звоним…')}catch(e){showToast('Разреши микрофон')}}
async function handleCall(d){if(d.type==='call_offer'){showToast('📞 Входящий звонок');if(!selected||selected.id!==d.from_id)return;try{const pc=new RTCPeerConnection();window.callPC=pc;const stream=await navigator.mediaDevices.getUserMedia({audio:true});stream.getTracks().forEach(t=>pc.addTrack(t,stream));pc.onicecandidate=e=>{if(e.candidate)ws.send(JSON.stringify({type:'call_ice',peer_id:d.from_id,candidate:e.candidate}))};pc.ontrack=e=>{let a=document.getElementById('remoteAudio')||Object.assign(document.createElement('audio'),{id:'remoteAudio',autoplay:true});a.srcObject=e.streams[0];if(!a.parentNode)document.body.appendChild(a)};await pc.setRemoteDescription(d.sdp);let ans=await pc.createAnswer();await pc.setLocalDescription(ans);ws.send(JSON.stringify({type:'call_answer',peer_id:d.from_id,sdp:ans}))}catch(e){showToast('Нет доступа к микрофону')}}if(d.type==='call_answer'&&window.callPC)await window.callPC.setRemoteDescription(d.sdp);if(d.type==='call_ice'&&window.callPC&&d.candidate)try{await window.callPC.addIceCandidate(d.candidate)}catch(e){}}
function openPublicProfile(username){
 api('/api/profile/'+encodeURIComponent(username)).then(u=>{
   normalizeVerified(u);
   const v=u.verified?verifiedBadge():'';
   openDrawer(`<div class="profile-page">
     <div class="profile-hero">
       <div class="profile-avatar">${u.avatar?`<img src="${u.avatar}?t=${Date.now()}">`:initials(u)}</div>
       <div class="profile-name">${esc(u.display_name||u.username)} ${v}</div>
       <div class="profile-username">@${esc(u.username)}</div>
       <div class="profile-status">${u.online?'🟢 в сети':'⚪ офлайн'}</div>
     </div>
     <div class="profile-actions">
       <button class="profile-action" onclick="closeDrawer();selectUser(${u.id})"><span>💬</span>Написать</button>
       <button class="profile-action" onclick="showToast('Профиль открыт')"><span>👤</span>Профиль</button>
       <button class="profile-action" onclick="showToast('Дополнительно')"><span>⋮</span>Ещё</button>
     </div>
     <div class="profile-section">Информация</div>
     <div class="profile-info">
       <div class="profile-row"><div class="profile-label">Имя пользователя</div><div class="profile-value">@${esc(u.username)}</div></div>
       <div class="profile-row"><div class="profile-label">О себе</div><div class="profile-value">${esc(u.bio||'Нет информации')}</div></div>
       <div class="profile-row"><div class="profile-label">Статус</div><div class="profile-value">${u.online?'В сети':'Не в сети'}</div></div>
     </div>
   </div>`);
 }).catch(e=>showToast(e.message))
}
function openCommunities(){openDrawer(`<h2>👥 Сообщества</h2><button class="save" onclick="createGroup()">➕ Создать группу</button><button class="save" onclick="createChannel()">📢 Создать канал</button><button class="save" onclick="joinCommunity()">🔗 Войти по invite-коду</button><div id="communityList" style="margin-top:15px"></div>`);loadCommunities()}
async function loadCommunities(){try{let gs=await api('/api/groups'),cs=await api('/api/channels');$('communityList').innerHTML='<h3>Группы</h3>'+gs.map(g=>`<div class="user" onclick="selectGroup(${g.id})"><div class="uinfo"><div>👥 ${esc(g.name)}</div><div class="preview">Invite: ${esc(g.invite_code)}</div></div></div>`).join('')+'<h3>Каналы</h3>'+cs.map(c=>`<div class="user" onclick="selectChannel(${c.id})"><div class="uinfo"><div>📢 ${esc(c.name)} @${esc(c.username)}</div><div class="preview">Invite: ${esc(c.invite_code)}</div></div></div>`).join('')||'<p>Пока пусто</p>'}catch(e){}}
async function createGroup(){let n=prompt('Название группы');if(!n)return;let fd=new FormData();fd.append('name',n);fd.append('description',prompt('Описание')||'');try{await api('/api/groups',{method:'POST',body:fd});showToast('👥 Группа создана');loadCommunities()}catch(e){showToast(e.message)}}
async function createChannel(){let n=prompt('Название канала');if(!n)return;let u=prompt('Username канала без @');if(!u)return;let fd=new FormData();fd.append('name',n);fd.append('username',u);fd.append('description',prompt('Описание')||'');try{await api('/api/channels',{method:'POST',body:fd});showToast('📢 Канал создан');loadCommunities()}catch(e){showToast(e.message)}}
async function joinCommunity(){let c=prompt('Invite-код');if(!c)return;try{await api('/api/groups/join/'+encodeURIComponent(c),{method:'POST'});showToast('Вы вошли в группу');loadCommunities();return}catch(e){}try{await api('/api/channels/join/'+encodeURIComponent(c),{method:'POST'});showToast('Вы подписались на канал');loadCommunities()}catch(e){showToast('Неверный invite-код')}}


let communityType=null, communityId=null;
async function selectGroup(id){closeDrawer();communityType='group';communityId=id;selected=null;$('sidebar').classList.add('chat-open');$('chat').classList.add('chat-open');$('chatName').textContent='👥 Группа';$('chatStatus').textContent='';try{let ms=await api('/api/groups/'+id+'/messages');$('messages').innerHTML='';ms.forEach(m=>renderCommunityMessage(m));scrollBottom()}catch(e){showToast(e.message)}}
async function selectChannel(id){closeDrawer();communityType='channel';communityId=id;selected=null;$('sidebar').classList.add('chat-open');$('chat').classList.add('chat-open');$('chatName').textContent='📢 Канал';$('chatStatus').textContent='';try{let ms=await api('/api/channels/'+id+'/messages');$('messages').innerHTML='';ms.forEach(m=>renderCommunityMessage(m));scrollBottom()}catch(e){showToast(e.message)}}
function renderCommunityMessage(m){let row=document.createElement('div');row.className='msgrow '+(m.sender_id===me.id?'mine':'');row.id='cm'+m.id;row.innerHTML=`<div class="bubble"><div class="msgtext">${esc(m.text)}</div><div class="meta">${new Date(m.created_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}${m.pinned?' · 📌':''}</div></div>`;$('messages').appendChild(row)}

let drawerCloseTimer=null;
function openDrawer(html){
 clearTimeout(drawerCloseTimer);
 const d=$('drawer');
 $('panelContent').innerHTML=html;
 d.classList.remove('hidden','rg-closing');
 void d.offsetWidth;
 d.classList.add('rg-opening');
}
function closeDrawer(){
 const d=$('drawer');
 if(d.classList.contains('hidden'))return;
 clearTimeout(drawerCloseTimer);
 d.classList.remove('rg-opening');
 d.classList.add('rg-closing');
 drawerCloseTimer=setTimeout(()=>{
   d.classList.add('hidden');
   d.classList.remove('rg-closing');
 },220);
}
function openProfile(){
 const v=me?.verified?verifiedBadge():'';
 const status=me?.online?'🟢 в сети':'⚪ офлайн';
 openDrawer(`<div class="profile-page">
   <div class="profile-hero">
     <div class="profile-avatar">${me?.avatar?`<img src="${me.avatar}?t=${Date.now()}">`:initials(me)}</div>
     <div class="profile-name">${esc(me.display_name||me.username)} ${v}</div>
     <div class="profile-username">@${esc(me.username)}</div>
     <div class="profile-status">${status}</div>
   </div>
   <div class="profile-actions">
     <button class="profile-action" onclick="avatarPick.click()"><span>📷</span>Фото</button>
     <button class="profile-action" onclick="startProfileEdit()"><span>✏️</span>Изменить</button>
     <button class="profile-action" onclick="openSettings()"><span>⚙️</span>Настройки</button>
   </div>
   <input id="avatarPick" type="file" accept="image/*" hidden onchange="uploadAvatar()">
   <div class="profile-section">Информация</div>
   <div class="profile-info">
     <div class="profile-row"><div class="profile-label">Имя пользователя</div><div class="profile-value">@${esc(me.username)}</div></div>
     <div class="profile-row"><div class="profile-label">О себе</div><div class="profile-value">${esc(me.bio||'О себе пока не заполнено')}</div></div>
     <div class="profile-row"><div class="profile-label">Аккаунт</div><div class="profile-value">${me.verified?'Подтверждённый аккаунт':'Обычный аккаунт'}</div></div>
   </div>
   <div id="profileEditBox"></div>
 </div>`);
}
function startProfileEdit(){
 const box=$('profileEditBox');
 if(!box)return;
 box.innerHTML=`<div class="profile-section">Редактирование</div>
 <div class="profile-edit"><input id="pname" class="field" value="${esc(me.display_name)}" placeholder="Имя"><textarea id="pbio" class="field" rows="4" placeholder="О себе">${esc(me.bio)}</textarea>
 <button class="save" onclick="saveProfile()">Сохранить изменения</button></div>`;
 box.scrollIntoView({behavior:'smooth'});
}
async function saveProfile(){try{let fd=new FormData();fd.append('display_name',$('pname').value);fd.append('bio',$('pbio').value);me=await api('/api/profile',{method:'POST',body:fd});showToast('Профиль сохранён');loadUsers()}catch(e){showToast(e.message)}}
async function uploadAvatar(){let f=$('avatarPick').files[0];if(!f)return;if(f.size>2*1024*1024){showToast('Аватар максимум 2 МБ');return}let fd=new FormData();fd.append('file',f);try{me=await api('/api/avatar',{method:'POST',body:fd});showToast('Аватар обновлён');openProfile();loadUsers()}catch(e){showToast(e.message)}}
async function openRayfStar(){
 try{const d=await api('/api/rayfstar');openDrawer(`<h2>⭐ RayfStar</h2><div style="text-align:center;padding:30px 10px"><div style="font-size:64px;line-height:1">⭐</div><div style="font-size:34px;font-weight:700;margin-top:18px">${d.stars}</div><div style="color:#8d8d8d;margin-top:6px">звёзд на аккаунте</div></div>`)}catch(e){showToast(e.message)}
}
function openBuyStars(){openDrawer(`<h2>⭐ Купить звёзды</h2><div style="text-align:center;padding:45px 10px;color:#8d8d8d;font-size:18px">Скоро появится</div>`)}
function openSettings(){
 openDrawer(`<h2>⚙️ Настройки</h2>
 <button class="save" onclick="openRayfStar()">⭐ RayfStar</button><button class="save" onclick="openBuyStars()">⭐ Купить звёзды</button><p>Уведомления</p><button class="save" onclick="enableNotifications()">🔔 Разрешить уведомления</button><p style="margin-top:25px">Безопасность</p><button class="save" onclick="setup2FA()">🔐 Настроить 2FA</button>
 <p style="margin-top:25px">Интерфейс</p><button class="save" onclick="document.body.classList.toggle('light');showToast('Настройка интерфейса сохранена')">🌙 Тёмная тема</button>
 <p style="color:#8da1af;margin-top:30px">RayfGram · приватный мессенджер</p>
 <button class="save" onclick="logout()">Выйти</button>`)
}
async function setup2FA(){try{let d=await api('/api/2fa/setup',{method:'POST'});let code=prompt('Секрет 2FA: '+d.secret+'\nДобавь его в Authenticator и введи текущий 6-значный код');if(!code)return;let fd=new FormData();fd.append('code',code);await api('/api/2fa/enable',{method:'POST',body:fd});showToast('🔐 2FA включена')}catch(e){showToast(e.message)}}
async function enableNotifications(){if(!('Notification'in window)){showToast('Браузер не поддерживает уведомления');return}let p=await Notification.requestPermission();showToast(p==='granted'?'Уведомления включены':'Уведомления отключены')}
function logout(){localStorage.removeItem('rayf_token');location.reload()}
async function searchMessages(){
 let q=prompt('Поиск по сообщениям');if(!q)return;try{let r=await api('/api/search?q='+encodeURIComponent(q));openDrawer('<h2>🔍 Результаты</h2>'+ (r.map(m=>`<div class="user"><div class="uinfo"><div>${esc(m.text||m.file_name||'Файл')}</div><div class="preview">${new Date(m.created_at).toLocaleString()}</div></div></div>`).join('')||'<p>Ничего не найдено</p>'))}catch(e){showToast(e.message)}
}
window.addEventListener('keydown',e=>{if(e.key==='Escape')closeDrawer()});
if(token)startApp();
</script>
</body>
</html>
"""
