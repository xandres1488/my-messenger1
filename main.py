import os
import json
import base64
import mimetypes
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

app = FastAPI(title="RayfGram 1.0")


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


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(HTML)


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
async def login(username: str = Form(...), password: str = Form(...)):
    username = username.strip().lower()
    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.username == username))
        if not user or not password_hash.verify(password, user.password_hash):
            raise HTTPException(401, "Неверный username или пароль")
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


@app.get("/api/messages/{other_id}")
async def messages(other_id: int, request: Request):
    user = await current_user(request)
    async with SessionLocal() as db:
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

            if typ == "send":
                receiver_id = int(data.get("receiver_id", 0))
                text = str(data.get("text", "")).strip()
                file_b64 = data.get("file_data")
                file_name = data.get("file_name")
                file_type = data.get("file_type")
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
                    m = Message(
                        sender_id=uid,
                        receiver_id=receiver_id,
                        text=text[:4000],
                        file_data=file_data,
                        file_name=(file_name or "")[:255] if file_name else None,
                        file_type=(file_type or "application/octet-stream")[:100] if file_data else None,
                    )
                    db.add(m)
                    await db.commit()
                    await db.refresh(m)
                    payload = {"type": "message", "message": msg_public(m)}
                await send_ws(uid, payload)
                await send_ws(receiver_id, payload)

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
<title>RayfGram 1.0</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#0e1621;color:#fff;height:100vh;overflow:hidden}
button,input,textarea{font:inherit}button{cursor:pointer;border:0}.hidden{display:none!important}
#auth{height:100vh;display:grid;place-items:center;padding:20px;background:linear-gradient(145deg,#0e1621,#172b3d)}
.card{width:min(420px,100%);background:#17212b;border-radius:22px;padding:28px;box-shadow:0 20px 60px #0008}
.logo{font-size:34px;font-weight:800;margin-bottom:8px}.sub{color:#9db0bf;margin-bottom:22px}
.field{width:100%;padding:14px 15px;border-radius:12px;border:1px solid #2a3a48;background:#0e1621;color:#fff;margin:7px 0;outline:0}
.primary{background:#2aabee;color:#fff;padding:13px 18px;border-radius:12px;width:100%;font-weight:700;margin-top:8px}.switch{color:#2aabee;background:none;margin-top:14px;width:100%}
#app{height:100vh;display:flex}.sidebar{width:360px;max-width:38%;background:#17212b;border-right:1px solid #253442;display:flex;flex-direction:column}
.top{padding:13px 14px;border-bottom:1px solid #253442}.brand{font-size:22px;font-weight:800}.toprow{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.icon{background:none;color:#b8c8d3;font-size:22px;padding:7px;border-radius:9px}.icon:hover{background:#223442}
.search{background:#0e1621;border:0;border-radius:10px;color:#fff;width:100%;padding:11px 13px;outline:0}
.userlist{overflow:auto;flex:1}.user{display:flex;gap:11px;align-items:center;padding:12px 14px;border-bottom:1px solid #20303c}.user:hover,.user.active{background:#223442}
.avatar{width:48px;height:48px;border-radius:50%;background:#2aabee;display:grid;place-items:center;font-weight:800;flex:none;overflow:hidden}.avatar img{width:100%;height:100%;object-fit:cover}
.uinfo{min-width:0;flex:1}.uname{font-weight:700}.preview{color:#91a3b0;font-size:13px;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dot{width:9px;height:9px;border-radius:50%;background:#35d07f;display:inline-block;margin-right:5px}
.chat{flex:1;display:flex;flex-direction:column;min-width:0;background:#0e1621}
.chathead{height:64px;background:#17212b;border-bottom:1px solid #253442;display:flex;align-items:center;padding:8px 14px;gap:10px}
.chathead .back{display:none}.chatname{font-weight:800}.status{font-size:12px;color:#8da1af;margin-top:3px}
.messages{flex:1;overflow:auto;padding:18px 7%;background:radial-gradient(circle at 50% 20%,#162533,#0e1621 60%)}
.msgrow{display:flex;margin:5px 0}.msgrow.mine{justify-content:flex-end}.bubble{max-width:min(72%,520px);background:#182b39;padding:8px 10px;border-radius:12px 12px 12px 3px;box-shadow:0 1px 2px #0004}.mine .bubble{background:#2b5278;border-radius:12px 12px 3px 12px}
.msgtext{white-space:pre-wrap;word-break:break-word}.meta{font-size:11px;color:#a7bac7;text-align:right;margin-top:3px}.deleted{font-style:italic;color:#91a3b0}
.file{display:block;margin:4px 0;color:#fff;text-decoration:none;background:#ffffff14;border-radius:8px;padding:9px}.file:hover{background:#ffffff22}
.composer{display:flex;gap:7px;padding:9px 12px;background:#17212b;border-top:1px solid #253442;align-items:flex-end}.attach{font-size:22px}.composer textarea{flex:1;resize:none;max-height:120px;border:0;background:#0e1621;color:#fff;border-radius:12px;padding:11px;outline:0}.send{background:#2aabee;color:#fff;border-radius:12px;padding:11px 16px;font-weight:700}
.context{position:fixed;background:#17212b;border:1px solid #2d4150;border-radius:12px;box-shadow:0 10px 35px #0008;padding:6px;z-index:20}.context button{display:block;background:none;color:#fff;padding:10px 15px;width:150px;text-align:left;border-radius:8px}.context button:hover{background:#223442}
.drawer{position:fixed;inset:0;background:#0008;z-index:10}.panel{position:absolute;right:0;top:0;height:100%;width:min(420px,92%);background:#17212b;padding:18px;overflow:auto}.panel h2{margin-top:0}.close{float:right}.profile-big{display:grid;place-items:center;margin:20px}.profile-big .avatar{width:110px;height:110px;font-size:32px}.save{background:#2aabee;color:#fff;border-radius:10px;padding:12px;width:100%;margin-top:10px}
.toast{position:fixed;left:50%;bottom:80px;transform:translateX(-50%);background:#263b4a;color:#fff;padding:11px 16px;border-radius:10px;z-index:30;box-shadow:0 5px 25px #0008}
@media(max-width:700px){.sidebar{max-width:none;width:100%}.chat{display:none}.sidebar.chat-open{display:none}.chat.chat-open{display:flex}.chathead .back{display:block}.messages{padding:14px 4%}.bubble{max-width:84%}}
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
   <div class="toprow"><span class="brand">✈️ RayfGram</span><span><button class="icon" onclick="searchMessages()">🔎</button><button class="icon" onclick="openProfile()">👤</button><button class="icon" onclick="openSettings()">⚙️</button></span></div>
   <input id="search" class="search" placeholder="🔍 Поиск" oninput="loadUsers()">
 </div>
 <div id="userlist" class="userlist"></div>
 </aside>
 <main class="chat" id="chat">
  <div class="chathead">
   <button class="icon back" onclick="closeChat()">‹</button>
   <div id="chatAvatar" class="avatar">?</div>
   <div><div id="chatName" class="chatname">Выберите чат</div><div id="chatStatus" class="status"></div></div>
  </div>
  <div id="messages" class="messages"><div style="text-align:center;color:#718694;margin-top:30vh">Выберите пользователя 👈</div></div>
  <div class="composer">
   <input id="fileInput" type="file" hidden onchange="pickedFile()">
   <button class="icon attach" onclick="fileInput.click()">📎</button>
   <textarea id="text" rows="1" placeholder="Сообщение..." onkeydown="keySend(event)"></textarea>
   <button class="send" onclick="sendMessage()">➤</button>
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
const $=id=>document.getElementById(id);

function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function initials(u){return esc((u?.display_name||u?.username||'?').slice(0,1).toUpperCase());}
function avatarHtml(u,cls='avatar'){return u?.avatar?`<div class="${cls}"><img src="${u.avatar}?t=${Date.now()}"></div>`:`<div class="${cls}">${initials(u)}</div>`;}
async function api(url,opt={}){opt.headers=opt.headers||{};if(token)opt.headers.Authorization='Bearer '+token;let r=await fetch(url,opt);if(!r.ok){let t=await r.text();throw new Error(t||'Ошибка');}return r.json();}
function showToast(t){$('toast').textContent=t;$('toast').classList.remove('hidden');setTimeout(()=>$('toast').classList.add('hidden'),2500);}
function showRegister(){$('loginBox').classList.add('hidden');$('regBox').classList.remove('hidden')}
function showLogin(){$('regBox').classList.add('hidden');$('loginBox').classList.remove('hidden')}

async function login(){
 try{let fd=new FormData();fd.append('username',$('loginUser').value);fd.append('password',$('loginPass').value);let r=await fetch('/api/login',{method:'POST',body:fd});if(!r.ok)throw Error(await r.text());let d=await r.json();token=d.token;localStorage.setItem('rayf_token',token);await startApp()}catch(e){showToast(e.message)}
}
async function register(){
 try{let fd=new FormData();fd.append('username',$('regUser').value);fd.append('password',$('regPass').value);fd.append('display_name',$('regName').value);let r=await fetch('/api/register',{method:'POST',body:fd});if(!r.ok)throw Error(await r.text());let d=await r.json();token=d.token;localStorage.setItem('rayf_token',token);await startApp()}catch(e){showToast(e.message)}
}
async function startApp(){
 try{me=await api('/api/me');$('auth').classList.add('hidden');$('app').classList.remove('hidden');connect();loadUsers()}catch(e){localStorage.removeItem('rayf_token');showLogin()}
}
function connect(){
 if(ws && (ws.readyState===WebSocket.OPEN||ws.readyState===WebSocket.CONNECTING))return;
 let proto=location.protocol==='https:'?'wss':'ws';ws=new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`);
 ws.onopen=()=>{clearTimeout(reconnectTimer);clearInterval(pingTimer);pingTimer=setInterval(()=>{if(ws?.readyState===1)ws.send(JSON.stringify({type:'ping'}))},25000)};
 ws.onclose=()=>{clearTimeout(reconnectTimer);reconnectTimer=setTimeout(connect,1800)};
 ws.onmessage=e=>handleWS(JSON.parse(e.data));
}
function handleWS(d){
 if(d.type==='message'){let m=d.message;if(selected && (m.sender_id===selected.id||m.receiver_id===selected.id)){renderMessage(m,true)};loadUsers();notifyIfNeeded(m)}
 if(d.type==='read'){updateMessageRead(d.message_id)}
 if(d.type==='message_update'){if(selected && (d.message.sender_id===selected.id||d.message.receiver_id===selected.id))renderMessage(d.message,false);loadUsers()}
 if(d.type==='presence'){let u=users.find(x=>x.id===d.user_id);if(u){u.online=d.online;renderUsers()}if(selected&&selected.id===d.user_id){selected.online=d.online;updateHeader()}}
 if(d.type==='profile'){me.avatar=d.avatar;openProfile()}
}
function notifyIfNeeded(m){if(document.hidden && m.sender_id!==me.id && selected?.id!==m.sender_id && 'Notification' in window && Notification.permission==='granted'){new Notification('RayfGram',{body:m.text||'📎 Файл'})}}
function renderUsers(){
 $('userlist').innerHTML=users.map(u=>`<div class="user ${selected?.id===u.id?'active':''}" onclick="selectUser(${u.id})">
 ${avatarHtml(u)}<div class="uinfo"><div class="uname">${u.online?'<span class="dot"></span>':''}${esc(u.display_name)}</div><div class="preview">@${esc(u.username)}</div></div></div>`).join('')||'<div style="padding:25px;color:#8193a0">Ничего не найдено</div>';
}
async function loadUsers(){try{users=await api('/api/users?q='+encodeURIComponent($('search').value));renderUsers()}catch(e){}}
async function selectUser(id){
 selected=users.find(u=>u.id===id);if(!selected)return;
 $('sidebar').classList.add('chat-open');$('chat').classList.add('chat-open');updateHeader();await loadMessages();
 renderUsers();
}
function closeChat(){$('sidebar').classList.remove('chat-open');$('chat').classList.remove('chat-open');selected=null}
function updateHeader(){if(!selected)return;$('chatAvatar').outerHTML=avatarHtml(selected,'avatar');$('chatAvatar').id='chatAvatar';$('chatName').textContent=selected.display_name;$('chatStatus').textContent=selected.online?'🟢 онлайн':'был(а) недавно'}
async function loadMessages(){if(!selected)return;try{let ms=await api('/api/messages/'+selected.id);$('messages').innerHTML='';ms.forEach(m=>renderMessage(m,false));scrollBottom()}catch(e){}}
function renderMessage(m,append){
 if(!selected)return;
 if(!append){let old=$(`m${m.id}`);if(old)old.remove()}
 else if($(`m${m.id}`))return;
 let row=document.createElement('div');row.className='msgrow '+(m.sender_id===me.id?'mine':'');row.id='m'+m.id;
 let time=new Date(m.created_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
 let body=m.deleted?'<span class="deleted">Сообщение удалено</span>':`${m.file_url?`<a class="file" target="_blank" href="${m.file_url}">📎 ${esc(m.file_name||'Файл')}</a>`:''}${m.text?`<div class="msgtext">${esc(m.text)}</div>`:''}`;
 let checks=m.sender_id===me.id?` ${m.read?'✓✓':'✓'}`:'';
 row.innerHTML=`<div class="bubble" oncontextmenu="openContext(event,${m.id},${m.sender_id===me.id&&!m.deleted})">${body}<div class="meta">${time}${m.edited?' · изменено':''}${checks}</div></div>`;
 $('messages').appendChild(row);if(append)scrollBottom()
}
function updateMessageRead(id){let row=$(`m${id}`);if(row){let meta=row.querySelector('.meta');if(meta&&!meta.textContent.includes('✓✓'))meta.textContent+=' ✓✓'}}
function scrollBottom(){let x=$('messages');x.scrollTop=x.scrollHeight}
function keySend(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage()}}
function pickedFile(){pendingFile=$('fileInput').files[0]||null;if(pendingFile)showToast('Прикреплено: '+pendingFile.name)}
async function sendMessage(){
 if(!selected||!ws||ws.readyState!==1)return;
 let text=$('text').value.trim();if(!text&&!pendingFile)return;
 if(editingId){ws.send(JSON.stringify({type:'edit',message_id:editingId,text}));editingId=null;$('text').value='';return}
 let data={type:'send',receiver_id:selected.id,text};
 if(pendingFile){if(pendingFile.size>8*1024*1024){showToast('Файл максимум 8 МБ');return}let b64=await fileToBase64(pendingFile);data.file_data=b64;data.file_name=pendingFile.name;data.file_type=pendingFile.type||'application/octet-stream'}
 ws.send(JSON.stringify(data));$('text').value='';$('fileInput').value='';pendingFile=null;
}
function fileToBase64(f){return new Promise((res,rej)=>{let r=new FileReader();r.onload=()=>res(r.result.split(',')[1]);r.onerror=rej;r.readAsDataURL(f)})}
function openContext(e,id,canEdit){e.preventDefault();let c=$('ctx');c.style.left=Math.min(e.clientX,innerWidth-165)+'px';c.style.top=Math.min(e.clientY,innerHeight-110)+'px';c.innerHTML='';if(canEdit){let b=document.createElement('button');b.textContent='✏️ Редактировать';b.onclick=()=>editMessage(id);c.appendChild(b)}if(canEdit){let b=document.createElement('button');b.textContent='🗑️ Удалить';b.onclick=()=>deleteMessage(id);c.appendChild(b)}c.classList.remove('hidden')}
document.addEventListener('click',e=>{if(!$('ctx').contains(e.target))$('ctx').classList.add('hidden')});
function editMessage(id){$('ctx').classList.add('hidden');let row=$(`m${id}`);let t=row?.querySelector('.msgtext')?.textContent||'';$('text').value=t;editingId=id;$('text').focus();showToast('Редактирование — отправь изменённый текст')}
function deleteMessage(id){$('ctx').classList.add('hidden');if(confirm('Удалить сообщение?'))ws.send(JSON.stringify({type:'delete',message_id:id}))}
function openDrawer(html){$('panelContent').innerHTML=html;$('drawer').classList.remove('hidden')}
function closeDrawer(){$('drawer').classList.add('hidden')}
function openProfile(){
 openDrawer(`<h2>👤 Профиль</h2><div class="profile-big">${avatarHtml(me,'avatar')}</div>
 <input id="avatarPick" type="file" accept="image/*" hidden onchange="uploadAvatar()"><button class="save" onclick="avatarPick.click()">📷 Изменить аватар</button>
 <label>Имя</label><input id="pname" class="field" value="${esc(me.display_name)}"><label>О себе</label><textarea id="pbio" class="field" rows="4">${esc(me.bio)}</textarea>
 <button class="save" onclick="saveProfile()">Сохранить</button><p style="color:#8da1af">@${esc(me.username)}</p>`)
}
async function saveProfile(){try{let fd=new FormData();fd.append('display_name',$('pname').value);fd.append('bio',$('pbio').value);me=await api('/api/profile',{method:'POST',body:fd});showToast('Профиль сохранён');loadUsers()}catch(e){showToast(e.message)}}
async function uploadAvatar(){let f=$('avatarPick').files[0];if(!f)return;if(f.size>2*1024*1024){showToast('Аватар максимум 2 МБ');return}let fd=new FormData();fd.append('file',f);try{me=await api('/api/avatar',{method:'POST',body:fd});showToast('Аватар обновлён');openProfile();loadUsers()}catch(e){showToast(e.message)}}
function openSettings(){
 openDrawer(`<h2>⚙️ Настройки</h2>
 <p>Уведомления</p><button class="save" onclick="enableNotifications()">🔔 Разрешить уведомления</button>
 <p style="margin-top:25px">Интерфейс</p><button class="save" onclick="document.body.classList.toggle('light');showToast('Настройка интерфейса сохранена')">🌙 Тёмная тема</button>
 <p style="color:#8da1af;margin-top:30px">RayfGram 1.0 · приватный мессенджер</p>
 <button class="save" onclick="logout()">Выйти</button>`)
}
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
