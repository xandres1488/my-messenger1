import os
import asyncio
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import String, Text, DateTime, ForeignKey, select, or_, and_, text as sql_text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from pwdlib import PasswordHash
import jwt

# ============================================================
# RayfGram v10 — stable login + private messages
# IMPORTANT: this version intentionally uses HTTP for messages.
# HTTP persistence is the source of truth; polling keeps chats fresh.
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing in Render Environment")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing in Render Environment")

ALGORITHM = "HS256"
TOKEN_DAYS = 30

engine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    connect_args={"command_timeout": 15},
)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
password_hash = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)

app = FastAPI(title="RayfGram Stable Messenger")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(80), default="")
    bio: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    receiver_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    text: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )


class RegisterIn(BaseModel):
    username: str
    password: str
    display_name: str = ""


class LoginIn(BaseModel):
    username: str
    password: str


class SendIn(BaseModel):
    receiver_id: int
    text: str


async def db():
    async with SessionLocal() as session:
        yield session


def normalize_username(value: str) -> str:
    return value.strip().lstrip("@").strip().lower()


def make_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=TOKEN_DAYS)).timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    session: AsyncSession = Depends(db),
) -> User:
    if not credentials:
        raise HTTPException(401, "Войдите в аккаунт")

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
        user_id = int(payload["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Сессия истекла. Войдите снова")
    except Exception:
        raise HTTPException(401, "Сессия недействительна. Войдите снова")

    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(401, "Пользователь не найден")
    return user


async def ensure_database():
    """
    Keeps the current Render database compatible with this stable build.
    Older RayfGram builds used either `password` or `password_hash`.
    We preserve existing users instead of forcing a new database.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # PostgreSQL compatibility migration.
        if engine.url.get_backend_name() == "postgresql":
            result = await conn.execute(sql_text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name='users'
            """))
            columns = {row[0] for row in result.fetchall()}

            if "password_hash" not in columns:
                await conn.execute(sql_text(
                    'ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)'
                ))
                if "password" in columns:
                    await conn.execute(sql_text(
                        'UPDATE users SET password_hash = password '
                        'WHERE password_hash IS NULL'
                    ))

            if "display_name" not in columns:
                await conn.execute(sql_text(
                    "ALTER TABLE users ADD COLUMN display_name VARCHAR(80) DEFAULT ''"
                ))

            if "bio" not in columns:
                await conn.execute(sql_text(
                    "ALTER TABLE users ADD COLUMN bio VARCHAR(160) DEFAULT ''"
                ))

            if "created_at" not in columns:
                await conn.execute(sql_text(
                    "ALTER TABLE users ADD COLUMN created_at TIMESTAMPTZ"
                ))
                await conn.execute(sql_text(
                    "UPDATE users SET created_at = NOW() WHERE created_at IS NULL"
                ))

            result = await conn.execute(sql_text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name='messages'
            """))
            msg_columns = {row[0] for row in result.fetchall()}

            if "sender_id" not in msg_columns:
                await conn.execute(sql_text(
                    "ALTER TABLE messages ADD COLUMN sender_id INTEGER"
                ))
            if "receiver_id" not in msg_columns:
                await conn.execute(sql_text(
                    "ALTER TABLE messages ADD COLUMN receiver_id INTEGER"
                ))
            if "text" not in msg_columns:
                await conn.execute(sql_text(
                    "ALTER TABLE messages ADD COLUMN text TEXT DEFAULT ''"
                ))
            if "created_at" not in msg_columns:
                await conn.execute(sql_text(
                    "ALTER TABLE messages ADD COLUMN created_at TIMESTAMPTZ"
                ))
                await conn.execute(sql_text(
                    "UPDATE messages SET created_at = NOW() WHERE created_at IS NULL"
                ))


@app.on_event("startup")
async def startup():
    await ensure_database()


@app.get("/health")
async def health():
    try:
        async with engine.connect() as conn:
            await conn.execute(sql_text("SELECT 1"))
        return {"ok": True, "database": True}
    except Exception as e:
        return {"ok": False, "database": False, "error": str(e)}


@app.post("/api/register")
async def register(data: RegisterIn, session: AsyncSession = Depends(db)):
    username = normalize_username(data.username)

    if len(username) < 3 or len(username) > 50:
        raise HTTPException(400, "Username: от 3 до 50 символов")

    if not username.replace("_", "").isalnum():
        raise HTTPException(400, "Username может содержать буквы, цифры и _")

    if len(data.password) < 6:
        raise HTTPException(400, "Пароль должен быть минимум 6 символов")

    exists = await session.scalar(
        select(User).where(User.username == username)
    )
    if exists:
        raise HTTPException(409, "Такой username уже существует")

    user = User(
        username=username,
        password_hash=password_hash.hash(data.password),
        display_name=data.display_name.strip()[:80] or username,
        bio="",
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    return {
        "token": make_token(user.id),
        "user": {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name or user.username,
        },
    }


@app.post("/api/login")
async def login(data: LoginIn, session: AsyncSession = Depends(db)):
    username = normalize_username(data.username)

    user = await session.scalar(
        select(User).where(User.username == username)
    )

    if not user:
        raise HTTPException(401, "Неверный username или пароль")

    try:
        valid = password_hash.verify(data.password, user.password_hash)
    except Exception:
        valid = False

    if not valid:
        raise HTTPException(401, "Неверный username или пароль")

    return {
        "token": make_token(user.id),
        "user": {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name or user.username,
        },
    }


@app.get("/api/me")
async def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name or user.username,
        "bio": user.bio or "",
    }


@app.get("/api/users")
async def users(
    session: AsyncSession = Depends(db),
    user: User = Depends(get_current_user),
):
    rows = (
        await session.scalars(
            select(User)
            .where(User.id != user.id)
            .order_by(User.username.asc())
        )
    ).all()

    return [
        {
            "id": u.id,
            "username": u.username,
            "display_name": u.display_name or u.username,
        }
        for u in rows
    ]


async def serialize_message(message: Message, session: AsyncSession):
    sender = await session.get(User, message.sender_id)
    receiver = await session.get(User, message.receiver_id)

    return {
        "id": message.id,
        "sender_id": message.sender_id,
        "sender_username": sender.username if sender else "",
        "sender_name": (sender.display_name or sender.username) if sender else "",
        "receiver_id": message.receiver_id,
        "receiver_username": receiver.username if receiver else "",
        "receiver_name": (receiver.display_name or receiver.username) if receiver else "",
        "text": message.text,
        "created_at": message.created_at.isoformat() if message.created_at else "",
    }


@app.get("/api/messages/{other_id}")
async def get_messages(
    other_id: int,
    after_id: int = 0,
    session: AsyncSession = Depends(db),
    user: User = Depends(get_current_user),
):
    other = await session.get(User, other_id)
    if not other:
        raise HTTPException(404, "Пользователь не найден")

    query = (
        select(Message)
        .where(
            Message.id > after_id,
            or_(
                and_(
                    Message.sender_id == user.id,
                    Message.receiver_id == other_id,
                ),
                and_(
                    Message.sender_id == other_id,
                    Message.receiver_id == user.id,
                ),
            ),
        )
        .order_by(Message.id.asc())
        .limit(300)
    )

    rows = (await session.scalars(query)).all()
    return [await serialize_message(m, session) for m in rows]


@app.post("/api/messages")
async def send_message(
    data: SendIn,
    session: AsyncSession = Depends(db),
    user: User = Depends(get_current_user),
):
    receiver = await session.get(User, data.receiver_id)

    if not receiver:
        raise HTTPException(404, "Получатель не найден")

    message_text = data.text.strip()

    if not message_text:
        raise HTTPException(400, "Нельзя отправить пустое сообщение")

    if len(message_text) > 10000:
        raise HTTPException(400, "Сообщение слишком длинное")

    if receiver.id == user.id:
        raise HTTPException(400, "Нельзя отправить сообщение самому себе")

    message = Message(
        sender_id=user.id,
        receiver_id=receiver.id,
        text=message_text,
    )

    session.add(message)

    # COMMIT happens BEFORE response.
    # Therefore a successful HTTP response means the message is in PostgreSQL.
    await session.commit()
    await session.refresh(message)

    return await serialize_message(message, session)


# ------------------------------------------------------------
# Stable frontend
# No WebSocket dependency. Messages are stored through HTTP
# and the open chat polls the server every 1.2 seconds.
# ------------------------------------------------------------


class ProfileIn(BaseModel):
    display_name: str = ""
    bio: str = ""


@app.put("/api/me")
async def update_me(
    data: ProfileIn,
    session: AsyncSession = Depends(db),
    user: User = Depends(get_current_user),
):
    user.display_name = data.display_name.strip()[:80] or user.username
    user.bio = data.bio.strip()[:160]
    await session.commit()
    await session.refresh(user)
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name or user.username,
        "bio": user.bio or "",
    }



class ProfileIn(BaseModel):
    display_name: str = ""
    bio: str = ""


@app.put("/api/me")
async def update_me(
    data: ProfileIn,
    session: AsyncSession = Depends(db),
    user: User = Depends(get_current_user),
):
    user.display_name = data.display_name.strip()[:80] or user.username
    user.bio = data.bio.strip()[:160]
    await session.commit()
    await session.refresh(user)
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name or user.username,
        "bio": user.bio or "",
    }



HTML = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>RayfGram</title>
<style>
*{box-sizing:border-box}
:root{
  --bg:#15171b;
  --panel:#1d2025;
  --panel2:#24282e;
  --panel3:#292d33;
  --line:#30343a;
  --text:#f7f7f8;
  --muted:#a8abb2;
  --soft:#777c86;
  --accent:#e8e9ec;
  --accentText:#17191c;
  --bubble:#2b2e34;
  --bubbleMine:#e8e9ec;
  --bubbleMineText:#17191c;
}
html,body{margin:0;width:100%;height:100%;background:var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;overflow:hidden}
button,input{font:inherit}
button{border:0}
#app{width:100%;height:100%}
.screen{height:100%;display:flex;flex-direction:column;background:var(--bg);overflow:hidden}
.topbar{height:76px;flex:0 0 76px;display:flex;align-items:center;padding:0 18px;gap:12px}
.brand{font-size:27px;font-weight:800;letter-spacing:-.8px;white-space:nowrap}
.brand .verified{font-size:22px;margin-left:5px;vertical-align:2px}
.top-spacer{flex:1}
.iconbtn{width:42px;height:42px;border-radius:50%;background:transparent;color:var(--text);display:flex;align-items:center;justify-content:center;cursor:pointer}
.iconbtn:active{transform:scale(.93)}
.icon{width:25px;height:25px;stroke:currentColor;stroke-width:2.2;fill:none;stroke-linecap:round;stroke-linejoin:round}
.content{flex:1;min-height:0;overflow:auto;padding:0 18px 115px}
.chat-list{display:flex;flex-direction:column;gap:4px}
.chat-row{min-height:88px;border-radius:18px;display:flex;align-items:center;padding:9px 3px;cursor:pointer;transition:.16s}
.chat-row:active{transform:scale(.985);background:#1b1e22}
.chat-avatar{width:68px;height:68px;border-radius:50%;flex:0 0 68px;margin-right:15px;display:flex;align-items:center;justify-content:center;background:#d9e4f4;color:#26313d;font-weight:800;font-size:27px;overflow:hidden}
.chat-avatar.angel{background:#dce8f7;color:#20242a}
.chat-avatar svg{width:42px;height:42px}
.chat-main{min-width:0;flex:1}
.chat-title{font-size:19px;font-weight:700;display:flex;align-items:center;gap:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chat-title .badge{font-size:20px;line-height:1}
.chat-preview{font-size:16px;color:#aeb2bb;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chat-meta{align-self:flex-start;padding-top:9px;color:#a8abb2;font-size:14px;white-space:nowrap}
.empty-large{text-align:center;color:var(--muted);padding:30vh 20px 0;font-size:16px}
.fab-stack{position:fixed;right:19px;bottom:103px;display:flex;flex-direction:column;gap:14px;align-items:center}
.fab{width:66px;height:66px;border-radius:22px;background:#24272d;color:#fff;box-shadow:0 8px 30px #0007;display:flex;align-items:center;justify-content:center;cursor:pointer}
.fab.primary{background:#fff;color:#202328;width:78px;height:78px;border-radius:26px}
.fab .icon{width:29px;height:29px}
.bottomnav{position:fixed;left:14px;right:14px;bottom:9px;height:82px;border-radius:42px;background:#24282e;display:grid;grid-template-columns:repeat(4,1fr);align-items:center;padding:6px;box-shadow:0 8px 30px #0007;z-index:20}
.navitem{height:70px;border-radius:35px;color:#f1f1f2;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;font-weight:650;font-size:15px;cursor:pointer;transition:.18s}
.navitem.active{background:#3a3e44;box-shadow:inset 0 0 0 1px #444950}
.navitem .icon{width:29px;height:29px}
.navitem:active{transform:scale(.95)}
.searchbox{display:flex;align-items:center;background:#22252a;border-radius:17px;padding:0 13px;margin:0 0 13px;height:48px}
.searchbox input{flex:1;background:transparent;border:0;outline:0;color:#fff;font-size:16px;min-width:0}
.searchbox .icon{width:22px;color:#9ca1aa;margin-right:7px}
.profile{display:flex;flex-direction:column;align-items:center;padding:12px 18px 110px;overflow:auto;height:100%}
.profile-top{width:100%;display:flex;justify-content:space-between;align-items:center;margin-bottom:2px}
.profile-top .left-icon{width:40px;height:40px}
.profile-avatar{width:174px;height:174px;border-radius:50%;background:#fff;display:flex;align-items:center;justify-content:center;color:#111;margin-top:7px;box-shadow:0 0 0 1px #2b2e34;overflow:hidden}
.profile-avatar svg{width:110px;height:110px}
.profile-name{font-size:31px;font-weight:750;letter-spacing:-.8px;margin-top:25px;text-align:center}
.profile-sub{font-size:17px;margin-top:5px;color:#f1f1f2}
.profile-actions{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;width:100%;margin-top:46px}
.profile-action{height:98px;border-radius:24px;background:#23262b;color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;font-weight:650;cursor:pointer}
.profile-action .icon{width:31px;height:31px}
.info-card{width:100%;background:#1b1d21;border-radius:26px;margin-top:44px;overflow:hidden}
.info-row{padding:16px 16px 13px;border-bottom:1px solid #2b2e33}
.info-row:last-child{border-bottom:0}
.info-value{font-size:23px;line-height:1.15}
.info-label{font-size:17px;color:#e0e1e3;margin-top:6px}
.info-row.location{position:relative;padding-right:55px}
.calendar{position:absolute;right:20px;top:36px;color:#a9acb5}
.posts-switch{margin-top:37px;background:#25292e;border-radius:24px;padding:4px;display:grid;grid-template-columns:1fr 1fr;width:min(520px,100%)}
.posts-switch button{height:54px;border-radius:20px;background:transparent;color:#fff;font-weight:700;font-size:17px}
.posts-switch button.active{background:#4a4f57}
.posts-grid{width:100%;display:grid;grid-template-columns:repeat(3,1fr);gap:2px;margin-top:24px}
.post-placeholder{aspect-ratio:1;background:#24272b;display:flex;align-items:center;justify-content:center;color:#777;font-size:12px}
.add-post{margin:28px auto 0;background:#fff;color:#222;border-radius:32px;padding:14px 27px;font-size:20px;font-weight:750;display:flex;align-items:center;gap:10px}
.page-title{font-size:27px;font-weight:800;margin:12px 0 22px}
.settings-list{display:flex;flex-direction:column;gap:9px}
.setting{background:#1d2025;border-radius:20px;padding:17px;display:flex;align-items:center;gap:14px;cursor:pointer}
.setting .round{width:48px;height:48px;border-radius:16px;background:#2a2d33;display:flex;align-items:center;justify-content:center}
.setting .text{flex:1}
.setting b{font-size:17px}.setting span{display:block;color:#9ea2aa;font-size:14px;margin-top:3px}
.contacts-grid{display:flex;flex-direction:column;gap:6px}
.contact{display:flex;align-items:center;padding:10px 3px;border-radius:18px;cursor:pointer}
.contact .mini-avatar{width:58px;height:58px;border-radius:50%;background:#dce8f7;color:#25292e;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:800;margin-right:13px}
.contact b{font-size:18px}.contact span{display:block;color:#9fa3ab;font-size:14px;margin-top:2px}
.chat-screen{height:100%;display:flex;flex-direction:column;background:var(--bg)}
.chat-head{height:76px;flex:0 0 76px;display:flex;align-items:center;padding:0 10px;gap:8px;border-bottom:1px solid #22252a}
.chat-head-main{flex:1;min-width:0;text-align:center;cursor:pointer}
.chat-head-name{font-size:18px;font-weight:750;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chat-head-user{font-size:13px;color:#a7abb3;margin-top:2px}
.chat-head .head-avatar{width:43px;height:43px;border-radius:50%;background:#dce8f7;color:#24282e;display:flex;align-items:center;justify-content:center;font-weight:800;overflow:hidden}
.chat-head .head-avatar svg{width:29px;height:29px}
.messages{flex:1;overflow:auto;padding:18px 14px 14px;display:flex;flex-direction:column}
.empty-chat{margin:auto;color:#858a93;text-align:center;padding:20px}
.msg{max-width:min(78%,520px);width:max-content;padding:10px 13px;margin:4px 0;border-radius:17px;background:var(--bubble);word-break:break-word;font-size:16px;line-height:1.3;animation:pop .18s ease}
.msg.mine{margin-left:auto;background:var(--bubbleMine);color:var(--bubbleMineText)}
.msgtime{font-size:10px;color:#92969f;margin-top:4px;text-align:right}
.composer{display:flex;gap:8px;padding:9px 12px 13px;background:var(--bg)}
.composer input{flex:1;min-width:0;border:0;outline:0;background:#22252a;color:#fff;border-radius:25px;padding:14px 18px;font-size:16px}
.send{width:53px;height:53px;border-radius:50%;background:#fff;color:#1c1e22;display:flex;align-items:center;justify-content:center;cursor:pointer}
.send .icon{width:25px;height:25px}
.status{height:0;overflow:hidden;color:#777c85;font-size:11px;text-align:center}
.back{display:none}
@keyframes pop{from{opacity:0;transform:translateY(5px) scale(.98)}to{opacity:1;transform:none}}
@media(min-width:760px){
 .screen{max-width:720px;margin:auto;border-left:1px solid #24272c;border-right:1px solid #24272c}
 .bottomnav{max-width:690px;margin:auto}
 .fab-stack{right:calc(50% - 340px)}
}
@media(max-width:420px){
 .brand{font-size:24px}
 .topbar{padding:0 13px}
 .content{padding-left:14px;padding-right:14px}
 .profile-name{font-size:28px}
 .profile-avatar{width:166px;height:166px}
 .profile-actions{gap:7px}
 .profile-action{height:94px;font-size:14px}
 .info-value{font-size:21px}
 .navitem{font-size:13px}
 .bottomnav{left:10px;right:10px;height:78px}
}
@media(prefers-reduced-motion:reduce){
 *{scroll-behavior:auto!important;animation:none!important;transition:none!important}
}
</style>
</head>
<body>
<div id="app"></div>
<script>
const KEY="rayfgram_token_v11";
let token=localStorage.getItem(KEY)||localStorage.getItem("rayfgram_token_v10")||"";
let me=null, active=null, lastId=0, pollTimer=null, loading=false, currentTab="chats";
const app=document.getElementById("app");

const icons={
 chat:`<svg class="icon" viewBox="0 0 24 24"><path d="M5 18l-2 3 4.5-1.7A9 9 0 1 0 3 12c0 2.2.8 4.2 2 6z"/><path d="M8 9h8M8 12h6"/></svg>`,
 contacts:`<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.2"/><path d="M5.5 20c.7-3.2 3-5 6.5-5s5.8 1.8 6.5 5"/><path d="M18 7.5a3 3 0 0 1 0 5.5M19 15.5c1.7.6 2.8 1.8 3.2 3.5"/></svg>`,
 settings:`<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-1.9 1.9-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5v.2h-2.7V20a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1-1.9-1.9.1-.1A1.7 1.7 0 0 0 7.7 15a1.7 1.7 0 0 0-1.5-1H6v-2.7h.2a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1 1.9-1.9.1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.5V5h2.7v.2a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1 1.9 1.9-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.5 1h.2V14h-.2a1.7 1.7 0 0 0-1.5 1z"/></svg>`,
 profile:`<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.2"/><path d="M5 21c.8-4 3.1-6 7-6s6.2 2 7 6"/></svg>`,
 search:`<svg class="icon" viewBox="0 0 24 24"><circle cx="10.8" cy="10.8" r="6.7"/><path d="M16 16l5 5"/></svg>`,
 more:`<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="5" r="1.2" fill="currentColor"/><circle cx="12" cy="12" r="1.2" fill="currentColor"/><circle cx="12" cy="19" r="1.2" fill="currentColor"/></svg>`,
 camera:`<svg class="icon" viewBox="0 0 24 24"><path d="M4 8h3l1.5-2h7L17 8h3v11H4z"/><circle cx="12" cy="13.5" r="3.5"/></svg>`,
 plus:`<svg class="icon" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>`,
 pencil:`<svg class="icon" viewBox="0 0 24 24"><path d="M4 20l4.2-1 10.7-10.7a2.1 2.1 0 0 0-3-3L5.2 16 4 20z"/><path d="M14.5 6.5l3 3"/></svg>`,
 back:`<svg class="icon" viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>`,
 send:`<svg class="icon" viewBox="0 0 24 24"><path d="M21 3L10 14"/><path d="M21 3l-7 18-4-7-7-4z"/></svg>`,
 qr:`<svg class="icon" viewBox="0 0 24 24"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 14h2v6h-2zM14 18h2v2h-2z"/></svg>`,
 calendar:`<svg class="icon" viewBox="0 0 24 24"><rect x="4" y="5" width="16" height="15" rx="2"/><path d="M8 3v4M16 3v4M4 10h16"/></svg>`
};

function angelSVG(){
 return `<svg viewBox="0 0 100 100" aria-hidden="true"><circle cx="50" cy="23" r="10" fill="currentColor"/><ellipse cx="50" cy="8" rx="11" ry="4" fill="none" stroke="currentColor" stroke-width="4"/><path d="M39 38c-10-4-17-1-22 4 5 1 8 4 10 8-3 1-6 3-8 6 8 2 15-2 20-8v31h22V48c5 6 12 10 20 8-2-3-5-5-8-6 2-4 5-7 10-8-5-5-12-8-22-4l-11 8z" fill="none" stroke="currentColor" stroke-width="5" stroke-linejoin="round"/><path d="M44 49v39M56 49v39" stroke="currentColor" stroke-width="6" stroke-linecap="round"/></svg>`;
}

function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}

async function api(url,options={}){
 const headers=Object.assign({},options.headers||{});
 if(!(options.body instanceof FormData)) headers["Content-Type"]="application/json";
 if(token) headers["Authorization"]="Bearer "+token;
 const response=await fetch(url,{...options,headers});
 const data=await response.json().catch(()=>({}));
 if(response.status===401){
   token="";localStorage.removeItem(KEY);localStorage.removeItem("rayfgram_token_v10");
   showAuth("Сессия закончилась. Войдите снова.");
   throw new Error("Сессия закончилась");
 }
 if(!response.ok)throw new Error(data.detail||"Ошибка сервера");
 return data;
}

function showAuth(message=""){
 clearInterval(pollTimer);
 app.innerHTML=`<div class="screen" style="justify-content:center;padding:22px">
  <div style="max-width:390px;width:100%;margin:auto;background:#1d2025;border-radius:28px;padding:28px;box-shadow:0 20px 60px #0008">
   <div style="font-size:34px;font-weight:850;letter-spacing:-1px">RayfGram <span class="verified">★</span></div>
   <div style="color:#a7abb2;margin:7px 0 23px">Личные сообщения без лишнего</div>
   <input id="loginUser" autocomplete="username" placeholder="@username" style="width:100%;background:#15171b;color:#fff;border:1px solid #30343a;border-radius:15px;padding:15px;outline:0;margin:6px 0">
   <input id="loginPass" type="password" autocomplete="current-password" placeholder="Пароль" style="width:100%;background:#15171b;color:#fff;border:1px solid #30343a;border-radius:15px;padding:15px;outline:0;margin:6px 0">
   <button onclick="doLogin()" style="width:100%;margin-top:10px;padding:15px;border-radius:16px;background:#fff;color:#17191c;font-weight:800;cursor:pointer">Войти</button>
   <button onclick="doRegister()" style="width:100%;margin-top:9px;padding:14px;border-radius:16px;background:#2a2d33;color:#fff;font-weight:700;cursor:pointer">Создать аккаунт</button>
   <div id="authError" style="min-height:25px;color:#ff8f8f;font-size:14px;margin-top:12px">${esc(message)}</div>
  </div>
 </div>`;
}

async function doLogin(){
 const error=document.getElementById("authError");error.textContent="Входим...";
 try{const data=await api("/api/login",{method:"POST",body:JSON.stringify({username:document.getElementById("loginUser").value,password:document.getElementById("loginPass").value})});
 token=data.token;localStorage.setItem(KEY,token);await startApp();
 }catch(e){error.textContent=e.message}
}
async function doRegister(){
 const error=document.getElementById("authError");
 const username=document.getElementById("loginUser").value.trim(),password=document.getElementById("loginPass").value;
 if(!username||!password){error.textContent="Введите username и пароль";return}
 try{const data=await api("/api/register",{method:"POST",body:JSON.stringify({username,password,display_name:username})});
 token=data.token;localStorage.setItem(KEY,token);await startApp();
 }catch(e){error.textContent=e.message}
}

async function startApp(){
 try{me=await api("/api/me");renderShell();await renderTab("chats");startPolling();}
 catch(e){token="";localStorage.removeItem(KEY);showAuth("Не удалось восстановить вход. Войдите снова.")}
}

function nav(){
 return `<nav class="bottomnav">
  <div class="navitem ${currentTab==="chats"?"active":""}" onclick="renderTab('chats')">${icons.chat}<span>Чаты</span></div>
  <div class="navitem ${currentTab==="contacts"?"active":""}" onclick="renderTab('contacts')">${icons.contacts}<span>Контакты</span></div>
  <div class="navitem ${currentTab==="settings"?"active":""}" onclick="renderTab('settings')">${icons.settings}<span>Настройки</span></div>
  <div class="navitem ${currentTab==="profile"?"active":""}" onclick="renderTab('profile')">${icons.profile}<span>Профиль</span></div>
 </nav>`;
}

function renderShell(){app.innerHTML=`<div id="view" class="screen"></div>${nav()}`;}

async function renderTab(tab){
 currentTab=tab;
 if(!document.getElementById("view"))renderShell();
 document.querySelectorAll(".navitem").forEach((n,i)=>n.classList.toggle("active",["chats","contacts","settings","profile"][i]===tab));
 if(tab==="chats")await renderChats();
 if(tab==="contacts")await renderContacts();
 if(tab==="settings")renderSettings();
 if(tab==="profile")renderProfile();
}

async function getUsers(){return await api("/api/users");}

async function renderChats(){
 active=null;lastId=0;
 const view=document.getElementById("view");
 view.innerHTML=`<div class="topbar"><div class="brand">${esc(me.display_name||me.username)} <span class="verified">★</span></div><div class="top-spacer"></div><button class="iconbtn" onclick="focusSearch()">${icons.search}</button><button class="iconbtn" onclick="showQuickMenu()">${icons.more}</button></div>
 <div class="content"><div id="chatSearch" class="searchbox" style="display:none">${icons.search}<input id="searchInput" placeholder="Поиск" oninput="filterChats(this.value)"></div><div id="chatList" class="chat-list"><div class="empty-large">Загрузка чатов…</div></div></div>
 <div class="fab-stack"><button class="fab" onclick="alert('Камера готова для следующего обновления')">${icons.camera}</button><button class="fab primary" onclick="focusSearch()">${icons.plus}</button></div>`;
 await loadChatList();
}

async function loadChatList(){
 const box=document.getElementById("chatList");if(!box)return;
 const list=await getUsers();
 box.dataset.users=JSON.stringify(list);
 drawChatList(list);
}
function drawChatList(list){
 const box=document.getElementById("chatList");if(!box)return;
 let html=`<div class="chat-row" onclick="openFavorite()"><div class="chat-avatar">${icons.chat}</div><div class="chat-main"><div class="chat-title">Избранное</div><div class="chat-preview">История очищена</div></div><div class="chat-meta">сегодня</div></div>`;
 if(list.length)html+=list.map(u=>`<div class="chat-row user-chat" data-name="${esc((u.display_name||u.username)+' '+u.username)}" onclick="openChat(${u.id},'${esc(u.username)}','${esc(u.display_name||u.username)}')">
  <div class="chat-avatar">${esc((u.display_name||u.username).slice(0,1).toUpperCase())}</div>
  <div class="chat-main"><div class="chat-title">${esc(u.display_name||u.username)}</div><div class="chat-preview">@${esc(u.username)}</div></div>
  <div class="chat-meta"></div></div>`).join("");
 else html+=`<div class="empty-large">Пока нет других пользователей</div>`;
 box.innerHTML=html;
}
function filterChats(q){
 const box=document.getElementById("chatList");if(!box)return;
 const all=JSON.parse(box.dataset.users||"[]");
 drawChatList(all.filter(u=>(u.display_name||u.username).toLowerCase().includes(q.toLowerCase())||u.username.toLowerCase().includes(q.toLowerCase())));
}
function focusSearch(){
 const s=document.getElementById("chatSearch");if(!s)return;
 s.style.display=s.style.display==="none"?"flex":"none";
 if(s.style.display!=="none")document.getElementById("searchInput").focus();
}
function showQuickMenu(){alert("Меню RayfGram")}
function openFavorite(){alert("Избранное: здесь можно хранить свои заметки в следующем обновлении")}

async function renderContacts(){
 const view=document.getElementById("view");
 view.innerHTML=`<div class="topbar"><div class="brand">Контакты</div><div class="top-spacer"></div><button class="iconbtn" onclick="focusContactSearch()">${icons.search}</button></div>
 <div class="content"><div id="contactSearch" class="searchbox" style="display:none">${icons.search}<input id="contactInput" placeholder="Поиск контактов" oninput="filterContacts(this.value)"></div><div id="contactsGrid" class="contacts-grid"></div></div>`;
 const list=await getUsers();document.getElementById("contactsGrid").dataset.users=JSON.stringify(list);drawContacts(list);
}
function drawContacts(list){
 const box=document.getElementById("contactsGrid");if(!box)return;
 box.innerHTML=list.length?list.map(u=>`<div class="contact" onclick="openChat(${u.id},'${esc(u.username)}','${esc(u.display_name||u.username)}')">
  <div class="mini-avatar">${esc((u.display_name||u.username).slice(0,1).toUpperCase())}</div>
  <div><b>${esc(u.display_name||u.username)}</b><span>@${esc(u.username)}</span></div>
 </div>`).join(""):`<div class="empty-large">Контактов пока нет</div>`;
}
function focusContactSearch(){const s=document.getElementById("contactSearch");if(!s)return;s.style.display=s.style.display==="none"?"flex":"none";if(s.style.display!=="none")document.getElementById("contactInput").focus()}
function filterContacts(q){const box=document.getElementById("contactsGrid"),all=JSON.parse(box.dataset.users||"[]");drawContacts(all.filter(u=>(u.display_name||u.username).toLowerCase().includes(q.toLowerCase())||u.username.toLowerCase().includes(q.toLowerCase())))}

function renderSettings(){
 const view=document.getElementById("view");
 view.innerHTML=`<div class="topbar"><div class="brand">Настройки</div></div><div class="content">
  <div class="settings-list">
   <div class="setting" onclick="renderProfile()"><div class="round">${icons.profile}</div><div class="text"><b>Мой профиль</b><span>Имя, username и данные</span></div>${icons.more}</div>
   <div class="setting" onclick="alert('Уведомления подключим следующим шагом')"><div class="round">${icons.chat}</div><div class="text"><b>Уведомления</b><span>Звук и сообщения</span></div>${icons.more}</div>
   <div class="setting" onclick="alert('Тема: тёмная')"><div class="round">${icons.settings}</div><div class="text"><b>Оформление</b><span>Тёмная тема RayfGram</span></div>${icons.more}</div>
   <div class="setting" onclick="logout()"><div class="round">${icons.back}</div><div class="text"><b>Выйти</b><span>Завершить текущую сессию</span></div></div>
  </div>
 </div>`;
}
function logout(){token="";localStorage.removeItem(KEY);localStorage.removeItem("rayfgram_token_v10");showAuth();}

function renderProfile(){
 const name=me.display_name||me.username;
 const verified=(me.username||"").toLowerCase()==="rayf"||(me.username||"").toLowerCase()==="monk";
 const view=document.getElementById("view");
 view.innerHTML=`<div class="profile">
  <div class="profile-top"><button class="iconbtn" onclick="renderTab('chats')">${icons.qr}</button><button class="iconbtn" onclick="showQuickMenu()">${icons.more}</button></div>
  <div class="profile-avatar">${angelSVG()}</div>
  <div class="profile-name">${esc(name)}${verified?` <span class="verified">★</span>`:""}</div>
  <div class="profile-sub">В сети</div>
  <div class="profile-actions">
   <button class="profile-action" onclick="alert('Выбор фото подключим следующим шагом')">${icons.camera}<span>Выбрать фото</span></button>
   <button class="profile-action" onclick="editProfile()">${icons.pencil}<span>Изменить</span></button>
   <button class="profile-action" onclick="renderTab('settings')">${icons.settings}<span>Настройки</span></button>
  </div>
  <div class="info-card">
   <div class="info-row"><div class="info-value">—</div><div class="info-label">Телефон</div></div>
   <div class="info-row"><div class="info-value">@${esc(me.username)}</div><div class="info-label">Имя пользователя</div></div>
   <div class="info-row location"><div class="info-value">${esc(me.bio||"RayfGram")}</div><div class="info-label">О себе</div><div class="calendar">${icons.calendar}</div></div>
  </div>
  <div class="posts-switch"><button class="active">Публикации</button><button>Архив публикаций</button></div>
  <div class="posts-grid"><div class="post-placeholder">Публикация</div></div>
  <button class="add-post" onclick="alert('Добавление публикации подключим следующим шагом')">${icons.camera} Добавить</button>
 </div>`;
}
async function editProfile(){
 const next=prompt("Какое имя показывать в профиле?",me.display_name||me.username);
 if(next===null)return;
 const bio=prompt("О себе",me.bio||"");
 try{me=await api("/api/me",{method:"PUT",body:JSON.stringify({display_name:next,bio:bio})});renderProfile();}
 catch(e){alert(e.message)}
}

async function openChat(id,username,displayName){
 clearInterval(pollTimer);
 active={id,username,displayName};lastId=0;loading=false;
 const view=document.getElementById("view");
 view.innerHTML=`<div class="chat-screen">
  <div class="chat-head"><button class="iconbtn" onclick="renderTab('chats')">${icons.back}</button>
   <div class="head-avatar">${esc((displayName||username).slice(0,1).toUpperCase())}</div>
   <div class="chat-head-main" onclick="openPersonProfile()"><div class="chat-head-name">${esc(displayName||username)}</div><div class="chat-head-user">@${esc(username)} · в сети</div></div>
   <button class="iconbtn" onclick="showQuickMenu()">${icons.more}</button>
  </div>
  <div class="messages" id="messages"><div class="empty-chat">Нет сообщений.<br>Напишите первым.</div></div>
  <div class="status" id="status"></div>
  <div class="composer"><input id="messageInput" placeholder="Сообщение..." onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage()}"><button class="send" onclick="sendMessage()">${icons.send}</button></div>
 </div>`;
 await loadMessages(true);
 document.getElementById("messageInput").focus();
 startPolling();
}
async function openPersonProfile(){
 if(!active)return;
 const name=active.displayName||active.username;
 const view=document.getElementById("view");
 view.innerHTML=`<div class="profile">
  <div class="profile-top"><button class="iconbtn" onclick="openChat(${active.id},'${esc(active.username)}','${esc(active.displayName)}')">${icons.back}</button><button class="iconbtn">${icons.more}</button></div>
  <div class="profile-avatar">${angelSVG()}</div>
  <div class="profile-name">${esc(name)}${(["rayf","monk"].includes((active.username||"").toLowerCase()))?` <span class="verified">★</span>`:""}</div>
  <div class="profile-sub">В сети</div>
  <div class="info-card" style="margin-top:38px">
   <div class="info-row"><div class="info-value">@${esc(active.username)}</div><div class="info-label">Имя пользователя</div></div>
  </div>
  <button class="add-post" style="margin-top:26px" onclick="openChat(${active.id},'${esc(active.username)}','${esc(active.displayName)}')">${icons.chat} Написать</button>
 </div>`;
}

async function loadMessages(initial=false){
 if(!active||loading)return;
 loading=true;
 try{
  const chatId=active.id;
  const rows=await api("/api/messages/"+chatId+"?after_id="+lastId);
  if(!active||active.id!==chatId)return;
  for(const m of rows){
   if(m.id<=lastId)continue;
   appendMessage(m);lastId=m.id;
  }
  if(initial){const box=document.getElementById("messages");if(box)box.scrollTop=box.scrollHeight}
 }catch(e){if(e.message!=="Сессия закончилась"){const s=document.getElementById("status");if(s)s.textContent="Нет связи — повторяем..."}}
 finally{loading=false}
}
function appendMessage(m){
 if(!active)return;
 const belongs=(m.sender_id===me.id&&m.receiver_id===active.id)||(m.sender_id===active.id&&m.receiver_id===me.id);
 if(!belongs)return;
 const box=document.getElementById("messages");if(!box)return;
 if(box.querySelector(`[data-message-id="${m.id}"]`))return;
 const empty=box.querySelector(".empty-chat");if(empty)empty.remove();
 const div=document.createElement("div");div.className="msg "+(m.sender_id===me.id?"mine":"");div.dataset.messageId=m.id;
 const date=m.created_at?new Date(m.created_at).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}):"";
 div.innerHTML=`<div>${esc(m.text)}</div><div class="msgtime">${date}</div>`;
 box.appendChild(div);box.scrollTop=box.scrollHeight;
}
async function sendMessage(){
 if(!active)return;
 const input=document.getElementById("messageInput"),text=input.value.trim();if(!text)return;
 input.disabled=true;
 try{const m=await api("/api/messages",{method:"POST",body:JSON.stringify({receiver_id:active.id,text})});appendMessage(m);lastId=Math.max(lastId,m.id);input.value=""}
 catch(e){const s=document.getElementById("status");if(s)s.textContent="Не отправлено: "+e.message}
 finally{input.disabled=false;input.focus()}
}
function startPolling(){clearInterval(pollTimer);pollTimer=setInterval(()=>{if(active)loadMessages(false)},1200)}
window.addEventListener("beforeunload",()=>clearInterval(pollTimer));
if(token)startApp();else showAuth();
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML
