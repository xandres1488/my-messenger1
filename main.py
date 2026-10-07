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

HTML = r"""
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>RayfGram</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0e1621;color:#fff;font-family:system-ui,-apple-system,Segoe UI,sans-serif}
button,input{font:inherit}
#app{min-height:100vh}
.auth{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.authbox{width:100%;max-width:390px;background:#17212b;border-radius:22px;padding:26px;box-shadow:0 20px 60px #0005}
.logo{font-size:30px;font-weight:800;margin-bottom:5px}
.sub{color:#94a3b8;margin-bottom:20px}
.auth input{width:100%;margin:7px 0;padding:14px;border:1px solid #293747;background:#0f1720;color:#fff;border-radius:12px;outline:none}
.auth input:focus{border-color:#3b9cff}
.primary{width:100%;padding:14px;margin-top:8px;border:0;border-radius:12px;background:#2481cc;color:white;font-weight:700;cursor:pointer}
.secondary{width:100%;padding:12px;margin-top:8px;border:0;border-radius:12px;background:#243342;color:#dbeafe;cursor:pointer}
.error{min-height:24px;color:#ff8b8b;margin-top:10px;font-size:14px}
.app{height:100vh;max-width:1000px;margin:auto;background:#17212b;display:flex;overflow:hidden}
.sidebar{width:310px;border-right:1px solid #263746;display:flex;flex-direction:column}
.top{padding:17px;border-bottom:1px solid #263746}
.top b{font-size:22px}
.me{color:#94a3b8;font-size:13px;margin-top:3px}
.users{overflow:auto;padding:8px}
.person{padding:13px;border-radius:14px;cursor:pointer;margin:3px 0;transition:.15s;background:#1a2632}
.person:hover{background:#223446}
.person.active{background:#2481cc}
.person b{display:block}
.person span{font-size:13px;color:#a9bacb}
.chat{flex:1;display:flex;flex-direction:column;min-width:0}
.chathead{height:68px;border-bottom:1px solid #263746;padding:10px 16px;display:flex;align-items:center;cursor:pointer}
.avatar{width:44px;height:44px;border-radius:50%;background:#2481cc;display:flex;align-items:center;justify-content:center;font-weight:800;margin-right:11px}
.chatname{font-weight:750}
.chatuser{font-size:12px;color:#a9bacb}
.messages{flex:1;overflow:auto;padding:18px}
.empty{text-align:center;color:#8294a6;margin-top:25vh}
.msg{max-width:min(75%,500px);width:max-content;padding:9px 12px;margin:7px 0;border-radius:15px;background:#263442;word-break:break-word}
.msg.mine{margin-left:auto;background:#2b75b5}
.msgtime{font-size:10px;color:#b9c9d8;margin-top:4px;text-align:right}
.composer{padding:11px;border-top:1px solid #263746;display:flex;gap:8px}
.composer input{flex:1;min-width:0;border:0;outline:none;border-radius:14px;padding:13px;background:#101922;color:white}
.send{border:0;border-radius:14px;padding:0 18px;background:#2481cc;color:white;font-size:20px;cursor:pointer}
.status{font-size:12px;color:#7f95a9;padding:0 15px 5px}
@media(max-width:700px){
 .sidebar{width:115px}
 .top{padding:12px 8px}.top b{font-size:17px}.me{font-size:10px}
 .person{padding:10px 7px}.person b{font-size:12px}.person span{font-size:10px}
 .msg{max-width:86%}
}
</style>
</head>
<body>
<div id="app"></div>
<script>
const KEY="rayfgram_token_v10";
let token=localStorage.getItem(KEY)||"";
let me=null;
let active=null;
let lastId=0;
let pollTimer=null;
let loading=false;

const app=document.getElementById("app");

function esc(v){
 return String(v??"").replace(/[&<>"']/g,c=>({
  "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
 }[c]));
}

async function api(url, options={}){
 const headers=Object.assign({},options.headers||{});
 headers["Content-Type"]="application/json";
 if(token) headers["Authorization"]="Bearer "+token;

 const response=await fetch(url,{...options,headers});
 const data=await response.json().catch(()=>({}));

 if(response.status===401){
   token="";
   localStorage.removeItem(KEY);
   showAuth("Сессия закончилась. Войдите снова.");
   throw new Error("Сессия закончилась");
 }
 if(!response.ok) throw new Error(data.detail||"Ошибка сервера");
 return data;
}

function showAuth(message=""){
 clearInterval(pollTimer);
 app.innerHTML=`
 <div class="auth"><div class="authbox">
   <div class="logo">RayfGram</div>
   <div class="sub">Надёжный вход и личные сообщения</div>
   <input id="loginUser" autocomplete="username" placeholder="Username">
   <input id="loginPass" type="password" autocomplete="current-password" placeholder="Пароль">
   <button class="primary" onclick="doLogin()">Войти</button>
   <button class="secondary" onclick="doRegister()">Создать аккаунт</button>
   <div class="error" id="authError">${esc(message)}</div>
 </div></div>`;
}

async function doLogin(){
 const error=document.getElementById("authError");
 error.textContent="Входим...";
 try{
   const data=await api("/api/login",{
     method:"POST",
     body:JSON.stringify({
       username:document.getElementById("loginUser").value,
       password:document.getElementById("loginPass").value
     })
   });
   token=data.token;
   localStorage.setItem(KEY,token);
   await startApp();
 }catch(e){error.textContent=e.message}
}

async function doRegister(){
 const error=document.getElementById("authError");
 const username=document.getElementById("loginUser").value.trim();
 const password=document.getElementById("loginPass").value;
 if(!username||!password){error.textContent="Введите username и пароль";return}
 try{
   const data=await api("/api/register",{
     method:"POST",
     body:JSON.stringify({
       username,
       password,
       display_name:username
     })
   });
   token=data.token;
   localStorage.setItem(KEY,token);
   await startApp();
 }catch(e){error.textContent=e.message}
}

async function startApp(){
 try{
   me=await api("/api/me");
   renderApp();
   await loadUsers();
   startPolling();
 }catch(e){
   token="";
   localStorage.removeItem(KEY);
   showAuth("Не удалось восстановить вход. Войдите снова.");
 }
}

function renderApp(){
 app.innerHTML=`
 <div class="app">
   <aside class="sidebar">
     <div class="top">
       <b>RayfGram</b>
       <div class="me">@${esc(me.username)}</div>
     </div>
     <div class="users" id="users"></div>
   </aside>
   <main class="chat">
     <div class="chathead" id="chatHead">
       <div class="avatar">R</div>
       <div><div class="chatname">Выберите чат</div><div class="chatuser">Выберите пользователя слева</div></div>
     </div>
     <div class="messages" id="messages"><div class="empty">Выберите пользователя, чтобы начать переписку</div></div>
     <div class="status" id="status"></div>
     <div class="composer">
       <input id="messageInput" placeholder="Сообщение..." disabled
        onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage()}">
       <button class="send" onclick="sendMessage()">➤</button>
     </div>
   </main>
 </div>`;
}

async function loadUsers(){
 const list=await api("/api/users");
 const box=document.getElementById("users");
 box.innerHTML=list.map(u=>`
   <div class="person ${active&&active.id===u.id?"active":""}" onclick="openChat(${u.id},'${esc(u.username)}','${esc(u.display_name||u.username)}')">
     <b>${esc(u.display_name||u.username)}</b>
     <span>@${esc(u.username)}</span>
   </div>`).join("");
}

async function openChat(id,username,displayName){
 active={id,username,displayName};
 lastId=0;
 document.getElementById("chatHead").innerHTML=`
   <div class="avatar">${esc((displayName||username).slice(0,1).toUpperCase())}</div>
   <div><div class="chatname">${esc(displayName||username)}</div><div class="chatuser">@${esc(username)}</div></div>`;
 document.getElementById("messages").innerHTML="";
 document.getElementById("messageInput").disabled=false;
 await loadMessages(true);
 await loadUsers();
 document.getElementById("messageInput").focus();
}

async function loadMessages(initial=false){
 if(!active||loading)return;
 loading=true;
 try{
   const rows=await api("/api/messages/"+active.id+"?after_id="+lastId);
   for(const message of rows){
     if(message.id<=lastId)continue;
     // The active chat is checked again because the user may switch chats
     // while the request was in flight.
     if(!active)break;
     appendMessage(message);
     lastId=message.id;
   }
   if(initial){
     const box=document.getElementById("messages");
     box.scrollTop=box.scrollHeight;
   }
 }catch(e){
   if(e.message!=="Сессия закончилась"){
     document.getElementById("status").textContent="Нет связи с сервером — повторяем...";
   }
 }finally{
   loading=false;
 }
}

function appendMessage(m){
 if(!active)return;
 const belongs=(m.sender_id===me.id&&m.receiver_id===active.id)||
               (m.sender_id===active.id&&m.receiver_id===me.id);
 if(!belongs)return;

 const box=document.getElementById("messages");
 const empty=box.querySelector(".empty");
 if(empty)empty.remove();

 if(box.querySelector(`[data-message-id="${m.id}"]`))return;

 const div=document.createElement("div");
 div.className="msg "+(m.sender_id===me.id?"mine":"");
 div.dataset.messageId=m.id;

 const date=m.created_at?new Date(m.created_at).toLocaleTimeString([],{
   hour:"2-digit",minute:"2-digit"
 }):"";

 div.innerHTML=`<div>${esc(m.text)}</div><div class="msgtime">${date}</div>`;
 box.appendChild(div);
 box.scrollTop=box.scrollHeight;
}

async function sendMessage(){
 if(!active)return;

 const input=document.getElementById("messageInput");
 const text=input.value.trim();
 if(!text)return;

 input.disabled=true;

 try{
   const message=await api("/api/messages",{
     method:"POST",
     body:JSON.stringify({
       receiver_id:active.id,
       text
     })
   });

   // Server has committed it before returning.
   appendMessage(message);
   lastId=Math.max(lastId,message.id);
   input.value="";
   document.getElementById("status").textContent="Доставлено на сервер";
 }catch(e){
   document.getElementById("status").textContent="Не отправлено: "+e.message;
 }finally{
   input.disabled=false;
   input.focus();
 }
}

function startPolling(){
 clearInterval(pollTimer);
 pollTimer=setInterval(()=>{
   if(active)loadMessages(false);
 },1200);
}

window.addEventListener("beforeunload",()=>clearInterval(pollTimer));

if(token)startApp();else showAuth();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML
