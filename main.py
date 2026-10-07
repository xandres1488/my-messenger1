import os
import asyncio
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import String, Text, DateTime, ForeignKey, select, or_, and_, UniqueConstraint
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from pwdlib import PasswordHash
import jwt

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./rayfgram.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret")
ALGORITHM = "HS256"

# For SQLite local testing; Render PostgreSQL works through DATABASE_URL.
engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
password_hash = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)

app = FastAPI(title="RayfGram Messenger")

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(100), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    receiver_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

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

def make_token(user_id: int) -> str:
    return jwt.encode({"sub": str(user_id)}, SECRET_KEY, algorithm=ALGORITHM)

async def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    session: AsyncSession = Depends(db),
) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Необходим вход")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Неверный токен")
    user = await session.get(User, uid)
    if not user:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    return user

async def message_json(m: Message, session: AsyncSession):
    sender = await session.get(User, m.sender_id)
    receiver = await session.get(User, m.receiver_id)
    return {
        "id": m.id,
        "sender_id": m.sender_id,
        "sender_username": sender.username if sender else "",
        "sender_name": sender.display_name if sender else "",
        "receiver_id": m.receiver_id,
        "receiver_username": receiver.username if receiver else "",
        "receiver_name": receiver.display_name if receiver else "",
        "text": m.text,
        "created_at": m.created_at.isoformat(),
    }

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.get("/health")
async def health():
    return {"ok": True}

@app.post("/api/register")
async def register(data: RegisterIn, session: AsyncSession = Depends(db)):
    username = data.username.strip().lstrip("@").lower()
    if len(username) < 3 or len(username) > 50:
        raise HTTPException(400, "Username должен быть от 3 до 50 символов")
    if len(data.password) < 6:
        raise HTTPException(400, "Пароль минимум 6 символов")
    exists = await session.scalar(select(User).where(User.username == username))
    if exists:
        raise HTTPException(409, "Такой username уже занят")
    user = User(
        username=username,
        password=password_hash.hash(data.password),
        display_name=data.display_name.strip() or username,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return {"token": make_token(user.id), "user": {"id": user.id, "username": user.username, "display_name": user.display_name}}

@app.post("/api/login")
async def login(data: LoginIn, session: AsyncSession = Depends(db)):
    username = data.username.strip().lstrip("@").lower()
    user = await session.scalar(select(User).where(User.username == username))
    if not user or not password_hash.verify(data.password, user.password):
        raise HTTPException(401, "Неверный username или пароль")
    return {"token": make_token(user.id), "user": {"id": user.id, "username": user.username, "display_name": user.display_name}}

@app.get("/api/me")
async def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "display_name": user.display_name}

@app.get("/api/users")
async def users(session: AsyncSession = Depends(db), user: User = Depends(current_user)):
    rows = (await session.scalars(select(User).where(User.id != user.id).order_by(User.username))).all()
    return [{"id": u.id, "username": u.username, "display_name": u.display_name} for u in rows]

@app.get("/api/messages/{other_id}")
async def get_messages(other_id: int, after_id: int = 0, session: AsyncSession = Depends(db), user: User = Depends(current_user)):
    other = await session.get(User, other_id)
    if not other:
        raise HTTPException(404, "Пользователь не найден")
    q = select(Message).where(
        or_(
            and_(Message.sender_id == user.id, Message.receiver_id == other_id),
            and_(Message.sender_id == other_id, Message.receiver_id == user.id),
        ),
        Message.id > after_id,
    ).order_by(Message.id.asc()).limit(200)
    rows = (await session.scalars(q)).all()
    return [await message_json(m, session) for m in rows]

class ConnectionManager:
    def __init__(self):
        self.connections: dict[int, set[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, uid: int, ws: WebSocket):
        await ws.accept()
        async with self.lock:
            self.connections.setdefault(uid, set()).add(ws)

    async def disconnect(self, uid: int, ws: WebSocket):
        async with self.lock:
            group = self.connections.get(uid)
            if group:
                group.discard(ws)
                if not group:
                    self.connections.pop(uid, None)

    async def send_to_user(self, uid: int, data: dict):
        async with self.lock:
            sockets = list(self.connections.get(uid, set()))
        dead = []
        for ws in sockets:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(uid, ws)

manager = ConnectionManager()

@app.post("/api/messages")
async def send_message(data: SendIn, session: AsyncSession = Depends(db), user: User = Depends(current_user)):
    text = data.text.strip()
    if not text:
        raise HTTPException(400, "Пустое сообщение")
    if len(text) > 10000:
        raise HTTPException(400, "Сообщение слишком длинное")
    receiver = await session.get(User, data.receiver_id)
    if not receiver:
        raise HTTPException(404, "Получатель не найден")
    if receiver.id == user.id:
        raise HTTPException(400, "Нельзя отправить сообщение самому себе")

    msg = Message(sender_id=user.id, receiver_id=receiver.id, text=text)
    session.add(msg)
    await session.commit()
    await session.refresh(msg)
    payload = await message_json(msg, session)

    # Send to all active connections of the receiver and sender.
    await manager.send_to_user(receiver.id, {"type": "message", "message": payload})
    await manager.send_to_user(user.id, {"type": "message", "message": payload})
    return payload

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    token = ws.query_params.get("token")
    if not token:
        await ws.close(code=1008)
        return
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload["sub"])
    except Exception:
        await ws.close(code=1008)
        return

    await manager.connect(uid, ws)
    try:
        while True:
            # Keep the connection alive. Client can send ping.
            await ws.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(uid, ws)
    except Exception:
        await manager.disconnect(uid, ws)

HTML = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RayfGram</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#101318;color:#fff}
.wrap{max-width:900px;margin:auto;height:100vh;display:flex;background:#151a21}
.sidebar{width:290px;border-right:1px solid #29303a;padding:14px;overflow:auto}.chat{flex:1;display:flex;flex-direction:column}
h2{margin:4px 0 14px}.user{padding:12px;border-radius:12px;margin:4px 0;background:#1c222b;cursor:pointer}.user:hover{background:#252d38}
.head{padding:14px 18px;border-bottom:1px solid #29303a;font-weight:700}.msgs{flex:1;overflow:auto;padding:18px}
.msg{max-width:72%;padding:9px 12px;margin:7px 0;border-radius:14px;background:#252c36}.mine{margin-left:auto;background:#245b9e}
.name{font-size:12px;opacity:.7;margin-bottom:3px}.composer{display:flex;padding:12px;border-top:1px solid #29303a;gap:8px}.composer input{flex:1;padding:12px;border:0;border-radius:12px;background:#202631;color:#fff}.composer button{border:0;border-radius:12px;padding:0 18px;background:#3487e8;color:#fff}
.auth{max-width:380px;margin:80px auto;padding:25px;background:#1a2028;border-radius:18px}.auth input,.auth button{width:100%;padding:13px;margin:6px 0;border-radius:10px;border:0}.auth button{background:#3487e8;color:white}
@media(max-width:650px){.sidebar{width:105px}.sidebar .title{font-size:13px}.user{font-size:12px}.wrap{width:100%}}
</style>
</head>
<body>
<div id="app"></div>
<script>
let token=localStorage.getItem("rayf_token"), me=null, active=null, ws=null, lastId=0, poll=null;

const app=document.getElementById("app");
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}

function auth(){
 app.innerHTML=`<div class="auth"><h2>RayfGram</h2>
 <input id="u" placeholder="username"><input id="p" type="password" placeholder="пароль">
 <button onclick="login()">Войти</button><button onclick="register()">Создать аккаунт</button>
 <div id="err"></div></div>`;
}
async function api(url,opt={}){
 opt.headers=Object.assign({"Content-Type":"application/json"},opt.headers||{});
 if(token) opt.headers.Authorization="Bearer "+token;
 const r=await fetch(url,opt), data=await r.json().catch(()=>({}));
 if(!r.ok) throw Error(data.detail||"Ошибка");
 return data;
}
async function login(){
 try{let d=await api("/api/login",{method:"POST",body:JSON.stringify({username:u.value,password:p.value})});token=d.token;localStorage.setItem("rayf_token",token);start();}
 catch(e){err.textContent=e.message}
}
async function register(){
 try{let d=await api("/api/register",{method:"POST",body:JSON.stringify({username:u.value,password:p.value,display_name:u.value})});token=d.token;localStorage.setItem("rayf_token",token);start();}
 catch(e){err.textContent=e.message}
}
async function start(){
 try{me=await api("/api/me");render();connectWS();}catch(e){localStorage.removeItem("rayf_token");token=null;auth();}
}
function render(){
 app.innerHTML=`<div class="wrap"><aside class="sidebar"><div class="title"><h2>RayfGram</h2></div><div id="users"></div></aside>
 <main class="chat"><div class="head" id="head">Выберите чат</div><div class="msgs" id="msgs"></div>
 <div class="composer"><input id="text" placeholder="Сообщение..." onkeydown="if(event.key==='Enter')send()"><button onclick="send()">➤</button></div></main></div>`;
 loadUsers();
}
async function loadUsers(){
 let list=await api("/api/users");users.innerHTML=list.map(u=>`<div class="user" onclick="openChat(${u.id},'${esc(u.username)}')"><b>${esc(u.display_name||u.username)}</b><br><small>@${esc(u.username)}</small></div>`).join("");
}
async function openChat(id,username){
 active={id,username};lastId=0;head.textContent=username;msgs.innerHTML="";
 await loadMessages(); startPolling();
}
async function loadMessages(){
 if(!active)return;
 try{
  let rows=await api("/api/messages/"+active.id+"?after_id="+lastId);
  for(const m of rows){if(m.id<=lastId)continue;append(m);lastId=m.id;}
 }catch(e){}
}
function append(m){
 if(!active || (m.sender_id!==active.id && m.receiver_id!==active.id))return;
 const div=document.createElement("div");div.className="msg "+(m.sender_id===me.id?"mine":"");
 div.innerHTML=`<div class="name">${esc(m.sender_name||m.sender_username)}</div>${esc(m.text)}`;
 msgs.appendChild(div);msgs.scrollTop=msgs.scrollHeight;
}
async function send(){
 if(!active)return;
 const input=document.getElementById("text"), value=input.value.trim();if(!value)return;
 input.value="";
 try{let m=await api("/api/messages",{method:"POST",body:JSON.stringify({receiver_id:active.id,text:value})});if(m.id>lastId){append(m);lastId=m.id;}}
 catch(e){alert(e.message);input.value=value}
}
function connectWS(){
 if(ws && (ws.readyState===0||ws.readyState===1))return;
 ws=new WebSocket((location.protocol==="https:"?"wss://":"ws://")+location.host+"/ws?token="+encodeURIComponent(token));
 ws.onmessage=e=>{let d=JSON.parse(e.data);if(d.type==="message"){let m=d.message;if(active && ((m.sender_id===me.id&&m.receiver_id===active.id)||(m.sender_id===active.id&&m.receiver_id===me.id)) && m.id>lastId){append(m);lastId=m.id;} loadUsers();}};
 ws.onclose=()=>setTimeout(connectWS,1500);
 ws.onerror=()=>{try{ws.close()}catch{}};
}
function startPolling(){clearInterval(poll);poll=setInterval(()=>{loadMessages();if(!ws||ws.readyState!==1)connectWS()},1800)}
if(token)start();else auth();
</script>
</body></html>"""

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML
