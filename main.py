import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import String, ForeignKey, DateTime, select, or_, and_
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from pwdlib import PasswordHash


DATABASE_URL = os.getenv("DATABASE_URL", "")
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret")

if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgresql://",
        "postgresql+asyncpg://",
        1
    )

engine = create_async_engine(DATABASE_URL, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
password_hash = PasswordHash.recommended()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255))


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    receiver_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    text: Mapped[str] = mapped_column(String(4000))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


app = FastAPI(title="RayfGram")

connections = {}


HTML = r"""
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RayfGram</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0e1621;color:#fff;font-family:Arial,sans-serif}
.app{height:100vh;max-width:700px;margin:auto;background:#17212b;display:flex;flex-direction:column}
.header{height:64px;background:#2481cc;padding:10px 16px;display:flex;align-items:center;gap:12px}
.logo{font-size:25px;font-weight:bold}
.user-name{font-size:13px;opacity:.85}
.screen{padding:18px}
input{width:100%;padding:14px;margin:7px 0;border:0;border-radius:12px;font-size:16px}
button{width:100%;padding:14px;margin-top:8px;border:0;border-radius:12px;background:#2481cc;color:#fff;font-size:16px;font-weight:bold}
button.secondary{background:#263747}
.error{color:#ff9b9b;margin-top:10px}
.success{color:#8ee6a8;margin-top:10px}
#main{display:none;flex:1;min-height:0}
#users{width:42%;border-right:1px solid #30404f;overflow:auto}
#chat{width:58%;display:none;flex-direction:column;min-width:0}
.user-card{padding:15px;border-bottom:1px solid #30404f;cursor:pointer}
.user-card:hover{background:#223446}
.user-card.active{background:#2b5278}
.chat-top{padding:13px 15px;background:#203040;border-bottom:1px solid #30404f;font-weight:bold}
#messages{flex:1;overflow:auto;padding:15px}
.message{max-width:85%;background:#263747;padding:9px 12px;margin:7px 0;border-radius:12px;word-break:break-word}
.message.mine{margin-left:auto;background:#2b5278}
.input-area{display:flex;gap:8px;padding:10px;background:#101b26}
.input-area input{margin:0;flex:1}
.input-area button{width:60px;margin:0}
@media(max-width:520px){
  #users{width:100%}
  #chat{width:100%}
  #main.chat-open #users{display:none}
  #main.chat-open #chat{display:flex}
  .back{display:block!important}
}
.back{display:none;width:auto;padding:7px 10px;margin:0;background:#263747}
.logout{font-size:12px;padding:7px 10px;width:auto;margin:0;background:#1b5f96}
.header-right{margin-left:auto}
</style>
</head>
<body>
<div class="app">
<div class="header">
  <div>
    <div class="logo">💬 RayfGram</div>
    <div class="user-name" id="user"></div>
  </div>
  <div class="header-right">
    <button class="logout" onclick="logout()">Выйти</button>
  </div>
</div>

<div id="auth" class="screen">
  <h2>Вход</h2>
  <input id="loginUsername" placeholder="Имя пользователя">
  <input id="loginPassword" type="password" placeholder="Пароль">
  <button onclick="login()">Войти</button>

  <hr style="margin:25px 0;border-color:#30404f">

  <h2>Регистрация</h2>
  <input id="regUsername" placeholder="Придумайте имя">
  <input id="regPassword" type="password" placeholder="Пароль">
  <button onclick="register()">Создать аккаунт</button>
  <div id="result"></div>
</div>

<div id="main">
  <div id="users"></div>
  <div id="chat">
    <button class="back" onclick="closeChat()">← Назад</button>
    <div class="chat-top" id="chatTitle">Выберите пользователя</div>
    <div id="messages"></div>
    <div class="input-area">
      <input id="message" placeholder="Сообщение..." autocomplete="off">
      <button onclick="sendMessage()">➤</button>
    </div>
  </div>
</div>
</div>

<script>
let token=localStorage.getItem("token");
let username=localStorage.getItem("username");
let myId=Number(localStorage.getItem("user_id"));
let socket=null;
let selectedUser=null;

const auth=document.getElementById("auth");
const main=document.getElementById("main");
const users=document.getElementById("users");
const chat=document.getElementById("chat");
const messages=document.getElementById("messages");
const input=document.getElementById("message");
const result=document.getElementById("result");

function showResult(text,type="error"){
  result.className=type;
  result.textContent=text;
}

async function register(){
  const u=document.getElementById("regUsername").value.trim();
  const p=document.getElementById("regPassword").value;
  if(!u||!p){showResult("Заполните все поля");return}
  const r=await fetch("/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});
  const d=await r.json();
  if(!r.ok){showResult(d.detail||"Ошибка регистрации");return}
  showResult("Готово! Теперь войдите.","success");
}

async function login(){
  const u=document.getElementById("loginUsername").value.trim();
  const p=document.getElementById("loginPassword").value;
  if(!u||!p){showResult("Заполните все поля");return}
  const r=await fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});
  const d=await r.json();
  if(!r.ok){showResult(d.detail||"Ошибка входа");return}
  token=d.token;
  username=d.username;
  myId=d.user_id;
  localStorage.setItem("token",token);
  localStorage.setItem("username",username);
  localStorage.setItem("user_id",myId);
  startApp();
}

function startApp(){
  auth.style.display="none";
  main.style.display="flex";
  document.getElementById("user").textContent="@" + username;
  loadUsers();
  connectSocket();
}

async function loadUsers(){
  const r=await fetch("/users",{headers:{"Authorization":"Bearer "+token}});
  if(!r.ok){logout();return}
  const list=await r.json();
  users.innerHTML="<div style='padding:15px;font-size:20px;font-weight:bold'>Чаты</div>";
  list.forEach(u=>{
    const el=document.createElement("div");
    el.className="user-card";
    el.textContent="👤 "+u.username;
    el.onclick=()=>openChat(u);
    users.appendChild(el);
  });
}

function connectSocket(){
  const protocol=location.protocol==="https:"?"wss":"ws";
  socket=new WebSocket(protocol+"://"+location.host+"/ws");
  socket.onopen=()=>socket.send("AUTH:"+token);
  socket.onmessage=e=>{
    try{
      const data=JSON.parse(e.data);
      if(data.type==="message"){
        if(selectedUser && (data.sender_id===selectedUser.id || data.receiver_id===selectedUser.id)){
          addMessage(data);
        }
      }
    }catch(err){}
  };
  socket.onclose=()=>setTimeout(()=>{
    if(token) connectSocket();
  },1500);
}

async function openChat(user){
  selectedUser=user;
  main.classList.add("chat-open");
  chat.style.display="flex";
  document.getElementById("chatTitle").textContent="👤 "+user.username;
  messages.innerHTML="";
  await loadHistory(user.id);
}

function closeChat(){
  main.classList.remove("chat-open");
  chat.style.display="none";
  selectedUser=null;
}

async function loadHistory(userId){
  const r=await fetch("/messages/"+userId,{headers:{"Authorization":"Bearer "+token}});
  if(!r.ok)return;
  const list=await r.json();
  list.forEach(addMessage);
}

function addMessage(m){
  const el=document.createElement("div");
  el.className="message"+(m.sender_id===myId?" mine":"");
  el.textContent=m.text;
  messages.appendChild(el);
  messages.scrollTop=messages.scrollHeight;
}

function sendMessage(){
  const text=input.value.trim();
  if(!text||!selectedUser)return;
  if(!socket||socket.readyState!==WebSocket.OPEN){
    alert("Соединение отсутствует");
    return;
  }
  socket.send("TO:"+selectedUser.id+":"+text);
  input.value="";
  input.focus();
}

input.addEventListener("keydown",e=>{
  if(e.key==="Enter")sendMessage();
});

function logout(){
  localStorage.removeItem("token");
  localStorage.removeItem("username");
  localStorage.removeItem("user_id");
  location.reload();
}

if(token&&username&&myId)startApp();
</script>
</body>
</html>
"""


def make_token(user: User):
    payload = {
        "user_id": user.id,
        "username": user.username,
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def get_payload(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        raise HTTPException(status_code=401, detail="Сессия истекла")


@app.on_event("startup")
async def startup():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


@app.get("/")
async def home():
    return HTMLResponse(HTML)


@app.post("/register")
async def register(data: dict):
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Имя должно содержать минимум 3 символа")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Пароль должен содержать минимум 6 символов")

    async with SessionLocal() as db:
        result = await db.execute(select(User).where(User.username == username))
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Такой пользователь уже существует")

        user = User(
            username=username,
            password_hash=password_hash.hash(password)
        )
        db.add(user)
        await db.commit()

    return {"message": "Регистрация успешна"}


@app.post("/login")
async def login(data: dict):
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    async with SessionLocal() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()

        if not user or not password_hash.verify(password, user.password_hash):
            raise HTTPException(status_code=401, detail="Неверное имя или пароль")

        return {
            "token": make_token(user),
            "username": user.username,
            "user_id": user.id
        }


@app.get("/users")
async def get_users(authorization: str = ""):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Нет авторизации")

    payload = get_payload(authorization[7:])
    my_id = int(payload["user_id"])

    async with SessionLocal() as db:
        result = await db.execute(
            select(User).where(User.id != my_id).order_by(User.username)
        )
        return [{"id": u.id, "username": u.username} for u in result.scalars().all()]


@app.get("/messages/{other_user_id}")
async def get_messages(other_user_id: int, authorization: str = ""):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Нет авторизации")

    payload = get_payload(authorization[7:])
    my_id = int(payload["user_id"])

    async with SessionLocal() as db:
        result = await db.execute(
            select(Message)
            .where(
                or_(
                    and_(Message.sender_id == my_id, Message.receiver_id == other_user_id),
                    and_(Message.sender_id == other_user_id, Message.receiver_id == my_id)
                )
            )
            .order_by(Message.created_at)
        )
        return [
            {
                "id": m.id,
                "sender_id": m.sender_id,
                "receiver_id": m.receiver_id,
                "text": m.text,
                "created_at": m.created_at.isoformat()
            }
            for m in result.scalars().all()
        ]


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        auth_message = await websocket.receive_text()

        if not auth_message.startswith("AUTH:"):
            await websocket.close()
            return

        token = auth_message[5:]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = int(payload["user_id"])
            username = payload["username"]
        except Exception:
            await websocket.close()
            return

        connections[websocket] = {
            "id": user_id,
            "username": username
        }

        await websocket.send_text('{"type":"ready"}')

        while True:
            message = await websocket.receive_text()

            if not message.startswith("TO:"):
                continue

            parts = message.split(":", 2)

            if len(parts) != 3:
                continue

            try:
                receiver_id = int(parts[1])
            except ValueError:
                continue

            message_text = parts[2].strip()

            if not message_text:
                continue

            async with SessionLocal() as db:
                receiver = await db.get(User, receiver_id)

                if not receiver:
                    continue

                new_message = Message(
                    sender_id=user_id,
                    receiver_id=receiver_id,
                    text=message_text
                )
                db.add(new_message)
                await db.commit()
                await db.refresh(new_message)

            data = {
                "type": "message",
                "id": new_message.id,
                "sender_id": user_id,
                "receiver_id": receiver_id,
                "text": message_text,
                "created_at": new_message.created_at.isoformat()
            }

            import json
            text = json.dumps(data, ensure_ascii=False)

            for connection, info in list(connections.items()):
                if info["id"] in (user_id, receiver_id):
                    try:
                        await connection.send_text(text)
                    except Exception:
                        connections.pop(connection, None)

    except WebSocketDisconnect:
        connections.pop(websocket, None)
    except Exception:
        connections.pop(websocket, None)
