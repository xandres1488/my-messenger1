import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from sqlalchemy import String, select, ForeignKey, DateTime
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

    sender_id: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )

    receiver_id: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )

    text: Mapped[str] = mapped_column(String(2000))

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )
app = FastAPI(title="My Messenger")

connections = {}


HTML = """
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>RayfGram</title>

<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #111827;
    color: white;
    font-family: Arial, sans-serif;
}

.app {
    max-width: 600px;
    margin: auto;
    min-height: 100vh;
    background: #1f2937;
}

.header {
    padding: 18px;
    background: #2563eb;
    font-size: 22px;
    font-weight: bold;
}

.screen {
    padding: 20px;
}

input {
    width: 100%;
    padding: 14px;
    margin: 8px 0;
    border: none;
    border-radius: 12px;
    font-size: 16px;
}

button {
    width: 100%;
    padding: 14px;
    margin-top: 8px;
    border: none;
    border-radius: 12px;
    background: #2563eb;
    color: white;
    font-size: 16px;
    font-weight: bold;
}

button.secondary {
    background: #374151;
}

.error {
    color: #fca5a5;
    margin-top: 12px;
}

.success {
    color: #86efac;
    margin-top: 12px;
}

#chat {
    display: none;
}
#users {
    display: none;
    padding: 20px;
}

.user-card {
    background: #374151;
    padding: 15px;
    margin-bottom: 10px;
    border-radius: 14px;
    font-size: 18px;
}
#messages {
    height: calc(100vh - 150px);
    overflow-y: auto;
    padding: 15px;
}

.message {
    background: #374151;
    padding: 12px;
    margin-bottom: 10px;
    border-radius: 12px;
    word-wrap: break-word;
}

.input-area {
    display: flex;
    gap: 8px;
    padding: 10px;
    background: #111827;
    position: sticky;
    bottom: 0;
}

.input-area input {
    margin: 0;
}

.input-area button {
    width: 60px;
    margin: 0;
}

.user {
    font-size: 14px;
    opacity: .8;
    margin-top: 5px;
}
</style>
</head>

<body>

<div class="app">

<div class="header">
💬 RayfGram
<div class="user" id="user"></div>
</div>

<div id="auth" class="screen">

<h2>Вход</h2>

<input id="loginUsername"
       placeholder="Имя пользователя">

<input id="loginPassword"
       type="password"
       placeholder="Пароль">

<button onclick="login()">Войти</button>

<hr style="margin:25px 0">

<h2>Регистрация</h2>

<input id="regUsername"
       placeholder="Придумайте имя">

<input id="regPassword"
       type="password"
       placeholder="Придумайте пароль">

<button onclick="register()">Создать аккаунт</button>

<div id="result"></div>

</div>

<div id="users">
    <h2>Пользователи</h2>
    <div id="userList"></div>
</div>
<div id="chat">

<div id="messages"></div>

<div class="input-area">

<input id="message"
       placeholder="Введите сообщение..."
       autocomplete="off">

<button onclick="sendMessage()">➤</button>

</div>

</div>

</div>


<script>

let token = localStorage.getItem("token");
let username = localStorage.getItem("username");
let socket = null;

let selectedUserId = null;
let selectedUsername = null;

const auth = document.getElementById("auth");
const chat = document.getElementById("chat");
const result = document.getElementById("result");
const messages = document.getElementById("messages");
const input = document.getElementById("message");


function showResult(text, type="error") {
    result.className = type;
    result.textContent = text;
}


async function register() {

    const username =
        document.getElementById("regUsername").value.trim();

    const password =
        document.getElementById("regPassword").value;

    if (!username || !password) {
        showResult("Заполните все поля");
        return;
    }

    const response = await fetch("/register", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            username: username,
            password: password
        })
    });

    const data = await response.json();

    if (!response.ok) {
        showResult(data.detail || "Ошибка регистрации");
        return;
    }

    showResult(
        "Регистрация успешна! Теперь войдите.",
        "success"
    );
}


async function login() {

    const username =
        document.getElementById("loginUsername").value.trim();

    const password =
        document.getElementById("loginPassword").value;

    if (!username || !password) {
        showResult("Заполните все поля");
        return;
    }

    const response = await fetch("/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            username: username,
            password: password
        })
    });

    const data = await response.json();

    if (!response.ok) {
        showResult(data.detail || "Ошибка входа");
        return;
    }

    token = data.token;

    localStorage.setItem("token", token);
    localStorage.setItem("username", username);

    startChat();
}


function startChat() {

    username = localStorage.getItem("username");

    auth.style.display = "none";
    chat.style.display = "block";
document.getElementById("users").style.display = "block";
loadUsers();
    document.getElementById("user").textContent =
        "Вы вошли как: " + username;

    const protocol =
        location.protocol === "https:" ? "wss" : "ws";

    socket = new WebSocket(
        protocol + "://" + location.host + "/ws"
    );

    socket.onopen = function() {
        socket.send("AUTH:" + token);
    };

    socket.onmessage = function(event) {

        const message =
            document.createElement("div");

        message.className = "message";
        message.textContent = event.data;

        messages.appendChild(message);

        messages.scrollTop =
            messages.scrollHeight;
    };

    socket.onclose = function() {

        if (chat.style.display !== "none") {
            alert("Соединение с сервером потеряно");
        }
    };
}

async function loadUsers() {

    const response = await fetch("/users");
    const users = await response.json();

    const userList =
        document.getElementById("userList");

    userList.innerHTML = "";

    users.forEach(function(user) {

        const card =
            document.createElement("div");

        card.className = "user-card";

        if (user.username === username) {
            card.textContent =
                "👤 " + user.username + " — Вы";
        } else {
            card.textContent =
                "👤 " + user.username;
        }

        userList.appendChild(card);
    });
}
function sendMessage() {

    const text = input.value.trim();

    if (!text) return;

    if (!socket ||
        socket.readyState !== WebSocket.OPEN) {

        alert("Нет соединения с сервером");
        return;
    }

    socket.send(text);

    input.value = "";
    input.focus();
}


input.addEventListener("keydown", function(event) {

    if (event.key === "Enter") {
        sendMessage();
    }

});


if (token) {
    startChat();
}

</script>

</body>
</html>
"""


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
        return {"detail": "Имя должно содержать минимум 3 символа"}

    if len(password) < 6:
        return {"detail": "Пароль должен содержать минимум 6 символов"}

    async with SessionLocal() as db:

        result = await db.execute(
            select(User).where(User.username == username)
        )

        existing = result.scalar_one_or_none()

        if existing:
            return {"detail": "Такой пользователь уже существует"}

        user = User(
            username=username,
            password_hash=password_hash.hash(password)
        )

        db.add(user)

        await db.commit()

    return {"message": "Регистрация успешна"}
@app.get("/users")
async def get_users():

    async with SessionLocal() as db:

        result = await db.execute(
            select(User).order_by(User.username)
        )

        users = result.scalars().all()

        return [
            {
                "id": user.id,
                "username": user.username
            }
            for user in users
        ]

@app.post("/login")
async def login(data: dict):

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    async with SessionLocal() as db:

        result = await db.execute(
            select(User).where(User.username == username)
        )

        user = result.scalar_one_or_none()

        if not user:
            return {"detail": "Неверное имя или пароль"}

        if not password_hash.verify(
            password,
            user.password_hash
        ):
            return {"detail": "Неверное имя или пароль"}

    payload = {
        "user_id": user.id,
        "username": user.username,
        "exp": datetime.now(timezone.utc)
        + timedelta(days=7)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256"
    )

    return {
        "token": token,
        "username": user.username
    }


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

            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=["HS256"]
            )

            username = payload["username"]

        except Exception:

            await websocket.close()
            return

        connections[websocket] = {
    "id": payload["user_id"],
    "username": username
        }

        await websocket.send_text(
            "🟢 Вы вошли в чат как " + username
        )

        while True:

            message = await websocket.receive_text()

            text = f"{username}: {message}"

            for connection in list(connections):

                try:
                    await connection.send_text(text)

                except Exception:

                    connections.pop(connection, None)

    except WebSocketDisconnect:

        connections.pop(websocket, None)

    except Exception:

        connections.pop(websocket, None)
