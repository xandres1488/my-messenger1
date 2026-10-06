from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

app = FastAPI(title="My Messenger")

connections = []


HTML = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>My Messenger</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: #111827;
            color: white;
            font-family: Arial, sans-serif;
            height: 100vh;
        }

        .app {
            max-width: 600px;
            margin: auto;
            height: 100vh;
            display: flex;
            flex-direction: column;
            background: #1f2937;
        }

        .header {
            padding: 18px;
            background: #2563eb;
            font-size: 22px;
            font-weight: bold;
        }

        .status {
            font-size: 13px;
            margin-top: 5px;
            opacity: 0.8;
        }

        #messages {
            flex: 1;
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
            padding: 10px;
            background: #111827;
            gap: 8px;
        }

        input {
            flex: 1;
            padding: 14px;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            outline: none;
        }

        button {
            border: none;
            border-radius: 12px;
            padding: 0 20px;
            background: #2563eb;
            color: white;
            font-size: 16px;
            font-weight: bold;
        }

        button:active {
            transform: scale(0.96);
        }
    </style>
</head>

<body>

<div class="app">

    <div class="header">
        💬 My Messenger
        <div class="status" id="status">
            Подключение...
        </div>
    </div>

    <div id="messages"></div>

    <div class="input-area">
        <input
            id="message"
            type="text"
            placeholder="Введите сообщение..."
            autocomplete="off"
        >

        <button onclick="sendMessage()">
            ➤
        </button>
    </div>

</div>

<script>

const messages = document.getElementById("messages");
const input = document.getElementById("message");
const status = document.getElementById("status");

const protocol = location.protocol === "https:" ? "wss" : "ws";

const socket = new WebSocket(
    protocol + "://" + location.host + "/ws"
);

socket.onopen = function() {
    status.textContent = "🟢 Онлайн";
};

socket.onclose = function() {
    status.textContent = "🔴 Соединение потеряно";
};

socket.onerror = function() {
    status.textContent = "⚠️ Ошибка соединения";
};

socket.onmessage = function(event) {

    const message = document.createElement("div");

    message.className = "message";

    message.textContent = event.data;

    messages.appendChild(message);

    messages.scrollTop = messages.scrollHeight;
};


function sendMessage() {

    const text = input.value.trim();

    if (!text) {
        return;
    }

    if (socket.readyState !== WebSocket.OPEN) {
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

</script>

</body>
</html>
"""


@app.get("/")
async def home():
    return HTMLResponse(HTML)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):

    await websocket.accept()

    connections.append(websocket)

    try:

        while True:

            message = await websocket.receive_text()

            for connection in connections.copy():

                try:
                    await connection.send_text(message)

                except:
                    if connection in connections:
                        connections.remove(connection)

    except WebSocketDisconnect:

        if websocket in connections:
            connections.remove(websocket)
