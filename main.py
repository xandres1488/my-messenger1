from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI(title="My Messenger")

connections = []


@app.get("/")
async def home():
    return {
        "status": "online",
        "message": "My Messenger server is running!"
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connections.append(websocket)

    try:
        while True:
            message = await websocket.receive_text()

            for connection in connections:
                try:
                    await connection.send_text(message)
                except:
                    pass

    except WebSocketDisconnect:
        if websocket in connections:
            connections.remove(websocket)
