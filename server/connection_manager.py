from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, username: str, websocket: WebSocket) -> None:
        self.active_connections[username] = websocket

    def disconnect(self, username: str) -> None:
        if username in self.active_connections:
            del self.active_connections[username]

    def get_connection(self, username: str) -> WebSocket | None:
        return self.active_connections.get(username)

    def is_online(self, username: str) -> bool:
        return username in self.active_connections

    def list_online_users(self) -> list[str]:
        return list(self.active_connections.keys())