from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, username: str, websocket: WebSocket) -> None:
        old_websocket = self.active_connections.get(username)

        if old_websocket is not None and old_websocket is not websocket:
            try:
                await old_websocket.send_json({
                    "type": "session_terminated",
                    "message": "This account was logged in from another client. This session has been terminated."
                })
            except Exception:
                pass

            try:
                await old_websocket.close(code=4001)
            except Exception:
                pass

        self.active_connections[username] = websocket

    def disconnect(self, username: str, websocket: WebSocket | None = None) -> None:
        current_websocket = self.active_connections.get(username)

        if current_websocket is None:
            return

        if websocket is not None and current_websocket is not websocket:
            return

        del self.active_connections[username]

    def disconnect_socket(self, websocket: WebSocket) -> None:
        usernames_to_remove = [
            username
            for username, active_websocket in self.active_connections.items()
            if active_websocket is websocket
        ]

        for username in usernames_to_remove:
            del self.active_connections[username]

    def get_connection(self, username: str) -> WebSocket | None:
        return self.active_connections.get(username)

    def is_online(self, username: str) -> bool:
        return username in self.active_connections

    def list_online_users(self) -> list[str]:
        return list(self.active_connections.keys())