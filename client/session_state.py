from dataclasses import dataclass, field


@dataclass
class ChatSession:
    peer_username: str
    session_key: bytes | None = None
    outgoing_counter: int = 0
    highest_incoming_counter: int = -1
    local_private_key = None
    local_public_key_bytes: bytes | None = None
    peer_public_key_bytes: bytes | None = None


@dataclass
class SessionState:
    logged_in_username: str | None = None
    sessions: dict[str, ChatSession] = field(default_factory=dict)

    def set_logged_in_user(self, username: str) -> None:
        self.logged_in_username = username

    def get_or_create_session(self, peer_username: str) -> ChatSession:
        if peer_username not in self.sessions:
            self.sessions[peer_username] = ChatSession(peer_username=peer_username)
        return self.sessions[peer_username]

    def get_session(self, peer_username: str) -> ChatSession | None:
        return self.sessions.get(peer_username)

    def has_session(self, peer_username: str) -> bool:
        return peer_username in self.sessions

    def list_sessions(self) -> list[str]:
        return list(self.sessions.keys())