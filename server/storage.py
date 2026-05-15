import json
import os
import tempfile
import threading
from pathlib import Path

USER_DB_PATH = Path("data/users.json")
_storage_lock = threading.Lock()


def load_users() -> dict:
    if not USER_DB_PATH.exists():
        return {}

    try:
        with open(USER_DB_PATH, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return {}


def save_users(users: dict) -> None:
    USER_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with _storage_lock:
        temp_file_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=USER_DB_PATH.parent,
                delete=False,
            ) as temp_file:
                temp_file_path = Path(temp_file.name)
                json.dump(users, temp_file, indent=2)
                temp_file.flush()
                os.fsync(temp_file.fileno())

            os.replace(temp_file_path, USER_DB_PATH)

        finally:
            if temp_file_path is not None and temp_file_path.exists():
                try:
                    temp_file_path.unlink()
                except OSError:
                    pass