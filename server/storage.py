import json
from pathlib import Path

USER_DB_PATH = Path("data/users.json")


def load_users() -> dict:
    if not USER_DB_PATH.exists():
        return {}

    with open(USER_DB_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def save_users(users: dict) -> None:
    USER_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(USER_DB_PATH, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=2)