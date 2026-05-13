from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from server.storage import load_users, save_users

password_hasher = PasswordHasher()


def register_user(username: str, password: str) -> tuple[bool, str]:
    users = load_users()

    if username in users:
        return False, "User already exists."

    password_hash = password_hasher.hash(password)

    users[username] = {
        "password_hash": password_hash
    }

    save_users(users)
    return True, "User registered successfully."


def authenticate_user(username: str, password: str) -> tuple[bool, str]:
    users = load_users()

    if username not in users:
        return False, "User does not exist."

    stored_hash = users[username]["password_hash"]

    try:
        password_hasher.verify(stored_hash, password)
        return True, "Authentication successful."
    except VerifyMismatchError:
        return False, "Invalid password."
    except Exception:
        return False, "Authentication error."