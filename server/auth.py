from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from server.storage import load_users, save_users

password_hasher = PasswordHasher()

DUMMY_PASSWORD_HASH = password_hasher.hash("dummy-password-for-timing-equalization")


def register_user(username: str, password: str) -> tuple[bool, str]:
    generic_registration_message = "If registration details are valid, the account is ready to use."

    if not isinstance(username, str) or not isinstance(password, str):
        return False, generic_registration_message

    users = load_users()

    if username in users:
        return True, generic_registration_message

    password_hash = password_hasher.hash(password)

    users[username] = {
        "password_hash": password_hash
    }

    save_users(users)
    return True, generic_registration_message


def authenticate_user(username: str, password: str) -> tuple[bool, str]:
    if not isinstance(username, str) or not isinstance(password, str):
        return False, "Invalid username or password."

    users = load_users()

    stored_hash = users.get(username, {}).get("password_hash", DUMMY_PASSWORD_HASH)

    try:
        password_hasher.verify(stored_hash, password)
    except VerifyMismatchError:
        return False, "Invalid username or password."
    except Exception:
        return False, "Invalid username or password."

    if username not in users:
        return False, "Invalid username or password."

    return True, "Authentication successful."