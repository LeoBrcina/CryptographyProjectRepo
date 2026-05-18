X25519_PUBLIC_KEY_LENGTH = 32

USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32
USERNAME_ALLOWED_CHARACTERS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)


def normalize_username(username: str) -> str:
    return username.strip()


def is_valid_username(username) -> bool:
    if not isinstance(username, str):
        return False

    username = normalize_username(username)

    if len(username) < USERNAME_MIN_LENGTH or len(username) > USERNAME_MAX_LENGTH:
        return False

    return all(char in USERNAME_ALLOWED_CHARACTERS for char in username)