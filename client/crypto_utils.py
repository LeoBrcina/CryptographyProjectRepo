import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return private_key, public_key_bytes


def load_x25519_public_key(public_key_bytes: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(public_key_bytes)


def derive_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_key_bytes: bytes,
) -> bytes:
    peer_public_key = load_x25519_public_key(peer_public_key_bytes)
    return private_key.exchange(peer_public_key)


def derive_session_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-chat-session-key",
    )

    return hkdf.derive(shared_secret)


def generate_nonce() -> bytes:
    return os.urandom(12)


def encrypt_message(
    session_key: bytes,
    plaintext: str,
    nonce: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    cipher = ChaCha20Poly1305(session_key)
    plaintext_bytes = plaintext.encode("utf-8")
    return cipher.encrypt(nonce, plaintext_bytes, associated_data)


def decrypt_message(
    session_key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    associated_data: bytes | None = None,
) -> str:
    cipher = ChaCha20Poly1305(session_key)
    plaintext_bytes = cipher.decrypt(nonce, ciphertext, associated_data)
    return plaintext_bytes.decode("utf-8")


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64_decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def build_associated_data(
    sender: str,
    recipient: str,
    counter: int,
) -> bytes:
    return f"{sender}|{recipient}|{counter}".encode("utf-8")


def encrypt_message_for_transport(
    session_key: bytes,
    plaintext: str,
    sender: str,
    recipient: str,
    counter: int,
) -> dict:
    nonce = generate_nonce()
    associated_data = build_associated_data(sender, recipient, counter)

    ciphertext = encrypt_message(
        session_key=session_key,
        plaintext=plaintext,
        nonce=nonce,
        associated_data=associated_data,
    )

    return {
        "nonce": b64_encode(nonce),
        "ciphertext": b64_encode(ciphertext),
        "counter": counter,
    }


def decrypt_message_from_transport(
    session_key: bytes,
    sender: str,
    recipient: str,
    counter: int,
    nonce_b64: str,
    ciphertext_b64: str,
) -> str:
    nonce = b64_decode(nonce_b64)
    ciphertext = b64_decode(ciphertext_b64)
    associated_data = build_associated_data(sender, recipient, counter)

    return decrypt_message(
        session_key=session_key,
        ciphertext=ciphertext,
        nonce=nonce,
        associated_data=associated_data,
    )