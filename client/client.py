import asyncio
import base64
import binascii
import json
import getpass

import websockets
from cryptography.exceptions import InvalidTag

from client.crypto_utils import (
    decrypt_message_from_transport,
    derive_session_key,
    derive_shared_secret,
    encrypt_message_for_transport,
    generate_x25519_keypair,
)
from client.session_state import SessionState
from shared.protocol import (
    X25519_PUBLIC_KEY_LENGTH,
    is_valid_username,
    normalize_username,
)

SERVER_URL = "ws://127.0.0.1:8000/ws"


def decode_x25519_public_key(public_key_b64) -> bytes | None:
    if not isinstance(public_key_b64, str):
        return None

    try:
        public_key_bytes = base64.b64decode(
            public_key_b64.encode("utf-8"),
            validate=True,
        )
    except (binascii.Error, ValueError):
        return None

    if len(public_key_bytes) != X25519_PUBLIC_KEY_LENGTH:
        return None

    return public_key_bytes


async def async_input(prompt: str) -> str:
    return await asyncio.to_thread(input, prompt)

async def async_password(prompt: str) -> str:
    return await asyncio.to_thread(getpass.getpass, prompt)

async def receive_messages(websocket, state: SessionState, pending_login: dict):
    try:
        while True:
            try:
                response = await websocket.recv()
                data = json.loads(response)

                message_type = data.get("type")

                if message_type == "incoming_encrypted_message":
                    sender = data.get("from")
                    nonce_b64 = data.get("nonce")
                    ciphertext_b64 = data.get("ciphertext")
                    counter = data.get("counter")

                    if not sender or nonce_b64 is None or ciphertext_b64 is None or counter is None:
                        print(f"\n[ENCRYPTED MESSAGE] Invalid encrypted payload: {data}")
                        continue

                    sender = normalize_username(sender)

                    session = state.get_session(sender)

                    if session is None or session.session_key is None:
                        print(f"\n[ENCRYPTED MESSAGE] No session key available for {sender}.")
                        continue

                    if counter <= session.highest_incoming_counter:
                        print(
                            f"\n[REPLAY PROTECTION] Rejected message from {sender} "
                            f"with counter={counter}."
                        )
                        continue

                    try:
                        plaintext = decrypt_message_from_transport(
                            session_key=session.session_key,
                            sender=sender,
                            recipient=state.logged_in_username,
                            counter=counter,
                            nonce_b64=nonce_b64,
                            ciphertext_b64=ciphertext_b64,
                        )
                    except InvalidTag:
                        print(
                            f"\n[ENCRYPTED MESSAGE] Authentication failed for message "
                            f"from {sender}."
                        )
                        continue
                    except Exception as exc:
                        print(f"\n[ENCRYPTED MESSAGE] Decryption error from {sender}: {exc}")
                        continue

                    session.highest_incoming_counter = counter
                    print(f"\n[NEW MESSAGE - ENCRYPTED] From {sender}: {plaintext}")

                elif message_type == "login_result":
                    success = data.get("success", False)

                    if success and pending_login.get("username"):
                        state.set_logged_in_user(pending_login["username"])

                    print(f"\n[SERVER RESPONSE] {data}")

                elif message_type == "session_terminated":
                    message = data.get(
                        "message",
                        "This session was terminated because the account logged in elsewhere.",
                    )
                    print(f"\n[SESSION TERMINATED] {message}")
                    await websocket.close()
                    break

                elif message_type == "key_exchange_request":
                    sender = data.get("from")
                    public_key_b64 = data.get("public_key")

                    if not sender or not is_valid_username(sender):
                        print(f"\n[KEY EXCHANGE] Invalid sender in request: {data}")
                        continue

                    sender = normalize_username(sender)
                    peer_public_key_bytes = decode_x25519_public_key(public_key_b64)

                    if peer_public_key_bytes is None:
                        print(f"\n[KEY EXCHANGE] Rejected malformed public key from {sender}.")
                        continue

                    session = state.get_or_create_session(sender)
                    session.peer_public_key_bytes = peer_public_key_bytes

                    try:
                        private_key, public_key_bytes = generate_x25519_keypair()
                        session.local_private_key = private_key
                        session.local_public_key_bytes = public_key_bytes

                        shared_secret = derive_shared_secret(
                            session.local_private_key,
                            session.peer_public_key_bytes,
                        )
                        session.session_key = derive_session_key(shared_secret)

                        # The ephemeral private key is only needed for this one
                        # key exchange operation. Clear it immediately after use
                        # so replayed key exchange messages cannot re-derive the
                        # same session key and reset replay counters.
                        session.local_private_key = None
                        session.outgoing_counter = 0
                        session.highest_incoming_counter = -1
                    except Exception as exc:
                        session.local_private_key = None
                        session.session_key = None
                        print(f"\n[KEY EXCHANGE] Failed to process request from {sender}: {exc}")
                        continue

                    await websocket.send(json.dumps({
                        "type": "key_exchange_response",
                        "to": sender,
                        "public_key": base64.b64encode(public_key_bytes).decode("utf-8")
                    }))

                    print(f"\n[KEY EXCHANGE] Received request from {sender}. Session key derived.")

                elif message_type == "key_exchange_response":
                    sender = data.get("from")
                    public_key_b64 = data.get("public_key")

                    if not sender or not is_valid_username(sender):
                        print(f"\n[KEY EXCHANGE] Invalid sender in response: {data}")
                        continue

                    sender = normalize_username(sender)
                    peer_public_key_bytes = decode_x25519_public_key(public_key_b64)

                    if peer_public_key_bytes is None:
                        print(f"\n[KEY EXCHANGE] Rejected malformed public key from {sender}.")
                        continue

                    session = state.get_session(sender)

                    if session is None:
                        print(f"\n[KEY EXCHANGE] No local session for {sender}.")
                        continue

                    if session.session_key is not None:
                        print(
                            f"\n[KEY EXCHANGE] Ignored unexpected key exchange response "
                            f"from {sender}; session key already exists."
                        )
                        continue

                    if session.local_private_key is None:
                        print(f"\n[KEY EXCHANGE] No pending key exchange for {sender}.")
                        continue

                    session.peer_public_key_bytes = peer_public_key_bytes

                    try:
                        shared_secret = derive_shared_secret(
                            session.local_private_key,
                            session.peer_public_key_bytes,
                        )
                        session.session_key = derive_session_key(shared_secret)

                        # Clear the ephemeral private key after successful use.
                        # This makes key exchange completion a one-shot transition
                        # and prevents replayed responses from resetting counters.
                        session.local_private_key = None
                        session.outgoing_counter = 0
                        session.highest_incoming_counter = -1
                    except Exception as exc:
                        session.local_private_key = None
                        session.session_key = None
                        print(f"\n[KEY EXCHANGE] Failed to process response from {sender}: {exc}")
                        continue

                    print(f"\n[KEY EXCHANGE] Response received from {sender}. Session key derived.")

                else:
                    print(f"\n[SERVER RESPONSE] {data}")

            except json.JSONDecodeError:
                print("\n[CLIENT] Received invalid JSON message. Ignoring.")
                continue
            except websockets.ConnectionClosed:
                raise
            except Exception as exc:
                print(f"\n[CLIENT] Ignored malformed inbound message: {exc}")
                continue

    except websockets.ConnectionClosed:
        print("\nDisconnected from server.")


async def main():
    state = SessionState()
    pending_login = {"username": None}

    async with websockets.connect(SERVER_URL) as websocket:
        print("Connected to server.")

        receiver_task = asyncio.create_task(
            receive_messages(websocket, state, pending_login)
        )

        try:
            while True:
                print("\nChoose an action:")
                print("1 - Register")
                print("2 - Login")
                print("3 - List online users")
                print("4 - Send encrypted message")
                print("5 - Show local session state")
                print("6 - Start key exchange with user")
                print("7 - Exit")

                choice = (await async_input("> ")).strip()

                if choice == "1":
                    username = normalize_username(await async_input("Username: "))
                    password = await async_password("Password: ")

                    if not is_valid_username(username):
                        print("Username must be 3-32 characters and use only letters, numbers, _ or -.")
                        continue

                    await websocket.send(json.dumps({
                        "type": "register",
                        "username": username,
                        "password": password
                    }))

                elif choice == "2":
                    username = normalize_username(await async_input("Username: "))
                    password = await async_password("Password: ")

                    if not is_valid_username(username):
                        print("Invalid username format.")
                        continue

                    pending_login["username"] = username

                    await websocket.send(json.dumps({
                        "type": "login",
                        "username": username,
                        "password": password
                    }))

                elif choice == "3":
                    await websocket.send(json.dumps({
                        "type": "list_online"
                    }))

                elif choice == "4":
                    if state.logged_in_username is None:
                        print("You must log in before sending messages.")
                        continue

                    recipient = normalize_username(await async_input("Send to: "))
                    content = (await async_input("Message: ")).strip()

                    if not is_valid_username(recipient):
                        print("Invalid recipient username.")
                        continue

                    if recipient == state.logged_in_username:
                        print("You cannot send encrypted messages to yourself.")
                        continue

                    if not content:
                        print("Message cannot be empty.")
                        continue

                    session = state.get_or_create_session(recipient)

                    if session.session_key is None:
                        print(f"No session key for {recipient}. Start key exchange first.")
                        continue

                    session.outgoing_counter += 1

                    encrypted_payload = encrypt_message_for_transport(
                        session_key=session.session_key,
                        plaintext=content,
                        sender=state.logged_in_username,
                        recipient=recipient,
                        counter=session.outgoing_counter,
                    )

                    await websocket.send(json.dumps({
                        "type": "send_encrypted_message",
                        "to": recipient,
                        "nonce": encrypted_payload["nonce"],
                        "ciphertext": encrypted_payload["ciphertext"],
                        "counter": encrypted_payload["counter"],
                    }))

                elif choice == "5":
                    print(f"Logged in user: {state.logged_in_username}")
                    print("Local sessions:")
                    for peer in state.list_sessions():
                        session = state.get_session(peer)
                        has_key = session.session_key is not None if session else False
                        outgoing_counter = session.outgoing_counter if session else None
                        highest_incoming_counter = (
                            session.highest_incoming_counter if session else None
                        )
                        print(
                            f" - {peer}: session_key_set={has_key}, "
                            f"outgoing_counter={outgoing_counter}, "
                            f"highest_incoming_counter={highest_incoming_counter}"
                        )

                elif choice == "6":
                    if state.logged_in_username is None:
                        print("You must log in before starting key exchange.")
                        continue

                    recipient = normalize_username(await async_input("Start key exchange with: "))

                    if not is_valid_username(recipient):
                        print("Invalid recipient username.")
                        continue

                    if recipient == state.logged_in_username:
                        print("You cannot start key exchange with yourself.")
                        continue

                    session = state.get_or_create_session(recipient)

                    private_key, public_key_bytes = generate_x25519_keypair()
                    session.local_private_key = private_key
                    session.local_public_key_bytes = public_key_bytes

                    # Starting a new key exchange intentionally invalidates the
                    # previous session state for this peer.
                    session.session_key = None
                    session.outgoing_counter = 0
                    session.highest_incoming_counter = -1

                    await websocket.send(json.dumps({
                        "type": "key_exchange_request",
                        "to": recipient,
                        "public_key": base64.b64encode(public_key_bytes).decode("utf-8")
                    }))

                    print(f"[KEY EXCHANGE] Request sent to {recipient}.")

                elif choice == "7":
                    print("Exiting client.")
                    break

                else:
                    print("Invalid choice.")

        finally:
            receiver_task.cancel()


if __name__ == "__main__":
    asyncio.run(main())