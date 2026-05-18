import base64
import binascii
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from server.auth import authenticate_user, register_user
from server.connection_manager import ConnectionManager
from shared.protocol import X25519_PUBLIC_KEY_LENGTH, is_valid_username

app = FastAPI()
manager = ConnectionManager()


def is_valid_password(password) -> bool:
    return isinstance(password, str) and len(password) > 0


def is_valid_x25519_public_key(public_key_b64) -> bool:
    if not isinstance(public_key_b64, str):
        return False

    try:
        public_key_bytes = base64.b64decode(
            public_key_b64.encode("utf-8"),
            validate=True,
        )
    except (binascii.Error, ValueError):
        return False

    return len(public_key_bytes) == X25519_PUBLIC_KEY_LENGTH


async def safe_send_json(websocket: WebSocket, payload: dict) -> bool:
    try:
        await websocket.send_json(payload)
        return True
    except Exception:
        return False


@app.get("/")
def root():
    return {"message": "Secure chat server is running."}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    username = None

    try:
        while True:
            try:
                data = await websocket.receive_json()
            except WebSocketDisconnect:
                raise
            except json.JSONDecodeError:
                await safe_send_json(websocket, {
                    "type": "error",
                    "message": "Invalid JSON message."
                })
                continue
            except Exception:
                await safe_send_json(websocket, {
                    "type": "error",
                    "message": "Invalid WebSocket message."
                })
                continue

            if not isinstance(data, dict):
                await safe_send_json(websocket, {
                    "type": "error",
                    "message": "Message must be a JSON object."
                })
                continue

            message_type = data.get("type")

            if message_type == "register":
                username_input = data.get("username")
                password_input = data.get("password")

                if not is_valid_username(username_input) or not is_valid_password(password_input):
                    await safe_send_json(websocket, {
                        "type": "register_result",
                        "success": False,
                        "message": "Username and password are required."
                    })
                    continue

                username_input = username_input.strip()

                success, message = register_user(username_input, password_input)

                await safe_send_json(websocket, {
                    "type": "register_result",
                    "success": success,
                    "message": message
                })

            elif message_type == "login":
                if username is not None:
                    await safe_send_json(websocket, {
                        "type": "login_result",
                        "success": False,
                        "message": "This WebSocket session is already authenticated."
                    })
                    continue

                username_input = data.get("username")
                password_input = data.get("password")

                if not is_valid_username(username_input) or not is_valid_password(password_input):
                    await safe_send_json(websocket, {
                        "type": "login_result",
                        "success": False,
                        "message": "Invalid username or password."
                    })
                    continue

                username_input = username_input.strip()

                success, message = authenticate_user(username_input, password_input)

                if success:
                    username = username_input
                    await manager.connect(username, websocket)

                await safe_send_json(websocket, {
                    "type": "login_result",
                    "success": success,
                    "message": message
                })

            elif message_type == "list_online":
                if username is None:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "You must be logged in to list online users."
                    })
                    continue

                await safe_send_json(websocket, {
                    "type": "online_users",
                    "users": manager.list_online_users()
                })

            elif message_type == "send_encrypted_message":
                if username is None:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "You must be logged in to send encrypted messages."
                    })
                    continue

                recipient = data.get("to")
                nonce = data.get("nonce")
                ciphertext = data.get("ciphertext")
                counter = data.get("counter")

                if not is_valid_username(recipient):
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "Invalid recipient username."
                    })
                    continue

                recipient = recipient.strip()

                if recipient == username:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "You cannot send encrypted messages to yourself."
                    })
                    continue

                if not isinstance(nonce, str) or not isinstance(ciphertext, str):
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "Nonce and ciphertext must be strings."
                    })
                    continue

                if not isinstance(counter, int) or counter < 1:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "Counter must be a positive integer."
                    })
                    continue

                recipient_socket = manager.get_connection(recipient)

                if recipient_socket is None:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": f"User '{recipient}' is not online."
                    })
                    continue

                delivered = await safe_send_json(recipient_socket, {
                    "type": "incoming_encrypted_message",
                    "from": username,
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "counter": counter
                })

                if not delivered:
                    manager.disconnect(recipient, recipient_socket)
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": f"User '{recipient}' is no longer reachable."
                    })
                    continue

                await safe_send_json(websocket, {
                    "type": "send_encrypted_result",
                    "success": True,
                    "message": f"Encrypted message sent to {recipient}."
                })

            elif message_type == "key_exchange_request":
                if username is None:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "You must be logged in to start key exchange."
                    })
                    continue

                recipient = data.get("to")
                public_key = data.get("public_key")

                if not is_valid_username(recipient):
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "Invalid recipient username."
                    })
                    continue

                recipient = recipient.strip()

                if recipient == username:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "You cannot start key exchange with yourself."
                    })
                    continue

                if not is_valid_x25519_public_key(public_key):
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "Invalid X25519 public key."
                    })
                    continue

                recipient_socket = manager.get_connection(recipient)

                if recipient_socket is None:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": f"User '{recipient}' is not online."
                    })
                    continue

                delivered = await safe_send_json(recipient_socket, {
                    "type": "key_exchange_request",
                    "from": username,
                    "public_key": public_key
                })

                if not delivered:
                    manager.disconnect(recipient, recipient_socket)
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": f"User '{recipient}' is no longer reachable."
                    })
                    continue

                await safe_send_json(websocket, {
                    "type": "key_exchange_request_sent",
                    "success": True,
                    "message": f"Key exchange request sent to {recipient}."
                })

            elif message_type == "key_exchange_response":
                if username is None:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "You must be logged in to respond to key exchange."
                    })
                    continue

                recipient = data.get("to")
                public_key = data.get("public_key")

                if not is_valid_username(recipient):
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "Invalid recipient username."
                    })
                    continue

                recipient = recipient.strip()

                if recipient == username:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "You cannot respond to key exchange with yourself."
                    })
                    continue

                if not is_valid_x25519_public_key(public_key):
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "Invalid X25519 public key."
                    })
                    continue

                recipient_socket = manager.get_connection(recipient)

                if recipient_socket is None:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": f"User '{recipient}' is not online."
                    })
                    continue

                delivered = await safe_send_json(recipient_socket, {
                    "type": "key_exchange_response",
                    "from": username,
                    "public_key": public_key
                })

                if not delivered:
                    manager.disconnect(recipient, recipient_socket)
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": f"User '{recipient}' is no longer reachable."
                    })
                    continue

                await safe_send_json(websocket, {
                    "type": "key_exchange_response_sent",
                    "success": True,
                    "message": f"Key exchange response sent to {recipient}."
                })

            else:
                await safe_send_json(websocket, {
                    "type": "error",
                    "message": "Unknown message type."
                })

    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect_socket(websocket)