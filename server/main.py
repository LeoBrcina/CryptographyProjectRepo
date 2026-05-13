from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from server.auth import authenticate_user, register_user
from server.connection_manager import ConnectionManager

app = FastAPI()
manager = ConnectionManager()


def is_valid_username(username: str | None) -> bool:
    if username is None:
        return False

    username = username.strip()

    if len(username) < 3 or len(username) > 32:
        return False

    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    return all(char in allowed for char in username)


@app.get("/")
def root():
    return {"message": "Secure chat server is running."}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    username = None

    try:
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")

            if message_type == "register":
                username_input = data.get("username")
                password_input = data.get("password")

                if not username_input or not password_input:
                    await websocket.send_json({
                        "type": "register_result",
                        "success": False,
                        "message": "Username and password are required."
                    })
                    continue

                if not is_valid_username(username_input):
                    await websocket.send_json({
                        "type": "register_result",
                        "success": False,
                        "message": "Username must be 3-32 characters and use only letters, numbers, _ or -."
                    })
                    continue

                success, message = register_user(username_input.strip(), password_input)

                await websocket.send_json({
                    "type": "register_result",
                    "success": success,
                    "message": message
                })

            elif message_type == "login":
                username_input = data.get("username")
                password_input = data.get("password")

                if not username_input or not password_input:
                    await websocket.send_json({
                        "type": "login_result",
                        "success": False,
                        "message": "Username and password are required."
                    })
                    continue

                if not is_valid_username(username_input):
                    await websocket.send_json({
                        "type": "login_result",
                        "success": False,
                        "message": "Invalid username format."
                    })
                    continue

                success, message = authenticate_user(username_input.strip(), password_input)

                if success:
                    username = username_input.strip()
                    await manager.connect(username, websocket)

                await websocket.send_json({
                    "type": "login_result",
                    "success": success,
                    "message": message
                })

            elif message_type == "list_online":
                await websocket.send_json({
                    "type": "online_users",
                    "users": manager.list_online_users()
                })

            elif message_type == "send_encrypted_message":
                if username is None:
                    await websocket.send_json({
                        "type": "error",
                        "message": "You must be logged in to send encrypted messages."
                    })
                    continue

                recipient = data.get("to")
                nonce = data.get("nonce")
                ciphertext = data.get("ciphertext")
                counter = data.get("counter")

                if not is_valid_username(recipient):
                    await websocket.send_json({
                        "type": "error",
                        "message": "Invalid recipient username."
                    })
                    continue

                recipient = recipient.strip()

                if recipient == username:
                    await websocket.send_json({
                        "type": "error",
                        "message": "You cannot send encrypted messages to yourself."
                    })
                    continue

                if nonce is None or ciphertext is None or counter is None:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Recipient, nonce, ciphertext, and counter are required."
                    })
                    continue

                if not isinstance(counter, int) or counter < 1:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Counter must be a positive integer."
                    })
                    continue

                recipient_socket = manager.get_connection(recipient)

                if recipient_socket is None:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"User '{recipient}' is not online."
                    })
                    continue

                await recipient_socket.send_json({
                    "type": "incoming_encrypted_message",
                    "from": username,
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "counter": counter
                })

                await websocket.send_json({
                    "type": "send_encrypted_result",
                    "success": True,
                    "message": f"Encrypted message sent to {recipient}."
                })

            elif message_type == "key_exchange_request":
                if username is None:
                    await websocket.send_json({
                        "type": "error",
                        "message": "You must be logged in to start key exchange."
                    })
                    continue

                recipient = data.get("to")
                public_key = data.get("public_key")

                if not is_valid_username(recipient):
                    await websocket.send_json({
                        "type": "error",
                        "message": "Invalid recipient username."
                    })
                    continue

                recipient = recipient.strip()

                if recipient == username:
                    await websocket.send_json({
                        "type": "error",
                        "message": "You cannot start key exchange with yourself."
                    })
                    continue

                if not public_key:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Recipient and public_key are required."
                    })
                    continue

                recipient_socket = manager.get_connection(recipient)

                if recipient_socket is None:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"User '{recipient}' is not online."
                    })
                    continue

                await recipient_socket.send_json({
                    "type": "key_exchange_request",
                    "from": username,
                    "public_key": public_key
                })

                await websocket.send_json({
                    "type": "key_exchange_request_sent",
                    "success": True,
                    "message": f"Key exchange request sent to {recipient}."
                })

            elif message_type == "key_exchange_response":
                if username is None:
                    await websocket.send_json({
                        "type": "error",
                        "message": "You must be logged in to respond to key exchange."
                    })
                    continue

                recipient = data.get("to")
                public_key = data.get("public_key")

                if not is_valid_username(recipient):
                    await websocket.send_json({
                        "type": "error",
                        "message": "Invalid recipient username."
                    })
                    continue

                recipient = recipient.strip()

                if recipient == username:
                    await websocket.send_json({
                        "type": "error",
                        "message": "You cannot respond to key exchange with yourself."
                    })
                    continue

                if not public_key:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Recipient and public_key are required."
                    })
                    continue

                recipient_socket = manager.get_connection(recipient)

                if recipient_socket is None:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"User '{recipient}' is not online."
                    })
                    continue

                await recipient_socket.send_json({
                    "type": "key_exchange_response",
                    "from": username,
                    "public_key": public_key
                })

                await websocket.send_json({
                    "type": "key_exchange_response_sent",
                    "success": True,
                    "message": f"Key exchange response sent to {recipient}."
                })

            else:
                await websocket.send_json({
                    "type": "error",
                    "message": "Unknown message type."
                })

    except WebSocketDisconnect:
        if username:
            manager.disconnect(username)