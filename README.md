# Secure Real-Time Chat Application

A course project for Applied Cryptography implementing a secure real-time chat system with end-to-end encrypted messaging, secure user authentication, ephemeral key exchange, authenticated encryption, and basic replay/tamper protection.

The project demonstrates clear separation of:

1. Authentication phase
2. Key exchange phase
3. Secure message transmission phase

---

## Features

### Authentication
- User registration and login
- Password hashing with **Argon2**
- No plaintext password storage

### Real-Time Communication
- WebSocket-based client/server communication
- Multiple simultaneous client connections
- Online user listing

### Key Exchange
- Peer-to-peer session establishment using **X25519**
- Public keys relayed by the server
- Shared secret derived locally on each client
- Session key derived locally using **HKDF-SHA256**

### Encrypted Messaging
- Message encryption with **ChaCha20-Poly1305**
- Authenticated encryption (AEAD)
- Random 12-byte nonce per encrypted message
- Encrypted payloads relayed by the server without server-side decryption

### Replay / Tamper Protection
- Per-session outgoing message counters
- Highest received counter tracking
- Replayed or stale encrypted messages are rejected
- Message authentication failures are rejected during decryption

---

## Architecture Overview

### Server

The server is responsible for:
- Handling registration and login
- Tracking online users
- Relaying key exchange messages
- Relaying encrypted chat messages

The server is **not** responsible for:
- Generating chat session keys
- Decrypting encrypted chat messages
- Reading protected message contents

### Client

The client is responsible for:
- Authenticating with the server
- Starting key exchange with another user
- Generating ephemeral X25519 key pairs
- Deriving the shared session key locally
- Encrypting outgoing messages locally
- Decrypting incoming encrypted messages locally
- Tracking replay counters per peer session

---

## Protocol Phases

### 1. Authentication Phase

A client first registers or logs in with a username and password.

- Passwords are hashed with Argon2 before storage
- Only password hashes are stored
- Successful login binds the authenticated username to that client's active WebSocket connection

### 2. Key Exchange Phase

When one user wants to establish a secure session with another:

1. The initiator generates an ephemeral X25519 key pair
2. The initiator sends the public key to the peer through the server
3. The receiving peer generates its own ephemeral X25519 key pair
4. Both clients derive the same shared secret locally
5. Both clients derive the same symmetric session key using HKDF-SHA256

The server only relays the public keys and does not derive the session key.

### 3. Secure Message Transmission Phase

After a session key is established:

1. The sender increments the outgoing counter
2. The sender encrypts the plaintext locally using ChaCha20-Poly1305
3. The encrypted payload includes: nonce, ciphertext, and counter
4. The server relays the encrypted payload
5. The recipient verifies counter freshness
6. The recipient decrypts locally
7. If authentication fails or the counter is stale, the message is rejected

---

## Cryptographic Design

### Password Hashing — Argon2
Used for secure password storage. Avoids storing plaintext passwords and avoids insecure direct use of general-purpose hashes for authentication.

### Key Exchange — X25519
Used for ephemeral Diffie-Hellman style key exchange. Provides secure shared-secret establishment between clients.

### Key Derivation — HKDF-SHA256
Derives a clean 32-byte symmetric session key from the raw shared secret. Improves key handling compared to using raw shared-secret bytes directly.

### Message Encryption — ChaCha20-Poly1305
Authenticated encryption with associated data (AEAD). Provides confidentiality, integrity, and tamper detection.

### Associated Data
The encrypted-message authentication binds the sender, recipient, and message counter. Modifications to any of those values cause decryption/authentication failure.

### Nonce Handling
A fresh random 12-byte nonce is generated for every encrypted message and transmitted with the payload. Nonce reuse with the same session key is avoided by generating a fresh random nonce each time.

---

## Replay Protection

Basic replay protection is implemented with per-session counters.

Each client stores:
- `outgoing_counter`
- `highest_incoming_counter`

When a message is received, if the incoming counter is less than or equal to the highest previously accepted counter, the message is rejected. Otherwise it is accepted and the highest counter is updated.

---

## Project Structure

```text
CryptographyProject/
│
├── client/
│   ├── __init__.py
│   ├── client.py
│   ├── crypto_utils.py
│   └── session_state.py
│
├── server/
│   ├── __init__.py
│   ├── auth.py
│   ├── connection_manager.py
│   ├── main.py
│   └── storage.py
│
├── shared/
│   └── __init__.py
│
├── data/
│   └── users.json
│
├── docs/
│
├── .gitignore
├── README.md
└── requirements.txt
```

### File Responsibilities

| File | Responsibilities |
|---|---|
| `server/main.py` | WebSocket endpoint, request routing, registration/login handling, key exchange relay, encrypted message relay |
| `server/auth.py` | Register user, hash password with Argon2, verify login credentials |
| `server/storage.py` | Load/save users from `data/users.json` |
| `server/connection_manager.py` | Store active WebSocket connections, map `username → websocket`, provide online-user lookup |
| `client/client.py` | Connect to server, handle menu actions, start key exchange, send/receive encrypted messages |
| `client/crypto_utils.py` | X25519 keypair generation, shared-secret derivation, HKDF session-key derivation, ChaCha20-Poly1305 encryption/decryption, base64 helpers, associated-data construction |
| `client/session_state.py` | Track logged-in username, per-peer chat sessions, session key, replay counters, key-exchange state |

---

## Installation

### 1. Open the project folder

Open the project in VS Code or your preferred terminal environment.

### 2. Create a virtual environment

**Windows (cmd)**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

**Windows (PowerShell)**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux / macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Application

### Start the server

From the project root:

```bash
uvicorn server.main:app --reload
```

The server starts on `http://127.0.0.1:8000`. FastAPI docs are available at `http://127.0.0.1:8000/docs`.

### Start a client

Open a new terminal in the project root and run:

```bash
python -m client.client
```

Start at least two clients in separate terminals for testing chat.

---

## Usage Flow

### 1. Register users

On two different client terminals:
- Choose `1 - Register`
- Create two usernames and passwords

### 2. Login
- Choose `2 - Login`
- Log in as each user on a separate client

### 3. Confirm online users
- Choose `3 - List online users`

### 4. Start key exchange

From one client:
- Choose `6 - Start key exchange with user`
- Enter the other username

Both clients should derive a session key.

### 5. Check local session state
- Choose `5 - Show local session state`

You should see the logged-in user, peer session, and `session_key_set=True`.

### 6. Send encrypted messages
- Choose `4 - Send encrypted message`
- Enter the recipient and type the message

The receiving client displays:
```
[NEW MESSAGE - ENCRYPTED] From <sender>: <plaintext>
```

---

## Test Scenarios

| Scenario | Expected Result |
|---|---|
| Valid registration | Successful registration response |
| Invalid registration (short/invalid username) | Username rejected |
| Valid login | Successful login response |
| Wrong password | Authentication failure |
| Online users | Logged-in users appear in the online list |
| Key exchange | Both clients derive a session key |
| Encrypted message send | Sender gets success; recipient decrypts plaintext |
| Replay attempt (stale counter) | Message rejected |
| Send before key exchange | Client refuses — no session key exists |
| Restarted client | In-memory session lost; key exchange required again |

---

## Limitations

This project is designed as a course project and intentionally keeps the protocol understandable.

- Public-key authenticity depends on honest server relay during key exchange
- Session keys are ephemeral and stored only in memory
- Restarting a client requires a new key exchange
- No message history is stored
- No long-term identity keys or digital signatures are implemented

---

Author: Leo Brčina

Institution: Sveučilište Algebra Bernays

Year / Semester: 4th year, 2nd semester

GitHub: LeoBrcina