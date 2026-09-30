# EphemeralDH

BCL-only demo for an ephemeral P-256 Diffie-Hellman handshake, HKDF-SHA256 key schedule and AES-256-GCM records (ECDH → HKDF-SHA256 → AES-GCM pipeline).

Original c# idea / implementation is [here](https://davidtavarez.github.io/2019/implementing-elliptic-curve-diffie-hellman-c-sharp/).
Also see SslStream ["limitations"](https://stackoverflow.com/questions/20188480/sslstream-without-certificate).

## Security properties

The handshake is **unauthenticated**. It does not identify either peer and is vulnerable to active interception: an intermediary can establish separate keys with both sides and read or change traffic. Records authenticate data only to the holder of the negotiated session key; they do not authenticate a person, server, or device.

## Core API

- `HandshakeRequest` creates a fresh client P-256 key and completes a handshake response.
- `Handshake.CreateSession` validates the client P-256 key and returns a server session plus handshake response.
- `Session` maintains independent client-to-server and server-to-client traffic keys and sequence counters, and provides message protection and authenticated record methods.
- `CryptoStream` wraps a readable and writable stream. It supports asynchronous duplex reads and writes and closes its write direction with an authenticated close record when disposed.

Each record has a 4-byte big-endian length, a record type, a 64-bit sequence number, ciphertext, and a 16-byte GCM tag. Data records carry up to 16 KiB. The nonce combines a direction-specific nonce base with the sequence number. Protocol version, direction, session, metadata context, record type, and sequence are authenticated. Readers reject invalid P-256 keys, out-of-order or replayed records, tampering, truncation, and data after an authenticated close in a message.

## Demo

The demo server uses:

- Basic auth (`Authorization: Basic ...`)
- SQLite-backed user storage
- `CryptoMiddleware` to encrypt responses only for endpoints marked with `RequireEdhxEncryption()`

Shipped endpoints:

- `GET /health`
- `POST /users` (admin-only)
- `POST /echo` (encrypted echo)

