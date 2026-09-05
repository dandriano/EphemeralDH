# EphemeralDH

The implementation of a ECDH → HKDF-SHA256 → AES-GCM pipeline, which is a standard cryptographic combination used to establish secure, authenticated end-to-end encryption between two parties without sharing a long-term secret beforehand.

Original c# idea / implementation is [here](https://davidtavarez.github.io/2019/implementing-elliptic-curve-diffie-hellman-c-sharp/).

## Core

Client request

- Identity (username) must be bound into transcripts as `username`.
- Middleware expects `X-EDHX-Username: <username>` by default.
- `X-EDHX-Client-Public-Key: base64(clientEphemeralPublicKey)` (P-256 uncompressed, 65 bytes; first byte is `0x04`)
- Transcript bindings for request salt + AEAD AAD are computed from the HTTP `method`, `path`, and identity `username`.

Server response (after successful authorization and after computing the shared secret)

- `X-EDHX-Server-Public-Key: base64(serverEphemeralPublicKey)` (P-256 uncompressed, 65 bytes)
- `X-EDHX-Nonce: base64(nonce)` (12 bytes)
- `X-EDHX-Tag: base64(tag)` (16 bytes)
- `X-EDHX-Protocol-Version: edhx1`
- Response body contains `ciphertext` (AES-GCM encrypted payload bytes).

Client processing (decrypt)

- Derive request salt: `requestSalt = DeriveRequestSalt(method, path, username)`
- Derive session key: `sessionKey = DeriveSessionKey(sharedSecret, requestSalt, info)`
- Compute AEAD AAD: `aad = BuildAssociatedData(edhx1, method, path, username)`
- Decrypt: `plaintext = DecryptResponse(sessionKey, ciphertext, nonce, tag, aad)`

```
client                      server
  | Authorization: Basic ...
  | X-EDHX-Client-Public-Key: ...
  |------------------------------------->
  |<-------------------------------------|
  | X-EDHX-Server-Public-Key: ...
  | X-EDHX-Nonce: ...
  | X-EDHX-Tag: ...
  | X-EDHX-Protocol-Version: edhx1
  | response body = ciphertext

client decrypts response using the returned server public key + nonce/tag + AAD
```

## Middleware

`IMiddleware` implementation of a server-side pipeline.

Request

- Identity must be resolvable by the configured `IEdhxIdentityResolver` (default: `X-EDHX-Username`); otherwise the middleware responds `401 Unauthorized`.
- `X-EDHX-Client-Public-Key: base64(clientEphemeralPublicKey)` must be present and parseable; otherwise the middleware responds `401 Unauthorized`.
- On any `401`, the middleware does not set any `X-EDHX-*` protocol headers.

Response

- Middleware buffers the downstream response and encrypts only when:
  - the downstream status code is `2xx`, and
  - the response body is non-empty.
- For non-2xx responses and empty bodies, the middleware passes the plaintext response through unchanged (and does not set `X-EDHX-*` protocol headers).
- When encrypting, the middleware returns a ciphertext body and sets:
  - `X-EDHX-Server-Public-Key: base64(serverEphemeralPublicKey)`
  - `X-EDHX-Nonce: base64(nonce)` (12 bytes)
  - `X-EDHX-Tag: base64(tag)` (16 bytes)
  - `X-EDHX-Protocol-Version: edhx1`

Transcript

- Request salt and AEAD AAD are computed from the HTTP `method`, `path`, and identity `username`.
- HKDF `info` is computed from `path` as UTF-8 bytes (must match the client implementation).
