# EphemeralDH

The implementation of a ECDH → HKDF-SHA256 → AES-GCM pipeline, which is a standard cryptographic combination used to establish secure, authenticated end-to-end encryption between two parties without sharing a long-term secret beforehand.

Original c# idea / implementation is [here](https://davidtavarez.github.io/2019/implementing-elliptic-curve-diffie-hellman-c-sharp/).

## Core

Client request

- `Authorization: Basic base64(username:password)`
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