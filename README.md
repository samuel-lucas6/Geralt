[![Maintenance](https://img.shields.io/maintenance/yes/2021)](https://github.com/samuel-lucas6/Geralt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/Geralt/blob/main/LICENSE)
# Geralt
Geralt is a cryptographic library for [.NET](https://dotnet.microsoft.com/) based on [libsodium](https://doc.libsodium.org/). Geralt is a cleaned up fork of [libsodium-core](https://github.com/tabrath/libsodium-core).

| Task | Recommended algorithm | Recommendations |
|-|-|-|
| Random bytes | SecureRandom | Always use this for generating random bytes/numbers. |
| Hashing | BLAKE2b | An output length of 64 bytes. |
| Message authentication code | BLAKE2b | A 64 byte key and an output length of 64 bytes. |
| Key derivation (from a high-entropy key) | BLAKE2b | A random 16 byte salt, a constant 16 byte personalisation parameter, and an output length of 32 bytes. |
| Password hashing/key derivation | Argon2id | A random 16 byte salt, an iteration count of 3+, and a memory size of 64+ MiB. |
| Symmetric encryption | XChaCha20Poly1305 | Split large messages into 16 KiB chunks. A unique 32 byte key per message. A random 24 byte nonce for the first chunk and increment the nonce for each subsequent chunk. |
| Asymmetric/hybrid encryption | PublicKeyBox | A random 24 byte nonce. |
| Key exchange | X25519 | If you have never heard of or don't understand Diffie-Hellman, use PublicKeyBox or Sealed boxes instead. |
| Digital signatures | Ed25519 | Hash large messages (1+ GiB) before signing. |
