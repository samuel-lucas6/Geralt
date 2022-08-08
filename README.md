# Geralt

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](https://github.com/samuel-lucas6/Geralt/blob/main/LICENSE)
[![NuGet](https://img.shields.io/badge/nuget-latest-blue)](https://www.nuget.org/packages/Geralt)

[Geralt](https://www.geralt.xyz/) is a modern cryptographic library for [.NET 6](https://dotnet.microsoft.com/en-us/download/dotnet/6.0) based on [libsodium](https://doc.libsodium.org/) and inspired by [Monocypher](https://monocypher.org/).

- **Simple**: an easy-to-learn API with descriptive naming. Only one primitive for each task is provided when possible.
- **Modern**: the latest and greatest cryptographic primitives, such as (X)ChaCha20-Poly1305, BLAKE2b, Argon2id, X25519, and Ed25519.
- **Secure**: libsodium was [audited](https://www.privateinternetaccess.com/blog/libsodium-audit-results/) in 2017 and is the library of choice for [lots](https://doc.libsodium.org/libsodium_users) of projects and [even](https://doc.libsodium.org/libsodium_users#companies-using-libsodium) large companies.
- **Fast**: libsodium is [faster](https://monocypher.org/speed) than many other cryptographic libraries. Furthermore, Geralt uses [Span&lt;T&gt;](https://docs.microsoft.com/en-us/archive/msdn-magazine/2017/connect/csharp-all-about-span-exploring-a-new-net-mainstay) buffers to avoid memory allocations.

For more information, please view to the following resources:

|                           |                                                  |
|:------------------------- |:------------------------------------------------ |
| Documentation:            | https://www.geralt.xyz/                          |
| Installation:             | https://www.geralt.xyz/#installation             |
| Open issues:              | https://github.com/samuel-lucas6/Geralt/issues   |
| Pull requests:            | https://github.com/samuel-lucas6/Geralt/pulls    |
