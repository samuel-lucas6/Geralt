using Geralt.Exceptions;
using System;
using System.Security.Cryptography;

/*
    Geralt: A cryptographic library for .NET based on libsodium.
    Copyright (c) 2021 Samuel Lucas

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
    COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

namespace Geralt
{
    /// <summary>Authenticated encryption with a nonce misuse-resistant API.</summary>
    public static class AuthenticatedEncryption
    {
        public const int KeySize = 32;

        /// <summary>Encrypts a message.</summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">Optional additional data to authenticate.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] key, byte[] additionalData = null)
        {
            byte[] nonce = SecureRandom.GetBytes(XChaCha20Poly1305.NonceSize);
            byte[] ciphertext = XChaCha20Poly1305.Encrypt(message, nonce, key, additionalData);
            return Arrays.Concat(nonce, ciphertext);
        }

        /// <summary>Decrypts a ciphertext message.</summary>
        /// <param name="ciphertext">The ciphertext message to decrypt.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">Optional additional data to authenticate.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] additionalData = null)
        {
            byte[] nonce = Nonce.Read(ciphertext, XChaCha20Poly1305.NonceSize);
            ciphertext = Nonce.Remove(ciphertext, XChaCha20Poly1305.NonceSize);
            return XChaCha20Poly1305.Decrypt(ciphertext, nonce, key, additionalData);
        }
    }
}
