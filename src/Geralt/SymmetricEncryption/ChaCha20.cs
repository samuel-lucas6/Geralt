using Geralt.Exceptions;
using System;
using System.Security.Cryptography;

/*
    Geralt: A cryptographic library for .NET based on libsodium.
    Copyright (c) 2021 Samuel Lucas
    Copyright (c) 2017-2020 tabrath
    Copyright (c) 2013-2017 Adam Caudill & Contributors

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
    /// <summary>Unauthenticated encryption using ChaCha20.</summary>
    /// <remarks>This should only be used for custom constructions if you know what you are doing.</remarks>
    public static class ChaCha20
    {
        public const int KeySize = 32;
        public const int NonceSize = 8;

        /// <summary>Encrypts a message using ChaCha20.</summary>
        /// <remarks>The nonce should never be reused with the same key. It must be incremented in constant time.</remarks>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key)
        {
            ParameterValidation.Message(message);
            ParameterValidation.Nonce(nonce, NonceSize);
            ParameterValidation.Key(key, KeySize);
            byte[] ciphertext = new byte[message.Length];
            int result = LibsodiumLibrary.crypto_stream_chacha20_xor(ciphertext, message, message.Length, nonce, key);
            ResultValidation.EncryptionResult(result);
            return ciphertext;
        }

        /// <summary>Decrypts a ciphertext message using ChaCha20.</summary>
        /// <param name="ciphertext">The ciphertext to be decrypted.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] key)
        {
            ParameterValidation.Ciphertext(ciphertext);
            ParameterValidation.Nonce(nonce, NonceSize);
            ParameterValidation.Key(key, KeySize);
            byte[] plaintext = new byte[ciphertext.Length];
            int result = LibsodiumLibrary.crypto_stream_chacha20_xor(plaintext, ciphertext, ciphertext.Length, nonce, key);
            ResultValidation.DecryptionResult(result);
            return plaintext;
        }
    }
}